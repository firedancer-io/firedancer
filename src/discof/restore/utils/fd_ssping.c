#define _GNU_SOURCE /* sendmmsg */
#include "fd_ssping.h"
#include "fd_sspeer_selector.h"

#include "../../../util/fd_util.h"
#include "../../../util/bits/fd_bits.h"
#include "../../../util/log/fd_log.h"

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#define PEER_STATE_UNPINGED   0
#define PEER_STATE_PINGED     1
#define PEER_STATE_VALID      2
#define PEER_STATE_REFRESHING 3
#define PEER_STATE_INVALID    4

#define PEER_DEADLINE_NANOS_PING    (1L*1000L*1000L*1000L)     /* 1 second */
#define PEER_DEADLINE_NANOS_VALID   (2L*60L*1000L*1000L*1000L) /* 2 minutes */
#define PEER_DEADLINE_NANOS_INVALID (5L*60L*1000L*1000L*1000L) /* 5 minutes */

#define PING_BURST_MAX (16UL) /* Limit how many pings we can burst at once. */

/* FIXME: This code uses fd_ip4_port_t as the key for peers, but it
   should really just use uint (IPv4 address) as port has no meaning
   for ICMP pings.  Making this change however requires some significant
   changes in snapct as we are also effectively storing peer invalidation
   state in this data structure.  The number of distinct peers with
   the same IP address but different ports will be low, so this is fine
   for now. */

/* FIXME: Properly set and track sequence numbers for repeated pings. */

struct fd_ssping_peer {
  ulong         refcnt;
  fd_ip4_port_t addr;

  struct {
    ulong next;
  } pool;

  struct {
    ulong next;
    ulong prev;
  } map;

  struct {
    ulong next;
    ulong prev;
  } deadline;

  int   state;
  ulong latency_nanos;
  long  deadline_nanos;
};

typedef struct fd_ssping_peer fd_ssping_peer_t;

#define POOL_NAME  peer_pool
#define POOL_T     fd_ssping_peer_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               peer_map
#define MAP_KEY                addr
#define MAP_ELE_T              fd_ssping_peer_t
#define MAP_KEY_T              fd_ip4_port_t
#define MAP_PREV               map.prev
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      ((k0)->l==(k1)->l)
#define MAP_KEY_HASH(key,seed) (seed^(key)->l)
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  deadline_list
#define DLIST_ELE_T fd_ssping_peer_t
#define DLIST_PREV  deadline.prev
#define DLIST_NEXT  deadline.next
#include "../../../util/tmpl/fd_dlist.c"

struct fd_ssping_private {
  fd_ssping_peer_t *     pool;
  peer_map_t *           map;

  deadline_list_t *      unpinged;
  deadline_list_t *      pinged;
  deadline_list_t *      valid;
  deadline_list_t *      refreshing;
  deadline_list_t *      invalid;

  int                    sockfd;

  fd_ssping_on_ping_fn_t on_ping_cb;
  void *                 cb_arg;

  ulong                  magic; /* ==FD_SSPING_MAGIC */
};

/* We attach the UDP port number associated with the peer to each ping
   echo request, which must be reflected back to us in the echo reply.
   This is used to look up the correct peer, which is keyed on both
   IP address and UDP port.  The ICMP echo protocol has no concept
   of UDP port which is why we must do this manually. */

struct __attribute__((packed)) ssping_pkt {
  struct icmphdr icmp;
  ushort         port;
};

FD_FN_CONST ulong
fd_ssping_align( void ) {
  return fd_ulong_max( alignof(fd_ssping_t),
         fd_ulong_max( peer_pool_align(),
         fd_ulong_max( peer_map_align(),
                       deadline_list_align() ) ) );
}

FD_FN_CONST ulong
fd_ssping_footprint( ulong max_peers ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_ssping_t),  sizeof(fd_ssping_t) );
  l = FD_LAYOUT_APPEND( l, peer_pool_align(),     peer_pool_footprint( max_peers ) );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),      peer_map_footprint( peer_map_chain_cnt_est( max_peers ) ) );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  return FD_LAYOUT_FINI( l, fd_ssping_align() );
}

void *
fd_ssping_new( void *                 shmem,
               ulong                  max_peers,
               ulong                  seed,
               fd_ssping_on_ping_fn_t on_ping_cb,
               void *                 cb_arg ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ssping_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_peers < 1UL ) ) {
    FD_LOG_WARNING(( "max_peers must be at least 1" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ssping_t * ssping = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ssping_t),  sizeof(fd_ssping_t) );
  void * _pool         = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(),     peer_pool_footprint( max_peers ) );
  void * _map          = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),      peer_map_footprint( peer_map_chain_cnt_est( max_peers ) ) );
  void * _unpinged     = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _pinged       = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _valid        = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _refreshing   = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _invalid      = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );

  ssping->pool = peer_pool_join( peer_pool_new( _pool, max_peers ) );
  ssping->map  = peer_map_join( peer_map_new( _map, peer_map_chain_cnt_est( max_peers ), seed ) );

  ssping->unpinged   = deadline_list_join( deadline_list_new( _unpinged ) );
  ssping->pinged     = deadline_list_join( deadline_list_new( _pinged ) );
  ssping->valid      = deadline_list_join( deadline_list_new( _valid ) );
  ssping->refreshing = deadline_list_join( deadline_list_new( _refreshing ) );
  ssping->invalid    = deadline_list_join( deadline_list_new( _invalid ) );

  /* Note: This uses an obscure feature of Linux called ICMP datagram
     sockets or unprivileged ping sockets.  Normally one would have to
     use SOCK_RAW sockets, but with this special feature any user can
     send & receive ICMP echo packets. */
  ssping->sockfd = socket( AF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_ICMP );
  if( FD_UNLIKELY( -1==ssping->sockfd ) ) FD_LOG_ERR(( "socket(SOCK_DGRAM,IPPROTO_ICMP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ssping->on_ping_cb = on_ping_cb;
  ssping->cb_arg     = cb_arg;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( ssping->magic ) = FD_SSPING_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)ssping;
}

fd_ssping_t *
fd_ssping_join( void * shping ) {
  if( FD_UNLIKELY( !shping ) ) {
    FD_LOG_WARNING(( "NULL shping" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shping, fd_ssping_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shping" ));
    return NULL;
  }

  fd_ssping_t * ssping = (fd_ssping_t *)shping;

  if( FD_UNLIKELY( ssping->magic!=FD_SSPING_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ssping;
}

int
fd_ssping_get_sockfd( fd_ssping_t const * ssping ) {
  return ssping->sockfd;
}

void
fd_ssping_add( fd_ssping_t * ssping,
               fd_ip4_port_t addr ) {
  fd_ssping_peer_t * peer = peer_map_ele_query( ssping->map, &addr, NULL, ssping->pool );
  if( FD_LIKELY( !peer ) ) {
    if( FD_UNLIKELY( !peer_pool_free( ssping->pool ) ) ) return;
    peer = peer_pool_ele_acquire( ssping->pool );
    FD_TEST( peer );
    memset( peer, 0, sizeof(fd_ssping_peer_t) );
    peer->refcnt        = 0UL;
    peer->state         = PEER_STATE_UNPINGED;
    peer->addr          = addr;
    peer->latency_nanos = ULONG_MAX;
    peer_map_ele_insert( ssping->map, peer, ssping->pool );
    deadline_list_ele_push_tail( ssping->unpinged, peer, ssping->pool );
  }
  peer->refcnt++;
}

int
fd_ssping_remove( fd_ssping_t * ssping,
                  fd_ip4_port_t addr ) {
  fd_ssping_peer_t * peer = peer_map_ele_query( ssping->map, &addr, NULL, ssping->pool );
  FD_TEST( peer );
  FD_TEST( peer->refcnt );
  peer->refcnt--;
  if( FD_LIKELY( !peer->refcnt ) ) {
    switch( peer->state ) {
      case PEER_STATE_UNPINGED:
        deadline_list_ele_remove( ssping->unpinged, peer, ssping->pool );
        break;
      case PEER_STATE_PINGED:
        deadline_list_ele_remove( ssping->pinged, peer, ssping->pool );
        break;
      case PEER_STATE_VALID:
        deadline_list_ele_remove( ssping->valid, peer, ssping->pool );
        break;
      case PEER_STATE_REFRESHING:
        deadline_list_ele_remove( ssping->refreshing, peer, ssping->pool );
        break;
      case PEER_STATE_INVALID:
        deadline_list_ele_remove( ssping->invalid, peer, ssping->pool );
        break;
    }
    peer_map_ele_remove_fast( ssping->map, peer, ssping->pool );
    peer_pool_ele_release( ssping->pool, peer );
    return 1;
  }
  return 0;
}

void
fd_ssping_invalidate( fd_ssping_t * ssping,
                      fd_ip4_port_t addr,
                      long          now ) {
  fd_ssping_peer_t * peer = peer_map_ele_query( ssping->map, &addr, NULL, ssping->pool );
  if( FD_UNLIKELY( !peer ) ) return;
  switch( peer->state ) {
    case PEER_STATE_UNPINGED:
      deadline_list_ele_remove( ssping->unpinged, peer, ssping->pool );
      break;
    case PEER_STATE_PINGED:
      deadline_list_ele_remove( ssping->pinged, peer, ssping->pool );
      break;
    case PEER_STATE_VALID:
      deadline_list_ele_remove( ssping->valid, peer, ssping->pool );
      break;
    case PEER_STATE_REFRESHING:
      deadline_list_ele_remove( ssping->refreshing, peer, ssping->pool );
      break;
    case PEER_STATE_INVALID:
      return;
  }
  peer->state = PEER_STATE_INVALID;
  peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
  deadline_list_ele_push_tail( ssping->invalid, peer, ssping->pool );
}

static inline void
recv_pings( fd_ssping_t * ssping,
            long          now ) {
  for( ulong i=0UL; i<PING_BURST_MAX; i++ ) {
    struct ssping_pkt  pkt;
    struct sockaddr_in addr;
    socklen_t          alen   = sizeof(addr);
    long               result = recvfrom( ssping->sockfd, &pkt, sizeof(pkt), 0, fd_type_pun( &addr ), &alen );
    if( FD_UNLIKELY( result!=sizeof(pkt) || alen!=sizeof(addr) || pkt.icmp.type!=ICMP_ECHOREPLY ) ) break;

    fd_ip4_port_t key = {
      .addr = addr.sin_addr.s_addr,
      .port = pkt.port
    };
    fd_ssping_peer_t * peer = peer_map_ele_query( ssping->map, &key, NULL, ssping->pool );
    if( FD_UNLIKELY( peer==NULL || ( peer->state!=PEER_STATE_PINGED && peer->state!=PEER_STATE_REFRESHING ) ) ) continue;

    deadline_list_ele_remove( peer->state==PEER_STATE_PINGED ? ssping->pinged : ssping->refreshing, peer, ssping->pool );
    FD_TEST( peer->deadline_nanos-PEER_DEADLINE_NANOS_PING<now );
    peer->latency_nanos  = (ulong)(now - (peer->deadline_nanos - PEER_DEADLINE_NANOS_PING));
    peer->state          = PEER_STATE_VALID;
    peer->deadline_nanos = now + PEER_DEADLINE_NANOS_VALID;
    deadline_list_ele_push_tail( ssping->valid, peer, ssping->pool );

    FD_LOG_INFO(( "pinged " FD_IP4_ADDR_FMT ":%hu in %lu nanos",
                  FD_IP4_ADDR_FMT_ARGS( peer->addr.addr ), fd_ushort_bswap( peer->addr.port ), peer->latency_nanos ));
    ssping->on_ping_cb( ssping->cb_arg, peer->addr, peer->latency_nanos );
  }
}

static uint
send_pings( fd_ssping_t *     ssping,
            deadline_list_t * list,
            long              until ) {
  uint msg_cnt = 0U;
  struct ssping_pkt  pkts  [ PING_BURST_MAX ];
  struct iovec       iovs  [ PING_BURST_MAX ];
  struct sockaddr_in addrs [ PING_BURST_MAX ];
  struct mmsghdr     msgs  [ PING_BURST_MAX ];
  for( deadline_list_iter_t iter = deadline_list_iter_fwd_init( list, ssping->pool );
       msg_cnt<PING_BURST_MAX && !deadline_list_iter_done( iter, list, ssping->pool );
       iter = deadline_list_iter_fwd_next( iter, list, ssping->pool ) ) {
    fd_ssping_peer_t * peer = peer_pool_ele( ssping->pool, deadline_list_iter_idx( iter, list, ssping->pool ) );
    if( peer->deadline_nanos>until ) break;

    pkts[ msg_cnt ] = (struct ssping_pkt){
      .icmp = { .type = ICMP_ECHO },
      .port = peer->addr.port
    };
    iovs[ msg_cnt ] = (struct iovec){
      .iov_base = pkts + msg_cnt,
      .iov_len = sizeof(struct ssping_pkt)
    };
    addrs[ msg_cnt ] = (struct sockaddr_in){
      .sin_family = AF_INET,
      .sin_addr   = { .s_addr = peer->addr.addr }
    };
    msgs[ msg_cnt ].msg_hdr = (struct msghdr){
      .msg_name = addrs + msg_cnt,
      .msg_namelen = sizeof(struct sockaddr_in),
      .msg_iov = iovs + msg_cnt,
      .msg_iovlen = 1,
    };
    msgs[ msg_cnt ].msg_len = 0;
    msg_cnt++;
  }

  if( msg_cnt==0U ) return 0U;
  int result = sendmmsg( ssping->sockfd, msgs, msg_cnt, 0 );
  if( FD_UNLIKELY( -1==result ) ) {
    if( errno!=EAGAIN && errno!=EINTR ) FD_LOG_WARNING(( "sendmmsg(%u) failed (%i-%s)", msg_cnt, errno, fd_io_strerror( errno ) ));
    return 0U;
  }
  FD_TEST( result>=0 && result<=(int)PING_BURST_MAX );
  return (uint)result;
}

void
fd_ssping_advance( fd_ssping_t *          ssping,
                   long                   now,
                   fd_sspeer_selector_t * selector) {
  uint sent = send_pings( ssping, ssping->unpinged, LONG_MAX );
  for( uint i=0U; i<sent; i++ ) {
    fd_ssping_peer_t * peer = deadline_list_ele_pop_head( ssping->unpinged, ssping->pool );
    FD_TEST( peer );
    peer->state = PEER_STATE_PINGED;
    peer->deadline_nanos = now + PEER_DEADLINE_NANOS_PING;
    deadline_list_ele_push_tail( ssping->pinged, peer, ssping->pool );
  }

  while( !deadline_list_is_empty( ssping->pinged, ssping->pool ) ) {
    fd_ssping_peer_t * peer = deadline_list_ele_peek_head( ssping->pinged, ssping->pool );
    if( FD_LIKELY( peer->deadline_nanos>now ) ) break;

    deadline_list_ele_pop_head( ssping->pinged, ssping->pool );

    peer->state = PEER_STATE_INVALID;
    peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
    deadline_list_ele_push_tail( ssping->invalid, peer, ssping->pool );
    fd_sspeer_selector_remove( selector, peer->addr );
  }

  sent = send_pings( ssping, ssping->valid, now );
  for( uint i=0U; i<sent; i++ ) {
    fd_ssping_peer_t * peer = deadline_list_ele_pop_head( ssping->valid, ssping->pool );
    FD_TEST( peer );
    peer->state = PEER_STATE_REFRESHING;
    peer->deadline_nanos = now + PEER_DEADLINE_NANOS_PING;
    deadline_list_ele_push_tail( ssping->refreshing, peer, ssping->pool );
  }

  while( !deadline_list_is_empty( ssping->refreshing, ssping->pool ) ) {
    fd_ssping_peer_t * peer = deadline_list_ele_peek_head( ssping->refreshing, ssping->pool );
    if( FD_LIKELY( peer->deadline_nanos>now ) ) break;

    deadline_list_ele_pop_head( ssping->refreshing, ssping->pool );

    peer->state = PEER_STATE_INVALID;
    peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
    deadline_list_ele_push_tail( ssping->invalid, peer, ssping->pool );
    fd_sspeer_selector_remove( selector, peer->addr );
  }

  while( !deadline_list_is_empty( ssping->invalid, ssping->pool ) ) {
    fd_ssping_peer_t * peer = deadline_list_ele_peek_head( ssping->invalid, ssping->pool );
    if( FD_LIKELY( peer->deadline_nanos>now ) ) break;

    deadline_list_ele_pop_head( ssping->invalid, ssping->pool );

    peer->state = PEER_STATE_UNPINGED;
    peer->deadline_nanos = 0L;
    deadline_list_ele_push_tail( ssping->unpinged, peer, ssping->pool );
  }

  recv_pings( ssping, now );
}
