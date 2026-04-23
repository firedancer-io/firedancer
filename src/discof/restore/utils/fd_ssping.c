#define _GNU_SOURCE /* ppoll */
#include "fd_ssping.h"
#include "fd_sspeer_selector.h"

#include "../../../util/fd_util.h"
#include "../../../util/bits/fd_bits.h"
#include "../../../util/log/fd_log.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>

#define PEER_STATE_UNPINGED   0
#define PEER_STATE_PINGED     1
#define PEER_STATE_VALID      2
#define PEER_STATE_REFRESHING 3
#define PEER_STATE_INVALID    4

#define PEER_DEADLINE_NANOS_PING    (1L*1000L*1000L*1000L)     /* 1 second */
#define PEER_DEADLINE_NANOS_VALID   (2L*60L*1000L*1000L*1000L) /* 2 minutes */
#define PEER_DEADLINE_NANOS_INVALID (5L*60L*1000L*1000L*1000L) /* 5 minutes */

#define PING_BURST_MAX (16UL) /* Limit how many pings we can burst at once. */

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
  ulong used_fd_idx;
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
  fd_ssping_peer_t *       pool;
  peer_map_t *             map;

  deadline_list_t *        unpinged;
  deadline_list_t *        pinged;
  deadline_list_t *        valid;
  deadline_list_t *        refreshing;
  deadline_list_t *        invalid;

  fd_ssping_on_ping_fn_t   on_ping_cb;
  void *                   cb_arg;

  ulong                    magic; /* ==FD_SSPING_MAGIC */

  /* Invariant: The pool elements with an associated file descriptor are
     exactly those that are PINGED or REFRESHING. */
  ulong                    used_fd_cnt;
  struct pollfd            used_fds[ FD_SSPING_FD_CNT ]; /* indexed [0, used_fd_cnt) */
  int                      idle_fds[ FD_SSPING_FD_CNT ]; /* indexed [0, FD_SSPING_FD_CNT-used_fd_cnt) */
  /* ping_to_pool[ i ]==x means that used_fds[ i ].fd is in use for
     pinging the peer in pool[ x ]. */
  ulong                    ping_to_pool[ FD_SSPING_FD_CNT ]; /* indexed [0, used_fd_cnt) */
  fd_ssping_sockfd_range_t ping_fds; /* redundant with the above info, but stored separately for convenience. */
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

  /* There's no automatic way to allocate contiguous file descriptors.
     We could probe for which are open with fcntl( fd, F_GETFD ), but
     that's racy.  Another way to do it is to read /proc/fd, but that's
     a bit gross from here, and still racy.  A third way to do it is to
     allocate until we find a contiguous region.  All this happens
     during privileged_init, so we have a lot of control over it, and in
     practice, I think any solution would be fine.  We'll go with the
     looping allocation solution. */

  int min_fd;
  int max_fd;
  int base_fd = 0;
  while( 1 ) {
    int i;
    int success   = 1;
    int next_base = 0;
    for( i=0; i<(int)FD_SSPING_FD_CNT; i++ ) {
      int fd0 = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP );
      if( FD_UNLIKELY( -1==fd0 ) ) FD_LOG_ERR(( "socket(SOCK_STREAM,IPPROTO_TCP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

      if( FD_LIKELY( fd0!=base_fd+i ) ) {
        int fd = fcntl( fd0, F_DUPFD, base_fd+i );
        if( FD_UNLIKELY( -1==fd           ) ) FD_LOG_ERR(( "fcntl( %i, F_DUPFD, %i ) failed (%i-%s)", fd0, base_fd+i, errno, fd_io_strerror( errno ) ));
        if( FD_UNLIKELY( -1==close( fd0 ) ) ) FD_LOG_ERR(( "close(%i) failed (%i-%s)", fd0, errno, fd_io_strerror( errno ) ));
        if( FD_UNLIKELY( fd!=base_fd+i ) ) {
          if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_ERR(( "close(%i) failed (%i-%s)", fd, errno, fd_io_strerror( errno ) ));
          success = 0;
          next_base = fd_int_max( fd, fd0 );
          /* Close our partial progress and try again.  If this keeps
             failing, eventually one of the syscalls will return an
             error, and we'll abort. */
          break;
        }
      }
      /* At this point, [base_fd, base_fd+i] are properly initialized
         sockets. */
    }
    if( FD_UNLIKELY( !success ) ) {
      /* We were able to allocate [base_fd, base_fd+i), but base_fd+i
         must have been taken.  Close everything we allocated, and
         restart the process from a larger base_fd. */
      for( int _i=0; _i<i; _i++ ) {
        if( FD_UNLIKELY( -1==close( base_fd+_i ) ) ) FD_LOG_ERR(( "close(%i) failed (%i-%s)", base_fd+_i, errno, fd_io_strerror( errno ) ));
      }
      base_fd = fd_int_max( base_fd+i+1, next_base );
    } else {
      min_fd = base_fd;
      max_fd = base_fd+i-1;
      break;
    }
  }


  for( ulong i=0UL; i<FD_SSPING_FD_CNT; i++ ) {
    int tcp_nodelay = 1;
    int fd = min_fd + (int)i;
    if( FD_UNLIKELY( setsockopt( fd, SOL_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(int) ) ) ) {
      FD_LOG_ERR(( "setsockopt(SOL_TCP,TCP_NODELAY,1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    ssping->idle_fds[ i ] = fd;

    ssping->used_fds[ i ].fd      = -1;
    ssping->used_fds[ i ].events  = POLLOUT|POLLRDHUP|POLLPRI;
    ssping->used_fds[ i ].revents = 0;
  }

  ssping->used_fd_cnt = 0UL;

  ssping->on_ping_cb = on_ping_cb;
  ssping->cb_arg     = cb_arg;

  ssping->ping_fds.min_fd = min_fd;
  ssping->ping_fds.max_fd = max_fd;

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

void
fd_ssping_add( fd_ssping_t * ssping,
               fd_ip4_port_t addr ) {
  fd_ssping_peer_t * peer = peer_map_ele_query( ssping->map, &addr, NULL, ssping->pool );
  if( FD_LIKELY( !peer ) ) {
    if( FD_UNLIKELY( !peer_pool_free( ssping->pool ) ) ) {
      FD_LOG_WARNING(( "ping peer pool exhausted" ));
      return;
    }
    peer = peer_pool_ele_acquire( ssping->pool );
    memset( peer, 0, sizeof(fd_ssping_peer_t) );
    peer->refcnt        = 0UL;
    peer->state         = PEER_STATE_UNPINGED;
    peer->addr          = addr;
    peer->latency_nanos = ULONG_MAX;
    peer->used_fd_idx   = ULONG_MAX;
    peer_map_ele_insert( ssping->map, peer, ssping->pool );
    deadline_list_ele_push_tail( ssping->unpinged, peer, ssping->pool );
  }
  peer->refcnt++;
}

static void
remove_fdesc_idx( fd_ssping_t * ssping,
                  ulong         fdesc_idx ) {
  FD_TEST( fdesc_idx<FD_SSPING_FD_CNT );
  FD_TEST( fdesc_idx<ssping->used_fd_cnt );
  ulong pool_idx = ssping->ping_to_pool[ fdesc_idx ];

  int fdesc = ssping->used_fds[ fdesc_idx ].fd;
  /* Abort the connection attempt or close the connection by connecting
     to AF_UNSPEC. */
  struct sockaddr_in addr[1] = {{
    .sin_family = AF_UNSPEC,
    .sin_addr   = { .s_addr = 0U },
    .sin_port   = 0
  }};
  if( FD_UNLIKELY( connect( fdesc, addr, sizeof(addr) ) ) ) FD_LOG_ERR(( "connect(AF_UNSPEC) failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  /* Mark that the pool element no longer has an associated index. */
  ssping->pool[ pool_idx ].used_fd_idx = ULONG_MAX;

  /* Now swap the last used_fd into this position, updating all the
     relevant bookkeeping info. */
  ulong last = ssping->used_fd_cnt-1UL;
  if( FD_LIKELY( fdesc_idx!=last ) ) {
    ssping->used_fds[ fdesc_idx ] = ssping->used_fds[ last ];
    ulong last_pool_idx = ssping->ping_to_pool[ fdesc_idx ] = ssping->ping_to_pool[ last ];
    ssping->pool[ last_pool_idx ].used_fd_idx = fdesc_idx;
  }

  ssping->idle_fds[ FD_SSPING_FD_CNT - ssping->used_fd_cnt ] = fdesc;
  ssping->used_fd_cnt--;
}

int
fd_ssping_remove( fd_ssping_t * ssping,
                  fd_ip4_port_t addr ) {
  fd_ssping_peer_t * peer = peer_map_ele_query( ssping->map, &addr, NULL, ssping->pool );
  if( FD_UNLIKELY( !peer ) ) return 0;
  if( FD_UNLIKELY( !peer->refcnt ) ) return 0;
  peer->refcnt--;
  if( FD_LIKELY( !peer->refcnt ) ) {
    switch( peer->state ) {
      case PEER_STATE_UNPINGED:
        deadline_list_ele_remove( ssping->unpinged, peer, ssping->pool );
        break;
      case PEER_STATE_PINGED:
        deadline_list_ele_remove( ssping->pinged, peer, ssping->pool );
        remove_fdesc_idx( ssping, peer->used_fd_idx );
        break;
      case PEER_STATE_VALID:
        deadline_list_ele_remove( ssping->valid, peer, ssping->pool );
        break;
      case PEER_STATE_REFRESHING:
        deadline_list_ele_remove( ssping->refreshing, peer, ssping->pool );
        remove_fdesc_idx( ssping, peer->used_fd_idx );
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
      remove_fdesc_idx( ssping, peer->used_fd_idx );
      break;
    case PEER_STATE_VALID:
      deadline_list_ele_remove( ssping->valid, peer, ssping->pool );
      break;
    case PEER_STATE_REFRESHING:
      deadline_list_ele_remove( ssping->refreshing, peer, ssping->pool );
      remove_fdesc_idx( ssping, peer->used_fd_idx );
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
            fd_sspeer_selector_t * selector) {
  int pollv = fd_syscall_poll( ssping->used_fds, (uint)ssping->used_fd_cnt, 0 );
  if( FD_UNLIKELY( pollv<0 ) ) {
    FD_LOG_WARNING(( "poll(used_fds,%lu,0) failed (%d-%s)", ssping->used_fd_cnt, errno, fd_io_strerror( errno ) ));
    return;
  }
  long now = fd_log_wallclock();
  ulong processed = 0UL;
  ulong processed_idx[ PING_BURST_MAX ];
  for( ulong i=0UL; i<ssping->used_fd_cnt; i++ ) {
    if( FD_UNLIKELY( processed >= fd_ulong_min( (ulong)pollv, PING_BURST_MAX ) ) ) break;
    if( FD_UNLIKELY( ssping->used_fds[ i ].revents ) ) {
      ulong pool_idx = ssping->ping_to_pool[ i ];
      fd_ssping_peer_t * peer = ssping->pool+pool_idx;

      FD_TEST( peer->state==PEER_STATE_PINGED || peer->state==PEER_STATE_REFRESHING );


      deadline_list_ele_remove( peer->state==PEER_STATE_PINGED ? ssping->pinged : ssping->refreshing, peer, ssping->pool );
      int is_err = ssping->used_fds[ i ].revents & (POLLRDHUP|POLLERR|POLLHUP);
      if( FD_LIKELY( !is_err ) ) {
        peer->latency_nanos  = (ulong)fd_long_max( now - (peer->deadline_nanos - PEER_DEADLINE_NANOS_PING), 1L );
        peer->state          = PEER_STATE_VALID;
        peer->deadline_nanos = now + PEER_DEADLINE_NANOS_VALID;
        deadline_list_ele_push_tail( ssping->valid, peer, ssping->pool );

        FD_LOG_INFO(( "pinged " FD_IP4_ADDR_FMT ":%hu in %lu nanos",
              FD_IP4_ADDR_FMT_ARGS( peer->addr.addr ), fd_ushort_bswap( peer->addr.port ), peer->latency_nanos ));
        ssping->on_ping_cb( ssping->cb_arg, peer->addr, peer->latency_nanos );
      } else {
        /* This is pretty unlikely, but the host could respond with an
           RST packet I suppose. */
        peer->state = PEER_STATE_INVALID;
        peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
        deadline_list_ele_push_tail( ssping->invalid, peer, ssping->pool );
        fd_sspeer_selector_remove_by_addr( selector, peer->addr );
      }
      processed_idx[ processed ] = i;
      processed++;
    }
  }
  /* Now we need to call remove_fdesc_idx on the processed ones in
     reverse order (largest to smallest) so that we don't trip on
     ourself as we shuffle the array. */
  while( processed ) remove_fdesc_idx( ssping, processed_idx[ --processed ] );
}

static uint
send_pings( fd_ssping_t *     ssping,
            deadline_list_t * list,
            long              until ) {
  uint msg_cnt = 0U;
  for( deadline_list_iter_t iter = deadline_list_iter_fwd_init( list, ssping->pool );
       msg_cnt<PING_BURST_MAX && ssping->used_fd_cnt<FD_SSPING_FD_CNT && !deadline_list_iter_done( iter, list, ssping->pool );
       iter = deadline_list_iter_fwd_next( iter, list, ssping->pool ) ) {
    ulong peer_idx = deadline_list_iter_idx( iter, list, ssping->pool );
    fd_ssping_peer_t * peer = peer_pool_ele( ssping->pool, peer_idx );
    if( peer->deadline_nanos>until ) break;

    int fdesc =  ssping->idle_fds[ FD_SSPING_FD_CNT-ssping->used_fd_cnt-1UL ];

    struct sockaddr_in addr[1] = {{
      .sin_family = AF_INET,
      .sin_addr   = { .s_addr = peer->addr.addr },
      .sin_port   = peer->addr.port
    }};

    if( FD_UNLIKELY( connect( fdesc, addr, sizeof(addr) ) && errno!=EINPROGRESS ) ) {
      FD_LOG_WARNING(( "connect(" FD_IP4_ADDR_FMT ":%hu) failed (%d-%s)", FD_IP4_ADDR_FMT_ARGS( peer->addr.addr ), fd_ushort_bswap( peer->addr.port ), errno, fd_io_strerror( errno ) ));
      /* Nothing to do.  It will get "reaped" later. */
    }

    ssping->used_fds    [ ssping->used_fd_cnt ].fd = fdesc;
    ssping->ping_to_pool[ ssping->used_fd_cnt ]    = peer_idx;
    peer->used_fd_idx = ssping->used_fd_cnt;
    ssping->used_fd_cnt++;
    msg_cnt++;
  }

  if( msg_cnt==0U ) return 0U;
  return (uint)msg_cnt;
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

    remove_fdesc_idx( ssping, peer->used_fd_idx );

    peer->state = PEER_STATE_INVALID;
    peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
    deadline_list_ele_push_tail( ssping->invalid, peer, ssping->pool );
    fd_sspeer_selector_remove_by_addr( selector, peer->addr );
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

    remove_fdesc_idx( ssping, peer->used_fd_idx );

    peer->state = PEER_STATE_INVALID;
    peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
    deadline_list_ele_push_tail( ssping->invalid, peer, ssping->pool );
    fd_sspeer_selector_remove_by_addr( selector, peer->addr );
  }

  while( !deadline_list_is_empty( ssping->invalid, ssping->pool ) ) {
    fd_ssping_peer_t * peer = deadline_list_ele_peek_head( ssping->invalid, ssping->pool );
    if( FD_LIKELY( peer->deadline_nanos>now ) ) break;

    deadline_list_ele_pop_head( ssping->invalid, ssping->pool );

    peer->state = PEER_STATE_UNPINGED;
    peer->deadline_nanos = 0L;
    deadline_list_ele_push_tail( ssping->unpinged, peer, ssping->pool );
  }

  recv_pings( ssping, selector );
}

fd_ssping_sockfd_range_t
fd_ssping_get_sockfds( fd_ssping_t const * ssping ) {
  return ssping->ping_fds;
}
