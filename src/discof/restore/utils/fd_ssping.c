#include "fd_ssping.h"

#include "../../../util/fd_util.h"
#include "../../../util/bits/fd_bits.h"
#include "../../../util/log/fd_log.h"

#include <poll.h>
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
    ulong parent;
    ulong left;
    ulong right;
    ulong prio;
  } score_treap;

  struct {
    ulong next;
    ulong prev;
  } deadline;

  struct {
    ulong idx;
  } fd;

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

#define COMPARE_WORSE(x,y) ( (x)->latency_nanos<(y)->latency_nanos )

#define TREAP_T         fd_ssping_peer_t
#define TREAP_NAME      score_treap
#define TREAP_QUERY_T   void *                                         /* We don't use query ... */
#define TREAP_CMP(a,b)  (__extension__({ (void)(a); (void)(b); -1; })) /* which means we don't need to give a real
                                                                          implementation to cmp either */
#define TREAP_IDX_T     ulong
#define TREAP_LT        COMPARE_WORSE
#define TREAP_PARENT    score_treap.parent
#define TREAP_LEFT      score_treap.left
#define TREAP_RIGHT     score_treap.right
#define TREAP_PRIO      score_treap.prio
#include "../../../util/tmpl/fd_treap.c"

#define DLIST_NAME  deadline_list
#define DLIST_ELE_T fd_ssping_peer_t
#define DLIST_PREV  deadline.prev
#define DLIST_NEXT  deadline.next

#include "../../../util/tmpl/fd_dlist.c"

struct fd_ssping_private {
  fd_ssping_peer_t * pool;
  peer_map_t *       map;
  score_treap_t *    score_treap;

  deadline_list_t *  unpinged;
  deadline_list_t *  pinged;
  deadline_list_t *  valid;
  deadline_list_t *  refreshing;
  deadline_list_t *  invalid;

  ulong              fds_len;
  struct pollfd *    fds;
  ulong *            fds_idx;

  ulong              magic; /* ==FD_SSPING_MAGIC */
};

FD_FN_CONST ulong
fd_ssping_align( void ) {
  return FD_SSPING_ALIGN;
}

FD_FN_CONST ulong
fd_ssping_footprint( ulong max_peers ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_SSPING_ALIGN,       sizeof(fd_ssping_t) );
  l = FD_LAYOUT_APPEND( l, peer_pool_align(),     peer_pool_footprint( max_peers ) );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),      peer_map_footprint( max_peers ) );
  l = FD_LAYOUT_APPEND( l, score_treap_align(),   score_treap_footprint( max_peers ) );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, sizeof(struct pollfd), max_peers*sizeof(struct pollfd) );
  l = FD_LAYOUT_APPEND( l, sizeof(ulong),         max_peers*sizeof(ulong) );
  return FD_LAYOUT_FINI( l, FD_SSPING_ALIGN );
}

void *
fd_ssping_new( void * shmem,
               ulong  max_peers,
               ulong  seed ) {
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
  fd_ssping_t * ssping = FD_SCRATCH_ALLOC_APPEND( l, FD_SSPING_ALIGN,     sizeof(fd_ssping_t) );
  void * _pool         = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(),   peer_pool_footprint( max_peers ) );
  void * _map          = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),    peer_map_footprint( max_peers ) );
  void * _score_treap  = FD_SCRATCH_ALLOC_APPEND( l, score_treap_align(), score_treap_footprint( max_peers ) );
  void * _unpinged     = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _pinged       = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _valid        = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _refreshing   = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _invalid      = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  struct pollfd * fds  = FD_SCRATCH_ALLOC_APPEND( l, sizeof(struct pollfd), max_peers*sizeof(struct pollfd) );
  ulong * fds_idx      = FD_SCRATCH_ALLOC_APPEND( l, sizeof(ulong), max_peers*sizeof(ulong) );

  ssping->pool = peer_pool_join( peer_pool_new( _pool, max_peers ) );
  ssping->map = peer_map_join( peer_map_new( _map, max_peers, seed ) );
  ssping->score_treap = score_treap_join( score_treap_new( _score_treap, max_peers ) );

  ssping->unpinged   = deadline_list_join( deadline_list_new( _unpinged ) );
  ssping->pinged     = deadline_list_join( deadline_list_new( _pinged ) );
  ssping->valid      = deadline_list_join( deadline_list_new( _valid ) );
  ssping->refreshing = deadline_list_join( deadline_list_new( _refreshing ) );
  ssping->invalid    = deadline_list_join( deadline_list_new( _invalid ) );

  ssping->fds_len = 0UL;
  ssping->fds     = fds;
  ssping->fds_idx = fds_idx;

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
    if( FD_UNLIKELY( !peer_pool_free( ssping->pool ) ) ) return;
    peer = peer_pool_ele_acquire( ssping->pool );
    FD_TEST( peer );
    peer->refcnt = 0UL;
    peer->state  = PEER_STATE_UNPINGED;
    peer->addr   = addr;
    peer_map_ele_insert( ssping->map, peer, ssping->pool );
    deadline_list_ele_push_tail( ssping->unpinged, peer, ssping->pool );
  }
  peer->refcnt++;
}

static inline void
remove_ping_fd( fd_ssping_t * ssping,
                ulong         idx ) {
  FD_TEST( idx<ssping->fds_len );

  if( FD_UNLIKELY( ssping->fds_len==1UL ) ) {
    ssping->fds_len = 0UL;
    return;
  }

  ssping->fds[ idx ] = ssping->fds[ ssping->fds_len-1UL ];
  ssping->fds_idx[ idx ] = ssping->fds_idx[ ssping->fds_len-1UL ];

  fd_ssping_peer_t * peer = peer_pool_ele( ssping->pool, ssping->fds_idx[ idx ] );
  peer->fd.idx = idx;

  ssping->fds_len--;
}

void
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
        remove_ping_fd( ssping, peer->fd.idx );
        deadline_list_ele_remove( ssping->pinged, peer, ssping->pool );
        break;
      case PEER_STATE_VALID:
        score_treap_ele_remove( ssping->score_treap, peer, ssping->pool );
        deadline_list_ele_remove( ssping->valid, peer, ssping->pool );
        break;
      case PEER_STATE_REFRESHING:
        remove_ping_fd( ssping, peer->fd.idx );
        score_treap_ele_remove( ssping->score_treap, peer, ssping->pool );
        deadline_list_ele_remove( ssping->refreshing, peer, ssping->pool );
        break;
      case PEER_STATE_INVALID:
        deadline_list_ele_remove( ssping->invalid, peer, ssping->pool );
        break;
    }
    peer_map_ele_remove_fast( ssping->map, peer, ssping->pool );
    peer_pool_ele_release( ssping->pool, peer );
  }
}

static inline void
unping_peer( fd_ssping_t *      ssping,
             fd_ssping_peer_t * peer,
             long               now ) {
  FD_TEST( peer->state==PEER_STATE_PINGED || peer->state==PEER_STATE_REFRESHING );

  remove_ping_fd( ssping, peer->fd.idx );
  if( FD_UNLIKELY( peer->state==PEER_STATE_PINGED ) ) {
    deadline_list_ele_remove( ssping->pinged, peer, ssping->pool );
  } else if( FD_UNLIKELY( peer->state==PEER_STATE_REFRESHING ) ) {
    score_treap_ele_remove( ssping->score_treap, peer, ssping->pool );
    deadline_list_ele_remove( ssping->refreshing, peer, ssping->pool );
  }
  peer->state = PEER_STATE_INVALID;
  peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
  deadline_list_ele_push_tail( ssping->invalid, peer, ssping->pool );
}

void
fd_ssping_invalidate( fd_ssping_t * ssping,
                      fd_ip4_port_t addr,
                      long          now ) {
  fd_ssping_peer_t * peer = peer_map_ele_query( ssping->map, &addr, NULL, ssping->pool );
  if( FD_UNLIKELY( !peer ) ) return;

  if( FD_UNLIKELY( peer->state==PEER_STATE_PINGED || peer->state==PEER_STATE_REFRESHING ) ) {
    unping_peer( ssping, peer, now );
  } else {
    FD_TEST( peer->state==PEER_STATE_UNPINGED || peer->state==PEER_STATE_VALID );
    if( FD_LIKELY( peer->state==PEER_STATE_UNPINGED ) ) {
      deadline_list_ele_remove( ssping->unpinged, peer, ssping->pool );
    } else if( FD_UNLIKELY( peer->state==PEER_STATE_VALID ) ) {
      score_treap_ele_remove( ssping->score_treap, peer, ssping->pool );
      deadline_list_ele_remove( ssping->valid, peer, ssping->pool );
    }
    peer->state = PEER_STATE_INVALID;
    peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
    deadline_list_ele_push_tail( ssping->invalid, peer, ssping->pool );
  }
}

static inline void
poll_advance( fd_ssping_t * ssping,
              long          now ) {
  if( FD_LIKELY( !ssping->fds_len ) ) return;

  int nfds = fd_syscall_poll( ssping->fds, (uint)ssping->fds_len, 0 );
  if( FD_LIKELY( !nfds ) ) return;
  else if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) return;
  else if( FD_UNLIKELY( -1==nfds ) ) FD_LOG_ERR(( "poll failed (%i-%s)", errno, strerror( errno ) ));

  for( ulong i=0UL; i<ssping->fds_len; i++ ) {
    struct pollfd * pfd = &ssping->fds[ i ];
    if( FD_UNLIKELY( pfd->revents & (POLLERR|POLLHUP) ) ) {
      unping_peer( ssping, peer_pool_ele( ssping->pool, ssping->fds_idx[ i ] ), now );
      continue;
    }

    if( FD_LIKELY( pfd->revents & POLLOUT ) ) {
      struct icmphdr icmp_hdr = (struct icmphdr){
        .type             = ICMP_ECHO,
        .code             = 0,
        .un.echo.id       = 0, /* Automatically set by kernel for a ping socket */
        .un.echo.sequence = 0, /* Only one ping goes out per socket, so nothing to change */
        .checksum         = 0  /* Will be calculated by the kernel */
      };

      long result = sendto( pfd->fd, &icmp_hdr, sizeof(icmp_hdr), 0, NULL, 0 );
      if( FD_UNLIKELY( !result ) ) continue;
      if( FD_UNLIKELY( -1==result && errno==EAGAIN ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) {
        unping_peer( ssping, peer_pool_ele( ssping->pool, ssping->fds_idx[ i ] ), now );
        continue;
      }
      pfd->revents &= ~POLLOUT;
    }

    if( FD_LIKELY( pfd->revents & POLLIN ) ) {
      struct icmphdr icmp_hdr;
      long result = recvfrom( pfd->fd, &icmp_hdr, sizeof(icmp_hdr), 0, NULL, 0 );

      if( FD_UNLIKELY( -1==result && errno==EAGAIN ) ) continue;
      else if( FD_UNLIKELY( -1==result || (ulong)result<sizeof(icmp_hdr) || icmp_hdr.type!=ICMP_ECHOREPLY ) ) {
        unping_peer( ssping, peer_pool_ele( ssping->pool, ssping->fds_idx[ i ] ), now );
        continue;
      }

      fd_ssping_peer_t * peer = peer_pool_ele( ssping->pool, ssping->fds_idx[ i ] );
      FD_TEST( peer->deadline_nanos>now );
      peer->latency_nanos = PEER_DEADLINE_NANOS_PING - (ulong)(peer->deadline_nanos - now);

      if( FD_LIKELY( peer->state==PEER_STATE_REFRESHING ) ) {
        score_treap_ele_remove( ssping->score_treap, peer, ssping->pool );
      }

      FD_LOG_INFO(( "pinged " FD_IP4_ADDR_FMT ":%hu in %lu ns", FD_IP4_ADDR_FMT_ARGS( peer->addr.addr ), fd_ushort_bswap( peer->addr.port ), peer->latency_nanos ));
      peer->state = PEER_STATE_VALID;
      peer->deadline_nanos = now + PEER_DEADLINE_NANOS_VALID;

      deadline_list_ele_remove( ssping->pinged, peer, ssping->pool );
      deadline_list_ele_push_tail( ssping->valid, peer, ssping->pool );
      score_treap_ele_insert( ssping->score_treap, peer, ssping->pool );
      remove_ping_fd( ssping, i );
    }
  }
}

static int
peer_connect( fd_ssping_t *      ssping,
              fd_ssping_peer_t * peer ) {
  FD_LOG_WARNING(("PEER CONNECT"));

  int sockfd = socket( PF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_ICMP );
  if( FD_UNLIKELY( -1==sockfd ) ) FD_LOG_ERR(( "socket failed (%i-%s)", errno, strerror( errno ) ));

  FD_LOG_WARNING(("PEER CONNECT %d", sockfd));


  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port   = peer->addr.port,
    .sin_addr   = { .s_addr = peer->addr.addr }
  };

  if( FD_UNLIKELY( -1==connect( sockfd, fd_type_pun( &addr ), sizeof(addr) ) && errno!=EINPROGRESS ) ) {
    if( FD_UNLIKELY( -1==close( sockfd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  ssping->fds[ ssping->fds_len ] = (struct pollfd){
    .fd      = sockfd,
    .events  = POLLIN|POLLOUT,
    .revents = 0
  };
  ssping->fds_idx[ ssping->fds_len ] = peer_pool_idx( ssping->pool, peer );
  peer->fd.idx = ssping->fds_len;
  ssping->fds_len++;

  return 0;
}

void
fd_ssping_advance( fd_ssping_t * ssping,
                   long          now ) {

  while( !deadline_list_is_empty( ssping->unpinged, ssping->pool ) ) {
    fd_ssping_peer_t * peer = deadline_list_ele_pop_head( ssping->unpinged, ssping->pool );

    FD_LOG_INFO(( "pinging " FD_IP4_ADDR_FMT ":%hu", FD_IP4_ADDR_FMT_ARGS( peer->addr.addr ), fd_ushort_bswap( peer->addr.port ) ));
    int result = peer_connect( ssping, peer );
    if( FD_UNLIKELY( -1==result ) ) {
      peer->state = PEER_STATE_INVALID;
      peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
      deadline_list_ele_push_tail( ssping->invalid, peer, ssping->pool );
    } else {
      peer->state = PEER_STATE_PINGED;
      peer->deadline_nanos = now + PEER_DEADLINE_NANOS_PING;
      deadline_list_ele_push_tail( ssping->pinged, peer, ssping->pool );
    }
  }

  while( !deadline_list_is_empty( ssping->pinged, ssping->pool ) ) {
    fd_ssping_peer_t * peer = deadline_list_ele_peek_head( ssping->pinged, ssping->pool );
    if( FD_LIKELY( peer->deadline_nanos>now ) ) break;

    deadline_list_ele_pop_head( ssping->pinged, ssping->pool );

    peer->state = PEER_STATE_INVALID;
    peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
    deadline_list_ele_push_tail( ssping->invalid, peer, ssping->pool );
    remove_ping_fd( ssping, peer->fd.idx );
  }

  while( !deadline_list_is_empty( ssping->valid, ssping->pool ) ) {
    fd_ssping_peer_t * peer = deadline_list_ele_peek_head( ssping->valid, ssping->pool );
    if( FD_LIKELY( peer->deadline_nanos>now ) ) break;

    deadline_list_ele_pop_head( ssping->valid, ssping->pool );

    int result = peer_connect( ssping, peer );
    if( FD_UNLIKELY( -1==result ) ) {
      peer->state = PEER_STATE_INVALID;
      peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
      score_treap_ele_remove( ssping->score_treap, peer, ssping->pool );
      deadline_list_ele_push_tail( ssping->invalid, peer, ssping->pool );
    } else {
      peer->state = PEER_STATE_REFRESHING;
      peer->deadline_nanos = now + PEER_DEADLINE_NANOS_PING;
      deadline_list_ele_push_tail( ssping->refreshing, peer, ssping->pool );
    }
  }

  while( !deadline_list_is_empty( ssping->refreshing, ssping->pool ) ) {
    fd_ssping_peer_t * peer = deadline_list_ele_peek_head( ssping->refreshing, ssping->pool );
    if( FD_LIKELY( peer->deadline_nanos>now ) ) break;

    deadline_list_ele_pop_head( ssping->refreshing, ssping->pool );

    peer->state = PEER_STATE_INVALID;
    peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
    deadline_list_ele_push_tail( ssping->invalid, peer, ssping->pool );
    score_treap_ele_remove( ssping->score_treap, peer, ssping->pool );
    remove_ping_fd( ssping, peer->fd.idx );
  }

  while( !deadline_list_is_empty( ssping->invalid, ssping->pool ) ) {
    fd_ssping_peer_t * peer = deadline_list_ele_peek_head( ssping->invalid, ssping->pool );
    if( FD_LIKELY( peer->deadline_nanos>now ) ) break;

    deadline_list_ele_pop_head( ssping->invalid, ssping->pool );

    peer->state = PEER_STATE_UNPINGED;
    peer->deadline_nanos = 0L;
    deadline_list_ele_push_tail( ssping->unpinged, peer, ssping->pool );
  }

  poll_advance( ssping, now );
}

fd_ip4_port_t
fd_ssping_best( fd_ssping_t const * ssping ) {
  score_treap_fwd_iter_t iter = score_treap_fwd_iter_init( ssping->score_treap, ssping->pool );
  if( FD_UNLIKELY( score_treap_fwd_iter_done( iter ) ) ) return (fd_ip4_port_t){ .l=0UL };

  fd_ssping_peer_t const * best = score_treap_fwd_iter_ele_const( iter, ssping->pool );
  return best->addr;
}
