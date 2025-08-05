#define _GNU_SOURCE
#include "fd_ssping.h"
#include "fd_ssresolve.h"

#include "../../../util/bits/fd_bits.h"
#include "../../../util/log/fd_log.h"

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#define PEER_STATE_UNPINGED   0
#define PEER_STATE_PINGED     1
#define PEER_STATE_VALID      2
#define PEER_STATE_REFRESHING 3
#define PEER_STATE_INVALID    4

#define PEER_DEADLINE_NANOS_PING    (2L*1000L*1000L*1000L)     /* 2 seconds */
#define PEER_DEADLINE_NANOS_VALID   (2L*60L*1000L*1000L*1000L) /* 2 minutes */
#define PEER_DEADLINE_NANOS_INVALID (5L*60L*1000L*1000L*1000L) /* 5 minutes */

struct fd_ssping_peer {
  ulong            refcnt;
  fd_ip4_port_t    addr;

  fd_ssresolve_t * full_ssresolve;
  fd_ssresolve_t * inc_ssresolve;

  fd_ssinfo_t      snapshot_info;

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
  ulong full_latency_nanos;
  ulong incremental_latency_nanos;
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
  l = FD_LAYOUT_APPEND( l, sizeof(struct pollfd), max_peers*sizeof(struct pollfd)*2UL );
  l = FD_LAYOUT_APPEND( l, sizeof(ulong),         max_peers*sizeof(ulong)*2UL );

  for( ulong i=0UL; i<max_peers*2UL; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_ssresolve_align(), fd_ssresolve_footprint() );
  }

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
  fd_ssping_t * ssping = FD_SCRATCH_ALLOC_APPEND( l, FD_SSPING_ALIGN,       sizeof(fd_ssping_t) );
  void * _pool         = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(),     peer_pool_footprint( max_peers ) );
  void * _map          = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),      peer_map_footprint( max_peers ) );
  void * _score_treap  = FD_SCRATCH_ALLOC_APPEND( l, score_treap_align(),   score_treap_footprint( max_peers ) );
  void * _unpinged     = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _pinged       = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _valid        = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _refreshing   = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _invalid      = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  struct pollfd * _fds = FD_SCRATCH_ALLOC_APPEND( l, sizeof(struct pollfd), max_peers*sizeof(struct pollfd)*2UL );
  ulong * fds_idx      = FD_SCRATCH_ALLOC_APPEND( l, sizeof(ulong), max_peers*sizeof(ulong)*2UL );

  ssping->pool        = peer_pool_join( peer_pool_new( _pool, max_peers ) );
  ssping->map         = peer_map_join( peer_map_new( _map, max_peers, seed ) );
  ssping->score_treap = score_treap_join( score_treap_new( _score_treap, max_peers ) );

  ssping->unpinged   = deadline_list_join( deadline_list_new( _unpinged ) );
  ssping->pinged     = deadline_list_join( deadline_list_new( _pinged ) );
  ssping->valid      = deadline_list_join( deadline_list_new( _valid ) );
  ssping->refreshing = deadline_list_join( deadline_list_new( _refreshing ) );
  ssping->invalid    = deadline_list_join( deadline_list_new( _invalid ) );

  ssping->fds_len  = 0UL;
  ssping->fds      = _fds;
  ssping->fds_idx  = fds_idx;

  FD_TEST( peer_pool_max( ssping->pool )==max_peers );
  for( ulong i=0UL; i<peer_pool_max( ssping->pool ); i++ ) {
    void * _full_ssresolve = FD_SCRATCH_ALLOC_APPEND( l, fd_ssresolve_align(), fd_ssresolve_footprint() );
    void * _inc_ssresolve  = FD_SCRATCH_ALLOC_APPEND( l, fd_ssresolve_align(), fd_ssresolve_footprint() );
    ssping->pool[ i ].full_ssresolve = fd_ssresolve_join( fd_ssresolve_new( _full_ssresolve ) );
    ssping->pool[ i ].inc_ssresolve  = fd_ssresolve_join( fd_ssresolve_new( _inc_ssresolve ) );
  }

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
    peer->snapshot_info.full.slot             = ULONG_MAX;
    peer->snapshot_info.incremental.base_slot = ULONG_MAX;
    peer->snapshot_info.incremental.slot      = ULONG_MAX;
    peer->full_latency_nanos        = 0UL;
    peer->incremental_latency_nanos = 0UL;
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

  ulong full_idx = idx;
  ulong inc_idx  = idx+1UL;

  ssping->fds[ inc_idx ]     = ssping->fds[ ssping->fds_len-1UL ];
  ssping->fds_idx[ inc_idx ] = ssping->fds_idx[ ssping->fds_len-1UL ];
  ssping->fds_len--;

  ssping->fds[ full_idx ]     = ssping->fds[ ssping->fds_len-1UL ];
  ssping->fds_idx[ full_idx ] = ssping->fds_idx[ ssping->fds_len-1UL ];
  ssping->fds_len--;

  FD_TEST( ssping->fds_idx[ full_idx ]== ssping->fds_idx[ inc_idx ] );
  fd_ssping_peer_t * peer = peer_pool_ele( ssping->pool, ssping->fds_idx[ full_idx ] );
  peer->fd.idx = full_idx;
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

  int nfds = poll( ssping->fds, ssping->fds_len, 0 );
  if( FD_LIKELY( !nfds ) ) return;
  else if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) return;
  else if( FD_UNLIKELY( -1==nfds ) ) FD_LOG_ERR(( "poll failed (%i-%s)", errno, strerror( errno ) ));

  for( ulong i=0UL; i<ssping->fds_len; i++ ) {
    fd_ssping_peer_t * peer = peer_pool_ele( ssping->pool, ssping->fds_idx[ i ] );
    struct pollfd * pfd = &ssping->fds[ i ];
    if( FD_UNLIKELY( pfd->revents & (POLLERR|POLLHUP) ) ) {
      unping_peer( ssping, peer_pool_ele( ssping->pool, ssping->fds_idx[ i ] ), now );
      continue;
    }

    int full = i&1UL ? 0 : 1; /* even indices are full, odd indices are incremental */
    fd_ssresolve_t * ssresolve = full ? peer->full_ssresolve : peer->inc_ssresolve;
    if( FD_UNLIKELY( now>peer->deadline_nanos ) ) {
      unping_peer( ssping, peer, now );
      continue;
    }

    if( FD_LIKELY( !fd_ssresolve_is_done( ssresolve ) ) ) {
      if( FD_LIKELY( pfd->revents & POLLOUT ) ) {
        int res = fd_ssresolve_advance_poll_out( ssresolve );

        if( FD_UNLIKELY( res==FD_SSRESOLVE_ADVANCE_ERROR ) ) {
          unping_peer( ssping, peer_pool_ele( ssping->pool, ssping->fds_idx[ i ] ), now );
          continue;
        }

        pfd->revents &= ~POLLOUT;
      }

      if( FD_LIKELY( pfd->revents & POLLIN ) ) {
        fd_ssresolve_result_t resolve_result;
        int res = fd_ssresolve_advance_poll_in( ssresolve, &resolve_result );

        if( FD_UNLIKELY( res==FD_SSRESOLVE_ADVANCE_ERROR ) ) {
          unping_peer( ssping, peer_pool_ele( ssping->pool, ssping->fds_idx[ i ] ), now );
          continue;
        } else if( FD_UNLIKELY( res==FD_SSRESOLVE_ADVANCE_AGAIN ) ) {
          continue;
        } else { /* FD_SSRESOLVE_ADVANCE_SUCCESS */
          FD_TEST( peer->deadline_nanos>now );

          if( resolve_result.base_slot==ULONG_MAX ) {
            peer->snapshot_info.full.slot = resolve_result.slot;
            memcpy( &peer->snapshot_info.full.hash, &resolve_result.hash, sizeof(fd_hash_t) );
            peer->full_latency_nanos = PEER_DEADLINE_NANOS_PING - (ulong)(peer->deadline_nanos - now);
          } else {
            peer->snapshot_info.incremental.base_slot = resolve_result.base_slot;
            peer->snapshot_info.incremental.slot      = resolve_result.slot;
            memcpy( &peer->snapshot_info.incremental.hash, &resolve_result.hash, sizeof(fd_hash_t) );
            peer->incremental_latency_nanos = PEER_DEADLINE_NANOS_PING - (ulong)(peer->deadline_nanos - now);          }
        }
      }
    }

    /* Once both the full and incremental snapshots are resolved, we can
       mark the peer valid and remove the peer from the list of peers to
       ping. */
    if( fd_ssresolve_is_done( peer->full_ssresolve ) &&
        fd_ssresolve_is_done( peer->inc_ssresolve ) ) {
      FD_LOG_NOTICE(("successfully resolved snapshots for peer " FD_IP4_ADDR_FMT ":%hu "
                    "with full slot %lu, incremental base slot %lu and incremental slot %lu",
                    FD_IP4_ADDR_FMT_ARGS( peer->addr.addr ), peer->addr.port,
                    peer->snapshot_info.full.slot,
                    peer->snapshot_info.incremental.base_slot,
                    peer->snapshot_info.incremental.slot ));
      peer->latency_nanos = (peer->full_latency_nanos + peer->incremental_latency_nanos) / 2UL;
      FD_LOG_NOTICE(( "full latency is %lu, incremental latency is %lu, latency is %lu",
                      peer->full_latency_nanos, peer->incremental_latency_nanos, peer->latency_nanos ));

      if( FD_LIKELY( peer->state==PEER_STATE_REFRESHING ) ) {
        score_treap_ele_remove( ssping->score_treap, peer, ssping->pool );
      }

      FD_LOG_INFO(( "pinged " FD_IP4_ADDR_FMT ":%hu in %lu ns", FD_IP4_ADDR_FMT_ARGS( peer->addr.addr ), peer->addr.port, peer->latency_nanos ));
      peer->state = PEER_STATE_VALID;
      peer->deadline_nanos = now + PEER_DEADLINE_NANOS_VALID;

      deadline_list_ele_remove( ssping->pinged, peer, ssping->pool );
      deadline_list_ele_push_tail( ssping->valid, peer, ssping->pool );
      score_treap_ele_insert( ssping->score_treap, peer, ssping->pool );
      remove_ping_fd( ssping, peer->fd.idx );
    }
  }
}

static int
create_socket( fd_ssping_t *      ssping,
               fd_ssping_peer_t * peer ) {
  int sockfd = socket( PF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==sockfd ) ) FD_LOG_ERR(( "socket failed (%i-%s)", errno, strerror( errno ) ));

  int optval = 1;
  if( FD_UNLIKELY( -1==setsockopt( sockfd, SOL_TCP, TCP_NODELAY, &optval, sizeof(int) ) ) ) {
    FD_LOG_ERR(( "setsockopt() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port   = fd_ushort_bswap( peer->addr.port ),
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

  return 0;
}

static int
peer_connect( fd_ssping_t *      ssping,
              fd_ssping_peer_t * peer ) {
  int err;
  err = create_socket( ssping, peer ); /* full */
  if( FD_UNLIKELY( err ) ) return err;
  ssping->fds_idx[ ssping->fds_len ] = peer_pool_idx( ssping->pool, peer );
  peer->fd.idx = ssping->fds_len;
  ssping->fds_len++;

  err = create_socket( ssping, peer ); /* incremental */
  if( FD_UNLIKELY( err ) ) return err;
  ssping->fds_idx[ ssping->fds_len ] = peer_pool_idx( ssping->pool, peer );
  ssping->fds_len++;

  fd_ssresolve_init( peer->full_ssresolve, peer->addr, ssping->fds[ peer->fd.idx ].fd, 1 );
  fd_ssresolve_init( peer->inc_ssresolve, peer->addr, ssping->fds[ peer->fd.idx+1UL ].fd, 0 );

  return 0;
}

void
fd_ssping_advance( fd_ssping_t * ssping,
                   long          now ) {
  while( !deadline_list_is_empty( ssping->unpinged, ssping->pool ) ) {
    fd_ssping_peer_t * peer = deadline_list_ele_pop_head( ssping->unpinged, ssping->pool );

    FD_LOG_INFO(( "pinging " FD_IP4_ADDR_FMT ":%hu", FD_IP4_ADDR_FMT_ARGS( peer->addr.addr ), peer->addr.port ));
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

fd_sspeer_t
fd_ssping_best( fd_ssping_t const * ssping ) {
  score_treap_fwd_iter_t iter = score_treap_fwd_iter_init( ssping->score_treap, ssping->pool );
  if( FD_UNLIKELY( score_treap_fwd_iter_done( iter ) ) ) {
    return (fd_sspeer_t){ 
      .addr = {
        .l = 0UL
      },
      .snapshot_info = NULL,
    };
  }

  fd_ssping_peer_t const * best = score_treap_fwd_iter_ele_const( iter, ssping->pool );

  return (fd_sspeer_t){
    .addr = best->addr,
    .snapshot_info = &best->snapshot_info,
  };
}
