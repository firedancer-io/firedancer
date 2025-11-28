#include "fd_http_resolver.h"
#include "fd_ssresolve.h"

#include "../../../util/log/fd_log.h"
#include "../../../util/fd_util.h"

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#if FD_HAS_OPENSSL
#include <openssl/ssl.h>
#include "../../../waltz/openssl/fd_openssl_tile.h"
#endif

#define PEER_STATE_UNRESOLVED (0)
#define PEER_STATE_REFRESHING (1)
#define PEER_STATE_VALID      (2)
#define PEER_STATE_INVALID    (3)

#define PEER_DEADLINE_NANOS_VALID   (5L*1000L*1000L*1000L) /* 5 seconds */
#define PEER_DEADLINE_NANOS_RESOLVE (2L*1000L*1000L*1000L) /* 2 seconds */
#define PEER_DEADLINE_NANOS_INVALID (5L*1000L*1000L*1000L) /* 5 seconds */

/* FIXME: The fds/fds_len/idx logic is fragile, replace with something
   that duplicates less state / etc. */

struct fd_ssresolve_peer {
  fd_ip4_port_t addr;
  char const *  hostname;
  int           is_https;
  fd_ssinfo_t   ssinfo;

  fd_ssresolve_t * full_ssresolve;
  fd_ssresolve_t * inc_ssresolve;

  struct {
    ulong next;
  } pool;

  struct {
    ulong next;
    ulong prev;
  } deadline;

  struct {
    ulong idx;
  } fd;

  int  state;
  long deadline_nanos;
};
typedef struct fd_ssresolve_peer fd_ssresolve_peer_t;

#define POOL_NAME  peer_pool
#define POOL_T     fd_ssresolve_peer_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../../util/tmpl/fd_pool.c"

#define DLIST_NAME  deadline_list
#define DLIST_ELE_T fd_ssresolve_peer_t
#define DLIST_PREV  deadline.prev
#define DLIST_NEXT  deadline.next
#include "../../../util/tmpl/fd_dlist.c"

struct fd_http_resolver_private {
  fd_ssresolve_peer_t *            pool;
  deadline_list_t *                unresolved;
  deadline_list_t *                resolving;
  deadline_list_t *                valid;
  deadline_list_t *                invalid;

  ulong                            fds_len;
  struct pollfd *                  fds;
  ulong *                          fds_idx;

  int                              incremental_snapshot_fetch;

  void *                           cb_arg;
  fd_http_resolver_on_resolve_fn_t on_resolve_cb;

#if FD_HAS_OPENSSL
  SSL_CTX * ssl_ctx;
#endif

  ulong                            magic; /* ==FD_HTTP_RESOLVER_MAGIC */
};

FD_FN_CONST ulong
fd_http_resolver_align( void ) {
  return fd_ulong_max( alignof(fd_http_resolver_t), fd_ulong_max( peer_pool_align(), fd_ulong_max( deadline_list_align(), fd_ulong_max( alignof(struct pollfd), alignof(ulong) ) ) ) );
}

FD_FN_CONST ulong
fd_http_resolver_footprint( ulong peers_cnt ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_http_resolver_t), sizeof(fd_http_resolver_t) );
  l = FD_LAYOUT_APPEND( l, peer_pool_align(),           peer_pool_footprint( peers_cnt ) );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(),       deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(),       deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(),       deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, deadline_list_align(),       deadline_list_footprint() );
  l = FD_LAYOUT_APPEND( l, alignof(struct pollfd),      2UL*peers_cnt*sizeof(struct pollfd) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),              2UL*peers_cnt*sizeof(ulong) );

  for( ulong i=0UL; i<peers_cnt*2UL; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_ssresolve_align(), fd_ssresolve_footprint() );
  }
  return FD_LAYOUT_FINI( l, fd_http_resolver_align() );
}

void *
fd_http_resolver_new( void *                           shmem,
                      ulong                            peers_cnt,
                      int                              incremental_snapshot_fetch,
                      fd_http_resolver_on_resolve_fn_t on_resolve_cb,
                      void *                           cb_arg ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_http_resolver_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( peers_cnt<1UL ) ) {
    FD_LOG_WARNING(( "max_peers must be at least 1" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_http_resolver_t * resolver = FD_SCRATCH_ALLOC_APPEND( l, fd_http_resolver_align(), sizeof(fd_http_resolver_t) );
  void * _pool        = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(), peer_pool_footprint( peers_cnt ) );
  void * _unresolved  = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _resolving   = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _invalid     = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  void * _valid       = FD_SCRATCH_ALLOC_APPEND( l, deadline_list_align(), deadline_list_footprint() );
  struct pollfd * fds = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct pollfd), 2UL*peers_cnt*sizeof(struct pollfd) );
  ulong * fds_idx     = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), 2UL*peers_cnt*sizeof(ulong) );

  resolver->pool       = peer_pool_join( peer_pool_new( _pool, peers_cnt ) );
  resolver->unresolved = deadline_list_join( deadline_list_new( _unresolved ) );
  resolver->resolving  = deadline_list_join( deadline_list_new( _resolving ) );
  resolver->invalid    = deadline_list_join( deadline_list_new( _invalid ) );
  resolver->valid      = deadline_list_join( deadline_list_new( _valid ) );

  resolver->fds_len     = 0UL;
  resolver->fds         = fds;
  resolver->fds_idx     = fds_idx;

  for( ulong i=0UL; i<peer_pool_max( resolver->pool ); i++ ) {
    void * _full_ssresolve = FD_SCRATCH_ALLOC_APPEND( l, fd_ssresolve_align(), fd_ssresolve_footprint() );
    void * _inc_ssresolve  = FD_SCRATCH_ALLOC_APPEND( l, fd_ssresolve_align(), fd_ssresolve_footprint() );
    resolver->pool[ i ].full_ssresolve = fd_ssresolve_join( fd_ssresolve_new( _full_ssresolve ) );
    resolver->pool[ i ].inc_ssresolve  = fd_ssresolve_join( fd_ssresolve_new( _inc_ssresolve ) );
  }

  resolver->incremental_snapshot_fetch = incremental_snapshot_fetch;
  resolver->cb_arg                     = cb_arg;
  resolver->on_resolve_cb              = on_resolve_cb;

#if FD_HAS_OPENSSL
  SSL_CTX * ssl_ctx = SSL_CTX_new( TLS_client_method() );
  if( FD_UNLIKELY( !ssl_ctx ) ) {
    FD_LOG_ERR(( "SSL_CTX_new failed" ));
  }

  if( FD_UNLIKELY( !SSL_CTX_set_min_proto_version( ssl_ctx, TLS1_3_VERSION ) ) ) {
    FD_LOG_ERR(( "SSL_CTX_set_min_proto_version(ssl_ctx,TLS1_3_VERSION) failed" ));
  }

  /* transfering ownership of ssl_ctx by assignment */
  resolver->ssl_ctx = ssl_ctx;

  fd_ossl_load_certs( resolver->ssl_ctx );
#endif

  FD_COMPILER_MFENCE();
  FD_VOLATILE( resolver->magic ) = FD_HTTP_RESOLVER_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)resolver;
}

fd_http_resolver_t *
fd_http_resolver_join( void * shresolver ) {
  if( FD_UNLIKELY( !shresolver ) ) {
    FD_LOG_WARNING(( "NULL shresolver" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shresolver, fd_http_resolver_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shresolver" ));
    return NULL;
  }

  fd_http_resolver_t * resolver = (fd_http_resolver_t *)shresolver;

  if( FD_UNLIKELY( resolver->magic!=FD_HTTP_RESOLVER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return resolver;
}

void
fd_http_resolver_add( fd_http_resolver_t * resolver,
                      fd_ip4_port_t        addr,
                      char const *         hostname,
                      int                  is_https ) {
  if( !peer_pool_free( resolver->pool ) ) {
    FD_LOG_ERR(( "peer pool exhausted" ));
  }
  fd_ssresolve_peer_t * peer = peer_pool_ele_acquire( resolver->pool );
  peer->state                        = PEER_STATE_UNRESOLVED;
  peer->addr                         = addr;
  peer->hostname                     = hostname;
  peer->is_https                     = is_https;
  peer->fd.idx                       = ULONG_MAX;
  peer->ssinfo.full.slot             = ULONG_MAX;
  peer->ssinfo.incremental.base_slot = ULONG_MAX;
  peer->ssinfo.incremental.slot      = ULONG_MAX;
  deadline_list_ele_push_tail( resolver->unresolved, peer, resolver->pool );
}

static int
create_socket( fd_http_resolver_t *  resolver,
               fd_ssresolve_peer_t * peer ) {
  int sockfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==sockfd ) ) FD_LOG_ERR(( "socket failed (%i-%s)", errno, strerror( errno ) ));

  int optval = 1;
  if( FD_UNLIKELY( -1==setsockopt( sockfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(int) ) ) ) {
    FD_LOG_ERR(( "setsockopt() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port   = peer->addr.port,
    .sin_addr   = { .s_addr = peer->addr.addr }
  };

  if( FD_UNLIKELY( -1==connect( sockfd, fd_type_pun( &addr ), sizeof(addr) ) && errno!=EINPROGRESS ) ) {
    if( FD_UNLIKELY( -1==close( sockfd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  resolver->fds[ resolver->fds_len ] = (struct pollfd){
    .fd      = sockfd,
    .events  = POLLIN|POLLOUT,
    .revents = 0
  };

  return 0;
}

static int
peer_connect( fd_http_resolver_t *  resolver,
              fd_ssresolve_peer_t * peer ) {
  int err;
  err = create_socket( resolver, peer ); /* full */
  if( FD_UNLIKELY( err ) ) return err;
  resolver->fds_idx[ resolver->fds_len ] = peer_pool_idx( resolver->pool, peer );
  peer->fd.idx = resolver->fds_len;
  resolver->fds_len++;

  if( FD_UNLIKELY( peer->is_https ) ) {
#if FD_HAS_OPENSSL
    fd_ssresolve_init_https( peer->full_ssresolve, peer->addr, resolver->fds[ peer->fd.idx ].fd, 1, peer->hostname, resolver->ssl_ctx );
#else
    FD_LOG_ERR(( "peer %s requires https but firedancer is built without openssl support. Please remove this peer from your validator config.", peer->hostname ));
#endif
  } else {
    fd_ssresolve_init( peer->full_ssresolve, peer->addr, resolver->fds[ peer->fd.idx ].fd, 1 );
  }

  if( FD_LIKELY( resolver->incremental_snapshot_fetch ) ) {
    err = create_socket( resolver, peer ); /* incremental */
    if( FD_UNLIKELY( err ) ) return err;
    resolver->fds_idx[ resolver->fds_len ] = peer_pool_idx( resolver->pool, peer );
    resolver->fds_len++;
    if( FD_UNLIKELY( peer->is_https ) ) {
#if FD_HAS_OPENSSL
      fd_ssresolve_init_https( peer->inc_ssresolve, peer->addr, resolver->fds[ peer->fd.idx+1UL ].fd, 0, peer->hostname, resolver->ssl_ctx );
#else
      FD_LOG_ERR(( "peer requires https but firedancer is built without openssl support" ));
#endif
    } else {
      fd_ssresolve_init( peer->inc_ssresolve, peer->addr, resolver->fds[ peer->fd.idx+1UL ].fd, 0 );
    }
  } else {
    resolver->fds[ resolver->fds_len ] = (struct pollfd) {
      .fd      = -1,
      .events  = 0,
      .revents = 0
    };
    resolver->fds_idx[ resolver->fds_len ] = ULONG_MAX;
    resolver->fds_len++;
  }

  return 0;
}

static inline void
remove_peer( fd_http_resolver_t * resolver,
             ulong                idx ) {
  FD_TEST( idx<resolver->fds_len );

  fd_ssresolve_peer_t * cur_peer = peer_pool_ele( resolver->pool, resolver->fds_idx[ idx ] );
  fd_ssresolve_cancel( cur_peer->full_ssresolve );
  fd_ssresolve_cancel( cur_peer->inc_ssresolve );

  if( FD_UNLIKELY( resolver->fds_len==2UL ) ) {
    resolver->fds_len = 0UL;
    return;
  }

  resolver->fds[ idx ]     = resolver->fds[ resolver->fds_len-2UL ];
  resolver->fds_idx[ idx ] = resolver->fds_idx[ resolver->fds_len-2UL ];

  resolver->fds[ idx+1UL ]     = resolver->fds[ resolver->fds_len-1UL ];
  resolver->fds_idx[ idx+1UL ] = resolver->fds_idx[ resolver->fds_len-1UL ];

  fd_ssresolve_peer_t * peer = peer_pool_ele( resolver->pool, resolver->fds_idx[ idx ] );
  peer->fd.idx               = idx;

  resolver->fds_len -= 2UL;
}

static inline void
unresolve_peer( fd_http_resolver_t *  resolver,
                fd_ssresolve_peer_t * peer,
                long                  now ) {
  FD_TEST( peer->state==PEER_STATE_UNRESOLVED || peer->state==PEER_STATE_REFRESHING );
  remove_peer( resolver, peer->fd.idx );
  deadline_list_ele_remove( resolver->resolving, peer, resolver->pool );
  peer->state          = PEER_STATE_INVALID;
  peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
  deadline_list_ele_push_tail( resolver->invalid, peer, resolver->pool );
}

static inline int
poll_resolve( fd_http_resolver_t *  resolver,
              struct pollfd *       pfd,
              fd_ssresolve_peer_t * peer,
              fd_ssresolve_t *      ssresolve,
              ulong                 idx,
              long                  now ) {
  FD_TEST( !fd_ssresolve_is_done( ssresolve ) );
  if( FD_LIKELY( pfd->revents & POLLOUT ) ) {
    int res = fd_ssresolve_advance_poll_out( ssresolve );

    if( FD_UNLIKELY( res==FD_SSRESOLVE_ADVANCE_ERROR ) ) {
      unresolve_peer( resolver, peer_pool_ele( resolver->pool, resolver->fds_idx[ idx ] ), now );
      return -1;
    }
  }

  if( FD_LIKELY( pfd->revents & POLLIN ) ) {
    fd_ssresolve_result_t resolve_result;
    int res = fd_ssresolve_advance_poll_in( ssresolve, &resolve_result );

    if( FD_UNLIKELY( res==FD_SSRESOLVE_ADVANCE_ERROR ) ) {
      unresolve_peer( resolver, peer_pool_ele( resolver->pool, resolver->fds_idx[ idx ] ), now );
      return -1;
    } else if( FD_UNLIKELY( res==FD_SSRESOLVE_ADVANCE_AGAIN ) ) {
      return -1;
    } else if( FD_LIKELY( res==FD_SSRESOLVE_ADVANCE_RESULT ) ) {
      FD_TEST( peer->deadline_nanos>now );

      if( resolve_result.base_slot==ULONG_MAX ) {
        peer->ssinfo.full.slot = resolve_result.slot;
      } else {
        peer->ssinfo.incremental.base_slot = resolve_result.base_slot;
        peer->ssinfo.incremental.slot      = resolve_result.slot;
      }
    }
  }

  return 0;
}

static inline void
poll_advance( fd_http_resolver_t * resolver,
              long                 now ) {
  if( FD_LIKELY( !resolver->fds_len ) ) return;

  int nfds = fd_syscall_poll( resolver->fds, (uint)resolver->fds_len, 0 );
  if( FD_LIKELY( !nfds ) ) return;
  else if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) return;
  else if( FD_UNLIKELY( -1==nfds ) ) FD_LOG_ERR(( "poll failed (%i-%s)", errno, strerror( errno ) ));

  for( ulong i=0UL; i<resolver->fds_len; i++) {

    struct pollfd * pfd = &resolver->fds[ i ];
    if( FD_UNLIKELY( pfd->fd==-1 ) ) continue;
    if( FD_UNLIKELY( pfd->revents & (POLLERR|POLLHUP) ) ) {
      unresolve_peer( resolver, peer_pool_ele( resolver->pool, resolver->fds_idx[ i ] ), now );
      continue;
    }

    fd_ssresolve_peer_t * peer = peer_pool_ele( resolver->pool, resolver->fds_idx[ i ] );
    int                   full = i&1UL ? 0 : 1; /* even indices are full, odd indices are incremental */
    fd_ssresolve_t * ssresolve = full ? peer->full_ssresolve : peer->inc_ssresolve;

    if( FD_LIKELY( !fd_ssresolve_is_done( ssresolve ) ) ) {
      int res = poll_resolve( resolver, pfd, peer, ssresolve, i, now );
      if( FD_UNLIKELY( res ) ) continue;
    }

    /* Once both the full and incremental snapshots are resolved, we can
       mark the peer valid and remove the peer from the list of peers to
       ping. */
    if( FD_LIKELY( fd_ssresolve_is_done( peer->full_ssresolve ) &&
                   (!resolver->incremental_snapshot_fetch || fd_ssresolve_is_done( peer->inc_ssresolve ) ) ) ) {
      peer->state                 = PEER_STATE_VALID;
      peer->deadline_nanos        = now + PEER_DEADLINE_NANOS_VALID;

      deadline_list_ele_remove( resolver->resolving, peer, resolver->pool );
      deadline_list_ele_push_tail( resolver->valid, peer, resolver->pool );
      remove_peer( resolver, peer->fd.idx );

      resolver->on_resolve_cb( resolver->cb_arg, peer->addr, &peer->ssinfo );
    }
  }
}

void
fd_http_resolver_advance( fd_http_resolver_t *   resolver,
                          long                   now,
                          fd_sspeer_selector_t * selector ) {
  while( !deadline_list_is_empty( resolver->unresolved, resolver->pool ) )  {
    fd_ssresolve_peer_t * peer = deadline_list_ele_pop_head( resolver->unresolved, resolver->pool );

    FD_LOG_INFO(( "resolving " FD_IP4_ADDR_FMT ":%hu", FD_IP4_ADDR_FMT_ARGS( peer->addr.addr ), fd_ushort_bswap( peer->addr.port ) ));
    int result = peer_connect( resolver, peer );
    if( FD_UNLIKELY( -1==result ) ) {
      peer->state          = PEER_STATE_INVALID;
      peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
      deadline_list_ele_push_tail( resolver->invalid, peer, resolver->pool );
    } else {
      peer->state          = PEER_STATE_REFRESHING;
      peer->deadline_nanos = now + PEER_DEADLINE_NANOS_RESOLVE;
      deadline_list_ele_push_tail( resolver->resolving, peer, resolver->pool );
    }
  }

  while( !deadline_list_is_empty( resolver->resolving, resolver->pool ) ) {
    fd_ssresolve_peer_t * peer = deadline_list_ele_peek_head( resolver->resolving, resolver->pool );
    if( FD_LIKELY( peer->deadline_nanos>now ) ) break;

    deadline_list_ele_pop_head( resolver->resolving, resolver->pool );
    peer->state          = PEER_STATE_INVALID;
    peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
    deadline_list_ele_push_tail( resolver->invalid, peer, resolver->pool );
    remove_peer( resolver, peer->fd.idx );

    fd_sspeer_selector_remove( selector, peer->addr );
  }

  while( !deadline_list_is_empty( resolver->invalid, resolver->pool ) ) {
    fd_ssresolve_peer_t * peer = deadline_list_ele_peek_head( resolver->invalid, resolver->pool );
    if( FD_LIKELY( peer->deadline_nanos>now ) ) break;

    deadline_list_ele_pop_head( resolver->invalid, resolver->pool );

    peer->state          = PEER_STATE_UNRESOLVED;
    peer->deadline_nanos = 0L;
    deadline_list_ele_push_tail( resolver->unresolved, peer, resolver->pool );
  }

  while( !deadline_list_is_empty( resolver->valid, resolver->pool ) )  {
    fd_ssresolve_peer_t * peer = deadline_list_ele_peek_head( resolver->valid, resolver->pool );
    if( FD_LIKELY( peer->deadline_nanos>now ) ) break;

    deadline_list_ele_pop_head( resolver->valid, resolver->pool );

    int result = peer_connect( resolver, peer );
    if( FD_UNLIKELY( -1==result ) ) {
      peer->state = PEER_STATE_INVALID;
      peer->deadline_nanos = now + PEER_DEADLINE_NANOS_INVALID;
      deadline_list_ele_push_tail( resolver->invalid, peer, resolver->pool );
      fd_sspeer_selector_remove( selector, peer->addr );
    } else {
      peer->state = PEER_STATE_REFRESHING;
      peer->deadline_nanos = now + PEER_DEADLINE_NANOS_RESOLVE;
      deadline_list_ele_push_tail( resolver->resolving, peer, resolver->pool );
    }
  }

  poll_advance( resolver, now );
}
