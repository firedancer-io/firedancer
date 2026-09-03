/* The waker tile sleeps in epoll_wait(2) on the outer epoll fd on
   behalf of all waker client tiles, and raises a client's readiness
   fseq when that client's inner epoll set has a ready fd.  See
   fd_waker.h for the full wake protocol. */

#include "fd_waker.h"

#include "../metrics/fd_metrics.h"
#include "../stem/fd_stem.h"
#include "../topo/fd_topo.h"
#include "../../tango/fseq/fd_fseq.h"

#include <errno.h>
#include <sys/epoll.h>

#include "generated/fd_waker_tile_seccomp.h"

#define EPOLL_TIMEOUT_MILLIS (10)

struct fd_waker_tile {
  ulong   client_cnt;
  ulong * fseq[ FD_WAKER_CLIENT_MAX ];
  ulong   client_tile_id[ FD_WAKER_CLIENT_MAX ];

  fd_sleep_t * sleep;
};

typedef struct fd_waker_tile fd_waker_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_waker_tile_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return sizeof(fd_waker_tile_t);
}

static void
before_credit( fd_waker_tile_t *   ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  struct epoll_event evs[ FD_WAKER_CLIENT_MAX ];
  int n = epoll_pwait( FD_WAKER_OUTER_FD, evs, FD_WAKER_CLIENT_MAX, EPOLL_TIMEOUT_MILLIS, NULL );
  if( FD_UNLIKELY( -1==n ) ) {
    if( FD_LIKELY( errno==EINTR ) ) return;
    FD_LOG_ERR(( "epoll_pwait() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  FD_MCNT_INC( WAKER, EPOLL_WAIT_DISPATCHED, 1UL );
  if( FD_LIKELY( !n ) ) return;

  *charge_busy = 1;
  for( int i=0; i<n; i++ ) {
    ulong idx = evs[ i ].data.u64;
    FD_TEST( idx<ctx->client_cnt );
    fd_fseq_update( ctx->fseq[ idx ], 1UL );
    if( FD_UNLIKELY( ctx->sleep ) ) fd_sleep_ring( ctx->sleep, ctx->client_tile_id[ idx ] );
  }
  FD_MCNT_INC( WAKER, WAKE_DELIVERED, (ulong)n );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_waker_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_waker_tile_t), sizeof(fd_waker_tile_t) );

  ctx->client_cnt = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * client = &topo->tiles[ i ];
    ulong idx = client->waker_client_idx;
    if( FD_LIKELY( idx==ULONG_MAX ) ) continue;
    FD_TEST( idx<FD_WAKER_CLIENT_MAX );
    ctx->fseq[ idx ] = fd_fseq_join( fd_topo_obj_laddr( topo, client->waker_fseq_obj_id ) );
    FD_TEST( ctx->fseq[ idx ] );
    ctx->client_tile_id[ idx ] = client->id;
    ctx->client_cnt = fd_ulong_max( ctx->client_cnt, idx+1UL );
  }

  ctx->sleep = NULL;
  if( FD_UNLIKELY( topo->sleep_obj_id!=ULONG_MAX ) ) {
    ctx->sleep = fd_sleep_join( fd_topo_obj_laddr( topo, topo->sleep_obj_id ) );
    FD_TEST( ctx->sleep );
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_waker_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)FD_WAKER_OUTER_FD );
  return sock_filter_policy_fd_waker_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)tile;

  ulong client_cnt = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    ulong idx = topo->tiles[ i ].waker_client_idx;
    if( FD_UNLIKELY( idx!=ULONG_MAX ) ) client_cnt = fd_ulong_max( client_cnt, idx+1UL );
  }

  if( FD_UNLIKELY( out_fds_cnt<3UL+client_cnt ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = FD_WAKER_OUTER_FD; /* waker outer epoll fd (rearm) */
  for( ulong i=0UL; i<client_cnt; i++ ) out_fds[ out_cnt++ ] = FD_WAKER_INNER_FD( i ); /* waker inner epoll fd */
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)10e6) /* 10ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_waker_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_waker_tile_t)

#define STEM_CALLBACK_BEFORE_CREDIT before_credit

#include "../stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_waker = {
  .name                     = "waker",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
