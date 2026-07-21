#include "fd_startup.h"
#include "../disco/metrics/fd_metrics.h"
#include <time.h>

__attribute__((weak)) int volatile const fd_startup_skip_checks = 0;

/* replay_status_laddr resolves the local address of the replay tile's
   RUNTIME_STATUS gauge, with defensive boilerplate to prevent
   segfault. */

static ulong volatile const *
replay_status_laddr( fd_topo_t const * topo ) {
  ulong metric_wksp_id = fd_topo_find_wksp( topo, "metric_in" );
  if( FD_UNLIKELY( metric_wksp_id==ULONG_MAX ) ) FD_LOG_ERR(( "This topology does not have a metric_in workspace" ));

  fd_topo_wksp_t const * metric_topo_wksp = &topo->workspaces[ metric_wksp_id ];
  if( FD_UNLIKELY( !metric_topo_wksp->wksp ) ) FD_LOG_ERR(( "metric_in wksp is not joined" ));

  fd_wksp_t * metric_wksp = metric_topo_wksp->wksp;
  if( FD_UNLIKELY( !metric_wksp ) ) FD_LOG_ERR(( "metric_in wksp is not joined" ));

  if( FD_UNLIKELY( fd_shmem_join_query_by_join( metric_wksp, NULL )!=0 ) ) {
    FD_LOG_ERR(( "metric_in wksp not mapped into current tile" ));
  }

  ulong replay_tile_id = fd_topo_find_tile( topo, "replay", 0 );
  if( FD_UNLIKELY( replay_tile_id==ULONG_MAX ) ) return NULL; /* dev topologies without replay never gate */
  fd_topo_tile_t const * replay_tile = &topo->tiles[ replay_tile_id ];

  fd_topo_obj_t const * metric_obj = fd_topo_find_tile_obj( topo, replay_tile, "metrics" );
  if( FD_UNLIKELY( !metric_obj ) ) FD_LOG_ERR(( "replay:0 does not have a metrics object" ));
  if( FD_UNLIKELY( metric_obj->wksp_id!=metric_wksp_id ) ) FD_LOG_ERR(( "This tile does not have access to replay:0 metrics" ));

  ulong * replay_metrics = fd_topo_obj_laddr( topo, metric_obj->id );
  if( FD_UNLIKELY( !replay_metrics ) ) FD_LOG_ERR(( "Cannot access replay:0 metrics" ));

  ulong volatile const * replay_tile_metrics = fd_metrics_tile( replay_metrics );
  return &replay_tile_metrics[ MIDX( GAUGE, REPLAY, RUNTIME_STATUS ) ];
}

void
fd_startup_gate_init( fd_startup_gate_t * gate,
                      fd_topo_t const *   topo,
                      ulong               in_cnt ) {
  gate->status   = fd_startup_skip_checks ? NULL : replay_status_laddr( topo );
  gate->started  = !gate->status;
  gate->idle_cnt = 0UL;
  gate->idle_max = 2UL*in_cnt+1UL;
}

int
fd_startup_gate_idle( fd_startup_gate_t * gate ) {
  if( FD_LIKELY( gate->started ) ) return 1;

  if( FD_UNLIKELY( FD_VOLATILE_CONST( *gate->status ) ) ) {
    gate->started = 1;
    return 1;
  }

  gate->idle_cnt++;
  if( FD_LIKELY( gate->idle_cnt>=gate->idle_max ) ) {
    gate->idle_cnt = 0UL;
    struct timespec ts = { .tv_sec=0, .tv_nsec=(int)1e6 }; /* 1ms */
    (void)clock_nanosleep( CLOCK_REALTIME, 0, &ts, NULL );
  }
  return 0;
}
