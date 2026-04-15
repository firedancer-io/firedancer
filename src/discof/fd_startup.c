#include "fd_startup.h"
#include "../disco/metrics/fd_metrics.h"
#include <time.h>

ulong
fd_sleep_until_replay_started( fd_topo_t const * topo ) {

  /* Defensive boilerplate to prevent segfault */

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
  if( FD_UNLIKELY( replay_tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "This topology does not have a replay tile" ));
  fd_topo_tile_t const * replay_tile = &topo->tiles[ replay_tile_id ];

  fd_topo_obj_t const * metric_obj = fd_topo_find_tile_obj( topo, replay_tile, "metrics" );
  if( FD_UNLIKELY( !metric_obj ) ) FD_LOG_ERR(( "replay:0 does not have a metrics object" ));
  if( FD_UNLIKELY( metric_obj->wksp_id!=metric_wksp_id ) ) FD_LOG_ERR(( "This tile does not have access to replay:0 metrics" ));

  ulong * replay_metrics = fd_topo_obj_laddr( topo, metric_obj->id );
  if( FD_UNLIKELY( !replay_metrics ) ) FD_LOG_ERR(( "Cannot access replay:0 metrics" ));

  /* We have access to metrics, now find 'status' metric */

  ulong volatile const * replay_tile_metrics = fd_metrics_tile( replay_metrics );
  ulong volatile const * replay_status = &replay_tile_metrics[ MIDX( GAUGE, REPLAY, RUNTIME_STATUS ) ];

  /* Wait */

  FD_LOG_INFO(( "waiting for replay:0 to start runtime" ));
  while( __atomic_load_n( replay_status, __ATOMIC_ACQUIRE )==0 ) {
    struct timespec ts = { .tv_sec=0, .tv_nsec=(int)1e6 }; /* 1ms */
    (void)clock_nanosleep( CLOCK_REALTIME, 0, &ts, NULL );
  }

  /* No need to log here because stem_run logs on startup */

  return replay_tile_metrics[ MIDX( GAUGE, REPLAY, ROOT_SLOT ) ];
}
