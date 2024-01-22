#include "fdctl.h"

#include "run/run.h"

#include "../../tango/fd_tango.h"

void
ready_cmd_fn( args_t *         args,
              config_t * const config ) {
  (void)args;

  ulong wksp_id = fd_topo_find_wksp( &config->topo, FD_TOPO_WKSP_KIND_METRIC_IN );
  FD_TEST( wksp_id!=ULONG_MAX );

  fd_topo_join_workspace( config->name, &config->topo.workspaces[ wksp_id ], FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topo_workspace_fill( &config->topo, &config->topo.workspaces[ wksp_id ], FD_TOPO_FILL_MODE_JOIN );

  for( ulong i=0; i<config->topo.tile_cnt; i++) {
    fd_topo_tile_t * tile = &config->topo.tiles[i];

    /* Don't wait for solana labs hosted tiles yet, they will take a
       long time, and aren't needed to start sending transactions
       anyway. */
    if( FD_UNLIKELY( fd_topo_tile_kind_is_labs( tile->kind ) ) ) continue;
    
    long start = fd_log_wallclock();
    int printed = 0;
    do {
      ulong signal = fd_cnc_signal_query( tile->cnc );
      char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];

      if( FD_LIKELY( signal==FD_CNC_SIGNAL_RUN ) ) break;
      else if( FD_UNLIKELY( signal!=FD_CNC_SIGNAL_BOOT ) )
        FD_LOG_ERR(( "cnc for tile %s(%lu) is in bad state %s", fd_topo_tile_kind_str( tile->kind ), tile->kind_id, fd_cnc_signal_cstr( signal, buf ) ));

      if( FD_UNLIKELY( !printed && (fd_log_wallclock()-start) > 1000000000L*1L ) ) {
        FD_LOG_NOTICE(( "waiting for tile %s(%lu) to be ready", fd_topo_tile_kind_str( tile->kind ), tile->kind_id ));
        printed = 1;
      }
    } while(1);
  }

  fd_topo_leave_workspaces( &config->topo );
  FD_LOG_NOTICE(( "all tiles ready" ));
}
