#include "fdctl.h"

#include "run/run.h"

#include "../../tango/fd_tango.h"

void
ready_cmd_fn( args_t *         args,
              config_t * const config ) {
  (void)args;

  fd_topo_t topo[ 1 ];
  fd_topo_new( topo, config->pod );

  fd_topo_wksp_t * wksp = NULL;
  for( ulong i=0UL; i<topo->wksp_cnt; i++ ) {
    fd_topo_wksp_t * _wksp = topo->wksps[ i ];
    if( FD_UNLIKELY( !strcmp( _wksp->name, "metric_in" ) ) ) continue;
    wksp = _wksp;
    break;
  }

  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "no workspace found" ));

  fd_topo_wksp_attach( wksp, FD_TOPO_WKSP_MMAP_MODE_READ );
  fd_topo_wksp_join( topo );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = topo->tiles[ i ];
    if( FD_UNLIKELY( tile->solana_labs ) ) continue;

    long start = fd_log_wallclock();
    int printed = 0;
    do {
      ulong signal = fd_cnc_signal_query( tile->cnc );
      char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];

      if( FD_LIKELY( signal==FD_CNC_SIGNAL_RUN ) ) break;
      else if( FD_UNLIKELY( signal!=FD_CNC_SIGNAL_BOOT ) )
        FD_LOG_ERR(( "cnc for tile %s:%lu is in bad state %s", tile->name, tile->tidx, fd_cnc_signal_cstr( signal, buf ) ));

      if( FD_UNLIKELY( !printed && (fd_log_wallclock()-start) > 1000000000L*1L ) ) {
        FD_LOG_NOTICE(( "waiting for tile %s:%lu to be ready", tile->name, tile->tidx ));
        printed = 1;
      }
    } while(1);
  }

  fd_topo_wksp_detach( topo );
  FD_LOG_NOTICE(( "all tiles ready" ));
}
