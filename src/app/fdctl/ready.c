#include "fdctl.h"

#include "run/run.h"

#include "../../tango/fd_tango.h"

void
ready_cmd_fn( args_t *         args,
              config_t * const config ) {
  (void)args;

  fd_topo_join_workspaces( config->name, &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topo_fill( &config->topo, FD_TOPO_FILL_MODE_JOIN );

  for( ulong i=0; i<config->topo.tile_cnt; i++) {
    fd_topo_tile_t * tile = &config->topo.tiles[i];

    /* don't wait for bank tiles yet, not a real firedancer tile */
    if( tile->kind == FD_TOPO_TILE_KIND_BANK ) continue;
    
    int first_iter = 1;
    do {
      ulong signal = fd_cnc_signal_query( tile->cnc );
      char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];

      if( FD_LIKELY( signal==FD_CNC_SIGNAL_RUN ) ) break;
      else if( FD_UNLIKELY( signal!=FD_CNC_SIGNAL_BOOT ) )
        FD_LOG_ERR(( "cnc for tile %s(%lu) is in bad state %s", fd_topo_tile_kind_str( tile->kind ), tile->kind_id, fd_cnc_signal_cstr( signal, buf ) ));

      if( FD_UNLIKELY( first_iter ) ) FD_LOG_NOTICE(( "waiting for tile %s(%lu) to be ready", fd_topo_tile_kind_str( tile->kind ), tile->kind_id ));
      first_iter = 0;
    } while(1);
  }

  FD_LOG_NOTICE(( "all tiles ready" ));
}
