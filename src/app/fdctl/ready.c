#include "fdctl.h"

#include "run/run.h"

#include "../../tango/fd_tango.h"

static void wait_for( char * app_name,
                      char * workspace_name,
                      char * cnc_name ) {
  const uchar * pod = workspace_pod_join( app_name, workspace_name );
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( pod, cnc_name ) );
  int first_iter = 1;
  do {
    ulong signal = fd_cnc_signal_query( cnc );
    char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];

    if( FD_LIKELY( signal==FD_CNC_SIGNAL_RUN ) ) break;
    else if( FD_UNLIKELY( signal!=FD_CNC_SIGNAL_BOOT ) )
      FD_LOG_ERR(( "cnc for tile %s is in bad state %s", workspace_name, fd_cnc_signal_cstr( signal, buf ) ));

    if( FD_UNLIKELY( first_iter ) )
      FD_LOG_NOTICE(( "waiting for tile %s to be ready", workspace_name ));
    first_iter = 0;
  } while(1);
}

void
ready_cmd_fn( args_t *         args,
              config_t * const config ) {
  (void)args;

  for( ulong i=0; i<config->shmem.workspaces_cnt; i++ ) {
    workspace_config_t * wksp = &config->shmem.workspaces[i];
    switch( wksp->kind ) {
      case wksp_netmux_inout:
      case wksp_quic_verify:
      case wksp_verify_dedup:
      case wksp_dedup_pack:
      case wksp_pack_bank:
      case wksp_bank_shred:
      case wksp_bank:
      case wksp_store:
      case wksp_shred_store:
        break;
      case wksp_net:
        for( ulong i=0; i<config->layout.net_tile_count; i++ ) {
          char cnc[32];
          snprintf1( cnc, 32, "cnc%lu", i );
          wait_for( config->name, wksp->name, cnc );
        }
        break;
      case wksp_quic:
      case wksp_verify: {
        for( ulong i=0; i<config->layout.verify_tile_count; i++ ) {
          char cnc[32];
          snprintf1( cnc, 32, "cnc%lu", i );
          wait_for( config->name, wksp->name, cnc );
        }
        break;
      }
      case wksp_netmux:
      case wksp_dedup:
      case wksp_pack:
      case wksp_shred: {
        wait_for( config->name, wksp->name, "cnc" );
        break;
      }
    }
  }

  FD_LOG_NOTICE(( "all tiles ready" ));
}
