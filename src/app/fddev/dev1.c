#define _GNU_SOURCE
#include "fddev.h"

#include "../fdctl/configure/configure.h"
#include "../fdctl/run/run.h"

#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

void
dev1_cmd_args( int *    pargc,
               char *** pargv,
               args_t * args) {
  char * usage = "usage: dev1 <tile>";
  if( FD_UNLIKELY( *pargc < 1 ) ) FD_LOG_ERR(( "%s", usage ));

  strncpy( args->dev1.tile_name, *pargv[ 0 ], sizeof( args->dev1.tile_name ) - 1 );

  (*pargc)--;
  (*pargv)++;

  args->dev1.no_configure = fd_env_strip_cmdline_contains( pargc, pargv, "--no-configure" );
}

void
dev1_cmd_perm( args_t *         args,
               fd_caps_ctx_t *  caps,
               config_t * const config ) {
  dev_cmd_perm( args, caps, config );
}

fd_topo_run_tile_args_t * tile_run_args( fd_topo_tile_t const * tile ) {
  (void)tile;
  FD_LOG_ERR(( "bbb" ));
  return NULL;
}

void
dev1_cmd_fn( args_t *         args,
             config_t * const config ) {
  (void)args;

  if( FD_LIKELY( !args->dev1.no_configure ) ) {
    args_t configure_args = {
      .configure.command = CONFIGURE_CMD_INIT,
    };
    for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ )
      configure_args.configure.stages[ i ] = STAGES[ i ];
    configure_cmd_fn( &configure_args, config );
  }

  update_config_for_dev( config );

  if( FD_UNLIKELY( close( 0 ) ) ) FD_LOG_ERR(( "close(0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( 1 ) ) ) FD_LOG_ERR(( "close(1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( config->log.lock_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( !strcmp( args->dev1.tile_name, "solana" ) ||
      !strcmp( args->dev1.tile_name, "labs" ) ||
      !strcmp( args->dev1.tile_name, "solana-labs" ) ) {
    solana_labs_main( config );
  } else {
    fd_topo_t topo[ 1 ];
    fd_topo_new( topo, config->pod );

    fd_topo_tile_t * tile = NULL;
    for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
      fd_topo_tile_t * _tile = topo->tiles[ i ];
      if( FD_UNLIKELY( strcmp( _tile->name, args->dev1.tile_name ) || _tile->tidx ) ) continue;
      tile = _tile;
      break;
    }

    if( FD_UNLIKELY( !tile ) ) FD_LOG_ERR(( "tile %s:%lu not found", args->dev1.tile_name, 0UL ));

    fd_topo_run_tile( tile,
                      config->development.sandbox,
                      config->uid,
                      config->gid,
                      -1, /* no parent process to notify about termination */
                      tile_run_args( tile ) );
  }

  /* main functions should exit_group and never return, but just in case */
  exit_group( 0 );
}
