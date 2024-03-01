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

  int result = 0;
  if( !strcmp( args->dev1.tile_name, "solana" ) ||
      !strcmp( args->dev1.tile_name, "labs" ) ||
      !strcmp( args->dev1.tile_name, "solana-labs" ) ) {
    result = solana_labs_main( config );
  } else {
    ulong tile_id = fd_topo_find_tile( &config->topo, args->dev1.tile_name, 0UL );
    if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "tile %s not found in topology", args->dev1.tile_name ));

    fd_topo_tile_t * tile = &config->topo.tiles[ tile_id ];
    fd_topo_run_tile_t run_tile = fdctl_tile_run( tile );
    fd_topo_run_tile( &config->topo, tile, config->development.sandbox, config->uid, config->gid, -1, NULL, NULL, &run_tile, fdctl_tile_align, fdctl_tile_footprint );
  }

  /* main functions should exit_group and never return, but just in case */
  exit_group( result );
}
