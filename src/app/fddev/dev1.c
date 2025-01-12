#define _GNU_SOURCE
#include "fddev.h"

#include "../fdctl/configure/configure.h"
#include "../fdctl/run/run.h"

#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

extern char fd_log_private_path[ 1024 ]; /* empty string on start */

#define FD_LOG_ERR_NOEXIT(a) do { long _fd_log_msg_now = fd_log_wallclock(); fd_log_private_1( 4, _fd_log_msg_now, __FILE__, __LINE__, __func__, fd_log_private_0 a ); } while(0)

extern int * fd_log_private_shared_lock;

static void
parent_signal( int sig ) {
  /* Same hack as in run.c, see comments there. */
  int lock = 0;
  fd_log_private_shared_lock = &lock;

  if( -1!=fd_log_private_logfile_fd() ) FD_LOG_ERR_NOEXIT(( "Received signal %s\nLog at \"%s\"", fd_io_strsignal( sig ), fd_log_private_path ));
  else                                  FD_LOG_ERR_NOEXIT(( "Received signal %s",                fd_io_strsignal( sig ) ));

  if( FD_LIKELY( sig==SIGINT ) ) exit_group( 128+SIGINT );
  else                           exit_group( 0          );
}

static void
install_parent_signals( void ) {
  struct sigaction sa = {
    .sa_handler = parent_signal,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

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
  run_firedancer_init( config, 1 );

  install_parent_signals();

  if( FD_UNLIKELY( close( 0 ) ) ) FD_LOG_ERR(( "close(0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( 1 ) ) ) FD_LOG_ERR(( "close(1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( config->log.lock_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int result = 0;
  if( !strcmp( args->dev1.tile_name, "agave" ) ) {
    result = agave_main( config );
  } else {
    ulong tile_id = fd_topo_find_tile( &config->topo, args->dev1.tile_name, 0UL );
    if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "tile %s not found in topology", args->dev1.tile_name ));

    fd_topo_tile_t * tile = &config->topo.tiles[ tile_id ];
    fd_topo_run_tile_t run_tile = fdctl_tile_run( tile );
    fd_topo_run_tile( &config->topo, tile, config->development.sandbox, 1, config->uid, config->gid, -1, NULL, NULL, &run_tile );
  }

  /* main functions should exit_group and never return, but just in case */
  exit_group( result );
}
