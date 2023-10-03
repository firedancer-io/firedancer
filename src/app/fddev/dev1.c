#define _GNU_SOURCE
#include "fddev.h"

#include "../fdctl/configure/configure.h"
#include "../fdctl/run/run.h"

#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

typedef enum {
  DEV1_PACK,
  DEV1_DEDUP,
  DEV1_VERIFY,
  DEV1_QUIC,
  DEV1_BANK,
  DEV1_SOLANA,
} tile_t;

void
dev1_cmd_args( int *    pargc,
               char *** pargv,
               args_t * args) {
  char * usage = "usage: run1 <tile>";
  if( FD_UNLIKELY( *pargc < 1 ) ) FD_LOG_ERR(( "%s", usage ));

  if( FD_LIKELY( !strcmp( *pargv[ 0 ], "pack" ) ) )             args->run1.tile = DEV1_PACK;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "dedup" ) ) )       args->run1.tile = DEV1_DEDUP;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "verify" ) ) )      args->run1.tile = DEV1_VERIFY;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "quic" ) ) )        args->run1.tile = DEV1_QUIC;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "bank" ) ) )        args->run1.tile = DEV1_BANK;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "labs" ) ) )        args->run1.tile = DEV1_SOLANA;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "solana" ) ) )      args->run1.tile = DEV1_SOLANA;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "solana-labs" ) ) ) args->run1.tile = DEV1_SOLANA;
  else FD_LOG_ERR(( "unrecognized tile %s", *pargv[0] ));

  (*pargc)--;
  (*pargv)++;
}

void
dev1_cmd_perm( args_t *         args,
               security_t *     security,
               config_t * const config ) {
  dev_cmd_perm( args, security, config );
}

void
dev1_cmd_fn( args_t *         args,
             config_t * const config ) {
  (void)args;

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };
  for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ )
    configure_args.configure.stages[ i ] = STAGES[ i ];
  configure_cmd_fn( &configure_args, config );

  update_config_for_dev( config );

  tile_main_args_t tile_args = {
    .app_name = config->name,
    .uid = config->uid,
    .gid = config->gid,
    .tile_idx = 0,
    .idx = 0,
    .sandbox = config->development.sandbox,
  };

  switch( args->run1.tile ) {
    case DEV1_PACK:    tile_args.tile = &pack; break;
    case DEV1_DEDUP:   tile_args.tile = &dedup; break;
    case DEV1_VERIFY:  tile_args.tile = &verify; break;
    case DEV1_QUIC:    tile_args.tile = &quic; break;
    case DEV1_SOLANA: break;
    default: FD_LOG_ERR(( "unknown tile %d", args->run1.tile ));
  }

  if( FD_UNLIKELY( close( 0 ) ) ) FD_LOG_ERR(( "close(0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( 1 ) ) ) FD_LOG_ERR(( "close(1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int result;
  if( args->run1.tile == DEV1_SOLANA ) result = solana_labs_main( config );
  else result = tile_main( &tile_args );
  /* main functions should exit_group and never return, but just in case */
  exit_group( result );
}
