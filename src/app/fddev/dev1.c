#define _GNU_SOURCE
#include "fddev.h"

#include "../fdctl/configure/configure.h"
#include "../fdctl/run.h"

#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

void
dev1_cmd_args( int *    pargc,
               char *** pargv,
               args_t * args) {
  char * usage = "usage: run1 <tile>";
  if( FD_UNLIKELY( *pargc < 1 ) ) FD_LOG_ERR(( "%s", usage ));

  if( FD_LIKELY( !strcmp( *pargv[ 0 ], "pack" ) ) ) args->run1.tile = 0;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "dedup" ) ) ) args->run1.tile = 1;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "verify" ) ) ) args->run1.tile = 2;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "quic" ) ) ) args->run1.tile = 3;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "bank" ) ) ) args->run1.tile = 4;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "labs" ) ) ) args->run1.tile = 4;
  else if( FD_LIKELY( !strcmp( *pargv[ 0 ], "solana-labs" ) ) ) args->run1.tile = 4;
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
  /* cluster and netns stages are not accessible from regular configure command,
     but perform them here. netns is first, as other stages might depend on it */
  /* netns is the first stage, others might depend on it */
  configure_args.configure.stages[ 0 ] = &netns;
  for( ulong i=0; i<CONFIGURE_STAGE_COUNT; i++ )
    configure_args.configure.stages[ i + 1 ] = STAGES[ i ];
  configure_args.configure.stages[ CONFIGURE_STAGE_COUNT ] = &cluster;
  configure_cmd_fn( &configure_args, config );

  /* when starting from a new genesis block, this needs to be off else the
     validator will get stuck forever. */
  config->consensus.wait_for_vote_to_start_leader = 0;

  tile_main_args_t tile_args = {
    .tile_idx = 0,
    .idx = 0,
    .sandbox = config->development.sandbox,
  };

  switch( args->run1.tile ) {
    case 0: tile_args.tile = &frank_pack; break;
    case 1: tile_args.tile = &frank_dedup; break;
    case 2: tile_args.tile = &frank_verify; break;
    case 3: tile_args.tile = &frank_quic; break;
    case 4: break;
    default: FD_LOG_ERR(( "unknown tile %d", args->run1.tile ));
  }

  int result;
  if( args->run1.tile == 4 ) result = solana_labs_main( config );
  else result = tile_main( &tile_args );
  /* main functions should exit_group and never return, but just in case */
  exit_group( result );
}
