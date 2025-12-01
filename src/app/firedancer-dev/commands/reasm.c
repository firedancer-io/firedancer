/* The reasm command joins replay tile memory and prints the fd_reasm tree.
   This is a standalone application that can be run to inspect the reasm
   state of a running Firedancer instance. */

#include "../../../discof/replay/fd_replay_tile.c"
#include "../../../discof/reasm/fd_reasm.h"
#include "../../shared/fd_config.h" /* config_t */
#include "../../shared_dev/commands/dev.h"

#include <unistd.h> /* sleep */

static void
replay_ctx_wksp( args_t *          args,
                 config_t *        config,
                 fd_replay_tile_t ** replay_ctx,
                 fd_topo_wksp_t ** replay_wksp ) {
  (void)args;

  fd_topo_t * topo = &config->topo;
  ulong wksp_id = fd_topo_find_wksp( topo, "replay" );
  if( FD_UNLIKELY( wksp_id==ULONG_MAX ) ) FD_LOG_ERR(( "replay workspace not found" ));

  fd_topo_wksp_t * _replay_wksp = &topo->workspaces[ wksp_id ];
  fd_topo_join_workspace( topo, _replay_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY );

  /* Access the replay tile scratch memory where replay_tile_ctx is stored */

  ulong tile_id = fd_topo_find_tile( topo, "replay", 0UL );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "replay tile not found" ));
  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];
  void * scratch = fd_topo_obj_laddr( &config->topo, tile->tile_obj_id );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "Failed to access replay tile scratch memory" ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_t * _replay_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_t), sizeof(fd_replay_tile_t) );

  *replay_ctx  = _replay_ctx;
  *replay_wksp = _replay_wksp;
}

static void
reasm_cmd_fn_print( args_t *   args,
                    config_t * config ) {
  (void)args;

  fd_replay_tile_t * replay_ctx;
  fd_topo_wksp_t *   replay_wksp;
  replay_ctx_wksp( args, config, &replay_ctx, &replay_wksp );

  /* Rejoin reasm to ensure we have a valid pointer in our address space */
  FD_LOG_NOTICE(( "sanity check replay_ctx slot %lu", replay_ctx->reset_slot ));
  FD_LOG_NOTICE(( "replay ctx wksp %p, reasm %p", (void *)&replay_ctx->wksp, (void *)replay_ctx->reasm ));
  FD_LOG_NOTICE(( "replay wksp %p", (void *)replay_wksp->wksp ));

  ulong replay_ctx_wksp = (ulong)&replay_ctx->wksp;

  ulong reasm_gaddr  = fd_wksp_gaddr_fast( (fd_wksp_t *)replay_ctx_wksp, replay_ctx->reasm );
  fd_reasm_t * reasm = (fd_reasm_t *)fd_wksp_laddr_fast( replay_wksp->wksp, reasm_gaddr );

  for( ;; ) {
    fd_reasm_print( reasm, replay_wksp->wksp, (fd_wksp_t *)replay_ctx_wksp );
    sleep( 1 );
  }
}

static const char * HELP =
  "\n\n"
  "usage: reasm [-h] {print}\n"
  "\n"
  "positional arguments:\n"
  "  {print}\n"
  "    print              prints the fd_reasm tree from the replay tile\n"
  "\n"
  "optional arguments:\n"
  "  -h, --help            show this help message and exit\n";

static const char * PRINT_HELP =
  "\n\n"
  "usage: reasm print [-h]\n"
  "\n"
  "optional arguments:\n"
  "  -h, --help            show this help message and exit\n";

void
reasm_cmd_help( char const * arg ) {
  if      ( FD_LIKELY( !arg                        ) ) FD_LOG_NOTICE(( "%s", HELP           ));
  else if ( FD_LIKELY( !strcmp( arg, "print"      ) ) ) FD_LOG_NOTICE(( "%s", PRINT_HELP      ));
  else                                                    FD_LOG_NOTICE(( "%s", HELP           ));
}

void
reasm_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args ) {

  /* help */
  args->reasm.help = fd_env_strip_cmdline_contains( pargc, pargv, "--help" );
  args->reasm.help = args->reasm.help || fd_env_strip_cmdline_contains( pargc, pargv, "-h" );

  /* positional arg */
  args->reasm.pos_arg = (*pargv)[0];
  if( FD_UNLIKELY( !args->reasm.pos_arg ) ) {
    args->reasm.help = 1;
    return;
  }

  (*pargc)--;
}

static void
reasm_cmd_fn( args_t *   args,
              config_t * config ) {

  if( args->reasm.help ) {
    reasm_cmd_help( args->reasm.pos_arg );
    return;
  }

  if     ( !strcmp( args->reasm.pos_arg, "print" ) ) reasm_cmd_fn_print( args, config );
  else                                                 reasm_cmd_help( NULL );
}

action_t fd_action_reasm = {
  .name = "reasm",
  .args = reasm_cmd_args,
  .fn   = reasm_cmd_fn,
  .perm = dev_cmd_perm,
};

