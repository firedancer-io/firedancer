/* The reasm command joins the replay tile and prints the reasm tree.
   This is a standalone development application that can be run to
   inspect the replay tile memory. */

#include "../../shared/fd_config.h" /* config_t */
#include "../../shared_dev/commands/dev.h"
#include "../../../discof/replay/fd_replay_tile.c"

#include <stdio.h>
#include <unistd.h>

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
replay_ctx_wksp( args_t *             args,
                 config_t *           config,
                 fd_replay_tile_t **  replay_ctx,
                 fd_topo_wksp_t **    replay_wksp ) {
  (void)args;

  fd_topo_t * topo = &config->topo;

  ulong tile_id = fd_topo_find_tile( topo, "replay", 0UL );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "replay tile not found" ));

  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];

  /* Get the workspace that contains the tile's scratch memory */
  ulong scratch_wksp_id = topo->objs[ tile->tile_obj_id ].wksp_id;
  if( FD_UNLIKELY( scratch_wksp_id>=topo->wksp_cnt ) ) FD_LOG_ERR(( "invalid workspace id %lu for tile scratch", scratch_wksp_id ));

  fd_topo_wksp_t * _replay_wksp = &topo->workspaces[ scratch_wksp_id ];
  fd_topo_join_workspace( topo, _replay_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  /* Access the replay tile scratch memory where replay_tile_ctx is stored */
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "Failed to access replay tile scratch memory" ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_t * _replay_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_t), sizeof(fd_replay_tile_t) );

  *replay_ctx  = _replay_ctx;
  *replay_wksp = _replay_wksp;
}

static void
reasm_cmd_fn( args_t *   args,
              config_t * config ) {
  (void)args;
  fd_replay_tile_t * replay_ctx;
  fd_topo_wksp_t *   replay_wksp;
  replay_ctx_wksp( args, config, &replay_ctx, &replay_wksp );

  ulong reasm_gaddr  = fd_wksp_gaddr_fast( replay_ctx->wksp, replay_ctx->reasm );
  fd_reasm_t * reasm = (fd_reasm_t *)fd_wksp_laddr( replay_wksp->wksp, reasm_gaddr );

  for( ;; ) {
    ulong root_slot = replay_ctx->consensus_root_slot;
    if( root_slot == ULONG_MAX ) {
      printf( "root_slot: ULONG_MAX (not set)\n" );
    } else {
      printf( "root_slot: %lu\n", root_slot );
    }

    fd_reasm_print( reasm );

    fflush( stdout );
    sleep( 1 );
  }
}

static const char * HELP =
  "\n\n"
  "usage: reasm [-h]\n"
  "\n"
  "optional arguments:\n"
  "  -h, --help            show this help message and exit\n";

void
reasm_cmd_help( char const * arg ) {
  (void)arg;
  FD_LOG_NOTICE(( "%s", HELP ));
}

void
reasm_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args ) {
  (void)pargc;
  (void)pargv;
  (void)args;
  /* no args yet */
}

action_t fd_action_reasm = {
  .name = "reasm",
  .args = reasm_cmd_args,
  .fn   = reasm_cmd_fn,
  .perm = dev_cmd_perm,
};

