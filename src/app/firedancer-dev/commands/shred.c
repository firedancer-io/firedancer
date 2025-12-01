/* The shred command joins shred tile memory and prints context information.
   This is a standalone application that can be run to inspect the shred
   tile state of a running Firedancer instance. */

#include "../../../disco/shred/fd_shred_tile.c"
#include "../../shared/fd_config.h" /* config_t */
#include "../../shared_dev/commands/dev.h"
#include "../../../disco/shred/fd_fec_resolver.c"
#include <stdio.h>
#include <unistd.h> /* sleep */

static void
shred_ctx_wksp( args_t *          args,
                config_t *        config,
                fd_shred_ctx_t **  shred_ctx,
                fd_topo_wksp_t **  shred_wksp ) {
  (void)args;

  fd_topo_t * topo = &config->topo;
  ulong wksp_id = fd_topo_find_wksp( topo, "shred" );
  if( FD_UNLIKELY( wksp_id==ULONG_MAX ) ) FD_LOG_ERR(( "shred workspace not found" ));

  fd_topo_wksp_t * _shred_wksp = &topo->workspaces[ wksp_id ];
  fd_topo_join_workspace( topo, _shred_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY );

  /* Access the shred tile scratch memory where shred_tile_ctx is stored */
  ulong tile_id = fd_topo_find_tile( topo, "shred", 0UL );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "shred tile not found" ));
  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];
  void * scratch = fd_topo_obj_laddr( &config->topo, tile->tile_obj_id );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "Failed to access shred tile scratch memory" ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_shred_ctx_t * _shred_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_shred_ctx_t), sizeof(fd_shred_ctx_t) );

  *shred_ctx  = _shred_ctx;
  *shred_wksp = _shred_wksp;
}

static void
shred_cmd_fn_slot( args_t *   args,
                   config_t * config ) {
  (void)args;

  fd_shred_ctx_t * shred_ctx;
  fd_topo_wksp_t * shred_wksp;
  shred_ctx_wksp( args, config, &shred_ctx, &shred_wksp );

  ulong shred_tile_wksp = (ulong)shred_ctx->stake_ci - sizeof(fd_shred_ctx_t);
  FD_TEST( fd_ulong_align_up( shred_tile_wksp, alignof(fd_shred_ctx_t) ) + sizeof(fd_shred_ctx_t) == (ulong)shred_ctx->stake_ci );

  FD_LOG_NOTICE(( "shred tile wksp %p", (void *)shred_tile_wksp ));
  FD_LOG_NOTICE(( "shred wksp %p", (void *)shred_wksp->wksp ));
  FD_LOG_NOTICE(( "shred resolver %p", (void *)shred_ctx->resolver ));

  fd_fec_resolver_t * resolver = fd_wksp_laddr_fast( shred_wksp->wksp, fd_wksp_gaddr_fast( (fd_wksp_t *)shred_tile_wksp, shred_ctx->resolver ) );
  FD_LOG_NOTICE(( "depth: %lu, done_depth: %lu, max_shred_idx: %lu", resolver->depth, resolver->done_depth, resolver->max_shred_idx ));

  for( ;; ) {
    fd_fec_resolver_print_done( resolver, shred_wksp->wksp, (fd_wksp_t *)shred_tile_wksp );
    fflush( stdout );
  }
}

static const char * HELP =
  "\n\n"
  "usage: shred [-h] {slot}\n"
  "\n"
  "positional arguments:\n"
  "  {slot}\n"
  "    slot                prints the slot from the shred tile context\n"
  "\n"
  "optional arguments:\n"
  "  -h, --help            show this help message and exit\n";

static const char * SLOT_HELP =
  "\n\n"
  "usage: shred slot [-h]\n"
  "\n"
  "optional arguments:\n"
  "  -h, --help            show this help message and exit\n";

void
shred_cmd_help( char const * arg ) {
  if      ( FD_LIKELY( !arg                        ) ) FD_LOG_NOTICE(( "%s", HELP           ));
  else if ( FD_LIKELY( !strcmp( arg, "slot"      ) ) ) FD_LOG_NOTICE(( "%s", SLOT_HELP      ));
  else                                                    FD_LOG_NOTICE(( "%s", HELP           ));
}

void
shred_cmd_args( int *    pargc,
               char *** pargv,
               args_t * args ) {

  /* help */
  args->shred.help = fd_env_strip_cmdline_contains( pargc, pargv, "--help" );
  args->shred.help = args->shred.help || fd_env_strip_cmdline_contains( pargc, pargv, "-h" );

  /* positional arg */
  args->shred.pos_arg = (*pargv)[0];
  if( FD_UNLIKELY( !args->shred.pos_arg ) ) {
    args->shred.help = 1;
    return;
  }

  (*pargc)--;
}

static void
shred_cmd_fn( args_t *   args,
              config_t * config ) {

  if( args->shred.help ) {
    shred_cmd_help( args->shred.pos_arg );
    return;
  }

  if     ( !strcmp( args->shred.pos_arg, "slot" ) ) shred_cmd_fn_slot( args, config );
  else                                               shred_cmd_help( NULL );
}

action_t fd_action_shred = {
  .name = "shred",
  .args = shred_cmd_args,
  .fn   = shred_cmd_fn,
  .perm = dev_cmd_perm,
};

