/* The tower command prints the tower forks tree structure and leaves.
   This is a standalone application that can be run to inspect the tower
   tile's fork structure. */

#include "../../shared/fd_config.h" /* config_t */
#include "../../shared_dev/commands/dev.h"
#include "../../../discof/tower/fd_tower_tile.c"
#include "../../../choreo/tower/fd_tower_forks.h"

#include <stdio.h>
#include <unistd.h>

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

/* ctx_t is defined in fd_tower_tile.c, we just need to access it */

static void
tower_ctx_wksp( args_t *          args,
                config_t *        config,
                ctx_t **          tower_ctx,
                fd_topo_wksp_t ** tower_wksp ) {
  (void)args;

  fd_topo_t * topo = &config->topo;

  ulong tile_id = fd_topo_find_tile( topo, "tower", 0UL );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "tower tile not found" ));

  fd_topo_tile_t * tile = &topo->tiles[ tile_id ];

  /* Get the workspace that contains the tile's scratch memory */
  ulong scratch_wksp_id = topo->objs[ tile->tile_obj_id ].wksp_id;
  if( FD_UNLIKELY( scratch_wksp_id>=topo->wksp_cnt ) ) FD_LOG_ERR(( "invalid workspace id %lu for tile scratch", scratch_wksp_id ));

  fd_topo_wksp_t * _tower_wksp = &topo->workspaces[ scratch_wksp_id ];
  fd_topo_join_workspace( topo, _tower_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  /* Access the tower tile scratch memory where tower_tile_ctx is stored */
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "Failed to access tower tile scratch memory" ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * _tower_ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );

  *tower_ctx  = _tower_ctx;
  *tower_wksp = _tower_wksp;
}

static void
print_all_forks( fd_wksp_t * wksp, ctx_t * tower_ctx, fd_forks_t * forks ) {
  printf( "\n[Tower Forks]\n" );
  printf( "=============\n" );
  printf( "%-15s | %-15s | %-10s | %-10s\n", "Slot", "Parent Slot", "Voted", "Confirmed" );
  printf( "%-15s-+-%-15s-+-%-10s-+-%-10s\n", "---------------", "---------------", "----------", "----------" );

  /* Iterate through all map slots */
  ulong tower_forks_gaddr = fd_wksp_gaddr_fast( tower_ctx->wksp, forks->tower_forks );
  fd_tower_forks_t * map = (fd_tower_forks_t *)fd_wksp_laddr_fast( wksp, tower_forks_gaddr );
  ulong slot_count = 0;

  for( ulong slot_idx = 0UL; slot_idx < fd_tower_forks_slot_cnt( map ); slot_idx++ ) {
    fd_tower_forks_t * fork = &map[ slot_idx ];
    /* Check if key is valid (not MAP_KEY_NULL which is ULONG_MAX) */
    if( !fd_tower_forks_key_inval( fork->slot ) ) {
      printf( "%-15lu | ", fork->slot );
      if( fork->parent_slot == ULONG_MAX ) {
        printf( "%-15s | ", "NULL" );
      } else {
        printf( "%-15lu | ", fork->parent_slot );
      }
      printf( "%-10s | ", fork->voted ? "Yes" : "No" );
      printf( "%-10s\n", fork->confirmed ? "Yes" : "No" );
      slot_count++;
    }
  }

  printf( "\n[Tower Leaves]\n" );
  printf( "==============\n" );

  ulong         tower_leaves_dlist_gaddr = fd_wksp_gaddr_fast( tower_ctx->wksp, forks->tower_leaves_dlist );
  fd_tower_leaves_dlist_t * leaves_dlist = (fd_tower_leaves_dlist_t *)fd_wksp_laddr_fast( wksp, tower_leaves_dlist_gaddr );
  ulong tower_leaves_pool_gaddr = fd_wksp_gaddr_fast( tower_ctx->wksp, forks->tower_leaves_pool );
  fd_tower_leaf_t * leaves_pool = (fd_tower_leaf_t *)fd_wksp_laddr_fast( wksp, tower_leaves_pool_gaddr );

  ulong leaf_count = 0;
  for( fd_tower_leaves_dlist_iter_t iter = fd_tower_leaves_dlist_iter_fwd_init( leaves_dlist, leaves_pool );
                                          !fd_tower_leaves_dlist_iter_done( iter, leaves_dlist, leaves_pool );
                                    iter = fd_tower_leaves_dlist_iter_fwd_next( iter, leaves_dlist, leaves_pool ) ) {
    fd_tower_leaf_t * leaf = fd_tower_leaves_dlist_iter_ele( iter, leaves_dlist, leaves_pool );
    if( FD_LIKELY( leaf ) ) {
      fd_tower_forks_t * fork = fd_tower_forks_query( map, leaf->slot, NULL );
      printf( "Leaf slot: %lu", leaf->slot );
      if( fork->voted )     printf( " [voted]"     );
      if( fork->confirmed ) printf( " [confirmed]" );
      printf( "\n" );
      leaf_count++;
    }
  }
  printf( "\nTotal leaves: %lu\n", leaf_count );
  printf( "Total slots: %lu\n", slot_count );
  printf( "\n" );
}

static const char * HELP =
  "\n\n"
  "usage: tower [-h] {forks}\n"
  "\n"
  "positional arguments:\n"
  "  {forks}\n"
  "    forks              prints the tower forks tree structure and leaves\n"
  "    ghost              prints the ghost fork choice structure\n"
  "    tower              prints the local tower\n"
  "\n"
  "optional arguments:\n"
  "  -h, --help            show this help message and exit\n";

static const char * FORKS_HELP =
  "\n\n"
  "usage: tower forks [-h]\n"
  "\n"
  "optional arguments:\n"
  "  -h, --help            show this help message and exit\n";

static const char * GHOST_HELP =
  "\n\n"
  "usage: tower ghost [-h]\n"
  "\n"
  "optional arguments:\n"
  "  -h, --help            show this help message and exit\n";

static const char * TOWER_HELP =
  "\n\n"
  "usage: tower tower [-h]\n"
  "\n"
  "optional arguments:\n"
  "  -h, --help            show this help message and exit\n";

void
tower_cmd_help( char const * arg ) {
  if      ( FD_LIKELY( !arg                    ) ) FD_LOG_NOTICE(( "%s", HELP           ));
  else if ( FD_LIKELY( !strcmp( arg, "forks" ) ) ) FD_LOG_NOTICE(( "%s", FORKS_HELP    ));
  else if ( FD_LIKELY( !strcmp( arg, "ghost" ) ) ) FD_LOG_NOTICE(( "%s", GHOST_HELP    ));
  else if ( FD_LIKELY( !strcmp( arg, "tower" ) ) ) FD_LOG_NOTICE(( "%s", TOWER_HELP    ));
  else                                             FD_LOG_NOTICE(( "%s", HELP           ));
}

static void
tower_cmd_fn_forks( args_t *   args,
                    config_t * config ) {
  ctx_t *          tower_ctx;
  fd_topo_wksp_t * tower_wksp;
  tower_ctx_wksp( args, config, &tower_ctx, &tower_wksp );

  ulong forks_gaddr = fd_wksp_gaddr_fast( tower_ctx->wksp, tower_ctx->forks );
  fd_forks_t * forks = (fd_forks_t *)fd_wksp_laddr( tower_wksp->wksp, forks_gaddr );

  for( ;; ) {
    print_all_forks( tower_wksp->wksp, tower_ctx, forks );
    sleep( 1 );
  }
}

static void
tower_cmd_fn_ghost( args_t *   args,
                    config_t * config ) {
  ctx_t *          tower_ctx;
  fd_topo_wksp_t * tower_wksp;
  tower_ctx_wksp( args, config, &tower_ctx, &tower_wksp );

  ulong ghost_gaddr = fd_wksp_gaddr_fast( tower_ctx->wksp, tower_ctx->ghost );
  fd_ghost_t * ghost = (fd_ghost_t *)fd_wksp_laddr( tower_wksp->wksp, ghost_gaddr );
  fd_ghost_root( ghost );
  FD_LOG_NOTICE(( "root slot %lu", fd_ghost_root( ghost )->slot ));

  for( ;; ) {
    fd_ghost_print( ghost, fd_ghost_root( ghost ), NULL );
    sleep( 1 );
  }
}

static void
tower_cmd_fn_tower( args_t    * args,
                     config_t * config ) {
  ctx_t *          tower_ctx;
  fd_topo_wksp_t * tower_wksp;
  tower_ctx_wksp( args, config, &tower_ctx, &tower_wksp );

  ulong tower_laddr = fd_wksp_gaddr_fast( tower_ctx->wksp, tower_ctx->tower );
  fd_tower_t * tower = (fd_tower_t *)fd_wksp_laddr( tower_wksp->wksp, tower_laddr );

  for( ;; ) {
    fd_tower_print( tower, ULONG_MAX, NULL );
    sleep( 1 );
  }
}

void
tower_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args ) {

  /* help */
  args->tower.help = fd_env_strip_cmdline_contains( pargc, pargv, "--help" );
  args->tower.help = args->tower.help || fd_env_strip_cmdline_contains( pargc, pargv, "-h" );

  /* positional arg */
  args->tower.pos_arg = (*pargv)[0];
  if( FD_UNLIKELY( !args->tower.pos_arg ) ) {
    args->tower.help = 1;
    return;
  }

  (*pargc)--;
}

static void
tower_cmd_fn( args_t *   args,
              config_t * config ) {

  if( args->tower.help ) {
    tower_cmd_help( args->tower.pos_arg );
    return;
  }

  if     ( !strcmp( args->tower.pos_arg, "forks" ) ) tower_cmd_fn_forks( args, config );
  else if( !strcmp( args->tower.pos_arg, "ghost" ) ) tower_cmd_fn_ghost( args, config );
  else if( !strcmp( args->tower.pos_arg, "tower" ) ) tower_cmd_fn_tower( args, config );
  else                                               tower_cmd_help( NULL );
}

action_t fd_action_tower = {
  .name = "tower",
  .args = tower_cmd_args,
  .fn   = tower_cmd_fn,
  .perm = dev_cmd_perm,
};
