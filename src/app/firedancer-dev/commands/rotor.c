/* The rotor command attaches to a running validator's rotor tile and
   prints the alpenglow chainer's orphan/repair worklist state. */

#include "../../../disco/topo/fd_topob.h"
#include "../../shared/fd_config.h" /* config_t */
#include "../../shared_dev/commands/dev.h" /* dev_cmd_perm */

#include "../../../discof/rotor/fd_rotor_tile.c" /* ctx_t + chainer layout helpers */

#include <stdio.h>

extern action_t fd_action_rotor;

/* rotor_chainer_reloc snapshots the chainer struct at chainer_laddr and
   fixes up its internal pointers for THIS process's mapping.  The tile
   stored direct pointers valid only in its own address space, so we
   replay fd_chainer_new's layout to recompute local addresses.  MUST
   mirror fd_chainer_new. */

static fd_chainer_t
rotor_chainer_reloc( void * chainer_laddr, ulong ele_max ) {
  fd_chainer_t c = *(fd_chainer_t *)chainer_laddr;

  ulong fec_max         = ele_max * FD_FEC_BLK_MAX;
  ulong fec_chain_cnt   = fd_fec_map_chain_cnt_est  ( fec_max );
  ulong slot_chain_cnt  = fd_slotv_map_chain_cnt_est( ele_max );
  ulong sched_chain_cnt = fd_sched_map_chain_cnt_est( ele_max );

  FD_SCRATCH_ALLOC_INIT( l, chainer_laddr );
  (void)          FD_SCRATCH_ALLOC_APPEND( l, fd_chainer_align(),      sizeof(fd_chainer_t)                        );
  c.fec_pool     = fd_fec_pool_join    ( FD_SCRATCH_ALLOC_APPEND( l, fd_fec_pool_align(),     fd_fec_pool_footprint    ( fec_max )        ) );
  c.fec_map      = fd_fec_map_join     ( FD_SCRATCH_ALLOC_APPEND( l, fd_fec_map_align(),      fd_fec_map_footprint     ( fec_chain_cnt )  ) );
  c.slotv_pool   = fd_slotv_pool_join  ( FD_SCRATCH_ALLOC_APPEND( l, fd_slotv_pool_align(),   fd_slotv_pool_footprint  ( ele_max )        ) );
  c.slotv_map    = fd_slotv_map_join   ( FD_SCRATCH_ALLOC_APPEND( l, fd_slotv_map_align(),    fd_slotv_map_footprint   ( slot_chain_cnt ) ) );
  c.sched_pool   = fd_sched_pool_join  ( FD_SCRATCH_ALLOC_APPEND( l, fd_sched_pool_align(),   fd_sched_pool_footprint  ( ele_max )        ) );
  c.sched_map    = fd_sched_map_join   ( FD_SCRATCH_ALLOC_APPEND( l, fd_sched_map_align(),    fd_sched_map_footprint   ( sched_chain_cnt )) );
  c.repair_treap = fd_sched_repair_join( FD_SCRATCH_ALLOC_APPEND( l, fd_sched_repair_align(), fd_sched_repair_footprint( ele_max )        ) );
  c.orphan_treap = fd_sched_orphan_join( FD_SCRATCH_ALLOC_APPEND( l, fd_sched_orphan_align(), fd_sched_orphan_footprint( ele_max )        ) );
  c.bfs          = bfs_join            ( FD_SCRATCH_ALLOC_APPEND( l, bfs_align(),             bfs_footprint            ( ele_max )        ) );
  c.out_queue    = out_queue_join      ( FD_SCRATCH_ALLOC_APPEND( l, out_queue_align(),       out_queue_footprint      ( fec_max )        ) );

  return c;
}

static void
rotor_cmd_args( int *    pargc FD_PARAM_UNUSED,
                char *** pargv FD_PARAM_UNUSED,
                args_t * args  FD_PARAM_UNUSED ) {}

static void
rotor_cmd_fn( args_t *   args FD_PARAM_UNUSED,
              config_t * config ) {
  fd_topo_t * topo = &config->topo;

  ulong wksp_id = fd_topo_find_wksp( topo, "rotor" );
  if( FD_UNLIKELY( wksp_id==ULONG_MAX ) ) FD_LOG_ERR(( "rotor workspace not found (is the validator running with --alpenglow?)" ));
  fd_topo_wksp_t * rotor_wksp = &topo->workspaces[ wksp_id ];
  fd_topo_join_workspace( topo, rotor_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  ulong tile_id = fd_topo_find_tile( topo, "rotor", 0UL );
  if( FD_UNLIKELY( tile_id==ULONG_MAX ) ) FD_LOG_ERR(( "rotor tile not found" ));
  fd_topo_tile_t * tile    = &topo->tiles[ tile_id ];
  void *           scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "Failed to access rotor tile scratch memory" ));

  ulong ele_max = tile->rotor.slot_max;

  /* Walk the tile scratch layout (ctx, protocol, chainer) to the chainer
     local address; mirrors the rotor tile's unprivileged_init. */
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  (void)               FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t),     sizeof(ctx_t)                    );
  (void)               FD_SCRATCH_ALLOC_APPEND( l, fd_repair_align(),  fd_repair_footprint()            );
  void * chainer_laddr = FD_SCRATCH_ALLOC_APPEND( l, fd_chainer_align(), fd_chainer_footprint( ele_max ) );

  fd_chainer_t c = rotor_chainer_reloc( chainer_laddr, ele_max );
  if( FD_UNLIKELY( c.magic!=FD_CHAINER_MAGIC ) ) FD_LOG_ERR(( "bad chainer magic 0x%lx (tile not initialized?)", c.magic ));

  fd_chainer_print( &c );
  fflush( stdout );
}

action_t fd_action_rotor = {
  .name        = "rotor",
  .args        = rotor_cmd_args,
  .fn          = rotor_cmd_fn,
  .perm        = dev_cmd_perm,
  .description = "Print the alpenglow rotor tile's chainer worklist state",
  .usage       = "rotor",
};
