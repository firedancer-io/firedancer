/* The sim command spawns a smaller topology for 2 purposes:
   1. read an archive file and reproduce the frags into the storei tile
   2. reproduce the behavior of the replay tile (e.g., the set of forks)

   The smaller topology is:
             shred_storei          store_replay       replay_exec
   playback--------------->storei-------------->replay------------>exec
     ^      \         ---->   |  <-----       /
     |       \_______/        |        \_____/
     |      repair_store      |       stake_out
     |______storei_notif______|

   Some tiles are not shown such as the metric tile.

   The playback tile will only send the next frag to the storei tile (
   either through shred_storei or through repair_store ) after receiving
   a notification for the previous frag from storei_notif.
 */

#include "../../firedancer/topology.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../../disco/topo/fd_cpu_topo.h" /* fd_topo_cpus */
#include "../../../disco/pack/fd_pack.h"
#include "../../../disco/pack/fd_pack_cost.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/pod/fd_pod_format.h"

#include <unistd.h> /* pause */

extern fd_topo_obj_callbacks_t * CALLBACKS[];
fd_topo_run_tile_t fdctl_tile_run( fd_topo_tile_t const * tile );

static void
sim_topo( config_t * config ) {
  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  enum{
  metric_cpu_idx=0,
  playback_cpu_idx,
  storei_cpu_idx,
  replay_cpu_idx,
  static_end_idx,
  };

  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_tile( topo, "metric", "metric", "metric_in", metric_cpu_idx, 0, 0 );

  fd_topob_wksp( topo, "playback" );
  fd_topob_tile( topo, "arch_p", "playback", "metric_in", playback_cpu_idx, 0, 0 );

  fd_topob_wksp( topo, "storei" );
  fd_topo_tile_t * storei_tile = fd_topob_tile( topo, "storei", "storei", "metric_in", storei_cpu_idx, 0, 0 );

  fd_topob_wksp( topo, "replay" );
  fd_topo_tile_t * replay_tile = fd_topob_tile( topo, "replay", "replay", "metric_in", replay_cpu_idx, 0, 0 );

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  fd_topob_wksp( topo, "execrp" );
  ulong exec_tile_cnt = config->firedancer.layout.execrp_tile_count;
  FOR(exec_tile_cnt) fd_topob_tile( topo, "execrp", "execrp", "metric_in", static_end_idx+i, 0, 0 );

  /**********************************************************************/
  /* Setup playback<->storei and storei<->replay links in topo          */
  /**********************************************************************/
  fd_topob_wksp( topo, "shred_storei" );
  fd_topob_wksp( topo, "repair_store" );
  fd_topob_wksp( topo, "storei_notif" );
  fd_topob_wksp( topo, "replay_epoch" );
  fd_topob_wksp( topo, "store_replay" );
  /*             topo,  link_name,      wksp_name,     depth,         mtu,                    burst */
  fd_topob_link( topo, "shred_storei", "shred_storei", 65536UL,       4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );
  fd_topob_link( topo, "repair_store", "repair_store", 1024UL*1024UL, FD_SHRED_MAX_SZ,        128UL                                          );
  fd_topob_link( topo, "storei_notif", "storei_notif", 65536UL,       4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );
  fd_topob_link( topo, "replay_epoch", "replay_epoch", 128UL,         40UL + 40200UL * 40UL,  1UL                                            );
  fd_topob_link( topo, "store_replay", "store_replay", 32768UL,       sizeof(ulong),          64UL                                           );

  /*                 topo, tile_name, tile_kind_id, link_name,      link_kind_id */
  fd_topob_tile_out( topo, "arch_p",  0UL,          "shred_storei", 0UL );
  fd_topob_tile_out( topo, "arch_p",  0UL,          "repair_store", 0UL );
  fd_topob_tile_in(  topo, "arch_p",  0UL,          "metric_in", "storei_notif",       0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /*                 topo, tile_name, tile_kind_id, fseq_wksp,   link_name,            link_kind_id, reliable,            polled */
  fd_topob_tile_in(  topo, "storei",  0UL,          "metric_in", "replay_epoch",       0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in(  topo, "storei",  0UL,          "metric_in", "repair_store",       0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_in(  topo, "storei",  0UL,          "metric_in", "shred_storei",       0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /*                 topo, tile_name, tile_kind_id, link_name,          link_kind_id */
  fd_topob_tile_out( topo, "storei",  0UL,          "store_replay",     0UL );
  fd_topob_tile_out( topo, "storei",  0UL,          "storei_notif",     0UL );

  /*                 topo, tile_name, tile_kind_id, fseq_wksp,   link_name,            link_kind_id, reliable,            polled */
  fd_topob_tile_in(  topo, "replay",  0UL,          "metric_in", "store_replay",       0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );

  /*                 topo, tile_name, tile_kind_id, link_name,          link_kind_id */
  fd_topob_tile_out( topo, "replay",  0UL,          "replay_epoch",     0UL );

  /**********************************************************************/
  /* Setup replay-->exec links in topo                                  */
  /**********************************************************************/
  fd_topob_wksp( topo, "replay_execr" );
  fd_topob_link( topo, "replay_execr", "replay_execr", 16384UL, 2240UL, 1UL );
  fd_topob_tile_out( topo, "replay", 0UL, "replay_execr", 0UL );
  for( ulong i=0; i<config->firedancer.layout.execrp_tile_count; i++ ) {
    fd_topob_tile_in( topo, "execrp", i, "metric_in", "replay_execr", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  /**********************************************************************/
  /* Setup the shared objs used by storei, replay and exec tiles        */
  /**********************************************************************/
  fd_topob_wksp( topo, "bstore"      );
  fd_topob_wksp( topo, "poh_shred"   );
  fd_topob_wksp( topo, "root_slot"   );
  fd_topob_wksp( topo, "txncache"    );
  fd_topob_wksp( topo, "poh_slot"    );
  fd_topob_wksp( topo, "bank_busy"   );
  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "poh_shred" );
  fd_topo_obj_t * root_slot_obj = fd_topob_obj( topo, "fseq", "root_slot" );
  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "txncache",
      config->firedancer.runtime.max_live_slots,
      fd_ulong_pow2_up( FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT ) );
  fd_topo_obj_t * poh_slot_obj = fd_topob_obj( topo, "fseq", "poh_slot" );
  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks", config->firedancer.runtime.max_live_slots, config->firedancer.runtime.max_fork_width, 0 );

  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, root_slot_obj->id, "root_slot" ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_slot_obj->id, "poh_slot" ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  fd_topob_tile_uses( topo, storei_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topob_tile_uses( topo, storei_tile, root_slot_obj, FD_SHMEM_JOIN_MODE_READ_ONLY  );

  fd_topob_tile_uses( topo, replay_tile, root_slot_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, poh_slot_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topob_tile_uses( topo, replay_tile, banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  for( ulong i=0UL; i<config->firedancer.layout.execle_tile_count; i++ ) {
    fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "bank_busy" );

    fd_topob_tile_uses( topo, replay_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", i ) );
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( !strcmp( tile->name, "arch_p" ) ) {
      strncpy( tile->archiver.rocksdb_path, config->tiles.archiver.rocksdb_path, PATH_MAX );
      if( FD_UNLIKELY( 0==strlen( tile->archiver.rocksdb_path ) ) ) {
        FD_LOG_ERR(( "Archive file not found for playback" ));
      } else {
        FD_LOG_NOTICE(( "Found archive file from config: %s", tile->archiver.rocksdb_path ));
      }
    } else {
      fd_topo_configure_tile( tile, config );
    }
  }

  /**********************************************************************/
  /* Finish and print out the topo information                          */
  /**********************************************************************/
  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
}

static void
sim_cmd_fn( args_t *   args FD_PARAM_UNUSED,
            config_t * config ) {
  sim_topo( config );

  initialize_workspaces( config );
  initialize_stacks( config );
  fd_topo_t * topo = &config->topo;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  /* FIXME: there's no PoH tile in this mini-topology,
   *        but replay tile waits for `poh_slot!=ULONG_MAX` before starting to vote
   *        -- vote updates the root for funk/blockstore publish */
  ulong poh_slot_obj_id = fd_pod_query_ulong( topo->props, "poh_slot", ULONG_MAX );
  FD_TEST( poh_slot_obj_id!=ULONG_MAX );
  ulong * poh = fd_fseq_join( fd_topo_obj_laddr( topo, poh_slot_obj_id ) );
  fd_fseq_update( poh, 0UL );

  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );
  for(;;) pause();
}

static void
sim_cmd_perm( args_t *         args   FD_PARAM_UNUSED,
              fd_cap_chk_t *   chk    FD_PARAM_UNUSED,
              config_t const * config FD_PARAM_UNUSED ) {}

static void
sim_cmd_args( int *    pargc FD_PARAM_UNUSED,
              char *** pargv FD_PARAM_UNUSED,
              args_t * args  FD_PARAM_UNUSED ) {}

action_t fd_action_sim = {
  .name = "sim",
  .args = sim_cmd_args,
  .fn   = sim_cmd_fn,
  .perm = sim_cmd_perm,
};
