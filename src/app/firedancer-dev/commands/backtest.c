/* The backtest command spawns a smaller topology for replaying shreds from
   rocksdb (or other sources TBD) and reproduce the behavior of replay tile.

   The smaller topology is:
           repair_repla         replay_exec       exec_writer
   backtest-------------->replay------------->exec------------->writer
     ^                    |^ | |                                   ^
     |____________________|| | |___________________________________|
          replay_notif     | |
                           | |------------------------------>no consumer
    no producer-------------  stake_out, send_out, poh_out
                store_replay,
                pack_replay,
                batch_replay

*/

#include "../../firedancer/topology.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include "../../../disco/tiles.h"
#include "../../../disco/topo/fd_cpu_topo.h" /* fd_topo_cpus */
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../discof/replay/fd_replay_notif.h"
#include "../../../flamenco/runtime/fd_runtime.h"
#include "../../../flamenco/runtime/fd_txncache.h"

#include <unistd.h> /* pause */
extern fd_topo_obj_callbacks_t * CALLBACKS[];
fd_topo_run_tile_t fdctl_tile_run( fd_topo_tile_t const * tile );

static void
backtest_topo( config_t * config ) {
  ulong exec_tile_cnt   = config->firedancer.layout.exec_tile_count;
  ulong writer_tile_cnt = config->firedancer.layout.writer_tile_count;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  ulong cpu_idx = 0;

  /**********************************************************************/
  /* Add the metric tile to topo                                        */
  /**********************************************************************/
  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_tile( topo, "metric", "metric", "metric_in", cpu_idx++, 0, 0 );

  /**********************************************************************/
  /* Add the backtest tile to topo                                      */
  /**********************************************************************/
  fd_topob_wksp( topo, "back" );
  fd_topo_tile_t * backtest_tile   = fd_topob_tile( topo, "back", "back", "metric_in", cpu_idx++, 0, 0 );
  FD_LOG_NOTICE(( "Found rocksdb path from config: %s", backtest_tile->archiver.archiver_path ));

  /**********************************************************************/
  /* Add the replay tile to topo                                        */
  /**********************************************************************/
  fd_topob_wksp( topo, "replay" );
  fd_topo_tile_t * replay_tile = fd_topob_tile( topo, "replay", "replay", "metric_in", cpu_idx++, 0, 0 );

  /* specified by [tiles.replay] */

  fd_topob_wksp( topo, "funk" );
  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions,
      config->firedancer.funk.heap_size_gib );

  fd_topob_tile_uses( topo, replay_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  /**********************************************************************/
  /* Add the executor tiles to topo                                     */
  /**********************************************************************/
  fd_topob_wksp( topo, "exec" );
  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )
  FOR(exec_tile_cnt) fd_topob_tile( topo, "exec",   "exec",   "metric_in", cpu_idx++, 0, 0 );

  /**********************************************************************/
  /* Add the writer tiles to topo                                       */
  /**********************************************************************/
  fd_topob_wksp( topo, "writer" );
  FOR(writer_tile_cnt) fd_topob_tile( topo, "writer",  "writer",  "metric_in",  cpu_idx++, 0, 0 );

  /**********************************************************************/
  /* Setup backtest->replay links in topo                               */
  /**********************************************************************/

  /* The repair tile is replaced by the backtest tile for the repair to
     replay link.  The frag interface is a "slice", ie. entry batch,
     which is provided by the backtest tile, which reads in the entry
     batches from the CLI-specified source (eg. RocksDB). */

  fd_topob_wksp( topo, "repair_repla" );
  fd_topob_link( topo, "repair_repla", "repair_repla", 65536UL, sizeof(ulong), 1UL );
  fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "repair_repla", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "back", 0UL, "repair_repla", 0UL );

  /**********************************************************************/
  /* Setup pack/batch->replay links in topo w/o a producer              */
  /**********************************************************************/
  fd_topob_wksp( topo, "pack_replay" );
  fd_topob_wksp( topo, "batch_replay" );
  fd_topob_link( topo, "pack_replay", "pack_replay", 65536UL, USHORT_MAX, 1UL );
  fd_topob_link( topo, "batch_replay", "batch_replay", 128UL, 32UL, 1UL );
  fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "pack_replay", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "batch_replay", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  topo->links[ replay_tile->in_link_id[ fd_topo_find_tile_in_link( topo, replay_tile, "pack_replay", 0 ) ] ].permit_no_producers = 1;
  topo->links[ replay_tile->in_link_id[ fd_topo_find_tile_in_link( topo, replay_tile, "batch_replay", 0 ) ] ].permit_no_producers = 1;

  /**********************************************************************/
  /* More backtest->replay links in topo                                */
  /**********************************************************************/

  /* The tower tile is replaced by the backtest tile for the tower to
     replay link.  The backtest tile simply sends monotonically
     increasing rooted slot numbers to the replay tile, once after each
     "replayed a full slot" notification received from the replay tile.
     This allows the replay tile to advance its watermark, and publish
     various data structures.  This is an oversimplified barebones mock
     of the tower tile. */
  fd_topob_wksp( topo, "tower_replay" );
  fd_topob_link( topo, "tower_replay", "tower_replay", 128UL, 0UL, 1UL );
  fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "tower_replay", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "back", 0UL, "tower_replay", 0UL );

  /**********************************************************************/
  /* Setup replay->stake/send/poh links in topo w/o consumers         */
  /**********************************************************************/
  fd_topob_wksp( topo, "stake_out"    );
  fd_topob_wksp( topo, "replay_poh"   );

  fd_topob_link( topo, "stake_out",   "stake_out",   128UL, 40UL + 40200UL * 40UL, 1UL );
  ulong bank_tile_cnt   = config->layout.bank_tile_count;
  FOR(bank_tile_cnt) fd_topob_link( topo, "replay_poh", "replay_poh", 128UL, (4096UL*sizeof(fd_txn_p_t))+sizeof(fd_microblock_trailer_t), 1UL );

  fd_topob_tile_out( topo, "replay", 0UL, "stake_out",   0UL );
  FOR(bank_tile_cnt) fd_topob_tile_out( topo, "replay", 0UL, "replay_poh", i );

  topo->links[ replay_tile->out_link_id[ fd_topo_find_tile_out_link( topo, replay_tile, "stake_out",   0 ) ] ].permit_no_consumers = 1;
  FOR(bank_tile_cnt) topo->links[ replay_tile->out_link_id[ fd_topo_find_tile_out_link( topo, replay_tile, "replay_poh", i ) ] ].permit_no_consumers = 1;

  /**********************************************************************/
  /* Setup replay->backtest link (replay_notif) in topo                 */
  /**********************************************************************/
  fd_topob_wksp( topo, "replay_notif" );
  fd_topob_link( topo, "replay_notif", "replay_notif", FD_REPLAY_NOTIF_DEPTH, FD_REPLAY_NOTIF_MTU, 1UL );
  fd_topob_tile_in(  topo, "back", 0UL, "metric_in", "replay_notif", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "replay", 0UL, "replay_notif", 0UL );

  /**********************************************************************/
  /* Setup replay->exec links in topo                                   */
  /**********************************************************************/
  fd_topob_wksp( topo, "replay_exec" );
  for( ulong i=0; i<exec_tile_cnt; i++ ) {
    fd_topob_link( topo, "replay_exec", "replay_exec", 128UL, 10240UL, exec_tile_cnt );
    fd_topob_tile_out( topo, "replay", 0UL, "replay_exec", i );
    fd_topob_tile_in( topo, "exec", i, "metric_in", "replay_exec", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  /**********************************************************************/
  /* Setup exec->writer links in topo                                   */
  /**********************************************************************/
  fd_topob_wksp( topo, "exec_writer" );
  FOR(exec_tile_cnt) fd_topob_link( topo, "exec_writer", "exec_writer", 128UL, FD_EXEC_WRITER_MTU, 1UL );
  FOR(exec_tile_cnt) fd_topob_tile_out( topo, "exec", i, "exec_writer", i );
  FOR(writer_tile_cnt) for( ulong j=0UL; j<exec_tile_cnt; j++ )
    fd_topob_tile_in( topo, "writer", i, "metric_in", "exec_writer", j, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  /**********************************************************************/
  /* Setup the shared objs used by replay and exec tiles                */
  /**********************************************************************/

  fd_topob_wksp( topo, "slot_fseqs"  ); /* fseqs for marked slots eg. turbine slot */

  /* blockstore_obj shared by replay and backtest tiles */
  fd_topob_wksp( topo, "blockstore" );
  fd_topo_obj_t * blockstore_obj = setup_topo_blockstore( topo, "blockstore", config->firedancer.blockstore.shred_max, config->firedancer.blockstore.block_max, config->firedancer.blockstore.idx_max, config->firedancer.blockstore.txn_max, config->firedancer.blockstore.alloc_max );
  fd_topob_tile_uses( topo, replay_tile, blockstore_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, backtest_tile, blockstore_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, blockstore_obj->id, "blockstore" ) );

  fd_topo_obj_t * root_slot_obj = fd_topob_obj( topo, "fseq", "slot_fseqs" );
  fd_topob_tile_uses( topo, backtest_tile,  root_slot_obj, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  fd_topob_tile_uses( topo, replay_tile, root_slot_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, root_slot_obj->id, "root_slot" ) );

  fd_topo_obj_t * turbine_slot0_obj = fd_topob_obj( topo, "fseq", "slot_fseqs" );
  fd_topob_tile_uses( topo, backtest_tile, turbine_slot0_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, turbine_slot0_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, turbine_slot0_obj->id, "turbine_slot0" ) );

  fd_topo_obj_t * turbine_slot_obj = fd_topob_obj( topo, "fseq", "slot_fseqs" );
  fd_topob_tile_uses( topo, backtest_tile, turbine_slot_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, turbine_slot_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, turbine_slot_obj->id, "turbine_slot" ) );

  /* runtime_pub_obj shared by replay, exec and writer tiles */
  fd_topob_wksp( topo, "runtime_pub" );
  fd_topo_obj_t * runtime_pub_obj = setup_topo_runtime_pub( topo, "runtime_pub", config->firedancer.runtime.heap_size_gib<<30 );
  fd_topob_tile_uses( topo, replay_tile, runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FOR(writer_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", i ) ], runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, runtime_pub_obj->id, "runtime_pub" ) );

  /* banks_obj shared by replay, exec and writer tiles */
  fd_topob_wksp( topo, "banks" );
  FD_LOG_WARNING(("max_banks: %lu", config->firedancer.runtime.limits.max_banks));
  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks", config->firedancer.runtime.limits.max_banks );
  fd_topob_tile_uses( topo, replay_tile, banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(writer_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", i ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  /* bank_hash_cmp_obj shared by replay, exec and writer tiles */
  fd_topob_wksp( topo, "bh_cmp" );
  fd_topo_obj_t * bank_hash_cmp_obj = setup_topo_bank_hash_cmp( topo, "bh_cmp" );
  fd_topob_tile_uses( topo, replay_tile, bank_hash_cmp_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], bank_hash_cmp_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, bank_hash_cmp_obj->id, "bh_cmp" ) );

  /* exec_spad_obj shared by replay, exec and writer tiles */
  fd_topob_wksp( topo, "exec_spad" );
  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    fd_topo_obj_t * exec_spad_obj = fd_topob_obj( topo, "exec_spad", "exec_spad" );
    fd_topob_tile_uses( topo, replay_tile, exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    for( ulong j=0UL; j<writer_tile_cnt; j++ ) {
      /* For txn_ctx. */
      fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", j ) ], exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    }
    FD_TEST( fd_pod_insertf_ulong( topo->props, exec_spad_obj->id, "exec_spad.%lu", i ) );
  }

  /* exec_fseq_obj shared by replay and exec tiles */
  fd_topob_wksp( topo, "exec_fseq" );
  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    fd_topo_obj_t * exec_fseq_obj = fd_topob_obj( topo, "fseq", "exec_fseq" );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], exec_fseq_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, replay_tile, exec_fseq_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    FD_TEST( fd_pod_insertf_ulong( topo->props, exec_fseq_obj->id, "exec_fseq.%lu", i ) );
  }

  /* writer_fseq_obj shared by replay and writer tiles */
  fd_topob_wksp( topo, "writer_fseq" );
  for( ulong i=0UL; i<writer_tile_cnt; i++ ) {
    fd_topo_obj_t * writer_fseq_obj = fd_topob_obj( topo, "fseq", "writer_fseq" );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", i ) ], writer_fseq_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, replay_tile, writer_fseq_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    FD_TEST( fd_pod_insertf_ulong( topo->props, writer_fseq_obj->id, "writer_fseq.%lu", i ) );
  }

  /* txncache_obj, busy_obj, poh_slot_obj and constipated_obj only by replay tile */
  fd_topob_wksp( topo, "tcache"      );
  fd_topob_wksp( topo, "bank_busy"   );
  fd_topob_wksp( topo, "constipate"  );
  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "tcache",
      config->firedancer.runtime.limits.max_rooted_slots,
      config->firedancer.runtime.limits.max_live_slots,
      config->firedancer.runtime.limits.max_transactions_per_slot,
      fd_txncache_max_constipated_slots_est( config->firedancer.runtime.limits.snapshot_grace_period_seconds ) );
  fd_topob_tile_uses( topo, replay_tile, txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );
  for( ulong i=0UL; i<bank_tile_cnt; i++ ) {
    fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "bank_busy" );
    fd_topob_tile_uses( topo, replay_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", i ) );
  }
  fd_topo_obj_t * constipated_obj = fd_topob_obj( topo, "fseq", "constipate" );
  fd_topob_tile_uses( topo, replay_tile, constipated_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, constipated_obj->id, "constipate" ) );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( !strcmp( tile->name, "rocksdb" ) ) {
      tile->archiver.end_slot = config->tiles.archiver.end_slot;
      strncpy( tile->archiver.archiver_path, config->tiles.archiver.archiver_path, PATH_MAX );
      if( FD_UNLIKELY( 0==strlen( tile->archiver.archiver_path ) ) ) {
        FD_LOG_ERR(( "Rocksdb not found, check `archiver.archiver_path` in toml" ));
      } else {
        FD_LOG_NOTICE(( "Found rocksdb path from config: %s", tile->archiver.archiver_path ));
      }
    } else if( !fd_topo_configure_tile( tile, config ) ) {
      FD_LOG_ERR(( "unknown tile name %lu `%s`", i, tile->name ));
    }

    /* Override */
    if( !strcmp( tile->name, "replay" ) ) {
      tile->replay.enable_bank_hash_cmp = 0;
      tile->replay.enable_features_cnt = config->tiles.replay.enable_features_cnt;
      for( ulong i = 0; i < tile->replay.enable_features_cnt; i++ ) {
        strncpy( tile->replay.enable_features[i], config->tiles.replay.enable_features[i], sizeof(tile->replay.enable_features[i]) );
      }
    }
  }

  /**********************************************************************/
  /* Finish and print out the topo information                          */
  /**********************************************************************/
  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
}

static void
backtest_cmd_fn( args_t *   args FD_PARAM_UNUSED,
                config_t * config ) {
  backtest_topo( config );

  initialize_workspaces( config );
  initialize_stacks( config );
  fd_topo_t * topo = &config->topo;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run, NULL );
  for(;;) pause();
}

static void
backtest_cmd_perm( args_t *         args   FD_PARAM_UNUSED,
                   fd_cap_chk_t *   chk    FD_PARAM_UNUSED,
                   config_t const * config FD_PARAM_UNUSED ) {}

static void
backtest_cmd_args( int *    pargc FD_PARAM_UNUSED,
                   char *** pargv FD_PARAM_UNUSED,
                   args_t * args  FD_PARAM_UNUSED ) {}

action_t fd_action_backtest = {
  .name = "backtest",
  .args = backtest_cmd_args,
  .fn   = backtest_cmd_fn,
  .perm = backtest_cmd_perm,
};
