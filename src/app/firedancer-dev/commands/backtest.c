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
                store_replay

*/

#include "../../firedancer/topology.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include "../../platform/fd_sys_util.h"
#include "../../../disco/tiles.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../discof/replay/fd_replay_notif.h"
#include "../../../discof/reasm/fd_reasm.h"
#include "../../../flamenco/runtime/fd_runtime_public.h" /* FD_RUNTIME_PUBLIC_ACCOUNT_UPDATE_MSG_MTU */
#include "../main.h"

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
  fd_topo_tile_t * backtest_tile = fd_topob_tile( topo, "back", "back", "metric_in", cpu_idx++, 0, 0 );

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
      config->firedancer.funk.heap_size_gib,
      config->firedancer.funk.lock_pages );

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
  /* Add the snapshot tiles to topo                                       */
  /**********************************************************************/
  fd_topob_wksp( topo, "snaprd" );
  fd_topob_wksp( topo, "snapdc" );
  fd_topob_wksp( topo, "snapin" );
  fd_topo_tile_t * snaprd_tile = fd_topob_tile( topo, "snaprd",  "snaprd",  "metric_in",  cpu_idx++, 0, 0 );
  fd_topo_tile_t * snapdc_tile = fd_topob_tile( topo, "snapdc",  "snapdc",  "metric_in",  cpu_idx++, 0, 0 );
  fd_topo_tile_t * snapin_tile = fd_topob_tile( topo, "snapin",  "snapin",  "metric_in",  cpu_idx++, 0, 0 );
  snaprd_tile->allow_shutdown = 1;
  snapdc_tile->allow_shutdown = 1;
  snapin_tile->allow_shutdown = 1;

  /**********************************************************************/
  /* Setup backtest->replay link (repair_repla) in topo                 */
  /**********************************************************************/

  /* The repair tile is replaced by the backtest tile for the repair to
     replay link.  The frag interface is a "slice", ie. entry batch,
     which is provided by the backtest tile, which reads in the entry
     batches from the CLI-specified source (eg. RocksDB). */

  fd_topob_wksp( topo, "repair_repla" );
  fd_topob_link( topo, "repair_repla", "repair_repla", 65536UL, sizeof(fd_reasm_fec_t), 1UL );
  fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "repair_repla", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "back", 0UL, "repair_repla", 0UL );

  /**********************************************************************/
  /* Setup snapshot links in topo                                       */
  /**********************************************************************/
  fd_topob_wksp( topo, "snap_zstd" );
  fd_topob_wksp( topo, "snap_stream");
  fd_topob_wksp( topo, "snapdc_rd" );
  fd_topob_wksp( topo, "snapin_rd" );
  fd_topob_wksp( topo, "snap_out" );
  fd_topob_wksp( topo, "replay_manif" );
  /* TODO: Should be depth of 1 or 2, not 4, but it causes backpressure
     from the replay tile parsing the manifest, remove when this is
     fixed. */
  fd_topob_link( topo, "snap_out", "snap_out", 4UL, 5UL*(1UL<<30UL), 1UL );

  fd_topob_link( topo, "snap_zstd",   "snap_zstd",   8192UL, 16384UL,    1UL );
  fd_topob_link( topo, "snap_stream", "snap_stream", 2048UL, USHORT_MAX, 1UL );
  fd_topob_link( topo, "snapdc_rd", "snapdc_rd", 128UL, 0UL, 1UL );
  fd_topob_link( topo, "snapin_rd", "snapin_rd", 128UL, 0UL, 1UL );

  fd_topob_tile_out( topo, "snaprd", 0UL, "snap_zstd",   0UL );
  fd_topob_tile_in ( topo, "snapdc", 0UL, "metric_in",   "snap_zstd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapdc", 0UL, "snap_stream", 0UL );
  fd_topob_tile_in ( topo, "snapin", 0UL, "metric_in",   "snap_stream", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );
  fd_topob_tile_out( topo, "snapin", 0UL, "snap_out",    0UL );
  fd_topob_tile_in ( topo, "replay", 0UL, "metric_in",   "snap_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  fd_topob_tile_in( topo, "snaprd", 0UL, "metric_in", "snapdc_rd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapdc", 0UL, "snapdc_rd", 0UL );
  fd_topob_tile_in( topo, "snaprd", 0UL, "metric_in", "snapin_rd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapin", 0UL, "snapin_rd", 0UL );

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
  fd_topob_wksp( topo, "root_out" );
  fd_topob_link( topo, "root_out", "root_out", 128UL, 0UL, 1UL );
  fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "root_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "back", 0UL, "root_out", 0UL );

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
  /* Setup writer->replay links in topo, to send solcap account updates
     so that they are serialized, and to notify replay tile that a txn
     has been finalized by the writer tile. */
  /**********************************************************************/
  fd_topob_wksp( topo, "writ_repl" );
  FOR(writer_tile_cnt) fd_topob_link( topo, "writ_repl", "writ_repl", 1UL, FD_RUNTIME_PUBLIC_ACCOUNT_UPDATE_MSG_FOOTPRINT, 1UL );
  FOR(writer_tile_cnt) fd_topob_tile_out( topo, "writer", i, "writ_repl", i );
  FOR(writer_tile_cnt) fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "writ_repl", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  /**********************************************************************/
  /* Setup the shared objs used by replay and exec tiles                */
  /**********************************************************************/

  fd_topob_wksp( topo, "slot_fseqs"  ); /* fseqs for marked slots eg. turbine slot */

  fd_topob_wksp( topo, "store" );
  fd_topo_obj_t * store_obj = setup_topo_store( topo, "store", config->firedancer.store.max_completed_shred_sets, 1 );
  fd_topob_tile_uses( topo, backtest_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, store_obj->id, "store" ) );

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
  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks", config->firedancer.runtime.limits.max_total_banks, config->firedancer.runtime.limits.max_fork_width );
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

  /* txncache_obj, busy_obj and poh_slot_obj only by replay tile */
  fd_topob_wksp( topo, "tcache"      );
  fd_topob_wksp( topo, "bank_busy"   );
  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "tcache",
      config->firedancer.runtime.limits.max_rooted_slots,
      config->firedancer.runtime.limits.max_live_slots,
      config->firedancer.runtime.limits.max_transactions_per_slot );
  fd_topob_tile_uses( topo, replay_tile, txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );
  for( ulong i=0UL; i<bank_tile_cnt; i++ ) {
    fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "bank_busy" );
    fd_topob_tile_uses( topo, replay_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", i ) );
  }

  /* Replay decoded manifest dcache topo obj */
  fd_topo_obj_t * replay_manifest_dcache = fd_topob_obj( topo, "dcache", "replay_manif" );
  fd_pod_insertf_ulong( topo->props, 2UL << 30UL, "obj.%lu.data_sz", replay_manifest_dcache->id );
  fd_pod_insert_ulong(  topo->props, "manifest_dcache", replay_manifest_dcache->id );

  fd_topob_tile_uses( topo, snapin_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, snapin_tile, replay_manifest_dcache, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, replay_manifest_dcache, FD_SHMEM_JOIN_MODE_READ_ONLY );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( !fd_topo_configure_tile( tile, config ) ) {
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
}

extern int * fd_log_private_shared_lock;

static void
backtest_cmd_topo( config_t * config ) {
  backtest_topo( config );
}

static args_t
configure_args( void ) {
  args_t args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  ulong stage_idx = 0UL;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_hugetlbfs;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_normalpage;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_snapshots;
  args.configure.stages[ stage_idx++ ] = NULL;

  return args;
}

void
backtest_cmd_perm( args_t *         args FD_PARAM_UNUSED,
                   fd_cap_chk_t *   chk,
                   config_t const * config ) {
  args_t c_args = configure_args();
  configure_cmd_perm( &c_args, chk, config );
  run_cmd_perm( NULL, chk, config );
}

static void
backtest_cmd_fn( args_t *   args FD_PARAM_UNUSED,
                 config_t * config ) {
  args_t c_args = configure_args();
  configure_cmd_fn( &c_args, config );

  run_firedancer_init( config, 1, 0 );

  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_fill( &config->topo );

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  double ns_per_tick = 1.0/tick_per_ns;

  long start = fd_log_wallclock();
  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );

  fd_topo_t * topo = &config->topo;

  fd_topo_tile_t * snaprd_tile = &topo->tiles[ fd_topo_find_tile( topo, "snaprd", 0UL ) ];
  fd_topo_tile_t * snapdc_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapdc", 0UL ) ];
  fd_topo_tile_t * snapin_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ];

  ulong volatile * const snaprd_metrics = fd_metrics_tile( snaprd_tile->metrics );
  ulong volatile * const snapdc_metrics = fd_metrics_tile( snapdc_tile->metrics );
  ulong volatile * const snapin_metrics = fd_metrics_tile( snapin_tile->metrics );

  ulong total_off_old    = 0UL;
  ulong snaprd_backp_old = 0UL;
  ulong snaprd_wait_old  = 0UL;
  ulong snapdc_backp_old = 0UL;
  ulong snapdc_wait_old  = 0UL;
  ulong snapin_backp_old = 0UL;
  ulong snapin_wait_old  = 0UL;
  ulong acc_cnt_old      = 0UL;
  sleep( 1 );
  puts( "-------------backp=(snaprd,snapdc,snapin) busy=(snaprd,snapdc,snapin)---------------" );
  long next = start+1000L*1000L*1000L;
  for(;;) {
    ulong snaprd_status = FD_VOLATILE_CONST( snaprd_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapdc_status = FD_VOLATILE_CONST( snapdc_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapin_status = FD_VOLATILE_CONST( snapin_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );

    if( FD_UNLIKELY( snaprd_status==2UL && snapdc_status==2UL && snapin_status == 2UL ) ) break;

    long cur = fd_log_wallclock();
    if( FD_UNLIKELY( cur<next ) ) {
      long sleep_nanos = fd_long_min( 1000L*1000L, next-cur );
      FD_TEST( !fd_sys_util_nanosleep(  (uint)(sleep_nanos/(1000L*1000L*1000L)), (uint)(sleep_nanos%(1000L*1000L*1000L)) ) );
      continue;
    }

    ulong total_off    = snaprd_metrics[ MIDX( GAUGE, SNAPRD, FULL_BYTES_READ ) ] +
                         snaprd_metrics[ MIDX( GAUGE, SNAPRD, INCREMENTAL_BYTES_READ ) ];
    ulong snaprd_backp = snaprd_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snaprd_wait  = snaprd_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG    ) ] +
                         snaprd_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snaprd_backp;
    ulong snapdc_backp = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapdc_wait  = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG    ) ] +
                         snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapdc_backp;
    ulong snapin_backp = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapin_wait  = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG    ) ] +
                         snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapin_backp;

    ulong acc_cnt      = snapin_metrics[ MIDX( GAUGE, SNAPIN, ACCOUNTS_INSERTED    ) ];
    printf( "bw=%4.0f MB/s backp=(%3.0f%%,%3.0f%%,%3.0f%%) busy=(%3.0f%%,%3.0f%%,%3.0f%%) acc=%3.1f M/s\n",
            (double)( total_off-total_off_old )/1e6,
            ( (double)( snaprd_backp-snaprd_backp_old )*ns_per_tick )/1e7,
            ( (double)( snapdc_backp-snapdc_backp_old )*ns_per_tick )/1e7,
            ( (double)( snapin_backp-snapin_backp_old )*ns_per_tick )/1e7,
            100-( ( (double)( snaprd_wait-snaprd_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snapdc_wait-snapdc_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snapin_wait-snapin_wait_old  )*ns_per_tick )/1e7 ),
            (double)( acc_cnt-acc_cnt_old  )/1e6 );
    fflush( stdout );
    total_off_old    = total_off;
    snaprd_backp_old = snaprd_backp;
    snaprd_wait_old  = snaprd_wait;
    snapdc_backp_old = snapdc_backp;
    snapdc_wait_old  = snapdc_wait;
    snapin_backp_old = snapin_backp;
    snapin_wait_old  = snapin_wait;
    acc_cnt_old      = acc_cnt;

    next+=1000L*1000L*1000L;
  }

  for(;;) pause();
}

action_t fd_action_backtest = {
  .name = "backtest",
  .fn   = backtest_cmd_fn,
  .perm = backtest_cmd_perm,
  .topo = backtest_cmd_topo,
};
