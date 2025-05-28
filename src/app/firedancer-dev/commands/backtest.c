/* The backtest command spawns a smaller topology for replaying shreds from
   rocksdb (or other sources TBD) and reproduce the behavior of replay tile.

   The smaller topology is:
           repair_repla         replay_exec       exec_writer
   backtest-------------->replay------------->exec------------->writer
     ^                    |^ | |                                   ^
     |____________________|| | |___________________________________|
          replay_notif     | |              replay_wtr
                           | |------------------------------>no consumer
    no producer-------------  stake_out, sender_out, poh_out
                store_replay,
                pack_replay,
                batch_replay

*/

#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include "../../../disco/tiles.h"
#include "../../../disco/topo/fd_cpu_topo.h" /* fd_topo_cpus */
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../discof/replay/fd_replay_notif.h"
#include "../../../flamenco/runtime/fd_runtime.h"
#include "../../../flamenco/runtime/fd_txncache.h"
#include "../../../flamenco/snapshot/fd_snapshot_base.h"

#include <unistd.h> /* pause */
extern fd_topo_obj_callbacks_t * CALLBACKS[];
fd_topo_run_tile_t fdctl_tile_run( fd_topo_tile_t const * tile );

static fd_topo_obj_t *
setup_topo_runtime_pub( fd_topo_t *  topo,
                        char const * wksp_name,
                        ulong        mem_max ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "runtime_pub", wksp_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, mem_max, "obj.%lu.mem_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, 12UL,    "obj.%lu.wksp_tag", obj->id ) );
  return obj;
}

static fd_topo_obj_t *
setup_topo_txncache( fd_topo_t *  topo,
                    char const * wksp_name,
                    ulong        max_rooted_slots,
                    ulong        max_live_slots,
                    ulong        max_txn_per_slot,
                    ulong        max_constipated_slots ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "txncache", wksp_name );

  FD_TEST( fd_pod_insertf_ulong( topo->props, max_rooted_slots, "obj.%lu.max_rooted_slots", obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_live_slots,   "obj.%lu.max_live_slots",   obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_txn_per_slot, "obj.%lu.max_txn_per_slot", obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_constipated_slots, "obj.%lu.max_constipated_slots", obj->id ) );

  return obj;
}

#include <sys/random.h>
#include "../../../flamenco/runtime/fd_blockstore.h"
static fd_topo_obj_t *
setup_topo_blockstore( fd_topo_t *  topo,
                       char const * wksp_name,
                       ulong        shred_max,
                       ulong        block_max,
                       ulong        idx_max,
                       ulong        txn_max,
                       ulong        alloc_max ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "blockstore", wksp_name );

  ulong seed;
  FD_TEST( sizeof(ulong) == getrandom( &seed, sizeof(ulong), 0 ) );

  FD_TEST( fd_pod_insertf_ulong( topo->props, 1UL,        "obj.%lu.wksp_tag",   obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, seed,       "obj.%lu.seed",       obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, shred_max,  "obj.%lu.shred_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, block_max,  "obj.%lu.block_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, idx_max,    "obj.%lu.idx_max",    obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txn_max,    "obj.%lu.txn_max",    obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, alloc_max,  "obj.%lu.alloc_max",  obj->id ) );

  /* DO NOT MODIFY LOOSE WITHOUT CHANGING HOW BLOCKSTORE ALLOCATES INTERNAL STRUCTURES */

  ulong blockstore_footprint = fd_blockstore_footprint( shred_max, block_max, idx_max, txn_max ) + alloc_max;
  FD_TEST( fd_pod_insertf_ulong( topo->props, blockstore_footprint,  "obj.%lu.loose", obj->id ) );

  return obj;
}

static void
setup_snapshots( config_t *       config,
                 fd_topo_tile_t * tile ) {
  uchar incremental_is_file, incremental_is_url;
  if( strnlen( config->tiles.replay.incremental, PATH_MAX )>0UL ) {
    incremental_is_file = 1U;
  } else {
    incremental_is_file = 0U;
  }
  if( strnlen( config->tiles.replay.incremental_url, PATH_MAX )>0UL ) {
    incremental_is_url = 1U;
  } else {
    incremental_is_url = 0U;
  }
  if( FD_UNLIKELY( incremental_is_file && incremental_is_url ) ) {
    FD_LOG_ERR(( "At most one of the incremental snapshot source strings in the configuration file under [tiles.replay.incremental] and [tiles.replay.incremental_url] may be set." ));
  }
  tile->replay.incremental_src_type = INT_MAX;
  if( FD_LIKELY( incremental_is_url ) ) {
    strncpy( tile->replay.incremental, config->tiles.replay.incremental_url, sizeof(tile->replay.incremental) );
    tile->replay.incremental_src_type = FD_SNAPSHOT_SRC_HTTP;
  }
  if( FD_UNLIKELY( incremental_is_file ) ) {
    strncpy( tile->replay.incremental, config->tiles.replay.incremental, sizeof(tile->replay.incremental) );
    tile->replay.incremental_src_type = FD_SNAPSHOT_SRC_FILE;
  }

  uchar snapshot_is_file, snapshot_is_url;
  if( strnlen( config->tiles.replay.snapshot, PATH_MAX )>0UL ) {
    snapshot_is_file = 1U;
  } else {
    snapshot_is_file = 0U;
  }
  if( strnlen( config->tiles.replay.snapshot_url, PATH_MAX )>0UL ) {
    snapshot_is_url = 1U;
  } else {
    snapshot_is_url = 0U;
  }
  if( FD_UNLIKELY( snapshot_is_file && snapshot_is_url ) ) {
    FD_LOG_ERR(( "At most one of the full snapshot source strings in the configuration file under [tiles.replay.snapshot] and [tiles.replay.snapshot_url] may be set." ));
  }
  tile->replay.snapshot_src_type = INT_MAX;
  if( FD_LIKELY( snapshot_is_url ) ) {
    strncpy( tile->replay.snapshot, config->tiles.replay.snapshot_url, sizeof(tile->replay.snapshot) );
    tile->replay.snapshot_src_type = FD_SNAPSHOT_SRC_HTTP;
  }
  if( FD_UNLIKELY( snapshot_is_file ) ) {
    strncpy( tile->replay.snapshot, config->tiles.replay.snapshot, sizeof(tile->replay.snapshot) );
    tile->replay.snapshot_src_type = FD_SNAPSHOT_SRC_FILE;
  }
}

static void
backtest_topo( config_t * config ) {
  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  enum{
  metric_cpu_idx=0,
  backtest_cpu_idx,
  replay_cpu_idx,
  exec_idx_start
  };
  ulong exec_tile_cnt = config->firedancer.layout.exec_tile_count;
#define writer_idx_start (exec_idx_start+exec_tile_cnt)

  /**********************************************************************/
  /* Add the metric tile to topo                                        */
  /**********************************************************************/
  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topo_tile_t * metric_tile = fd_topob_tile( topo, "metric", "metric", "metric_in", metric_cpu_idx, 0, 0 );
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( config->tiles.metric.prometheus_listen_address, &metric_tile->metric.prometheus_listen_addr ) ) )
    FD_LOG_ERR(( "failed to parse prometheus listen address `%s`", config->tiles.metric.prometheus_listen_address ));
  metric_tile->metric.prometheus_listen_port = config->tiles.metric.prometheus_listen_port;

  /**********************************************************************/
  /* Add the backtest tile to topo                                      */
  /**********************************************************************/
  fd_topob_wksp( topo, "backtest" );
  fd_topo_tile_t * backtest_tile   = fd_topob_tile( topo, "btest", "backtest", "metric_in", backtest_cpu_idx, 0, 0 );
  backtest_tile->archiver.end_slot = config->tiles.archiver.end_slot;
  strncpy( backtest_tile->archiver.archiver_path, config->tiles.archiver.archiver_path, PATH_MAX );
  if( FD_UNLIKELY( 0==strlen( backtest_tile->archiver.archiver_path ) ) ) {
    FD_LOG_ERR(( "Rocksdb not found, check `archiver.archiver_path` in toml" ));
  } else {
    FD_LOG_NOTICE(( "Found rocksdb path from config: %s", backtest_tile->archiver.archiver_path ));
  }

  /**********************************************************************/
  /* Add the replay tile to topo                                        */
  /**********************************************************************/
  fd_topob_wksp( topo, "replay" );
  fd_topo_tile_t * replay_tile = fd_topob_tile( topo, "replay", "replay", "metric_in", replay_cpu_idx, 0, 0 );
  replay_tile->replay.fec_max = config->tiles.shred.max_pending_shred_sets;
  replay_tile->replay.max_vote_accounts = config->firedancer.runtime.limits.max_vote_accounts;

  /* specified by [tiles.replay] */

  strncpy( replay_tile->replay.blockstore_file,    config->firedancer.blockstore.file,    sizeof(replay_tile->replay.blockstore_file) );
  strncpy( replay_tile->replay.blockstore_checkpt, config->firedancer.blockstore.checkpt, sizeof(replay_tile->replay.blockstore_checkpt) );

  replay_tile->replay.tx_metadata_storage = config->rpc.extended_tx_metadata_storage;
  strncpy( replay_tile->replay.capture, config->tiles.replay.capture, sizeof(replay_tile->replay.capture) );
  strncpy( replay_tile->replay.funk_checkpt, config->tiles.replay.funk_checkpt, sizeof(replay_tile->replay.funk_checkpt) );
  replay_tile->replay.funk_rec_max = config->tiles.replay.funk_rec_max;
  replay_tile->replay.funk_sz_gb   = config->tiles.replay.funk_sz_gb;
  replay_tile->replay.funk_txn_max = config->tiles.replay.funk_txn_max;
  strncpy( replay_tile->replay.funk_file, config->tiles.replay.funk_file, sizeof(replay_tile->replay.funk_file) );
  replay_tile->replay.plugins_enabled = config->tiles.gui.enabled;

  if( FD_UNLIKELY( !strncmp( config->tiles.replay.genesis,  "", 1 )
                   && !strncmp( config->tiles.replay.snapshot, "", 1 ) ) ) {
    fd_cstr_printf_check(  config->tiles.replay.genesis, PATH_MAX, NULL, "%s/genesis.bin", config->paths.ledger );
  }
  strncpy( replay_tile->replay.genesis, config->tiles.replay.genesis, sizeof(replay_tile->replay.genesis) );

  setup_snapshots( config, replay_tile );

  strncpy( replay_tile->replay.slots_replayed, config->tiles.replay.slots_replayed, sizeof(replay_tile->replay.slots_replayed) );
  strncpy( replay_tile->replay.status_cache, config->tiles.replay.status_cache, sizeof(replay_tile->replay.status_cache) );
  strncpy( replay_tile->replay.cluster_version, config->tiles.replay.cluster_version, sizeof(replay_tile->replay.cluster_version) );
  replay_tile->replay.bank_tile_count = config->layout.bank_tile_count;
  replay_tile->replay.exec_tile_count   = config->firedancer.layout.exec_tile_count;
  replay_tile->replay.writer_tile_cuont = config->firedancer.layout.writer_tile_count;
  strncpy( replay_tile->replay.tower_checkpt, config->tiles.replay.tower_checkpt, sizeof(replay_tile->replay.tower_checkpt) );

  replay_tile->replay.enable_features_cnt = config->tiles.replay.enable_features_cnt;
  for( ulong i = 0; i < replay_tile->replay.enable_features_cnt; i++ ) {
    strncpy( replay_tile->replay.enable_features[i], config->tiles.replay.enable_features[i], sizeof(replay_tile->replay.enable_features[i]) );
  }

  /* not specified by [tiles.replay] */

  strncpy( replay_tile->replay.identity_key_path, config->paths.identity_key, sizeof(replay_tile->replay.identity_key_path) );
  replay_tile->replay.ip_addr = config->net.ip_addr;
  replay_tile->replay.vote = config->firedancer.consensus.vote;
  strncpy( replay_tile->replay.vote_account_path, config->paths.vote_account, sizeof(replay_tile->replay.vote_account_path) );
  replay_tile->replay.full_interval        = config->tiles.batch.full_interval;
  replay_tile->replay.incremental_interval = config->tiles.batch.incremental_interval;

  /**********************************************************************/
  /* Add the executor tiles to topo                                     */
  /**********************************************************************/
  fd_topob_wksp( topo, "exec" );
  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )
  FOR(exec_tile_cnt) fd_topob_tile( topo, "exec",   "exec",   "metric_in", exec_idx_start+i, 0, 0 );

  /**********************************************************************/
  /* Add the writer tiles to topo                                       */
  /**********************************************************************/
  fd_topob_wksp( topo, "writer" );
  ulong writer_tile_cnt = config->firedancer.layout.writer_tile_count;
  FOR(writer_tile_cnt) fd_topob_tile( topo, "writer",  "writer",  "metric_in",  writer_idx_start+i, 0, 0 );

  /**********************************************************************/
  /* Setup backtest->replay link (repair_repla) in topo                 */
  /**********************************************************************/
  fd_topob_wksp( topo, "repair_repla" );
  fd_topob_link( topo, "repair_repla", "repair_repla", 65536UL, sizeof(ulong), 1UL );
  fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "repair_repla", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "btest", 0UL, "repair_repla", 0UL );

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
  /* Setup replay->stake/sender/poh links in topo w/o consumers         */
  /**********************************************************************/
  fd_topob_wksp( topo, "stake_out"    );
  fd_topob_wksp( topo, "replay_voter" );
  fd_topob_wksp( topo, "replay_poh"   );

  fd_topob_link( topo, "stake_out", "stake_out", 128UL, 40UL + 40200UL * 40UL, 1UL );
  fd_topob_link( topo, "replay_voter", "replay_voter", 128UL, sizeof(fd_txn_p_t), 1UL );
  ulong bank_tile_cnt   = config->layout.bank_tile_count;
  FOR(bank_tile_cnt) fd_topob_link( topo, "replay_poh", "replay_poh", 128UL, (4096UL*sizeof(fd_txn_p_t))+sizeof(fd_microblock_trailer_t), 1UL );

  fd_topob_tile_out( topo, "replay", 0UL, "stake_out", 0UL );
  fd_topob_tile_out( topo, "replay", 0UL, "replay_voter", 0UL );
  FOR(bank_tile_cnt) fd_topob_tile_out( topo, "replay", 0UL, "replay_poh", i );

  topo->links[ replay_tile->out_link_id[ fd_topo_find_tile_out_link( topo, replay_tile, "stake_out", 0 ) ] ].permit_no_consumers = 1;
  topo->links[ replay_tile->out_link_id[ fd_topo_find_tile_out_link( topo, replay_tile, "replay_voter", 0 ) ] ].permit_no_consumers = 1;
  FOR(bank_tile_cnt) topo->links[ replay_tile->out_link_id[ fd_topo_find_tile_out_link( topo, replay_tile, "replay_poh", i ) ] ].permit_no_consumers = 1;

  /**********************************************************************/
  /* Setup replay->backtest link (replay_notif) in topo                 */
  /**********************************************************************/
  fd_topob_wksp( topo, "replay_notif" );
  fd_topob_link( topo, "replay_notif", "replay_notif", FD_REPLAY_NOTIF_DEPTH, FD_REPLAY_NOTIF_MTU, 1UL );
  fd_topob_tile_in(  topo, "btest", 0UL, "metric_in", "replay_notif", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
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
  /* Setup replay->writer links in topo                                 */
  /**********************************************************************/
  fd_topob_wksp( topo, "replay_wtr" );
  for( ulong i=0; i<writer_tile_cnt; i++ ) {
    fd_topob_link( topo, "replay_wtr", "replay_wtr", 128UL, FD_REPLAY_WRITER_MTU, 1UL );
    fd_topob_tile_out( topo, "replay", 0UL, "replay_wtr", i );
    fd_topob_tile_in( topo, "writer", i, "metric_in", "replay_wtr", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  /**********************************************************************/
  /* Setup the shared objs used by replay and exec tiles                */
  /**********************************************************************/

  /* blockstore_obj shared by replay and backtest tiles */
  fd_topob_wksp( topo, "blockstore"      );
  fd_topo_obj_t * blockstore_obj = setup_topo_blockstore( topo,
                                                          "blockstore",
                                                          config->firedancer.blockstore.shred_max,
                                                          config->firedancer.blockstore.block_max,
                                                          config->firedancer.blockstore.idx_max,
                                                          config->firedancer.blockstore.txn_max,
                                                          config->firedancer.blockstore.alloc_max );
  fd_topob_tile_uses( topo, replay_tile, blockstore_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, backtest_tile, blockstore_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, blockstore_obj->id, "blockstore" ) );

  /* turb_slot_obj shared by replay and backtest tiles */
  fd_topob_wksp( topo, "turb_slot"   );
  fd_topo_obj_t * turb_slot_obj = fd_topob_obj( topo, "fseq", "turb_slot" );
  fd_topob_tile_uses( topo, replay_tile, turb_slot_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topob_tile_uses( topo, backtest_tile, turb_slot_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, turb_slot_obj->id, "turb_slot" ) );

  /* runtime_pub_obj shared by replay, exec and writer tiles */
  fd_topob_wksp( topo, "runtime_pub" );
  fd_topo_obj_t * runtime_pub_obj = setup_topo_runtime_pub( topo, "runtime_pub", config->firedancer.runtime.heap_size_gib<<30 );
  fd_topob_tile_uses( topo, replay_tile, runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FOR(writer_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "writer", i ) ], runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, runtime_pub_obj->id, "runtime_pub" ) );

  /* exec_spad_obj shared by replay, exec and writer tiles */
  fd_topob_wksp( topo, "exec_spad"   );
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
  fd_topob_wksp( topo, "exec_fseq"   );
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

  /* root_slot_obj shared by replay and backtest tiles */
  fd_topob_wksp( topo, "root_slot"    );
  fd_topo_obj_t * root_slot_obj = fd_topob_obj( topo, "fseq", "root_slot" );
  fd_topob_tile_uses( topo, replay_tile, root_slot_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, backtest_tile,  root_slot_obj, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  FD_TEST( fd_pod_insertf_ulong( topo->props, root_slot_obj->id, "root_slot" ) );

  /* txncache_obj, busy_obj, poh_slot_obj and constipated_obj only by replay tile */
  fd_topob_wksp( topo, "tcache"      );
  fd_topob_wksp( topo, "bank_busy"   );
  fd_topob_wksp( topo, "poh_slot"    );
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
  fd_topo_obj_t * poh_slot_obj = fd_topob_obj( topo, "fseq", "poh_slot" );
  fd_topob_tile_uses( topo, replay_tile, poh_slot_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_slot_obj->id, "poh_slot" ) );
  fd_topo_obj_t * constipated_obj = fd_topob_obj( topo, "fseq", "constipate" );
  fd_topob_tile_uses( topo, replay_tile, constipated_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, constipated_obj->id, "constipate" ) );

  /**********************************************************************/
  /* Finish and print out the topo information                          */
  /**********************************************************************/
  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
}

static void
backtest_cmd_fn( args_t *   args FD_PARAM_UNUSED,
                config_t * config ) {
  FD_LOG_NOTICE(( "Start to run the backtest cmd" ));
  backtest_topo( config );

  initialize_workspaces( config );
  initialize_stacks( config );
  fd_topo_t * topo = &config->topo;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  /* FIXME: there's no PoH tile in this mini-topology,
   *        but replay tile waits for `poh_slot!=ULONG_MAX` before starting to vote
   *        -- vote updates the root for funk/blockstore publish */
  ulong poh_slot_obj_id = fd_pod_query_ulong( topo->props, "poh_slot", ULONG_MAX );
  FD_TEST( poh_slot_obj_id!=ULONG_MAX );
  ulong * poh = fd_fseq_join( fd_topo_obj_laddr( topo, poh_slot_obj_id ) );
  fd_fseq_update( poh, 0UL );

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
