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

#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/fd_config.h" /* config_t */
#include "../../../disco/topo/fd_cpu_topo.h" /* fd_topo_cpus */
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../flamenco/runtime/fd_runtime.h"
#include "../../../flamenco/runtime/fd_txncache.h"

#include <unistd.h> /* pause */
extern fd_topo_obj_callbacks_t * CALLBACKS[];
fd_topo_run_tile_t fdctl_tile_run( fd_topo_tile_t const * tile );

/* setup_topo_txncache, setup_topo_runtime_pub and setup_topo_blockstore
   are simply copied from fd_firedancer.c */
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

static fd_topo_obj_t *
setup_topo_runtime_pub( fd_topo_t *  topo,
                        char const * wksp_name,
                        ulong        mem_max ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, "runtime_pub", wksp_name );
  FD_TEST( fd_pod_insertf_ulong( topo->props, mem_max, "obj.%lu.mem_max",  obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, 12UL,    "obj.%lu.wksp_tag", obj->id ) );
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
  /* Add the playback tile to topo                                      */
  /**********************************************************************/
  fd_topob_wksp( topo, "playback" );
  fd_topo_tile_t * playback_tile = fd_topob_tile( topo, "arch_p", "playback", "metric_in", playback_cpu_idx, 0, 0 );
  strncpy( playback_tile->archiver.archiver_path, config->tiles.archiver.archiver_path, PATH_MAX );
  if( FD_UNLIKELY( 0==strlen( playback_tile->archiver.archiver_path ) ) ) {
    FD_LOG_ERR(( "Archive file not found for playback" ));
  } else {
    FD_LOG_NOTICE(( "Found archive file from config: %s", playback_tile->archiver.archiver_path ));
  }

  /**********************************************************************/
  /* Add the storei tile to topo                                        */
  /**********************************************************************/
  fd_topob_wksp( topo, "storei" );
  fd_topo_tile_t * storei_tile = fd_topob_tile( topo, "storei", "storei", "metric_in", storei_cpu_idx, 0, 0 );
  strncpy( storei_tile->store_int.blockstore_file,    config->firedancer.blockstore.file,        sizeof(storei_tile->store_int.blockstore_file) );
  strncpy( storei_tile->store_int.blockstore_restore, config->firedancer.blockstore.restore,     sizeof(storei_tile->store_int.blockstore_restore) );
  strncpy( storei_tile->store_int.identity_key_path,  config->paths.identity_key,           sizeof(storei_tile->store_int.identity_key_path) );
  strncpy( storei_tile->store_int.slots_pending,      config->tiles.store_int.slots_pending,     sizeof( storei_tile->store_int.slots_pending ) );
  strncpy( storei_tile->store_int.shred_cap_archive,  config->tiles.store_int.shred_cap_archive, sizeof(storei_tile->store_int.shred_cap_archive) );
  strncpy( storei_tile->store_int.shred_cap_replay,   config->tiles.store_int.shred_cap_replay,  sizeof(storei_tile->store_int.shred_cap_replay) );
  storei_tile->store_int.shred_cap_end_slot     = config->tiles.store_int.shred_cap_end_slot;
  storei_tile->store_int.expected_shred_version = config->consensus.expected_shred_version;

  /**********************************************************************/
  /* Add the replay tile to topo                                        */
  /**********************************************************************/
  fd_topob_wksp( topo, "replay" );
  fd_topo_tile_t * replay_tile = fd_topob_tile( topo, "replay", "replay", "metric_in", replay_cpu_idx, 0, 0 );
  replay_tile->replay.fec_max = config->tiles.shred.max_pending_shred_sets;
  replay_tile->replay.max_vote_accounts = config->firedancer.runtime.limits.max_vote_accounts;

  /* specified by [tiles.replay] */
  strncpy( replay_tile->replay.blockstore_file, config->firedancer.blockstore.file, sizeof(replay_tile->replay.blockstore_file) );
  strncpy( replay_tile->replay.blockstore_checkpt, config->firedancer.blockstore.checkpt, sizeof(replay_tile->replay.blockstore_checkpt) );

  replay_tile->replay.tx_metadata_storage = config->rpc.extended_tx_metadata_storage;
  strncpy( replay_tile->replay.capture, config->tiles.replay.capture, sizeof(replay_tile->replay.capture) );
  strncpy( replay_tile->replay.funk_checkpt, config->tiles.replay.funk_checkpt, sizeof(replay_tile->replay.funk_checkpt) );
  replay_tile->replay.funk_rec_max = config->tiles.replay.funk_rec_max;
  replay_tile->replay.funk_sz_gb   = config->tiles.replay.funk_sz_gb;
  replay_tile->replay.funk_txn_max = config->tiles.replay.funk_txn_max;
  strncpy( replay_tile->replay.funk_file, config->tiles.replay.funk_file, sizeof(replay_tile->replay.funk_file) );
  replay_tile->replay.plugins_enabled = 0;

  if( FD_UNLIKELY( !strncmp( config->tiles.replay.genesis,  "", 1 )
                   && !strncmp( config->tiles.replay.snapshot, "", 1 ) ) ) {
    fd_cstr_printf_check(  config->tiles.replay.genesis, PATH_MAX, NULL, "%s/genesis.bin", config->paths.ledger );
  }
  strncpy( replay_tile->replay.genesis, config->tiles.replay.genesis, sizeof(replay_tile->replay.genesis) );

  strncpy( replay_tile->replay.incremental, config->tiles.replay.incremental, sizeof(replay_tile->replay.incremental) );
  strncpy( replay_tile->replay.slots_replayed, config->tiles.replay.slots_replayed, sizeof(replay_tile->replay.slots_replayed) );
  strncpy( replay_tile->replay.snapshot, config->tiles.replay.snapshot, sizeof(replay_tile->replay.snapshot) );
  strncpy( replay_tile->replay.status_cache, config->tiles.replay.status_cache, sizeof(replay_tile->replay.status_cache) );

  strncpy( replay_tile->replay.cluster_version, config->tiles.replay.cluster_version, sizeof(replay_tile->replay.cluster_version) );
  replay_tile->replay.bank_tile_count = config->layout.bank_tile_count;
  replay_tile->replay.exec_tile_count = config->firedancer.layout.exec_tile_count;
  strncpy( replay_tile->replay.tower_checkpt, config->tiles.replay.tower_checkpt, sizeof(replay_tile->replay.tower_checkpt) );

  /* not specified by [tiles.replay] */
  strncpy( replay_tile->replay.identity_key_path, config->paths.identity_key, sizeof(replay_tile->replay.identity_key_path) );
  replay_tile->replay.ip_addr = config->net.ip_addr;
  replay_tile->replay.vote = config->firedancer.consensus.vote;
  strncpy( replay_tile->replay.vote_account_path, config->paths.vote_account, sizeof(replay_tile->replay.vote_account_path) );
  replay_tile->replay.full_interval        = config->tiles.batch.full_interval;
  replay_tile->replay.incremental_interval = config->tiles.batch.incremental_interval;

  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /**********************************************************************/
  /* Add the executor tiles to topo                                     */
  /**********************************************************************/
  fd_topob_wksp( topo, "exec" );
  ulong exec_tile_cnt   = config->firedancer.layout.exec_tile_count;
  FOR(exec_tile_cnt)               fd_topob_tile( topo, "exec",   "exec",   "metric_in", static_end_idx+i, 0,        0 );

  /**********************************************************************/
  /* Setup playback<->storei and storei<->replay links in topo          */
  /**********************************************************************/
  fd_topob_wksp( topo, "shred_storei" );
  fd_topob_wksp( topo, "repair_store" );
  fd_topob_wksp( topo, "storei_notif" );
  fd_topob_wksp( topo, "stake_out"    );
  fd_topob_wksp( topo, "store_replay" );
  /*             topo,  link_name,      wksp_name,     depth,         mtu,                    burst */
  fd_topob_link( topo, "shred_storei", "shred_storei", 65536UL,       4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );
  fd_topob_link( topo, "repair_store", "repair_store", 1024UL*1024UL, FD_SHRED_MAX_SZ,        128UL                                          );
  fd_topob_link( topo, "storei_notif", "storei_notif", 65536UL,       4UL*FD_SHRED_STORE_MTU, 4UL+config->tiles.shred.max_pending_shred_sets );
  fd_topob_link( topo, "stake_out",    "stake_out",    128UL,         40UL + 40200UL * 40UL,  1UL                                            );
  fd_topob_link( topo, "store_replay", "store_replay", 32768UL,       sizeof(ulong),          64UL                                           );

  /*                 topo, tile_name, tile_kind_id, link_name,      link_kind_id */
  fd_topob_tile_out( topo, "arch_p",  0UL,          "shred_storei", 0UL );
  fd_topob_tile_out( topo, "arch_p",  0UL,          "repair_store", 0UL );
  fd_topob_tile_in(  topo, "arch_p",  0UL,          "metric_in", "storei_notif",       0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /*                 topo, tile_name, tile_kind_id, fseq_wksp,   link_name,            link_kind_id, reliable,            polled */
  fd_topob_tile_in(  topo, "storei",  0UL,          "metric_in", "stake_out",          0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in(  topo, "storei",  0UL,          "metric_in", "repair_store",       0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_in(  topo, "storei",  0UL,          "metric_in", "shred_storei",       0UL,          FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  /*                 topo, tile_name, tile_kind_id, link_name,          link_kind_id */
  fd_topob_tile_out( topo, "storei",  0UL,          "store_replay",     0UL );
  fd_topob_tile_out( topo, "storei",  0UL,          "storei_notif",     0UL );

  /*                 topo, tile_name, tile_kind_id, fseq_wksp,   link_name,            link_kind_id, reliable,            polled */
  fd_topob_tile_in(  topo, "replay",  0UL,          "metric_in", "store_replay",       0UL,          FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED   );

  /*                 topo, tile_name, tile_kind_id, link_name,          link_kind_id */
  fd_topob_tile_out( topo, "replay",  0UL,          "stake_out",        0UL );

  /**********************************************************************/
  /* Setup replay<->exec links in topo                                  */
  /**********************************************************************/
  fd_topob_wksp( topo, "replay_exec" );
  for( ulong i=0; i<config->firedancer.layout.exec_tile_count; i++ ) {
    fd_topob_link( topo, "replay_exec", "replay_exec", 128UL, 10240UL, 1UL );
    fd_topob_tile_out( topo, "replay", 0UL, "replay_exec", i );
    fd_topob_tile_in( topo, "exec", i, "metric_in", "replay_exec", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }
  fd_topo_tile_t * exec_tile   = &topo->tiles[ fd_topo_find_tile( topo, "exec", 0UL ) ];

  /**********************************************************************/
  /* Setup the shared objs used by storei, replay and exec tiles        */
  /**********************************************************************/
  fd_topob_wksp( topo, "bstore"      );
  fd_topob_wksp( topo, "poh_shred"   );
  fd_topob_wksp( topo, "root_slot"   );
  fd_topob_wksp( topo, "runtime_pub" );
  fd_topob_wksp( topo, "tcache"      );
  fd_topob_wksp( topo, "poh_slot"    );
  fd_topob_wksp( topo, "constipate"  );
  fd_topob_wksp( topo, "bank_busy"   );
  fd_topob_wksp( topo, "exec_spad"   );
  fd_topob_wksp( topo, "exec_fseq"   );
  fd_topo_obj_t * blockstore_obj = setup_topo_blockstore( topo,
                                                          "bstore",
                                                          config->firedancer.blockstore.shred_max,
                                                          config->firedancer.blockstore.block_max,
                                                          config->firedancer.blockstore.idx_max,
                                                          config->firedancer.blockstore.txn_max,
                                                          config->firedancer.blockstore.alloc_max );
  fd_topo_obj_t * poh_shred_obj = fd_topob_obj( topo, "fseq", "poh_shred" );
  fd_topo_obj_t * root_slot_obj = fd_topob_obj( topo, "fseq", "root_slot" );
  fd_topo_obj_t * runtime_pub_obj = setup_topo_runtime_pub( topo, "runtime_pub", config->firedancer.runtime.heap_size_gib<<30 );
  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "tcache",
      config->firedancer.runtime.limits.max_rooted_slots,
      config->firedancer.runtime.limits.max_live_slots,
      config->firedancer.runtime.limits.max_transactions_per_slot,
      fd_txncache_max_constipated_slots_est( config->firedancer.runtime.limits.snapshot_grace_period_seconds ) );
  fd_topo_obj_t * poh_slot_obj = fd_topob_obj( topo, "fseq", "poh_slot" );
  fd_topo_obj_t * constipated_obj = fd_topob_obj( topo, "fseq", "constipate" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, blockstore_obj->id, "blockstore" ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_shred_obj->id, "poh_shred" ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, root_slot_obj->id, "root_slot" ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, runtime_pub_obj->id, "runtime_pub" ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, poh_slot_obj->id, "poh_slot" ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, constipated_obj->id, "constipate" ) );

  fd_topob_tile_uses( topo, storei_tile, blockstore_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, storei_tile, poh_shred_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topob_tile_uses( topo, storei_tile, root_slot_obj, FD_SHMEM_JOIN_MODE_READ_ONLY  );

  fd_topob_tile_uses( topo, replay_tile, blockstore_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, runtime_pub_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, root_slot_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, poh_slot_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topob_tile_uses( topo, replay_tile, constipated_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  for( ulong i=0UL; i<config->layout.bank_tile_count; i++ ) {
    fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "bank_busy" );

    fd_topob_tile_uses( topo, replay_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", i ) );
  }

  for( ulong i=0UL; i<config->firedancer.layout.exec_tile_count; i++ ) {
    fd_topo_obj_t * exec_spad_obj = fd_topob_obj( topo, "exec_spad", "exec_spad" );
    fd_topo_obj_t * exec_fseq_obj = fd_topob_obj( topo, "fseq", "exec_fseq" );
    fd_topob_tile_uses( topo, replay_tile, exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, replay_tile, exec_fseq_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, exec_tile, exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, exec_tile, exec_fseq_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    FD_TEST( fd_pod_insertf_ulong( topo->props, exec_spad_obj->id, "exec_spad.%lu", i ) );
    FD_TEST( fd_pod_insertf_ulong( topo->props, exec_fseq_obj->id, "exec_fseq.%lu", i ) );
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
