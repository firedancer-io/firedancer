/* The backtest command spawns a smaller topology for replaying shreds from
   rocksdb (or other sources TBD) and reproduce the behavior of replay tile.

   The smaller topology is:
           shred_out             replay_exec
   backtest-------------->replay------------->exec
     ^                    |^ | ^                |
     |____________________|| | |________________|
          replay_out       | |   exec_replay
                           | |------------------------------>no consumer
    no producer-------------  stake_out, send_out, poh_out
                store_replay

*/
#define _GNU_SOURCE
#include "../../firedancer/topology.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/commands/watch/watch.h"
#include "../../shared/fd_config.h" /* config_t */
#include "../../../disco/tiles.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../discof/replay/fd_replay_tile.h"
#include "../../../discof/restore/utils/fd_ssmsg.h"
#include "../../../discof/tower/fd_tower_tile.h"
#include "../../../discof/replay/fd_exec.h" /* FD_RUNTIME_PUBLIC_ACCOUNT_UPDATE_MSG_MTU */

#include "../main.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];
fd_topo_run_tile_t fdctl_tile_run( fd_topo_tile_t const * tile );

static void
backtest_topo( config_t * config ) {

  config->development.sandbox  = 0;
  config->development.no_clone = 1;

  ulong exec_tile_cnt   = config->firedancer.layout.exec_tile_count;

  int disable_snap_loader = !config->gossip.entrypoints_cnt;
  int solcap_enabled      = strlen( config->capture.solcap_capture )>0;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  ulong cpu_idx = 0;

  fd_topob_wksp( topo, "metric_in" );

  /**********************************************************************/
  /* Add the backtest tile to topo                                      */
  /**********************************************************************/
  fd_topob_wksp( topo, "backt" );
  fd_topo_tile_t * backt_tile = fd_topob_tile( topo, "backt", "backt", "metric_in", cpu_idx++, 0, 0 );

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
  FOR(exec_tile_cnt) fd_topob_tile( topo, "exec", "exec", "metric_in", cpu_idx++, 0, 0 );

  /**********************************************************************/
  /* Add the snapshot tiles to topo                                       */
  /**********************************************************************/
  fd_topo_tile_t * snapin_tile = NULL;
  if( FD_UNLIKELY( !disable_snap_loader ) ) {
    fd_topob_wksp( topo, "snaprd" );
    fd_topob_wksp( topo, "snapdc" );
    fd_topob_wksp( topo, "snapin" );
    fd_topo_tile_t * snaprd_tile = fd_topob_tile( topo, "snaprd",  "snaprd",  "metric_in",  cpu_idx++, 0, 0 );
    fd_topo_tile_t * snapdc_tile = fd_topob_tile( topo, "snapdc",  "snapdc",  "metric_in",  cpu_idx++, 0, 0 );
    snapin_tile = fd_topob_tile( topo, "snapin",  "snapin",  "metric_in",  cpu_idx++, 0, 0 );
    snaprd_tile->allow_shutdown = 1;
    snapdc_tile->allow_shutdown = 1;
    snapin_tile->allow_shutdown = 1;
  } else {
    fd_topob_wksp( topo, "genesi" );
    fd_topob_tile( topo, "genesi",  "genesi",  "metric_in",  cpu_idx++, 0, 0 )->allow_shutdown = 1;
  }

  /**********************************************************************/
  /* Setup backtest->replay link (shred_out) in topo                 */
  /**********************************************************************/

  /* The repair tile is replaced by the backtest tile for the repair to
     replay link.  The frag interface is a "slice", ie. entry batch,
     which is provided by the backtest tile, which reads in the entry
     batches from the CLI-specified source (eg. RocksDB). */

  fd_topob_wksp( topo, "shred_out" );
  fd_topob_link( topo, "shred_out", "shred_out", 65536UL, FD_SHRED_OUT_MTU, 1UL );
  fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "shred_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "backt", 0UL, "shred_out", 0UL );

  /**********************************************************************/
  /* Setup snapshot links in topo                                       */
  /**********************************************************************/
  if( FD_LIKELY( !disable_snap_loader ) ) {
    fd_topob_wksp( topo, "snap_zstd" );
    fd_topob_wksp( topo, "snap_stream");
    fd_topob_wksp( topo, "snapdc_rd" );
    fd_topob_wksp( topo, "snapin_rd" );
    fd_topob_wksp( topo, "snap_out" );
    fd_topob_wksp( topo, "snaprd_rp" );
    /* TODO: Should be depth of 1 or 2, not 4, but it causes backpressure
      from the replay tile parsing the manifest, remove when this is
      fixed. */
    fd_topob_link( topo, "snap_out",  "snap_out",  4UL,   sizeof(fd_snapshot_manifest_t), 1UL );
    fd_topob_link( topo, "snaprd_rp", "snaprd_rp", 128UL, 0UL,                            1UL )->permit_no_consumers = 1;

    fd_topob_link( topo, "snap_zstd",   "snap_zstd",   8192UL, 16384UL,  1UL );
    fd_topob_link( topo, "snap_stream", "snap_stream", 2048UL, USHORT_MAX, 1UL );
    fd_topob_link( topo, "snapdc_rd", "snapdc_rd", 128UL, 0UL, 1UL );
    fd_topob_link( topo, "snapin_rd", "snapin_rd", 128UL, 0UL, 1UL );

    fd_topob_tile_out( topo, "snaprd", 0UL, "snap_zstd",   0UL );
    fd_topob_tile_in ( topo, "snapdc", 0UL, "metric_in",   "snap_zstd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapdc", 0UL, "snap_stream", 0UL );
    fd_topob_tile_in ( topo, "snapin", 0UL, "metric_in",   "snap_stream", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );
    fd_topob_tile_out( topo, "snapin", 0UL, "snap_out",  0UL );
    fd_topob_tile_in ( topo, "replay", 0UL, "metric_in",   "snap_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snaprd", 0UL, "snaprd_rp", 0UL );

    fd_topob_tile_in( topo, "snaprd", 0UL, "metric_in", "snapdc_rd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapdc", 0UL, "snapdc_rd", 0UL );
    fd_topob_tile_in( topo, "snaprd", 0UL, "metric_in", "snapin_rd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapin", 0UL, "snapin_rd", 0UL );
  } else {
    fd_topob_wksp( topo, "genesi_out" );
    fd_topob_link( topo, "genesi_out", "genesi_out", 2UL, 10UL*1024UL*1024UL+32UL+sizeof(fd_lthash_value_t), 1UL );
    fd_topob_tile_out( topo, "genesi", 0UL, "genesi_out", 0UL );
    fd_topob_tile_in ( topo, "replay", 0UL, "metric_in", "genesi_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

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
  fd_topob_wksp( topo, "tower_out" );
  fd_topob_link( topo, "tower_out", "tower_out", 1024UL, sizeof(fd_tower_slot_done_t), 1UL );
  fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "tower_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "backt", 0UL, "tower_out", 0UL );

  /**********************************************************************/
  /* Setup replay->stake/send/poh links in topo w/o consumers         */
  /**********************************************************************/
  fd_topob_wksp( topo, "replay_stake"    );
  fd_topob_wksp( topo, "replay_poh"   );

  fd_topob_link( topo, "replay_stake",   "replay_stake",   128UL, 40UL + 40200UL * 40UL, 1UL );
  ulong bank_tile_cnt   = config->layout.bank_tile_count;
  FOR(bank_tile_cnt) fd_topob_link( topo, "replay_poh", "replay_poh", 128UL, (4096UL*sizeof(fd_txn_p_t))+sizeof(fd_microblock_trailer_t), 1UL );

  fd_topob_tile_out( topo, "replay", 0UL, "replay_stake",   0UL );
  FOR(bank_tile_cnt) fd_topob_tile_out( topo, "replay", 0UL, "replay_poh", i );

  topo->links[ replay_tile->out_link_id[ fd_topo_find_tile_out_link( topo, replay_tile, "replay_stake",   0 ) ] ].permit_no_consumers = 1;
  FOR(bank_tile_cnt) topo->links[ replay_tile->out_link_id[ fd_topo_find_tile_out_link( topo, replay_tile, "replay_poh", i ) ] ].permit_no_consumers = 1;

  /**********************************************************************/
  /* Setup replay->backtest link (replay_notif) in topo                 */
  /**********************************************************************/

  fd_topob_wksp( topo, "replay_out"   );
  fd_topob_link( topo, "replay_out", "replay_out", 8192UL, sizeof( fd_replay_message_t ), 1UL );
  fd_topob_tile_out( topo, "replay", 0UL, "replay_out", 0UL );
  fd_topob_tile_in ( topo, "backt", 0UL, "metric_in", "replay_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  if( FD_LIKELY( !disable_snap_loader ) ) {
    fd_topob_tile_in ( topo, "backt", 0UL, "metric_in", "snap_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  } else {
    fd_topob_tile_in ( topo, "backt", 0UL, "metric_in", "genesi_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  /**********************************************************************/
  /* Setup replay->exec link in topo                                    */
  /**********************************************************************/
  fd_topob_wksp( topo, "replay_exec" );
  fd_topob_link( topo, "replay_exec", "replay_exec", 16384UL, 2240UL, 1UL );
  fd_topob_tile_out( topo, "replay", 0UL, "replay_exec", 0UL );
  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    fd_topob_tile_in( topo, "exec", i, "metric_in", "replay_exec", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  /**********************************************************************/
  /* Setup exec->replay links in topo, to send solcap account updates
     so that they are serialized, and to notify replay tile that a txn
     has been finalized by the exec tile. */
  /**********************************************************************/
  fd_topob_wksp( topo, "exec_replay" );
  FOR(exec_tile_cnt) fd_topob_link( topo, "exec_replay", "exec_replay", 16384UL, sizeof(fd_exec_replay_txn_finalized_msg_t), 1UL );
  FOR(exec_tile_cnt) fd_topob_tile_out( topo, "exec", i, "exec_replay", i );
  FOR(exec_tile_cnt) fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "exec_replay", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  if( FD_UNLIKELY( solcap_enabled ) ) {
    /* Capture account updates, whose updates must be centralized in the replay tile as solcap is currently not thread-safe.
      TODO: remove this when solcap v2 is here. */
    fd_topob_wksp( topo, "capt_replay" );
    FOR(exec_tile_cnt) fd_topob_link(     topo, "capt_replay", "capt_replay", FD_CAPTURE_CTX_MAX_ACCOUNT_UPDATES, FD_CAPTURE_CTX_ACCOUNT_UPDATE_MSG_FOOTPRINT, 1UL );
    FOR(exec_tile_cnt) fd_topob_tile_out( topo, "exec",        i,                               "capt_replay", i );
    FOR(exec_tile_cnt) fd_topob_tile_in(  topo, "replay",      0UL,         "metric_in",        "capt_replay", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  /**********************************************************************/
  /* Setup the shared objs used by replay and exec tiles                */
  /**********************************************************************/

  fd_topob_wksp( topo, "store" );
  fd_topo_obj_t * store_obj = setup_topo_store( topo, "store", config->firedancer.store.max_completed_shred_sets, 1 );
  fd_topob_tile_uses( topo, backt_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, store_obj->id, "store" ) );

  /* banks_obj shared by replay and exec tiles */
  fd_topob_wksp( topo, "banks" );
  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks", config->firedancer.runtime.max_live_slots, config->firedancer.runtime.max_fork_width );
  fd_topob_tile_uses( topo, replay_tile, banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  /* bank_hash_cmp_obj shared by replay and exec tiles */
  fd_topob_wksp( topo, "bh_cmp" );
  fd_topo_obj_t * bank_hash_cmp_obj = setup_topo_bank_hash_cmp( topo, "bh_cmp" );
  fd_topob_tile_uses( topo, replay_tile, bank_hash_cmp_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], bank_hash_cmp_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, bank_hash_cmp_obj->id, "bh_cmp" ) );

  /* exec_spad_obj used by exec tiles */
  fd_topob_wksp( topo, "exec_spad" );
  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    fd_topo_obj_t * exec_spad_obj = fd_topob_obj( topo, "exec_spad", "exec_spad" );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], exec_spad_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    FD_TEST( fd_pod_insertf_ulong( topo->props, exec_spad_obj->id, "exec_spad.%lu", i ) );
  }

  /* txncache_obj, busy_obj and poh_slot_obj only by replay tile */
  fd_topob_wksp( topo, "txncache"    );
  fd_topob_wksp( topo, "bank_busy"   );
  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "txncache",
      config->firedancer.runtime.max_live_slots,
      fd_ulong_pow2_up( FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT ) );
  fd_topob_tile_uses( topo, replay_tile, txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  if( FD_LIKELY( !disable_snap_loader ) ) {
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
  for( ulong i=0UL; i<bank_tile_cnt; i++ ) {
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "bank", i ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }

  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );
  for( ulong i=0UL; i<bank_tile_cnt; i++ ) {
    fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "bank_busy" );
    fd_topob_tile_uses( topo, replay_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "bank_busy.%lu", i ) );
  }

  if( FD_LIKELY( !disable_snap_loader ) ) {
    fd_topob_tile_uses( topo, snapin_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );

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
backtest_cmd_args( int *    pargc,
                   char *** pargv,
                   args_t * args ) {
  args->backtest.no_watch = fd_env_strip_cmdline_contains( pargc, pargv, "--no-watch" );
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

  initialize_workspaces( config );
  initialize_stacks( config );

  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_fill( &config->topo );

  args_t watch_args;
  int pipefd[2];
  if( !args->backtest.no_watch ) {
    if( FD_UNLIKELY( pipe2( pipefd, O_NONBLOCK ) ) ) FD_LOG_ERR(( "pipe2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    watch_args.watch.drain_output_fd = pipefd[0];
    if( FD_UNLIKELY( -1==dup2( pipefd[ 1 ], STDERR_FILENO ) ) ) FD_LOG_ERR(( "dup2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  fd_topo_run_single_process( &config->topo, 2, config->uid, config->gid, fdctl_tile_run );
  if( args->backtest.no_watch ) {
    for(;;) pause();
  } else {
    watch_cmd_fn( &watch_args, config );
  }
}

action_t fd_action_backtest = {
  .name = "backtest",
  .args = backtest_cmd_args,
  .fn   = backtest_cmd_fn,
  .perm = backtest_cmd_perm,
  .topo = backtest_cmd_topo,
};
