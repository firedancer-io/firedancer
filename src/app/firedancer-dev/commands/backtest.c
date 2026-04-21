/* The backtest command spawns a smaller topology for replaying shreds from
   rocksdb (or other sources TBD) and reproduce the behavior of replay tile.

   The smaller topology is:
           shred_out             replay_execr
   backtest-------------->replay------------->execrp
     ^                    |^ | ^                |
     |____________________|| | |________________|
          replay_out       | |   execrp_replay
                           | |------------------------------>no consumer
    no producer-------------  stake_out, txsend_out, poh_out
                store_replay

*/
#define _GNU_SOURCE
#include "../../firedancer/topology.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h" /* initialize_workspaces */
#include "../../shared/commands/watch/watch.h"
#include "../../shared/fd_config.h" /* config_t */
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../discof/genesis/fd_genesi_tile.h"
#include "../../../discof/replay/fd_replay_tile.h"
#include "../../../discof/restore/utils/fd_ssctrl.h"
#include "../../../discof/restore/utils/fd_ssmsg.h"
#include "../../../discof/tower/fd_tower_tile.h"
#include "../../../discof/replay/fd_execrp.h"
#include "../../../flamenco/capture/fd_capture_ctx.h"
#include "../../../disco/pack/fd_pack_cost.h"
#include "../../../flamenco/progcache/fd_progcache_admin.h"
#include "../../../flamenco/runtime/fd_cost_tracker.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];
fd_topo_run_tile_t fdctl_tile_run( fd_topo_tile_t const * tile );

void
backtest_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args ) {
  args->backtest.no_watch = fd_env_strip_cmdline_contains( pargc, pargv, "--no-watch" );
}

static void
backtest_topo( config_t * config ) {

  config->development.sandbox  = 0;
  config->development.no_clone = 1;

  ulong execrp_tile_cnt = config->firedancer.layout.execrp_tile_count;

  int disable_snap_loader      = !config->gossip.entrypoints_cnt;
  int solcap_enabled           = strlen( config->capture.solcap_capture )>0;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  ulong cpu_idx = 0;

  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_tile( topo, "metric", "metric", "metric_in", ULONG_MAX, 0, 0, 0 );

  fd_topob_wksp( topo, "backt" );
  fd_topo_tile_t * backt_tile = fd_topob_tile( topo, "backt", "backt", "metric_in", cpu_idx++, 0, 0, 0 );

  fd_topob_wksp( topo, "replay" );
  fd_topo_tile_t * replay_tile = fd_topob_tile( topo, "replay", "replay", "metric_in", cpu_idx++, 0, 1, 0 );

  fd_topob_wksp( topo, "accdb" )->core_dump_level = FD_TOPO_CORE_DUMP_LEVEL_FULL;
  fd_topo_tile_t * accdb_tile = fd_topob_tile( topo, "accdb", "accdb", "metric_in", cpu_idx++, 0, 0, 0 );

  /* specified by [tiles.replay] */

  fd_topob_wksp( topo, "progcache" );
  setup_topo_progcache( topo, "progcache",
      fd_progcache_est_rec_max( config->firedancer.runtime.program_cache.heap_size_mib<<20,
                                config->firedancer.runtime.program_cache.mean_cache_entry_size ),
      config->firedancer.runtime.max_live_slots,
      config->firedancer.runtime.program_cache.heap_size_mib<<20 );
  ulong progcache_obj_id; FD_TEST( (progcache_obj_id = fd_pod_query_ulong( topo->props, "progcache", ULONG_MAX ) )!=ULONG_MAX );
  fd_topob_tile_uses( topo, replay_tile, &topo->objs[ progcache_obj_id ], FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topob_wksp( topo, "accdb_data" );
  fd_topo_obj_t * accdb_obj = setup_topo_accdb( topo, "accdb_data",
      config->firedancer.accounts.max_accounts,
      config->firedancer.runtime.max_live_slots,
      FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT,
      8192UL,
      1UL<<35UL,
      config->firedancer.accounts.cache_size_gib*(1UL<<30UL),
      execrp_tile_cnt+3UL );
  FD_TEST( fd_pod_insertf_ulong( topo->props, accdb_obj->id, "accdb" ) );

  /**********************************************************************/
  /* Add the executor tiles to topo                                     */
  /**********************************************************************/
  fd_topob_wksp( topo, "execrp" );
  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )
  FOR(execrp_tile_cnt) fd_topob_tile( topo, "execrp", "execrp", "metric_in", cpu_idx++, 0, 0, 0 );

  /**********************************************************************/
  /* Add the capture tile to topo                                       */
  /**********************************************************************/
  if( solcap_enabled ) {
    fd_topob_wksp( topo, "solcap" );
    fd_topob_tile( topo, "solcap", "solcap", "metric_in", cpu_idx++, 0, 0, 0 );
  }

  /**********************************************************************/
  /* Add the snapshot tiles to topo                                       */
  /**********************************************************************/
  fd_topo_tile_t * snapin_tile = NULL;
  if( FD_UNLIKELY( !disable_snap_loader ) ) {
    fd_topob_wksp( topo, "snapct" );
    fd_topob_wksp( topo, "snapld" );
    fd_topob_wksp( topo, "snapdc" );
    fd_topob_wksp( topo, "snapin" );
    fd_topob_wksp( topo, "snapwr" );

    fd_topo_tile_t * snapct_tile = fd_topob_tile( topo, "snapct",  "snapct",  "metric_in",  cpu_idx++, 0, 0, 0 );
    fd_topo_tile_t * snapld_tile = fd_topob_tile( topo, "snapld",  "snapld",  "metric_in",  cpu_idx++, 0, 0, 0 );
    fd_topo_tile_t * snapdc_tile = fd_topob_tile( topo, "snapdc",  "snapdc",  "metric_in",  cpu_idx++, 0, 0, 0 );
                     snapin_tile = fd_topob_tile( topo, "snapin",  "snapin",  "metric_in",  cpu_idx++, 0, 0, 0 );
    fd_topo_tile_t * snapwr_tile = fd_topob_tile( topo, "snapwr",  "snapwr",  "metric_in",  cpu_idx++, 0, 0, 0 );

    snapct_tile->allow_shutdown = 1;
    snapld_tile->allow_shutdown = 1;
    snapdc_tile->allow_shutdown = 1;
    snapin_tile->allow_shutdown = 1;
    snapwr_tile->allow_shutdown = 1;
  } else {
    fd_topob_wksp( topo, "genesi" );
    fd_topob_tile( topo, "genesi",  "genesi",  "metric_in",  cpu_idx++, 0, 0, 0 )->allow_shutdown = 1;
  }

  /**********************************************************************/
  /* Setup backtest->replay link (repair_out) in topo                 */
  /**********************************************************************/

  /* The repair tile is replaced by the backtest tile for the repair to
     replay link.  The frag interface is a "slice", ie. entry batch,
     which is provided by the backtest tile, which reads in the entry
     batches from the CLI-specified source (eg. RocksDB). */

  fd_topob_wksp( topo, "repair_out" );
  fd_topob_link( topo, "repair_out", "repair_out", 65536UL, FD_SHRED_OUT_MTU, 1UL );
  fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "repair_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "backt", 0UL, "repair_out", 0UL );

  /**********************************************************************/
  /* Setup snapshot links in topo                                       */
  /**********************************************************************/
  if( FD_LIKELY( !disable_snap_loader ) ) {
    fd_topob_wksp( topo, "snapct_ld"    );
    fd_topob_wksp( topo, "snapld_dc"    );
    fd_topob_wksp( topo, "snapdc_in"    );

    fd_topob_wksp( topo, "snapin_manif" );
    fd_topob_wksp( topo, "snapct_repr"  );

    fd_topob_wksp( topo, "snapin_ct" );
    fd_topob_wksp( topo, "snapwr_ct" );

    fd_topob_link( topo, "snapct_ld",    "snapct_ld",    128UL,   sizeof(fd_ssctrl_init_t),       1UL );
    fd_topob_link( topo, "snapld_dc",    "snapld_dc",    16384UL, USHORT_MAX,                     1UL );
    fd_topob_link( topo, "snapdc_in",    "snapdc_in",    16384UL, USHORT_MAX,                     1UL );

    fd_topob_link( topo, "snapin_manif", "snapin_manif", 4UL,     sizeof(fd_snapshot_manifest_t), 1UL ); /* TODO: Should be depth 1 or 2 but replay backpressures */
    fd_topob_link( topo, "snapct_repr",  "snapct_repr",  128UL,   0UL,                            1UL )->permit_no_consumers = 1;

    fd_topob_link( topo, "snapin_ct",    "snapin_ct",    128UL,   0UL,                            1UL );
    fd_topob_link( topo, "snapwr_ct",    "snapwr_ct",    128UL,   0UL,                            1UL );

    fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapin_ct",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapwr_ct",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapld_dc",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapct",  0UL,              "snapct_ld",    0UL                                       );
    fd_topob_tile_out( topo, "snapct",  0UL,              "snapct_repr",  0UL                                       );
    fd_topob_tile_in ( topo, "snapld",  0UL, "metric_in", "snapct_ld",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapld",  0UL,              "snapld_dc",    0UL                                       );
    fd_topob_tile_in ( topo, "snapdc",  0UL, "metric_in", "snapld_dc",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapdc",  0UL,              "snapdc_in",    0UL                                       );
    fd_topob_tile_in ( topo, "snapin",  0UL, "metric_in", "snapdc_in",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_in ( topo, "snapwr",  0UL, "metric_in", "snapdc_in",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

    fd_topob_tile_out( topo, "snapin",  0UL,              "snapin_manif", 0UL                                       );
    fd_topob_tile_in ( topo, "replay",  0UL, "metric_in", "snapin_manif", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );

    fd_topob_tile_out( topo, "snapin", 0UL,               "snapin_ct",    0UL                                       );
    fd_topob_tile_out( topo, "snapwr", 0UL,               "snapwr_ct",    0UL                                       );
  } else {
    fd_topob_wksp( topo, "genesi_out" );
    fd_topob_link( topo, "genesi_out", "genesi_out", 1UL, FD_GENESIS_TILE_MTU, 0UL );
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
  fd_topob_wksp( topo, "replay_epoch"    );
  fd_topob_link( topo, "replay_epoch", "replay_epoch", 128UL, FD_EPOCH_OUT_MTU, 1UL );
  fd_topob_tile_out( topo, "replay", 0UL, "replay_epoch",   0UL );
  topo->links[ replay_tile->out_link_id[ fd_topo_find_tile_out_link( topo, replay_tile, "replay_epoch",   0 ) ] ].permit_no_consumers = 1;

  /**********************************************************************/
  /* Setup replay->backtest link (replay_notif) in topo                 */
  /**********************************************************************/

  fd_topob_wksp( topo, "replay_out" );
  fd_topob_link( topo, "replay_out", "replay_out", 8192UL, sizeof( fd_replay_message_t ), 1UL );
  fd_topob_tile_out( topo, "replay", 0UL, "replay_out", 0UL );
  fd_topob_tile_in ( topo, "backt", 0UL, "metric_in", "replay_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  if( FD_LIKELY( !disable_snap_loader ) ) {
    fd_topob_tile_in ( topo, "backt", 0UL, "metric_in", "snapin_manif", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  } else {
    fd_topob_tile_in ( topo, "backt", 0UL, "metric_in", "genesi_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  /**********************************************************************/
  /* Setup replay->exec link in topo                                    */
  /**********************************************************************/
  fd_topob_wksp( topo, "replay_execrp" );
  fd_topob_link( topo, "replay_execrp", "replay_execrp", 16384UL, 2240UL, 1UL );
  fd_topob_tile_out( topo, "replay", 0UL, "replay_execrp", 0UL );
  for( ulong i=0UL; i<execrp_tile_cnt; i++ ) {
    fd_topob_tile_in( topo, "execrp", i, "metric_in", "replay_execrp", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  /**********************************************************************/
  /* Setup exec->replay links in topo, to send solcap account updates
     so that they are serialized, and to notify replay tile that a txn
     has been finalized by the exec tile. */
  /**********************************************************************/
  fd_topob_wksp( topo, "execrp_replay" );

  FOR(execrp_tile_cnt) fd_topob_link( topo, "execrp_replay", "execrp_replay", 16384UL, sizeof(fd_execrp_task_done_msg_t), 1UL );

  FOR(execrp_tile_cnt) fd_topob_tile_out( topo, "execrp", i, "execrp_replay", i );
  FOR(execrp_tile_cnt) fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "execrp_replay", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  /**********************************************************************/
  /* Setup the shared objs used by replay and exec tiles                */
  /**********************************************************************/

  if( FD_UNLIKELY( solcap_enabled ) ) {
    /* 32 sections of SOLCAP_WRITE_ACCOUNT_DATA_MTU bytes each ≈ 4MB.
       This is done to ideally avoid cache thrashing and allow for all
       the links to sit on L3 cache. */
    fd_topob_link( topo, "cap_repl", "solcap", 32UL, SOLCAP_WRITE_ACCOUNT_DATA_MTU, 1UL );
    fd_topob_tile_out( topo, "replay", 0UL, "cap_repl", 0UL );
    fd_topob_tile_in( topo, "solcap", 0UL, "metric_in", "cap_repl", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    FOR(execrp_tile_cnt) fd_topob_link( topo, "cap_execrp", "solcap", 32UL, SOLCAP_WRITE_ACCOUNT_DATA_MTU, 1UL );
    FOR(execrp_tile_cnt) fd_topob_tile_out( topo, "execrp", i, "cap_execrp", i );
    FOR(execrp_tile_cnt) fd_topob_tile_in( topo, "solcap", 0UL, "metric_in", "cap_execrp", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  fd_topob_wksp( topo, "store" );
  ulong store_fec_data_max = fd_ulong_if( config->firedancer.runtime.fixed_fec_sets, 31840UL, 63985UL );
  fd_topo_obj_t * store_obj = setup_topo_store( topo, "store", config->firedancer.runtime.max_live_slots * FD_SHRED_BLK_MAX, 1, store_fec_data_max );
  fd_topob_tile_uses( topo, backt_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, store_obj->id, "store" ) );

  fd_topob_wksp( topo, "banks" );
  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks", config->firedancer.runtime.max_live_slots, config->firedancer.runtime.max_fork_width, 0 );
  fd_topob_tile_uses( topo, replay_tile, banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(execrp_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  fd_topob_wksp( topo, "txncache"    );
  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "txncache", config->firedancer.runtime.max_live_slots, FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT );
  fd_topob_tile_uses( topo, replay_tile, txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  if( FD_LIKELY( !disable_snap_loader ) ) fd_topob_tile_uses( topo, snapin_tile, txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  for( ulong i=0UL; i<execrp_tile_cnt; i++ ) {
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );

  fd_topob_tile_uses( topo, snapin_tile, accdb_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, accdb_tile, accdb_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, accdb_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR( execrp_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i ) ], accdb_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );

    if( !strcmp( tile->name, "replay" ) ) {
      tile->replay.enable_features_cnt = config->tiles.replay.enable_features_cnt;
      for( ulong i = 0; i < tile->replay.enable_features_cnt; i++ ) {
        fd_cstr_ncpy( tile->replay.enable_features[i], config->tiles.replay.enable_features[i], sizeof(tile->replay.enable_features[i]) );
      }
    }
  }

  // fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
}

static void
backtest_cmd_topo( config_t * config ) {
  backtest_topo( config );
}

extern configure_stage_t fd_cfg_stage_accdb;
extern configure_stage_t fd_cfg_stage_keys;

static args_t
configure_args( void ) {
  args_t args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  ulong stage_idx = 0UL;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_hugetlbfs;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_snapshots;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_accdb;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_keys;
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
fixup_config( config_t * config ) {

  /* FIXME Unfortunately, the fdctl boot procedure constructs the
           topology before parsing command-line arguments.  So, here,
           we construct the topology again (a third time ... sigh). */
  backtest_topo( config );
}

static void
backtest_cmd_fn( args_t *   args,
                 config_t * config ) {
  fixup_config( config );
  args_t c_args = configure_args();
  configure_cmd_fn( &c_args, config );

  initialize_workspaces( config );
  initialize_stacks( config );
  initialize_accdb_fd( config );

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
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
