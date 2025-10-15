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
#include <string.h>
#include "../firedancer/topology.h"
#include "../shared/commands/configure/configure.h"
#include "../shared/commands/run/run.h" /* initialize_workspaces */
#include "../shared/commands/watch/watch.h"
#include "../shared/fd_config.h" /* config_t */
#include "../../disco/tiles.h"
#include "../../disco/topo/fd_topob.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../discof/restore/utils/fd_ssctrl.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../discof/tower/fd_tower_tile.h"
#include "../../discof/replay/fd_exec.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../disco/pack/fd_pack_cost.h"
#include "../../flamenco/progcache/fd_progcache_admin.h"


#include "main.h"
#include "ledgers.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];
fd_topo_run_tile_t fdctl_tile_run( fd_topo_tile_t const * tile );

/* Global variable to store ledger name for access in topo function */
static char g_ledger_name[64] = {0};

/* Forward declaration */
static void apply_ledger_config( fd_ledger_config_t const * ledger_config, config_t * config );

/* Function to set the ledger name from main.c */
void
backtest_set_ledger_name( char const * ledger_name ) {
  strncpy( g_ledger_name, ledger_name, sizeof(g_ledger_name) - 1 );
  g_ledger_name[ sizeof(g_ledger_name) - 1 ] = '\0';
}

/* Global variable to store custom ledger config */
static fd_ledger_config_t g_custom_ledger_config = {0};
static int g_has_custom_config = 0;

/* Function to set custom ledger configuration from main function */
void
backtest_set_custom_config( fd_ledger_config_t * config ) {
  if( config ) {
    g_custom_ledger_config = *config;
    g_has_custom_config = 1;
    FD_LOG_NOTICE(( "Custom ledger configuration set from main function" ));
  }
}

/* Function to clear custom ledger configuration (for child processes) */
void
backtest_clear_custom_config( void ) {
  g_has_custom_config = 0;
  memset( &g_custom_ledger_config, 0, sizeof(g_custom_ledger_config) );
}

/* Function to create custom ledger configuration from command-line arguments */
void
create_custom_ledger_config( args_t * args ) {
  if( args->backtest.ledger_name[0] == '\0' ) {
    return; /* No ledger name provided */
  }

  /* Skip custom configuration creation if this is a child process (has --no-watch) */
  if( args->backtest.no_watch ) {
    FD_LOG_NOTICE(( "Child process detected, clearing custom config" ));
    /* Clear any inherited custom config from parent process */
    g_has_custom_config = 0;
    memset( &g_custom_ledger_config, 0, sizeof(g_custom_ledger_config) );
    return; /* This is a child process, skip custom config creation */
  }

  /* Check if any custom configuration flags were provided */
  int has_custom_flags = 0;
  if( args->backtest.cluster_version[0] != '\0' ||
      args->backtest.funk_pages != 0 ||
      args->backtest.index_max != 0 ||
      args->backtest.end_slot != 0 ||
      args->backtest.genesis ||
      args->backtest.has_incremental ) {
    has_custom_flags = 1;
  }

  if( !has_custom_flags ) {
    return;
  }

  /* Initialize custom config with defaults */
  memset( &g_custom_ledger_config, 0, sizeof(g_custom_ledger_config) );

  /* Set the name */
  snprintf( g_custom_ledger_config.name, FD_LEDGER_NAME_MAX_LEN, "%s", args->backtest.ledger_name );

  /* Set cluster version (default to "mainnet" if not provided) */
  if( args->backtest.cluster_version[0] != '\0' ) {
    snprintf( g_custom_ledger_config.cluster_version, FD_LEDGER_CLUSTER_VERSION_MAX_LEN, "%s", args->backtest.cluster_version );
  } else {
    snprintf( g_custom_ledger_config.cluster_version, FD_LEDGER_CLUSTER_VERSION_MAX_LEN, "mainnet" );
  }

  /* Set numeric values (use defaults if not provided) */
  g_custom_ledger_config.funk_pages = args->backtest.funk_pages ? args->backtest.funk_pages : 1UL;
  g_custom_ledger_config.index_max = args->backtest.index_max ? args->backtest.index_max : 0UL;
  g_custom_ledger_config.end_slot = args->backtest.end_slot ? args->backtest.end_slot : 0UL;

  /* Set boolean flags */
  g_custom_ledger_config.genesis = args->backtest.genesis;
  g_custom_ledger_config.has_incremental = args->backtest.has_incremental;

  g_has_custom_config = 1;
  FD_LOG_NOTICE(( "Created custom ledger configuration for: %s", g_custom_ledger_config.name ));
}

/* Custom topo initialize function that applies ledger configuration before calling fd_topo_initialize */
void
backtest_topo_initialize( config_t * config ) {
  /* Apply ledger configuration if provided - this needs to happen before
     fd_topo_initialize is called */
  if( g_ledger_name[0] != '\0' && strcmp( g_ledger_name, "backtest" ) != 0 ) {
    fd_ledger_config_t const * ledger_config = fd_ledger_config_find( g_ledger_name );
    if( !ledger_config ) {
      if( g_has_custom_config ) {
        /* Check if the custom config name matches the current ledger name */
        /* If not, this might be a child process with inherited custom config */
        if( strcmp( g_custom_ledger_config.name, g_ledger_name ) != 0 ) {
          FD_LOG_NOTICE(( "Custom config name mismatch (custom=%s, ledger=%s), clearing custom config", g_custom_ledger_config.name, g_ledger_name ));
          g_has_custom_config = 0;
          memset( &g_custom_ledger_config, 0, sizeof(g_custom_ledger_config) );
          /* Try to find predefined config again */
          ledger_config = fd_ledger_config_find( g_ledger_name );
          if( !ledger_config ) {
            FD_LOG_ERR(( "Ledger configuration not found for: %s. Please provide a configuration flags.", g_ledger_name ));
            return;
          }
          apply_ledger_config( ledger_config, config );
        } else {
          FD_LOG_NOTICE(( "Using custom ledger configuration for: %s", g_ledger_name ));
          apply_ledger_config( &g_custom_ledger_config, config );
        }
      } else {
        FD_LOG_ERR(( "Ledger configuration not found for: %s. Please provide a configuration flags.", g_ledger_name ));
        return;
      }
    } else {
      apply_ledger_config( ledger_config, config );
    }
  }

  /* Call the original topo initialize function */
  fd_topo_initialize( config );
}

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
      config->firedancer.funk.heap_size_gib );
  fd_topob_tile_uses( topo, replay_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topob_wksp( topo, "progcache" );
  fd_topo_obj_t * progcache_obj = setup_topo_progcache( topo, "progcache",
      fd_progcache_est_rec_max( config->firedancer.runtime.program_cache.heap_size_mib<<20,
                                config->firedancer.runtime.program_cache.mean_cache_entry_size ),
      config->firedancer.funk.max_database_transactions,
      config->firedancer.runtime.program_cache.heap_size_mib<<20 );
  fd_topob_tile_uses( topo, replay_tile, progcache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

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
    fd_topob_wksp( topo, "snapct" );
    fd_topob_wksp( topo, "snapld" );
    fd_topob_wksp( topo, "snapdc" );
    fd_topob_wksp( topo, "snapin" );
    fd_topo_tile_t * snapct_tile = fd_topob_tile( topo, "snapct",  "snapct",  "metric_in",  cpu_idx++, 0, 0 );
    fd_topo_tile_t * snapld_tile = fd_topob_tile( topo, "snapld",  "snapld",  "metric_in",  cpu_idx++, 0, 0 );
    fd_topo_tile_t * snapdc_tile = fd_topob_tile( topo, "snapdc",  "snapdc",  "metric_in",  cpu_idx++, 0, 0 );
                     snapin_tile = fd_topob_tile( topo, "snapin",  "snapin",  "metric_in",  cpu_idx++, 0, 0 );
    snapct_tile->allow_shutdown = 1;
    snapld_tile->allow_shutdown = 1;
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
    fd_topob_wksp( topo, "snapct_ld"    );
    fd_topob_wksp( topo, "snapld_dc"    );
    fd_topob_wksp( topo, "snapdc_in"    );
    fd_topob_wksp( topo, "snapin_ct"    );
    fd_topob_wksp( topo, "snapin_manif" );
    fd_topob_wksp( topo, "snapct_repr"  );

    fd_topob_link( topo, "snapct_ld",    "snapct_ld",    128UL,   sizeof(fd_ssctrl_init_t),       1UL );
    fd_topob_link( topo, "snapld_dc",    "snapld_dc",    16384UL, USHORT_MAX,                     1UL );
    fd_topob_link( topo, "snapdc_in",    "snapdc_in",    16384UL, USHORT_MAX,                     1UL );
    fd_topob_link( topo, "snapin_ct",    "snapin_ct",    128UL,   0UL,                            1UL );
    fd_topob_link( topo, "snapin_manif", "snapin_manif", 4UL,     sizeof(fd_snapshot_manifest_t), 1UL ); /* TODO: Should be depth 1 or 2 but replay backpressures */
    fd_topob_link( topo, "snapct_repr",  "snapct_repr",  128UL,   0UL,                            1UL )->permit_no_consumers = 1;

    fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapin_ct",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapld_dc",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapct",  0UL,              "snapct_ld",    0UL                                       );
    fd_topob_tile_out( topo, "snapct",  0UL,              "snapct_repr",  0UL                                       );
    fd_topob_tile_in ( topo, "snapld",  0UL, "metric_in", "snapct_ld",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapld",  0UL,              "snapld_dc",    0UL                                       );
    fd_topob_tile_in ( topo, "snapdc",  0UL, "metric_in", "snapld_dc",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapdc",  0UL,              "snapdc_in",    0UL                                       );
    fd_topob_tile_in ( topo, "snapin",  0UL, "metric_in", "snapdc_in",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapin",  0UL,              "snapin_ct",    0UL                                       );
    fd_topob_tile_out( topo, "snapin",  0UL,              "snapin_manif", 0UL                                       );
    fd_topob_tile_in ( topo, "replay",  0UL, "metric_in", "snapin_manif", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );
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

  /* If solcap is enabled, we need to overload this link to also send
     solcap account updates to the replay tile. We can't use a separate
     link for this without introducing a race. This will get removed with solcap V2. */
  if( FD_UNLIKELY( solcap_enabled ) ) {
    /* TODO: remove this with solcap V2 */
    FOR(exec_tile_cnt) fd_topob_link( topo, "exec_replay", "exec_replay", 1024UL, FD_CAPTURE_CTX_ACCOUNT_UPDATE_MSG_FOOTPRINT, 1UL );
  } else {
    FOR(exec_tile_cnt) fd_topob_link( topo, "exec_replay", "exec_replay", 16384UL, sizeof(fd_exec_task_done_msg_t), 1UL );
  }

  FOR(exec_tile_cnt) fd_topob_tile_out( topo, "exec", i, "exec_replay", i );
  FOR(exec_tile_cnt) fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "exec_replay", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

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

    if( !strcmp( tile->name, "replay" ) ) {
      tile->replay.enable_bank_hash_cmp = 0;
      tile->replay.enable_features_cnt = config->tiles.replay.enable_features_cnt;
      for( ulong i = 0; i < tile->replay.enable_features_cnt; i++ ) {
        strncpy( tile->replay.enable_features[i], config->tiles.replay.enable_features[i], sizeof(tile->replay.enable_features[i]) );
      }
    }
  }

  // fd_topob_auto_layout( topo, 0 );
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
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_snapshots;
  args.configure.stages[ stage_idx++ ] = NULL;

  return args;
}

void
backtest_cmd_args( int *    pargc,
                   char *** pargv,
                   args_t * args ) {

  args->backtest.no_watch = fd_env_strip_cmdline_contains( pargc, pargv, "--no-watch" );
  args->backtest.ci_mode = fd_env_strip_cmdline_contains( pargc, pargv, "--ci" );

  if( *pargc > 0 && strncmp( **pargv, "--", 2 ) ) {
    strncpy( args->backtest.ledger_name, **pargv, sizeof(args->backtest.ledger_name) - 1 );
    args->backtest.ledger_name[ sizeof(args->backtest.ledger_name) - 1 ] = '\0';
  } else {
    args->backtest.ledger_name[0] = '\0';
  }

  *pargc = 0;
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
apply_ledger_config( fd_ledger_config_t const * ledger_config, config_t * config ) {
  if( !ledger_config ) return;


  char * dump_dir = getenv("DUMP_DIR");
  if( dump_dir == NULL ) {
    dump_dir = "dump";
  }

  // create var for ledger_path and set to dump_dir/ledger_config->name
  char ledger_path[1024];
  strncpy( ledger_path, dump_dir, sizeof(ledger_path) - 1 );
  ledger_path[ sizeof(ledger_path) - 1 ] = '\0';
  strncat( ledger_path, "/", sizeof(ledger_path) - strlen(ledger_path) - 1 );
  ledger_path[ sizeof(ledger_path) - 1 ] = '\0';
  strncat( ledger_path, ledger_config->name, sizeof(ledger_path) - strlen(ledger_path) - 1 );
  ledger_path[ sizeof(ledger_path) - 1 ] = '\0';

  if( access( ledger_path, F_OK ) != 0 ) {
    FD_LOG_NOTICE(( "Ledger directory does not exist: %s, attempting to download...", ledger_path ));

    char mkdir_cmd[2048];
    snprintf( mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", ledger_path );
    if( system( mkdir_cmd ) != 0 ) {
      FD_LOG_ERR(( "Failed to create ledger directory: %s", ledger_path ));
      return;
    }

    char download_cmd[4096];
    snprintf( download_cmd, sizeof(download_cmd),
              "gcloud storage cat gs://firedancer-ci-resources/%s.tar.gz | tar zxf - -C %s",
              ledger_config->name, dump_dir );

    FD_LOG_NOTICE(( "Downloading ledger from gcloud: %s", ledger_config->name ));
    int download_result = system( download_cmd );

    if( download_result != 0 ) {
      FD_LOG_ERR(( "Failed to download ledger: %s", ledger_config->name ));
      return;
    }

    if( access( ledger_path, F_OK ) != 0 ) {
      FD_LOG_ERR(( "Ledger directory still does not exist after download: %s", ledger_path ));
      return;
    }

    FD_LOG_NOTICE(( "Successfully downloaded and extracted ledger: %s", ledger_path ));
  }

  if( chmod( ledger_path, 0700 ) != 0 ) {
    FD_LOG_ERR(( "Failed to change permissions of ledger directory: %s", ledger_path ));
    return;
  }

  /* Set cluster version */
  strncpy( config->tiles.replay.cluster_version, ledger_config->cluster_version,
           sizeof(config->tiles.replay.cluster_version) - 1 );
  config->tiles.replay.cluster_version[ sizeof(config->tiles.replay.cluster_version) - 1 ] = '\0';

  /* Set funk configuration */
  config->firedancer.funk.heap_size_gib = ledger_config->funk_pages;
  config->firedancer.funk.max_account_records = ledger_config->index_max;

  /* Set archiver configuration */
  config->tiles.archiver.enabled = 1;
  config->tiles.archiver.end_slot = ledger_config->end_slot;

  strncpy( config->tiles.archiver.ingest_mode, "rocksdb", sizeof(config->tiles.archiver.ingest_mode) - 1 );
  config->tiles.archiver.ingest_mode[ sizeof(config->tiles.archiver.ingest_mode) - 1 ] = '\0';

  strncpy( config->tiles.archiver.rocksdb_path, dump_dir, sizeof(config->tiles.archiver.rocksdb_path) - 1 );
  config->tiles.archiver.rocksdb_path[ sizeof(config->tiles.archiver.rocksdb_path) - 1 ] = '\0';
  strncat( config->tiles.archiver.rocksdb_path, "/", sizeof(config->tiles.archiver.rocksdb_path) - strlen(config->tiles.archiver.rocksdb_path) - 1 );
  config->tiles.archiver.rocksdb_path[ sizeof(config->tiles.archiver.rocksdb_path) - 1 ] = '\0';
  strncat( config->tiles.archiver.rocksdb_path, ledger_config->name, sizeof(config->tiles.archiver.rocksdb_path) - strlen(config->tiles.archiver.rocksdb_path) - 1 );
  config->tiles.archiver.rocksdb_path[ sizeof(config->tiles.archiver.rocksdb_path) - 1 ] = '\0';
  strncat( config->tiles.archiver.rocksdb_path, "/rocksdb", sizeof(config->tiles.archiver.rocksdb_path) - strlen(config->tiles.archiver.rocksdb_path) - 1 );
  config->tiles.archiver.rocksdb_path[ sizeof(config->tiles.archiver.rocksdb_path) - 1 ] = '\0';

  // set paths to dump/ledger_config->name
  strncpy( config->paths.snapshots, dump_dir, sizeof(config->paths.snapshots) - 1 );
  config->paths.snapshots[ sizeof(config->paths.snapshots) - 1 ] = '\0';
  strncat( config->paths.snapshots, "/", sizeof(config->paths.snapshots) - strlen(config->paths.snapshots) - 1 );
  config->paths.snapshots[ sizeof(config->paths.snapshots) - 1 ] = '\0';
  strncat( config->paths.snapshots, ledger_config->name, sizeof(config->paths.snapshots) - strlen(config->paths.snapshots) - 1 );
  config->paths.snapshots[ sizeof(config->paths.snapshots) - 1 ] = '\0';

  /* Set snapshot configuration */
  config->firedancer.snapshots.incremental_snapshots = ledger_config->has_incremental;
  config->firedancer.snapshots.sources.servers_cnt = 0;
  config->firedancer.snapshots.sources.gossip.allow_any = false;
  config->firedancer.snapshots.sources.gossip.allow_list_cnt = 0;

  /* Set gossip configuration based on genesis flag */
  if( ledger_config->genesis ) {
    config->gossip.entrypoints_cnt = 0; /* No entrypoints for genesis mode */
  } else {
    config->gossip.entrypoints_cnt = 1;
    strncpy( config->gossip.entrypoints[0], "0.0.0.0:1", sizeof(config->gossip.entrypoints[0]) - 1 );
    config->gossip.entrypoints[0][ sizeof(config->gossip.entrypoints[0]) - 1 ] = '\0';
  }

  /* Set replay features if any */
  config->tiles.replay.enable_features_cnt = (uint)ledger_config->features_cnt;
  for( ulong i = 0; i < ledger_config->features_cnt && i < FD_LEDGER_MAX_FEATURES; i++ ) {
    strncpy( config->tiles.replay.enable_features[i], ledger_config->features[i],
             sizeof(config->tiles.replay.enable_features[i]) - 1 );
    config->tiles.replay.enable_features[i][ sizeof(config->tiles.replay.enable_features[i]) - 1 ] = '\0';
  }
  if( ledger_config->genesis ) {
    strncpy( config->paths.genesis, dump_dir, sizeof(config->paths.genesis) - 1 );
    config->paths.genesis[ sizeof(config->paths.genesis) - 1 ] = '\0';
    strncat( config->paths.genesis, "/", sizeof(config->paths.genesis) - strlen(config->paths.genesis) - 1 );
    config->paths.genesis[ sizeof(config->paths.genesis) - 1 ] = '\0';
    strncat( config->paths.genesis, ledger_config->name, sizeof(config->paths.genesis) - strlen(config->paths.genesis) - 1 );
    config->paths.genesis[ sizeof(config->paths.genesis) - 1 ] = '\0';
    strncat( config->paths.genesis, "/", sizeof(config->paths.genesis) - strlen(config->paths.genesis) - 1 );
    config->paths.genesis[ sizeof(config->paths.genesis) - 1 ] = '\0';
    strncat( config->paths.genesis, "genesis.bin", sizeof(config->paths.genesis) - strlen(config->paths.genesis) - 1 );
    config->paths.genesis[ sizeof(config->paths.genesis) - 1 ] = '\0';

  }
}

static void
backtest_cmd_fn( args_t *   args,
                 config_t * config ) {
  args_t c_args = configure_args();
  configure_cmd_fn( &c_args, config );

  /* Create custom ledger configuration if flags are provided */
  create_custom_ledger_config( args );

  /* Store ledger name in global variable for access in topo function */
  strncpy( g_ledger_name, args->backtest.ledger_name, sizeof(g_ledger_name) - 1 );
  g_ledger_name[ sizeof(g_ledger_name) - 1 ] = '\0';

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
