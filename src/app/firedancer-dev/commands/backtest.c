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
#include "../../../disco/tiles.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/topo/fd_topob_vinyl.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../discof/replay/fd_replay_tile.h"
#include "../../../discof/restore/fd_snapin_tile_private.h"
#include "../../../discof/restore/fd_snaplv_tile_private.h"
#include "../../../discof/restore/fd_snapwm_tile_private.h"
#include "../../../discof/restore/utils/fd_slot_delta_parser.h"
#include "../../../discof/restore/utils/fd_ssctrl.h"
#include "../../../discof/restore/utils/fd_ssmsg.h"
#include "../../../discof/tower/fd_tower_tile.h"
#include "../../../discof/replay/fd_execrp.h"
#include "../../../ballet/lthash/fd_lthash.h"
#include "../../../flamenco/capture/fd_capture_ctx.h"
#include "../../../disco/pack/fd_pack_cost.h"
#include "../../../flamenco/progcache/fd_progcache_admin.h"
#include "../../../flamenco/runtime/tests/ledgers.h"
#include "../../../flamenco/runtime/fd_rocksdb.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern fd_topo_obj_callbacks_t * CALLBACKS[];
fd_topo_run_tile_t fdctl_tile_run( fd_topo_tile_t const * tile );

extern void fd_config_load_buf( fd_config_t * out, char const * buf, ulong sz, char const * path );
extern void fd_config_validate( fd_config_t const * config );

static char g_ledger_name[64] = {0};
static char g_config_file[PATH_MAX] = {0};
static char const * g_binary_path = NULL;

static fd_ledger_config_t const *
fd_ledger_config_find( char const * name ) {
  if( !name ) return NULL;
  for( ulong i = 0UL; i < FD_LEDGER_CONFIG_COUNT; i++ ) {
    if( !fd_ledger_configs[ i ] ) break;
    if( !strcmp( fd_ledger_configs[ i ]->test_name, name ) ) {
      return fd_ledger_configs[ i ];
    }
  }
  return NULL;
}

static void
gcloud_auth( void ) {
  char const * key_files[] = {
    "/etc/firedancer-scratch-bucket-key.json",
    "/etc/firedancer-ci-78fff3e07c8b.json",
  };

  for( ulong i = 0UL; i < sizeof(key_files)/sizeof(key_files[0]); i++ ) {
    pid_t pid = fork();
    if( FD_UNLIKELY( pid < 0 ) ) {
      continue;
    }

    if( pid == 0 ) {
      int devnull = open( "/dev/null", O_WRONLY );
      if( devnull >= 0 ) {
        dup2( devnull, STDOUT_FILENO );
        dup2( devnull, STDERR_FILENO );
        close( devnull );
      }

      char const * argv[] = { "gcloud", "auth", "activate-service-account", "--key-file", key_files[i], NULL };
      execvp( "gcloud", (char **)argv );
      exit( 1 );
    }

    int status;
    waitpid( pid, &status, 0 );
  }
}

static int
download_ledger_from_gcloud( char const * ledger_name,
                              char const * dump_dir ) {
  gcloud_auth();

  int pipefd[2];
  if( FD_UNLIKELY( pipe( pipefd ) ) ) {
    FD_LOG_WARNING(( "pipe() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  pid_t gcloud_pid = fork();
  if( FD_UNLIKELY( gcloud_pid < 0 ) ) {
    FD_LOG_WARNING(( "fork() failed for gcloud (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( pipefd[0] );
    close( pipefd[1] );
    return -1;
  }

  if( gcloud_pid == 0 ) {
    close( pipefd[0] );
    if( FD_UNLIKELY( dup2( pipefd[1], STDOUT_FILENO ) < 0 ) ) {
      FD_LOG_ERR(( "dup2() failed for gcloud stdout (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    close( pipefd[1] );

    char gs_path[256];
    snprintf( gs_path, sizeof(gs_path), "gs://firedancer-ci-resources/%s.tar.gz", ledger_name );

    char const * argv[] = { "gcloud", "storage", "cat", gs_path, NULL };
    execvp( "gcloud", (char **)argv );
    FD_LOG_ERR(( "execvp() failed for gcloud (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  pid_t tar_pid = fork();
  if( FD_UNLIKELY( tar_pid < 0 ) ) {
    FD_LOG_WARNING(( "fork() failed for tar (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( pipefd[0] );
    close( pipefd[1] );
    return -1;
  }

  if( tar_pid == 0 ) {
    close( pipefd[1] );
    if( FD_UNLIKELY( dup2( pipefd[0], STDIN_FILENO ) < 0 ) ) {
      FD_LOG_ERR(( "dup2() failed for tar stdin (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    close( pipefd[0] );

    char const * argv[] = { "tar", "zxf", "-", "-C", dump_dir, NULL };
    execvp( "tar", (char **)argv );
    FD_LOG_ERR(( "execvp() failed for tar (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  close( pipefd[0] );
  close( pipefd[1] );

  int gcloud_status = 0;
  int tar_status = 0;
  if( FD_UNLIKELY( waitpid( gcloud_pid, &gcloud_status, 0 ) < 0 ) ) {
    return -1;
  }
  if( FD_UNLIKELY( waitpid( tar_pid, &tar_status, 0 ) < 0 ) ) {
    return -1;
  }

  if( !WIFEXITED( gcloud_status ) || WEXITSTATUS( gcloud_status ) != 0 ) {
    return -1;
  }
  if( !WIFEXITED( tar_status ) || WEXITSTATUS( tar_status ) != 0 ) {
    return -1;
  }

  return 0;
}

static void
apply_ledger_config( fd_ledger_config_t const * ledger_config, config_t * config ) {
  if( !ledger_config ) return;

  if( ledger_config->vinyl ) {
    config->firedancer.funk.heap_size_gib             = 2UL;
    config->firedancer.funk.max_account_records       = 1000000UL;

    config->firedancer.vinyl.enabled              = 1;
    config->firedancer.vinyl.max_account_records  = ledger_config->index_max<1000000UL ? 2000000UL : ledger_config->index_max * 2UL;
    config->firedancer.vinyl.file_size_gib        = ledger_config->funk_pages * 4UL;
    config->firedancer.vinyl.max_cache_entries    = 100000UL;
    config->firedancer.vinyl.cache_size_gib       = 10UL;
    config->firedancer.vinyl.io_uring.enabled     = 1;
  } else {
    config->firedancer.funk.heap_size_gib             = ledger_config->funk_pages;
    config->firedancer.funk.max_account_records       = ledger_config->index_max;
  }

  config->tiles.archiver.enabled  = 1;
  config->tiles.archiver.end_slot = ledger_config->end_slot;
  config->tiles.archiver.ingest_dead_slots = 0;
  config->tiles.archiver.root_distance = 32;

  char ledger_dir[256];
  char ledger_name_stripped[256];
  fd_cstr_ncpy( ledger_name_stripped, ledger_config->ledger_name, sizeof(ledger_name_stripped) );

  char * vinyl_suffix = strstr( ledger_name_stripped, "-vinyl" );
  if( vinyl_suffix && vinyl_suffix[ 6 ] == '\0' ) {
    *vinyl_suffix = '\0';
  }

  char * dump_dir = getenv("DUMP_DIR");
  if( dump_dir == NULL ) {
    dump_dir = "dump";
  }

  fd_cstr_printf( ledger_dir, sizeof(ledger_dir), NULL, "%s/%s", dump_dir, ledger_name_stripped );

  if( access( ledger_dir, F_OK )!=0 ) {
    FD_LOG_NOTICE(( "Ledger directory does not exist, checking gcloud for ledger %s", ledger_config->ledger_name ));

    if( FD_UNLIKELY( mkdir( ledger_dir, 0700 )!=0 ) ) {
      FD_LOG_ERR(( "Failed to create ledger directory: %s", ledger_dir ));
    }

    FD_LOG_NOTICE(( "Downloading ledger from gcloud: %s", ledger_config->ledger_name ));

    if( FD_UNLIKELY( download_ledger_from_gcloud( ledger_config->ledger_name, dump_dir ) ) ) {
      rmdir( ledger_dir );
      FD_LOG_ERR(( "Failed to download ledger: %s", ledger_config->ledger_name ));
      return;
    }

    if( access( ledger_dir, F_OK )!=0 ) {
      FD_LOG_ERR(( "Ledger directory still does not exist after download: %s", ledger_dir ));
      return;
    }

    FD_LOG_NOTICE(( "Successfully downloaded and extracted ledger: %s", ledger_dir ));
  }

  if( FD_UNLIKELY( chmod( ledger_dir, 0700 )!=0 ) ) {
    FD_LOG_ERR(( "Failed to chmod ledger directory: %s", ledger_dir ));
  }

  char shredcap_path[PATH_MAX];
  fd_cstr_printf( shredcap_path, sizeof(shredcap_path), NULL, "%s/shreds.pcapng.zst", ledger_dir );

  struct stat st;
  if( stat( shredcap_path, &st )==0 ) {
    fd_cstr_ncpy( config->tiles.archiver.ingest_mode, "shredcap", sizeof(config->tiles.archiver.ingest_mode) );
    fd_cstr_ncpy( config->tiles.archiver.shredcap_path, shredcap_path, sizeof(config->tiles.archiver.shredcap_path) );
  } else {
    fd_cstr_ncpy( config->tiles.archiver.ingest_mode, "rocksdb", sizeof(config->tiles.archiver.ingest_mode) );
    char rocksdb_path[PATH_MAX];
    fd_cstr_printf( rocksdb_path, sizeof(rocksdb_path), NULL, "%s/rocksdb", ledger_dir );
    fd_cstr_ncpy( config->tiles.archiver.rocksdb_path, rocksdb_path, sizeof(config->tiles.archiver.rocksdb_path) );

    /* If end_slot is not set (ULONG_MAX), detect it from the rocksdb */
    if( FD_UNLIKELY( ledger_config->end_slot==ULONG_MAX || ledger_config->end_slot==0UL ) ) {
      fd_rocksdb_t db;
      if( FD_LIKELY( !fd_rocksdb_init( &db, rocksdb_path ) ) ) {
        char * err = NULL;
        ulong last_slot;
        if( FD_LIKELY( (last_slot = fd_rocksdb_last_slot(&db, &err))!=0UL ) ) {
          config->tiles.archiver.end_slot = last_slot;
          FD_LOG_NOTICE(( "Auto-detected end_slot from rocksdb: %lu", last_slot ));
        } else {
          fd_rocksdb_destroy( &db );
          FD_LOG_ERR(( "Failed to get last slot from rocksdb: %s", err ));
        }
        fd_rocksdb_destroy( &db );
      } else {
        FD_LOG_ERR(( "Failed to open rocksdb at %s", rocksdb_path ));
      }
    }
  }

  fd_cstr_ncpy( config->paths.snapshots, ledger_dir, sizeof(config->paths.snapshots) );

  if( ledger_config->vinyl ) {
    char accounts_path[PATH_MAX];
    fd_cstr_printf( accounts_path, sizeof(accounts_path), NULL, "%s/accounts.db", ledger_dir );
    fd_cstr_ncpy( config->paths.accounts, accounts_path, sizeof(config->paths.accounts) );
  }

  config->firedancer.snapshots.incremental_snapshots = ledger_config->has_incremental;

  config->development.snapshots.disable_lthash_verification = 1;

  config->firedancer.layout.snapshot_hash_tile_count = 1UL;
  config->firedancer.layout.execrp_tile_count        = 10UL;

  config->firedancer.runtime.max_live_slots  = 32UL;
  config->firedancer.runtime.max_fork_width  = 4UL;

  config->tiles.replay.enable_features_cnt = ledger_config->enable_features_cnt;
  for( ulong i = 0UL; i < ledger_config->enable_features_cnt && i < 16UL; i++ ) {
    fd_cstr_ncpy( config->tiles.replay.enable_features[i],
                  ledger_config->enable_features[i],
                  sizeof(config->tiles.replay.enable_features[i]) );
  }

  config->firedancer.snapshots.sources.servers_cnt = 0;
  config->firedancer.snapshots.sources.gossip.allow_any = 0;
  config->firedancer.snapshots.sources.gossip.allow_list_cnt = 0;

  if( ledger_config->genesis ) {
    char genesis_path[PATH_MAX];
    fd_cstr_printf( genesis_path, sizeof(genesis_path), NULL, "%s/genesis.bin", ledger_dir );
    fd_cstr_ncpy( config->paths.genesis, genesis_path, sizeof(config->paths.genesis) );
    config->gossip.entrypoints_cnt = 0;
  } else {
    config->gossip.entrypoints_cnt = 1;
    snprintf( config->gossip.entrypoints[0], sizeof(config->gossip.entrypoints[0]), "0.0.0.0:1" );
  }
}

static void
backtest_topo( config_t * config ) {

  config->development.sandbox  = 0;
  config->development.no_clone = 1;
  config->development.snapshots.disable_lthash_verification = 1;

  ulong execrp_tile_cnt = config->firedancer.layout.execrp_tile_count;
  ulong lta_tile_cnt    = config->firedancer.layout.snapshot_hash_tile_count;
  ulong snapwr_tile_cnt = config->firedancer.layout.snapwr_tile_count;
  ulong snaplh_tile_cnt = config->firedancer.layout.snapshot_hash_tile_count;

  int disable_snap_loader      = !config->gossip.entrypoints_cnt;
  int vinyl_enabled            = !!config->firedancer.vinyl.enabled;
  int solcap_enabled           = strlen( config->capture.solcap_capture )>0;
  int snapshot_lthash_disabled = config->development.snapshots.disable_lthash_verification;

  fd_topo_t * topo = { fd_topob_new( &config->topo, config->name ) };
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  topo->gigantic_page_threshold = config->hugetlbfs.gigantic_page_threshold_mib << 20;

  ulong cpu_idx = 0;

  fd_topob_wksp( topo, "metric" );
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_tile( topo, "metric", "metric", "metric_in", ULONG_MAX, 0, 0 );

  fd_topob_wksp( topo, "backt" );
  fd_topo_tile_t * backt_tile = fd_topob_tile( topo, "backt", "backt", "metric_in", cpu_idx++, 0, 0 );

  fd_topob_wksp( topo, "replay" );
  fd_topo_tile_t * replay_tile = fd_topob_tile( topo, "replay", "replay", "metric_in", cpu_idx++, 0, 0 );

  /* specified by [tiles.replay] */

  fd_topob_wksp( topo, "funk" );
  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.runtime.max_live_slots + config->firedancer.vinyl.write_delay_slots,
      config->firedancer.funk.heap_size_gib );
  fd_topob_tile_uses( topo, replay_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topob_wksp( topo, "progcache" );
  fd_topo_obj_t * progcache_obj = setup_topo_progcache( topo, "progcache",
      fd_progcache_est_rec_max( config->firedancer.runtime.program_cache.heap_size_mib<<20,
                                config->firedancer.runtime.program_cache.mean_cache_entry_size ),
      config->firedancer.runtime.max_live_slots,
      config->firedancer.runtime.program_cache.heap_size_mib<<20 );
  fd_topob_tile_uses( topo, replay_tile, progcache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  /**********************************************************************/
  /* Add the executor tiles to topo                                     */
  /**********************************************************************/
  fd_topob_wksp( topo, "execrp" );
  #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )
  FOR(execrp_tile_cnt) fd_topob_tile( topo, "execrp", "execrp", "metric_in", cpu_idx++, 0, 0 );

  /**********************************************************************/
  /* Add the capture tile to topo                                       */
  /**********************************************************************/
  if( solcap_enabled ) {
    fd_topob_wksp( topo, "solcap" );
    fd_topob_tile( topo, "solcap", "solcap", "metric_in", cpu_idx++, 0, 0 );
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

    fd_topo_tile_t * snapct_tile = fd_topob_tile( topo, "snapct",  "snapct",  "metric_in",  cpu_idx++, 0, 0 );
    fd_topo_tile_t * snapld_tile = fd_topob_tile( topo, "snapld",  "snapld",  "metric_in",  cpu_idx++, 0, 0 );
    fd_topo_tile_t * snapdc_tile = fd_topob_tile( topo, "snapdc",  "snapdc",  "metric_in",  cpu_idx++, 0, 0 );
                     snapin_tile = fd_topob_tile( topo, "snapin",  "snapin",  "metric_in",  cpu_idx++, 0, 0 );

    snapct_tile->allow_shutdown = 1;
    snapld_tile->allow_shutdown = 1;
    snapdc_tile->allow_shutdown = 1;
    snapin_tile->allow_shutdown = 1;

    if( vinyl_enabled ) {
      fd_topob_wksp( topo, "snapwm" );
      fd_topo_tile_t * snapwm_tile = fd_topob_tile( topo, "snapwm", "snapwm", "metric_in", cpu_idx++, 0, 0 );
      snapwm_tile->allow_shutdown = 1;

      fd_topob_wksp( topo, "snapwh" );
      fd_topo_tile_t * snapwh_tile = fd_topob_tile( topo, "snapwh", "snapwh", "metric_in", cpu_idx++, 0, 0 );
      snapwh_tile->allow_shutdown = 1;

      fd_topob_wksp( topo, "snapwr" );
      FOR(snapwr_tile_cnt) fd_topob_tile( topo, "snapwr", "snapwr", "metric_in", cpu_idx++, 0, 0 )->allow_shutdown = 1;
    }

    if( snapshot_lthash_disabled ) {
      /* nothing to do here */
    } else {
      if( vinyl_enabled ) {
        fd_topob_wksp( topo, "snaplh"    );
        fd_topob_wksp( topo, "snaplv"    );
        FOR(snaplh_tile_cnt) fd_topob_tile( topo, "snaplh", "snaplh", "metric_in", ULONG_MAX, 0, 0 )->allow_shutdown = 1;
        /**/                 fd_topob_tile( topo, "snaplv", "snaplv", "metric_in", ULONG_MAX, 0, 0 )->allow_shutdown = 1;
        fd_topob_wksp( topo, "vinyl_admin" );
      } else {
        fd_topob_wksp( topo, "snapla" );
        fd_topob_wksp( topo, "snapls" );
        FOR(lta_tile_cnt)  fd_topob_tile( topo, "snapla", "snapla", "metric_in", cpu_idx++,  0, 0 )->allow_shutdown = 1;
        /**/               fd_topob_tile( topo, "snapls", "snapls", "metric_in", cpu_idx++,  0, 0 )->allow_shutdown = 1;
      }
    }

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

    fd_topob_wksp( topo, "snapin_manif" );
    fd_topob_wksp( topo, "snapct_repr"  );

    if( vinyl_enabled ) {
      fd_topob_wksp( topo, "snapin_txn");
      fd_topob_wksp( topo, "snapin_wm" );
      fd_topob_wksp( topo, "snapwm_wr" );
    }
    if( snapshot_lthash_disabled ) {
      if( vinyl_enabled ) {
        fd_topob_wksp( topo, "snapwm_ct" );
      } else {
        fd_topob_wksp( topo, "snapin_ct" );
      }
    } else {
      if( vinyl_enabled ) {
        fd_topob_wksp( topo, "snaplv_lh" );
        fd_topob_wksp( topo, "snaplh_lv" );
        fd_topob_wksp( topo, "snapwm_lv" );
        fd_topob_wksp( topo, "snaplv_ct" );
      } else {
        fd_topob_wksp( topo, "snapla_ls" );
        fd_topob_wksp( topo, "snapin_ls" );
        fd_topob_wksp( topo, "snapls_ct" );
      }
    }

    fd_topob_link( topo, "snapct_ld",    "snapct_ld",    128UL,   sizeof(fd_ssctrl_init_t),       1UL );
    fd_topob_link( topo, "snapld_dc",    "snapld_dc",    16384UL, USHORT_MAX,                     1UL );
    fd_topob_link( topo, "snapdc_in",    "snapdc_in",    16384UL, USHORT_MAX,                     1UL );

    fd_topob_link( topo, "snapin_manif", "snapin_manif", 4UL,     sizeof(fd_snapshot_manifest_t), 1UL ); /* TODO: Should be depth 1 or 2 but replay backpressures */
    fd_topob_link( topo, "snapct_repr",  "snapct_repr",  128UL,   0UL,                            1UL )->permit_no_consumers = 1;

    if( vinyl_enabled ) {
      /* snapwm needs all txn_cache data in order to verify the slot
       deltas with the slot history.  To make this possible, snapin
       uses the dcache of the snapin_txn link as the scratch memory.
       The depth of the link should match that of snapin_wm, just to
       guarantee enough mcache credits.  The mtu needs to be adjusted
       so that the total dcache size matches what snapin requires.
       Round up the mtu (ulong) size using: (...+(depth-1))/depth. */
      fd_topob_link( topo, "snapin_txn", "snapin_txn",   16UL, (sizeof(fd_sstxncache_entry_t)*FD_SNAPIN_TXNCACHE_MAX_ENTRIES+15UL/*depth-1*/)/16UL/*depth*/, 1UL );
      fd_topob_link( topo, "snapin_wm", "snapin_wm",     16UL, FD_SNAPWM_PAIR_BATCH_SZ_MAX,       1UL );
      /* snapwh and snapwr both use snapwm_wh's dcache.  snapwh sends
         control messages to snapwr, using snapwh_wr link, instructing
         which chunks in the dcache are ready to be consumed by snapwr. */
      fd_topo_link_t * snapwm_wh =
      fd_topob_link( topo, "snapwm_wh", "snapwm_wr",     64UL, FD_SNAPWM_WR_MTU,                  1UL );
      fd_topob_link( topo, "snapwh_wr", "snapwm_wr",     64UL, 0UL,                               1UL );
      fd_pod_insertf_ulong( topo->props, 8UL, "obj.%lu.app_sz",  snapwm_wh->dcache_obj_id );
    }
    if( snapshot_lthash_disabled ) {
      if( vinyl_enabled ) {
        fd_topob_link( topo, "snapwm_ct", "snapwm_ct",   128UL,   0UL,                            1UL );
      } else {
        fd_topob_link( topo, "snapin_ct", "snapin_ct",   128UL,  0UL,                             1UL );
      }
    } else {
      if( vinyl_enabled ) {
        FOR(snaplh_tile_cnt) fd_topob_link( topo, "snaplh_lv",  "snaplh_lv",    128UL,   sizeof(fd_lthash_value_t),     1UL );
        /**/                 fd_topob_link( topo, "snapwm_lv",  "snapwm_lv",  32768UL, FD_SNAPWM_DUP_META_BATCH_SZ,     1UL );
        /**/                 fd_topob_link( topo, "snaplv_lh",  "snaplv_lh", 262144UL,       FD_SNAPLV_DUP_META_SZ, FD_SNAPLV_STEM_BURST ); /* FD_SNAPWM_DUP_META_BATCH_CNT_MAX times the depth of snapwm_lv */
        /**/                 fd_topob_link( topo, "snaplv_ct",  "snaplv_ct",    128UL,                         0UL,     1UL );
      } else {
        FOR(lta_tile_cnt) fd_topob_link( topo, "snapla_ls",  "snapla_ls",   128UL,  sizeof(fd_lthash_value_t),          1UL );
        /**/              fd_topob_link( topo, "snapin_ls",  "snapin_ls",   256UL,  sizeof(fd_snapshot_full_account_t), 1UL );
        /**/              fd_topob_link( topo, "snapls_ct",  "snapls_ct",   128UL,  0UL,                                1UL );
      }
    }

    if( snapshot_lthash_disabled ) {
      if( vinyl_enabled ) {
        fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapwm_ct",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      } else {
        fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapin_ct",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      }
    } else {
      if( vinyl_enabled ) {
        fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snaplv_ct",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      } else {
        fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapls_ct", 0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED  );
      }
    }

    fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapld_dc",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapct",  0UL,              "snapct_ld",    0UL                                       );
    fd_topob_tile_out( topo, "snapct",  0UL,              "snapct_repr",  0UL                                       );
    fd_topob_tile_in ( topo, "snapld",  0UL, "metric_in", "snapct_ld",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapld",  0UL,              "snapld_dc",    0UL                                       );
    fd_topob_tile_in ( topo, "snapdc",  0UL, "metric_in", "snapld_dc",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapdc",  0UL,              "snapdc_in",    0UL                                       );
    fd_topob_tile_in ( topo, "snapin",  0UL, "metric_in", "snapdc_in",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

    fd_topob_tile_out( topo, "snapin",  0UL,              "snapin_manif", 0UL                                       );
    fd_topob_tile_in ( topo, "replay",  0UL, "metric_in", "snapin_manif", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );

    if( vinyl_enabled ) {
      fd_topob_tile_out( topo, "snapin", 0UL,              "snapin_wm", 0UL );
      fd_topob_tile_in ( topo, "snapwm", 0UL, "metric_in", "snapin_wm", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
      fd_topob_tile_out( topo, "snapin", 0UL,              "snapin_txn",0UL );
      fd_topob_tile_in ( topo, "snapwm", 0UL, "metric_in", "snapin_txn",0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
      fd_topob_tile_out( topo, "snapwm", 0UL,              "snapwm_wh", 0UL );
      fd_topob_tile_in ( topo, "snapwh", 0UL, "metric_in", "snapwm_wh", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
      fd_topob_tile_out( topo, "snapwh", 0UL,              "snapwh_wr", 0UL );
      /* snapwh and snapwr both access snapwm_wh's dcache, avoiding a
         memcpy for every account (vinyl pair) that is being processed
         (loaded) from the snapshot. */
      FOR(snapwr_tile_cnt) fd_topob_tile_in ( topo, "snapwr", i, "metric_in", "snapwh_wr", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
      FOR(snapwr_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapwr", i ) ], &topo->objs[ topo->links[ fd_topo_find_link( topo, "snapwm_wh", 0UL ) ].dcache_obj_id ], FD_SHMEM_JOIN_MODE_READ_ONLY );
    }
    if( snapshot_lthash_disabled ) {
      if( vinyl_enabled ) {
        /**/                fd_topob_tile_out( topo, "snapwm",  0UL,              "snapwm_ct",  0UL                                       );
      } else {
        /**/                fd_topob_tile_out( topo, "snapin", 0UL,               "snapin_ct",  0UL                                       );
      }
    } else {
      if( vinyl_enabled ) {
        FOR(snaplh_tile_cnt) fd_topob_tile_in ( topo, "snaplh", i,   "metric_in", "snapwh_wr",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
        FOR(snaplh_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snaplh", i ) ], &topo->objs[ topo->links[ fd_topo_find_link( topo, "snapwm_wh", 0UL ) ].dcache_obj_id ], FD_SHMEM_JOIN_MODE_READ_ONLY );
        FOR(snaplh_tile_cnt) fd_topob_tile_in ( topo, "snaplh", i,   "metric_in", "snaplv_lh",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
        /**/                 fd_topob_tile_out( topo, "snaplv", 0UL,              "snaplv_lh",  0UL                                       );
        FOR(snaplh_tile_cnt) fd_topob_tile_out( topo, "snaplh", i,                "snaplh_lv",  i                                         );
        /**/                 fd_topob_tile_in ( topo, "snaplv", 0UL, "metric_in", "snapwm_lv",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
        FOR(snaplh_tile_cnt) fd_topob_tile_in ( topo, "snaplv", 0UL, "metric_in", "snaplh_lv",  i,   FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
        /**/                 fd_topob_tile_out( topo, "snaplv", 0UL,              "snaplv_ct",  0UL                                       );
        /**/                 fd_topob_tile_out( topo, "snapwm", 0UL,              "snapwm_lv",  0UL                                       );

        fd_topo_obj_t * vinyl_admin_obj = setup_topo_vinyl_admin( topo, "vinyl_admin" );
        /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapwm", 0UL ) ], vinyl_admin_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
        FOR(snapwr_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapwr", i   ) ], vinyl_admin_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
        /**/                 fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snaplv", 0UL ) ], vinyl_admin_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
        FOR(snaplh_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snaplh", i   ) ], vinyl_admin_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
        FD_TEST( fd_pod_insertf_ulong( topo->props, vinyl_admin_obj->id, "vinyl_admin" ) );
      } else {
        FOR(lta_tile_cnt)    fd_topob_tile_in ( topo, "snapla", i,   "metric_in", "snapdc_in",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
        FOR(lta_tile_cnt)    fd_topob_tile_out( topo, "snapla", i,                "snapla_ls",  i                                         );
        /**/                 fd_topob_tile_in ( topo, "snapls", 0UL, "metric_in", "snapin_ls",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
        FOR(lta_tile_cnt)    fd_topob_tile_in ( topo, "snapls", 0UL, "metric_in", "snapla_ls",  i,   FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
        /**/                 fd_topob_tile_out( topo, "snapls", 0UL,              "snapls_ct",  0UL                                       );
        /**/                 fd_topob_tile_out( topo, "snapin", 0UL,              "snapin_ls",  0UL                                       );
      }
    }
  } else {
    fd_topob_wksp( topo, "genesi_out" );
    fd_topob_link( topo, "genesi_out", "genesi_out", 2UL, 10UL*1024UL*1024UL+32UL+sizeof(fd_lthash_value_t), 1UL );
    fd_topob_tile_out( topo, "genesi", 0UL, "genesi_out", 0UL );
    fd_topob_tile_in ( topo, "replay", 0UL, "metric_in", "genesi_out", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  if( vinyl_enabled ) {
    setup_topo_accdb_meta( topo, &config->firedancer );

    fd_topo_obj_t * accdb_data = setup_topo_accdb_cache( topo, &config->firedancer );

    fd_topob_wksp( topo, "accdb_execrp" );
    fd_topo_tile_t * accdb_tile = fd_topob_tile( topo, "accdb", "accdb_execrp", "metric_in", cpu_idx++, 0, 0 );
    fd_topob_tile_uses( topo, accdb_tile,  accdb_data, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, replay_tile, accdb_data, FD_SHMEM_JOIN_MODE_READ_WRITE );
    for( ulong i=0UL; i<execrp_tile_cnt; i++ ) {
      fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i ) ], accdb_data, FD_SHMEM_JOIN_MODE_READ_WRITE );
    }

    fd_topob_wksp( topo, "accdb_replay" );
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
  fd_topob_wksp( topo, "replay_poh"   );

  fd_topob_link( topo, "replay_epoch", "replay_epoch", 128UL, FD_EPOCH_OUT_MTU, 1UL );
  ulong execle_tile_cnt = config->firedancer.layout.execle_tile_count;
  FOR(execle_tile_cnt) fd_topob_link( topo, "replay_poh", "replay_poh", 128UL, (4096UL*sizeof(fd_txn_p_t))+sizeof(fd_microblock_trailer_t), 1UL );

  fd_topob_tile_out( topo, "replay", 0UL, "replay_epoch",   0UL );
  FOR(execle_tile_cnt) fd_topob_tile_out( topo, "replay", 0UL, "replay_poh", i );

  topo->links[ replay_tile->out_link_id[ fd_topo_find_tile_out_link( topo, replay_tile, "replay_epoch",   0 ) ] ].permit_no_consumers = 1;
  FOR(execle_tile_cnt) topo->links[ replay_tile->out_link_id[ fd_topo_find_tile_out_link( topo, replay_tile, "replay_poh", i ) ] ].permit_no_consumers = 1;

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
  fd_topo_obj_t * store_obj = setup_topo_store( topo, "store", config->firedancer.runtime.max_live_slots * FD_SHRED_BLK_MAX, 1 );
  fd_topob_tile_uses( topo, backt_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, store_obj->id, "store" ) );

  fd_topo_obj_t * acc_pool_obj = setup_topo_acc_pool( topo, config->firedancer.runtime.max_account_cnt );
  fd_topob_tile_uses( topo, replay_tile, acc_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(execrp_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i ) ], acc_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, acc_pool_obj->id, "acc_pool" ) );

  /* banks_obj shared by replay and exec tiles */
  fd_topob_wksp( topo, "banks" );
  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks", config->firedancer.runtime.max_live_slots, config->firedancer.runtime.max_fork_width, 0 );
  fd_topob_tile_uses( topo, replay_tile, banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(execrp_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  /* banks_locks_obj shared by replay and exec tiles */
  fd_topob_wksp( topo, "banks_locks" );
  fd_topo_obj_t * banks_locks_obj = setup_topo_banks_locks( topo, "banks_locks" );
  fd_topob_tile_uses( topo, replay_tile, banks_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(execrp_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i ) ], banks_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_locks_obj->id, "banks_locks" ) );

  /* txncache_obj, busy_obj and poh_slot_obj only by replay tile */
  fd_topob_wksp( topo, "txncache"    );
  fd_topob_wksp( topo, "execle_busy" );
  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "txncache",
      config->firedancer.runtime.max_live_slots,
      fd_ulong_pow2_up( FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT ) );
  fd_topob_tile_uses( topo, replay_tile, txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  if( FD_LIKELY( !disable_snap_loader ) ) {
    fd_topob_tile_uses( topo, snapin_tile, txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    if( vinyl_enabled ) {
      ulong vinyl_map_obj_id  = fd_pod_query_ulong( topo->props, "accdb.meta_map",  ULONG_MAX ); FD_TEST( vinyl_map_obj_id !=ULONG_MAX );
      ulong vinyl_pool_obj_id = fd_pod_query_ulong( topo->props, "accdb.meta_pool", ULONG_MAX ); FD_TEST( vinyl_pool_obj_id!=ULONG_MAX );
      fd_topo_obj_t * vinyl_map_obj  = &topo->objs[ vinyl_map_obj_id ];
      fd_topo_obj_t * vinyl_pool_obj = &topo->objs[ vinyl_pool_obj_id ];
      fd_topob_tile_uses( topo, snapin_tile, vinyl_map_obj,  FD_SHMEM_JOIN_MODE_READ_WRITE );
      fd_topob_tile_uses( topo, snapin_tile, vinyl_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    }
  }
  for( ulong i=0UL; i<execrp_tile_cnt; i++ ) {
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "execrp", i ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }

  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );
  for( ulong i=0UL; i<execle_tile_cnt; i++ ) {
    fd_topo_obj_t * busy_obj = fd_topob_obj( topo, "fseq", "execle_busy" );
    fd_topob_tile_uses( topo, replay_tile, busy_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    FD_TEST( fd_pod_insertf_ulong( topo->props, busy_obj->id, "execle_busy.%lu", i ) );
  }

  if( FD_LIKELY( !disable_snap_loader ) ) {
    fd_topob_tile_uses( topo, snapin_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }

  if( vinyl_enabled ) {
    fd_topob_vinyl_rq( topo, "replay", 0UL, "accdb_replay", "replay", 4UL, 1024UL, 1024UL );
    for( ulong i=0UL; i<execrp_tile_cnt; i++ ) {
      fd_topob_vinyl_rq( topo, "execrp", i, "accdb_execrp", "execrp", 4UL, 1024UL, 1024UL );
    }
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );

    if( !strcmp( tile->name, "replay" ) ) {
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
  if( g_ledger_name[0] != '\0' && !strcmp( g_ledger_name, "all" ) ) {
    return;
  }

  if( g_ledger_name[0] != '\0' && !strcmp( g_ledger_name, "ci" ) ) {
    return;
  }

  if( g_ledger_name[0] != '\0' ) {
    fd_ledger_config_t const * ledger_config = fd_ledger_config_find( g_ledger_name );
    if( ledger_config ) {
      apply_ledger_config( ledger_config, config );
    } else {
      fd_ledger_config_t default_config = {
        .funk_pages = 5UL,
        .index_max = 2000000UL,
        .end_slot = ULONG_MAX,
        .genesis = 0,
        .has_incremental = 0,
        .vinyl = 0,
        .enable_features = { "" },
        .enable_features_cnt = 0UL,
      };
      fd_cstr_ncpy( default_config.test_name, g_ledger_name, sizeof(default_config.test_name) );
      fd_cstr_ncpy( default_config.ledger_name, g_ledger_name, sizeof(default_config.ledger_name) );
      apply_ledger_config( &default_config, config );
    }
  }
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

__attribute__((constructor))
static void
backtest_parse_ledger_name_early( void ) {
  FILE * fp = fopen( "/proc/self/cmdline", "rb" );
  if( !fp ) return;

  char cmdline[4096];
  size_t n = fread( cmdline, 1, sizeof(cmdline) - 1, fp );
  fclose( fp );
  if( n == 0 ) return;
  cmdline[n] = '\0';

  char * argv[256];
  int argc = 0;
  size_t pos = 0;
  while( pos < n && argc < 256 ) {
    argv[argc++] = cmdline + pos;
    while( pos < n && cmdline[pos] != '\0' ) pos++;
    pos++;
  }

  if( argc > 0 ) {
    g_binary_path = argv[0];
  }

  int is_backtest = 0;
  for( int i = 0; i < argc; i++ ) {
    if( !strcmp( argv[i], "--config" ) && (i + 1) < argc ) {
      strncpy( g_config_file, argv[i+1], sizeof(g_config_file) - 1 );
      g_config_file[ sizeof(g_config_file) - 1 ] = '\0';
    }

    if( !strcmp( argv[i], "backtest" ) ) {
      is_backtest = 1;
      if( (i + 1) < argc && argv[i+1] && argv[i+1][0] != '-' ) {
        strncpy( g_ledger_name, argv[i+1], sizeof(g_ledger_name) - 1 );
        g_ledger_name[ sizeof(g_ledger_name) - 1 ] = '\0';
      }
    }

    if( is_backtest ) {
      if( !strcmp( argv[i], "--all" ) ) {
        strncpy( g_ledger_name, "all", sizeof(g_ledger_name) - 1 );
        g_ledger_name[ sizeof(g_ledger_name) - 1 ] = '\0';
      } else if( !strcmp( argv[i], "--ci" ) ) {
        strncpy( g_ledger_name, "ci", sizeof(g_ledger_name) - 1 );
        g_ledger_name[ sizeof(g_ledger_name) - 1 ] = '\0';
      }
    }
  }
}

void
backtest_cmd_args( int *    pargc,
                   char *** pargv,
                   args_t * args ) {
  char const * db         = fd_env_strip_cmdline_cstr( pargc, pargv, "--db", NULL,   "funk"     );
  char const * vinyl_path = fd_env_strip_cmdline_cstr( pargc, pargv, "--vinyl-path", NULL, NULL );
  char const * vinyl_io   = fd_env_strip_cmdline_cstr( pargc, pargv, "--vinyl-io",   NULL, "bd" );

  args->backtest.no_watch = fd_env_strip_cmdline_contains( pargc, pargv, "--no-watch" );

  int is_all = fd_env_strip_cmdline_contains( pargc, pargv, "--all" );
  int is_ci  = fd_env_strip_cmdline_contains( pargc, pargv, "--ci"  );

  if( is_all && is_ci ) {
    FD_LOG_ERR(( "cannot specify both --all and --ci" ));
  }

  if( is_all ) {
    strncpy( g_ledger_name, "all", sizeof(g_ledger_name) - 1 );
    g_ledger_name[ sizeof(g_ledger_name) - 1 ] = '\0';
  } else if( is_ci ) {
    strncpy( g_ledger_name, "ci", sizeof(g_ledger_name) - 1 );
    g_ledger_name[ sizeof(g_ledger_name) - 1 ] = '\0';
  }

  if(      0==strcmp( db, "funk"  ) ) args->backtest.is_vinyl = 0;
  else if( 0==strcmp( db, "vinyl" ) ) args->backtest.is_vinyl = 1;
  else FD_LOG_ERR(( "invalid --db '%s' (must be 'funk' or 'vinyl')", db ));

  fd_cstr_ncpy( args->backtest.vinyl_path, vinyl_path, sizeof(args->backtest.vinyl_path) );

  if( FD_UNLIKELY( strlen( vinyl_io )!=2UL ) ) FD_LOG_ERR(( "invalid --vinyl-io '%s'", vinyl_io ));
  fd_cstr_ncpy( args->backtest.vinyl_io, vinyl_io, sizeof(args->backtest.vinyl_io) );

  if( *pargc > 0 ) {
    char const * ledger_name = (*pargv)[0];
    if( ledger_name && ledger_name[0] != '-' ) {
      if( !is_all && !is_ci ) {
        strncpy( g_ledger_name, ledger_name, sizeof(g_ledger_name) - 1 );
        g_ledger_name[ sizeof(g_ledger_name) - 1 ] = '\0';
      }
      (*pargc)--;
      (*pargv)++;
    }
  }
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
fixup_config( config_t *     config,
              args_t const * args ) {

  if( g_config_file[0] != '\0' ) {
    char const * config_file_path = g_config_file;
    FD_LOG_NOTICE(( "loading custom config from '%s'", config_file_path ));

    char saved_snapshots[PATH_MAX];
    fd_cstr_ncpy( saved_snapshots, config->paths.snapshots, sizeof(saved_snapshots) );
    if( saved_snapshots[0] != '\0' && saved_snapshots[0] != '/' ) {
      char abs_snapshots[PATH_MAX];
      if( realpath( saved_snapshots, abs_snapshots ) ) {
        fd_cstr_ncpy( config->paths.snapshots, abs_snapshots, sizeof(config->paths.snapshots) );
      }
    }

    FILE * fp = fopen( config_file_path, "rb" );
    if( FD_UNLIKELY( !fp ) ) {
      FD_LOG_ERR(( "failed to open config file '%s' (%i-%s)",
                   config_file_path, errno, fd_io_strerror( errno ) ));
    }

    if( FD_UNLIKELY( fseek( fp, 0L, SEEK_END ) ) ) {
      FD_LOG_ERR(( "failed to seek config file '%s' (%i-%s)",
                   config_file_path, errno, fd_io_strerror( errno ) ));
    }
    long file_size = ftell( fp );
    if( FD_UNLIKELY( file_size < 0L ) ) {
      FD_LOG_ERR(( "failed to get size of config file '%s' (%i-%s)",
                   config_file_path, errno, fd_io_strerror( errno ) ));
    }
    rewind( fp );

    char * config_buf = (char *)malloc( (ulong)file_size + 1UL );
    if( FD_UNLIKELY( !config_buf ) ) {
      FD_LOG_ERR(( "failed to allocate memory for config file '%s'", config_file_path ));
    }

    ulong bytes_read = fread( config_buf, 1UL, (ulong)file_size, fp );
    if( FD_UNLIKELY( bytes_read != (ulong)file_size ) ) {
      FD_LOG_ERR(( "failed to read config file '%s' (%i-%s)",
                   config_file_path, errno, fd_io_strerror( errno ) ));
    }
    config_buf[ file_size ] = '\0';
    fclose( fp );

    fd_config_load_buf( config, config_buf, (ulong)file_size, config_file_path );

    free( config_buf );
  }

  if( args->backtest.vinyl_path[0] ) {
    fd_cstr_ncpy( config->paths.accounts, args->backtest.vinyl_path, sizeof(config->paths.accounts) );
  }

  if( args->backtest.is_vinyl ) {
    config->firedancer.vinyl.enabled = 1;

    config->firedancer.vinyl.file_size_gib       = config->firedancer.funk.heap_size_gib * 4UL;
    config->firedancer.vinyl.max_account_records = config->firedancer.funk.max_account_records;

    char const * io_mode = args->backtest.vinyl_io;
    if(      0==strcmp( io_mode, "ur" ) ) config->firedancer.vinyl.io_uring.enabled = 1;
    else if( 0==strcmp( io_mode, "bd" ) ) {}
    else FD_LOG_ERR(( "unsupported --vinyl-io '%s' (valid options are 'bd' and 'ur')", io_mode ));
  }

  /* FIXME Unfortunately, the fdctl boot procedure constructs the
           topology before parsing command-line arguments.  So, here,
           we construct the topology again (a third time ... sigh). */
  backtest_topo( config );
}

static void
run_ledgers( fd_ledger_config_t const * const * ledger_configs,
             ulong                              ledger_count ) {

  ulong passed = 0UL;
  ulong failed = 0UL;

  char const * failed_tests[ 256 ];
  ulong failed_count = 0UL;

  for( ulong i = 0UL; i < ledger_count; i++ ) {
    fd_ledger_config_t const * ledger = ledger_configs[ i ];
    if( !ledger ) {
      FD_LOG_WARNING(( "Ledger config is NULL at index %lu", i ));
      continue;
    }

    FD_LOG_NOTICE(( "[%lu/%lu] Testing: %s", i+1, ledger_count, ledger->test_name ));

    pid_t pid = fork();
    if( pid < 0 ) {
      FD_LOG_ERR(( "fork() failed for ledger %s (%i-%s)", ledger->test_name, errno, fd_io_strerror( errno ) ));
    } else if( pid == 0 ) {
      char const * argv[] = {
        "firedancer-dev",
        "backtest",
        ledger->test_name,
        "--no-watch",
        NULL
      };
      execv( "/proc/self/exe", (char **)argv );
      FD_LOG_ERR(( "execv() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    } else {
      int status;
      if( FD_UNLIKELY( waitpid( pid, &status, 0 ) < 0 ) ) {
        FD_LOG_ERR(( "waitpid() failed for ledger %s (%i-%s)", ledger->test_name, errno, fd_io_strerror( errno ) ));
      }

      if( WIFEXITED( status ) && WEXITSTATUS( status ) == 0 ) {
        FD_LOG_NOTICE(( "PASS: %s", ledger->test_name ));
        passed++;
      } else {
        FD_LOG_WARNING(( "FAIL: %s (exit code: %d)", ledger->test_name, WIFEXITED( status ) ? WEXITSTATUS( status ) : -1 ));
        failed++;
        if( failed_count < 256UL ) {
          failed_tests[ failed_count++ ] = ledger->test_name;
        }
      }
    }
  }

  FD_LOG_NOTICE(( "========================================" ));
  FD_LOG_NOTICE(( "Summary:" ));
  FD_LOG_NOTICE(( "  Passed: %lu", passed ));
  FD_LOG_NOTICE(( "  Failed: %lu", failed ));
  FD_LOG_NOTICE(( "  Total:  %lu", ledger_count ));

  if( failed > 0UL ) {
    FD_LOG_NOTICE(( "Failed tests:" ));
    for( ulong i = 0UL; i < failed_count; i++ ) {
      FD_LOG_NOTICE(( "  - %s", failed_tests[ i ] ));
    }
  }

  FD_LOG_NOTICE(( "========================================" ));

  exit( failed > 0UL ? 1 : 0 );
}

static void
backtest_cmd_fn( args_t *   args,
                 config_t * config ) {
  if( g_ledger_name[0] != '\0' && !strcmp( g_ledger_name, "all" ) ) {
    run_ledgers( fd_ledger_configs, FD_LEDGER_CONFIG_COUNT );
  }

  if( g_ledger_name[0] != '\0' && !strcmp( g_ledger_name, "ci" ) ) {
    run_ledgers( fd_ledger_ci_list, FD_LEDGER_CI_COUNT );
  }

  fixup_config( config, args );
  args_t c_args = configure_args();
  configure_cmd_fn( &c_args, config );

  initialize_workspaces( config );
  initialize_stacks( config );

  fd_log_private_shared_lock[ 1 ] = 0;
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
