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
#include "../../../discof/replay/fd_exec.h"
#include "../../../ballet/lthash/fd_lthash.h"
#include "../../../flamenco/capture/fd_capture_ctx.h"
#include "../../../disco/pack/fd_pack_cost.h"
#include "../../../flamenco/progcache/fd_progcache_admin.h"

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
        fd_topob_wksp( topo, "snaplv_wr" );
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
        /**/                 fd_topob_link( topo, "snaplv_wr",  "snaplv_wr",    128UL,                         0UL,     1UL ); /* no dcache, only mcache fseq is used on this link. */
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
        /**/                 fd_topob_tile_out( topo, "snaplv", 0UL,              "snaplv_wr",  0UL                                       );
        FOR(snapwr_tile_cnt) fd_topob_tile_in ( topo, "snapwr", i,   "metric_in", "snaplv_wr",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
        /**/                 fd_topob_tile_out( topo, "snaplv", 0UL,              "snaplv_ct",  0UL                                       );
        /**/                 fd_topob_tile_out( topo, "snapwm", 0UL,              "snapwm_lv",  0UL                                       );
        FOR(snapwr_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapwr", i ) ], &topo->objs[ topo->links[ fd_topo_find_link( topo, "snaplv_wr", 0UL ) ].mcache_obj_id ], FD_SHMEM_JOIN_MODE_READ_WRITE );
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

    fd_topob_wksp( topo, "accdb_exec" );
    fd_topo_tile_t * accdb_tile = fd_topob_tile( topo, "accdb", "accdb_exec", "metric_in", cpu_idx++, 0, 0 );
    fd_topob_tile_uses( topo, accdb_tile,  accdb_data, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, replay_tile, accdb_data, FD_SHMEM_JOIN_MODE_READ_WRITE );
    for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
      fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], accdb_data, FD_SHMEM_JOIN_MODE_READ_WRITE );
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

  FOR(exec_tile_cnt) fd_topob_link( topo, "exec_replay", "exec_replay", 16384UL, sizeof(fd_exec_task_done_msg_t), 1UL );

  FOR(exec_tile_cnt) fd_topob_tile_out( topo, "exec", i, "exec_replay", i );
  FOR(exec_tile_cnt) fd_topob_tile_in( topo, "replay", 0UL, "metric_in", "exec_replay", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

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
    FOR(exec_tile_cnt) fd_topob_link( topo, "cap_exec", "solcap", 32UL, SOLCAP_WRITE_ACCOUNT_DATA_MTU, 1UL );
    FOR(exec_tile_cnt) fd_topob_tile_out( topo, "exec", i, "cap_exec", i );
    FOR(exec_tile_cnt) fd_topob_tile_in( topo, "solcap", 0UL, "metric_in", "cap_exec", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  fd_topob_wksp( topo, "store" );
  fd_topo_obj_t * store_obj = setup_topo_store( topo, "store", config->firedancer.runtime.max_live_slots * FD_SHRED_BLK_MAX, 1 );
  fd_topob_tile_uses( topo, backt_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, replay_tile, store_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, store_obj->id, "store" ) );

  fd_topo_obj_t * acc_pool_obj = setup_topo_acc_pool( topo, config->firedancer.runtime.max_account_cnt );
  fd_topob_tile_uses( topo, replay_tile, acc_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], acc_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, acc_pool_obj->id, "acc_pool" ) );

  /* banks_obj shared by replay and exec tiles */
  fd_topob_wksp( topo, "banks" );
  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks", config->firedancer.runtime.max_live_slots, config->firedancer.runtime.max_fork_width, 0 );
  fd_topob_tile_uses( topo, replay_tile, banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  /* banks_locks_obj shared by replay and exec tiles */
  fd_topob_wksp( topo, "banks_locks" );
  fd_topo_obj_t * banks_locks_obj = setup_topo_banks_locks( topo, "banks_locks" );
  fd_topob_tile_uses( topo, replay_tile, banks_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(exec_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], banks_locks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_locks_obj->id, "banks_locks" ) );

  /* txncache_obj, busy_obj and poh_slot_obj only by replay tile */
  fd_topob_wksp( topo, "txncache"    );
  fd_topob_wksp( topo, "bank_busy"   );
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
  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "exec", i ) ], txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
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

  if( vinyl_enabled ) {
    fd_topob_vinyl_rq( topo, "replay", 0UL, "accdb_replay", "replay", 4UL, 1024UL, 1024UL );
    for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
      fd_topob_vinyl_rq( topo, "exec", i, "accdb_exec", "exec", 4UL, 1024UL, 1024UL );
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
  backtest_topo( config );
}

extern configure_stage_t fd_cfg_stage_accdb;

static args_t
configure_args( void ) {
  args_t args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  ulong stage_idx = 0UL;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_hugetlbfs;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_snapshots;
  args.configure.stages[ stage_idx++ ] = &fd_cfg_stage_accdb;
  args.configure.stages[ stage_idx++ ] = NULL;

  return args;
}

void
backtest_cmd_args( int *    pargc,
                   char *** pargv,
                   args_t * args ) {
  char const * db         = fd_env_strip_cmdline_cstr( pargc, pargv, "--db", NULL,   "funk"     );
  char const * vinyl_path = fd_env_strip_cmdline_cstr( pargc, pargv, "--vinyl-path", NULL, NULL );
  char const * vinyl_io   = fd_env_strip_cmdline_cstr( pargc, pargv, "--vinyl-io",   NULL, "bd" );

  args->backtest.no_watch = fd_env_strip_cmdline_contains( pargc, pargv, "--no-watch" );

  if(      0==strcmp( db, "funk"  ) ) args->backtest.is_vinyl = 0;
  else if( 0==strcmp( db, "vinyl" ) ) args->backtest.is_vinyl = 1;
  else FD_LOG_ERR(( "invalid --db '%s' (must be 'funk' or 'vinyl')", db ));

  fd_cstr_ncpy( args->backtest.vinyl_path, vinyl_path, sizeof(args->backtest.vinyl_path) );

  if( FD_UNLIKELY( strlen( vinyl_io )!=2UL ) ) FD_LOG_ERR(( "invalid --vinyl-io '%s'", vinyl_io ));
  fd_cstr_ncpy( args->backtest.vinyl_io, vinyl_io, sizeof(args->backtest.vinyl_io) );
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
  if( args->backtest.vinyl_path[0] ) {
    fd_cstr_ncpy( config->paths.accounts, args->backtest.vinyl_path, sizeof(config->paths.accounts) );
  }

  if( args->backtest.is_vinyl ) {
    config->firedancer.vinyl.enabled = 1;

    config->firedancer.vinyl.file_size_gib       = config->firedancer.funk.heap_size_gib;
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
backtest_cmd_fn( args_t *   args,
                 config_t * config ) {
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
