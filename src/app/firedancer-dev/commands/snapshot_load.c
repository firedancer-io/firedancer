#include "../../firedancer/topology.h"
#include "../../platform/fd_sys_util.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../shared_dev/commands/dev.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/pack/fd_pack.h"
#include "../../../disco/pack/fd_pack_cost.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../discof/restore/utils/fd_ssctrl.h"
#include "../../../discof/restore/utils/fd_ssmsg.h"
#include "../../../flamenco/accdb/fd_accdb_fsck.h"
#include "../../../funk/fd_funk.h"
#include "../../../vinyl/fd_vinyl.h"
#include "../../../tango/cnc/fd_cnc.h"
#include "../../../ballet/lthash/fd_lthash.h"

#include <errno.h>
#include <fcntl.h> /* open */
#include <sys/resource.h>
#include <linux/capability.h>
#include <unistd.h> /* close, sleep */
#include <stdio.h>

#define NAME "snapshot-load"

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
snapshot_load_topo( config_t * config,
                    _Bool      vinyl_server ) {
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "txncache" );
  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "txncache",
      config->firedancer.runtime.max_live_slots,
      fd_ulong_pow2_up( FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );

  fd_topob_wksp( topo, "funk" );
  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions,
      config->firedancer.funk.heap_size_gib );

  int snapshot_lthash_disabled = config->development.snapshots.disable_lthash_verification;
  ulong lta_tile_cnt           = config->firedancer.layout.snapla_tile_count;

  if( config->firedancer.vinyl.enabled ) {
    setup_topo_vinyl_meta( topo, &config->firedancer );
  }

  if( vinyl_server ) {
    /* Create a workspace with 512 MiB of free space for clients to
       create objects in. */
    fd_topo_wksp_t * server_wksp = fd_topob_wksp( topo, "vinyl_server" );
    server_wksp->min_part_max = 64UL;
    server_wksp->min_loose_sz = 64UL<<20;
  }

#define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /* metrics tile *****************************************************/
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "metric" );
  fd_topob_tile( topo, "metric",  "metric", "metric_in", ULONG_MAX, 0, 0 );

  /* read() tile */
  fd_topob_wksp( topo, "snapct" );
  fd_topo_tile_t * snapct_tile = fd_topob_tile( topo, "snapct", "snapct", "metric_in", ULONG_MAX, 0, 0 );
  snapct_tile->allow_shutdown = 1;

  /* load tile */
  fd_topob_wksp( topo, "snapld" );
  fd_topo_tile_t * snapld_tile = fd_topob_tile( topo, "snapld", "snapld", "metric_in", ULONG_MAX, 0, 0 );
  snapld_tile->allow_shutdown = 1;

  /* "snapdc": Zstandard decompress tile */
  fd_topob_wksp( topo, "snapdc" );
  fd_topo_tile_t * snapdc_tile = fd_topob_tile( topo, "snapdc", "snapdc", "metric_in", ULONG_MAX, 0, 0 );
  snapdc_tile->allow_shutdown = 1;

  /* "snapin": Snapshot parser tile */
  fd_topob_wksp( topo, "snapin" );
  fd_topo_tile_t * snapin_tile = fd_topob_tile( topo, "snapin", "snapin", "metric_in", ULONG_MAX, 0, 0 );
  snapin_tile->allow_shutdown = 1;

  /* "snapwr": Snapshot writer tile */
  ulong snapwr_cnt = 2;
  int vinyl_enabled = config->firedancer.vinyl.enabled;
  if( vinyl_enabled ) {

    fd_topob_wksp( topo, "snapwm" );
    fd_topo_tile_t * snapwm_tile = fd_topob_tile( topo, "snapwm", "snapwm", "metric_in", ULONG_MAX, 0, 0 );
    snapwm_tile->allow_shutdown = 1;

    fd_topob_wksp( topo, "snapwh" );
    fd_topo_tile_t * snapwh_tile = fd_topob_tile( topo, "snapwh", "snapwh", "metric_in", ULONG_MAX, 0, 0 );
    snapwh_tile->allow_shutdown = 1;

    fd_topob_wksp( topo, "snapwr" );
    FOR(snapwr_cnt) fd_topob_tile( topo, "snapwr", "snapwr", "metric_in", ULONG_MAX, 0, 0 )->allow_shutdown = 1;
  }

  fd_topob_wksp( topo, "snapct_ld"    );
  fd_topob_wksp( topo, "snapld_dc"    );
  fd_topob_wksp( topo, "snapdc_in"    );

  fd_topob_wksp( topo, "snapin_manif" );
  fd_topob_wksp( topo, "snapct_repr"  );
  if( vinyl_enabled ) {
    fd_topob_wksp( topo, "snapin_txn");
    fd_topob_wksp( topo, "snapin_wm" );
    fd_topob_wksp( topo, "snapwm_wr" );
    if( FD_UNLIKELY( snapshot_lthash_disabled ) ) {
      fd_topob_wksp( topo, "snapwm_ct" );
    } else {
      /* TODO pending */
    }
  } else {
    if( FD_UNLIKELY( snapshot_lthash_disabled ) ) {
      fd_topob_wksp( topo, "snapin_ct" );
    } else {
      fd_topob_wksp( topo, "snapla"    );
      fd_topob_wksp( topo, "snapls"    );
      fd_topob_wksp( topo, "snapla_ls" );
      fd_topob_wksp( topo, "snapin_ls" );
      fd_topob_wksp( topo, "snapls_ct" );
    }
  }

  if( FD_LIKELY( !snapshot_lthash_disabled ) ) {
    FOR(lta_tile_cnt)  fd_topob_tile( topo, "snapla", "snapla", "metric_in", ULONG_MAX, 0, 0 )->allow_shutdown = 1;
    /**/               fd_topob_tile( topo, "snapls", "snapls", "metric_in", ULONG_MAX, 0, 0 )->allow_shutdown = 1;
  }

  fd_topob_link( topo, "snapct_ld",   "snapct_ld",     128UL,   sizeof(fd_ssctrl_init_t),       1UL );
  fd_topob_link( topo, "snapld_dc",   "snapld_dc",     16384UL, USHORT_MAX,                     1UL );
  fd_topob_link( topo, "snapdc_in",   "snapdc_in",     16384UL, USHORT_MAX,                     1UL );
  fd_topob_link( topo, "snapin_manif", "snapin_manif", 4UL,     sizeof(fd_snapshot_manifest_t), 1UL )->permit_no_consumers = 1;
  fd_topob_link( topo, "snapct_repr", "snapct_repr",   128UL,   0UL,                            1UL )->permit_no_consumers = 1;
  if( vinyl_enabled ) {
    if( FD_LIKELY( snapshot_lthash_disabled ) ) {
      fd_topob_link( topo, "snapwm_ct", "snapwm_ct",   128UL,   0UL,                            1UL );
    } else {
      /* TODO pending */
    }
    fd_topob_link( topo, "snapin_txn", "snapin_txn",    4UL,   (ulong)((3764697600UL+64UL)/4),  1UL ); /* mtu=(sizeof(fd_sstxncache_entry_t)*(FD_SNAPIN_TXNCACHE_MAX_ENTRIES+1UL))/depth */
    fd_topob_link( topo, "snapin_wm", "snapin_wm",     16UL,   128UL<<20,                       1UL ); /* FD_SSPARSE_ACC_BATCH_MAX * 16<<20 */
    fd_topo_link_t * snapwm_wh =
    fd_topob_link( topo, "snapwm_wh", "snapwm_wr",     16UL,    16UL<<20,                       1UL );
    fd_topob_link( topo, "snapwh_wr", "snapwm_wr",     16UL,    0UL,                            1UL );
    fd_pod_insertf_ulong( topo->props, 8UL, "obj.%lu.app_sz",  snapwm_wh->dcache_obj_id );
  } else {
    if( FD_LIKELY( snapshot_lthash_disabled ) ) {
      fd_topob_link( topo, "snapin_ct", "snapin_ct",   128UL,  0UL,                             1UL );
    } else {
      FOR(lta_tile_cnt) fd_topob_link( topo, "snapla_ls",  "snapla_ls",   128UL,  sizeof(fd_lthash_value_t),          1UL );
      /**/              fd_topob_link( topo, "snapin_ls",  "snapin_ls",   256UL,  sizeof(fd_snapshot_full_account_t), 1UL );
      /**/              fd_topob_link( topo, "snapls_ct",  "snapls_ct",   128UL,  0UL,                                1UL );
    }
  }

  if( vinyl_enabled ) {
    if( FD_UNLIKELY( snapshot_lthash_disabled ) ) {
      fd_topob_tile_out( topo, "snapwm",  0UL,              "snapwm_ct",  0UL                                       );
      fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapwm_ct",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
    } else {
      /* TODO pending */
    }
  } else {
    if( FD_UNLIKELY( snapshot_lthash_disabled ) ) {
      fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapin_ct",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
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
  if( vinyl_enabled ) {
    if( FD_LIKELY( !snapshot_lthash_disabled ) ) {
      /* TODO pending */
    }
    fd_topob_tile_out( topo, "snapin", 0UL,              "snapin_wm", 0UL );
    fd_topob_tile_in ( topo, "snapwm", 0UL, "metric_in", "snapin_wm", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapin", 0UL,              "snapin_txn",0UL );
    fd_topob_tile_in ( topo, "snapwm", 0UL, "metric_in", "snapin_txn",0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapwm", 0UL,              "snapwm_wh", 0UL );
    fd_topob_tile_in ( topo, "snapwh", 0UL, "metric_in", "snapwm_wh", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapwh", 0UL,              "snapwh_wr", 0UL );
    FOR(snapwr_cnt) fd_topob_tile_in ( topo, "snapwr", i, "metric_in", "snapwh_wr", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    FOR(snapwr_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapwr", i ) ], &topo->objs[ topo->links[ fd_topo_find_link( topo, "snapwm_wh", 0UL ) ].dcache_obj_id ], FD_SHMEM_JOIN_MODE_READ_ONLY );

  } else {
    if( FD_LIKELY( !snapshot_lthash_disabled ) ) {
      FOR(lta_tile_cnt) fd_topob_tile_in ( topo, "snapla", i,   "metric_in", "snapdc_in",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      FOR(lta_tile_cnt) fd_topob_tile_out( topo, "snapla", i,                "snapla_ls",  i                                         );
      /**/              fd_topob_tile_in ( topo, "snapls", 0UL, "metric_in", "snapin_ls",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      FOR(lta_tile_cnt) fd_topob_tile_in ( topo, "snapls", 0UL, "metric_in", "snapla_ls",  i,   FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
      /**/              fd_topob_tile_out( topo, "snapls", 0UL,              "snapls_ct",  0UL                                       );
    }
    if( FD_UNLIKELY( snapshot_lthash_disabled ) ) {
      fd_topob_tile_out( topo, "snapin", 0UL,           "snapin_ct",    0UL                                       );
    } else {
      fd_topob_tile_out( topo, "snapin", 0UL,           "snapin_ls",   0UL                                       );
    }
  }

  /* snapin funk / txncache access */
  fd_topob_tile_uses( topo, snapin_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, snapin_tile, txncache_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  snapin_tile->snapin.funk_obj_id     = funk_obj->id;
  snapin_tile->snapin.txncache_obj_id = txncache_obj->id;
  if( config->firedancer.vinyl.enabled ) {
    ulong vinyl_map_obj_id  = fd_pod_query_ulong( topo->props, "vinyl.meta_map",  ULONG_MAX ); FD_TEST( vinyl_map_obj_id !=ULONG_MAX );
    ulong vinyl_pool_obj_id = fd_pod_query_ulong( topo->props, "vinyl.meta_pool", ULONG_MAX ); FD_TEST( vinyl_pool_obj_id!=ULONG_MAX );

    fd_topo_obj_t * vinyl_map_obj  = &topo->objs[ vinyl_map_obj_id ];
    fd_topo_obj_t * vinyl_pool_obj = &topo->objs[ vinyl_pool_obj_id ];

    fd_topob_tile_uses( topo, snapin_tile, vinyl_map_obj,  FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, snapin_tile, vinyl_pool_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }

  snapin_tile->snapin.max_live_slots  = config->firedancer.runtime.max_live_slots;

  if( vinyl_server ) {
    /* Allocate a public CNC, which allows the vinyl tile to map memory
       allocated by other clients.  This is useful for flexibility
       during development, but not something we'd run in production due
       to security concerns. */
    fd_topo_obj_t * vinyl_cnc = fd_topob_obj( topo, "cnc", "vinyl_server" );
    fd_pod_insertf_ulong( topo->props, FD_VINYL_CNC_APP_SZ, "obj.%lu.app_sz", vinyl_cnc->id );
    fd_pod_insertf_ulong( topo->props, FD_VINYL_CNC_TYPE,   "obj.%lu.type",   vinyl_cnc->id );
    fd_pod_insert_ulong ( topo->props, "vinyl.cnc", vinyl_cnc->id );

    fd_topo_obj_t * vinyl_data = setup_topo_vinyl_cache( topo, &config->firedancer );

    fd_topob_wksp( topo, "vinyl_exec" );
    fd_topo_tile_t * vinyl_tile = fd_topob_tile( topo, "vinyl", "vinyl_exec", "metric_in", ULONG_MAX, 0, 0 );

    fd_topob_tile_uses( topo, vinyl_tile, vinyl_cnc,  FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, vinyl_tile, vinyl_data, FD_SHMEM_JOIN_MODE_READ_WRITE );

    fd_topob_tile_in( topo, "vinyl", 0UL, "metric_in", "snapin_manif", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
}

static void
snapshot_load_topo1( config_t * config ) {
  snapshot_load_topo( config, 0 );
}

extern int * fd_log_private_shared_lock;

static void
snapshot_load_args( int *    pargc,
                    char *** pargv,
                    args_t * args ) {
  if( FD_UNLIKELY( fd_env_strip_cmdline_contains( pargc, pargv, "--help" ) ) ) {
    fputs(
      "\nUsage: firedancer-dev snapshot-load [GLOBAL FLAGS] [FLAGS]\n"
      "\n"
      "Global Flags:\n"
      "  --mainnet            Use Solana mainnet-beta defaults\n"
      "  --testnet            Use Solana testnet defaults\n"
      "  --devnet             Use Solana devnet defaults\n"
      "\n"
      "Flags:\n"
      "  --snapshot-dir PATH  Load/save snapshots from this directory\n"
      "  --offline            Do not attempt to download snapshots\n"
      "  --no-incremental     Disable incremental snapshot loading\n"
      "  --no-watch           Do not print periodic progress updates\n"
      "  --db <funk/vinyl>    Database engine\n"
      "  --db-sz <bytes>      Database size in bytes (e.g. 10e9 -> 10 GB)\n"
      "  --db-rec-max <num>   Database max record/account count (e.g. 10e6 -> 10M accounts)\n"
      "  --fsck               After loading, run database integrity checks\n"
      "  --lthash             After loading, recompute the account DB lthash\n"
      "  --accounts-hist      After loading, analyze account size distribution\n"
      "\n"
      "Vinyl database flags:\n"
      "  --vinyl-server         After loading, indefinitely run a vinyl DB server\n"
      "  --vinyl-path <path>    Path to vinyl bstream file (overrides existing files!)\n"
      "  --vinyl-io <backend>   Vinyl I/O backend (default: bd)\n"
      "  --cache-sz <bytes>     DB cache size in bytes (e.g. 1e9 -> 1 GB)\n"
      "  --cache-rec-max <num>  DB cache max entry count (e.g. 1e6 -> 1M cache entries)\n"
      "\n"
      "Vinyl I/O backends:\n"
      "  bd  readv/writev-style single-threaded blocking I/O\n"
      "  mm  Memory-mapped I/O\n"
      "\n",
      stderr );
    exit( 0 );
  }
  memset( &args->snapshot_load, 0, sizeof(args->snapshot_load) );

  char const * snapshot_dir  = fd_env_strip_cmdline_cstr    ( pargc, pargv, "--snapshot-dir", NULL, NULL   );
  _Bool        offline       = fd_env_strip_cmdline_contains( pargc, pargv, "--offline"                    )!=0;
  _Bool        no_incremental= fd_env_strip_cmdline_contains( pargc, pargv, "--no-incremental"             )!=0;
  _Bool        no_watch      = fd_env_strip_cmdline_contains( pargc, pargv, "--no-watch"                   )!=0;
  char const * db            = fd_env_strip_cmdline_cstr    ( pargc, pargv, "--db",           NULL, "funk" );
  float        db_sz         = fd_env_strip_cmdline_float   ( pargc, pargv, "--db-sz",        NULL, 0.0f   );
  float        db_rec_max    = fd_env_strip_cmdline_float   ( pargc, pargv, "--db-rec-max",   NULL, 0.0f   );
  _Bool        fsck          = fd_env_strip_cmdline_contains( pargc, pargv, "--fsck"                       )!=0;
  _Bool        fsck_lthash   = fd_env_strip_cmdline_contains( pargc, pargv, "--fsck-lthash"                )!=0;
  _Bool        lthash        = fd_env_strip_cmdline_contains( pargc, pargv, "--lthash"                     )!=0;
  _Bool        accounts_hist = fd_env_strip_cmdline_contains( pargc, pargv, "--accounts-hist"              )!=0;
  _Bool        vinyl_server  = fd_env_strip_cmdline_contains( pargc, pargv, "--vinyl-server"               )!=0;
  char const * vinyl_path    = fd_env_strip_cmdline_cstr    ( pargc, pargv, "--vinyl-path",   NULL, NULL   );
  char const * vinyl_io      = fd_env_strip_cmdline_cstr    ( pargc, pargv, "--vinyl-io",     NULL, "bd"   );
  float        cache_sz      = fd_env_strip_cmdline_float   ( pargc, pargv, "--cache-sz",     NULL, 0.0f   );
  float        cache_rec_max = fd_env_strip_cmdline_float   ( pargc, pargv, "--cache-rec-max",NULL, 0.0f   );

  fd_cstr_ncpy( args->snapshot_load.snapshot_dir, snapshot_dir, sizeof(args->snapshot_load.snapshot_dir) );
  args->snapshot_load.fsck           = fsck;
  args->snapshot_load.fsck_lthash    = fsck_lthash;
  args->snapshot_load.lthash         = lthash;
  args->snapshot_load.accounts_hist  = accounts_hist;
  args->snapshot_load.offline        = offline;
  args->snapshot_load.no_incremental = no_incremental;
  args->snapshot_load.no_watch       = no_watch;
  args->snapshot_load.vinyl_server   = !!vinyl_server;

  if(      0==strcmp( db, "funk"  ) ) args->snapshot_load.is_vinyl = 0;
  else if( 0==strcmp( db, "vinyl" ) ) args->snapshot_load.is_vinyl = 1;
  else FD_LOG_ERR(( "invalid --db '%s' (must be 'funk' or 'vinyl')", db ));

  args->snapshot_load.db_sz         = (ulong)db_sz;
  args->snapshot_load.db_rec_max    = (ulong)db_rec_max;
  args->snapshot_load.cache_sz      = (ulong)cache_sz;
  args->snapshot_load.cache_rec_max = (ulong)cache_rec_max;

  fd_cstr_ncpy( args->snapshot_load.vinyl_path, vinyl_path, sizeof(args->snapshot_load.vinyl_path) );

  if( FD_UNLIKELY( strlen( vinyl_io )!=2UL ) ) FD_LOG_ERR(( "invalid --vinyl-io '%s'", vinyl_io ));
  fd_cstr_ncpy( args->snapshot_load.vinyl_io, vinyl_io, sizeof(args->snapshot_load.vinyl_io) );
}

static uint
fsck_funk( config_t * config,
           _Bool      lthash ) {
  ulong funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );
  FD_TEST( funk_obj_id!=ULONG_MAX );
  void * funk_shmem = fd_topo_obj_laddr( &config->topo, funk_obj_id );
  fd_funk_t funk[1];
  FD_TEST( fd_funk_join( funk, funk_shmem ) );
  uint fsck_err = fd_accdb_fsck_funk( funk, lthash ? FD_ACCDB_FSCK_FLAGS_LTHASH : 0U );
  FD_TEST( fd_funk_leave( funk, NULL ) );
  return fsck_err;
}

static uint
fsck_vinyl( config_t * config,
           _Bool       lthash ) {
  /* Join meta index */

  fd_topo_t * topo = &config->topo;
  ulong meta_map_id  = fd_pod_query_ulong( topo->props, "vinyl.meta_map",  ULONG_MAX );
  ulong meta_pool_id = fd_pod_query_ulong( topo->props, "vinyl.meta_pool", ULONG_MAX );
  FD_TEST( meta_map_id!=ULONG_MAX && meta_pool_id!=ULONG_MAX );
  void * shmap = fd_topo_obj_laddr( topo, meta_map_id  );
  void * shele = fd_topo_obj_laddr( topo, meta_pool_id );
  fd_vinyl_meta_t meta[1];
  FD_TEST( fd_vinyl_meta_join( meta, shmap, shele ) );

  /* Join bstream */

  int dev_fd = open( config->paths.accounts, O_RDWR|O_CLOEXEC );
  if( FD_UNLIKELY( dev_fd<0 ) ) {
    FD_LOG_ERR(( "open(%s,O_RDWR|O_CLOEXEC) failed (%i-%s)",
                 config->paths.accounts, errno, fd_io_strerror( errno ) ));
  }
  void * mmio    = NULL;
  ulong  mmio_sz = 0UL;
  int map_err = fd_io_mmio_init( dev_fd, FD_IO_MMIO_MODE_READ_WRITE, &mmio, &mmio_sz );
  if( FD_UNLIKELY( map_err ) ) {
    FD_LOG_ERR(( "fd_io_mmio_init(%s,rw) failed (%i-%s)",
                 config->paths.accounts, map_err, fd_io_strerror( map_err ) ));
  }
  FD_TEST( 0==close( dev_fd ) );
  ulong  io_spad_max = 1UL<<20;
  void * io_mm       = aligned_alloc( fd_vinyl_io_mm_align(), fd_vinyl_io_mm_footprint( io_spad_max ) );
  FD_TEST( io_mm );
  fd_vinyl_io_t * io = fd_vinyl_io_mm_init( io_mm, io_spad_max, mmio, mmio_sz, 0, NULL, 0UL, 0UL );
  FD_TEST( io );

  /* Run verifier */

  uint fsck_err = fd_accdb_fsck_vinyl( io, meta, lthash ? FD_ACCDB_FSCK_FLAGS_LTHASH : 0U );

  /* Clean up */

  FD_TEST( fd_vinyl_io_fini( io ) );
  free( io_mm );
  fd_io_mmio_fini( mmio, mmio_sz );
  fd_vinyl_meta_leave( meta );
  return fsck_err;
}

/* ACCOUNTS_HIST_N (32) is chosen to make the histogram lightweight.
   And because accounts can have a data size in the range [0, 10MiB],
   the width of the bins increments in powers of 2.  In the future, it
   should be possible to pass this as a configuration parameter. */
#define ACCOUNTS_HIST_N (32)

struct accounts_hist {
  ulong total_cnt;
  ulong total_acc;
  ulong bin_thi[ ACCOUNTS_HIST_N ];
  ulong bin_cnt[ ACCOUNTS_HIST_N ];
  ulong bin_acc[ ACCOUNTS_HIST_N ];
  ulong bin_min[ ACCOUNTS_HIST_N ];
  ulong bin_max[ ACCOUNTS_HIST_N ];
  ulong token_cnt;
};
typedef struct accounts_hist accounts_hist_t;

static inline void
accounts_hist_reset( accounts_hist_t * hist ) {
  hist->total_cnt = 0UL;
  hist->total_acc = 0UL;
  for( int i=0; i < ACCOUNTS_HIST_N; i++ ) {
    hist->bin_thi[ i ] = fd_ulong_if( i > 0, fd_pow2( ulong, i-1 ), 0UL );
    hist->bin_cnt[ i ] = 0UL;
    hist->bin_acc[ i ] = 0UL;
    hist->bin_min[ i ] = ULONG_MAX;
    hist->bin_max[ i ] = 0UL;
  }
  hist->token_cnt = 0UL;
}

static inline void
accounts_hist_update( accounts_hist_t * hist,
                      ulong             account_sz ) {
  hist->total_cnt += 1UL;
  hist->total_acc += account_sz;
  int i=0;
  /* This allows for arbitrary thresholds - not optimized for pow2
     bins. */
  for( ; i < ACCOUNTS_HIST_N; i++ ) {
    if( FD_UNLIKELY( account_sz <= hist->bin_thi[ i ] )) {
      hist->bin_cnt[ i ] += 1;
      hist->bin_acc[ i ] += account_sz;
      hist->bin_min[ i ] = fd_ulong_min( hist->bin_min[ i ], account_sz );
      hist->bin_max[ i ] = fd_ulong_max( hist->bin_max[ i ], account_sz );
      break;
    }
  }
  FD_TEST( i < ACCOUNTS_HIST_N );
}

static inline int
accounts_hist_check( accounts_hist_t const * hist ) {
  ulong cnt = 0UL;
  ulong acc = 0UL;
  for( int i=0; i < ACCOUNTS_HIST_N; i++ ) {
    cnt += hist->bin_cnt[ i ];
    acc += hist->bin_acc[ i ];
  }
  if( cnt != hist->total_cnt ) return -1;
  if( acc != hist->total_acc ) return -2;
  return 0;
}

static void
accounts_hist_print( accounts_hist_t const * hist ) {
  double hist_total_cnt_M   = (double)hist->total_cnt / (double)1.0e6;
  double hist_total_cnt_GiB = (double)hist->total_acc / (double)1073741824;
  printf( "\n" );
  printf( "hist_total_cnt %16lu ( %6.1f M   )\n", hist->total_cnt, hist_total_cnt_M   );
  printf( "hist_total_acc %16lu ( %6.1f GiB )\n", hist->total_acc, hist_total_cnt_GiB );
  printf( "   bin_th_lo <  sz <=    bin_th_hi |    bin_cnt (run_sum%%) |      bin_acc (run_sum%%) |    bin_min B |    bin_max B |    bin_avg B |\n" );
  ulong sum_cnt = 0UL;
  ulong sum_acc = 0UL;
  for( int i=0; i < ACCOUNTS_HIST_N; i++ ) {
    /* bin thresholds */
    ulong hist_bin_tlo      = hist->bin_thi[ fd_int_if( i>0, i-1, i ) ];
    ulong hist_bin_thi      = hist->bin_thi[ i ];
    /* bin cnt */
    ulong hist_bin_cnt      = hist->bin_cnt[ i ];
    sum_cnt                += hist->bin_cnt[ i ];
    double sum_cnt_p        = (double)(sum_cnt * 100) / (double)hist->total_cnt;
    double hist_bin_cnt_K   = (double)(hist_bin_cnt) / (double)1.0e3;
    /* bin acc */
    ulong hist_bin_acc      = hist->bin_acc[ i ];
    sum_acc                += hist->bin_acc[ i ];
    double sum_acc_p        = (double)(sum_acc * 100) / (double)hist->total_acc;
    double hist_bin_acc_MiB = (double)(hist_bin_acc) / (double)1048576.0f;
    /* bin min, max, avg */
    ulong hist_bin_min      = fd_ulong_if( hist->bin_cnt[ i ] > 0, hist->bin_min[ i ], 0UL );
    ulong hist_bin_max      = hist->bin_max[ i ];
    ulong hist_bin_avg      = fd_ulong_if( hist->bin_cnt[ i ] > 0, hist->bin_acc[ i ] / hist->bin_cnt[ i ], 0UL );
    /* log */
    char buf[256];
    char * p = fd_cstr_init( buf );
    p = fd_cstr_append_printf( p, "%12lu %s sz <= %12lu |", hist_bin_tlo, i==0? "<=" : "< ", hist_bin_thi );
    p = fd_cstr_append_printf( p, " %8.1f K (%6.1f %%) |", hist_bin_cnt_K, sum_cnt_p );
    p = fd_cstr_append_printf( p, " %8.1f MiB (%6.1f %%) |", hist_bin_acc_MiB, sum_acc_p );
    p = fd_cstr_append_printf( p, " %12lu | %12lu | %12lu |", hist_bin_min, hist_bin_max, hist_bin_avg );
    p = fd_cstr_append_printf( p, "\n" );
    printf( "%s", buf );
  }
  printf( "\n" );
}

static void
accounts_hist_vinyl( accounts_hist_t * hist,
                     config_t *        config ) {
  fd_topo_t * topo = &config->topo;
  ulong meta_map_id  = fd_pod_query_ulong( topo->props, "vinyl.meta_map",  ULONG_MAX );
  ulong meta_pool_id = fd_pod_query_ulong( topo->props, "vinyl.meta_pool", ULONG_MAX );
  FD_TEST( meta_map_id!=ULONG_MAX && meta_pool_id!=ULONG_MAX );
  void * shmap = fd_topo_obj_laddr( topo, meta_map_id  );
  void * shele = fd_topo_obj_laddr( topo, meta_pool_id );
  fd_vinyl_meta_t meta[1];
  FD_TEST( fd_vinyl_meta_join( meta, shmap, shele ) );

  for( ulong ele_i=0; ele_i < fd_vinyl_meta_ele_max( meta ); ele_i++ ) {
    fd_vinyl_meta_ele_t const * ele = meta->ele + ele_i;
    if( FD_UNLIKELY( fd_vinyl_meta_private_ele_is_free( meta->ctx, ele ) ) ) continue;
    accounts_hist_update( hist, (ulong)ele->phdr.info.val_sz );
  }
}

static void
accounts_hist_funk( accounts_hist_t * hist,
                    config_t *        config ) {
  fd_topo_t * topo = &config->topo;
  ulong funk_obj_id = fd_pod_query_ulong( topo->props, "funk", ULONG_MAX );
  FD_TEST( funk_obj_id!=ULONG_MAX );
  void * funk_shmem = fd_topo_obj_laddr( topo, funk_obj_id );
  fd_funk_t funk[1];
  FD_TEST( fd_funk_join( funk, funk_shmem ) );

  fd_funk_rec_map_t const * rec_map = funk->rec_map;
  fd_funk_rec_t const * ele = rec_map->ele;
  fd_funk_rec_map_shmem_private_chain_t const * chain = fd_funk_rec_map_shmem_private_chain_const( rec_map->map, 0UL );
  ulong chain_cnt = fd_funk_rec_map_chain_cnt( rec_map );
  for( ulong chain_i=0UL; chain_i < chain_cnt; chain_i++ ) {
    ulong ver_cnt = chain[ chain_i ].ver_cnt;
    ulong ele_cnt = fd_funk_rec_map_private_vcnt_cnt( ver_cnt );
    ulong head_i  = fd_funk_rec_map_private_idx( chain[ chain_i ].head_cidx );
    ulong ele_i   = head_i;
    for( ulong ele_rem=ele_cnt; ele_rem; ele_rem-- ) {
      fd_funk_xid_key_pair_t const * pair = &ele[ ele_i ].pair;
      fd_funk_rec_query_t query[1];
      fd_funk_rec_t * rec = fd_funk_rec_query_try( funk, pair->xid, pair->key, query );
      FD_TEST( !!rec );
      fd_account_meta_t * meta = fd_funk_val( rec, funk->wksp );
      FD_TEST( !!meta );
      accounts_hist_update( hist, sizeof(fd_account_meta_t) + meta->dlen );
    }
  }
}

/* fixup_config applies command-line arguments to config, overriding
   defaults / config file */

static void
fixup_config( config_t *     config,
              args_t const * args ) {
  fd_topo_t * topo = &config->topo;
  if( args->snapshot_load.snapshot_dir[0] ) {
    fd_cstr_ncpy( config->paths.snapshots, args->snapshot_load.snapshot_dir, sizeof(config->paths.snapshots) );
  }

  if( args->snapshot_load.vinyl_path[0] ) {
    fd_cstr_ncpy( config->paths.accounts, args->snapshot_load.vinyl_path, sizeof(config->paths.accounts) );
  }

  if( args->snapshot_load.db_rec_max ) {
    config->firedancer.funk.max_account_records = args->snapshot_load.db_rec_max;
  }

  if( args->snapshot_load.db_sz ) {
    config->firedancer.funk.heap_size_gib = fd_ulong_align_up( args->snapshot_load.db_sz, (1UL<<30) )>>30;
  }

  if( args->snapshot_load.cache_sz ) {
    config->firedancer.vinyl.cache_size_gib = fd_ulong_align_up( args->snapshot_load.cache_sz, (1UL<<30) )>>30;
  }

  if( args->snapshot_load.cache_rec_max ) {
    config->firedancer.vinyl.max_cache_entries = args->snapshot_load.cache_rec_max;
  }

  if( args->snapshot_load.is_vinyl ) {
    config->firedancer.vinyl.enabled = 1;

    config->firedancer.vinyl.file_size_gib       = config->firedancer.funk.heap_size_gib;
    config->firedancer.vinyl.max_account_records = config->firedancer.funk.max_account_records;

    config->firedancer.funk.heap_size_gib       = 0;
    config->firedancer.funk.max_account_records = 0;

    char const * io_mode = args->snapshot_load.vinyl_io;
    if(      0==strcmp( io_mode, "ur" ) ) config->firedancer.vinyl.io_uring.enabled = 1;
    else if( 0==strcmp( io_mode, "bd" ) ) {}
    else FD_LOG_ERR(( "unsupported --vinyl-io '%s' (valid options are 'bd' and 'ur')", io_mode ));
  }

  if( args->snapshot_load.offline ) {
    config->firedancer.snapshots.sources.gossip.allow_any      = 0;
    config->firedancer.snapshots.sources.gossip.allow_list_cnt = 0;
    config->firedancer.snapshots.sources.servers_cnt           = 0;
  }

  if( args->snapshot_load.no_incremental ) {
    config->firedancer.snapshots.incremental_snapshots = 0;
  }

  config->development.snapshots.disable_lthash_verification = !args->snapshot_load.lthash;

  /* FIXME Unfortunately, the fdctl boot procedure constructs the
           topology before parsing command-line arguments.  So, here,
           we construct the topology again (a third time ... sigh). */
  snapshot_load_topo( config, args->snapshot_load.vinyl_server );

  fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
}

static void
snapshot_load_cmd_fn( args_t *   args,
                      config_t * config ) {
  fixup_config( config, args );
  if( FD_UNLIKELY( config->firedancer.snapshots.sources.gossip.allow_any || 0UL!=config->firedancer.snapshots.sources.gossip.allow_list_cnt ) ) {
    FD_LOG_ERR(( "snapshot-load command is incompatible with gossip snapshot sources" ));
  }
  _Bool watch = !args->snapshot_load.no_watch;

  fd_topo_t * topo = &config->topo;

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  for( ulong i=0UL; STAGES[ i ]; i++ )
    configure_args.configure.stages[ i ] = STAGES[ i ];
  configure_cmd_fn( &configure_args, config );

  run_firedancer_init( config, 1, 0 );

  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_fill( topo );

  fd_topo_tile_t * snapct_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapct", 0UL ) ];
  fd_topo_tile_t * snapld_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapld", 0UL ) ];
  fd_topo_tile_t * snapdc_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapdc", 0UL ) ];
  fd_topo_tile_t * snapin_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ];
  ulong            snapwm_idx  =               fd_topo_find_tile( topo, "snapwm", 0UL );
  ulong            snapwh_idx  =               fd_topo_find_tile( topo, "snapwh", 0UL );
  ulong            snapwr_idx  =               fd_topo_find_tile( topo, "snapwr", 0UL );
  fd_topo_tile_t * snapwm_tile = snapwm_idx!=ULONG_MAX ? &topo->tiles[ snapwm_idx ] : NULL;
  fd_topo_tile_t * snapwh_tile = snapwh_idx!=ULONG_MAX ? &topo->tiles[ snapwh_idx ] : NULL;
  fd_topo_tile_t * snapwr_tile = snapwr_idx!=ULONG_MAX ? &topo->tiles[ snapwr_idx ] : NULL;
  ulong            snapla_idx  =               fd_topo_find_tile( topo, "snapla", 0UL );
  fd_topo_tile_t * snapla_tile = snapla_idx!=ULONG_MAX ? &topo->tiles[ snapla_idx ] : NULL;
  ulong            snapls_idx  =               fd_topo_find_tile( topo, "snapls", 0UL );
  fd_topo_tile_t * snapls_tile = snapls_idx!=ULONG_MAX ? &topo->tiles[ snapls_idx ] : NULL;

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  double ns_per_tick = 1.0/tick_per_ns;

  long start = fd_log_wallclock();
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  ulong volatile * const snapct_metrics = fd_metrics_tile( snapct_tile->metrics );
  ulong volatile * const snapld_metrics = fd_metrics_tile( snapld_tile->metrics );
  ulong volatile * const snapdc_metrics = fd_metrics_tile( snapdc_tile->metrics );
  ulong volatile * const snapin_metrics = fd_metrics_tile( snapin_tile->metrics );
  ulong volatile * const snapwm_metrics = snapwm_tile ? fd_metrics_tile( snapwm_tile->metrics ) : NULL;
  ulong volatile * const snapwh_metrics = snapwh_tile ? fd_metrics_tile( snapwh_tile->metrics ) : NULL;
  ulong volatile * const snapwr_metrics = snapwr_tile ? fd_metrics_tile( snapwr_tile->metrics ) : NULL;
  ulong volatile * const snapla_metrics = snapla_tile ? fd_metrics_tile( snapla_tile->metrics ) : NULL;
  ulong volatile * const snapls_metrics = snapls_tile ? fd_metrics_tile( snapls_tile->metrics ) : NULL;

  ulong total_off_old    = 0UL;
  ulong decomp_off_old   = 0UL;
  ulong vinyl_off_old    = 0UL;
  ulong snapld_backp_old = 0UL;
  ulong snapld_wait_old  = 0UL;
  ulong snapdc_backp_old = 0UL;
  ulong snapdc_wait_old  = 0UL;
  ulong snapin_backp_old = 0UL;
  ulong snapin_wait_old  = 0UL;
  ulong snapwm_backp_old = 0UL;
  ulong snapwm_wait_old  = 0UL;
  ulong snapwh_backp_old = 0UL;
  ulong snapwh_wait_old  = 0UL;
  ulong snapwr_wait_old  = 0UL;
  ulong snapla_backp_old = 0UL;
  ulong snapla_wait_old  = 0UL;
  ulong snapls_backp_old = 0UL;
  ulong snapls_wait_old  = 0UL;
  ulong acc_cnt_old      = 0UL;

  sleep( 1 );
  if( watch ) {
    puts( "" );
    puts( "Columns:" );
    puts( "- comp:  Compressed bandwidth"             );
    puts( "- raw:   Uncompressed bandwidth"           );
    puts( "- backp: Backpressured by downstream tile" );
    puts( "- stall: Waiting on upstream tile"         );
    puts( "- acc:   Number of accounts"               );
    puts( "" );
    fputs( "--------------------------------------------", stdout );
    if( snapwr_tile )      fputs( "--------------", stdout );
    if( snapls_tile )      fputs( "[ld],[dc],[in],[la],[ls]--------[ld],[dc],[in],[la],[ls]", stdout );
    else if( snapwr_tile ) fputs( "[ld],[dc],[in],[wm],[wh]--------[ld],[dc],[in],[wm],[wh],[wr]", stdout );
    else                   fputs( "[ld],[dc],[in]--------[ld],[dc],[in]", stdout );
    puts( "--------------" );
  }

  long next = start+1000L*1000L*1000L;
  for(;;) {
    ulong snapct_status = FD_VOLATILE_CONST( snapct_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapld_status = FD_VOLATILE_CONST( snapld_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapdc_status = FD_VOLATILE_CONST( snapdc_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapin_status = FD_VOLATILE_CONST( snapin_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapls_status = snapls_metrics ? FD_VOLATILE_CONST( snapls_metrics[ MIDX( GAUGE, TILE, STATUS ) ] ) : 2UL;

    if( FD_UNLIKELY( snapct_status==2UL && snapld_status==2UL && snapdc_status==2UL && snapin_status==2UL && snapls_status==2UL ) ) break;

    long cur = fd_log_wallclock();
    if( FD_UNLIKELY( cur<next ) ) {
      long sleep_nanos = fd_long_min( 1000L*1000L, next-cur );
      FD_TEST( !fd_sys_util_nanosleep(  (uint)(sleep_nanos/(1000L*1000L*1000L)), (uint)(sleep_nanos%(1000L*1000L*1000L)) ) );
      continue;
    }

    ulong total_off    = snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_READ ) ] +
                         snapct_metrics[ MIDX( GAUGE, SNAPCT, INCREMENTAL_BYTES_READ ) ];
    ulong decomp_off   = snapdc_metrics[ MIDX( GAUGE, SNAPDC, FULL_DECOMPRESSED_BYTES_WRITTEN ) ] +
                         snapdc_metrics[ MIDX( GAUGE, SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_WRITTEN ) ];
    ulong vinyl_off    = snapwr_tile ? snapwr_metrics[ MIDX( GAUGE, SNAPWR, VINYL_BYTES_WRITTEN ) ] : 0UL;
    ulong snapld_backp = snapld_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapld_wait  = snapld_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapld_backp;
    ulong snapdc_backp = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapdc_wait  = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapdc_backp;
    ulong snapin_backp = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapin_wait  = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapin_backp;
    ulong snapwm_backp = 0UL;
    ulong snapwm_wait  = 0UL;
    ulong snapwh_backp = 0UL;
    ulong snapwh_wait  = 0UL;
    ulong snapwr_backp = 0UL;
    ulong snapwr_wait  = 0UL;
    ulong snapla_backp = snapla_metrics ? snapla_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ] : 0UL;
    ulong snapla_wait  = snapla_metrics ? snapla_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapla_backp : 0UL;
    ulong snapls_backp = snapls_metrics ? snapls_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ] : 0UL;
    ulong snapls_wait  = snapls_metrics ? snapls_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapls_backp : 0UL;
    if( snapwr_tile ) {
      snapwm_backp     = snapwm_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
      snapwm_wait      = snapwm_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapwm_backp;
      snapwh_backp     = snapwh_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
      snapwh_wait      = snapwh_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapwh_backp;
      snapwr_backp     = snapwr_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
      snapwr_wait      = snapwr_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapwr_backp;
    }

    double progress = 100.0 * (double)snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_READ ) ] / (double)snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_TOTAL ) ];

    ulong acc_cnt      = snapin_metrics[ MIDX( GAUGE, SNAPIN, ACCOUNTS_INSERTED    ) ];

    if( watch ) {
      printf( "%5.1f %% comp=%4.0fMB/s snap=%4.0fMB/s",
              progress,
              (double)( total_off -total_off_old  )/1e6,
              (double)( decomp_off-decomp_off_old )/1e6 );
      if( snapwr_tile ) {
        printf( " vinyl=%4.0fMB/s", (double)( vinyl_off - vinyl_off_old )/1e6 );
      }

      printf( " backp=(%3.0f%%,%3.0f%%,%3.0f%%",
          ( (double)( snapld_backp-snapld_backp_old )*ns_per_tick )/1e7,
          ( (double)( snapdc_backp-snapdc_backp_old )*ns_per_tick )/1e7,
          ( (double)( snapin_backp-snapin_backp_old )*ns_per_tick )/1e7 );
      if( snapls_tile ) {
        printf( ",%3.0f%%,%3.0f%%",
          ( (double)( snapla_backp-snapla_backp_old )*ns_per_tick )/1e7,
          ( (double)( snapls_backp-snapls_backp_old )*ns_per_tick )/1e7 );
      } else if( snapwr_tile ) {
        printf( ",%3.0f%%,%3.0f%%",
          ( (double)( snapwm_backp-snapwm_backp_old )*ns_per_tick )/1e7,
          ( (double)( snapwh_backp-snapwh_backp_old )*ns_per_tick )/1e7 );
      }
      printf( ")" );

      printf( " busy=(%3.0f%%,%3.0f%%,%3.0f%%",
          100-( ( (double)( snapld_wait-snapld_wait_old )*ns_per_tick )/1e7 ),
          100-( ( (double)( snapdc_wait-snapdc_wait_old )*ns_per_tick )/1e7 ),
          100-( ( (double)( snapin_wait-snapin_wait_old )*ns_per_tick )/1e7 ) );
      if( snapls_tile )  {
        printf( ",%3.0f%%,%3.0f%%",
          100-( ( (double)( snapla_wait-snapla_wait_old )*ns_per_tick )/1e7 ),
          100-( ( (double)( snapls_wait-snapls_wait_old )*ns_per_tick )/1e7 ) );
      } else if( snapwr_tile ) {
        printf( ",%3.0f%%,%3.0f%%,%3.0f%%",
          100-( ( (double)( snapwm_wait-snapwm_wait_old )*ns_per_tick )/1e7 ),
          100-( ( (double)( snapwh_wait-snapwh_wait_old )*ns_per_tick )/1e7 ),
          100-( ( (double)( snapwr_wait-snapwr_wait_old )*ns_per_tick )/1e7 ) );
      }
      printf( ")" );

      printf( " acc=%4.1f M/s\n",
              (double)( acc_cnt-acc_cnt_old  )/1e6 );
      fflush( stdout );
    }
    total_off_old    = total_off;
    decomp_off_old   = decomp_off;
    vinyl_off_old    = vinyl_off;
    snapld_backp_old = snapld_backp;
    snapld_wait_old  = snapld_wait;
    snapdc_backp_old = snapdc_backp;
    snapdc_wait_old  = snapdc_wait;
    snapin_backp_old = snapin_backp;
    snapin_wait_old  = snapin_wait;
    snapwm_backp_old = snapwm_backp;
    snapwm_wait_old  = snapwm_wait;
    snapwh_backp_old = snapwh_backp;
    snapwh_wait_old  = snapwh_wait;
    snapwr_wait_old  = snapwr_wait;
    snapla_backp_old = snapla_backp;
    snapla_wait_old  = snapla_wait;
    snapls_backp_old = snapls_backp;
    snapls_wait_old  = snapls_wait;
    acc_cnt_old      = acc_cnt;

    next+=1000L*1000L*1000L;
  }

  if( args->snapshot_load.fsck ) {
    FD_LOG_NOTICE(( "FSCK: starting" ));
    uint fsck_err;
    if( snapwr_tile ) fsck_err = fsck_vinyl( config, args->snapshot_load.fsck_lthash );
    else              fsck_err = fsck_funk ( config, args->snapshot_load.fsck_lthash );
    if( !fsck_err ) {
      FD_LOG_NOTICE(( "FSCK: passed" ));
    } else {
      FD_LOG_ERR(( "FSCK: errors detected" ));
    }
  }

  if( args->snapshot_load.accounts_hist ) {
    accounts_hist_t hist[1];
    accounts_hist_reset( hist );
    FD_LOG_NOTICE(( "Accounts histogram: starting" ));
    if( snapwr_tile ) accounts_hist_vinyl( hist, config );
    else              accounts_hist_funk ( hist, config );
    FD_TEST( !accounts_hist_check( hist ) );
    accounts_hist_print( hist );
  }

  if( args->snapshot_load.vinyl_server ) {
    /* Generate a config pod */
    fd_wksp_t * server_wksp = topo->workspaces[ fd_topo_find_wksp( topo, "vinyl_server" ) ].wksp;
    ulong const cfg_pod_sz = 8192UL;
    ulong cfg_gaddr = fd_wksp_alloc( server_wksp, fd_pod_align(), fd_pod_footprint( cfg_pod_sz ), 1UL );
    FD_TEST( cfg_gaddr );
    uchar * cfg = fd_pod_join( fd_pod_new( fd_wksp_laddr( server_wksp, cfg_gaddr ), cfg_pod_sz ) );
    FD_TEST( cfg );
    char gaddr_tmp[ 256 ];
#   define POD_ADD( key, obj_id ) do {                                 \
      ulong _obj_id = (obj_id);                                        \
      FD_TEST( _obj_id!=ULONG_MAX );                                   \
      fd_topo_obj_t * _obj = &topo->objs[ _obj_id ];                   \
      FD_TEST( fd_cstr_printf_check( gaddr_tmp, sizeof(gaddr_tmp), NULL, "%s_%s.wksp:%lu", topo->app_name, topo->workspaces[ _obj->wksp_id ].name, _obj->offset ) ); \
      FD_TEST( fd_pod_insert_cstr( cfg, (key), gaddr_tmp )!=0UL );     \
    } while(0)
    POD_ADD( "cnc",  fd_pod_query_ulong( topo->props, "vinyl.cnc",       ULONG_MAX ) );
    POD_ADD( "meta", fd_pod_query_ulong( topo->props, "vinyl.meta_map",  ULONG_MAX ) );
    POD_ADD( "ele",  fd_pod_query_ulong( topo->props, "vinyl.meta_pool", ULONG_MAX ) );
    POD_ADD( "obj",  fd_pod_query_ulong( topo->props, "vinyl.data",      ULONG_MAX ) );
#   undef POD_ADD
    fd_pod_leave( cfg );
    FD_LOG_NOTICE(( "Wrote vinyl topology pod to %s_%s.wksp:%lu", topo->app_name, "vinyl_server", cfg_gaddr ));

    /* Wait for vinyl tile to boot */
    fd_cnc_t * cnc = fd_cnc_join( fd_topo_obj_laddr( topo, fd_pod_query_ulong( topo->props, "vinyl.cnc", ULONG_MAX )  ) );
    FD_TEST( cnc );
    ulong vinyl_status = fd_cnc_wait( cnc, FD_VINYL_CNC_SIGNAL_BOOT, LONG_MAX, NULL );
    FD_TEST( vinyl_status==FD_VINYL_CNC_SIGNAL_RUN );
    FD_LOG_NOTICE(( "Vinyl server running" ));
    for(;;) {
      vinyl_status = fd_cnc_wait( cnc, vinyl_status, LONG_MAX, NULL );
      char cnc_signal_cstr[ FD_VINYL_CNC_SIGNAL_CSTR_BUF_MAX ];
      fd_vinyl_cnc_signal_cstr( vinyl_status, cnc_signal_cstr );
      FD_LOG_NOTICE(( "Vinyl CNC signal %s", cnc_signal_cstr ));
      //if( vinyl_status==FD_VINYL_CNC_SIGNAL_BOOT ) break;
    }
    FD_LOG_NOTICE(( "Vinyl server shut down" ));
    fd_cnc_leave( cnc );
  }
}

action_t fd_action_snapshot_load = {
  .name = NAME,
  .topo = snapshot_load_topo1,
  .perm = dev_cmd_perm,
  .args = snapshot_load_args,
  .fn   = snapshot_load_cmd_fn
};
