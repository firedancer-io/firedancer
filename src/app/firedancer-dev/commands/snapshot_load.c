#include "../../firedancer/topology.h"
#include "../../platform/fd_sys_util.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../shared_dev/commands/dev.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/pack/fd_pack_cost.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../discof/restore/utils/fd_ssctrl.h"
#include "../../../discof/restore/utils/fd_ssmsg.h"
#include "../../../flamenco/runtime/fd_cost_tracker.h"
#define FD_ACCDB_NO_FORK_ID
#include "../../../flamenco/accdb/fd_accdb_private.h"
#undef FD_ACCDB_NO_FORK_ID

#include <fcntl.h> /* open */
#include <sys/resource.h>
#include <linux/capability.h>
#include <unistd.h> /* close, sleep */
#include <stdlib.h>
#include <stdio.h>

#define NAME "snapshot-load"

#define SL_RESET  "\033[0m"
#define SL_BOLD   "\033[1m"
#define SL_DIM    "\033[2m"
#define SL_RED    "\033[31m"
#define SL_GREEN  "\033[32m"
#define SL_YELLOW "\033[33m"

static char const *
sev_color( int    color,
           double pct ) {
  if( FD_UNLIKELY( !color ) ) return "";
  if( FD_UNLIKELY( pct>=85.0 ) ) return SL_RED;
  if( FD_UNLIKELY( pct>=50.0 ) ) return SL_YELLOW;
  return "";
}

static double
clamp_pct( double pct ) {
  return fd_double_if( pct<0.0, 0.0, fd_double_if( pct>100.0, 100.0, pct ) );
}

static char *
fmt_bar( char * buf,
         ulong  buf_sz,
         int    color,
         double pct,
         ulong  width ) {
  ulong filled = (ulong)( clamp_pct( pct )*(double)width/100.0+0.5 );
  ulong len = 0UL, l;
  FD_TEST( fd_cstr_printf_check( buf, buf_sz, &len, "%s", color ? SL_GREEN : "" ) );
  for( ulong i=0UL;    i<filled; i++ ) { FD_TEST( fd_cstr_printf_check( buf+len, buf_sz-len, &l, "█" ) ); len += l; }
  FD_TEST( fd_cstr_printf_check( buf+len, buf_sz-len, &l, "%s", color ? SL_DIM : "" ) ); len += l;
  for( ulong i=filled; i<width;  i++ ) { FD_TEST( fd_cstr_printf_check( buf+len, buf_sz-len, &l, "░" ) ); len += l; }
  FD_TEST( fd_cstr_printf_check( buf+len, buf_sz-len, &l, "%s", color ? SL_RESET : "" ) );
  return buf;
}

static char const *
phase_cstr( ulong state ) {
  if( FD_LIKELY( ( state>= 5UL && state<= 8UL ) || ( state>=13UL && state<=16UL ) ) ) return "full";
  if( FD_LIKELY( ( state>= 9UL && state<=12UL ) || ( state>=17UL && state<=20UL ) ) ) return "incr";
  if( FD_UNLIKELY( state==21UL ) ) return "done";
  return "wait";
}

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
snapshot_load_topo( config_t * config ) {
  config->firedancer.layout.resolv_tile_count = 0;
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "txncache" );
  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "txncache",
      config->firedancer.runtime.max_live_slots,
      FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT,
      config->development.bench.larger_max_cost_per_block );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );

  fd_topob_wksp( topo, "accdb" );
  fd_topo_obj_t * accdb_obj = setup_topo_accdb( topo, "accdb",
      config->firedancer.accounts.max_accounts,
      config->firedancer.runtime.max_live_slots,
      FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT,
      8192UL,
      1UL<<35UL,
      config->firedancer.accounts.cache_size_gib*(1UL<<30UL),
      config->tiles.bundle.enabled,
      2UL );
  FD_TEST( fd_pod_insertf_ulong( topo->props, accdb_obj->id, "accdb" ) );

  fd_topob_wksp( topo, "banks" );
  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks",
      config->firedancer.runtime.max_live_slots,
      config->firedancer.runtime.max_fork_width,
      config->development.bench.larger_max_cost_per_block );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

#define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /* metrics tile *****************************************************/
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "metric" );
  fd_topob_tile( topo, "metric",  "metric", "metric_in", ULONG_MAX, 0, 0, 0 );

  /* read() tile */
  fd_topob_wksp( topo, "snapct" );
  fd_topo_tile_t * snapct_tile = fd_topob_tile( topo, "snapct", "snapct", "metric_in", ULONG_MAX, 0, 0, 0 );
  snapct_tile->allow_shutdown = 1;

  /* load tile */
  fd_topob_wksp( topo, "snapld" );
  fd_topo_tile_t * snapld_tile = fd_topob_tile( topo, "snapld", "snapld", "metric_in", ULONG_MAX, 0, 0, 0 );
  snapld_tile->allow_shutdown = 1;

  /* "snapdc": Zstandard decompress tile */
  fd_topob_wksp( topo, "snapdc" );
  fd_topo_tile_t * snapdc_tile = fd_topob_tile( topo, "snapdc", "snapdc", "metric_in", ULONG_MAX, 0, 0, 0 );
  snapdc_tile->allow_shutdown = 1;

  /* "snapin": Snapshot parser tile */
  fd_topob_wksp( topo, "snapin" );
  fd_topo_tile_t * snapin_tile = fd_topob_tile( topo, "snapin", "snapin", "metric_in", ULONG_MAX, 0, 0, 0 );
  snapin_tile->allow_shutdown = 1;

  fd_topob_wksp( topo, "snapwr" );
  fd_topo_tile_t * snapwr_tile = fd_topob_tile( topo, "snapwr", "snapwr", "metric_in", ULONG_MAX, 0, 0, 0 );
  snapwr_tile->allow_shutdown = 1;

  fd_topob_wksp( topo, "diag" );
  fd_topob_tile( topo, "diag", "diag", "metric_in", ULONG_MAX, 0, 0, 0 );
  fd_topo_tile_t * accdb_tile = fd_topob_tile( topo, "accdb", "accdb", "metric_in", ULONG_MAX, 0, 0, 0 );

  fd_topob_wksp( topo, "snapct_ld"    );
  fd_topob_wksp( topo, "snapld_dc"    );
  fd_topob_wksp( topo, "snapdc_in"    );

  fd_topob_wksp( topo, "snapin_manif" );
  fd_topob_wksp( topo, "snapct_repr"  );

  fd_topob_wksp( topo, "snapin_ct"    );
  fd_topob_wksp( topo, "snapwr_ct"    );

  fd_topob_link( topo, "snapct_ld",    "snapct_ld",    128UL,   sizeof(fd_ssctrl_init_t),       1UL );
  fd_topob_link( topo, "snapld_dc",    "snapld_dc",    16384UL, FD_SNAPSHOT_DATA_MTU,           1UL );
  fd_topob_link( topo, "snapdc_in",    "snapdc_in",    16384UL, FD_SNAPSHOT_DATA_MTU,           1UL );
  fd_topob_link( topo, "snapin_manif", "snapin_manif", 4UL,     sizeof(fd_snapshot_manifest_t), 1UL )->permit_no_consumers = 1;
  fd_topob_link( topo, "snapct_repr",  "snapct_repr",  128UL,   0UL,                            1UL )->permit_no_consumers = 1;

  fd_topob_link( topo, "snapin_ct", "snapin_ct",   128UL,  0UL,                             1UL );
  fd_topob_link( topo, "snapwr_ct", "snapwr_ct",   128UL,  0UL,                             1UL );
  fd_topob_tile_in( topo, "snapct",  0UL, "metric_in", "snapin_ct",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_in( topo, "snapct",  0UL, "metric_in", "snapwr_ct",  0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );

  fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapld_dc",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapct",  0UL,              "snapct_ld",    0UL                                       );
  fd_topob_tile_out( topo, "snapct",  0UL,              "snapct_repr",  0UL                                       );
  fd_topob_tile_in ( topo, "snapld",  0UL, "metric_in", "snapct_ld",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapld",  0UL,              "snapld_dc",    0UL                                       );
  fd_topob_tile_in ( topo, "snapdc",  0UL, "metric_in", "snapld_dc",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapdc",  0UL,              "snapdc_in",    0UL                                       );
  fd_topob_tile_in ( topo, "snapin",  0UL, "metric_in", "snapdc_in",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapin",  0UL,              "snapin_manif", 0UL                                       );
  fd_topob_tile_out( topo, "snapin",  0UL,              "snapin_ct",    0UL                                       );
  fd_topob_tile_in ( topo, "snapwr",  0UL, "metric_in", "snapdc_in",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapwr",  0UL,              "snapwr_ct",    0UL                                       );

  fd_topob_tile_uses( topo, snapin_tile, txncache_obj,   FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, snapin_tile, accdb_obj,      FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, snapin_tile, banks_obj,      FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, accdb_tile,  accdb_obj,      FD_SHMEM_JOIN_MODE_READ_WRITE );
  snapin_tile->snapin.accdb_obj_id    = accdb_obj->id;
  snapin_tile->snapin.txncache_obj_id = txncache_obj->id;
  snapin_tile->snapin.banks_obj_id    = banks_obj->id;
  snapin_tile->snapin.max_live_slots  = config->firedancer.runtime.max_live_slots;

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
}

static void
snapshot_load_topo1( config_t * config ) {
  snapshot_load_topo( config );
}

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
      "  --db-rec-max <num>   Database max record/account count (e.g. 10e6 -> 10M accounts)\n"
      "  --accounts-hist      After loading, analyze account size distribution\n"
      "\n",
      stderr );
    exit( 0 );
  }
  memset( &args->snapshot_load, 0, sizeof(args->snapshot_load) );

  char const * snapshot_dir  = fd_env_strip_cmdline_cstr    ( pargc, pargv, "--snapshot-dir", NULL, NULL   );
  int          offline       = fd_env_strip_cmdline_contains( pargc, pargv, "--offline"                    )!=0;
  int          no_incremental= fd_env_strip_cmdline_contains( pargc, pargv, "--no-incremental"             )!=0;
  int          no_watch      = fd_env_strip_cmdline_contains( pargc, pargv, "--no-watch"                   )!=0;
  int          accounts_hist = fd_env_strip_cmdline_contains( pargc, pargv, "--accounts-hist"              )!=0;

  fd_cstr_ncpy( args->snapshot_load.snapshot_dir, snapshot_dir, sizeof(args->snapshot_load.snapshot_dir) );
  args->snapshot_load.accounts_hist  = accounts_hist;
  args->snapshot_load.offline        = offline;
  args->snapshot_load.no_incremental = no_incremental;
  args->snapshot_load.no_watch       = no_watch;
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

static inline void FD_FN_UNUSED
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
    ulong hist_bin_avg      = hist->bin_cnt[ i ] > 0 ? hist->bin_acc[ i ] / hist->bin_cnt[ i ] : 0UL;
    /* log */
    char buf[256];
    FD_TEST( fd_cstr_printf_check( buf, sizeof(buf), NULL,
                                  "%12lu %s sz <= %12lu | %8.1f K (%6.1f %%) | %8.1f MiB (%6.1f %%) | %12lu | %12lu | %12lu |\n",
                                  hist_bin_tlo, i==0? "<=" : "< ", hist_bin_thi,
                                  hist_bin_cnt_K, sum_cnt_p,
                                  hist_bin_acc_MiB, sum_acc_p,
                                  hist_bin_min, hist_bin_max, hist_bin_avg ) );
    printf( "%s", buf );
  }
  printf( "\n" );
}

static void
accounts_hist( accounts_hist_t * hist,
               config_t *        config ) {
  fd_topo_t * topo = &config->topo;
  ulong accdb_obj_id = fd_pod_query_ulong( topo->props, "accdb", ULONG_MAX );
  FD_TEST( accdb_obj_id!=ULONG_MAX );
  void * _accdb_shmem = fd_topo_obj_laddr( topo, accdb_obj_id );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( shmem );

  /* Recompute the shmem layout to locate acc_map and acc_pool element
     storage without taking a writer joiner slot.  This mirrors the
     layout in fd_accdb_shmem_new and fd_accdb_join_readonly. */

  ulong max_live_slots              = shmem->max_live_slots;
  ulong max_accounts                = shmem->max_accounts;
  ulong max_account_writes_per_slot = shmem->max_account_writes_per_slot;
  ulong partition_cnt               = shmem->partition_cnt;
  ulong chain_cnt                   = shmem->chain_cnt;
  ulong txn_max                     = max_live_slots * max_account_writes_per_slot;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
                                  FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,           sizeof(fd_accdb_shmem_t)                                );
                                  FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),              fork_pool_footprint()                                   );
                                  FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)            );
                                  FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),           max_live_slots*descends_set_footprint( max_live_slots ) );
  uint *               acc_map  = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                  chain_cnt*sizeof(uint)                                  );
                                  FD_SCRATCH_ALLOC_APPEND( l, acc_pool_align(),               acc_pool_footprint()                                    );
  fd_accdb_accmeta_t * acc_pool = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_accmeta_t),    max_accounts*sizeof(fd_accdb_accmeta_t)                     );
  (void)txn_max; (void)partition_cnt;

  /* Walk every hash chain.  Each non-UINT_MAX head index yields a
     linked list of live acc_pool elements via map.next. */

  for( ulong chain_i=0UL; chain_i<chain_cnt; chain_i++ ) {
    uint acc_idx = acc_map[ chain_i ];
    while( acc_idx!=UINT_MAX ) {
      fd_accdb_accmeta_t const * accmeta = &acc_pool[ acc_idx ];
      ulong data_sz = (ulong)FD_ACCDB_SIZE_DATA( accmeta->executable_size );
      accounts_hist_update( hist, sizeof(fd_accdb_disk_meta_t) + data_sz );
      acc_idx = accmeta->map.next;
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

  if( args->snapshot_load.db_rec_max ) {
    config->firedancer.accounts.max_accounts = args->snapshot_load.db_rec_max;
  }

  if( args->snapshot_load.cache_sz ) {
    config->firedancer.accounts.cache_size_gib = fd_ulong_align_up( args->snapshot_load.cache_sz, (1UL<<30) )>>30;
  }

  if( args->snapshot_load.offline ) {
    config->firedancer.snapshots.sources.gossip.allow_any      = 0;
    config->firedancer.snapshots.sources.gossip.allow_list_cnt = 0;
    config->firedancer.snapshots.sources.servers_cnt           = 0;
  }

  if( args->snapshot_load.no_incremental ) {
    config->firedancer.snapshots.incremental_snapshots = 0;
  }

  if( FD_UNLIKELY( config->firedancer.snapshots.sources.gossip.allow_any || config->firedancer.snapshots.sources.gossip.allow_list_cnt ) ) {
    FD_LOG_WARNING(( "snapshot-load command is incompatible with gossip snapshot sources; disabling gossip snapshot sources" ));
    config->firedancer.snapshots.sources.gossip.allow_any      = 0;
    config->firedancer.snapshots.sources.gossip.allow_list_cnt = 0;
  }

  /* FIXME Unfortunately, the fdctl boot procedure constructs the
           topology before parsing command-line arguments.  So, here,
           we construct the topology again (a third time ... sigh). */
  snapshot_load_topo( config );

  fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
}

static void
snapshot_load_cmd_fn( args_t *   args,
                      config_t * config ) {
  fixup_config( config, args );

  int watch = !args->snapshot_load.no_watch;

  fd_topo_t * topo = &config->topo;

  args_t configure_args = {
    .configure.command = CONFIGURE_CMD_INIT,
  };

  for( ulong i=0UL; STAGES[ i ]; i++ )
    configure_args.configure.stages[ i ] = STAGES[ i ];
  configure_cmd_fn( &configure_args, config );

  run_firedancer_init( config, 1, 0 );

  initialize_accdb_fd( config );

  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( topo );

  fd_topo_tile_t * snapct_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapct", 0UL ) ];
  fd_topo_tile_t * snapld_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapld", 0UL ) ];
  fd_topo_tile_t * snapdc_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapdc", 0UL ) ];
  fd_topo_tile_t * snapin_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ];
  fd_topo_tile_t * snapwr_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapwr", 0UL ) ];

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  double ns_per_tick = 1.0/tick_per_ns;

  long start = fd_log_wallclock();
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  ulong volatile * const snapct_metrics = fd_metrics_tile( snapct_tile->metrics );
  ulong volatile * const snapld_metrics = fd_metrics_tile( snapld_tile->metrics );
  ulong volatile * const snapdc_metrics = fd_metrics_tile( snapdc_tile->metrics );
  ulong volatile * const snapin_metrics = fd_metrics_tile( snapin_tile->metrics );
  ulong volatile * const snapwr_metrics = fd_metrics_tile( snapwr_tile->metrics );

  ulong total_off_old    = 0UL;
  ulong decomp_off_old   = 0UL;
  ulong snapld_wait_old  = 0UL;
  ulong snapdc_wait_old  = 0UL;
  ulong snapin_wait_old  = 0UL;
  ulong snapwr_wait_old  = 0UL;
  ulong acc_cnt_old      = 0UL;

  int color = fd_log_colorize() && isatty( STDOUT_FILENO );
  char const * c_bold = color ? SL_BOLD : "";
  char const * c_dim  = color ? SL_DIM  : "";
  char const * c_norm = color ? SL_RESET : "";

  sleep( 1 );
  if( watch ) {
    printf( "%scomp%s compressed %s·%s %sraw%s uncompressed %s·%s %sacc%s accounts %s·%s "
            "%sbusy%s %%%s of load·decompress·insert·write, yellow when the bottleneck%s\n",
            c_dim, c_norm, c_dim, c_norm,
            c_dim, c_norm, c_dim, c_norm,
            c_dim, c_norm, c_dim, c_norm,
            c_dim, c_norm, c_dim, c_norm );
    fflush( stdout );
  }

  long next = start+1000L*1000L*1000L;
  for(;;) {
    ulong snapct_status = FD_VOLATILE_CONST( snapct_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapld_status = FD_VOLATILE_CONST( snapld_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapdc_status = FD_VOLATILE_CONST( snapdc_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapin_status = FD_VOLATILE_CONST( snapin_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapwr_status = FD_VOLATILE_CONST( snapwr_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );

    if( FD_UNLIKELY( snapct_status==2UL && snapld_status==2UL && snapdc_status==2UL && snapin_status==2UL && snapwr_status==2UL ) ) break;

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
    /* Waiting on either neighbor counts as not busy */
    ulong snapld_wait  = snapld_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) ]
                       + snapld_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapdc_wait  = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) ]
                       + snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapin_wait  = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) ]
                       + snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapwr_wait  = snapwr_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) ]
                       + snapwr_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];

    char const * phase = phase_cstr( snapct_metrics[ MIDX( GAUGE, SNAPCT, STATE ) ] );
    ulong consumed, dc_in, dc_out, size_bytes;
    if( FD_UNLIKELY( !strcmp( phase, "incr" ) ) ) {
      consumed   = fd_ulong_min( snapin_metrics[ MIDX( GAUGE, SNAPIN, INCREMENTAL_BYTES_READ ) ],
                                 snapwr_metrics[ MIDX( GAUGE, SNAPWR, INCREMENTAL_BYTES_READ ) ] );
      dc_in      = snapdc_metrics[ MIDX( GAUGE, SNAPDC, INCREMENTAL_COMPRESSED_BYTES_READ ) ];
      dc_out     = snapdc_metrics[ MIDX( GAUGE, SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_WRITTEN ) ];
      size_bytes = snapct_metrics[ MIDX( GAUGE, SNAPCT, INCREMENTAL_SIZE_BYTES ) ];
    } else {
      consumed   = fd_ulong_min( snapin_metrics[ MIDX( GAUGE, SNAPIN, FULL_BYTES_READ ) ],
                                 snapwr_metrics[ MIDX( GAUGE, SNAPWR, FULL_BYTES_READ ) ] );
      dc_in      = snapdc_metrics[ MIDX( GAUGE, SNAPDC, FULL_COMPRESSED_BYTES_READ ) ];
      dc_out     = snapdc_metrics[ MIDX( GAUGE, SNAPDC, FULL_DECOMPRESSED_BYTES_WRITTEN ) ];
      size_bytes = snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_SIZE_BYTES ) ];
    }
    double done_comp = dc_out ? (double)dc_in*( (double)consumed/(double)dc_out ) : 0.0;
    double progress  = size_bytes ? clamp_pct( 100.0*done_comp/(double)size_bytes ) : 0.0;

    ulong acc_cnt      = snapin_metrics[ MIDX( GAUGE, SNAPIN, ACCOUNT_LOADED    ) ];

    if( watch ) {
      double busy[ 4 ] = {
        clamp_pct( 100.0-( ( (double)( snapld_wait-snapld_wait_old )*ns_per_tick )/1e7 ) ),
        clamp_pct( 100.0-( ( (double)( snapdc_wait-snapdc_wait_old )*ns_per_tick )/1e7 ) ),
        clamp_pct( 100.0-( ( (double)( snapin_wait-snapin_wait_old )*ns_per_tick )/1e7 ) ),
        clamp_pct( 100.0-( ( (double)( snapwr_wait-snapwr_wait_old )*ns_per_tick )/1e7 ) ),
      };

      char bar[ 256 ];
      printf( " %s%4s%s %s %s%5.1f%%%s"
              "  %scomp%s %5.2f %sGB/s%s"
              "  %sraw%s %5.2f %sGB/s%s"
              "  %sacc%s %4.1f %sM/s%s",
              c_dim, phase, c_norm,
              fmt_bar( bar, sizeof(bar), color, progress, 20UL ),
              c_bold, progress, c_norm,
              c_dim, c_norm, (double)( total_off -total_off_old  )/1e9, c_dim, c_norm,
              c_dim, c_norm, (double)( decomp_off-decomp_off_old )/1e9, c_dim, c_norm,
              c_dim, c_norm, (double)( acc_cnt   -acc_cnt_old    )/1e6, c_dim, c_norm );

      static char const * tile_key[ 4 ] = { "ld", "dc", "in", "wr" };
      printf( "  %sbusy%s", c_dim, c_norm );
      for( ulong i=0UL; i<4UL; i++ )
        printf( " %s%s%s %s%3.0f%s%%%s",
                c_dim, tile_key[ i ], c_norm,
                sev_color( color, busy[ i ] ), busy[ i ], c_dim, c_norm );
      printf( "\n" );
      fflush( stdout );
    }
    total_off_old    = total_off;
    decomp_off_old   = decomp_off;
    snapld_wait_old  = snapld_wait;
    snapdc_wait_old  = snapdc_wait;
    snapin_wait_old  = snapin_wait;
    snapwr_wait_old  = snapwr_wait;
    acc_cnt_old      = acc_cnt;

    next+=1000L*1000L*1000L;
  }

  if( args->snapshot_load.accounts_hist ) {
    accounts_hist_t hist[1];
    accounts_hist_reset( hist );
    FD_LOG_NOTICE(( "Accounts histogram: starting" ));
    accounts_hist( hist, config );
    FD_TEST( !accounts_hist_check( hist ) );
    accounts_hist_print( hist );
  }
}

static void
snapshot_load_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--snapshot-dir",   "<path>",  "Load/save snapshots from this directory" );
  fd_action_help_arg( help, "--offline",        NULL,      "Do not attempt to download snapshots" );
  fd_action_help_arg( help, "--no-incremental", NULL,      "Disable incremental snapshot loading" );
  fd_action_help_arg( help, "--no-watch",       NULL,      "Do not print periodic progress updates" );
  fd_action_help_arg( help, "--db-sz",          "<bytes>", "Database size in bytes (e.g. 10e9 -> 10 GB)" );
  fd_action_help_arg( help, "--db-rec-max",     "<num>",   "Database max record/account count (e.g. 10e6 -> 10M accounts)" );
  fd_action_help_arg( help, "--fsck",           NULL,      "After loading, run database integrity checks" );
  fd_action_help_arg( help, "--accounts-hist",  NULL,      "After loading, analyze account size distribution" );
}

action_t fd_action_snapshot_load = {
  .name        = NAME,
  .topo        = snapshot_load_topo1,
  .perm        = dev_cmd_perm,
  .args        = snapshot_load_args,
  .fn          = snapshot_load_cmd_fn,
  .description = "Load a snapshot into a database and optionally inspect it",
  .detail      = "Boots a reduced topology that downloads (or reads from disk) a full and\n"
                 "optional incremental snapshot, loads the accounts into a database, and\n"
                 "can then run integrity checks or analyze the account size distribution.",
  .usage       = NAME " [OPTIONS]",
  .args_help   = snapshot_load_args_help,
};
