#include "../../../flamenco/progcache/fd_prog_load.h"
#include "../../../flamenco/runtime/fd_bank.h"
#include "../../../flamenco/runtime/fd_system_ids.h"
#include "../../../flamenco/runtime/program/fd_bpf_loader_program.h"
#include "../../../ballet/blake3/fd_blake3.h"
#include "../../../flamenco/runtime/sysvar/fd_sysvar_clock.h"
#include "../../../flamenco/vm/transpile/fd_transpile_obj.h"
#include "../../../ballet/base58/fd_base58.h"
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
#include "../../../flamenco/accdb/fd_accdb_private.h"

#include <errno.h>
#include <fcntl.h> /* open */
#include <limits.h>
#include <sys/stat.h>
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
snapshot_load_layout( config_t *  config,
                      fd_topo_t * topo ) {
  if( FD_LIKELY( !strcmp( config->layout.affinity, "auto" ) ) ) {
    fd_topob_auto_layout( topo, 0 );
    return;
  }

  ushort tile_to_cpu[ FD_TILE_MAX ];
  ulong affinity_tile_cnt = fd_topob_parse_affinity_cstr( config->layout.affinity, tile_to_cpu, 1, 1 );
  if( FD_UNLIKELY( affinity_tile_cnt<topo->tile_cnt ) ) {
    FD_LOG_ERR(( "snapshot-load topology has %lu tiles, but [layout.affinity] only provides %lu entries",
                 topo->tile_cnt, affinity_tile_cnt ));
  }
  if( FD_UNLIKELY( affinity_tile_cnt>topo->tile_cnt ) ) {
    FD_LOG_WARNING(( "snapshot-load topology has %lu tiles, but [layout.affinity] provides %lu entries; ignoring extras",
                     topo->tile_cnt, affinity_tile_cnt ));
  }

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    ushort encoded = tile_to_cpu[ i ];
    ushort cpu_idx = (ushort)(encoded & ~FD_TOPOB_CPU_SHARED);
    if( FD_UNLIKELY( encoded!=USHORT_MAX && cpu_idx>=cpus->cpu_cnt ) ) {
      FD_LOG_ERR(( "[layout.affinity] assigns snapshot-load tile %lu to CPU %hu, but the system has %lu CPUs",
                   i, cpu_idx, cpus->cpu_cnt ));
    }
    topo->tiles[ i ].cpu_idx = fd_ulong_if( encoded==USHORT_MAX,
                                            ULONG_MAX,
                                            (ulong)cpu_idx );
    topo->tiles[ i ].floats = encoded!=USHORT_MAX && !!(encoded & FD_TOPOB_CPU_SHARED);
  }
}

static void
snapshot_load_topo( config_t * config ) {
  config->firedancer.layout.resolv_tile_count = 0;
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "txncache" );
  fd_topo_obj_t * txncache_obj = setup_topo_txncache( topo, "txncache",
      config->firedancer.runtime.max_live_slots,
      2UL*config->limits.max_txn_per_slot );
  FD_TEST( fd_pod_insertf_ulong( topo->props, txncache_obj->id, "txncache" ) );

  fd_topob_wksp( topo, "accdb" );
  fd_topo_obj_t * accdb_obj = setup_topo_accdb( topo, "accdb",
      config->firedancer.accounts.max_accounts,
      config->firedancer.runtime.max_live_slots,
      FD_RUNTIME_MAX_ACC_WRITES_PER_SLOT,
      8192UL,
      1UL<<35UL,
      config->firedancer.accounts.cache_size_gib*(1UL<<30UL),
      config->tiles.bundle.enabled,
      1UL+config->firedancer.layout.snapin_tile_count,
      0UL );
  FD_TEST( fd_pod_insertf_ulong( topo->props, accdb_obj->id, "accdb" ) );

  fd_topob_wksp( topo, "banks" );
  fd_topo_obj_t * banks_obj = setup_topo_banks( topo, "banks",
      config->firedancer.runtime.max_live_slots,
      config->firedancer.runtime.max_fork_width,
      config->development.bench.max_cost_per_block );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

#define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )

  /* metrics tile *****************************************************/
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "metric" );
  fd_topob_tile( topo, "metric",  "metric", "metric_in", ULONG_MAX, 0, 0, 0, 1 );

  /* read() tile */
  fd_topob_wksp( topo, "snapct" );
  fd_topo_tile_t * snapct_tile = fd_topob_tile( topo, "snapct", "snapct", "metric_in", ULONG_MAX, 0, 0, 0, 1 );
  snapct_tile->allow_shutdown = 1;

  /* load tile */
  fd_topob_wksp( topo, "snapld" );
  fd_topo_tile_t * snapld_tile = fd_topob_tile( topo, "snapld", "snapld", "metric_in", ULONG_MAX, 0, 0, 0, 1 );
  snapld_tile->allow_shutdown = 1;

  /* "snapdc": Zstandard decompress tile */
  fd_topob_wksp( topo, "snapdc" );
  ulong snapdc_tile_cnt = config->firedancer.layout.snapdc_tile_count;
  FOR(snapdc_tile_cnt) fd_topob_tile( topo, "snapdc", "snapdc", "metric_in", ULONG_MAX, 0, 0, 0, 0 )->allow_shutdown = 1;

  /* Parallel snapshot loader tiles. */
  fd_topob_wksp( topo, "snapin" );
  ulong snapin_tile_cnt = config->firedancer.layout.snapin_tile_count;
  FOR(snapin_tile_cnt) {
    fd_topo_tile_t * tile = fd_topob_tile( topo, "snapin", "snapin", "metric_in", ULONG_MAX, 0, 0, 0, 0 );
    tile->allow_shutdown = 1;
  }

  fd_topob_wksp( topo, "snapin_shmem" );
  fd_topo_obj_t * shmem_obj = fd_topob_obj( topo, "snapin_shmem", "snapin_shmem" );
  FD_TEST( fd_pod_insertf_ulong( topo->props, shmem_obj->id, "snapin_shmem" ) );

  fd_topo_obj_t * dc_ticket_obj = fd_topob_obj_named( topo, "fseq", "snapdc", "frame_ticket" );
  FOR(snapdc_tile_cnt) fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapdc", i ) ], dc_ticket_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );

  fd_topob_wksp( topo, "diag" );
  fd_topob_tile( topo, "diag", "diag", "metric_in", ULONG_MAX, 0, 0, 0, 0 );
  fd_topo_tile_t * accdb_tile = fd_topob_tile( topo, "accdb", "accdb", "metric_in", ULONG_MAX, 0, 0, 0, 0 );

  fd_topob_wksp( topo, "snapct_ld"    );
  fd_topob_wksp( topo, "snapld_dc"    );
  fd_topob_wksp( topo, "snapdc_in"    );

  fd_topob_wksp( topo, "snapin_manif" );
  fd_topob_wksp( topo, "snapct_repr"  );

  fd_topob_wksp( topo, "snapin_ct"    );

  fd_topob_link( topo, "snapct_ld",    "snapct_ld",    128UL,                  sizeof(fd_ssctrl_msg_t),        1UL );
  fd_topob_link( topo, "snapld_dc",    "snapld_dc",    FD_SNAPSHOT_DATA_DEPTH, FD_SNAPSHOT_DATA_MTU,           1UL );
  FOR(snapdc_tile_cnt) fd_topob_link( topo, "snapdc_in", "snapdc_in", FD_SNAPSHOT_DC_IN_DEPTH, FD_SNAPSHOT_DATA_MTU, 1UL );
  fd_topob_link( topo, "snapin_manif", "snapin_manif", 4UL,     sizeof(fd_snapshot_manifest_t), 1UL )->permit_no_consumers = 1;
  fd_topob_link( topo, "snapct_repr",  "snapct_repr",  128UL,   0UL,                            1UL )->permit_no_consumers = 1;

  FOR(snapin_tile_cnt) fd_topob_link( topo, "snapin_ct", "snapin_ct", 128UL, 0UL, 1UL );
  FOR(snapin_tile_cnt) fd_topob_tile_in( topo, "snapct", 0UL, "metric_in", "snapin_ct", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  fd_topob_tile_in ( topo, "snapct",  0UL, "metric_in", "snapld_dc",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapct",  0UL,              "snapct_ld",    0UL                                       );
  fd_topob_tile_out( topo, "snapct",  0UL,              "snapct_repr",  0UL                                       );
  fd_topob_tile_in ( topo, "snapld",  0UL, "metric_in", "snapct_ld",    0UL, FD_TOPOB_RELIABLE,   FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapld",  0UL,              "snapld_dc",    0UL                                       );
  FOR(snapdc_tile_cnt) fd_topob_tile_in ( topo, "snapdc", i,   "metric_in", "snapld_dc", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  FOR(snapdc_tile_cnt) fd_topob_tile_out( topo, "snapdc", i,               "snapdc_in", i                                         );
  for( ulong t=0UL; t<snapin_tile_cnt; t++ ) {
    FOR(snapdc_tile_cnt) fd_topob_tile_in( topo, "snapin", t, "metric_in", "snapdc_in", i, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_out( topo, "snapin", t, "snapin_ct", t );
  }
  fd_topob_tile_out( topo, "snapin",  0UL,              "snapin_manif", 0UL                                       );

  fd_topo_tile_t * snapin_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ];
  fd_topob_tile_uses( topo, snapin_tile, txncache_obj,   FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topob_tile_uses( topo, accdb_tile,  accdb_obj,      FD_SHMEM_JOIN_MODE_READ_WRITE );
  FOR(snapin_tile_cnt) {
    fd_topo_tile_t * tile = &topo->tiles[ fd_topo_find_tile( topo, "snapin", i ) ];
    fd_topob_tile_uses( topo, tile, accdb_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, tile, shmem_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, tile, banks_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    tile->snapin.accdb_obj_id    = accdb_obj->id;
    tile->snapin.txncache_obj_id = txncache_obj->id;
    tile->snapin.banks_obj_id    = banks_obj->id;
    tile->snapin.shmem_obj_id    = shmem_obj->id;
    tile->snapin.max_live_slots  = config->firedancer.runtime.max_live_slots;
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  snapshot_load_layout( config, topo );
  fd_topob_waker( topo );
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
      "  --transpile \"<addr> ...\"  After loading, transpile these programs to x86\n"
      "  --transpile-list PATH  After loading, transpile programs listed in file\n"
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
  char const * transpile     = fd_env_strip_cmdline_cstr    ( pargc, pargv, "--transpile",      NULL, NULL );
  char const * transpile_list= fd_env_strip_cmdline_cstr    ( pargc, pargv, "--transpile-list", NULL, NULL );
  double       db_sz         = fd_env_strip_cmdline_double  ( pargc, pargv, "--db-sz",        NULL, 0.0    );
  double       db_rec_max    = fd_env_strip_cmdline_double  ( pargc, pargv, "--db-rec-max",   NULL, 0.0    );
  if( FD_UNLIKELY( !(db_sz>=0.0 && db_sz<1.8e19) ) )           FD_LOG_ERR(( "--db-sz out of range" ));      /* also rejects NaN */
  if( FD_UNLIKELY( !(db_rec_max>=0.0 && db_rec_max<1.8e19) ) ) FD_LOG_ERR(( "--db-rec-max out of range" ));

  fd_cstr_ncpy( args->snapshot_load.snapshot_dir, snapshot_dir, sizeof(args->snapshot_load.snapshot_dir) );
  args->snapshot_load.accounts_hist  = accounts_hist;
  args->snapshot_load.offline        = offline;
  args->snapshot_load.no_incremental = no_incremental;
  args->snapshot_load.no_watch       = no_watch;
  args->snapshot_load.db_rec_max     = (ulong)db_rec_max;
  args->snapshot_load.cache_sz       = (ulong)db_sz;
  args->snapshot_load.transpile      = transpile;
  args->snapshot_load.transpile_list = transpile_list;
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
  ulong chain_cnt                   = shmem->chain_cnt;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
                                  FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,           sizeof(fd_accdb_shmem_t)                                );
                                  FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)            );
                                  FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),           max_live_slots*descends_set_footprint( max_live_slots ) );
  uint *               acc_map  = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                  chain_cnt*sizeof(uint)                                  );
  fd_accdb_accmeta_t * acc_pool = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_accmeta_t),    max_accounts*sizeof(fd_accdb_accmeta_t)                 );

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

/* Transpile support **************************************************/

#define TRANSPILE_DIR "build/transpiled/x86"

struct transpile_list {
  fd_pubkey_t * addrs;
  ulong         cnt;
  ulong         max;
};
typedef struct transpile_list transpile_list_t;

/* transpile_list_add_cstr appends the whitespace separated base58
   addresses in cstr to list.  '#' starts a comment running to the end
   of the line.  Duplicates are dropped. */

static void
transpile_list_add_cstr( transpile_list_t * list,
                         char const *       cstr ) {
  char const * p = cstr;
  for(;;) {
    while( *p==' ' || *p=='\t' || *p=='\n' || *p=='\r' ) p++;
    if( !*p ) break;
    if( *p=='#' ) {
      while( *p && *p!='\n' ) p++;
      continue;
    }
    char const * tok = p;
    while( *p && *p!=' ' && *p!='\t' && *p!='\n' && *p!='\r' && *p!='#' ) p++;
    ulong tok_len = (ulong)( p-tok );

    char b58[ FD_BASE58_ENCODED_32_SZ ];
    fd_pubkey_t addr;
    if( FD_UNLIKELY( tok_len>=sizeof(b58) ) ) FD_LOG_ERR(( "invalid transpile address `%.*s`", (int)tok_len, tok ));
    fd_memcpy( b58, tok, tok_len );
    b58[ tok_len ] = '\0';
    if( FD_UNLIKELY( !fd_base58_decode_32( b58, addr.uc ) ) ) FD_LOG_ERR(( "invalid transpile address `%s`", b58 ));

    int dup = 0;
    for( ulong i=0UL; i<list->cnt; i++ ) dup |= fd_pubkey_eq( &list->addrs[ i ], &addr );
    if( dup ) continue;

    if( list->cnt==list->max ) {
      list->max   = fd_ulong_max( 2UL*list->max, 16UL );
      list->addrs = realloc( list->addrs, list->max*sizeof(fd_pubkey_t) );
      FD_TEST( list->addrs );
    }
    list->addrs[ list->cnt++ ] = addr;
  }
}

static void
transpile_list_add_file( transpile_list_t * list,
                         char const *       path ) {
  FILE * f = fopen( path, "r" );
  if( FD_UNLIKELY( !f ) ) FD_LOG_ERR(( "fopen(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  char line[ 4096 ];
  while( fgets( line, sizeof(line), f ) ) {
    ulong len = strlen( line );
    if( FD_UNLIKELY( len==sizeof(line)-1UL && line[ len-1UL ]!='\n' && !feof( f ) ) ) FD_LOG_ERR(( "line too long in %s", path ));
    transpile_list_add_cstr( list, line );
  }
  if( FD_UNLIKELY( ferror( f ) ) ) FD_LOG_ERR(( "failed to read %s", path ));
  fclose( f );
}

static void
mkdir_p( char const * path ) {
  char buf[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( buf, sizeof(buf), NULL, "%s", path ) );
  for( char * p=buf+1; ; p++ ) {
    if( *p=='/' || !*p ) {
      char c = *p;
      *p = '\0';
      if( FD_UNLIKELY( mkdir( buf, 0755 ) && errno!=EEXIST ) ) FD_LOG_ERR(( "mkdir(%s) failed (%i-%s)", buf, errno, fd_io_strerror( errno ) ));
      *p = c;
      if( !c ) break;
    }
  }
}

/* transpile_env_t holds state shared across programs: the loading
   environment at the snapshot slot and buffers sized for the largest
   possible program account. */

struct transpile_env {
  fd_accdb_t *            accdb;
  fd_accdb_fork_id_t      fork_id;
  fd_sbpf_loader_config_t config;
  fd_sbpf_syscalls_t *    syscalls;

  uchar *           prog;    /* FD_RUNTIME_ACC_SZ_MAX */
  uchar *           pd;      /* FD_RUNTIME_ACC_SZ_MAX */
  uchar *           rodata;  /* FD_RUNTIME_ACC_SZ_MAX */
  uchar *           scratch; /* FD_RUNTIME_ACC_SZ_MAX */
  void *            prog_mem;
  ulong             prog_mem_sz;
  fd_transpiler_t * t;
  uchar *           obj;
  ulong             obj_max;
};
typedef struct transpile_env transpile_env_t;

/* transpile_one resolves the program at addr, loads its ELF exactly
   like the program cache will at the snapshot slot, transpiles it, and
   writes the object to TRANSPILE_DIR.  Returns 0 on success.  On
   failure, logs warning and returns -1. */

static int
transpile_one( transpile_env_t *   env,
               fd_pubkey_t const * addr ) {
  FD_BASE58_ENCODE_32_BYTES( addr->uc, addr_b58 );

  fd_acc_t prog = {0};
  fd_memcpy( prog.pubkey, addr->uc, 32UL );
  prog.data = env->prog;
  fd_accdb_read_one_nocache( env->accdb, env->fork_id, addr->uc, &prog.lamports, &prog.executable, prog.owner, prog.data, &prog.data_len );
  if( FD_UNLIKELY( !prog.lamports ) ) {
    FD_LOG_WARNING(( "transpile %s: account not found", addr_b58 ));
    return -1;
  }

  /* Locate the account holding the ELF */

  fd_acc_t const * pd = &prog;
  fd_acc_t pd_acc = {0};
  if( fd_pubkey_eq( (fd_pubkey_t const *)prog.owner, &fd_solana_bpf_loader_upgradeable_program_id ) ) {
    fd_bpf_state_t state;
    if( FD_UNLIKELY( fd_bpf_loader_program_get_state2( prog.data, prog.data_len, &state ) ||
                     state.discriminant!=FD_BPF_STATE_PROGRAM ) ) {
      FD_LOG_WARNING(( "transpile %s: not a loader v3 program account", addr_b58 ));
      return -1;
    }
    fd_memcpy( pd_acc.pubkey, state.inner.program.programdata_address.uc, 32UL );
    pd_acc.data = env->pd;
    fd_accdb_read_one_nocache( env->accdb, env->fork_id, pd_acc.pubkey, &pd_acc.lamports, &pd_acc.executable, pd_acc.owner, pd_acc.data, &pd_acc.data_len );
    if( FD_UNLIKELY( !pd_acc.lamports ) ) {
      FD_LOG_WARNING(( "transpile %s: program data account not found", addr_b58 ));
      return -1;
    }
    pd = &pd_acc;
  }

  fd_prog_info_t info[1];
  if( FD_UNLIKELY( !fd_prog_info( info, pd ) ) ) {
    FD_LOG_WARNING(( "transpile %s: invalid program data account", addr_b58 ));
    return -1;
  }
  uchar const * bin    = pd->data + info->elf_off;
  ulong         bin_sz = info->elf_sz;

  fd_sbpf_elf_info_t elf_info;
  if( FD_UNLIKELY( fd_sbpf_elf_peek( &elf_info, bin, bin_sz, &env->config ) ) ) {
    FD_LOG_WARNING(( "transpile %s: invalid sBPF ELF", addr_b58 ));
    return -1;
  }
  if( FD_UNLIKELY( fd_sbpf_program_footprint( &elf_info )>env->prog_mem_sz ) ) {
    FD_LOG_WARNING(( "transpile %s: program too large", addr_b58 ));
    return -1;
  }
  fd_sbpf_program_t * sbpf = fd_sbpf_program_new( env->prog_mem, &elf_info, env->rodata );
  FD_TEST( sbpf );
  if( FD_UNLIKELY( fd_sbpf_program_load( sbpf, bin, bin_sz, env->syscalls, &env->config, env->scratch, FD_RUNTIME_ACC_SZ_MAX ) ) ) {
    FD_LOG_WARNING(( "transpile %s: failed to load sBPF program", addr_b58 ));
    return -1;
  }

  if( FD_UNLIKELY( fd_vm_transpile_prog( env->t, sbpf, env->syscalls ) ) ) {
    FD_LOG_WARNING(( "transpile %s: failed to transpile", addr_b58 ));
    return -1;
  }
  fd_memcpy( env->t->meta.prog_id, addr->uc, 32UL );
  fd_blake3_hash( bin, bin_sz, env->t->meta.elf_hash );

  ulong obj_sz = fd_transpiler_export_obj( env->t, env->syscalls, env->obj, env->obj_max );
  if( FD_UNLIKELY( !obj_sz ) ) {
    FD_LOG_WARNING(( "transpile %s: failed to export object", addr_b58 ));
    return -1;
  }

  /* Name matches what fd_transpiler_export_archive expects */

  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, TRANSPILE_DIR "/fd_transpiled_%s.o", addr_b58 ) );
  FILE * f = fopen( path, "wb" );
  int err = !f;
  if( f ) {
    err |= fwrite( env->obj, 1UL, obj_sz, f )!=obj_sz;
    err |= fclose( f )!=0;
  }
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "transpile %s: failed to write %s", addr_b58, path ));
    return -1;
  }
  FD_LOG_INFO(( "transpile %s: wrote %s (%lu bytes)", addr_b58, path, obj_sz ));
  return 0;
}

static void
transpile_programs( config_t *               config,
                    transpile_list_t const * list ) {
  fd_topo_t * topo = &config->topo;
  ulong accdb_obj_id = fd_pod_query_ulong( topo->props, "accdb", ULONG_MAX );
  FD_TEST( accdb_obj_id!=ULONG_MAX );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join( fd_topo_obj_laddr( topo, accdb_obj_id ) );
  FD_TEST( shmem );

  /* All tiles have shut down, so a private epoch slot suffices */
  ulong  epoch_slot = ULONG_MAX;
  void * ljoin = aligned_alloc( fd_accdb_align(), fd_ulong_align_up( fd_accdb_footprint( shmem->max_live_slots, 0 ), fd_accdb_align() ) );
  FD_TEST( ljoin );
  fd_accdb_t * accdb = fd_accdb_join_readonly( ljoin, shmem, &epoch_slot, FD_ACCDB_FD_RO );
  FD_TEST( accdb );
  fd_accdb_fork_id_t fork_id = shmem->root_fork_id;
  FD_TEST( fork_id.val!=USHORT_MAX );

  /* Load exactly like the program cache will at the snapshot slot (see
     fd_progcache_user.c).  snapshot-load does not populate the root
     bank slot, so take it from the clock sysvar. */
  ulong banks_obj_id = fd_pod_query_ulong( topo->props, "banks", ULONG_MAX );
  FD_TEST( banks_obj_id!=ULONG_MAX );
  fd_banks_t * banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  FD_TEST( banks );
  fd_sol_sysvar_clock_t clock[1];
  FD_TEST( fd_sysvar_clock_read( accdb, fork_id, clock ) );
  static fd_bank_t bank;
  memset( &bank, 0, sizeof(bank) );
  bank.f.features = fd_banks_root( banks )->f.features;
  bank.f.slot     = clock->slot;
  fd_prog_load_env_t load_env[1];
  fd_prog_load_env_from_bank( load_env, &bank );
  fd_prog_versions_t versions = fd_prog_versions( load_env->features, load_env->feature_slot );

  static fd_sbpf_syscalls_t syscalls_mem[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( syscalls_mem ) );
  FD_TEST( syscalls );
  FD_TEST( !fd_vm_syscall_register_slot( syscalls, load_env->feature_slot, load_env->features, 0 ) );

  fd_sbpf_elf_info_t max_info = { .calldests_max = FD_SBPF_TEXT_CNT_MAX };
  transpile_env_t env = {
    .accdb       = accdb,
    .fork_id     = fork_id,
    .config      = {
      .sbpf_min_version = versions.min_sbpf_version,
      .sbpf_max_version = versions.max_sbpf_version
    },
    .syscalls    = syscalls,
    .prog        = malloc( FD_RUNTIME_ACC_SZ_MAX ),
    .pd          = malloc( FD_RUNTIME_ACC_SZ_MAX ),
    .rodata      = malloc( FD_RUNTIME_ACC_SZ_MAX ),
    .scratch     = malloc( FD_RUNTIME_ACC_SZ_MAX ),
    .prog_mem_sz = fd_sbpf_program_footprint( &max_info ),
    .t           = aligned_alloc( 64UL, sizeof(fd_transpiler_t) ),
    .obj_max     = 4UL*FD_TRANSPILER_CODE_MAX
  };
  env.prog_mem = aligned_alloc( fd_sbpf_program_align(), fd_ulong_align_up( env.prog_mem_sz, fd_sbpf_program_align() ) );
  env.obj      = malloc( env.obj_max );
  FD_TEST( env.prog && env.pd && env.rodata && env.scratch && env.prog_mem && env.t && env.obj );

  mkdir_p( TRANSPILE_DIR );

  long  start  = fd_log_wallclock();
  ulong ok_cnt = 0UL;
  for( ulong i=0UL; i<list->cnt; i++ ) {
    if( !transpile_one( &env, &list->addrs[ i ] ) ) ok_cnt++;
  }
  if( FD_UNLIKELY( fd_transpiler_export_archive( TRANSPILE_DIR ) ) ) {
    FD_LOG_ERR(( "failed to write " TRANSPILE_DIR "/libfd_transpiled.a" ));
  }
  FD_LOG_NOTICE(( "transpiled %lu/%lu programs in %.3f s into " TRANSPILE_DIR "/libfd_transpiled.a",
                  ok_cnt, list->cnt, (double)( fd_log_wallclock()-start )/1e9 ));

  free( env.obj );
  free( env.t );
  free( env.prog_mem );
  free( env.scratch );
  free( env.rodata );
  free( env.pd );
  free( env.prog );
  free( ljoin );
}

/* fixup_config applies command-line arguments to config, overriding
   defaults / config file */

static void
fixup_config( config_t *     config,
              args_t const * args ) {
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
}

static void
snapshot_load_cmd_fn( args_t *   args,
                      config_t * config ) {
  fixup_config( config, args );

  transpile_list_t transpile_list = {0};
  if( args->snapshot_load.transpile      ) transpile_list_add_cstr( &transpile_list, args->snapshot_load.transpile      );
  if( args->snapshot_load.transpile_list ) transpile_list_add_file( &transpile_list, args->snapshot_load.transpile_list );

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
  initialize_stake_delegations_fd( config );
  initialize_store_fds( config );
  initialize_snapshot_fds( config );

  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( topo );

  fd_topo_tile_t * snapct_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapct", 0UL ) ];
  fd_topo_tile_t * snapld_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapld", 0UL ) ];
  ulong snapdc_tile_cnt = config->firedancer.layout.snapdc_tile_count;
  ulong snapin_tile_cnt = config->firedancer.layout.snapin_tile_count;
  FD_TEST( snapin_tile_cnt<=FD_TOPO_MAX_TILE_IN_LINKS );

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  double ns_per_tick = 1.0/tick_per_ns;

  long start = fd_log_wallclock();
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  ulong volatile * const snapct_metrics = fd_metrics_tile( snapct_tile->metrics );
  ulong volatile * const snapld_metrics = fd_metrics_tile( snapld_tile->metrics );
  ulong volatile *       snapin_all_metrics[ FD_TOPO_MAX_TILE_IN_LINKS ];
  for( ulong i=0UL; i<snapin_tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ fd_topo_find_tile( topo, "snapin", i ) ];
    snapin_all_metrics[ i ] = fd_metrics_tile( tile->metrics );
  }
  ulong volatile *       snapdc_metrics[ FD_TOPO_MAX_TILE_IN_LINKS ];
  for( ulong i=0UL; i<snapdc_tile_cnt; i++ ) {
    fd_topo_tile_t * snapdc_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapdc", i ) ];
    snapdc_metrics[ i ] = fd_metrics_tile( snapdc_tile->metrics );
  }

  ulong total_off_old    = 0UL;
  ulong decomp_off_old   = 0UL;
  ulong snapld_wait_old  = 0UL;
  ulong snapdc_wait_old[ FD_TOPO_MAX_TILE_IN_LINKS ] = {0};
  ulong snapin_wait_old[ FD_TOPO_MAX_TILE_IN_LINKS ] = {0};
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
    int snapin_shutdown = 1;
    for( ulong i=0UL; i<snapin_tile_cnt; i++ ) {
      snapin_shutdown &= FD_VOLATILE_CONST( snapin_all_metrics[ i ][ MIDX( GAUGE, TILE, STATUS ) ] )==2UL;
    }
    int snapdc_shutdown = 1;
    for( ulong i=0UL; i<snapdc_tile_cnt; i++ ) {
      snapdc_shutdown &= FD_VOLATILE_CONST( snapdc_metrics[ i ][ MIDX( GAUGE, TILE, STATUS ) ] )==2UL;
    }

    if( FD_UNLIKELY( snapct_status==2UL && snapld_status==2UL && snapdc_shutdown && snapin_shutdown ) ) break;

    long cur = fd_log_wallclock();
    if( FD_UNLIKELY( cur<next ) ) {
      long sleep_nanos = fd_long_min( 1000L*1000L, next-cur );
      FD_TEST( !fd_sys_util_nanosleep(  (uint)(sleep_nanos/(1000L*1000L*1000L)), (uint)(sleep_nanos%(1000L*1000L*1000L)) ) );
      continue;
    }

    ulong total_off    = snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_READ ) ] +
                         snapct_metrics[ MIDX( GAUGE, SNAPCT, INCREMENTAL_BYTES_READ ) ];
    ulong decomp_off   = 0UL;
    ulong snapdc_wait[ FD_TOPO_MAX_TILE_IN_LINKS ];
    for( ulong i=0UL; i<snapdc_tile_cnt; i++ ) {
      decomp_off += snapdc_metrics[ i ][ MIDX( GAUGE, SNAPDC, FULL_DECOMPRESSED_BYTES_WRITTEN ) ] +
                    snapdc_metrics[ i ][ MIDX( GAUGE, SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_WRITTEN ) ];
      snapdc_wait[ i ] = snapdc_metrics[ i ][ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) ]
                       + snapdc_metrics[ i ][ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_SLEEPING ) ]
                       + snapdc_metrics[ i ][ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ]
                       + snapdc_metrics[ i ][ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_SLEEPING ) ];
    }
    /* Waiting on either neighbor counts as not busy */
    ulong snapld_wait  = snapld_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) ]
                       + snapld_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_SLEEPING ) ]
                       + snapld_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ]
                       + snapld_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_SLEEPING ) ];
    ulong snapin_wait[ FD_TOPO_MAX_TILE_IN_LINKS ];
    ulong acc_cnt     = 0UL;
    for( ulong i=0UL; i<snapin_tile_cnt; i++ ) {
      ulong volatile * metrics = snapin_all_metrics[ i ];
      snapin_wait[ i ] = metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG ) ]
                       + metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_SLEEPING ) ]
                       + metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ]
                       + metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_SLEEPING ) ];
      acc_cnt += metrics[ MIDX( GAUGE, SNAPIN, ACCOUNT_LOADED ) ];
    }

    char const * phase = phase_cstr( snapct_metrics[ MIDX( GAUGE, SNAPCT, STATE ) ] );
    ulong consumed, dc_in, dc_out, size_bytes;
    if( FD_UNLIKELY( !strcmp( phase, "incr" ) ) ) {
      consumed   = ULONG_MAX;
      for( ulong i=0UL; i<snapin_tile_cnt; i++ ) consumed = fd_ulong_min( consumed, snapin_all_metrics[ i ][ MIDX( GAUGE, SNAPIN, INCREMENTAL_BYTES_READ ) ] );
      dc_in      = 0UL;
      dc_out     = 0UL;
      for( ulong i=0UL; i<snapdc_tile_cnt; i++ ) {
        dc_in  += snapdc_metrics[ i ][ MIDX( GAUGE, SNAPDC, INCREMENTAL_COMPRESSED_BYTES_READ ) ];
        dc_out += snapdc_metrics[ i ][ MIDX( GAUGE, SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_WRITTEN ) ];
      }
      size_bytes = snapct_metrics[ MIDX( GAUGE, SNAPCT, INCREMENTAL_SIZE_BYTES ) ];
    } else {
      consumed   = ULONG_MAX;
      for( ulong i=0UL; i<snapin_tile_cnt; i++ ) consumed = fd_ulong_min( consumed, snapin_all_metrics[ i ][ MIDX( GAUGE, SNAPIN, FULL_BYTES_READ ) ] );
      dc_in      = 0UL;
      dc_out     = 0UL;
      for( ulong i=0UL; i<snapdc_tile_cnt; i++ ) {
        dc_in  += snapdc_metrics[ i ][ MIDX( GAUGE, SNAPDC, FULL_COMPRESSED_BYTES_READ ) ];
        dc_out += snapdc_metrics[ i ][ MIDX( GAUGE, SNAPDC, FULL_DECOMPRESSED_BYTES_WRITTEN ) ];
      }
      size_bytes = snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_SIZE_BYTES ) ];
    }
    double done_comp = dc_out ? (double)dc_in*( (double)consumed/(double)dc_out ) : 0.0;
    double progress  = size_bytes ? clamp_pct( 100.0*done_comp/(double)size_bytes ) : 0.0;

    if( watch ) {
      double snapdc_busy[ FD_TOPO_MAX_TILE_IN_LINKS ];
      double snapdc_busy_avg = 0.0;
      for( ulong i=0UL; i<snapdc_tile_cnt; i++ ) {
        snapdc_busy[ i ] = clamp_pct( 100.0-( ( (double)( snapdc_wait[ i ]-snapdc_wait_old[ i ] )*ns_per_tick )/1e7 ) );
        snapdc_busy_avg += snapdc_busy[ i ];
      }
      snapdc_busy_avg /= (double)snapdc_tile_cnt;

      double snapin_busy[ FD_TOPO_MAX_TILE_IN_LINKS ];
      double snapin_busy_avg = 0.0;
      for( ulong i=0UL; i<snapin_tile_cnt; i++ ) {
        snapin_busy[ i ] = clamp_pct( 100.0-( ( (double)( snapin_wait[ i ]-snapin_wait_old[ i ] )*ns_per_tick )/1e7 ) );
        snapin_busy_avg += snapin_busy[ i ];
      }
      snapin_busy_avg /= (double)snapin_tile_cnt;

      double busy[ 3 ] = {
        clamp_pct( 100.0-( ( (double)( snapld_wait-snapld_wait_old )*ns_per_tick )/1e7 ) ),
        snapdc_busy_avg,
        snapin_busy_avg,
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
              c_dim, c_norm, (double)fd_ulong_sat_sub( acc_cnt, acc_cnt_old )/1e6, c_dim, c_norm );

      static char const * tile_key[ 3 ] = { "ld", "dc(avg)", "in(avg)" };
      printf( "  %sbusy%s", c_dim, c_norm );
      for( ulong i=0UL; i<3UL; i++ ) {
        printf( " %s%s%s %s%3.0f%s%%%s",
                c_dim, tile_key[ i ], c_norm,
                sev_color( color, busy[ i ] ), busy[ i ], c_dim, c_norm );
      }
      for( ulong i=0UL; i<snapdc_tile_cnt; i++ ) {
        printf( " %sdc%lu%s %s%3.0f%s%%%s",
                c_dim, i, c_norm,
                sev_color( color, snapdc_busy[ i ] ), snapdc_busy[ i ], c_dim, c_norm );
      }
      for( ulong i=0UL; i<snapin_tile_cnt; i++ ) {
        printf( " %sin%lu%s %s%3.0f%s%%%s",
                c_dim, i, c_norm,
                sev_color( color, snapin_busy[ i ] ), snapin_busy[ i ], c_dim, c_norm );
      }
      printf( "\n" );
      fflush( stdout );
    }
    total_off_old    = total_off;
    decomp_off_old   = decomp_off;
    snapld_wait_old  = snapld_wait;
    for( ulong i=0UL; i<snapdc_tile_cnt; i++ ) {
      snapdc_wait_old[ i ] = snapdc_wait[ i ];
    }
    for( ulong i=0UL; i<snapin_tile_cnt; i++ ) {
      snapin_wait_old[ i ] = snapin_wait[ i ];
    }
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

  if( transpile_list.cnt ) transpile_programs( config, &transpile_list );
  free( transpile_list.addrs );
}

static void
snapshot_load_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--snapshot-dir",   "<path>",  "Load/save snapshots from this directory" );
  fd_action_help_arg( help, "--offline",        NULL,      "Do not attempt to download snapshots" );
  fd_action_help_arg( help, "--no-incremental", NULL,      "Disable incremental snapshot loading" );
  fd_action_help_arg( help, "--no-watch",       NULL,      "Do not print periodic progress updates" );
  fd_action_help_arg( help, "--db-sz",          "<bytes>", "Accounts cache size in bytes (e.g. 10e9 -> 10 GB)" );
  fd_action_help_arg( help, "--db-rec-max",     "<num>",   "Database max record/account count (e.g. 10e6 -> 10M accounts)" );
  fd_action_help_arg( help, "--fsck",           NULL,      "After loading, run database integrity checks" );
  fd_action_help_arg( help, "--accounts-hist",  NULL,      "After loading, analyze account size distribution" );
  fd_action_help_arg( help, "--transpile",      "\"<addr> ...\"", "After loading, transpile these programs to x86 objects" );
  fd_action_help_arg( help, "--transpile-list", "<path>",  "After loading, transpile the programs listed in this file" );
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
