#include "../../firedancer/topology.h"
#include "../../platform/fd_sys_util.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../shared_dev/commands/dev.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/tile/fd_tile_private.h"
#include "../../../discof/restore/utils/fd_ssctrl.h"
#include "../../../discof/restore/utils/fd_ssmsg.h"

#include <sys/resource.h>
#include <linux/capability.h>
#include <unistd.h>
#include <stdio.h>

#define NAME "snapshot-load"

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

static void
snapshot_load_topo( config_t *     config,
                    args_t const * args ) {
  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size   = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );
  ulong snaplt_tile_cnt = config->firedancer.layout.snaplt_tile_count;
  int snaplt_disabled   = config->development.snapshots.disable_lthash_verification;

  fd_topob_wksp( topo, "funk" );
  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions,
      config->firedancer.funk.heap_size_gib,
      config->firedancer.funk.lock_pages );

  static ushort tile_to_cpu[ FD_TILE_MAX ] = {0};
  if( args->snapshot_load.tile_cpus[0] ) {
    ulong cpu_cnt = fd_tile_private_cpus_parse( args->snapshot_load.tile_cpus, tile_to_cpu );
    if( FD_UNLIKELY( cpu_cnt<4UL + (snaplt_disabled?0:snaplt_tile_cnt) ) ) FD_LOG_ERR(( "--tile-cpus specifies %lu CPUs, but need at least %lu", cpu_cnt, 4UL + (snaplt_disabled?snaplt_tile_cnt:0) ));
  }

  /* metrics tile *****************************************************/
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "metric" );
  fd_topob_tile( topo, "metric",  "metric", "metric_in", tile_to_cpu[0], 0, 0 );

  /* read() tile */
  fd_topob_wksp( topo, "snaprd" );
  fd_topo_tile_t * snaprd_tile = fd_topob_tile( topo, "snaprd", "snaprd", "snaprd", tile_to_cpu[1], 0, 0 );
  snaprd_tile->allow_shutdown = 1;

  /* "snapdc": Zstandard decompress tile */
  fd_topob_wksp( topo, "snapdc" );
  fd_topo_tile_t * snapdc_tile = fd_topob_tile( topo, "snapdc", "snapdc", "snapdc", tile_to_cpu[2], 0, 0 );
  snapdc_tile->allow_shutdown = 1;

  /* Compressed data stream */
  fd_topob_wksp( topo, "snap_zstd" );
  fd_topob_link( topo, "snap_zstd", "snap_zstd", 8192UL, 16384, 1UL );

  /* Uncompressed data stream */
  fd_topob_wksp( topo, "snap_stream" );
  fd_topob_link( topo, "snap_stream", "snap_stream", 2048UL, USHORT_MAX, 1UL );

  /* snaprd tile -> compressed stream */
  fd_topob_tile_out( topo, "snaprd", 0UL, "snap_zstd", 0UL );

  /* compressed stream -> snapdc tile */
  fd_topob_tile_in( topo, "snapdc", 0UL, "metric_in", "snap_zstd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  /* snapdc tile -> uncompressed stream */
  fd_topob_tile_out( topo, "snapdc", 0UL, "snap_stream", 0UL );

  /* "snapin": Snapshot parser tile */
  fd_topob_wksp( topo, "snapin" );
  fd_topo_tile_t * snapin_tile = fd_topob_tile( topo, "snapin", "snapin", "snapin", tile_to_cpu[3], 0, 0 );
  snapin_tile->allow_shutdown = 1;

  if( FD_LIKELY( !snaplt_disabled ) ) {
    fd_topob_wksp( topo, "snaplt" );
    fd_topob_wksp( topo, "snapin_lt" );
    fd_topob_wksp( topo, "snaplt_out" );
    fd_topob_wksp( topo, "snaplt_rd" );

    #define FOR(cnt) for( ulong i=0UL; i<cnt; i++ )
    for( ulong i=0UL; i<snaplt_tile_cnt; i++ ) {
      fd_topo_tile_t * snaplt_tile = fd_topob_tile( topo, "snaplt", "snaplt", "metric_in", tile_to_cpu[4 + i], 0, 0 );
      snaplt_tile->allow_shutdown = 1;
    }
  }

  if( FD_LIKELY( !snaplt_disabled ) ) {
                         fd_topob_link( topo, "snapin_lt",  "snapin_lt",  128UL, sizeof(fd_snapshot_existing_account_t), 1UL );
    FOR(snaplt_tile_cnt) fd_topob_link( topo, "snaplt_out", "snaplt_out", 128UL, 2048UL,                                 1UL );
    FOR(snaplt_tile_cnt) fd_topob_link( topo, "snaplt_rd",  "snaplt_rd",  128UL, 0UL,                                    1UL );
  }

  /* uncompressed stream -> snapin tile */
  fd_topob_tile_in  ( topo, "snapin", 0UL, "metric_in", "snap_stream", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  /* snapin funk access */
  fd_topob_tile_uses( topo, snapin_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  snapin_tile->snapin.funk_obj_id = funk_obj->id;

  /* snapshot manifest out link */
  fd_topob_wksp( topo, "snap_out" );
  fd_topo_link_t * snap_out_link = fd_topob_link( topo, "snap_out", "snap_out", 4UL, sizeof(fd_snapshot_manifest_t), 1UL );
  snap_out_link->permit_no_consumers = 1;
  fd_topob_tile_out( topo, "snapin", 0UL, "snap_out", 0UL );

  fd_topob_link( topo, "snapdc_rd", "snap_zstd", 128UL, 0UL, 1UL );
  fd_topob_tile_in( topo, "snaprd", 0UL, "metric_in", "snapdc_rd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapdc", 0UL, "snapdc_rd", 0UL );

  fd_topob_wksp( topo, "snapin_rd" );
  fd_topob_link( topo, "snapin_rd", "snapin_rd", 128UL, 0UL, 1UL );
  fd_topob_tile_in( topo, "snaprd", 0UL, "metric_in", "snapin_rd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapin", 0UL, "snapin_rd", 0UL );

  if( FD_LIKELY( !snaplt_disabled ) ) {
                         fd_topob_tile_out( topo, "snapin", 0UL, "snapin_lt",  0UL );
    FOR(snaplt_tile_cnt) fd_topob_tile_in(  topo, "snapin", 0UL, "metric_in",  "snaplt_out", i,   FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    FOR(snaplt_tile_cnt) fd_topob_tile_in(  topo, "snaplt", i,   "metric_in",  "snapin_lt",  0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    FOR(snaplt_tile_cnt) fd_topob_tile_in ( topo, "snaprd", 0UL, "metric_in",  "snaplt_rd",  i,   FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    FOR(snaplt_tile_cnt) fd_topob_tile_out( topo, "snaplt", i,   "snaplt_out", i );
    FOR(snaplt_tile_cnt) fd_topob_tile_out( topo, "snaplt", i,   "snaplt_rd",  i );
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  /* No need for diagnostics, this is a diagnostic tool which prints on
     its own. */
  snaprd_tile->snaprd.diagnostics = 0;

  if( !args->snapshot_load.tile_cpus[0] ) {
    fd_topob_auto_layout( topo, 0 );
  }
  fd_topob_finish( topo, CALLBACKS );
}

static void
snapshot_load_cmd_args( int *    pargc,
                        char *** pargv,
                        args_t * args ) {
  char const * tile_cpus                = fd_env_strip_cmdline_cstr( pargc, pargv,  "--tile-cpus",     "FD_TILE_CPUS", NULL );

  if( tile_cpus ) {
    ulong tile_cpus_strlen = strlen( tile_cpus );
    if( FD_UNLIKELY( tile_cpus_strlen>=sizeof(args->snapshot_load.tile_cpus) ) ) FD_LOG_ERR(( "--tile-cpus: flag too long" ));
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->snapshot_load.tile_cpus ), tile_cpus, tile_cpus_strlen ) );
  }
}

extern int * fd_log_private_shared_lock;

static void
snapshot_load_cmd_fn( args_t *   args,
                      config_t * config ) {
  snapshot_load_topo( config, args );
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

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  double ns_per_tick = 1.0/tick_per_ns;

  long start = fd_log_wallclock();
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  fd_topo_tile_t * snaprd_tile = &topo->tiles[ fd_topo_find_tile( topo, "snaprd", 0UL ) ];
  fd_topo_tile_t * snapdc_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapdc", 0UL ) ];
  fd_topo_tile_t * snapin_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ];

  ulong volatile * snaplt_metrics[ FD_MAX_SNAPLT_TILES ];
  ulong snaplt_tile_cnt = fd_topo_tile_name_cnt( topo, "snaplt" );

  for( ulong i=0UL; i<snaplt_tile_cnt; i++ ) {
    ulong snaplt_tile_idx = fd_topo_find_tile( topo, "snaplt", i );
    FD_TEST( snaplt_tile_idx!=ULONG_MAX );
    fd_topo_tile_t * snaplt_tile = &topo->tiles[ snaplt_tile_idx ];
    snaplt_metrics[ i ]          = fd_metrics_tile( snaplt_tile->metrics );
  }

  ulong volatile * const snaprd_metrics = fd_metrics_tile( snaprd_tile->metrics );
  ulong volatile * const snapdc_metrics = fd_metrics_tile( snapdc_tile->metrics );
  ulong volatile * const snapin_metrics = fd_metrics_tile( snapin_tile->metrics );

  ulong total_off_old    = 0UL;
  ulong snaprd_backp_old = 0UL;
  ulong snaprd_wait_old  = 0UL;
  ulong snapdc_backp_old = 0UL;
  ulong snapdc_wait_old  = 0UL;
  ulong snapin_backp_old = 0UL;
  ulong snapin_wait_old  = 0UL;
  ulong snaplt_backp_old = 0UL;
  ulong snaplt_wait_old  = 0UL;
  ulong acc_cnt_old      = 0UL;
  sleep( 1 );
  puts( "" );
  puts( "Columns:" );
  puts( "- bw:    Uncompressed bandwidth" );
  puts( "- backp: Backpressured by downstream tile" );
  puts( "- stall: Waiting on upstream tile"         );
  puts( "- acc:   Number of accounts"               );
  puts( "" );
  puts( "-------------backp=(snaprd,snapdc,snapin,snaplt) busy=(snaprd,snapdc,snapin,snaplt)---------------" );
  long next = start+1000L*1000L*1000L;
  for(;;) {
    ulong snaprd_status = FD_VOLATILE_CONST( snaprd_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapdc_status = FD_VOLATILE_CONST( snapdc_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapin_status = FD_VOLATILE_CONST( snapin_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snaplt_status = ULONG_MAX;

    ulong snaplt_status_sum = 0UL;
    for( ulong i=0UL; i<snaplt_tile_cnt; i++ ) {
      ulong snaplt_status = FD_VOLATILE_CONST( snaplt_metrics[ i ][ MIDX( GAUGE, TILE, STATUS ) ] );
      snaplt_status_sum  += snaplt_status;
    }
    if( FD_UNLIKELY( snaplt_status_sum==2UL*snaplt_tile_cnt ) ) snaplt_status = 2UL;
    else                                                        snaplt_status = snaplt_tile_cnt>0UL ? 1UL : 2UL;

    if( FD_UNLIKELY( snaprd_status==2UL && snapdc_status==2UL && snapin_status == 2UL && snaplt_status==2UL ) ) break;

    long cur = fd_log_wallclock();
    if( FD_UNLIKELY( cur<next ) ) {
      long sleep_nanos = fd_long_min( 1000L*1000L, next-cur );
      FD_TEST( !fd_sys_util_nanosleep(  (uint)(sleep_nanos/(1000L*1000L*1000L)), (uint)(sleep_nanos%(1000L*1000L*1000L)) ) );
      continue;
    }

    ulong total_off    = snaprd_metrics[ MIDX( GAUGE, SNAPRD, FULL_BYTES_READ ) ] +
                         snaprd_metrics[ MIDX( GAUGE, SNAPRD, INCREMENTAL_BYTES_READ ) ];
    ulong snaprd_backp = snaprd_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snaprd_wait  = snaprd_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snaprd_backp;
    ulong snapdc_backp = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapdc_wait  = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapdc_backp;
    ulong snapin_backp = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapin_wait  = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapin_backp;
    ulong snaplt_backp = 0UL;
    ulong snaplt_wait  = 0UL;

    for( ulong i=0UL; i<snaplt_tile_cnt; i++ ) {
      snaplt_backp += snaplt_metrics[ i ][ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    }
    for( ulong i=0UL; i<snaplt_tile_cnt; i++ ) {
      snaplt_wait  += snaplt_metrics[ i ][ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snaplt_backp;
    }

    double progress         = 100.0 * (double)snaprd_metrics[ MIDX( GAUGE, SNAPRD, FULL_BYTES_READ ) ] / (double)snaprd_metrics[ MIDX( GAUGE, SNAPRD, FULL_BYTES_TOTAL ) ];
    double snaplt_backp_val = snaplt_tile_cnt ? ((double)(snaplt_backp-snaplt_backp_old)*ns_per_tick)/1e7/(double)snaplt_tile_cnt : 0.0;
    double snaplt_busy_val  = snaplt_tile_cnt ? 100-(((double)( snaplt_wait-snaplt_wait_old)*ns_per_tick)/1e7/(double)snaplt_tile_cnt) : 0.0;
    ulong  acc_cnt          = snapin_metrics[ MIDX( GAUGE, SNAPIN, ACCOUNTS_INSERTED ) ];

    printf( "%.1f %% bw=%4.0f MB/s backp=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%) busy=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%) acc=%3.1f M/s\n",
            progress,
            (double)( total_off-total_off_old )/1e6,
            ( (double)( snaprd_backp-snaprd_backp_old )*ns_per_tick )/1e7,
            ( (double)( snapdc_backp-snapdc_backp_old )*ns_per_tick )/1e7,
            ( (double)( snapin_backp-snapin_backp_old )*ns_per_tick )/1e7,
            snaplt_backp_val,
            100-( ( (double)( snaprd_wait-snaprd_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snapdc_wait-snapdc_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snapin_wait-snapin_wait_old  )*ns_per_tick )/1e7 ),
            snaplt_busy_val,
            (double)( acc_cnt-acc_cnt_old  )/1e6 );
    fflush( stdout );
    total_off_old    = total_off;
    snaprd_backp_old = snaprd_backp;
    snaprd_wait_old  = snaprd_wait;
    snapdc_backp_old = snapdc_backp;
    snapdc_wait_old  = snapdc_wait;
    snapin_backp_old = snapin_backp;
    snapin_wait_old  = snapin_wait;
    snaplt_backp_old = snaplt_backp;
    snaplt_wait_old  = snaplt_wait;
    acc_cnt_old      = acc_cnt;

    next+=1000L*1000L*1000L;
  }
}

action_t fd_action_snapshot_load = {
  .name = NAME,
  .args = snapshot_load_cmd_args,
  .perm = dev_cmd_perm,
  .fn   = snapshot_load_cmd_fn
};
