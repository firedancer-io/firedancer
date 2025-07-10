#include "../../firedancer/topology.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../util/tile/fd_tile_private.h"
#include "../../../discof/restore/utils/fd_snapshot_messages.h"
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
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "funk" );
  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions,
      config->firedancer.funk.heap_size_gib );

  static ushort tile_to_cpu[ FD_TILE_MAX ] = {0};
  if( args->snapshot_load.tile_cpus[0] ) {
    ulong cpu_cnt = fd_tile_private_cpus_parse( args->snapshot_load.tile_cpus, tile_to_cpu );
    if( FD_UNLIKELY( cpu_cnt<4UL ) ) FD_LOG_ERR(( "--tile-cpus specifies %lu CPUs, but need at least 4", cpu_cnt ));
  }

  /* metrics tile *****************************************************/
  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "metric" );
  fd_topob_tile( topo, "metric",  "metric", "metric_in", tile_to_cpu[0], 0, 0 );

  /* shared dcache between snapin and replay to store the decoded solana
     manifest */
  fd_topob_wksp( topo, "replay_manif" );
  fd_topo_obj_t * replay_manifest_dcache = fd_topob_obj( topo, "dcache", "replay_manif" );
  fd_pod_insertf_ulong( topo->props, 1UL << 30UL, "obj.%lu.data_sz", replay_manifest_dcache->id );
  fd_pod_insert_ulong(  topo->props, "manifest_dcache", replay_manifest_dcache->id );

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
  fd_topob_link( topo, "snap_zstd", "snap_zstd", 512UL, 16384, 1UL );

  /* Uncompressed data stream */
  fd_topob_wksp( topo, "snap_stream" );
  fd_topob_link( topo, "snap_stream", "snap_stream", 512UL, USHORT_MAX, 1UL );

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

  /* uncompressed stream -> snapin tile */
  fd_topob_tile_in  ( topo, "snapin", 0UL, "metric_in", "snap_stream", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  /* snapin funk access */
  fd_topob_tile_uses( topo, snapin_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  snapin_tile->snapin.funk_obj_id = funk_obj->id;

  /* snapin replay manifest dcache access */
  fd_topob_tile_uses( topo, snapin_tile, replay_manifest_dcache, FD_SHMEM_JOIN_MODE_READ_WRITE );
  snapin_tile->snapin.manifest_dcache_obj_id = replay_manifest_dcache->id;

  /* snapshot manifest out link */
  fd_topob_wksp( topo, "snap_out" );
  fd_topo_link_t * snap_out_link = fd_topob_link( topo, "snap_out", "snap_out",   128UL, sizeof(fd_snapshot_manifest_t), 1UL );
  /* snapshot load topology doesn't consume from snap out link */
  snap_out_link->permit_no_consumers = 1;
  fd_topob_tile_out( topo, "snapin", 0UL, "snap_out", 0UL );

  fd_topob_link( topo, "snapdc_rd", "snap_zstd", 128UL, 0UL, 1UL );
  fd_topob_tile_in( topo, "snaprd", 0UL, "metric_in", "snapdc_rd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapdc", 0UL, "snapdc_rd", 0UL );

  fd_topob_wksp( topo, "snapin_rd" );
  fd_topob_link( topo, "snapin_rd", "snapin_rd", 128UL, 0UL, 1UL );
  fd_topob_tile_in( topo, "snaprd", 0UL, "metric_in", "snapin_rd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "snapin", 0UL, "snapin_rd", 0UL );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( !fd_topo_configure_tile( tile, config ) ) {
      FD_LOG_ERR(( "unknown tile name %lu `%s`", i, tile->name ));
    }
  }

  if( !args->snapshot_load.tile_cpus[0] ) {
    fd_topob_auto_layout( topo, 0 );
  }
  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
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

static void
snapshot_load_cmd_perm( args_t *         args,
                        fd_cap_chk_t *   chk,
                        config_t const * config ) {
  (void)args;
  ulong mlock_limit = fd_topo_mlock_max_tile( &config->topo );
  fd_cap_chk_raise_rlimit( chk, NAME, RLIMIT_MEMLOCK, mlock_limit, "call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`" );
  fd_cap_chk_raise_rlimit( chk, NAME, RLIMIT_NICE,    40,          "call `setpriority(2)` to increase thread priorities" );
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

  run_firedancer_init( config, 1 );

  fd_log_private_shared_lock[ 1 ] = 0;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  double ns_per_tick = 1.0/tick_per_ns;


  long start = fd_log_wallclock();
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  fd_topo_tile_t * snaprd_tile = &topo->tiles[ fd_topo_find_tile( topo, "snaprd", 0UL ) ];
  fd_topo_tile_t * snapdc_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapdc", 0UL ) ];
  fd_topo_tile_t * snapin_tile = &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ];

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
  ulong acc_cnt_old      = 0UL;
  sleep( 1 );
  puts( "" );
  puts( "Columns:" );
  puts( "- bw:    Uncompressed bandwidth" );
  puts( "- backp: Backpressured by downstream tile" );
  puts( "- stall: Waiting on upstream tile"         );
  puts( "- acc:   Number of accounts"               );
  puts( "" );
  puts( "-------------backp=(snaprd,snapdc,snapin) busy=(snaprd,snapdc,snapin)---------------" );
  for(;;) {
    ulong snaprd_status = FD_VOLATILE_CONST( snaprd_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapdc_status = FD_VOLATILE_CONST( snapdc_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapin_status = FD_VOLATILE_CONST( snapin_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );

    if( FD_UNLIKELY( snaprd_status==2UL && snapdc_status==2UL && snapin_status == 2UL ) ) break;

    ulong total_off    = snaprd_metrics[ MIDX( GAUGE, SNAPRD, FULL_BYTES_READ ) ] +
                         snaprd_metrics[ MIDX( GAUGE, SNAPRD, INCREMENTAL_BYTES_READ ) ];
    ulong snaprd_backp = snaprd_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snaprd_wait  = snaprd_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG    ) ] +
                         snaprd_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snaprd_backp;
    ulong snapdc_backp = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapdc_wait  = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG    ) ] +
                         snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapdc_backp;
    ulong snapin_backp = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapin_wait  = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG    ) ] +
                         snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapin_backp;

    ulong acc_cnt      = snapin_metrics[ MIDX( GAUGE, SNAPIN, ACCOUNTS_INSERTED    ) ];
    printf( "bw=%4.0f MB/s backp=(%3.0f%%,%3.0f%%,%3.0f%%) busy=(%3.0f%%,%3.0f%%,%3.0f%%) acc=%3.1f M/s\n",
            (double)( total_off-total_off_old )/1e6,
            ( (double)( snaprd_backp-snaprd_backp_old )*ns_per_tick )/1e7,
            ( (double)( snapdc_backp-snapdc_backp_old )*ns_per_tick )/1e7,
            ( (double)( snapin_backp-snapin_backp_old )*ns_per_tick )/1e7,
            100-( ( (double)( snaprd_wait-snaprd_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snapdc_wait-snapdc_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snapin_wait-snapin_wait_old  )*ns_per_tick )/1e7 ),
            (double)( acc_cnt-acc_cnt_old  )/1e6 );
    fflush( stdout );
    total_off_old    = total_off;
    snaprd_backp_old = snaprd_backp;
    snaprd_wait_old  = snaprd_wait;
    snapdc_backp_old = snapdc_backp;
    snapdc_wait_old  = snapdc_wait;
    snapin_backp_old = snapin_backp;
    snapin_wait_old  = snapin_wait;
    acc_cnt_old      = acc_cnt;
    sleep( 1 );
  }

  long end = fd_log_wallclock();
  FD_LOG_NOTICE(( "Loaded %.1fM accounts in %.1f seconds", (double)snapin_metrics[ MIDX( GAUGE, SNAPIN, ACCOUNTS_INSERTED ) ]/1e6, ((double)(end-start))/(1e9)));
}

action_t fd_action_snapshot_load = {
  .name = NAME,
  .args = snapshot_load_cmd_args,
  .perm = snapshot_load_cmd_perm,
  .fn   = snapshot_load_cmd_fn
};
