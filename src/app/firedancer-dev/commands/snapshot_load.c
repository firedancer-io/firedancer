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
snapshot_load_topo( config_t * config ) {
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

  if( config->firedancer.vinyl.enabled ) {
    setup_topo_vinyl( topo, &config->firedancer );
  }

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
  int vinyl_enabled = config->firedancer.vinyl.enabled;
  if( vinyl_enabled ) {
    fd_topob_wksp( topo, "snapwr" );
    fd_topo_tile_t * snapwr_tile = fd_topob_tile( topo, "snapwr", "snapwr", "metric_in", ULONG_MAX, 0, 0 );
    snapwr_tile->allow_shutdown = 1;
  }

  fd_topob_wksp( topo, "snapct_ld"    );
  fd_topob_wksp( topo, "snapld_dc"    );
  fd_topob_wksp( topo, "snapdc_in"    );
  fd_topob_wksp( topo, "snapin_ct"    );
  fd_topob_wksp( topo, "snapin_manif" );
  fd_topob_wksp( topo, "snapct_repr"  );
  if( vinyl_enabled ) fd_topob_wksp( topo, "snapin_wr" );

  fd_topob_link( topo, "snapct_ld",   "snapct_ld",     128UL,   sizeof(fd_ssctrl_init_t),       1UL );
  fd_topob_link( topo, "snapld_dc",   "snapld_dc",     16384UL, USHORT_MAX,                     1UL );
  fd_topob_link( topo, "snapdc_in",   "snapdc_in",     16384UL, USHORT_MAX,                     1UL );
  fd_topob_link( topo, "snapin_ct",   "snapin_ct",     128UL,   0UL,                            1UL );
  fd_topob_link( topo, "snapin_manif", "snapin_manif", 2UL,     sizeof(fd_snapshot_manifest_t), 1UL )->permit_no_consumers = 1;
  fd_topob_link( topo, "snapct_repr", "snapct_repr",   128UL,   0UL,                            1UL )->permit_no_consumers = 1;
  if( vinyl_enabled ) {
    fd_topob_link( topo, "snapin_wr", "snapin_wr", 4UL, 16UL<<20, 1UL );
  }

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
  if( vinyl_enabled ) {
    fd_topob_tile_out( topo, "snapin", 0UL,              "snapin_wr", 0UL );
    fd_topob_tile_in ( topo, "snapwr", 0UL, "metric_in", "snapin_wr", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
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

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  fd_topob_auto_layout( topo, 0 );
  fd_topob_finish( topo, CALLBACKS );
}

extern int * fd_log_private_shared_lock;

static void
snapshot_load_args( int *    pargc,
                    char *** pargv,
                    args_t * args ) {
  args->snapshot_load.fsck = !!fd_env_strip_cmdline_contains( pargc, pargv, "--fsck" );
  char const * snap_path = fd_env_strip_cmdline_cstr( pargc, pargv, "--snapshot-dir", NULL, NULL );
  if( snap_path ) {
    ulong snap_path_len = strlen( snap_path ); FD_TEST( snap_path_len<sizeof(args->snapshot_load.snapshot_path) );
    memcpy( args->snapshot_load.snapshot_path, snap_path, snap_path_len+1UL );
  }
}

static uint
fsck_funk( config_t * config ) {
  ulong funk_obj_id = fd_pod_query_ulong( config->topo.props, "funk", ULONG_MAX );
  FD_TEST( funk_obj_id!=ULONG_MAX );
  void * funk_shmem = fd_topo_obj_laddr( &config->topo, funk_obj_id );
  fd_funk_t funk[1];
  FD_TEST( fd_funk_join( funk, funk_shmem ) );
  uint fsck_err = fd_accdb_fsck_funk( funk );
  FD_TEST( fd_funk_leave( funk, NULL ) );
  return fsck_err;
}

static uint
fsck_vinyl( config_t * config ) {
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

  uint fsck_err = fd_accdb_fsck_vinyl( io, meta );

  /* Clean up */

  FD_TEST( fd_vinyl_io_fini( io ) );
  free( io_mm );
  fd_io_mmio_fini( mmio, mmio_sz );
  fd_vinyl_meta_leave( meta );
  return fsck_err;
}

static void
snapshot_load_cmd_fn( args_t *   args,
                      config_t * config ) {
  if( FD_UNLIKELY( config->firedancer.snapshots.sources.gossip.allow_any || 0UL!=config->firedancer.snapshots.sources.gossip.allow_list_cnt ) ) {
    FD_LOG_ERR(( "snapshot-load command is incompatible with gossip snapshot sources" ));
  }
  fd_topo_t * topo = &config->topo;

  if( args->snapshot_load.snapshot_path[0] ) {
    strcpy( config->paths.snapshots, args->snapshot_load.snapshot_path );
  }

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
  ulong            snapwr_idx  =               fd_topo_find_tile( topo, "snapwr", 0UL );
  fd_topo_tile_t * snapwr_tile = snapwr_idx!=ULONG_MAX ? &topo->tiles[ snapwr_idx ] : NULL;
  if( args->snapshot_load.snapshot_path[0] ) {
    strcpy( snapct_tile->snapct.snapshots_path, args->snapshot_load.snapshot_path );
    strcpy( snapld_tile->snapld.snapshots_path, args->snapshot_load.snapshot_path );
  }

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  double ns_per_tick = 1.0/tick_per_ns;

  long start = fd_log_wallclock();
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run );

  ulong volatile * const snapct_metrics = fd_metrics_tile( snapct_tile->metrics );
  ulong volatile * const snapld_metrics = fd_metrics_tile( snapld_tile->metrics );
  ulong volatile * const snapdc_metrics = fd_metrics_tile( snapdc_tile->metrics );
  ulong volatile * const snapin_metrics = fd_metrics_tile( snapin_tile->metrics );
  ulong volatile * const snapwr_metrics = snapwr_tile ? fd_metrics_tile( snapwr_tile->metrics ) : NULL;

  ulong total_off_old    = 0UL;
  ulong decomp_off_old   = 0UL;
  ulong vinyl_off_old    = 0UL;
  ulong snapct_backp_old = 0UL;
  ulong snapct_wait_old  = 0UL;
  ulong snapld_backp_old = 0UL;
  ulong snapld_wait_old  = 0UL;
  ulong snapdc_backp_old = 0UL;
  ulong snapdc_wait_old  = 0UL;
  ulong snapin_backp_old = 0UL;
  ulong snapin_wait_old  = 0UL;
  ulong snapwr_wait_old  = 0UL;
  ulong acc_cnt_old      = 0UL;
  sleep( 1 );
  puts( "" );
  puts( "Columns:" );
  puts( "- comp:  Compressed bandwidth"             );
  puts( "- raw:   Uncompressed bandwidth"           );
  puts( "- backp: Backpressured by downstream tile" );
  puts( "- stall: Waiting on upstream tile"         );
  puts( "- acc:   Number of accounts"               );
  puts( "" );
  fputs( "--------------------------------------------", stdout );
  if( snapwr_tile ) fputs( "--------------", stdout );
  fputs( "[ct],[ld],[dc],[in]--------[ct],[ld],[dc],[in]", stdout );
  if( snapwr_tile ) fputs( ",[wr]" , stdout );
  puts( "--------------" );
  long next = start+1000L*1000L*1000L;
  for(;;) {
    ulong snapct_status = FD_VOLATILE_CONST( snapct_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapld_status = FD_VOLATILE_CONST( snapld_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapdc_status = FD_VOLATILE_CONST( snapdc_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapin_status = FD_VOLATILE_CONST( snapin_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );

    if( FD_UNLIKELY( snapct_status==2UL && snapld_status==2UL && snapdc_status==2UL && snapin_status == 2UL ) ) break;

    long cur = fd_log_wallclock();
    if( FD_UNLIKELY( cur<next ) ) {
      long sleep_nanos = fd_long_min( 1000L*1000L, next-cur );
      FD_TEST( !fd_sys_util_nanosleep(  (uint)(sleep_nanos/(1000L*1000L*1000L)), (uint)(sleep_nanos%(1000L*1000L*1000L)) ) );
      continue;
    }

    ulong total_off    = snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_READ ) ] +
                         snapct_metrics[ MIDX( GAUGE, SNAPCT, INCREMENTAL_BYTES_READ ) ];
    ulong decomp_off   = snapdc_metrics[ MIDX( GAUGE, SNAPDC, FULL_DECOMPRESSED_BYTES_READ ) ] +
                         snapdc_metrics[ MIDX( GAUGE, SNAPDC, INCREMENTAL_DECOMPRESSED_BYTES_READ ) ];
    ulong vinyl_off    = snapwr_tile ? snapwr_metrics[ MIDX( GAUGE, SNAPWR, VINYL_BYTES_WRITTEN ) ] : 0UL;
    ulong snapct_backp = snapct_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapct_wait  = snapct_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapct_backp;
    ulong snapld_backp = snapld_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapld_wait  = snapld_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapld_backp;
    ulong snapdc_backp = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapdc_wait  = snapdc_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapdc_backp;
    ulong snapin_backp = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    ulong snapin_wait  = snapin_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] + snapin_backp;
    ulong snapwr_wait  = 0UL;
    if( snapwr_tile ) {
      snapwr_wait      = snapwr_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] +
                         snapwr_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ];
    }

    double progress = 100.0 * (double)snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_READ ) ] / (double)snapct_metrics[ MIDX( GAUGE, SNAPCT, FULL_BYTES_TOTAL ) ];

    ulong acc_cnt      = snapin_metrics[ MIDX( GAUGE, SNAPIN, ACCOUNTS_INSERTED    ) ];
    printf( "%5.1f %% comp=%4.0fMB/s snap=%4.0fMB/s",
            progress,
            (double)( total_off -total_off_old  )/1e6,
            (double)( decomp_off-decomp_off_old )/1e6 );
    if( snapwr_tile ) {
      printf( " vinyl=%4.0fMB/s", (double)( vinyl_off - vinyl_off_old )/1e6 );
    }
    printf( " backp=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%",
            ( (double)( snapct_backp-snapct_backp_old )*ns_per_tick )/1e7,
            ( (double)( snapld_backp-snapld_backp_old )*ns_per_tick )/1e7,
            ( (double)( snapdc_backp-snapdc_backp_old )*ns_per_tick )/1e7,
            ( (double)( snapin_backp-snapin_backp_old )*ns_per_tick )/1e7 );
    printf( ") busy=(%3.0f%%,%3.0f%%,%3.0f%%,%3.0f%%",
            100-( ( (double)( snapct_wait-snapct_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snapld_wait-snapld_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snapdc_wait-snapdc_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snapin_wait-snapin_wait_old  )*ns_per_tick )/1e7 ) );
    if( snapwr_tile ) {
      printf( ",%3.0f%%",
            100-( ( (double)( snapwr_wait-snapwr_wait_old  )*ns_per_tick )/1e7 ) );
    }
    printf( ") acc=%4.1f M/s\n",
            (double)( acc_cnt-acc_cnt_old  )/1e6 );
    fflush( stdout );
    total_off_old    = total_off;
    decomp_off_old   = decomp_off;
    vinyl_off_old    = vinyl_off;
    snapct_backp_old = snapct_backp;
    snapct_wait_old  = snapct_wait;
    snapld_backp_old = snapld_backp;
    snapld_wait_old  = snapld_wait;
    snapdc_backp_old = snapdc_backp;
    snapdc_wait_old  = snapdc_wait;
    snapin_backp_old = snapin_backp;
    snapin_wait_old  = snapin_wait;
    snapwr_wait_old  = snapwr_wait;
    acc_cnt_old      = acc_cnt;

    next+=1000L*1000L*1000L;
  }

  if( args->snapshot_load.fsck ) {
    FD_LOG_NOTICE(( "FSCK: starting" ));
    uint fsck_err;
    if( snapwr_tile ) fsck_err = fsck_vinyl( config );
    else              fsck_err = fsck_funk ( config );
    if( !fsck_err ) {
      FD_LOG_NOTICE(( "FSCK: passed" ));
    } else {
      FD_LOG_ERR(( "FSCK: errors detected" ));
    }
  }
}

action_t fd_action_snapshot_load = {
  .name = NAME,
  .topo = snapshot_load_topo,
  .perm = dev_cmd_perm,
  .args = snapshot_load_args,
  .fn   = snapshot_load_cmd_fn
};
