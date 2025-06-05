#include "../../firedancer/topology.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../util/pod/fd_pod_format.h"
#include "../../../util/tile/fd_tile_private.h"
#include "../../../flamenco/snapshot/fd_snapshot_loader.h"
#include <sys/resource.h>
#include <linux/capability.h>
#include <unistd.h>
#include <stdio.h>

#define NAME "snapshot-load"

extern fd_topo_obj_callbacks_t * CALLBACKS[];

fd_topo_run_tile_t
fdctl_tile_run( fd_topo_tile_t const * tile );

/* _is_zstd returns 1 if given file handle points to the beginning of a
    zstd stream, otherwise zero. */

static int
_is_zstd( char const * path ) {
  FILE * file = fopen( path, "r" );
  FD_TEST( file );
  uint magic;
  ulong n = fread( &magic, 1UL, 4UL, file );
  if( FD_UNLIKELY( feof( file ) ) ) {
    clearerr( file );
    fseek( file, -(long)n, SEEK_CUR );
    fclose( file );
    return 0;
  }
  int err = ferror( file );
  if( FD_UNLIKELY( err ) )
    FD_LOG_ERR(( "fread() failed (%d-%s)", err, strerror( err ) ));
  fseek( file, -4L, SEEK_CUR );
  fclose( file );
  return ( magic==0xFD2FB528UL );
}

static void
snapshot_load_topo( config_t *     config,
                    args_t const * args ) {
  fd_snapshot_src_t src[1];
  char snapshot_path_copy[4096];
  memcpy( snapshot_path_copy, args->snapshot_load.full_snapshot_path, sizeof(snapshot_path_copy) );
  fd_snapshot_src_parse_type_unknown( src, snapshot_path_copy );

  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "funk" );
  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions,
      config->firedancer.funk.heap_size_gib );

  static ushort tile_to_cpu[ FD_TILE_MAX ] = {0};
  if( args->tile_cpus[0] ) {
    ulong cpu_cnt = fd_tile_private_cpus_parse( args->tile_cpus, tile_to_cpu );
    if( FD_UNLIKELY( cpu_cnt<6UL ) ) FD_LOG_ERR(( "--tile-cpus specifies %lu CPUs, but need at least 6", cpu_cnt ));
  }

  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "metric" );
  fd_topob_tile( topo, "metric",  "metric", "metric_in", tile_to_cpu[0], 0, 0 );

  /* fseq for communicating snapshot loading done */
  fd_topob_wksp( topo, "snap_fseq" );
  fd_topo_obj_t * snapshot_fseq_obj = fd_topob_obj( topo, "fseq", "snap_fseq" );

  /* Uncompressed data stream */
  fd_topob_wksp( topo, "snap_stream" );
  fd_topo_link_t * snapin_link   = fd_topob_link( topo, "snap_stream", "snap_stream", 512UL, 0UL, 0UL );
  fd_topo_obj_t *  snapin_dcache = fd_topob_obj( topo, "dcache", "snap_stream" );
  snapin_link->dcache_obj_id = snapin_dcache->id;
  FD_LOG_WARNING(("snapin dcache obj id is %lu", snapin_link->dcache_obj_id));
  FD_TEST( fd_pod_insertf_ulong( topo->props, (16UL<<20), "obj.%lu.data_sz", snapin_dcache->id ) );

  if( src->type==FD_SNAPSHOT_SRC_FILE ) {

    int is_zstd = _is_zstd( args->snapshot_load.full_snapshot_path );

    /* read() tile */
    fd_topob_wksp( topo, "SnapRd" );
    fd_topo_tile_t * snaprd_tile = fd_topob_tile( topo, "SnapRd", "SnapRd", "SnapRd", tile_to_cpu[1], 0, 0 );
    fd_memcpy( snaprd_tile->snaprd.full_snapshot_path, args->snapshot_load.full_snapshot_path, PATH_MAX );
    FD_STATIC_ASSERT( sizeof(snaprd_tile->snaprd.full_snapshot_path)==sizeof(args->snapshot_load.full_snapshot_path), abi );
    FD_STATIC_ASSERT( sizeof(snaprd_tile->snaprd.full_snapshot_path)==PATH_MAX,                                       abi );

    fd_memcpy( snaprd_tile->snaprd.incremental_snapshot_path, args->snapshot_load.incremental_snapshot_path, PATH_MAX );
    FD_STATIC_ASSERT( sizeof(snaprd_tile->snaprd.full_snapshot_path)==sizeof(args->snapshot_load.full_snapshot_path), abi );
    FD_STATIC_ASSERT( sizeof(snaprd_tile->snaprd.full_snapshot_path)==PATH_MAX,                                       abi );

    if( is_zstd ) {  /* .tar.zst file */

      /* "snapdc": Zstandard decompress tile */
      fd_topob_wksp( topo, "SnapDc" );
      fd_topo_tile_t * snapdc_tile = fd_topob_tile( topo, "SnapDc", "SnapDc", "SnapDc", tile_to_cpu[2], 0, 0 );
      (void)snapdc_tile;

      /* Compressed data stream */
      fd_topob_wksp( topo, "snap_zstd" );
      fd_topo_link_t * zstd_link   = fd_topob_link( topo, "snap_zstd", "snap_zstd", 512UL, 0UL, 0UL );
      fd_topo_obj_t *  zstd_dcache = fd_topob_obj( topo, "dcache", "snap_zstd");
      zstd_link->dcache_obj_id = zstd_dcache->id;
      FD_TEST( fd_pod_insertf_ulong( topo->props, (16UL<<20), "obj.%lu.data_sz", zstd_dcache->id ) );

      /* snaprd tile -> compressed stream */
      fd_topob_tile_out( topo, "SnapRd", 0UL, "snap_zstd", 0UL );
      fd_topob_tile_uses( topo, snaprd_tile, zstd_dcache, FD_SHMEM_JOIN_MODE_READ_WRITE );

      /* compressed stream -> snapdc tile */
      fd_topob_tile_in( topo, "SnapDc", 0UL, "metric_in", "snap_zstd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
      fd_topob_tile_uses( topo, snapdc_tile, zstd_dcache, FD_SHMEM_JOIN_MODE_READ_ONLY  );

      /* snapdc tile -> uncompressed stream */
      fd_topob_tile_out( topo, "SnapDc", 0UL, "snap_stream", 0UL );
      fd_topob_tile_uses( topo, snapdc_tile, snapin_dcache, FD_SHMEM_JOIN_MODE_READ_WRITE );

    } else {  /* .tar file */

      /* snaprd tile -> uncompressed stream */
      fd_topob_tile_out( topo, "SnapRd", 0UL, "snap_stream", 0UL );
      fd_topob_tile_uses( topo, snaprd_tile, snapin_dcache, FD_SHMEM_JOIN_MODE_READ_WRITE );

    }
  }
  else if ( src->type==FD_SNAPSHOT_SRC_HTTP ) {

    /* httpdl() tile */
    fd_topob_wksp( topo, "HttpDl" );
    fd_topo_tile_t * httpdl_tile = fd_topob_tile( topo, "HttpDl", "HttpDl", "HttpDl", tile_to_cpu[1], 0, 0 );
    fd_memcpy( httpdl_tile->httpdl.path, src->http.path, PATH_MAX );
    fd_memcpy( httpdl_tile->httpdl.snapshot_dir, args->snapshot_load.snapshot_dir, PATH_MAX );
    fd_memcpy( httpdl_tile->httpdl.dest, src->http.dest, sizeof(src->http.dest) );
    httpdl_tile->httpdl.ip4      = src->http.ip4;
    httpdl_tile->httpdl.path_len = src->http.path_len;
    httpdl_tile->httpdl.port     = src->http.port;

    /* "snapdc": Zstandard decompress tile */
    fd_topob_wksp( topo, "SnapDc" );
    fd_topo_tile_t * snapdc_tile = fd_topob_tile( topo, "SnapDc", "SnapDc", "SnapDc", tile_to_cpu[2], 0, 0 );
    (void)snapdc_tile;

    /* Compressed data stream */
    fd_topob_wksp( topo, "snap_zstd" );
    fd_topo_link_t * zstd_link   = fd_topob_link( topo, "snap_zstd", "snap_zstd", 512UL, 0UL, 0UL );
    fd_topo_obj_t *  zstd_dcache = fd_topob_obj( topo, "dcache", "snap_zstd");
    zstd_link->dcache_obj_id = zstd_dcache->id;
    FD_TEST( fd_pod_insertf_ulong( topo->props, (16UL<<20), "obj.%lu.data_sz", zstd_dcache->id ) );

    /* snaprd tile -> compressed stream */
    fd_topob_tile_out( topo, "HttpDl", 0UL, "snap_zstd", 0UL );
    fd_topob_tile_uses( topo, httpdl_tile, snapin_dcache, FD_SHMEM_JOIN_MODE_READ_WRITE );

    /* compressed stream -> snapdc tile */
    fd_topob_tile_in( topo, "SnapDc", 0UL, "metric_in", "snap_zstd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_uses( topo, snapdc_tile, zstd_dcache, FD_SHMEM_JOIN_MODE_READ_ONLY  );

    /* snapdc tile -> uncompressed stream */
    fd_topob_tile_out( topo, "SnapDc", 0UL, "snap_stream", 0UL );
    fd_topob_tile_uses( topo, snapdc_tile, snapin_dcache, FD_SHMEM_JOIN_MODE_READ_WRITE );
  }

  /* "SnapIn": Snapshot parser tile */
  fd_topob_wksp( topo, "SnapIn" );
  fd_topo_tile_t * snapin_tile = fd_topob_tile( topo, "SnapIn", "SnapIn", "SnapIn", tile_to_cpu[3], 0, 0 );
  snapin_tile->snapin.scratch_sz = (3UL<<30);

  /* uncompressed stream -> snapin tile */
  fd_topob_tile_in  ( topo, "SnapIn", 0UL, "metric_in", "snap_stream", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );
  fd_topob_tile_uses( topo, snapin_tile, snapin_dcache, FD_SHMEM_JOIN_MODE_READ_ONLY  );

  fd_topob_tile_uses( topo, snapin_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  snapin_tile->snapin.funk_obj_id = funk_obj->id;

  fd_topob_tile_uses( topo, snapin_tile, snapshot_fseq_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  snapin_tile->snapin.fseq_obj_id = snapshot_fseq_obj->id;
  fd_pod_insertf_ulong( topo->props, snapshot_fseq_obj->id, "snap_fseq" );
  

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    fd_topo_configure_tile( tile, config );
  }

  if( !args->tile_cpus[0] ) {
    fd_topob_auto_layout( topo, 0 );
  }
  fd_topob_finish( topo, CALLBACKS );
  fd_topo_print_log( /* stdout */ 1, topo );
}

static void
snapshot_load_cmd_args( int *    pargc,
                        char *** pargv,
                        args_t * args ) {
  char const * tile_cpus                = fd_env_strip_cmdline_cstr( pargc, pargv, "--tile-cpus",     "FD_TILE_CPUS", NULL );
  char const * full_snapshot_src        = fd_env_strip_cmdline_cstr(  pargc, pargv,  "--full-snapshot", NULL,          NULL );
  char const * incremental_snapshot_src = fd_env_strip_cmdline_cstr(  pargc, pargv,  "--incremental-snapshot", NULL,          NULL );
  char const * snapshot_dir             = fd_env_strip_cmdline_cstr(  pargc, pargv,  "--snapshot-dir", NULL,           NULL );

  if( tile_cpus ) {
    ulong tile_cpus_strlen = strlen( tile_cpus );
    if( FD_UNLIKELY( tile_cpus_strlen>=sizeof(args->tile_cpus) ) ) FD_LOG_ERR(( "--tile-cpus: flag too long" ));
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->tile_cpus ), tile_cpus, tile_cpus_strlen ) );
  }

  if( FD_UNLIKELY( !full_snapshot_src ) ) FD_LOG_ERR(( "Missing --full-snapshot flag" ));
  ulong snapshot_file_strlen = strlen( full_snapshot_src );
  if( FD_UNLIKELY( snapshot_file_strlen>=sizeof(args->snapshot_load.full_snapshot_path) ) ) FD_LOG_ERR(( "--snapshot: path too long" ));
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->snapshot_load.full_snapshot_path ), full_snapshot_src, snapshot_file_strlen ) );

  if( FD_UNLIKELY( !incremental_snapshot_src ) ) FD_LOG_ERR(( "Missing --full-snapshot flag" ));
  snapshot_file_strlen = strlen( incremental_snapshot_src );
  if( FD_UNLIKELY( snapshot_file_strlen>=sizeof(args->snapshot_load.incremental_snapshot_path) ) ) FD_LOG_ERR(( "--snapshot: path too long" ));
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->snapshot_load.incremental_snapshot_path ), full_snapshot_src, snapshot_file_strlen ) );

  /* FIXME: check if we need the snapshot dir argument (parse the snapshot input src to see if it's http)*/
  if( snapshot_dir!=NULL ) {
    ulong snapshot_dir_strlen = strlen( snapshot_dir );
    if( FD_UNLIKELY( snapshot_file_strlen>=sizeof(args->snapshot_load.snapshot_dir) ) ) FD_LOG_ERR(( "--snapshot-dir: dir too long" ));
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->snapshot_load.snapshot_dir ), snapshot_dir, snapshot_dir_strlen ) );
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

static void
snapshot_load_cmd_fn( args_t *   args,
                      config_t * config ) {
  snapshot_load_topo( config, args );
  fd_topo_t * topo = &config->topo;

  configure_stage( &fd_cfg_stage_hugetlbfs, CONFIGURE_CMD_INIT, config );
  initialize_workspaces( config );
  initialize_stacks( config );
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_WRITE );
  fd_topo_fill( topo );
  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  double ns_per_tick = 1.0/tick_per_ns;
  fd_topo_run_single_process( topo, 2, config->uid, config->gid, fdctl_tile_run, NULL );

  ulong            httpdl_tile_idx     =              fd_topo_find_tile( topo, "HttpDl", 0UL );
  ulong            snaprd_tile_idx     =              fd_topo_find_tile( topo, "SnapRd", 0UL );
  fd_topo_tile_t * http_dl_tile        = httpdl_tile_idx!=ULONG_MAX ?  &topo->tiles[ httpdl_tile_idx ] : NULL;
  fd_topo_tile_t * file_rd_tile        = snaprd_tile_idx!=ULONG_MAX ?  &topo->tiles[ snaprd_tile_idx ] : NULL;
  fd_topo_tile_t * const snap_in_tile  = &topo->tiles[ fd_topo_find_tile( topo, "SnapIn", 0UL ) ];
  ulong            const zstd_tile_idx =               fd_topo_find_tile( topo, "SnapDc", 0UL );
  fd_topo_tile_t * const snapdc_tile   = zstd_tile_idx!=ULONG_MAX ? &topo->tiles[ zstd_tile_idx ] : NULL;

  ulong *          const snap_in_fseq      = snap_in_tile->in_link_fseq[ 0 ];
  ulong *          const snap_accs_sync    = fd_mcache_seq_laddr( topo->links[ fd_topo_find_link( topo, "snap_stream", 0UL ) ].mcache );
  ulong volatile * file_rd_metrics         = file_rd_tile ? fd_metrics_tile( file_rd_tile->metrics ) : NULL;
  ulong volatile * http_dl_metrics         = http_dl_tile ? fd_metrics_tile( http_dl_tile->metrics ) : NULL;
  ulong volatile * const snap_in_metrics   = fd_metrics_tile( snap_in_tile->metrics );
  ulong volatile * const snapdc_in_metrics = snapdc_tile ? fd_metrics_tile( snapdc_tile->metrics ) : NULL;

  ulong goff_old          = 0UL;
  ulong file_rd_backp_old = 0UL;
  ulong file_rd_wait_old  = 0UL;
  ulong snap_in_backp_old = 0UL;
  ulong snap_in_wait_old  = 0UL;
  ulong acc_cnt_old       = 0UL;
  sleep( 1 );
  puts( "" );
  puts( "Columns:" );
  puts( "- bw:    Uncompressed bandwidth" );
  puts( "- backp: Backpressured by downstream tile" );
  puts( "- stall: Waiting on upstream tile"         );
  puts( "- acc:   Number of accounts"               );
  puts( "" );
  puts( "-------------backp=(file,snap,alc ) busy=(file,snap,alc ,idx )---------------" );
  long start = fd_log_wallclock();
  for(;;) {
    ulong snaprd_status = file_rd_metrics ? FD_VOLATILE_CONST( file_rd_metrics[ MIDX( GAUGE, TILE, STATUS ) ] ) : 2UL;
    ulong httpdl_status = http_dl_metrics ? FD_VOLATILE_CONST( http_dl_metrics[ MIDX( GAUGE, TILE, STATUS ) ] ) : 2UL;
    ulong snapin_status = FD_VOLATILE_CONST( snap_in_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapdc_status = snapdc_in_metrics ? FD_VOLATILE_CONST( snapdc_in_metrics[ MIDX( GAUGE, TILE, STATUS ) ] ) : 2UL;
    if( FD_UNLIKELY( httpdl_status==2UL && snaprd_status==2UL && snapdc_status==2UL && snapin_status == 2UL ) ) {
      FD_LOG_NOTICE(( "Done" ));
      break;
    }

    ulong goff          = FD_VOLATILE_CONST( snap_in_fseq[ 1 ] );
    ulong file_rd_backp = file_rd_metrics ? FD_VOLATILE_CONST( file_rd_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ] ) :
                          http_dl_metrics ? FD_VOLATILE_CONST( http_dl_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ] ) : 0UL;
    ulong file_rd_wait  = file_rd_metrics ? FD_VOLATILE_CONST( file_rd_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG    ) ] ) +
                          FD_VOLATILE_CONST( file_rd_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] ) + file_rd_backp :
                          http_dl_metrics ? FD_VOLATILE_CONST( http_dl_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG    ) ] ) +
                          FD_VOLATILE_CONST( http_dl_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] ) + file_rd_backp :0UL;
    ulong snap_in_backp = FD_VOLATILE_CONST( snap_in_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ] );
    ulong snap_in_wait  = FD_VOLATILE_CONST( snap_in_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG    ) ] ) +
                          FD_VOLATILE_CONST( snap_in_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] ) +
                          snap_in_backp;
    ulong acc_cnt       = FD_VOLATILE_CONST( snap_accs_sync[3] );
    printf( "bw=%4.2g GB/s backp=(%3.0f%%,%3.0f%%) busy=(%3.0f%%,%3.0f%%) acc=%8.3g/s\n",
            (double)( goff-goff_old )/1e9,
            ( (double)( file_rd_backp-file_rd_backp_old )*ns_per_tick )/1e7,
            ( (double)( snap_in_backp-snap_in_backp_old )*ns_per_tick )/1e7,
            100-( ( (double)( file_rd_wait -file_rd_wait_old  )*ns_per_tick )/1e7 ),
            100-( ( (double)( snap_in_wait -snap_in_wait_old  )*ns_per_tick )/1e7 ),
            (double)( acc_cnt -acc_cnt_old  ) );
    fflush( stdout );
    goff_old          = goff;
    file_rd_backp_old = file_rd_backp;
    file_rd_wait_old  = file_rd_wait;
    snap_in_backp_old = snap_in_backp;
    snap_in_wait_old  = snap_in_wait;
    acc_cnt_old       = acc_cnt;
    sleep( 1 );
  }

  long end = fd_log_wallclock();
  FD_LOG_NOTICE(( "Loaded %g accounts in %ld nanos %f seconds", (double)FD_VOLATILE_CONST( snap_accs_sync[3] ), end-start, ((double)(end-start))/(1000000000UL)));
}

action_t fd_action_snapshot_load = {
  .name = NAME,
  .args = snapshot_load_cmd_args,
  .perm = snapshot_load_cmd_perm,
  .fn   = snapshot_load_cmd_fn
};
