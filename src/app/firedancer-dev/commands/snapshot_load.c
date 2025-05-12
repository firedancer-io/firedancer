#include "../../firedancer/topology.h"
#include "../../shared/commands/configure/configure.h"
#include "../../shared/commands/run/run.h"
#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/topo/fd_pod_format.h"
#include "../../../util/tile/fd_tile_private.h"
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
  int is_zstd = _is_zstd( args->snapshot_load.snapshot_path );

  fd_topo_t * topo = &config->topo;
  fd_topob_new( &config->topo, config->name );
  topo->max_page_size = fd_cstr_to_shmem_page_sz( config->hugetlbfs.max_page_size );

  fd_topob_wksp( topo, "funk" );
  fd_topo_obj_t * funk_obj = setup_topo_funk( topo, "funk",
      config->firedancer.funk.max_account_records,
      config->firedancer.funk.max_database_transactions );

  static ushort tile_to_cpu[ FD_TILE_MAX ] = {0};
  if( args->tile_cpus[0] ) {
    ulong cpu_cnt = fd_tile_private_cpus_parse( args->tile_cpus, tile_to_cpu );
    if( FD_UNLIKELY( cpu_cnt<4UL ) ) FD_LOG_ERR(( "--tile-cpus specifies %lu CPUs, but need at least 4", cpu_cnt ));
  }

  fd_topob_wksp( topo, "metric_in" );
  fd_topob_wksp( topo, "metric" );
  fd_topob_tile( topo, "metric",  "metric", "metric_in", tile_to_cpu[0], 0, 0 );

  /* read() tile */
  fd_topob_wksp( topo, "FileRd" );
  fd_topo_tile_t * filerd_tile = fd_topob_tile( topo, "FileRd", "FileRd", "FileRd", tile_to_cpu[1], 0, 0 );
  fd_memcpy( filerd_tile->filerd.file_path, args->snapshot_load.snapshot_path, PATH_MAX );
  FD_STATIC_ASSERT( sizeof(filerd_tile->filerd.file_path)==sizeof(args->snapshot_load.snapshot_path), abi );
  FD_STATIC_ASSERT( sizeof(filerd_tile->filerd.file_path)==PATH_MAX,                                  abi );

  /* Uncompressed data stream */
  fd_topob_wksp( topo, "snap_stream" );
  fd_topo_link_t * snapin_link   = fd_topob_link( topo, "snap_stream", "snap_stream", 512UL, 0UL, 0UL );
  fd_topo_obj_t *  snapin_dcache = fd_topob_obj( topo, "dcache", "snap_stream" );
  snapin_link->dcache_obj_id = snapin_dcache->id;
  FD_TEST( fd_pod_insertf_ulong( topo->props, (16UL<<20), "obj.%lu.data_sz", snapin_dcache->id ) );

  if( is_zstd ) {  /* .tar.zst file */

    /* "unzstd": Zstandard decompress tile */
    fd_topob_wksp( topo, "Unzstd" );
    fd_topo_tile_t * unzstd_tile = fd_topob_tile( topo, "Unzstd", "Unzstd", "Unzstd", tile_to_cpu[2], 0, 0 );
    (void)unzstd_tile;

    /* Compressed data stream */
    fd_topob_wksp( topo, "snap_zstd" );
    fd_topo_link_t * zstd_link   = fd_topob_link( topo, "snap_zstd", "snap_zstd", 512UL, 0UL, 0UL );
    fd_topo_obj_t *  zstd_dcache = fd_topob_obj( topo, "dcache", "snap_zstd");
    zstd_link->dcache_obj_id = zstd_dcache->id;
    FD_TEST( fd_pod_insertf_ulong( topo->props, (16UL<<20), "obj.%lu.data_sz", zstd_dcache->id ) );

    /* filerd tile -> compressed stream */
    fd_topob_tile_out( topo, "FileRd", 0UL, "snap_zstd", 0UL );
    fd_topob_tile_uses( topo, filerd_tile, zstd_dcache, FD_SHMEM_JOIN_MODE_READ_WRITE );

    /* compressed stream -> unzstd tile */
    fd_topob_tile_in( topo, "Unzstd", 0UL, "metric_in", "snap_zstd", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    fd_topob_tile_uses( topo, unzstd_tile, zstd_dcache, FD_SHMEM_JOIN_MODE_READ_ONLY  );

    /* unzstd tile -> uncompressed stream */
    fd_topob_tile_out( topo, "Unzstd", 0UL, "snap_stream", 0UL );
    fd_topob_tile_uses( topo, unzstd_tile, snapin_dcache, FD_SHMEM_JOIN_MODE_READ_WRITE );

  } else {  /* .tar file */

    /* filerd tile -> uncompressed stream */
    fd_topob_tile_out( topo, "FileRd", 0UL, "snap_stream", 0UL );
    fd_topob_tile_uses( topo, filerd_tile, snapin_dcache, FD_SHMEM_JOIN_MODE_READ_WRITE );

  }

  fd_topob_wksp( topo, "SnapIn" );
  fd_topo_tile_t * snapin_tile = fd_topob_tile( topo, "SnapIn", "SnapIn", "SnapIn", tile_to_cpu[3], 0, 0 );
  snapin_tile->snapin.scratch_sz = (3UL<<30);

  fd_topob_wksp( topo, "ActAlc" );
  fd_topo_tile_t * actalc_tile = fd_topob_tile( topo, "ActAlc", "ActAlc", "ActAlc", tile_to_cpu[4], 0, 0 );
  fd_topob_tile_uses( topo, actalc_tile, funk_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
  actalc_tile->actalc.funk_obj_id = funk_obj->id;

  fd_topob_tile_in  ( topo, "SnapIn", 0UL, "metric_in", "snap_stream", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED   );
  fd_topob_tile_uses( topo, snapin_tile, snapin_dcache, FD_SHMEM_JOIN_MODE_READ_ONLY  );
  fd_topob_tile_uses( topo, actalc_tile, snapin_dcache, FD_SHMEM_JOIN_MODE_READ_ONLY  );

  fd_topob_wksp( topo, "snap_frags" );
  fd_topob_link( topo, "snap_frags", "snap_frags", 65536UL, 0UL, 0UL );
  fd_topob_tile_out( topo, "SnapIn", 0UL, "snap_frags", 0UL );
  fd_topob_tile_in ( topo, "ActAlc", 0UL, "metric_in", "snap_frags", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );

  fd_topob_wksp( topo, "snap_descs" );
  fd_topob_link( topo, "snap_descs", "snap_descs", 512UL, 0UL, 0UL )->permit_no_consumers = 1;
  fd_topob_tile_out( topo, "ActAlc", 0UL, "snap_descs", 0UL );

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
  char const * tile_cpus     = fd_env_strip_cmdline_cstr( pargc, pargv, "--tile-cpus", "FD_TILE_CPUS", NULL );
  char const * snapshot_file = fd_env_strip_cmdline_cstr( pargc, pargv, "--snapshot",  NULL,           NULL );

  if( tile_cpus ) {
    ulong tile_cpus_strlen = strlen( tile_cpus );
    if( FD_UNLIKELY( tile_cpus_strlen>=sizeof(args->tile_cpus) ) ) FD_LOG_ERR(( "--tile-cpus: flag too long" ));
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->tile_cpus ), tile_cpus, tile_cpus_strlen ) );
  }

  if( FD_UNLIKELY( !snapshot_file ) ) FD_LOG_ERR(( "Missing --snapshot flag" ));
  ulong snapshot_file_strlen = strlen( snapshot_file );
  if( FD_UNLIKELY( snapshot_file_strlen>=sizeof(args->snapshot_load.snapshot_path) ) ) FD_LOG_ERR(( "--snapshot: path too long" ));
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->snapshot_load.snapshot_path ), snapshot_file, snapshot_file_strlen ) );
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

  fd_topo_tile_t * file_rd_tile = &topo->tiles[ fd_topo_find_tile( topo, "FileRd", 0UL ) ];
  fd_topo_tile_t * snap_in_tile = &topo->tiles[ fd_topo_find_tile( topo, "SnapIn", 0UL ) ];
  fd_topo_tile_t * unzstd_tile = &topo->tiles[ fd_topo_find_tile( topo, "Unzstd", 0UL ) ];

  ulong *          snap_in_fseq    = snap_in_tile->in_link_fseq[ 0 ];
  ulong *          snap_accs_sync  = fd_mcache_seq_laddr( topo->links[ fd_topo_find_link( topo, "snap_frags", 0UL ) ].mcache );
  ulong volatile * file_rd_metrics = fd_metrics_tile( file_rd_tile->metrics );
  ulong volatile * snap_in_metrics = fd_metrics_tile( snap_in_tile->metrics );
  ulong volatile * unzstd_in_metrics = fd_metrics_tile( unzstd_tile->metrics );

  ulong goff_old          = 0UL;
  ulong file_rd_backp_old = 0UL;
  ulong snap_in_wait_old  = 0UL;
  ulong acc_cnt_old       = 0UL;
  ulong frag_cnt_old      = 0UL;
  for(;;) {
    sleep( 1 );

    ulong filerd_status = FD_VOLATILE_CONST( file_rd_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong snapin_status = FD_VOLATILE_CONST( snap_in_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    ulong unzstd_status = FD_VOLATILE_CONST( unzstd_in_metrics[ MIDX( GAUGE, TILE, STATUS ) ] );
    if( FD_UNLIKELY( filerd_status==2UL || snapin_status==2UL || unzstd_status==2UL ) ) {
      FD_LOG_NOTICE(( "Done" ));
      break;
    }

    ulong goff          = FD_VOLATILE_CONST( snap_in_fseq[ 1 ] );
    ulong file_rd_backp = FD_VOLATILE_CONST( file_rd_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG ) ] );
    ulong snap_in_wait  = FD_VOLATILE_CONST( snap_in_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG    ) ] ) +
                          FD_VOLATILE_CONST( snap_in_metrics[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG   ) ] );
    ulong frag_cnt      = FD_VOLATILE_CONST( snap_accs_sync[0] );
    ulong acc_cnt       = FD_VOLATILE_CONST( snap_accs_sync[1] );
    FD_LOG_NOTICE(( "rate=%4.2g GB/s back=%3.0f%% parser_busy=%3.0f%% acc=%8.3g/s frag=%8.3g/s",
                    (double)( goff-goff_old )/1e9,
                    ( (double)( file_rd_backp-file_rd_backp_old )*ns_per_tick )/1e7,
                    ( (double)( snap_in_wait -snap_in_wait_old  )*ns_per_tick )/1e7,
                    (double)( acc_cnt -acc_cnt_old  ),
                    (double)( frag_cnt-frag_cnt_old ) ) );
    goff_old          = goff;
    file_rd_backp_old = file_rd_backp;
    snap_in_wait_old  = snap_in_wait;
    acc_cnt_old       = acc_cnt;
    frag_cnt_old      = frag_cnt;
  }

  FD_LOG_NOTICE(( "Loaded %g accounts", (double)FD_VOLATILE_CONST( snap_accs_sync[1] ) ));
}

action_t fd_action_snapshot_load = {
  .name = NAME,
  .args = snapshot_load_cmd_args,
  .perm = snapshot_load_cmd_perm,
  .fn   = snapshot_load_cmd_fn
};
