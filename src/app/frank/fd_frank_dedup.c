#include "fd_frank.h"

#include <stdio.h>
#include <linux/unistd.h>

static void
run( fd_frank_args_t * args ) {
  FD_LOG_INFO(( "dedup init" ));

  FD_LOG_INFO(( "joining cnc" ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( args->tile_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));
  /* FIXME: CNC DIAG REGION? */

  ulong in_cnt = fd_pod_query_ulong( args->in_pod, "cnt", 0 );
  if( FD_UNLIKELY( !in_cnt ) ) FD_LOG_ERR(( "cnt is zero" ));
  FD_LOG_INFO(( "%lu verify found", in_cnt ));

  /* Join the IPC objects needed this tile instance */

  fd_frag_meta_t const ** in_mcache = (fd_frag_meta_t const **)
    fd_alloca( alignof(fd_frag_meta_t const *), sizeof(fd_frag_meta_t const *)*in_cnt );
  if( FD_UNLIKELY( !in_mcache ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  ulong ** in_fseq = (ulong **)fd_alloca( alignof(ulong *), sizeof(ulong *)*in_cnt );
  if( FD_UNLIKELY( !in_fseq ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  ulong in_idx = 0UL;
  for( ulong i=0; i<in_cnt; i++ ) {
    char path[ 32 ];
    snprintf( path, 32, "mcache%lu", i );
    FD_LOG_INFO(( "joining mcache%lu", i ));
    in_mcache[ in_idx ] = fd_mcache_join( fd_wksp_pod_map( args->in_pod, path ) );
    if( FD_UNLIKELY( !in_mcache[ in_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

    snprintf( path, 32, "fseq%lu", i );
    FD_LOG_INFO(( "joining fseq%lu", i ));
    in_fseq[ in_idx ] = fd_fseq_join( fd_wksp_pod_map( args->in_pod, path ) );
    if( FD_UNLIKELY( !in_fseq[ in_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));

    in_idx++;
  }

  FD_LOG_INFO(( "joining tcache" ));
  fd_tcache_t * tcache = fd_tcache_join( fd_wksp_pod_map( args->tile_pod, "tcache" ) );
  if( FD_UNLIKELY( !tcache ) ) FD_LOG_ERR(( "fd_tcache_join failed" ));

  FD_LOG_INFO(( "joining mcache" ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( args->out_pod, "mcache" ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

  FD_LOG_INFO(( "joining fseq" ));
  ulong * out_fseq = fd_fseq_join( fd_wksp_pod_map( args->out_pod, "fseq" ) );
  if( FD_UNLIKELY( !out_fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));

  /* Setup local objects used by this tile */

  ulong cr_max = fd_pod_query_ulong( args->tile_pod, "cr_max", 0UL ); /*  0  <> pick reasonable default */
  long  lazy   = fd_pod_query_long ( args->tile_pod, "lazy",   0L  ); /* <=0 <> pick reasonable default */
  FD_LOG_INFO(( "configuring flow control (cr_max %lu lazy %li)", cr_max, lazy ));

  uint seed = fd_pod_query_uint( args->tile_pod, "seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (seed %u)", seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

  FD_LOG_INFO(( "creating scratch" ));
  ulong footprint = fd_dedup_tile_scratch_footprint( in_cnt, 1UL );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "fd_dedup_tile_scratch_footprint failed" ));
  void * scratch = fd_alloca( FD_DEDUP_TILE_SCRATCH_ALIGN, footprint );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  /* Start deduping */

  FD_LOG_INFO(( "dedup run" ));
  int err = fd_dedup_tile( cnc, in_cnt, in_mcache, in_fseq, tcache, mcache, 1UL, &out_fseq, cr_max, lazy, rng, scratch );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_dedup_tile failed (%i)", err ));
}

static long allow_syscalls[] = {
  __NR_write,     /* logging */
  __NR_futex,     /* logging, glibc fprintf unfortunately uses a futex internally */
  __NR_fsync,     /* logging, WARNING and above fsync immediately */
  __NR_nanosleep, /* fd_tempo_tick_per_ns calibration */
};

fd_frank_task_t frank_dedup = {
  .name     = "dedup",
  .in_wksp  = "verify_dedup",
  .out_wksp = "dedup_pack",
  .close_fd_start = 4, /* stdin, stdout, stderr, logfile */
  .allow_syscalls_sz = sizeof(allow_syscalls)/sizeof(allow_syscalls[ 0 ]),
  .allow_syscalls = allow_syscalls,
  .init = NULL,
  .run  = run,
};
