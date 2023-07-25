#include "fd_frank.h"

int
fd_frank_dedup_task( int     argc,
                     char ** argv ) {
  (void)argc;
  fd_log_thread_set( argv[0] );
  FD_LOG_INFO(( "dedup init" ));

  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[1];

  /* Load up the configuration for this frank instance */

  FD_LOG_INFO(( "using configuration in pod %s at path firedancer", pod_gaddr ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, "firedancer" );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  FD_LOG_INFO(( "joining firedancer.dedup.cnc" ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( cfg_pod, "dedup.cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));
  /* FIXME: CNC DIAG REGION? */

  uchar const * verify_pods = fd_pod_query_subpod( cfg_pod, "verify" );
  ulong in_cnt = fd_pod_cnt_subpod( verify_pods );
  FD_LOG_INFO(( "%lu verify found", in_cnt ));

  /* Join the IPC objects needed this tile instance */

  fd_frag_meta_t const ** in_mcache = (fd_frag_meta_t const **)
    fd_alloca( alignof(fd_frag_meta_t const *), sizeof(fd_frag_meta_t const *)*in_cnt );
  if( FD_UNLIKELY( !in_mcache ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  ulong ** in_fseq = (ulong **)fd_alloca( alignof(ulong *), sizeof(ulong *)*in_cnt );
  if( FD_UNLIKELY( !in_fseq ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  ulong in_idx = 0UL;
  for( fd_pod_iter_t iter = fd_pod_iter_init( verify_pods ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) {
    fd_pod_info_t info = fd_pod_iter_info( iter );
    if( FD_UNLIKELY( info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;
    char const  * verify_name =                info.key;
    uchar const * verify_pod  = (uchar const *)info.val;

    FD_LOG_INFO(( "joining firedancer.verify.%s.mcache", verify_name ));
    in_mcache[ in_idx ] = fd_mcache_join( fd_wksp_pod_map( verify_pod, "mcache" ) );
    if( FD_UNLIKELY( !in_mcache[ in_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

    FD_LOG_INFO(( "joining firedancer.verify.%s.fseq", verify_name ));
    in_fseq[ in_idx ] = fd_fseq_join( fd_wksp_pod_map( verify_pod, "fseq" ) );
    if( FD_UNLIKELY( !in_fseq[ in_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));

    in_idx++;
  }

  FD_LOG_INFO(( "joining firedancer.dedup.tcache" ));
  fd_tcache_t * tcache = fd_tcache_join( fd_wksp_pod_map( cfg_pod, "dedup.tcache" ) );
  if( FD_UNLIKELY( !tcache ) ) FD_LOG_ERR(( "fd_tcache_join failed" ));

  FD_LOG_INFO(( "joining firedancer.dedup.mcache" ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( cfg_pod, "dedup.mcache" ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

  FD_LOG_INFO(( "joining firedancer.dedup.fseq" ));
  ulong * out_fseq = fd_fseq_join( fd_wksp_pod_map( cfg_pod, "dedup.fseq" ) );
  if( FD_UNLIKELY( !out_fseq ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));

  /* Setup local objects used by this tile */

  ulong cr_max = fd_pod_query_ulong( cfg_pod, "dedup.cr_max", 0UL ); /*  0  <> pick reasonable default */
  long  lazy   = fd_pod_query_long ( cfg_pod, "dedup.lazy",   0L  ); /* <=0 <> pick reasonable default */
  FD_LOG_INFO(( "configuring flow control (firedancer.dedup.cr_max %lu firedancer.dedup.lazy %li)", cr_max, lazy ));

  uint seed = fd_pod_query_uint( cfg_pod, "dedup.seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (firedancer.dedup.seed %u)", seed ));
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

  /* Clean up */

  FD_LOG_INFO(( "dedup fini" ));
  fd_rng_delete    ( fd_rng_leave   ( rng      ) );
  fd_wksp_pod_unmap( fd_fseq_leave  ( out_fseq ) );
  fd_wksp_pod_unmap( fd_mcache_leave( mcache   ) );
  fd_wksp_pod_unmap( fd_tcache_leave( tcache   ) );
  for( ulong in_idx=in_cnt; in_idx; in_idx-- ) {
    fd_wksp_pod_unmap( fd_fseq_leave  ( in_fseq  [ in_idx-1UL ] ) );
    fd_wksp_pod_unmap( fd_mcache_leave( in_mcache[ in_idx-1UL ] ) );
  }
  fd_wksp_pod_unmap( fd_cnc_leave( cnc ) );
  fd_wksp_pod_detach( pod );
  return 0;
}
