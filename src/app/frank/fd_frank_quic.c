#include "fd_frank.h"

#include "../../disco/quic/fd_quic.h"

int
fd_frank_quic_task( int     argc,
                    char ** argv ) {
  if( FD_UNLIKELY( argc!=3 ) )
    FD_LOG_ERR(( "unexpected arguments to tile" ));

  char const * tile_name = argv[0];
  fd_log_thread_set( tile_name );
  FD_LOG_INFO(( "%s init", tile_name ));

  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[1];
  char const * cfg_path  = argv[2];

  /* Load up the configuration for this frank instance */

  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path %s not found", cfg_path ));

  uchar const * quic_pod = fd_pod_query_subpod( cfg_pod, tile_name );
  if( FD_UNLIKELY( !quic_pod ) ) FD_LOG_ERR(( "path %s.%s not found", cfg_pod, tile_name ));

  /* Join the IPC objects needed by this tile instance */

  FD_LOG_INFO(( "joining %s.%s.cnc", cfg_path, tile_name ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( quic_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));

  FD_LOG_INFO(( "joining %s.%s.mcache", cfg_path, tile_name ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_pod_map( quic_pod, "mcache" ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

  FD_LOG_INFO(( "joining %s.%s.dcache", cfg_path, tile_name ));
  uchar * dcache = fd_dcache_join( fd_wksp_pod_map( quic_pod, "dcache" ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));

  FD_LOG_INFO(( "joining %s.%s.quic", cfg_path, tile_name ));
  fd_quic_t * quic = (fd_quic_t *)fd_wksp_pod_map( quic_pod, "quic" );
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_join failed" ));

  /* Setup local objects used by this tile */

  uint seed = fd_pod_query_uint( cfg_pod, "dedup.seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (%s.dedup.seed %u)", cfg_path, seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));

  FD_LOG_INFO(( "creating scratch" ));
  ulong footprint = fd_quic_tile_scratch_footprint( /* ... */ );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "fd_quic_tile_scratch_footprint failed" ));
  void * scratch = fd_alloca( FD_QUIC_TILE_SCRATCH_ALIGN, footprint );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "fd_alloca failed" ));

  /* Start serving */

  FD_LOG_INFO(( "%s run", tile_name ));
  int err = fd_quic_tile( /* ... */ );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_quic_tile failed (%i)", err ));

  /* Clean up */

  FD_LOG_INFO(( "%s fini", tile_name ));
  fd_rng_delete    ( fd_rng_leave( rng )       );
  fd_wksp_pod_unmap( (void *)quic              );
  fd_wksp_pod_unmap( fd_mcache_leave( mcache ) );
  fd_wksp_pod_unmap( fd_dcache_leave( dcache ) );
  fd_wksp_pod_unmap( fd_cnc_leave   ( cnc    ) );
  fd_wksp_pod_detach( pod );
  return 0;
}
