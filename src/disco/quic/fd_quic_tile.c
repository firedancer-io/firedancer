#include "fd_quic.h"

#if FD_HAS_HOSTED && FD_HAS_X86

FD_STATIC_ASSERT( FD_QUIC_TILE_SCRATCH_ALIGN<=FD_SHMEM_HUGE_PAGE_SZ, alignment );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "init" ));

  char const * _cnc       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cnc",       NULL, NULL   );
  ulong        orig       = fd_env_strip_cmdline_ulong( &argc, &argv, "--orig",      NULL, 0UL    );
  char const * _mcache    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache",    NULL, NULL   );
  char const * _dcache    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--dcache",    NULL, NULL   );
  uint         seed       = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",      NULL, (uint)(ulong)fd_tickcount() );
  long         lazy       = fd_env_strip_cmdline_long ( &argc, &argv, "--lazy",      NULL, 0L     ); /* <=0 <> use default */
  char const * _quic      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--quic",      NULL, NULL   );

  fd_quic_config_t quic_cfg = {0};
  if( FD_UNLIKELY( !fd_quic_config_from_env( &argc, &argv, &quic_cfg ) ) )
    FD_LOG_ERR(( "fd_quic_config_from_env failed" ));

  if( FD_UNLIKELY( !_cnc ) ) FD_LOG_ERR(( "--cnc not specified" ));
  FD_LOG_NOTICE(( "Joining --cnc %s", _cnc ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));

  if( FD_UNLIKELY( !_mcache ) ) FD_LOG_ERR(( "--mcache not specified" ));
  FD_LOG_NOTICE(( "Joining --mcache %s", _mcache ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  ulong depth = fd_mcache_depth( mcache );

  if( FD_UNLIKELY( !_dcache ) ) FD_LOG_ERR(( "--dcache not specified" ));
  FD_LOG_NOTICE(( "Joining --dcache %s", _dcache ));
  uchar * dcache = fd_dcache_join( fd_wksp_map( _dcache ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));

  FD_LOG_NOTICE(( "Using --lazy %li", lazy ));

  FD_LOG_NOTICE(( "Creating rng --seed %u", seed ));
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  if( FD_UNLIKELY( !_quic ) ) FD_LOG_ERR(( "--quic not specified" ));
  FD_LOG_NOTICE(( "Joining --quic %s", _quic ));
  fd_quic_t * quic = (fd_quic_t *)fd_wksp_map( _quic ); /* TODO join func */
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_join failed" ));

  FD_LOG_NOTICE(( "Creating scratch" ));
  ulong footprint = fd_quic_tile_scratch_footprint( depth );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "fd_quic_tile_scratch_footprint failed" ));
  ulong  page_sz  = FD_SHMEM_HUGE_PAGE_SZ;
  ulong  page_cnt = fd_ulong_align_up( footprint, page_sz ) / page_sz;
  ulong  cpu_idx  = fd_tile_cpu_id( fd_tile_idx() );
  void * scratch  = fd_shmem_acquire( page_sz, page_cnt, cpu_idx );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "fd_shmem_acquire failed (need at least %lu free huge pages on numa node %lu)",
                                             page_cnt, fd_shmem_numa_idx( cpu_idx ) ));

  FD_LOG_NOTICE(( "Run" ));

  int err = fd_quic_tile( cnc, orig, quic, &quic_cfg, mcache, dcache, lazy, rng, scratch );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_quic_tile failed (%i)", err ));

  FD_LOG_NOTICE(( "Fini" ));

  fd_shmem_release( scratch, page_sz, page_cnt );
  fd_wksp_unmap(        (void *)( quic   ) );
  fd_rng_delete( fd_rng_leave   ( rng    ) );
  fd_wksp_unmap( fd_dcache_leave( dcache ) );
  fd_wksp_unmap( fd_mcache_leave( mcache ) );
  fd_wksp_unmap( fd_cnc_leave   ( cnc    ) );

  fd_halt();
  return err;
}

#else /* FD_HAS_HOSTED && FD_HAS_X86 */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "not supported for this build target" ));
  fd_halt();
  return 0;
}

#endif /* FD_HAS_HOSTED && FD_HAS_X86 */
