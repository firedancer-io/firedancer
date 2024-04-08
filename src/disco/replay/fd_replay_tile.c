#include "../fd_disco.h"

#if FD_HAS_HOSTED

FD_STATIC_ASSERT( FD_REPLAY_TILE_SCRATCH_ALIGN<=FD_SHMEM_HUGE_PAGE_SZ, alignment );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Init" ));

  char const * _cnc       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cnc",       NULL, NULL   );
  char const * _pcap      = fd_env_strip_cmdline_cstr ( &argc, &argv, "--pcap",      NULL, NULL   );
  ulong        pkt_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--pkt-max",   NULL, 1522UL );
  ulong        orig       = fd_env_strip_cmdline_ulong( &argc, &argv, "--orig",      NULL, 0UL    );
  char const * _mcache    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache",    NULL, NULL   );
  char const * _dcache    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--dcache",    NULL, NULL   );
  char const * _out_fseqs = fd_env_strip_cmdline_cstr ( &argc, &argv, "--out-fseqs", NULL, ""     );
  ulong        cr_max     = fd_env_strip_cmdline_ulong( &argc, &argv, "--cr-max",    NULL, 0UL    ); /*   0 <> use default */
  long         lazy       = fd_env_strip_cmdline_long ( &argc, &argv, "--lazy",      NULL, 0L     ); /* <=0 <> use default */
  uint         seed       = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",      NULL, (uint)(ulong)fd_tickcount() );

  if( FD_UNLIKELY( !_cnc ) ) FD_LOG_ERR(( "--cnc not specified" ));
  FD_LOG_NOTICE(( "Joining --cnc %s", _cnc ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));

  if( FD_UNLIKELY( !_pcap ) ) FD_LOG_ERR(( "--pcap not specified" ));
  FD_LOG_NOTICE(( "Using --pcap %s", _pcap ));

  if( FD_UNLIKELY( !_mcache ) ) FD_LOG_ERR(( "--mcache not specified" ));
  FD_LOG_NOTICE(( "Joining --mcache %s", _mcache ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

  if( FD_UNLIKELY( !_dcache ) ) FD_LOG_ERR(( "--dcache not specified" ));
  FD_LOG_NOTICE(( "Joining --dcache %s", _dcache ));
  uchar * dcache = fd_dcache_join( fd_wksp_map( _dcache ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));

  char * _out_fseq[ 256 ];
  ulong out_cnt = fd_cstr_tokenize( _out_fseq, 256UL, (char *)_out_fseqs, ',' ); /* argv is non-const */
  if( FD_UNLIKELY( out_cnt>256UL ) ) FD_LOG_ERR(( "too many --out-fseqs specified for current implementation" ));

  ulong * out_fseq[ 256 ];
  for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {
    FD_LOG_NOTICE(( "Joining --out-fseqs[%lu] %s", out_idx, _out_fseq[ out_idx ] ));
    out_fseq[ out_idx ] = fd_fseq_join( fd_wksp_map( _out_fseq[ out_idx ] ) );
    if( FD_UNLIKELY( !out_fseq[ out_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  }

  FD_LOG_NOTICE(( "Using --cr-max %lu, --lazy %li", cr_max, lazy ));

  FD_LOG_NOTICE(( "Creating rng --seed %u", seed ));
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  FD_LOG_NOTICE(( "Creating scratch" ));
  ulong footprint = fd_replay_tile_scratch_footprint( out_cnt );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "fd_replay_tile_scratch_footprint failed" ));
  ulong  page_sz  = FD_SHMEM_HUGE_PAGE_SZ;
  ulong  page_cnt = fd_ulong_align_up( footprint, page_sz ) / page_sz;
  ulong  cpu_idx  = fd_tile_cpu_id( fd_tile_idx() );
  void * scratch  = fd_shmem_acquire( page_sz, page_cnt, cpu_idx );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "fd_shmem_acquire failed (need at least %lu free huge pages on numa node %lu)",
                                             page_cnt, fd_shmem_numa_idx( cpu_idx ) ));

  FD_LOG_NOTICE(( "Run" ));

  int err = fd_replay_tile( cnc, _pcap, pkt_max, orig, mcache, dcache, out_cnt, out_fseq, cr_max, lazy, rng, scratch );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_replay_tile failed (%i)", err ));

  FD_LOG_NOTICE(( "Fini" ));

  fd_shmem_release( scratch, page_sz, page_cnt );
  fd_rng_delete( fd_rng_leave( rng ) );
  for( ulong out_idx=out_cnt; out_idx; out_idx-- ) fd_wksp_unmap( fd_fseq_leave( out_fseq[ out_idx-1UL ] ) );
  fd_wksp_unmap( fd_dcache_leave( dcache ) );
  fd_wksp_unmap( fd_mcache_leave( mcache ) );
  fd_wksp_unmap( fd_cnc_leave   ( cnc    ) );

  fd_halt();
  return err;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "implement support for this build target" ));
  fd_halt();
  return 1;
}

#endif

