#include "../fd_disco.h"

#if FD_HAS_HOSTED

FD_STATIC_ASSERT( FD_MUX_TILE_SCRATCH_ALIGN<=FD_SHMEM_HUGE_PAGE_SZ, alignment );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Init" ));

  char const * _cnc        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cnc",        NULL, NULL );
  char const * _in_mcaches = fd_env_strip_cmdline_cstr ( &argc, &argv, "--in-mcaches", NULL, ""   );
  char const * _in_fseqs   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--in-fseqs",   NULL, ""   );
  char const * _mcache     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache",     NULL, NULL );
  char const * _out_fseqs  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--out-fseqs",  NULL, ""   );
  ulong        cr_max      = fd_env_strip_cmdline_ulong( &argc, &argv, "--cr-max",     NULL, 0UL  ); /*   0 <> use default */
  long         lazy        = fd_env_strip_cmdline_long ( &argc, &argv, "--lazy",       NULL, 0L   ); /* <=0 <> use default */
  uint         seed        = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",       NULL, (uint)(ulong)fd_tickcount() );

  if( FD_UNLIKELY( !_cnc ) ) FD_LOG_ERR(( "--cnc not specified" ));
  FD_LOG_NOTICE(( "Joining --cnc %s", _cnc ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));

  char * _in_mcache[ 256 ];
  ulong in_cnt = fd_cstr_tokenize( _in_mcache, 256UL, (char *)_in_mcaches, ',' ); /* argv is non-const */
  if( FD_UNLIKELY( in_cnt>256UL ) ) FD_LOG_ERR(( "too many --in-mcaches specified for current implementation" ));

  fd_frag_meta_t const * in_mcache[ 256 ];
  for( ulong in_idx=0UL; in_idx<in_cnt; in_idx++ ) {
    FD_LOG_NOTICE(( "Joining --in-mcaches[%lu] %s", in_idx, _in_mcache[ in_idx ] ));
    in_mcache[ in_idx ] = fd_mcache_join( fd_wksp_map( _in_mcache[ in_idx ] ) );
    if( FD_UNLIKELY( !in_mcache[ in_idx ] ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));
  }

  char * _in_fseq[ 256 ];
  ulong tmp = fd_cstr_tokenize( _in_fseq, 256UL, (char *)_in_fseqs, ',' ); /* argv is non-const */
  if( FD_UNLIKELY( tmp!=in_cnt ) ) FD_LOG_ERR(( "--in-mcaches and --in-fseqs mismatch" ));

  ulong * in_fseq[ 256 ];
  for( ulong in_idx=0UL; in_idx<in_cnt; in_idx++ ) {
    FD_LOG_NOTICE(( "Joining --in-fseqs[%lu] %s", in_idx, _in_fseq[ in_idx ] ));
    in_fseq[ in_idx ] = fd_fseq_join( fd_wksp_map( _in_fseq[ in_idx ] ) );
    if( FD_UNLIKELY( !in_fseq[ in_idx ] ) ) FD_LOG_ERR(( "fd_fseq_join failed" ));
  }

  if( FD_UNLIKELY( !_mcache ) ) FD_LOG_ERR(( "--mcache not specified" ));
  FD_LOG_NOTICE(( "Joining --mcache %s", _mcache ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

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
  ulong footprint = fd_mux_tile_scratch_footprint( in_cnt, out_cnt );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "fd_mux_tile_scratch_footprint failed" ));
  ulong  page_sz  = FD_SHMEM_HUGE_PAGE_SZ;
  ulong  page_cnt = fd_ulong_align_up( footprint, page_sz ) / page_sz;
  ulong  cpu_idx  = fd_tile_cpu_id( fd_tile_idx() );
  void * scratch  = fd_shmem_acquire( page_sz, page_cnt, cpu_idx );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "fd_shmem_acquire failed (need at least %lu free huge pages on numa node %lu)",
                                             page_cnt, fd_shmem_numa_idx( cpu_idx ) ));

  FD_LOG_NOTICE(( "Run" ));

  fd_mux_callbacks_t callbacks = {0};
  int err = fd_mux_tile( cnc, 0, FD_MUX_FLAG_DEFAULT, in_cnt, in_mcache, in_fseq, mcache, out_cnt, out_fseq, cr_max, lazy, rng, scratch, NULL, &callbacks );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_mux_tile failed (%i)", err ));

  FD_LOG_NOTICE(( "Fini" ));

  fd_shmem_release( scratch, page_sz, page_cnt );
  fd_rng_delete( fd_rng_leave( rng ) );
  for( ulong out_idx=out_cnt; out_idx; out_idx-- ) fd_wksp_unmap( fd_fseq_leave( out_fseq[ out_idx-1UL ] ) );
  fd_wksp_unmap( fd_mcache_leave( mcache ) );
  for( ulong in_idx=in_cnt; in_idx; in_idx-- ) fd_wksp_unmap( fd_fseq_leave  ( in_fseq  [ in_idx-1UL ] ) );
  for( ulong in_idx=in_cnt; in_idx; in_idx-- ) fd_wksp_unmap( fd_mcache_leave( in_mcache[ in_idx-1UL ] ) );
  fd_wksp_unmap( fd_cnc_leave( cnc ) );

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

