#include "../fd_tango.h"

#if FD_HAS_HOSTED

FD_STATIC_ASSERT( FD_TCACHE_ALIGN==128UL,              unit_test );
FD_STATIC_ASSERT( FD_TCACHE_FOOTPRINT(1UL,4UL)==128UL, unit_test );

FD_STATIC_ASSERT( FD_TCACHE_TAG_NULL==0UL, unit_test );

FD_STATIC_ASSERT( FD_TCACHE_SPARSE_DEFAULT==2, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_tcache_align()==FD_TCACHE_ALIGN );
  FD_TEST( !fd_tcache_footprint( ULONG_MAX, 4UL ) );
  FD_TEST( !fd_tcache_footprint( 1UL, ULONG_MAX ) );
  FD_TEST( fd_tcache_map_cnt_default( 0UL )== 0UL );
  FD_TEST( fd_tcache_map_cnt_default( 1UL )== 8UL );
  FD_TEST( fd_tcache_map_cnt_default( 2UL )== 8UL );
  FD_TEST( fd_tcache_map_cnt_default( 3UL )==16UL );
  FD_TEST( fd_tcache_map_cnt_default( 6UL )==16UL );
  FD_TEST( fd_tcache_map_cnt_default( 7UL )==32UL );
  for( ulong rem=1000000UL; rem; rem-- ) {
    uint  r       = fd_rng_uint( rng );
    ulong depth   = (ulong)(r & 1023U);     r >>= 10;
    ulong map_cnt = 1UL << (int)(r & 15U);  r >>=  4;
    ulong delta   = (ulong)(r & 1U);        r >>=  1;
    if( (int)(r & 1U) ) { delta = -delta; } r >>=  1;
    map_cnt += delta;
    /* delta is in  [0,2^10) */
    /* map_cnt is a 2^[0,15] +/- {0,1} */
    ulong footprint = fd_tcache_footprint( depth, map_cnt );
    if( !map_cnt ) map_cnt = fd_tcache_map_cnt_default( depth ); /* get the actual map_cnt used */
    if( (!depth) || map_cnt<(depth+2UL) || !fd_ulong_is_pow2( map_cnt ) ) FD_TEST( !footprint );
    else FD_TEST( footprint==FD_TCACHE_FOOTPRINT( depth, map_cnt ) );
  }

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",     NULL, "gigantic"                   );
  ulong        page_cnt    = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",    NULL, 1UL                          );
  ulong        numa_idx    = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",    NULL, fd_shmem_numa_idx( cpu_idx ) );
  ulong        depth       = fd_env_strip_cmdline_ulong( &argc, &argv, "--depth",       NULL, (1UL<<22)-1UL );
  ulong        map_cnt     = fd_env_strip_cmdline_ulong( &argc, &argv, "--map-cnt",     NULL, 0UL           ); /* 0 <> use def */
  float        dup_frac    = fd_env_strip_cmdline_float( &argc, &argv, "--dup-frac",    NULL, 0.5f          );
  float        dup_avg_age = fd_env_strip_cmdline_float( &argc, &argv, "--dup-avg-age", NULL, 1.f           );

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp =
    fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  ulong  align     = fd_tcache_align();
  ulong  footprint = fd_tcache_footprint( depth, map_cnt );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "bad depth / map_cnt" ));
  FD_LOG_NOTICE(( "Creating tcache (--depth %lu, --map-cnt %lu, align %lu, footprint %lu)", depth, map_cnt, align, footprint ));
  void *        mem     = fd_wksp_alloc_laddr( wksp, align, footprint, 1UL ); FD_TEST( mem );
  void *        _tcache = fd_tcache_new( mem, depth, map_cnt );               FD_TEST( _tcache );
  fd_tcache_t * tcache  = fd_tcache_join( _tcache );                          FD_TEST( tcache );

  if( !map_cnt ) {
    map_cnt = fd_tcache_map_cnt_default( depth );
    FD_LOG_NOTICE(( "default map_cnt %lu used", map_cnt ));
  }

  FD_TEST( fd_tcache_depth  ( tcache )==depth   );
  FD_TEST( fd_tcache_map_cnt( tcache )==map_cnt );
  ulong * _oldest = fd_tcache_oldest_laddr( tcache ); FD_TEST( _oldest );
  ulong * ring    = fd_tcache_ring_laddr  ( tcache ); FD_TEST( ring    );
  ulong * map     = fd_tcache_map_laddr   ( tcache ); FD_TEST( map     );
  ulong   oldest  = _oldest[0];                       FD_TEST( !oldest );

  FD_TEST( fd_tcache_tag_is_null( FD_TCACHE_TAG_NULL ) );
  FD_TEST( fd_tcache_tag_is_null( ring[ oldest ]     ) );

  FD_LOG_NOTICE(( "Testing query" ));

  for( ulong seq=0UL; seq<depth; seq++ ) {
    ulong tag = fd_ulong_hash( seq + 1UL ); /* Assumes FD_TCACHE_TAG_NULL is zero, hash is perm and hash(0) is 0 */

    int   found;
    ulong map_idx;
    FD_TCACHE_QUERY( found, map_idx, map, map_cnt, tag );
    FD_TEST( !found );
    FD_TEST( map_idx<map_cnt );
    FD_TEST( fd_tcache_tag_is_null( map[ map_idx ] ) );

    map[ map_idx ] = tag;

    int   found2;
    ulong map_idx2;
    FD_TCACHE_QUERY( found2, map_idx2, map, map_cnt, tag );
    FD_TEST( found2 );
    FD_TEST( map_idx2==map_idx );
    FD_TEST( map[ map_idx ]==tag );
  }

  FD_LOG_NOTICE(( "Testing remove" ));

  for( ulong seq=0UL; seq<depth; seq++ ) {
    ulong tag = fd_ulong_hash( seq + 1UL ); /* Assumes FD_TCACHE_TAG_NULL is zero, hash is perm and hash(0) is 0 */

    int   found;
    ulong map_idx;
    FD_TCACHE_QUERY( found, map_idx, map, map_cnt, tag );
    FD_TEST( found );
    FD_TEST( map_idx<map_cnt );
    FD_TEST( map[ map_idx ]==tag );

    fd_tcache_remove( map, map_cnt, tag );

    int   found2;
    ulong map_idx2;
    FD_TCACHE_QUERY( found2, map_idx2, map, map_cnt, tag );
    FD_TEST( !found2 );
    FD_TEST( map_idx2<map_cnt ); /* remove might have shuffled map so no guarantee map_idx2 will match */
    FD_TEST( fd_tcache_tag_is_null( map[ map_idx2 ] ) );
  }

  FD_LOG_NOTICE(( "Testing reset" )); /* note also that fd_mcache_new tests also cover reset */

  /* Loads up the tcache */
  for( ulong seq=0UL; seq<depth; seq++ ) {
    ulong tag = fd_ulong_hash( seq + 1UL ); /* Assumes FD_TCACHE_TAG_NULL is zero, hash is perm and hash(0) is 0 */

    int   found;
    ulong map_idx;
    FD_TCACHE_QUERY( found, map_idx, map, map_cnt, tag );
    FD_TEST( !found );
    FD_TEST( map_idx<map_cnt );
    FD_TEST( fd_tcache_tag_is_null( map[ map_idx ] ) );

    map[ map_idx ] = tag;
  }

  FD_TEST( !fd_tcache_reset( ring, depth, map, map_cnt ) );

  for( ulong seq=0UL; seq<depth; seq++ ) {
    ulong tag = fd_ulong_hash( seq + 1UL ); /* Assumes FD_TCACHE_TAG_NULL is zero, hash is perm and hash(0) is 0 */

    int   found;
    ulong map_idx;
    FD_TCACHE_QUERY( found, map_idx, map, map_cnt, tag );
    FD_TEST( !found );
    FD_TEST( map_idx<map_cnt );
    FD_TEST( fd_tcache_tag_is_null( map[ map_idx ] ) );
  }

  FD_LOG_NOTICE(( "Running (--dup-frac %e, --dup-avg-age %e)", (double)dup_frac, (double)dup_avg_age ));

  oldest = fd_tcache_reset( ring, depth, map, map_cnt );      FD_TEST( !oldest );
  uint dup_thresh = (uint)(0.5f + dup_frac*(float)(1UL<<32));
  
  for( ulong rem=3UL*depth; rem; rem-- ) {

    ulong tag;

    int is_dup = (fd_rng_uint( rng ) < dup_thresh);
    if( is_dup ) { /* Next tag should be a duplicate */

      /* Randomly select a tag from an IID exponential distribution
         that is on average dup_avg_age back from the newest tag. */

      ulong age; do age = (ulong)(uint)(int)(1.0f + dup_avg_age*fd_rng_float_exp( rng )); while( FD_UNLIKELY( age>depth ) );
      /* At this point, oldest is in [0,depth-1] and age is in
         [1,depth].  Thus depth-age is in [0,depth-1] and
         oldest+depth-age is in [0,2*depth-2] */
      ulong dup_idx = oldest + depth - age;
      dup_idx = fd_ulong_if( dup_idx<depth, dup_idx, dup_idx-depth );

      tag = ring[ dup_idx ];
      if( FD_UNLIKELY( fd_tcache_tag_is_null( tag ) ) ) is_dup = 0; /* handle dup during startup */
    }

    if( !is_dup ) {

      /* Randomly select a non-NULL 64-bit tag from an IID uniform
         distribution.  For extra paranoia, we strictly check has tag is
         not already in the cache found. */

      int found;
      do {
        do tag = fd_rng_ulong( rng ); while( FD_UNLIKELY( fd_tcache_tag_is_null( tag ) ) );
        ulong map_idx;
        FD_TCACHE_QUERY( found, map_idx, map, map_cnt, tag );
        (void)map_idx;
      } while( FD_UNLIKELY( found ) );
    }

    int dup;
    FD_TCACHE_INSERT( dup, oldest, ring, depth, map, map_cnt, tag );
    FD_TEST( dup==is_dup );
    rem += (ulong)is_dup; /* Only count unique inserts */
  }

  FD_LOG_NOTICE(( "Benchmarking" ));

  ulong   bench_cnt = 1UL<<20;
  ulong * bench_tag = (ulong *)fd_wksp_alloc_laddr( wksp, 0UL, bench_cnt*sizeof(ulong), 1UL ); FD_TEST( bench_tag );

  for( ulong iter=0UL; iter<10UL; iter++ ) {

    /* Make a longish test vector */
    for( ulong bench_idx=0UL; bench_idx<bench_cnt; bench_idx++ ) {
      ulong tag;
      int is_dup = (fd_rng_uint( rng ) < dup_thresh);
      if( is_dup ) { /* Next tag should be a duplicate */
        ulong age = (ulong)(uint)(int)(1.0f + dup_avg_age*fd_rng_float_exp( rng )); /* note that age is at least 1 */
        if( FD_UNLIKELY( age>=bench_idx ) ) is_dup = 0; /* Duplicate of a "pre-benchmark" tag ... just use random */
        else                                tag = bench_tag[ bench_idx - age ];
      }
      if( !is_dup ) do tag = fd_rng_ulong( rng ); while( FD_UNLIKELY( fd_tcache_tag_is_null( tag ) ) );
      bench_tag[ bench_idx ] = tag;
    }

    /* Benchmark it */
    long tic = fd_log_wallclock();
    for( ulong bench_idx=0UL; bench_idx<bench_cnt; bench_idx++ ) {
      int dup;
      FD_TCACHE_INSERT( dup, oldest, ring, depth, map, map_cnt, bench_tag[ bench_idx ] );
      (void)dup;
    }
    long toc = fd_log_wallclock();

    float avg = ((float)(toc-tic))/((float)bench_cnt);
    FD_LOG_NOTICE(( "iter %lu: %.3f ns/dedup", iter, (double)avg ));
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_wksp_free_laddr( bench_tag );

  FD_TEST( fd_tcache_leave ( tcache  )==_tcache );
  FD_TEST( fd_tcache_delete( _tcache )==mem     );
  fd_wksp_free_laddr( mem );
  fd_wksp_delete_anonymous( wksp );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED capabilities" ));
  fd_halt();
  return 0;
}

#endif
