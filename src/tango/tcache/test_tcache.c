#include "../fd_tango.h"

#if FD_HAS_HOSTED

FD_STATIC_ASSERT( FD_TCACHE_ALIGN==128UL,              unit_test );
FD_STATIC_ASSERT( FD_TCACHE_FOOTPRINT(1UL,4UL)==128UL, unit_test );
FD_STATIC_ASSERT( FD_TCACHE_FOOTPRINT(28UL,32UL)==384UL, unit_test );

FD_STATIC_ASSERT( FD_TCACHE_TAG_NULL==0UL, unit_test );

FD_STATIC_ASSERT( FD_TCACHE_SPARSE_DEFAULT==2, unit_test );

/* check_map verifies every map slot against the ring (unique idx,
   exact or saturated disp, fp) and that live ring entries are mapped. */

static void
check_map( ulong const * ring,
           ulong         depth,
           uint const *  map,
           ulong         map_cnt ) {
  FD_TCACHE_MAP_LAYOUT( ib, imask, dmax, fpsh, depth );
  ulong live = 0UL;
  for( ulong i=0UL; i<depth; i++ ) live += !fd_tcache_tag_is_null( ring[ i ] );
  ulong used = 0UL;
  for( ulong i=0UL; i<map_cnt; i++ ) {
    ulong s = map[ i ];
    if( !s ) continue;
    used++;
    ulong idx = (s & imask)-1UL;             FD_TEST( idx<depth );
    ulong tag = ring[ idx ];                 FD_TEST( !fd_tcache_tag_is_null( tag ) );
    ulong d   = (i - fd_tcache_map_start( tag, map_cnt )) & (map_cnt-1UL);
    FD_TEST( ((s>>ib) & dmax)==fd_ulong_min( d, dmax ) );
    FD_TEST( (s>>fpsh)==((tag>>32)>>fpsh) );
    for( ulong j=1UL; j<=d; j++ ) FD_TEST( map[ (i-j) & (map_cnt-1UL) ] ); /* no hole between home and slot */
    for( ulong j=i+1UL; j<map_cnt; j++ ) FD_TEST( (map[ j ] & imask)!=(s & imask) );
  }
  FD_TEST( used==live );
}

/* Clustered tags (few distinct homes) at high fill vs a reference
   ring scan: forces saturated disp, wrap and long shift deletes. */

static void
test_cluster( fd_rng_t * rng,
              ulong      depth,
              ulong      map_cnt,
              ulong      home_cnt ) {
  static ulong mem[ 4096 ] __attribute__((aligned(FD_TCACHE_ALIGN)));
  FD_TEST( fd_tcache_footprint( depth, map_cnt )<=sizeof(mem) );
  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( mem, depth, map_cnt ) ); FD_TEST( tcache );
  ulong * ring   = fd_tcache_ring_laddr( tcache );
  uint *  map    = fd_tcache_map_laddr ( tcache );
  ulong   oldest = 0UL;
  for( ulong iter=0UL; iter<200000UL; iter++ ) {
    ulong tag;
    if( fd_rng_uint( rng ) & 1U ) tag = ring[ fd_rng_ulong_roll( rng, depth ) ];
    else                          tag = (fd_rng_ulong( rng ) & ~(map_cnt-1UL)) | ((map_cnt-3UL+fd_rng_ulong_roll( rng, home_cnt )) & (map_cnt-1UL));
    if( fd_tcache_tag_is_null( tag ) ) tag = map_cnt-1UL;
    int ref_dup = 0;
    for( ulong i=0UL; i<depth; i++ ) ref_dup |= (ring[ i ]==tag);
    int found; ulong map_idx;
    FD_TCACHE_QUERY( found, map_idx, ring, depth, map, map_cnt, tag );
    FD_TEST( found==ref_dup ); FD_TEST( map_idx<map_cnt );
    int dup;
    FD_TCACHE_INSERT( dup, oldest, ring, depth, map, map_cnt, tag );
    FD_TEST( dup==ref_dup );
    FD_TCACHE_QUERY( found, map_idx, ring, depth, map, map_cnt, tag );
    FD_TEST( found );
    if( !(iter & 63UL) ) check_map( ring, depth, map, map_cnt );
  }
  check_map( ring, depth, map, map_cnt );
  FD_TEST( fd_tcache_delete( fd_tcache_leave( tcache ) )==mem );
}

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
  FD_TEST( !fd_tcache_footprint( (ulong)UINT_MAX+1UL, 0UL ) );

  do { FD_TCACHE_MAP_LAYOUT( ib, imask, dmax, fpsh, 8388606UL  ); FD_TEST( ib==23 && imask==0x7fffffUL && dmax==31UL && fpsh==28 ); } while(0);
  do { FD_TCACHE_MAP_LAYOUT( ib, imask, dmax, fpsh, 1UL<<28    ); FD_TEST( ib==29 && dmax== 7UL && fpsh==32 ); (void)imask; } while(0);
  do { FD_TCACHE_MAP_LAYOUT( ib, imask, dmax, fpsh, UINT_MAX   ); FD_TEST( ib==32 && dmax== 0UL && fpsh==32 ); (void)imask; } while(0);

  test_cluster( rng,  30UL,  32UL,  2UL );
  test_cluster( rng,  60UL,  64UL, 64UL );
  test_cluster( rng, 100UL, 128UL,  4UL );
  test_cluster( rng, 126UL, 512UL,  3UL );
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
  uint *  map     = fd_tcache_map_laddr   ( tcache ); FD_TEST( map     );
  ulong   oldest  = _oldest[0];                       FD_TEST( !oldest );

  FD_TEST( fd_tcache_tag_is_null( FD_TCACHE_TAG_NULL ) );
  FD_TEST( fd_tcache_tag_is_null( ring[ oldest ]     ) );

  FD_LOG_NOTICE(( "Testing query" ));

  for( ulong seq=0UL; seq<depth; seq++ ) {
    ulong tag = fd_ulong_hash( seq + 1UL ); /* Assumes FD_TCACHE_TAG_NULL is zero, hash is perm and hash(0) is 0 */

    int   found;
    ulong map_idx;
    FD_TCACHE_QUERY( found, map_idx, ring, depth, map, map_cnt, tag );
    FD_TEST( !found );
    FD_TEST( map_idx<map_cnt );
    FD_TEST( !map[ map_idx ] );

    int dup;
    FD_TCACHE_INSERT( dup, oldest, ring, depth, map, map_cnt, tag );
    FD_TEST( !dup );
    FD_TEST( oldest==(seq+1UL)%depth );

    int   found2;
    ulong map_idx2;
    FD_TCACHE_QUERY( found2, map_idx2, ring, depth, map, map_cnt, tag );
    FD_TEST( found2 );
    FD_TEST( map_idx2==map_idx );
    FD_TEST( (map[ map_idx ] & ((1UL<<(fd_ulong_find_msb( depth )+1))-1UL))==seq+1UL );
  }

  if( depth<=(1UL<<16) ) check_map( ring, depth, map, map_cnt );

  FD_LOG_NOTICE(( "Testing remove" ));

  for( ulong seq=0UL; seq<depth; seq++ ) {
    ulong tag = fd_ulong_hash( seq + 1UL ); /* Assumes FD_TCACHE_TAG_NULL is zero, hash is perm and hash(0) is 0 */

    int   found;
    ulong map_idx;
    FD_TCACHE_QUERY( found, map_idx, ring, depth, map, map_cnt, tag );
    FD_TEST( found );
    FD_TEST( map_idx<map_cnt );

    fd_tcache_remove( ring, depth, map, map_cnt, seq );

    int   found2;
    ulong map_idx2;
    FD_TCACHE_QUERY( found2, map_idx2, ring, depth, map, map_cnt, tag );
    FD_TEST( !found2 );
    FD_TEST( map_idx2<map_cnt ); /* remove might have shuffled map so no guarantee map_idx2 will match */
    FD_TEST( !map[ map_idx2 ] );
  }
  for( ulong map_idx=0UL; map_idx<map_cnt; map_idx++ ) FD_TEST( !map[ map_idx ] );

  FD_LOG_NOTICE(( "Testing reset" )); /* note also that fd_mcache_new tests also cover reset */

  /* Loads up the tcache */
  for( ulong seq=0UL; seq<depth; seq++ ) {
    ulong tag = fd_ulong_hash( seq + 1UL ); /* Assumes FD_TCACHE_TAG_NULL is zero, hash is perm and hash(0) is 0 */
    int dup;
    FD_TCACHE_INSERT( dup, oldest, ring, depth, map, map_cnt, tag );
    FD_TEST( !dup );
  }

  FD_TEST( !fd_tcache_reset( ring, depth, map, map_cnt ) );

  for( ulong seq=0UL; seq<depth; seq++ ) {
    ulong tag = fd_ulong_hash( seq + 1UL ); /* Assumes FD_TCACHE_TAG_NULL is zero, hash is perm and hash(0) is 0 */

    int   found;
    ulong map_idx;
    FD_TCACHE_QUERY( found, map_idx, ring, depth, map, map_cnt, tag );
    FD_TEST( !found );
    FD_TEST( map_idx<map_cnt );
    FD_TEST( !map[ map_idx ] );
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
        FD_TCACHE_QUERY( found, map_idx, ring, depth, map, map_cnt, tag );
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
