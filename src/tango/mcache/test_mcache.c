#include "../fd_tango.h"

FD_STATIC_ASSERT( FD_FRAG_META_ALIGN    ==32UL, unit_test );
FD_STATIC_ASSERT( FD_FRAG_META_FOOTPRINT==32UL, unit_test );
/* FIXME: VERIFY MORE OF THE FRAG_META LAYOUT TO SNIFF OUT SILENT ABI CHANGES */

FD_STATIC_ASSERT( FD_MCACHE_ALIGN                 == 128UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_FOOTPRINT(128UL,  0UL)==4352UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_FOOTPRINT(128UL,  1UL)==4480UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_FOOTPRINT(128UL,128UL)==4480UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_FOOTPRINT(128UL,129UL)==4608UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_FOOTPRINT(256UL,  0UL)==8448UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_FOOTPRINT(256UL,  1UL)==8576UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_FOOTPRINT(256UL,128UL)==8576UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_FOOTPRINT(256UL,129UL)==8704UL, unit_test );

FD_STATIC_ASSERT( FD_MCACHE_SEQ_CNT==16UL, unit_test );

FD_STATIC_ASSERT( FD_MCACHE_LG_BLOCK     ==     7, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_LG_INTERLEAVE==     0, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_BLOCK        == 128UL, unit_test );

#define DEPTH_MAX (1024UL)
#define APP_MAX   (4096UL)

static uchar __attribute__((aligned(FD_MCACHE_ALIGN))) shmem[ FD_MCACHE_FOOTPRINT( DEPTH_MAX, APP_MAX ) ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong depth  = fd_env_strip_cmdline_ulong( &argc, &argv, "--depth",  NULL,    DEPTH_MAX );
  ulong app_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--app-sz", NULL,      APP_MAX );
  ulong seq0   = fd_env_strip_cmdline_ulong( &argc, &argv, "--seq0",   NULL, 1234567890UL );

  if( FD_UNLIKELY( depth >DEPTH_MAX ) ) FD_LOG_ERR(( "Increase unit test DEPTH_MAX to support this large --depth" ));
  if( FD_UNLIKELY( app_sz>APP_MAX   ) ) FD_LOG_ERR(( "Increase unit test APP_MAX to support this large --app-sz" ));

  FD_LOG_NOTICE(( "Testing with --depth %lu and --app-sz %lu", depth, app_sz ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Test mcache procurement */

  FD_TEST( fd_mcache_align()==FD_MCACHE_ALIGN );

  /* FIXME: MORE fd_mcache_footprint TESTS */
  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong _depth     = fd_rng_ulong_roll( rng, DEPTH_MAX+1UL ); /* In [0,DEPTH_MAX] */
    ulong _app_sz    = fd_rng_ulong_roll( rng,   APP_MAX+1UL ); /* In [0,  APP_MAX] */
    FD_TEST( fd_mcache_footprint( _depth, _app_sz )==fd_ulong_if( (_depth>=FD_MCACHE_BLOCK) & fd_ulong_is_pow2(_depth),
                                                                  FD_MCACHE_FOOTPRINT( _depth, _app_sz ), 0UL ) );
  }

  /* Test failure cases for fd_mcache_new */

  FD_TEST( fd_mcache_new( NULL,      depth, app_sz, seq0 )==NULL ); /* null shmem */
  FD_TEST( fd_mcache_new( shmem+1UL, depth, app_sz, seq0 )==NULL ); /* misaligned shmem */
  FD_TEST( fd_mcache_new( shmem,     0,     app_sz, seq0 )==NULL ); /* zero depth */

  /* Test mcache creation */

  ulong footprint = fd_mcache_footprint( depth, app_sz );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "Bad --depth" ));
  FD_TEST( footprint==FD_MCACHE_FOOTPRINT( depth,     app_sz  ) );
  FD_TEST( footprint<=FD_MCACHE_FOOTPRINT( DEPTH_MAX, APP_MAX ) );

  void * shmcache = fd_mcache_new( shmem, depth, app_sz, seq0 ); FD_TEST( shmcache );

  /* Test failure cases for fd_mcache_join */

  FD_TEST( fd_mcache_join( NULL          )==NULL ); /* null shmcache */
  FD_TEST( fd_mcache_join( (void *)0x1UL )==NULL ); /* misaligned shmcache */

  /* Test bad magic value */
  ulong * shfseq_magic = (ulong *)shmcache;
  (*shfseq_magic)++;
  FD_TEST( fd_mcache_join( shmcache )==NULL );
  (*shfseq_magic)--;

  fd_frag_meta_t * mcache = fd_mcache_join( shmcache );
  FD_TEST( mcache );
  FD_TEST( fd_ulong_is_aligned( (ulong)mcache, FD_MCACHE_ALIGN ) );

  /* Test mcache accessors */

  FD_TEST( fd_mcache_depth ( mcache )==depth  );
  FD_TEST( fd_mcache_app_sz( mcache )==app_sz );
  FD_TEST( fd_mcache_seq0  ( mcache )==seq0   );

  ulong const * _seq_const = fd_mcache_seq_laddr_const( mcache );
  ulong       * _seq       = fd_mcache_seq_laddr      ( mcache );
  FD_TEST( (ulong)_seq==(ulong)_seq_const );
  FD_TEST( fd_ulong_is_aligned( (ulong)_seq, FD_MCACHE_ALIGN ) );

  uchar const * _app_const  = fd_mcache_app_laddr_const( mcache );
  uchar       * _app        = fd_mcache_app_laddr      ( mcache );
  FD_TEST( (ulong)_app==(ulong)_app_const );
  FD_TEST( fd_ulong_is_aligned( (ulong)_app, FD_MCACHE_ALIGN ) );

  /* Test mcache initial state */

  FD_TEST( fd_mcache_seq_query( _seq_const )==seq0 );
  for( ulong idx=1UL; idx<FD_MCACHE_SEQ_CNT; idx++ ) FD_TEST( !_seq[idx] );

  uchar * p = _app;
  for( ulong rem=app_sz; rem; rem-- ) { FD_TEST( !*p ); *p = (uchar)'a'; p++; }

  for( ulong iter=0UL; iter<1000000UL; iter++ ) {

    /* Generate random sequence number with a bias towards sequence
       numbers around seq0. */

    uint  r     = fd_rng_uint( rng );
    int   shift = (int)(r & 63U); r >>= 6;
    int   sign  = (int)(r &  1U); r >>= 1;
    ulong delta = fd_rng_ulong( rng ) >> shift;
    ulong seq   = sign ? fd_seq_dec( seq0, delta ) : fd_seq_inc( seq0, delta );

    /* Test that seq queries on a fresh mcache fail in a useful way for
       consumers */

    ulong line  = fd_mcache_line_idx( seq, depth );
    if( fd_seq_ge( seq, seq0 ) ) FD_TEST( fd_seq_lt( mcache[line].seq, seq ) );
    else                         FD_TEST( fd_seq_gt( mcache[line].seq, seq ) );

    /* Test that meta data doesn't indicate any valid data or connection
       to other frags. */

    FD_TEST( !mcache[line].sz );

    ulong ctl = (ulong)mcache[line].ctl;
    FD_TEST( fd_frag_meta_ctl_som( ctl ) );
    FD_TEST( fd_frag_meta_ctl_eom( ctl ) );
    FD_TEST( fd_frag_meta_ctl_err( ctl ) );
  }

  /* Test mcache entry operations */

  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong next = fd_mcache_seq_query( _seq_const );

    /* At this point iter lines with sequence numbers [seq0,next) cyclic
       have been inserted into mcache and the most recent
       min(iter,depth) of these should be available in mcache. */

    ulong seq0 = fd_seq_dec( next, fd_ulong_min( iter, depth*2UL ) );
    ulong seq1 = fd_seq_dec( next, fd_ulong_min( iter, depth     ) );
    /* [seq0,seq1) are some sequence numbers that have been inserted but
       recently evicted */
    for( ulong seq=seq0; fd_seq_ne(seq,seq1); seq=fd_seq_inc(seq,1UL) ) {
      ulong line = fd_mcache_line_idx( seq, depth );
      FD_TEST( line<depth );
      FD_TEST( fd_seq_gt( mcache[line].seq, seq ) );
    }

    seq0 = seq1;
    seq1 = next;
    /* [seq0,seq1) are some sequence numbers that have been recently
       inserted and should still be cached */
    for( ulong seq=seq0; fd_seq_ne(seq,seq1); seq=fd_seq_inc(seq,1UL) ) {
      ulong line = fd_mcache_line_idx( seq, depth );
      FD_TEST( line<depth );
      FD_TEST( fd_seq_eq( mcache[line].seq, seq ) );
    }

    seq0 = seq1;
    seq1 = fd_seq_inc( next, depth );
    /* [seq0,seq1) are some sequence numbers that have been not been
       inserted yet. */
    for( ulong seq=seq0; fd_seq_ne(seq,seq1); seq=fd_seq_inc(seq,1UL) ) {
      ulong line = fd_mcache_line_idx( seq, depth );
      FD_TEST( line<depth );
      FD_TEST( fd_seq_lt( mcache[line].seq, seq ) );
    }

    /* Insert next into the mcache and advance to the next sequence
       number for the next iteration */

    FD_TEST( fd_seq_gt( next, fd_mcache_query( mcache, depth, next ) ) );

    fd_mcache_publish( mcache, depth, next, 0UL, 1UL, 2UL, 3UL, 4UL, 5UL );
    /* FIXME: TEST SSE AND AVX VARIANTS AS WELL */

    FD_TEST( fd_seq_eq( next, fd_mcache_query( mcache, depth, next ) ) );
    ulong evict = fd_seq_dec( next, depth );
    FD_TEST( fd_seq_lt( evict, fd_mcache_query( mcache, depth, evict ) ) );

    fd_mcache_seq_update( _seq, fd_seq_inc( next, 1UL ) );
  }

  /* Test mcache for corruption */

  FD_TEST( fd_mcache_depth          ( mcache )==depth      );
  FD_TEST( fd_mcache_app_sz         ( mcache )==app_sz     );
  FD_TEST( fd_mcache_seq0           ( mcache )==seq0       );
  FD_TEST( fd_mcache_seq_laddr_const( mcache )==_seq_const );
  FD_TEST( fd_mcache_seq_laddr      ( mcache )==_seq       );
  FD_TEST( fd_mcache_app_laddr_const( mcache )==_app_const );
  FD_TEST( fd_mcache_app_laddr      ( mcache )==_app       );

  for( ulong idx=1UL; idx<FD_MCACHE_SEQ_CNT; idx++ ) FD_TEST( !_seq[idx] );

  uchar const * q = _app_const;
  for( ulong rem=app_sz; rem; rem-- ) { FD_TEST( (*q)==(uchar)'a' ); q++; }

  /* Test mcache destruction */

  FD_TEST( fd_mcache_leave( NULL   )==NULL     ); /* null mcache */
  FD_TEST( fd_mcache_leave( mcache )==shmcache ); /* ok */

  /* Test failure cases of fd_mcache_delete */
  FD_TEST( fd_mcache_delete( NULL          )==NULL ); /* null shmcache       */
  FD_TEST( fd_mcache_delete( (void *)0x1UL )==NULL ); /* misaligned shmcache */

  /* Test bad magic value */
  (*shfseq_magic)++;
  FD_TEST( fd_mcache_delete( shmcache )==NULL );
  (*shfseq_magic)--;

  FD_TEST( fd_mcache_delete( shmcache )==shmem );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

