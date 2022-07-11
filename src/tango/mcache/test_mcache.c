#include "../fd_tango.h"

FD_STATIC_ASSERT( FD_FRAG_META_ALIGN    ==32UL, unit_test );
FD_STATIC_ASSERT( FD_FRAG_META_FOOTPRINT==32UL, unit_test );
/* FIXME: VERIFY MORE OF THE FRAG_META LAYOUT TO SNIFF OUT SILENT ABI CHANGES */

FD_STATIC_ASSERT( FD_MCACHE_ALIGN        ==4096UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_SEQ_ALIGN    == 128UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_SEQ_CNT      ==  16UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_APP_ALIGN    == 128UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_APP_FOOTPRINT==3840UL, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_LG_BLOCK     ==     7, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_LG_INTERLEAVE==     2, unit_test );
FD_STATIC_ASSERT( FD_MCACHE_BLOCK        == 128UL, unit_test );

#define DEPTH_MAX (1024L)

static uchar __attribute__((aligned(FD_MCACHE_ALIGN))) shmem[ FD_MCACHE_FOOTPRINT( DEPTH_MAX ) ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong depth = fd_env_strip_cmdline_ulong( &argc, &argv, "--depth", NULL,        256UL );
  ulong seq0  = fd_env_strip_cmdline_ulong( &argc, &argv, "--seq0",  NULL, 1234567890UL );

  if( FD_UNLIKELY( depth>DEPTH_MAX ) ) FD_LOG_ERR(( "Increase unit test DEPTH_MAX to support this large --depth" ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  TEST( fd_mcache_align()==FD_MCACHE_ALIGN );

  TEST( !fd_mcache_footprint( 0UL                     ) );
  TEST( !fd_mcache_footprint(     FD_MCACHE_BLOCK-1UL ) );
  TEST(  fd_mcache_footprint(     FD_MCACHE_BLOCK     ) );
  TEST( !fd_mcache_footprint(     FD_MCACHE_BLOCK+1UL ) );
  TEST( !fd_mcache_footprint( 2UL*FD_MCACHE_BLOCK-1UL ) );
  TEST(  fd_mcache_footprint( 2UL*FD_MCACHE_BLOCK     ) );
  TEST( !fd_mcache_footprint( 2UL*FD_MCACHE_BLOCK+1UL ) );

  ulong footprint = fd_mcache_footprint( depth );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "Bad --depth" ));
  TEST( footprint==FD_MCACHE_FOOTPRINT( depth     ) );
  TEST( footprint<=FD_MCACHE_FOOTPRINT( DEPTH_MAX ) );

  void *           shmcache = fd_mcache_new ( shmem, depth, seq0 ); TEST( shmcache );
  fd_frag_meta_t * mcache   = fd_mcache_join( shmcache );           TEST( mcache );

  TEST( fd_mcache_depth( mcache )==depth );
  TEST( fd_mcache_seq0 ( mcache )==seq0  );

  ulong const * _seq_const = fd_mcache_seq_laddr_const( mcache );
  ulong       * _seq       = fd_mcache_seq_laddr      ( mcache );
  TEST( (ulong)_seq==(ulong)_seq_const );

  uchar const * _app_const  = fd_mcache_app_laddr_const( mcache );
  uchar       * _app        = fd_mcache_app_laddr      ( mcache );
  TEST( (ulong)_app==(ulong)_app_const );

  /* Test the initial state of the mcache */

  TEST( (*_seq_const)==seq0 );
  TEST( (*_seq      )==seq0 );
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
    if( fd_seq_ge( seq, seq0 ) ) TEST( fd_seq_lt( mcache[line].seq, seq ) );
    else                         TEST( fd_seq_gt( mcache[line].seq, seq ) );

    /* Test that meta data doesn't indicate any valid data or connection
       to other frags. */

    TEST( !mcache[line].sz );

    ulong ctl = (ulong)mcache[line].ctl;
    TEST( fd_frag_meta_ctl_som( ctl ) );
    TEST( fd_frag_meta_ctl_eom( ctl ) );
    TEST( fd_frag_meta_ctl_err( ctl ) );
  }

  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong next = *_seq;

    /* At this point iter lines with sequence numbers [seq0,next) cyclic
       have been inserted into mcache and the most recent
       min(iter,depth) of these should be available in mcache. */

    ulong seq0 = fd_seq_dec( next, fd_ulong_min( iter, depth*2UL ) );
    ulong seq1 = fd_seq_dec( next, fd_ulong_min( iter, depth     ) );
    /* [seq0,seq1) are some sequence numbers that have been inserted but
       recently evicted */
    for( ulong seq=seq0; fd_seq_ne(seq,seq1); seq=fd_seq_inc(seq,1UL) ) {
      ulong line = fd_mcache_line_idx( seq, depth );
      TEST( line<depth );
      TEST( fd_seq_gt( mcache[line].seq, seq ) );
    }

    seq0 = seq1;
    seq1 = next;
    /* [seq0,seq1) are some sequence numbers that have been recently
       inserted and should still be cached */
    for( ulong seq=seq0; fd_seq_ne(seq,seq1); seq=fd_seq_inc(seq,1UL) ) {
      ulong line = fd_mcache_line_idx( seq, depth );
      TEST( line<depth );
      TEST( fd_seq_eq( mcache[line].seq, seq ) );
    }

    seq0 = seq1;
    seq1 = fd_seq_inc( next, depth );
    /* [seq0,seq1) are some sequence numbers that have been not been
       inserted yet. */
    for( ulong seq=seq0; fd_seq_ne(seq,seq1); seq=fd_seq_inc(seq,1UL) ) {
      ulong line = fd_mcache_line_idx( seq, depth );
      TEST( line<depth );
      TEST( fd_seq_lt( mcache[line].seq, seq ) );
    }

    /* Insert next into the mcache */
    ulong line = fd_mcache_line_idx( next, depth );
    TEST( line<depth );
    mcache[ line ].seq = next;
    *_seq = fd_seq_inc(next,1UL);
  }

  TEST( fd_mcache_leave ( mcache   )==shmcache );
  TEST( fd_mcache_delete( shmcache )==shmem    );

# undef TEST

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

