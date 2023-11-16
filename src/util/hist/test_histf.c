#include "../fd_util.h"
#include "fd_histf.h"
#include "../rng/fd_rng.h"
#include <math.h>
#include <stdlib.h>

FD_STATIC_ASSERT( FD_HISTF_ALIGN    ==alignof(fd_histf_t), unit_test );
FD_STATIC_ASSERT( FD_HISTF_FOOTPRINT==sizeof (fd_histf_t), unit_test );

static inline void
assert_range( fd_histf_t * hist,
              ulong       idx,
              uint        left_edge,
              uint        right_edge ) { /* exclusive */

  FD_TEST( fd_histf_left ( hist, idx )== left_edge );
  FD_TEST( fd_histf_right( hist, idx )==right_edge );

  ulong expected    = fd_histf_cnt( hist, idx );
  ulong initial_sum = fd_histf_sum( hist );
  fd_histf_sample( hist, left_edge-1UL ); /* Might underflow, but okay */
  FD_TEST( fd_histf_cnt( hist, idx )==expected );

  for( uint i=left_edge; i<right_edge; i++ ) {
    fd_histf_sample( hist, i );
    FD_TEST( fd_histf_cnt( hist, idx )==++expected );
  }
  fd_histf_sample( hist, right_edge );
  FD_TEST( fd_histf_cnt( hist, idx )==expected );
  FD_TEST( fd_histf_sum( hist      )==initial_sum + (left_edge-1UL) + (left_edge+right_edge)*(right_edge-left_edge+1UL)/2UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Testing align / footprint" ));

  FD_TEST( fd_histf_align    ()==FD_HISTF_ALIGN     );
  FD_TEST( fd_histf_footprint()==FD_HISTF_FOOTPRINT );

  FD_LOG_NOTICE(( "Testing new" ));

  fd_histf_t * _hist = aligned_alloc( FD_HISTF_ALIGN, FD_HISTF_FOOTPRINT ); FD_TEST( !!_hist );
  void * shhist = fd_histf_new( _hist, 4U, 20U ); FD_TEST( !!shhist );

  FD_LOG_NOTICE(( "Testing join" ));

  fd_histf_t * hist  = fd_histf_join( shhist ); FD_TEST( !!hist );

  FD_LOG_NOTICE(( "Testing sample" ));

  for( ulong i=0; i<16UL; i++ ) FD_TEST( fd_histf_cnt( hist, i )==0UL );

  fd_histf_sample( hist, 0U );

  FD_TEST( fd_histf_cnt( hist, 0 )==1UL );
  for( ulong i=1UL; i<16UL; i++ ) FD_TEST( fd_histf_cnt( hist, i )==0UL );

  /* All < 4 so go in underflow bucket */
  fd_histf_sample( hist, 1U );
  fd_histf_sample( hist, 2U );
  fd_histf_sample( hist, 3U );

  FD_TEST( fd_histf_cnt( hist, 0UL )==4UL );
  for( ulong i=1UL; i<16UL; i++ ) FD_TEST( fd_histf_cnt( hist, i )==0UL );

  fd_histf_sample( hist, 20U );    FD_TEST( fd_histf_cnt( hist, 15UL )==1UL );
  fd_histf_sample( hist, 21U );    FD_TEST( fd_histf_cnt( hist, 15UL )==2UL );
  fd_histf_sample( hist, 30U );    FD_TEST( fd_histf_cnt( hist, 15UL )==3UL );
  fd_histf_sample( hist, 99U );    FD_TEST( fd_histf_cnt( hist, 15UL )==4UL );

  FD_TEST( fd_histf_sum( hist )==0UL+1UL+2UL+3UL+20UL+21UL+30UL+99UL );

  hist = fd_histf_join( fd_histf_new( fd_histf_delete( fd_histf_leave( hist ) ), 1U, 100U ) );

  assert_range( hist,  0UL,   0U,   1U );
  assert_range( hist,  1UL,   1U,   2U );
  assert_range( hist,  2UL,   2U,   3U );
  assert_range( hist,  3UL,   3U,   4U );
  assert_range( hist,  4UL,   4U,   5U );
  assert_range( hist,  5UL,   5U,   7U );
  assert_range( hist,  6UL,   7U,   9U );
  assert_range( hist,  7UL,   9U,  12U );
  assert_range( hist,  8UL,  12U,  16U );
  assert_range( hist,  9UL,  16U,  22U );
  assert_range( hist, 10UL,  22U,  30U );
  assert_range( hist, 11UL,  30U,  41U );
  assert_range( hist, 12UL,  41U,  55U );
  assert_range( hist, 13UL,  55U,  74U );
  assert_range( hist, 14UL,  74U, 100U );
  /* We've already tested the overflow bucket above */

  FD_LOG_NOTICE(( "Testing bucket_cnt" ));

  FD_TEST( fd_histf_bucket_cnt( hist )==FD_HISTF_BUCKET_CNT );

  FD_LOG_NOTICE(( "Testing performance" ));
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  long overhead = -fd_log_wallclock();
  for( ulong i=0UL; i<1000000000UL; i++ ) {
    uint v = fd_rng_uint_roll( rng, 100U );
    FD_COMPILER_FORGET( v );
  }
  overhead += fd_log_wallclock();

  long time = -fd_log_wallclock();
  for( ulong i=0UL; i<1000000000UL; i++ ) {
    uint v = fd_rng_uint_roll( rng, 100U );
    fd_histf_sample( hist, v );
  }
  time += fd_log_wallclock();

  FD_LOG_NOTICE(( "average time per sample %f ns (excluding rng overhead)",
                  (double)(time        - overhead)/1000000000.0 ));

  FD_LOG_NOTICE(( "Testing leave" ));

  FD_TEST( fd_histf_leave( hist )==shhist );

  FD_LOG_NOTICE(( "Testing delete" ));

  FD_TEST( fd_histf_delete( shhist )==_hist );
  free( _hist );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

