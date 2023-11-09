#include "../fd_util.h"
#include <math.h>
#include <stdlib.h>

FD_STATIC_ASSERT( FD_HIST_ALIGN       >=alignof(fd_hist_t), unit_test );
FD_STATIC_ASSERT( FD_HIST_FOOTPRINT(0)==16,                 unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Testing align / footprint" ));

  FD_TEST( fd_hist_align    (  )==FD_HIST_ALIGN   );
  FD_TEST( fd_hist_footprint( 0)==FD_HIST_ALIGN   );
  FD_TEST( fd_hist_footprint( 1)==FD_HIST_ALIGN   );
  FD_TEST( fd_hist_footprint(12)==FD_HIST_ALIGN   );
  FD_TEST( fd_hist_footprint(99)==808UL );

  FD_LOG_NOTICE(( "Testing new" ));

  fd_hist_t * _hist = aligned_alloc( FD_HIST_ALIGN, FD_HIST_FOOTPRINT( 4UL ) ); FD_TEST( !!_hist );
  void * shhist = fd_hist_new( _hist, 4UL, 12UL ); FD_TEST( !!shhist );

  FD_LOG_NOTICE(( "Testing join" ));

  fd_hist_t * hist  = fd_hist_join( shhist ); FD_TEST( !!hist );

  FD_LOG_NOTICE(( "Testing sample" ));

  for( ulong i=0; i<4UL; i++ ) FD_TEST( fd_hist_cnt( hist, i )==0UL );

  fd_hist_sample( hist, 0UL );

  FD_TEST( fd_hist_cnt( hist, 0 )==1UL );
  for( ulong i=1; i<4UL; i++ ) FD_TEST( fd_hist_cnt( hist, i )==0UL );

  fd_hist_sample( hist, 0UL );
  fd_hist_sample( hist, 0UL );

  FD_TEST( fd_hist_cnt( hist, 0 )==3UL );
  for( ulong i=1; i<4UL; i++ ) FD_TEST( fd_hist_cnt( hist, i )==0UL );

  fd_hist_sample( hist, 1UL );
  FD_TEST( fd_hist_cnt( hist, 0 )==4UL );
  fd_hist_sample( hist, 2UL );
  FD_TEST( fd_hist_cnt( hist, 0 )==5UL );
  fd_hist_sample( hist, 1UL );
  FD_TEST( fd_hist_cnt( hist, 0 )==6UL );
  fd_hist_sample( hist, 3UL );
  FD_TEST( fd_hist_cnt( hist, 0 )==7UL );
  FD_TEST( fd_hist_cnt( hist, 1 )==0UL );
  fd_hist_sample( hist, 4UL );
  FD_TEST( fd_hist_cnt( hist, 0 )==7UL );
  FD_TEST( fd_hist_cnt( hist, 1 )==1UL );

  fd_hist_sample( hist, 11UL );
  FD_TEST( fd_hist_cnt( hist, 2 )==1UL );
  FD_TEST( fd_hist_cnt( hist, 3 )==0UL );
  fd_hist_sample( hist, 12UL );
  FD_TEST( fd_hist_cnt( hist, 2 )==1UL );
  FD_TEST( fd_hist_cnt( hist, 3 )==1UL );

  fd_hist_sample( hist, 128UL );
  FD_TEST( fd_hist_cnt( hist, 3 )==2UL );

  fd_hist_sample( hist, ULONG_MAX-1 );
  FD_TEST( fd_hist_cnt( hist, 3 )==3UL );
  fd_hist_sample( hist, ULONG_MAX );
  FD_TEST( fd_hist_cnt( hist, 3 )==4UL );

  FD_LOG_NOTICE(( "Testing bucket_cnt" ));

  FD_TEST( fd_hist_bucket_cnt( hist )==4UL );

  FD_LOG_NOTICE(( "Testing leave" ));

  FD_TEST( fd_hist_leave( hist )==shhist );

  FD_LOG_NOTICE(( "Testing delete" ));

  FD_TEST( fd_hist_delete( shhist )==_hist );
  free( _hist );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

