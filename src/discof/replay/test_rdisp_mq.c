#include "../../disco/fd_disco_base.h"
#include "../../util/tmpl/fd_unit_test.c"
#include "fd_rdisp_mq.h"

#define TEST_MAX_FOOTPRINT (1024UL*1024UL)
uchar _footprint[ TEST_MAX_FOOTPRINT ] __attribute__((aligned(8UL)));

FD_UNIT_TEST( basic ) {
  FD_TEST( fd_rdisp_mq_footprint( 20UL, 10UL )<TEST_MAX_FOOTPRINT );
  fd_rdisp_mq_t * mq = fd_rdisp_mq_join( fd_rdisp_mq_new( _footprint, 20UL, 10UL ) );
  FD_TEST( mq );

  for( ulong a=1UL; a<=20UL; a++ ) for( ulong l=0UL; l<4UL; l++ ) FD_TEST( !fd_rdisp_mq_test( mq, a, l ) );

  for( ulong outer=0UL; outer<20UL; outer++ ) {
    /* insert [outer+1, outer+10), cyclic, skipping 0 */
    for( ulong inner=0UL; inner<10UL; inner++ ) {
      ulong acct_idx = fd_ulong_if( outer+inner<=20UL, outer+inner, outer+inner-19UL );
      fd_rdisp_mq_insert( mq, acct_idx, 0UL, (float)inner );
      FD_TEST( fd_rdisp_mq_cnt( mq, 0UL )==inner+1UL );
    }
    for( ulong inner=0UL; inner<10UL; inner++ ) {
      ulong acct_idx = fd_ulong_if( outer+inner<=20UL, outer+inner, outer+inner-19UL );
      FD_TEST( fd_rdisp_mq_pop( mq, 0UL )==acct_idx );
      FD_TEST( fd_rdisp_mq_cnt( mq, 0UL )==9UL-inner );
    }
  }
  fd_rdisp_mq_delete( fd_rdisp_mq_leave( mq ) );
}


FD_UNIT_TEST( adjust ) {
  fd_rdisp_mq_t * mq = fd_rdisp_mq_join( fd_rdisp_mq_new( _footprint, 20UL, 10UL ) );

  float prio[11];
  for( ulong a=1UL; a<=10UL; a++ ) {
    fd_rdisp_mq_insert( mq, a, 0UL, (float)a );
    prio[a] = (float)a;
  }

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 11U, 12UL ) );
  for( ulong i=0UL; i<10000UL; i++ ) {
    ulong acct = 1UL + fd_rng_uint_roll( rng, 10U );
    float new_prio = (float)fd_rng_uint_roll( rng, 4U ) * fd_rng_float_c( rng ); /* 25% chance of being 0 */
    fd_rdisp_mq_adjust( mq, acct, 0UL, new_prio );
    prio[acct] = new_prio;
  }
  for( ulong i=0UL; i<10UL; i++ ) {
    ulong popped = fd_rdisp_mq_pop( mq, 0UL );
    for( ulong j=1UL; j<11UL; j++ ) FD_TEST( prio[j]>=prio[popped] );
    prio[popped] = FLT_MAX;
  }
  FD_TEST( fd_rdisp_mq_cnt( mq, 0UL )==0UL );

  fd_rdisp_mq_delete( fd_rdisp_mq_leave( mq ) );
}

FD_UNIT_TEST( multi_lane ) {
  fd_rdisp_mq_t * mq = fd_rdisp_mq_join( fd_rdisp_mq_new( _footprint, 20UL, 10UL ) );

  float prio[21][4];
  for( ulong i=0UL; i<21UL; i++ ) for( ulong j=0UL; j<4UL; j++ ) prio[i][j] = FLT_MAX;

  ulong cnt[4] = { 0UL };
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 11U, 12UL ) );
  for( ulong i=0UL; i<10000UL; i++ ) {
    uint  action = fd_rng_uint_roll( rng, 5U );
    ulong lane   = fd_rng_uint_roll( rng, 4U );
    ulong acct;
    float new_prio;
    switch( action ) {
      case 0U: /* insert */
        if( FD_UNLIKELY( cnt[lane]==10UL ) ) continue;
        do { acct = fd_rng_uint_roll( rng, 20UL )+1UL; } while( prio[acct][lane]!=FLT_MAX );
        new_prio = (float)fd_rng_uint_roll( rng, 4U ) * fd_rng_float_c( rng ); /* 25% chance of being 0 */
        fd_rdisp_mq_insert( mq, acct, lane, new_prio );
        prio[acct][lane] = new_prio;
        cnt[lane]++;
        break;
      case 1U: /* pop */
        if( FD_UNLIKELY( cnt[lane]==0UL ) ) continue;
        ulong popped = fd_rdisp_mq_pop( mq, lane );
        for( ulong j=1UL; j<21UL; j++ ) FD_TEST( prio[j][lane]>=prio[popped][lane] );
        prio[popped][lane] = FLT_MAX;
        cnt[lane]--;
        break;
      case 2U: /* adjust */
        if( FD_UNLIKELY( cnt[lane]==0UL ) ) continue;
        do { acct = fd_rng_uint_roll( rng, 20UL )+1UL; } while( prio[acct][lane]==FLT_MAX );
        new_prio = (float)fd_rng_uint_roll( rng, 4U ) * fd_rng_float_c( rng ); /* 25% chance of being 0 */
        fd_rdisp_mq_adjust( mq, acct, lane, new_prio );
        prio[acct][lane] = new_prio;
        break;
      case 3U: /* query */
        acct = fd_rng_uint_roll( rng, 20UL )+1UL;
        FD_TEST( fd_rdisp_mq_test( mq, acct, lane )==(prio[acct][lane]!=FLT_MAX) );
        break;
      case 4U: /* cnt */
        FD_TEST( cnt[lane]==fd_rdisp_mq_cnt( mq, lane ) );
        break;
    }
  }
  fd_rdisp_mq_delete( fd_rdisp_mq_leave( mq ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

