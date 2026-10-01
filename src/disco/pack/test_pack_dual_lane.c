#include "fd_pack_dual_lane.h"

#define ENT_MAX (8UL)

static uchar mem[ 1UL<<16 ] __attribute__((aligned(64)));

static fd_pack_dual_pair_t verdicts[ 64 ];
static ulong               verdict_cnt;

static void
on_verdict( void *                      ctx,
            fd_pack_dual_pair_t const * pair ) {
  FD_TEST( ctx==(void *)&verdict_cnt );
  FD_TEST( verdict_cnt<64UL );
  verdicts[ verdict_cnt++ ] = *pair;
}

static uchar sigs[ 64 ][ 64 ];

/* sig(i) is a distinct signature per i.  Signatures i and i+32 share
   their first 8 bytes, to exercise full-signature comparison. */
static uchar const *
sig( ulong i ) {
  memset( sigs[ i ], (int)(i%32UL)+1, 64UL );
  sigs[ i ][ 63 ] = (uchar)i;
  return sigs[ i ];
}

#define S8(i) fd_ulong_load_8( sig( (i) ) )

static fd_pack_dual_t *
fresh( void ) {
  fd_pack_dual_t * dual = fd_pack_dual_join( fd_pack_dual_new( mem, ENT_MAX ) );
  FD_TEST( dual );
  fd_pack_dual_set_verdict_cb( dual, on_verdict, &verdict_cnt );
  verdict_cnt = 0UL;
  return dual;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_pack_dual_footprint( ENT_MAX )<=sizeof(mem) );
  FD_TEST( !fd_pack_dual_new( mem, 0UL ) );
  FD_TEST( !fd_pack_dual_new( mem, 6UL ) );

  /* TPU first, scheduled before the bundle arrives: TPU won, decided
     on insert.  Offers come from the bundle side. */
  fd_pack_dual_t * dual = fresh();
  FD_TEST( !fd_pack_dual_insert_tpu( dual, sig( 0 ), 100L ) );
  fd_pack_dual_tpu_scheduled( dual, sig( 0 ), 150L, 7UL );
  FD_TEST( verdict_cnt==0UL );
  FD_TEST( fd_pack_dual_insert_bundle( dual, sig( 0 ), 50UL, 900UL, 11UL, 200L ) );
  FD_TEST( fd_pack_dual_pair_cnt( dual )==1UL );
  FD_TEST( verdict_cnt==1UL );
  FD_TEST( verdicts[0].verdict==FD_PACK_DUAL_VERDICT_TPU_WON );
  FD_TEST( verdicts[0].slot==7UL && verdicts[0].tpu_offer==50UL && verdicts[0].bundle_offer==900UL );
  /* Decided pairs are not decided again */
  fd_pack_dual_bundle_scheduled( dual, S8( 0 ), 11UL, 300L, 8UL );
  fd_pack_dual_bundle_done     ( dual, S8( 0 ), 11UL, 1 );
  FD_TEST( verdict_cnt==1UL );

  /* Bundle first, lands before the TPU copy is scheduled: bundle won */
  dual = fresh();
  fd_pack_dual_insert_bundle( dual, sig( 2 ), 60UL, 900UL, 21UL, 100L );
  FD_TEST( fd_pack_dual_insert_tpu( dual, sig( 2 ), 110L ) );
  fd_pack_dual_bundle_scheduled( dual, S8( 2 ), 21UL, 120L, 9UL );
  FD_TEST( verdict_cnt==0UL );
  fd_pack_dual_tpu_scheduled( dual, sig( 2 ), 125L, 9UL ); /* after the bundle, whose outcome is pending */
  FD_TEST( verdict_cnt==0UL );
  fd_pack_dual_bundle_done( dual, S8( 2 ), 21UL, 1 );
  FD_TEST( verdict_cnt==1UL && verdicts[0].verdict==FD_PACK_DUAL_VERDICT_BUNDLE_WON && verdicts[0].slot==9UL );
  FD_TEST( verdicts[0].tpu_offer==60UL );

  /* Bundle scheduled first but failed: TPU won */
  dual = fresh();
  fd_pack_dual_insert_bundle( dual, sig( 4 ), 60UL, 900UL, 31UL, 100L );
  fd_pack_dual_insert_tpu   ( dual, sig( 4 ), 110L );
  fd_pack_dual_bundle_scheduled( dual, S8( 4 ), 31UL, 120L, 10UL );
  fd_pack_dual_tpu_scheduled( dual, sig( 4 ), 125L, 10UL );
  fd_pack_dual_bundle_done( dual, S8( 4 ), 31UL, 0 );
  FD_TEST( verdict_cnt==1UL && verdicts[0].verdict==FD_PACK_DUAL_VERDICT_TPU_WON );

  /* Bundle dropped unscheduled, TPU never scheduled: neither, decided at
     eviction.  Updates for another bundle are ignored. */
  dual = fresh();
  fd_pack_dual_insert_bundle( dual, sig( 6 ), 60UL, 900UL, 41UL, 100L );
  fd_pack_dual_insert_tpu   ( dual, sig( 6 ), 110L );
  fd_pack_dual_bundle_done( dual, S8( 6 ), 99UL, 1 ); /* wrong bundle */
  FD_TEST( verdict_cnt==0UL );
  fd_pack_dual_bundle_done( dual, S8( 6 ), 41UL, 0 );
  FD_TEST( verdict_cnt==0UL );
  for( ulong i=0UL; i<ENT_MAX-2UL; i++ ) fd_pack_dual_insert_tpu( dual, sig( 8UL+i ), 200L );
  FD_TEST( verdict_cnt==0UL );
  FD_TEST( fd_pack_dual_evicted_young( dual )==0UL );
  /* The next insert evicts the oldest (the bundle entry) */
  fd_pack_dual_insert_tpu( dual, sig( 20 ), 300L );
  FD_TEST( verdict_cnt==1UL && verdicts[0].verdict==FD_PACK_DUAL_VERDICT_NEITHER && verdicts[0].slot==ULONG_MAX );
  FD_TEST( fd_pack_dual_evicted_young( dual )==1UL );
  /* Evicting the TPU half of a decided pair emits nothing */
  fd_pack_dual_insert_tpu( dual, sig( 21 ), 300L+FD_PACK_DUAL_MIN_RETENTION_NS );
  FD_TEST( verdict_cnt==1UL );
  FD_TEST( fd_pack_dual_evicted_young( dual )==1UL );

  /* Pairing needs the whole signature, and the other lane */
  dual = fresh();
  FD_TEST( !fd_pack_dual_insert_tpu   ( dual, sig( 1 ),  100L ) );
  FD_TEST( !fd_pack_dual_insert_tpu   ( dual, sig( 1 ),  101L ) ); /* same lane */
  FD_TEST( !fd_pack_dual_insert_bundle( dual, sig( 33 ), 5UL, 9UL, 1UL, 102L ) ); /* same first 8 bytes */
  FD_TEST(  fd_pack_dual_insert_bundle( dual, sig( 1 ),  5UL, 9UL, 2UL, 103L ) );
  fd_pack_dual_bundle_scheduled( dual, S8( 1 ), 2UL, 110L, 3UL );
  fd_pack_dual_bundle_done     ( dual, S8( 1 ), 2UL, 1 );
  FD_TEST( verdict_cnt==1UL && verdicts[0].verdict==FD_PACK_DUAL_VERDICT_BUNDLE_WON );
  /* The bundle paired with the more recent TPU entry; the older one can
     still pair with another bundle carrying the same transaction */
  FD_TEST(  fd_pack_dual_insert_bundle( dual, sig( 1 ),  5UL, 8UL, 3UL, 104L ) );
  fd_pack_dual_tpu_scheduled( dual, sig( 1 ), 120L, 4UL );
  FD_TEST( verdict_cnt==2UL && verdicts[1].verdict==FD_PACK_DUAL_VERDICT_TPU_WON && verdicts[1].bundle_offer==8UL );
  /* A TPU copy is only scheduled once */
  fd_pack_dual_tpu_scheduled( dual, sig( 1 ), 130L, 5UL );
  FD_TEST( verdict_cnt==2UL );

  /* Stress: random operations keep the chains consistent */
  dual = fresh();
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1U, 0UL ) );
  for( ulong iter=0UL; iter<100000UL; iter++ ) {
    ulong i = fd_rng_ulong_roll( rng, 64UL );
    switch( fd_rng_uint_roll( rng, 5U ) ) {
      case 0: fd_pack_dual_insert_tpu   ( dual, sig( i ), (long)iter );                 break;
      case 1: fd_pack_dual_insert_bundle( dual, sig( i ), 1UL, 2UL, i%4UL, (long)iter ); break;
      case 2: fd_pack_dual_tpu_scheduled( dual, sig( i ), (long)iter, iter );          break;
      case 3: fd_pack_dual_bundle_scheduled( dual, S8( i ), i%4UL, (long)iter, iter ); break;
      case 4: fd_pack_dual_bundle_done( dual, S8( i ), i%4UL, (int)fd_rng_uint_roll( rng, 2U ) ); break;
    }
    if( verdict_cnt>=32UL ) verdict_cnt = 0UL;
  }
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
