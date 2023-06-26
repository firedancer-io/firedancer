#include "../../util/fd_util.h"

#define MYVEC_T uint

#define VEC_NAME myvec
#define VEC_T    MYVEC_T
#include "fd_vec.c"

#define REF_MAX (16384UL)
#define MEM_MAX (2UL*REF_MAX*sizeof(MYVEC_T))

static uchar   mem[ MEM_MAX ] __attribute__((aligned(128)));
static MYVEC_T ref[ REF_MAX ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong max      = fd_env_strip_cmdline_ulong( &argc, &argv, "--max",      NULL,     512UL );
  ulong iter_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max", NULL, 1000000UL );

  if( max>REF_MAX ) { FD_LOG_WARNING(( "skip: adjust ref to be compatible with --max" )); return 0; }

  FD_LOG_NOTICE(( "Testing with --max %lu --iter-max %lu", max, iter_max ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong align     = myvec_align();                FD_TEST( fd_ulong_is_aligned( align, alignof(MYVEC_T) ) );
  ulong footprint = myvec_footprint( 0UL );       FD_TEST( footprint && fd_ulong_is_aligned( footprint, align ) );
  /**/  footprint = myvec_footprint( ULONG_MAX ); FD_TEST( !footprint );

  footprint = myvec_footprint( max ); FD_TEST( footprint && fd_ulong_is_aligned( footprint, align ) );
  if( !footprint ) { FD_LOG_WARNING(( "skip: bad max passed to unit test" )); return 0; }
  if( align>128UL || footprint>MEM_MAX ) { FD_LOG_WARNING(( "skip: adjust mem to compatible with --max" )); return 0; }
  FD_TEST( footprint > sizeof(MYVEC_T)*max );

  FD_TEST( !myvec_new( NULL, max ) );
  void * shvec = myvec_new( mem, max ); FD_TEST( shvec==(void *)mem );

  FD_TEST( !myvec_join( NULL ) );
  MYVEC_T * vec = myvec_join( shvec ); FD_TEST( vec );

  ulong cnt = 0UL;

  for( ulong iter=0UL; iter<iter_max; iter++ ) {
    FD_TEST( myvec_max     ( vec )==max               );
    FD_TEST( myvec_cnt     ( vec )==cnt               );
    FD_TEST( myvec_free    ( vec )==max-cnt           );
    FD_TEST( myvec_is_full ( vec )==(cnt==max)        );
    FD_TEST( myvec_is_empty( vec )==(!cnt)            );
    FD_TEST( !memcmp( vec, ref, cnt*sizeof(MYVEC_T) ) );

    uint r  = fd_rng_uint( rng );
    int  op = (int)(r & 3U); r>>=2;

    switch( op ) {
    default:
    case 0: { /* expand by a random amount */
      ulong delta = fd_ulong_min( max-cnt, (ulong)fd_uint_popcnt( fd_rng_uint( rng ) ) );
      MYVEC_T * tst_ele = myvec_expand( vec, delta ); FD_TEST( tst_ele==(vec+cnt) );
      MYVEC_T * ref_ele = ref + cnt;
      for( ulong idx=0UL; idx<delta; idx++ ) {
        MYVEC_T val = (MYVEC_T)fd_rng_uint( rng );
        tst_ele[idx] = val;
        ref_ele[idx] = val;
      }
      cnt += delta;
      break;
    }

    case 1: { /* contract by a random amount */
      ulong delta = fd_ulong_min( cnt, fd_rng_coin_tosses( rng ) );
      cnt -= delta;
      MYVEC_T * tst_ele = myvec_contract( vec, delta ); FD_TEST( tst_ele==(vec+cnt) );
      MYVEC_T * ref_ele = ref + cnt;
      for( ulong idx=0UL; idx<delta; idx++ ) FD_TEST( tst_ele[idx]==ref_ele[idx] );
      break;
    }

    case 2: { /* remove with backfill */
      if( !cnt ) break;
      ulong idx = fd_rng_ulong_roll( rng, cnt );
      FD_TEST( myvec_remove( vec, idx )==vec );
      cnt--;
      ref[idx] = ref[cnt];
      break;
    }

    case 3: { /* remove with compaction */
      if( !cnt ) break;
      ulong idx = fd_rng_ulong_roll( rng, cnt );
      FD_TEST( myvec_remove_compact( vec, idx )==vec );
      cnt--;
      for( ; idx<cnt; idx++ ) ref[idx] = ref[idx+1UL];
      break;
    }
    }
  }

  FD_TEST( !myvec_leave( NULL ) );
  FD_TEST( myvec_leave( vec )==shvec );

  FD_TEST( !myvec_delete( NULL ) );
  FD_TEST( myvec_delete( shvec )==(void *)mem );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

