#include "../fd_ballet_base.h"
#include "fd_wsample.h"
#include <math.h>

#define MAX 1024UL
#define MAX_FOOTPRINT (1024UL + 64UL*MAX)

uchar _shmem[MAX_FOOTPRINT] __attribute__((aligned(128)));
ulong weights[MAX];
ulong counts[MAX];

uchar seed[32] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 };

/* It would be nice to measure the weighted depth to show that the hint
   actually does something, but it's not exposed easily. */
/*
ulong
weighted_depth( uint idx, ulong depth ) {
  if( treap_idx_is_null( idx ) ) return 0UL;
  return depth*pool[idx].weight + weighted_depth( pool[idx].left, depth+1UL ) + weighted_depth( pool[idx].right, depth+1UL );
}
*/

/* Chi squared goodness of fit statistical test.  The null hypothesis is
   that the observed counts comes from the same distribution as the
   expected counts.  Requires that both sets of counts have the same
   sum.  Uses alpha=1% as the significance level.  The typical rule of
   thumb for Chi^2 also requires that expected[i]>=5 for each i.  This
   is just a statistical test, so it may occasionally fail even though
   nothing is wrong.  Everything in this test file is deterministic
   though, and with the specified seed, it should pass. */
static inline void
chi_squared_test( ulong * observed,
                  ulong * expected,
                  ulong   cnt ) {
  float stat = 0.0f;
  for( ulong i=0UL; i<cnt; i++ ) { float o = (float)observed[i]; float e = (float)expected[i];  stat += (o-e)*(o-e)/e; }

  /* These would be a nightmare to calculate, so just pre-compute what
     we need using Python's scipy.stats.chi2.isf(.01, 113*k) or similar.
     */
  float critical_value;
  switch( cnt ) {
    case    1UL: critical_value =    1.000f; break; /* Not really valid, but stat must be 0 in this case */
    case   24UL: critical_value =   41.638f; break;
    case  114UL: critical_value =  150.882f; break;
    case  227UL: critical_value =  278.378f; break;
    case  340UL: critical_value =  402.498f; break;
    case  453UL: critical_value =  524.871f; break;
    case  566UL: critical_value =  646.129f; break;
    case  679UL: critical_value =  766.594f; break;
    case  792UL: critical_value =  886.459f; break;
    case  905UL: critical_value = 1005.848f; break;
    case 1018UL: critical_value = 1124.849f; break;
    default: FD_LOG_ERR(( "Update the test with the new critical value for cnt=%lu", cnt ));
  }
  FD_LOG_NOTICE(( "cnt=%lu. stat=%f vs critical_value=%f", cnt, (double)stat, (double)critical_value ));

  FD_TEST( stat<critical_value );
}

static inline void
test_probability_dist_replacement( void ) {
  fd_chacha20rng_t _rng[1];
  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_SHIFT ) );
  fd_chacha20rng_init( rng, seed );

  for( ulong i=0UL; i<1024UL; i++ ) weights[i] = 2000000UL / (i+1UL);

  for( ulong sz=1UL; sz<1024UL; sz+=113UL ) {
    void * partial = fd_wsample_new_init( _shmem, rng, sz, 0, FD_WSAMPLE_HINT_POWERLAW_NOREMOVE );
    for( ulong i=0UL; i<sz; i++ ) partial = fd_wsample_new_add( partial, weights[i] );
    fd_wsample_t * tree = fd_wsample_join( fd_wsample_new_fini( partial ) );

    ulong weight_sum = 0UL;
    for( ulong i=0UL; i<sz; i++ ) weight_sum += weights[i];

    memset( counts, 0, MAX*sizeof(ulong) );
    for( ulong j=0UL; j<weight_sum; j++ ) {
      ulong sample = fd_wsample_sample( tree );
      FD_TEST( sample<sz );
      counts[sample]++;
    }
    chi_squared_test( counts, weights, sz );

    memset( counts, 0, MAX*sizeof(ulong) );
    for( ulong j=0UL; j<weight_sum; j+=100UL ) {
      ulong round_count = fd_ulong_min( 100UL, weight_sum-j );
      ulong samples[100];
      fd_wsample_sample_many( tree, samples, round_count );
      for( ulong k=0UL; k<round_count; k++ ) counts[samples[k]]++;
    }
    chi_squared_test( counts, weights, sz );

    fd_wsample_delete( fd_wsample_leave( tree ) );
  }
}

static inline void
test_probability_dist_noreplacement( void ) {
  fd_chacha20rng_t _rng[1];
  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_SHIFT ) );
  fd_chacha20rng_init( rng, seed );

  for( ulong sz=1UL; sz<1024UL; sz+=113UL ) {
    void * partial = fd_wsample_new_init( _shmem, rng, sz, 1, FD_WSAMPLE_HINT_POWERLAW_REMOVE );
    for( ulong i=0UL; i<sz; i++ ) partial = fd_wsample_new_add( partial, 2000000UL / (i+1UL) );
    fd_wsample_t * tree = fd_wsample_join( fd_wsample_new_fini( partial ) );

    memset( counts, 0, MAX*sizeof(ulong) );
    for( ulong j=0UL; j<sz; j++ ) {
      ulong sample = fd_wsample_sample_and_remove( tree );
      FD_TEST( sample<sz );
      counts[sample]++;
    }
    FD_TEST( fd_wsample_sample_and_remove( tree ) == FD_WSAMPLE_EMPTY );
    for( ulong j=0UL; j<sz; j++ ) FD_TEST( counts[j]==1UL );

    fd_wsample_restore_all( tree );

    memset( counts, 0, MAX*sizeof(ulong) );
    for( ulong j=0UL; j<sz; j+=100UL ) {
      ulong samples[100];
      fd_wsample_sample_and_remove_many( tree, samples, 100UL );
      for( ulong k=0UL; k<fd_ulong_min( sz-j, 100UL );   k++ ) counts[samples[k]]++;
      for( ulong k=fd_ulong_min( sz-j, 100UL ); k<100UL; k++ ) FD_TEST( samples[k]==FD_WSAMPLE_EMPTY );
    }
    for( ulong j=0UL; j<sz; j++ ) FD_TEST( counts[j]==1UL );

    fd_wsample_delete( fd_wsample_leave( tree ) );
  }

  /* Expected probabilities of sampling without replacement get
     complicated.  We're going to use a 4-element set, and make sure the
     distrubtion of returned 4-tuples matches what we manually compute. */
  void * partial = fd_wsample_new_init( _shmem, rng, 4UL, 1, FD_WSAMPLE_HINT_FLAT );
  partial = fd_wsample_new_add( fd_wsample_new_add( fd_wsample_new_add( fd_wsample_new_add( partial, 40UL ), 30UL ), 20UL ), 10UL );
  fd_wsample_t * tree = fd_wsample_join( fd_wsample_new_fini( partial ) );
  memset( counts, 0, MAX*sizeof(ulong) );

  for( ulong sample=0UL; sample<302400UL; sample++ ) {
    ulong tuple = 0UL;
    for( ulong j=0UL; j<4UL; j++ ) tuple = (tuple<<4) | fd_wsample_sample_and_remove( tree );
    fd_wsample_restore_all( tree );

    switch( tuple ) {
      case 0x0123: counts[  0 ]++; break;
      case 0x0132: counts[  1 ]++; break;
      case 0x0213: counts[  2 ]++; break;
      case 0x0231: counts[  3 ]++; break;
      case 0x0312: counts[  4 ]++; break;
      case 0x0321: counts[  5 ]++; break;
      case 0x1023: counts[  6 ]++; break;
      case 0x1032: counts[  7 ]++; break;
      case 0x1203: counts[  8 ]++; break;
      case 0x1230: counts[  9 ]++; break;
      case 0x1302: counts[ 10 ]++; break;
      case 0x1320: counts[ 11 ]++; break;
      case 0x2013: counts[ 12 ]++; break;
      case 0x2031: counts[ 13 ]++; break;
      case 0x2103: counts[ 14 ]++; break;
      case 0x2130: counts[ 15 ]++; break;
      case 0x2301: counts[ 16 ]++; break;
      case 0x2310: counts[ 17 ]++; break;
      case 0x3012: counts[ 18 ]++; break;
      case 0x3021: counts[ 19 ]++; break;
      case 0x3102: counts[ 20 ]++; break;
      case 0x3120: counts[ 21 ]++; break;
      case 0x3201: counts[ 22 ]++; break;
      case 0x3210: counts[ 23 ]++; break;
      default: FD_LOG_ERR(( "Illegal permutation: %lx", tuple ));
    }
  }
  ulong expected[ 24 ] = { 40320UL, 20160UL, 30240UL, 10080UL, 12096UL, 8064UL,
                           34560UL, 17280UL, 20736UL,  5184UL,  8640UL, 4320UL,
                           22680UL,  7560UL, 18144UL,  4536UL,  4320UL, 3240UL,
                            8064UL,  5376UL,  6720UL,  3360UL,  3840UL, 2880UL };

  chi_squared_test( counts, expected, 24UL );

  fd_wsample_delete( fd_wsample_leave( tree ) );
}

static void
test_matches_solana( void ) {
  /* Adopted from test_repeated_leader_schedule_specific: */
  fd_chacha20rng_t _rng[1];
  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_MOD ) );
  uchar zero_seed[32] = {0};

  void * partial = fd_wsample_new_init( _shmem, rng, 2UL, 0, FD_WSAMPLE_HINT_FLAT );
  fd_wsample_t * tree = fd_wsample_join( fd_wsample_new_fini( fd_wsample_new_add( fd_wsample_new_add( partial, 2UL ), 1UL ) ) );
  fd_wsample_seed_rng( fd_wsample_get_rng( tree ), zero_seed );

  FD_TEST( fd_wsample_sample( tree ) == 0UL );
  FD_TEST( fd_wsample_sample( tree ) == 0UL );
  FD_TEST( fd_wsample_sample( tree ) == 0UL );
  FD_TEST( fd_wsample_sample( tree ) == 1UL );
  FD_TEST( fd_wsample_sample( tree ) == 0UL );
  FD_TEST( fd_wsample_sample( tree ) == 0UL );
  FD_TEST( fd_wsample_sample( tree ) == 0UL );
  FD_TEST( fd_wsample_sample( tree ) == 0UL );

  fd_wsample_delete( fd_wsample_leave( tree ) );
  fd_chacha20rng_delete( fd_chacha20rng_leave( rng ) );

  rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_SHIFT ) );

  /* Adopted from test_weighted_shuffle_hard_coded, except they handle
     the special case for 0 weights inside their WeightedShuffle object,
     and the test case initially used i32 as weights, which made their
     Chacha20 object generate i32s instead of u64s. */
  ulong weights2[18] = { 78, 70, 38, 27, 21, 82, 42, 21, 77, 77, 17, 4, 50, 96, 83, 33, 16, 72 };

  memset( zero_seed, 48, 32UL );
  fd_chacha20rng_init( rng, zero_seed );

  partial = fd_wsample_new_init( _shmem, rng, 18UL, 0, FD_WSAMPLE_HINT_FLAT );
  for( ulong i=0UL; i<18UL; i++ ) partial = fd_wsample_new_add( partial, weights2[i] );
  tree = fd_wsample_join( fd_wsample_new_fini( partial ) );
  fd_wsample_seed_rng( fd_wsample_get_rng( tree ), zero_seed );

  FD_TEST( fd_wsample_sample_and_remove( tree ) ==  9UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) ==  3UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) == 12UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) == 15UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) ==  0UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) ==  8UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) == 16UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) ==  5UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) ==  2UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) ==  1UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) == 14UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) ==  6UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) == 11UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) == 13UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) == 17UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) == 10UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) ==  4UL );
  FD_TEST( fd_wsample_sample_and_remove( tree ) ==  7UL );

  fd_wsample_delete( fd_wsample_leave( tree ) );
  fd_chacha20rng_delete( fd_chacha20rng_leave( rng ) );
}

static void
test_sharing( void ) {
  fd_chacha20rng_t _rng[1];
  uchar zero_seed[32] = {0};

  for( ulong i=0UL; i<0x100UL; i++ ) {
    fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_SHIFT ) );
    fd_chacha20rng_init( rng, zero_seed );

    void * pl1 = fd_wsample_new_init( _shmem,                   rng, 2UL, 0, FD_WSAMPLE_HINT_FLAT );
    void * pl2 = fd_wsample_new_init( _shmem+MAX_FOOTPRINT/2UL, rng, 2UL, 0, FD_WSAMPLE_HINT_FLAT );
    fd_wsample_t * sample1 = fd_wsample_join( fd_wsample_new_fini( fd_wsample_new_add( fd_wsample_new_add( pl1, 2UL ), 1UL ) ) );
    fd_wsample_t * sample2 = fd_wsample_join( fd_wsample_new_fini( fd_wsample_new_add( fd_wsample_new_add( pl2, 2UL ), 1UL ) ) );

    /* Since they're using the same weights, they are interchangeable. */

    FD_TEST( fd_wsample_sample( i&0x01UL ? sample1 : sample2 ) == 0UL );
    FD_TEST( fd_wsample_sample( i&0x02UL ? sample1 : sample2 ) == 0UL );
    FD_TEST( fd_wsample_sample( i&0x04UL ? sample1 : sample2 ) == 0UL );
    FD_TEST( fd_wsample_sample( i&0x08UL ? sample1 : sample2 ) == 1UL );
    FD_TEST( fd_wsample_sample( i&0x10UL ? sample1 : sample2 ) == 0UL );
    FD_TEST( fd_wsample_sample( i&0x20UL ? sample1 : sample2 ) == 0UL );
    FD_TEST( fd_wsample_sample( i&0x40UL ? sample1 : sample2 ) == 0UL );
    FD_TEST( fd_wsample_sample( i&0x80UL ? sample1 : sample2 ) == 0UL );

    fd_wsample_delete( fd_wsample_leave( sample1 ) );
    fd_wsample_delete( fd_wsample_leave( sample2 ) );

    fd_chacha20rng_delete( fd_chacha20rng_leave( rng ) );
  }
}

static void
test_restore_disabled( void ) {
  fd_chacha20rng_t _rng[1];
  uchar zero_seed[32] = {0};

  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_SHIFT ) );
  fd_chacha20rng_init( rng, zero_seed );

  void * partial1 = fd_wsample_new_init( _shmem,                   rng, 2UL, 0, FD_WSAMPLE_HINT_FLAT );
  void * partial2 = fd_wsample_new_init( _shmem+MAX_FOOTPRINT/2UL, rng, 2UL, 1, FD_WSAMPLE_HINT_FLAT );
  fd_wsample_t * sample1 = fd_wsample_join( fd_wsample_new_fini( fd_wsample_new_add( fd_wsample_new_add( partial1, 2UL ), 1UL ) ) );
  fd_wsample_t * sample2 = fd_wsample_join( fd_wsample_new_fini( fd_wsample_new_add( fd_wsample_new_add( partial2, 2UL ), 1UL ) ) );

  FD_TEST( fd_wsample_sample_and_remove( sample1 ) != FD_WSAMPLE_EMPTY );
  FD_TEST( fd_wsample_sample_and_remove( sample1 ) != FD_WSAMPLE_EMPTY );
  FD_TEST( fd_wsample_sample_and_remove( sample2 ) != FD_WSAMPLE_EMPTY );
  FD_TEST( fd_wsample_sample_and_remove( sample2 ) != FD_WSAMPLE_EMPTY );

  FD_TEST( fd_wsample_sample_and_remove( sample1 ) == FD_WSAMPLE_EMPTY );
  FD_TEST( fd_wsample_sample_and_remove( sample2 ) == FD_WSAMPLE_EMPTY );

  FD_TEST( fd_wsample_restore_all( sample1 ) == NULL    );
  FD_TEST( fd_wsample_restore_all( sample2 ) == sample2 );

  FD_TEST( fd_wsample_sample_and_remove( sample1 ) == FD_WSAMPLE_EMPTY );
  FD_TEST( fd_wsample_sample_and_remove( sample2 ) != FD_WSAMPLE_EMPTY );

  fd_wsample_delete( fd_wsample_leave( sample1 ) );
  fd_wsample_delete( fd_wsample_leave( sample2 ) );

  fd_chacha20rng_delete( fd_chacha20rng_leave( rng ) );
}

static void
test_remove_idx( void ) {
  fd_chacha20rng_t _rng[1];
  uchar zero_seed[32] = {0};

  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_SHIFT ) );
  fd_chacha20rng_init( rng, zero_seed );

  void * partial = fd_wsample_new_init( _shmem, rng, 2UL, 1, FD_WSAMPLE_HINT_FLAT );
  fd_wsample_t * sample = fd_wsample_join( fd_wsample_new_fini( fd_wsample_new_add( fd_wsample_new_add( partial, 2UL ), 1UL ) ) );
  FD_TEST( sample );

  fd_wsample_remove_idx( sample, 1UL );

  for( ulong j=0UL; j<10UL; j++ ) FD_TEST( fd_wsample_sample( sample ) != 1UL );

  fd_wsample_remove_idx( sample, 1UL ); /* no-op */
  for( ulong j=0UL; j<10UL; j++ ) FD_TEST( fd_wsample_sample( sample ) == 0UL );

  FD_TEST( fd_wsample_sample_and_remove( sample ) == 0UL );
  FD_TEST( fd_wsample_sample_and_remove( sample ) == FD_WSAMPLE_EMPTY );
  FD_TEST( fd_wsample_sample_and_remove( sample ) == FD_WSAMPLE_EMPTY );

  FD_TEST( fd_wsample_restore_all( sample ) );

  FD_TEST( fd_wsample_sample_and_remove( sample ) != FD_WSAMPLE_EMPTY );
  FD_TEST( fd_wsample_sample_and_remove( sample ) != FD_WSAMPLE_EMPTY );
  FD_TEST( fd_wsample_sample_and_remove( sample ) == FD_WSAMPLE_EMPTY );

  fd_wsample_delete( fd_wsample_leave( sample ) );

  fd_chacha20rng_delete( fd_chacha20rng_leave( rng ) );
}

/* FIXME: Probably go back to making this function a static inline and
   delete this test. */
uint fd_wsample_map_sample( fd_wsample_t * tree, ulong         query );

static inline void
test_map( void ) {
  fd_chacha20rng_t _rng[1];
  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_SHIFT ) );

  ulong sz=1018UL;
  void * partial = fd_wsample_new_init( _shmem, rng, sz, 0, FD_WSAMPLE_HINT_POWERLAW_NOREMOVE );
  for( ulong i=0UL; i<sz; i++ ) partial = fd_wsample_new_add( partial, 2000000UL / (i+1UL) );
  fd_wsample_t * tree = fd_wsample_join( fd_wsample_new_fini( partial ) );

  ulong x = 0UL;
  for( ulong i=0UL; i<sz; i++ ) for( ulong j=0UL; j<weights[i]; j++ ) FD_TEST( fd_wsample_map_sample( tree, x++ )==i );

  fd_wsample_delete( fd_wsample_leave( tree ) );
  fd_chacha20rng_delete( fd_chacha20rng_leave( rng ) );
}

static void
test_empty( void ) {
  fd_chacha20rng_t _rng[1];
  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_SHIFT ) );

  void * partial = fd_wsample_new_init( _shmem, rng, 0UL, 0, FD_WSAMPLE_HINT_POWERLAW_NOREMOVE );
  fd_wsample_t * tree = fd_wsample_join( fd_wsample_new_fini( partial ) );
  FD_TEST( tree );

  FD_TEST( fd_wsample_sample           ( tree ) == FD_WSAMPLE_EMPTY );
  FD_TEST( fd_wsample_sample_and_remove( tree ) == FD_WSAMPLE_EMPTY );
  fd_wsample_delete( fd_wsample_leave( tree ) );
  fd_chacha20rng_delete( fd_chacha20rng_leave( rng ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_wsample_footprint( UINT_MAX, 1 ) == 0UL         );
  FD_TEST( fd_wsample_footprint( MAX,      1 )                );
  FD_TEST( fd_wsample_footprint( MAX,      1 )<MAX_FOOTPRINT  );

  for( ulong i=0UL; i<=(ulong)UINT_MAX+11UL; i+=11UL ) FD_TEST( fd_wsample_footprint( i,  0 ) == FD_WSAMPLE_FOOTPRINT( i,  0 ) );
  for( ulong i=0UL; i<=(ulong)UINT_MAX+11UL; i+=11UL ) FD_TEST( fd_wsample_footprint( i, 11 ) == FD_WSAMPLE_FOOTPRINT( i, 21 ) );

  test_matches_solana();
  test_map();
  test_sharing();
  test_restore_disabled();
  test_remove_idx();
  test_empty();

  test_probability_dist_replacement();
  test_probability_dist_noreplacement();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
