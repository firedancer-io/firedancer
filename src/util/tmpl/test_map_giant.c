#include "../fd_util.h"

struct pair {
  ulong mykey;
  ulong mynext;
  uint  val;
  uint  tag;
};

typedef struct pair pair_t;

#define SORT_NAME        sort_pair
#define SORT_KEY_T       pair_t
#define SORT_BEFORE(a,b) ((a).mykey<(b).mykey)
#include "fd_sort.c"

#define MAP_NAME map
#define MAP_T    pair_t
#define MAP_KEY  mykey
#define MAP_NEXT mynext
#include "fd_map_giant.c"

uchar mem[ 32768 ] __attribute__((aligned(128)));

static void
shuffle_pair( fd_rng_t * rng,
              pair_t *   pair,
              ulong      cnt ) {
  for( ulong i=1UL; i<cnt; i++ ) {
    ulong j  = fd_rng_ulong_roll( rng, i+1UL );
    pair_t t = pair[i]; pair[i] = pair[j]; pair[j] = t;
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong max      = fd_env_strip_cmdline_ulong( &argc, &argv, "--max",      NULL,  512UL );
  ulong seed     = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",     NULL, 1234UL );
  ulong iter_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max", NULL, 1000UL );

  FD_LOG_NOTICE(( "Testing with --max %lu --seed %lu --iter-max %lu", max, seed, iter_max ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  pair_t ref[512];
  pair_t tst[512];
  if( FD_UNLIKELY( max>512UL ) ) {
    FD_LOG_WARNING(( "skip: adjust ref and tst to support this test" ));
    return 0;
  }
  for( ulong idx=0UL; idx<max; idx++ ) {
    ref[idx].mykey  = (1UL<<63) | (fd_rng_ulong( rng )<<9) | idx; /* Every map key is unique and non-zero */
    ref[idx].mynext = fd_rng_ulong( rng );
    ref[idx].val    = fd_rng_uint( rng );
    ref[idx].tag    = 0U;
    tst[idx] = ref[idx];
  }
  sort_pair_inplace( ref, max );

  FD_TEST( !map_footprint( ULONG_MAX ) );

  ulong align     = map_align();
  ulong footprint = map_footprint( max );
  if( FD_UNLIKELY( (footprint>32768UL) | (align>128UL) ) ) {
    FD_LOG_WARNING(( "skip: adjust mem to support this test" ));
    return 0;
  }
  FD_TEST( fd_ulong_is_pow2   ( align            ) ); FD_TEST( align>=alignof(pair_t) );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  FD_TEST( !map_new( NULL,  max,       seed ) ); /* NULL mem */
  FD_TEST( !map_new( mem+1, max,       seed ) ); /* misaligned mem */
  FD_TEST( !map_new( mem,   ULONG_MAX, seed ) ); /* too big request */
  void * shmap = map_new ( mem, max, seed ); FD_TEST( shmap );

  FD_TEST( !map_join( NULL  ) ); /* NULL mem */
  FD_TEST( !map_join( mem+1 ) ); /* misaligned mem */
  /* not a map tested below */
  pair_t * map = map_join( shmap ); FD_TEST( map );

  FD_TEST( map_key_cnt ( map )==0UL  );
  FD_TEST( map_key_max ( map )==max  );
  FD_TEST( map_seed    ( map )==seed );

  for( ulong rem=1000000UL; rem; rem-- ) {
    uint  r  = fd_rng_uint( rng );
    ulong k0 = fd_rng_ulong( rng ) >> (int)(r&31U); r >>= 5;
    ulong k1 = fd_rng_ulong( rng ) >> (int)(r&31U); r >>= 5;
    int   eq = (k0==k1);
    FD_TEST( map_key_eq(&k0,&k0)==1  && map_key_eq(&k1,&k0)==eq && map_key_eq(&k0,&k1)==eq && map_key_eq(&k1,&k1)==1  );
    k1 = map_key_hash( &k0, k1 ); FD_COMPILER_FORGET( k1 ); /* All values possible and hash quality depends on the user */
    FD_TEST( map_key_copy( &k1, &k0 )==&k1 && k1==k0 );
  }

  FD_TEST( !map_verify( map ) );

  uint tag = 0U;

  for( ulong iter=0UL; iter<iter_max; iter++ ) {
    if( !(iter % 100UL) ) FD_LOG_NOTICE(( "Iter %lu", iter ));
    shuffle_pair( rng, tst, max ); /* Generate a randomized insertion order */

    /* Map is empty at this point */

    for( ulong i=0UL; i<max; i++ ) {
      FD_TEST( !map_is_full( map ) );

      /* Try iterating over map (incl empty case) */
      tag++;
      ulong cnt = 0UL;
      for( map_iter_t iter = map_iter_init( map ); !map_iter_done( map, iter ); iter = map_iter_next( map, iter ) ) {
        pair_t *       p0 = map_iter_ele(       map, iter );
        pair_t const * p1 = map_iter_ele_const( map, iter );
        FD_TEST( p0 );
        FD_TEST( p1 );
        FD_TEST( p1==(pair_t const *)p0 );
        FD_TEST( p0->tag!=tag );
        p0->tag = tag;
        cnt++;
      }
      FD_TEST( cnt==i );

      ulong ki = tst[i].mykey;
      uint  vi = tst[i].val;

      /* Make sure we can find all values inserted so far */
      for( ulong j=0UL; j<i; j++ ) {
        pair_t const * p = map_query_const( map, &tst[j].mykey, NULL );
        FD_TEST( p && p->val==tst[j].val );
      }

      /* Make sure ki isn't already in the map */
      FD_TEST( map_query_const( map, &ki, (pair_t *)1UL )==(pair_t *)1UL );

      /* Insert the value */
      pair_t * p = map_insert( map, &ki );
      FD_TEST( p && p->mykey==ki );
      p->val = vi;

      FD_TEST( map_key_cnt( map )==(i+1UL) );

      /* Make sure we can look up the inserted value */
      pair_t const * q = map_query_const( map, &tst[i].mykey, NULL );
      FD_TEST( q==p && q->mykey==ki && q->val==vi );

      FD_TEST( !map_verify( map ) );
    }

    /* Make sure map is full at this point */
    FD_TEST( map_is_full( map ) );

    do {
      tag++;
      ulong cnt = 0UL;
      for( map_iter_t iter = map_iter_init( map ); !map_iter_done( map, iter ); iter = map_iter_next( map, iter ) ) {
        pair_t *       p0 = map_iter_ele(       map, iter );
        pair_t const * p1 = map_iter_ele_const( map, iter );
        FD_TEST( p0 );
        FD_TEST( p1 );
        FD_TEST( p1==(pair_t const *)p0 );
        FD_TEST( p0->tag!=tag );
        p0->tag = tag;
        cnt++;
      }
      FD_TEST( cnt==max );
    } while(0);

    /* Generate a different randomized deletion order */
    shuffle_pair( rng, tst, max );

    for( ulong i=0UL; i<max; i++ ) {
      ulong ki = tst[i].mykey;
      uint  vi = tst[i].val;

      /* Make sure we've deleted all entries before i */
      for( ulong j=0UL; j<i; j++ ) FD_TEST( map_query( map, &tst[j].mykey, (pair_t *)2UL )==(pair_t *)2UL );

      /* Look up entry i and make sure it is intact */
      pair_t * p = map_query( map, &ki, NULL );
      FD_TEST( p && p->mykey==ki && p->val==vi );

      /* Delete entry i and verify the deletion */
      FD_TEST( map_key_cnt( map )==(max-i)     );
      FD_TEST( map_remove( map, &ki )==p );
      FD_TEST( map_key_cnt( map )==(max-i-1UL) );
      FD_TEST( !map_query( map, &ki, NULL ) );

      FD_TEST( !map_is_full( map ) );

      /* Make sure deleting again fails */
      FD_TEST( !map_remove( map, &ki ) ); /* FIXME: CONSIDER SENTINEL HERE? */

      /* Make sure all remaining entries are intact */
      for( ulong j=i+1UL; j<max; j++ ) {
        ulong kj = tst[j].mykey;
        uint  vj = tst[j].val;
        pair_t * p = map_query( map, &kj, NULL );
        FD_TEST( p && p->mykey==kj && p->val==vj );
      }

      /* Map is empty at this point */

      FD_TEST( !map_verify( map ) );
    }
  }

  /* FIXME: TEST ITERATOR */

  FD_TEST( !map_leave( NULL ) ); /* NULL map */
  FD_TEST( map_leave( map )==shmap );

  FD_TEST( !map_delete( NULL  ) ); /* NULL map */
  FD_TEST( !map_delete( mem+1 ) ); /* misaligned map */
  FD_TEST( map_delete( shmap )==(void *)mem );

  FD_TEST( !map_delete( shmap ) ); /* not a map */
  FD_TEST( !map_join( shmap ) ); /* not a map */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
