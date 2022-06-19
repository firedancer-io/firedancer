#include "../fd_util.h"

#define LG_SLOT_CNT 9
#define MEMOIZE     0

struct pair {
  ulong mykey;
# if MEMOIZE
  uint  myhash;
# endif
  uint  val;
};

typedef struct pair pair_t;

#define SORT_NAME        sort_pair
#define SORT_KEY_T       pair_t
#define SORT_BEFORE(a,b) ((a).mykey<(b).mykey)
#include "fd_sort.c"

#define MAP_NAME    map
#define MAP_T       pair_t
#define MAP_MEMOIZE MEMOIZE
#define MAP_KEY     mykey
#if MEMOIZE
#define MAP_HASH    myhash
#endif
#include "fd_map_dynamic.c"

uchar mem[ 16384 ] __attribute__((aligned(8)));

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

# define TEST(c) do if( !(c) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  pair_t ref[511];
  pair_t tst[511];
  ulong max = (1UL<<LG_SLOT_CNT) - 1UL; /* Take map right to its algorithmic limit */
  if( FD_UNLIKELY( max>511UL ) ) { FD_LOG_WARNING(( "SKIP: adjust ref and tst to support this test" )); return 0; }
  for( ulong idx=0UL; idx<max; idx++ ) {
    ref[idx].mykey  = ((fd_rng_ulong( rng ) | 1UL) << 8) | idx; /* Every map key is unique and non-zero */
#   if MEMOIZE
    ref[idx].myhash = map_key_hash( ref[idx].mykey );
#   endif
    ref[idx].val      = fd_rng_uint( rng );
    tst[idx] = ref[idx];
  }
  sort_pair_inplace( ref, max );

  ulong align     = map_align();
  ulong footprint = map_footprint( LG_SLOT_CNT );
  if( FD_UNLIKELY( (footprint>16384UL) | (align>8UL) ) ) { FD_LOG_WARNING(( "SKIP: adjust mem to support this test" )); return 0; }
  TEST( fd_ulong_is_pow2   ( align            )                 );
  TEST( fd_ulong_is_aligned( footprint, align )                 );
  TEST( align     >=alignof(pair_t)                             );
  TEST( footprint > sizeof (pair_t)*fd_ulong_pow2( LG_SLOT_CNT) );

  void   * shmap = map_new ( mem, LG_SLOT_CNT ); TEST( shmap );
  pair_t * map   = map_join( shmap );            TEST( map   );

  TEST( map_key_cnt    ( map )==0UL                          );
  TEST( map_key_max    ( map )==map_slot_cnt( map )-1UL      );
  TEST( map_lg_slot_cnt( map )==LG_SLOT_CNT                  );
  TEST( map_slot_cnt   ( map )==fd_ulong_pow2( LG_SLOT_CNT ) );

  ulong slot_cnt = map_slot_cnt( map );
  for( ulong slot_idx=0UL; slot_idx<slot_cnt; slot_idx++ ) TEST( map_slot_idx( map, &map[slot_idx] )==slot_idx );

  TEST( map_key_inval( map_key_null() ) );
  TEST( map_key_equal( map_key_null(), map_key_null() ) );
  for( ulong i=0UL; i<max; i++ ) {
    TEST( !map_key_inval( ref[i].mykey ) );
    TEST( !map_key_equal( ref[i].mykey, map_key_null() ) );
    TEST(  map_key_equal( ref[i].mykey, ref[i].mykey ) );
    for( ulong j=0UL; j<i; j++ ) TEST( !map_key_equal( ref[i].mykey, ref[j].mykey ) );
  }

  for( ulong iter=0UL; iter<100UL; iter++ ) {
    FD_LOG_NOTICE(( "Iter %lu", iter ));
    shuffle_pair( rng, tst, max ); /* Generate a randomized insertion order */

    /* Map is empty at this point */

    for( ulong i=0UL; i<max; i++ ) {
      ulong ki = tst[i].mykey;
#     if MEMOIZE
      uint  hi = tst[i].myhash;
#     endif
      uint  vi = tst[i].val;

      /* Make sure we can find all values inserted so far */
      for( ulong j=0UL; j<i; j++ ) {
        pair_t * p = map_query( map, tst[j].mykey, NULL );
        TEST( p && p->val==tst[j].val );
#       if MEMOIZE
        TEST( p->myhash==map_key_hash( p->mykey ) );
#       endif
      }

      /* Make sure ki isn't already in the map */
      TEST( !map_query( map, ki, NULL ) );

      /* Insert the value */
      pair_t * p = map_insert( map, ki );
      TEST( p && map_key_equal( p->mykey, ki ) );
#     if MEMOIZE
      TEST( p->myhash==hi );
#     endif
      p->val = vi;

      /* Make sure inserting again fails */
      TEST( map_key_cnt( map )==(i+1UL) );
      TEST( !map_insert( map, ki ) );
      TEST( map_key_cnt( map )==(i+1UL) );

      /* Make sure we can look up the inserted value */
      pair_t * q = map_query( map, tst[i].mykey, NULL );
      TEST( q==p && map_key_equal( q->mykey, ki ) && q->val==vi );
#     if MEMOIZE
      TEST( q->myhash==hi );
#     endif
    }

    /* Map is loaded at this point */

    shuffle_pair( rng, tst, max ); /* Generate a different randomized deletion order */

    for( ulong i=0UL; i<max; i++ ) {
      ulong ki = tst[i].mykey;
#     if MEMOIZE
      uint  hi = tst[i].myhash;
#     endif
      uint  vi = tst[i].val;

      /* Make we've deleted all entries before i */
      for( ulong j=0UL; j<i; j++ ) TEST( !map_query( map, tst[j].mykey, NULL ) );

      /* Look up entry i and make sure it is intact */
      pair_t * p = map_query( map, ki, NULL );
      TEST( p && map_key_equal( p->mykey, ki ) && p->val==vi );
#     if MEMOIZE
      TEST( p->myhash==hi );
#     endif

      /* Delete entry i and verify the deletion */
      TEST( map_key_cnt( map )==(max-i) );
      map_remove( map, p );
      TEST( map_key_cnt( map )==(max-i-1UL) );
      TEST( !map_query( map, ki, NULL ) );

      /* Make sure all remaining entries are intact */
      for( ulong j=i+1UL; j<max; j++ ) {
        ulong kj = tst[j].mykey;
#       if MEMOIZE
        uint  hj = tst[j].myhash;
#       endif
        uint  vj = tst[j].val;
        pair_t * p = map_query( map, kj, NULL );
        TEST( p && map_key_equal( p->mykey, kj ) && p->val==vj );
#       if MEMOIZE
        TEST( p->myhash==hj );
#       endif
      }

      /* Map is empty at this point */
    }
  }

  TEST( map_leave ( map   )==shmap       );
  TEST( map_delete( shmap )==(void *)mem );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
