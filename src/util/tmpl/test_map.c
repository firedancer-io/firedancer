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

#define MAP_NAME        map
#define MAP_T           pair_t
#define MAP_LG_SLOT_CNT LG_SLOT_CNT
#define MAP_MEMOIZE     MEMOIZE
#define MAP_KEY         mykey
#if MEMOIZE
#define MAP_HASH        myhash
#endif
#include "fd_map.c"

pair_t _map[ 1UL<<LG_SLOT_CNT ];

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

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  pair_t ref[511];
  pair_t tst[511];
  ulong max = (1UL<<LG_SLOT_CNT) - 1UL; /* Take map right to its algorithmic limit */
  if( FD_UNLIKELY( max>511UL ) ) { FD_LOG_WARNING(( "skip: adjust ref and tst to support this test" )); return 0; }
  for( ulong idx=0UL; idx<max; idx++ ) {
    ref[idx].mykey  = ((fd_rng_ulong( rng ) | 1UL) << 8) | idx; /* Every map key is unique and non-zero */
#   if MEMOIZE
    ref[idx].myhash = map_key_hash( ref[idx].mykey );
#   endif
    ref[idx].val      = fd_rng_uint( rng );
    tst[idx] = ref[idx];
  }
  sort_pair_inplace( ref, max );

  FD_TEST( map_align()    ==alignof(pair_t) );
  FD_TEST( map_footprint()==(sizeof(pair_t)*(1UL<<LG_SLOT_CNT)) );

  void   * shmap = map_new ( _map  ); FD_TEST( shmap );
  pair_t * map   = map_join( shmap ); FD_TEST( map   );

  FD_TEST( map_key_max() ==(fd_ulong_pow2( LG_SLOT_CNT )-1UL) );
  FD_TEST( map_slot_cnt()== fd_ulong_pow2( LG_SLOT_CNT )      );

  for( ulong slot_idx=0UL; slot_idx<map_slot_cnt(); slot_idx++ ) FD_TEST( map_slot_idx( map, &map[slot_idx] )==slot_idx );

  FD_TEST( map_key_inval( map_key_null() ) );
  FD_TEST( map_key_equal( map_key_null(), map_key_null() ) );
  for( ulong i=0UL; i<max; i++ ) {
    FD_TEST( !map_key_inval( ref[i].mykey ) );
    FD_TEST( !map_key_equal( ref[i].mykey, map_key_null() ) );
    FD_TEST(  map_key_equal( ref[i].mykey, ref[i].mykey ) );
    for( ulong j=0UL; j<i; j++ ) FD_TEST( !map_key_equal( ref[i].mykey, ref[j].mykey ) );
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
        FD_TEST( p && p->val==tst[j].val );
#       if MEMOIZE
        FD_TEST( p->myhash==map_key_hash( p->mykey ) );
#       endif
      }

      /* Make sure ki isn't already in the map */
      FD_TEST( !map_query( map, ki, NULL ) );

      /* Insert the value */
      pair_t * p = map_insert( map, ki );
      FD_TEST( p && map_key_equal( p->mykey, ki ) );
#     if MEMOIZE
      FD_TEST( p->myhash==hi );
#     endif
      p->val = vi;

      /* Make sure inserting again fails */
      FD_TEST( !map_insert( map, ki ) );

      /* Make sure we can look up the inserted value */
      pair_t * q = map_query( map, tst[i].mykey, NULL );
      FD_TEST( q==p && map_key_equal( q->mykey, ki ) && q->val==vi );
#     if MEMOIZE
      FD_TEST( q->myhash==hi );
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
      for( ulong j=0UL; j<i; j++ ) FD_TEST( !map_query( map, tst[j].mykey, NULL ) );

      /* Look up entry i and make sure it is intact */
      pair_t * p = map_query( map, ki, NULL );
      FD_TEST( p && map_key_equal( p->mykey, ki ) && p->val==vi );
#     if MEMOIZE
      FD_TEST( p->myhash==hi );
#     endif

      /* Delete entry i and verify the deletion */
      map_remove( map, p );
      FD_TEST( !map_query( map, ki, NULL ) );

      /* Make sure all remaining entries are intact */
      for( ulong j=i+1UL; j<max; j++ ) {
        ulong kj = tst[j].mykey;
#       if MEMOIZE
        uint  hj = tst[j].myhash;
#       endif
        uint  vj = tst[j].val;
        pair_t * p = map_query( map, kj, NULL );
        FD_TEST( p && map_key_equal( p->mykey, kj ) && p->val==vj );
#       if MEMOIZE
        FD_TEST( p->myhash==hj );
#       endif
      }

      /* Map is empty at this point */
    }
  }

  FD_TEST( map_leave ( map   )==shmap        );
  FD_TEST( map_delete( shmap )==(void *)_map );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
