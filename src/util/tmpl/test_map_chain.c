#include "../fd_util.h"

struct pair {
  uint mykey;
  uint mynext;
  uint val;
  uint tag;
};

typedef struct pair pair_t;

#define SORT_NAME        sort_pair
#define SORT_KEY_T       pair_t
#define SORT_BEFORE(a,b) ((a).mykey<(b).mykey)
#include "fd_sort.c"

#define POOL_NAME  pool
#define POOL_T     pair_t
#define POOL_IDX_T uint
#define POOL_NEXT  mynext
#include "fd_pool.c"

#define MAP_NAME          map
#define MAP_ELE_T         pair_t
#define MAP_KEY_T         uint
#define MAP_KEY           mykey
#define MAP_IDX_T         uint
#define MAP_NEXT          mynext
#define MAP_KEY_HASH(k,s) fd_ulong_hash( ((ulong)*(k)) ^ (s) )
#include "fd_map_chain.c"

static void
shuffle_pair( fd_rng_t * rng,
              pair_t *   pair,
              ulong      cnt ) {
  for( ulong i=1UL; i<cnt; i++ ) {
    ulong j  = fd_rng_ulong_roll( rng, i+1UL );
    pair_t t = pair[i]; pair[i] = pair[j]; pair[j] = t;
  }
}

#define SCRATCH_SZ (32768UL)
uchar scratch[ SCRATCH_SZ ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong pool_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--pool-max",  NULL, 512UL );
  ulong chain_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--chain-cnt", NULL, map_chain_cnt_est( pool_max ) );
  ulong seed      = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed",      NULL, 1234UL );
  ulong iter_max  = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max",  NULL, 1000UL );

  FD_LOG_NOTICE(( "Testing with --pool-max %lu --chain-cnt %lu --seed %lu --iter-max %lu", pool_max, chain_cnt, seed, iter_max ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  pair_t ref[512];
  pair_t tst[512];
  if( FD_UNLIKELY( pool_max>512UL ) ) {
    FD_LOG_WARNING(( "skip: adjust ref and tst to support this test" ));
    return 0;
  }

  for( ulong idx=0UL; idx<pool_max; idx++ ) {
    ref[idx].mykey  = (1U<<31) | (fd_rng_uint( rng )<<9) | (uint)idx; /* Every map key is unique and non-zero */
    ref[idx].mynext = fd_rng_uint( rng );
    ref[idx].val    = fd_rng_uint( rng );
    ref[idx].tag    = 0U;
    tst[idx]        = ref[idx];
  }
  sort_pair_inplace( ref, pool_max );

  ulong ptr  = (ulong)scratch;
  ulong stop = ptr + SCRATCH_SZ;
# define ALLOC(a,s) (__extension__({                                      \
    ptr = fd_ulong_align_up( ptr, (a) );                                  \
    void * _mem = (void *)ptr;                                            \
    ptr += (s);                                                           \
    if( FD_UNLIKELY( ptr>stop ) ) {                                       \
      FD_LOG_WARNING(( "skip: adjust SCRATCH_SZ to support this test" )); \
      return 0;                                                           \
    }                                                                     \
    _mem;                                                                 \
  }))

  pair_t * pool = pool_join( pool_new( ALLOC( pool_align(), pool_footprint( pool_max ) ), pool_max ) );

  ulong ele_max   = map_ele_max();
  ulong chain_max = map_chain_max();
  FD_TEST( ele_max>=1UL );
  FD_TEST( fd_ulong_is_pow2( chain_max ) );

  FD_TEST( map_chain_cnt_est( 0UL )==map_chain_cnt_est( 1UL ) );
  FD_TEST( map_chain_cnt_est( ele_max+(ele_max<ULONG_MAX) )==map_chain_cnt_est( ele_max ) );
  for( ulong rem=1000000UL; rem; rem-- ) {
    ulong ele_max_est = 1UL+fd_rng_ulong_roll( rng, ele_max ); /* In [1,ele_max] */
    ulong chain_cnt   = map_chain_cnt_est( ele_max_est );
    FD_TEST( fd_ulong_is_pow2( chain_cnt ) & (chain_cnt<=chain_max) );

    uint r  = fd_rng_uint( rng );
    uint k0 = fd_rng_uint( rng ) >> (int)(r&31U); r >>= 5;
    uint k1 = fd_rng_uint( rng ) >> (int)(r&31U); r >>= 5;
    int  eq = (k0==k1);
    FD_TEST( map_key_eq(&k0,&k0)==1  && map_key_eq(&k1,&k0)==eq && map_key_eq(&k0,&k1)==eq && map_key_eq(&k1,&k1)==1  );

    ulong s = fd_rng_ulong( rng );
    ulong h = map_key_hash( &k0, s ); FD_COMPILER_FORGET( h ); /* All values possible and hash quality depends on the user */
  }

  FD_TEST( !map_footprint( 0UL           ) ); // too small
  FD_TEST( !map_footprint( 3UL           ) ); // tot power of 2
  FD_TEST( !map_footprint( chain_max*2UL ) ); // too large power of 2 (or 0 again)

  ulong align     = map_align();
  ulong footprint = map_footprint( chain_cnt );

  FD_TEST( fd_ulong_is_pow2( align ) );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  uchar * mem = ALLOC( align, footprint );

  FD_TEST( !map_new( NULL,  chain_cnt,     seed ) ); /* NULL mem */
  FD_TEST( !map_new( mem+1, chain_cnt,     seed ) ); /* misaligned mem */
  FD_TEST( !map_new( mem,   0UL,           seed ) ); /* too small */
  FD_TEST( !map_new( mem,   3UL,           seed ) ); /* not power of 2 */
  FD_TEST( !map_new( mem,   chain_max*2UL, seed ) ); /* too big (or 0 again) */
  void * shmap = map_new( mem, chain_cnt, seed ); FD_TEST( shmap );

  FD_TEST( !map_join( NULL  ) ); /* NULL mem */
  FD_TEST( !map_join( mem+1 ) ); /* misaligned mem */
  /* not a map tested below */
  map_t * map = map_join( shmap ); FD_TEST( map );

  FD_TEST( map_chain_cnt( map )==chain_cnt );
  FD_TEST( map_seed     ( map )==seed      );

  if( ele_max<ULONG_MAX ) FD_TEST( map_verify( map, ele_max+1UL, pool ) );

  FD_TEST(  map_verify( NULL, pool_max, pool ) );
  FD_TEST(  map_verify( map,  pool_max, NULL ) );
  FD_TEST( !map_verify( map,  pool_max, pool ) );

  uint tag = 0U;

  for( ulong iter=0UL; iter<iter_max; iter++ ) {
    if( !(iter % 100UL) ) FD_LOG_NOTICE(( "Iter %lu", iter ));

    /* Pool full at this point */
    /* Map empty at this point */

    /* Generate a randomized insertion order */
    shuffle_pair( rng, tst, pool_max );

    for( ulong i=0UL; i<pool_max; i++ ) {

      /* Try iterating over map (incl empty case) */
      tag++;
      ulong cnt = 0UL;
      for( map_iter_t iter = map_iter_init( map, pool );
           !map_iter_done( iter, map, pool );
           iter = map_iter_next( iter, map, pool ) ) {
        ulong          pi = map_iter_idx(       iter, map, pool );
        pair_t *       p  = map_iter_ele(       iter, map, pool );
        pair_t const * pc = map_iter_ele_const( iter, map, pool );
        FD_TEST( pi<pool_max   );
        FD_TEST( p ==&pool[pi] );
        FD_TEST( pc==&pool[pi] );
        FD_TEST( p->tag!=tag );
        p->tag = tag;
        cnt++;
      }
      FD_TEST( cnt==pool_used( pool ) );

      uint ki = tst[i].mykey;
      uint vi = tst[i].val;

      /* Make sure we can find all values inserted so far */
      for( ulong j=0UL; j<i; j++ ) {
        pair_t const * p = map_ele_query_const( map, &tst[j].mykey, NULL, pool );
        FD_TEST( p && p->val==tst[j].val );
      }

      /* Make sure ki isn't already in the map */
      FD_TEST( map_ele_query_const( map, &ki, (pair_t *)1UL, pool )==(pair_t *)1UL );

      /* Insert the value */
      pair_t * p = pool_ele_acquire( pool );
      p->mykey  = ki;
    //p->mynext = d/c ... managed pool and map
      p->val    = vi;
      p->tag    = tag;
      FD_TEST( map_ele_insert( map, p, pool )==map );

      /* Make sure we can look up the inserted value */
      pair_t const * q = map_ele_query_const( map, &p->mykey, NULL, pool );
      FD_TEST( q==p && q->mykey==ki && q->val==vi && q->tag==tag );

      FD_TEST( !map_verify( map, pool_max, pool ) );
    }

    /* Try iterating over map (incl full case) */
    do {
      tag++;
      ulong cnt = 0UL;
      for( map_iter_t iter = map_iter_init( map, pool );
           !map_iter_done( iter, map, pool );
           iter = map_iter_next( iter, map, pool ) ) {
        ulong          pi = map_iter_idx(       iter, map, pool );
        pair_t *       p  = map_iter_ele(       iter, map, pool );
        pair_t const * pc = map_iter_ele_const( iter, map, pool );
        FD_TEST( pi<pool_max   );
        FD_TEST( p ==&pool[pi] );
        FD_TEST( pc==&pool[pi] );
        FD_TEST( p->tag!=tag );
        p->tag = tag;
        cnt++;
      }
      FD_TEST( cnt==pool_max );
    } while(0);

    /* Generate a different randomized deletion order */
    shuffle_pair( rng, tst, pool_max );

    for( ulong i=0UL; i<pool_max; i++ ) {
      uint ki = tst[i].mykey;
      uint vi = tst[i].val;

      /* Make sure we've deleted all entries before i */
      for( ulong j=0UL; j<i; j++ ) FD_TEST( map_ele_query( map, &tst[j].mykey, (pair_t *)2UL, pool )==(pair_t *)2UL );

      /* Look up entry i and make sure it is intact */
      pair_t * p = map_ele_query( map, &ki, NULL, pool );
      FD_TEST( p && p->mykey==ki && p->val==vi && p->tag==tag );

      /* Delete entry i and verify the deletion */
      FD_TEST( map_ele_remove( map, &ki, NULL, pool )==p );
      pool_ele_release( pool, p );

      FD_TEST( !map_ele_query( map, &ki, NULL, pool ) );

      /* Make sure deleting again fails */
      FD_TEST( !map_ele_remove( map, &ki, NULL, pool ) );

      /* Make sure all remaining entries are intact */
      for( ulong j=i+1UL; j<pool_max; j++ ) {
        uint kj = tst[j].mykey;
        uint vj = tst[j].val;
        pair_t * p = map_ele_query( map, &kj, NULL, pool );
        FD_TEST( p && p->mykey==kj && p->val==vj && p->tag==tag );
      }

      FD_TEST( !map_verify( map, pool_max, pool ) );
    }

    /* Map is empty at this point */
  }

  FD_TEST( !map_delete( NULL  ) ); /* NULL map */
  FD_TEST( !map_delete( mem+1 ) ); /* misaligned map */
  FD_TEST( map_delete( shmap )==(void *)mem );

  FD_TEST( !map_leave( NULL ) ); /* NULL map */
  FD_TEST( map_leave( map )==shmap );

  FD_TEST( !map_delete( shmap ) ); /* not a map */
  FD_TEST( !map_join( shmap ) ); /* not a map */

  pool_delete( pool_leave( pool ) );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
