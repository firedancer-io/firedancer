#include "../fd_util.h"

struct pair {
  ulong mykey;
  ulong myval;
};

typedef struct pair pair_t;

static inline int
ulong_cmp( ulong const * _a,
           ulong const * _b ) {
  ulong a = *_a;
  ulong b = *_b;
  if( a<b ) return -1;
  if( a>b ) return  1;
  return 0;
}

#define BPLUS_NAME         bplus
#define BPLUS_KEY_T        ulong
#define BPLUS_PAIR_T       pair_t
#define BPLUS_PAIR_KEY     mykey
#define BPLUS_KEY_CMP(a,b) ulong_cmp(a,b)
#define BPLUS_TREE_MAX     6
#define BPLUS_PAIR_MAX     4
#include "fd_bplus.c"

#define MEM_ALIGN (128UL)
#define MEM_SZ    (1048576UL)
static uchar mem[ MEM_SZ ] __attribute__((aligned(MEM_ALIGN)));
static ulong mem_used = 0UL; /* MEM_ALIGN multiple */

/* Note: assumes all required alignments are <=MEM_ALIGN and result will
   be aligned MEM_ALIGN */

#define ALLOC( T, n ) (__extension__({                                       \
    T *    _alloc    = (T *)(mem + mem_used);                                \
    ulong _footprint = fd_ulong_align_up( sizeof(T)*(ulong)(n), MEM_ALIGN ); \
    if( FD_UNLIKELY( _footprint>(MEM_SZ-mem_used) ) )                        \
      FD_LOG_ERR(( "increase MEM_SZ for these unit test parameters" ));      \
    mem_used += _footprint;                                                  \
    _alloc;                                                                  \
  }))

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong ele_max_est = fd_env_strip_cmdline_ulong( &argc, &argv, "--ele-max-est", NULL, 4096UL );
  ulong node_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--node-max",    NULL, bplus_node_max_est( ele_max_est ) );
  ulong leaf_max    = fd_env_strip_cmdline_ulong( &argc, &argv, "--leaf-max",    NULL, bplus_leaf_max_est( ele_max_est ) );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Testing (--ele-max-est %lu --node-max %lu --leaf-max %lu)", ele_max_est, node_max, leaf_max ));

  ulong    pair_max = ele_max_est;
  pair_t * pair     = ALLOC( pair_t, pair_max );
  ulong    pair_cnt = 0UL;

  /* Test construction */

  FD_TEST( bplus_node_max_est( 0UL )==0UL );
  FD_TEST( bplus_node_max_est( 1UL )==0UL );

  FD_TEST( bplus_leaf_max_est( 0UL )==0UL );
  FD_TEST( bplus_leaf_max_est( 1UL )==1UL );

  ulong align = bplus_align();
  FD_TEST( fd_ulong_is_pow2( align ) );
  FD_TEST( align<=4096UL );

  FD_TEST( !bplus_footprint( ULONG_MAX, leaf_max  ) );
  FD_TEST( !bplus_footprint( node_max,  ULONG_MAX ) );

  ulong footprint = bplus_footprint( node_max, leaf_max );
  FD_TEST( footprint );

  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  uchar * shmem = ALLOC( uchar, footprint );

  FD_TEST( !bplus_new( NULL,        node_max,  leaf_max  ) ); /* NULL shmem */
  FD_TEST( !bplus_new( (void *)1UL, node_max,  leaf_max  ) ); /* misaligned shmem */
  FD_TEST( !bplus_new( shmem,       ULONG_MAX, leaf_max  ) ); /* bad node max */
  FD_TEST( !bplus_new( shmem,       node_max,  ULONG_MAX ) ); /* bad leaf max */

  FD_TEST( bplus_new( shmem, node_max, leaf_max )==shmem );

  FD_TEST( !bplus_join( NULL        ) ); /* NULL shbplus */
  FD_TEST( !bplus_join( (void *)1UL ) ); /* NULL shbplus */
  /* bad magic tested below */

  bplus_t * bplus = bplus_join( shmem );
  FD_TEST( bplus );

  /* Test filling up bplus to its limits */

  pair_cnt = 0UL;

  FD_TEST( bplus_is_empty( bplus ) );

  for( ulong iter=0UL; iter<3UL*ele_max_est; iter++ ) {
    ulong key = fd_ulong_hash( iter );
    pair_t * p = bplus_insert( bplus, &key );
    if( FD_UNLIKELY( !p ) ) break;
    p->myval = iter;
    pair_cnt++;
  }

  FD_TEST( ele_max_est<=pair_cnt );
  FD_TEST( pair_cnt<=2UL*ele_max_est );

  for( ulong iter=0UL; iter<pair_cnt; iter++ ) {
    ulong key = fd_ulong_hash( iter );
    pair_t const * p = bplus_query_const( bplus, &key );
    FD_TEST( p );
    FD_TEST( p->mykey==key  );
    FD_TEST( p->myval==iter );
  }

  for( ulong iter=0UL; iter<pair_cnt; iter++ ) {
    ulong key = fd_ulong_hash( iter );
    FD_TEST( !bplus_remove_key( bplus, &key ) );
  }

  FD_TEST( bplus_is_empty( bplus ) );

  /* Test accessors and operations */

  pair_cnt = 0UL;

  ulong min_key = ULONG_MAX;
  ulong max_key = 0UL;

  ulong iter_max = 10000000UL; /* Should be less than 2^32 */
  ulong diag_rem = 0UL;
  for( ulong iter=0UL; iter<iter_max; iter++ ) {
    if( FD_UNLIKELY( !diag_rem ) ) {
      FD_LOG_NOTICE(( "On iter %10lu of %10lu (pair_cnt %lu)", iter, iter_max, pair_cnt ));
      diag_rem = 1000000UL;
    }
    diag_rem--;

    ulong r  = fd_rng_ulong( rng );
    int   op = (int)(r & 15UL); r >>= 4;
    switch( op ) {

    case 0: { /* query_const (key exists) */
      if( FD_UNLIKELY( !pair_cnt ) ) { FD_TEST( bplus_is_empty( bplus ) ); break; } /* empty */
      FD_TEST( !bplus_is_empty( bplus ) );
      ulong pair_idx = fd_rng_ulong_roll( rng, pair_cnt ); /* In [0,pair_cnt) */
      pair_t const * q = &pair[ pair_idx ];
      pair_t const * p = bplus_query_const( bplus, &q->mykey );
      FD_TEST( p );
      FD_TEST( p->mykey==q->mykey );
      FD_TEST( p->myval==q->myval );
      break;
    }

    case 1: { /* query (key exists) (changes the val associated with key) */
      if( FD_UNLIKELY( !pair_cnt ) ) { FD_TEST( bplus_is_empty( bplus ) ); break; } /* empty */
      FD_TEST( !bplus_is_empty( bplus ) );
      ulong pair_idx = fd_rng_ulong_roll( rng, pair_cnt ); /* In [0,pair_cnt) */
      pair_t * q = &pair[ pair_idx ];
      pair_t * p = bplus_query( bplus, &q->mykey );
      FD_TEST( p );
      FD_TEST( p->mykey==q->mykey );
      FD_TEST( p->myval==q->myval );
      ulong val = fd_rng_ulong( rng );
      p->myval = val;
      q->myval = val;
      break;
    }

    case 2: { /* query / query_const (key does not exist) */
      ulong key = fd_rng_ulong( rng ) | 1UL; /* We only insert even keys in this unit test */
      FD_TEST( !bplus_query      ( bplus, &key ) );
      FD_TEST( !bplus_query_const( bplus, &key ) );
      break;
    }

    case 3: { /* insert (key exists) */
      if( FD_UNLIKELY( !pair_cnt ) ) { FD_TEST( bplus_is_empty( bplus ) ); break; } /* empty */
      FD_TEST( !bplus_is_empty( bplus ) );
      ulong pair_idx = fd_rng_ulong_roll( rng, pair_cnt ); /* In [0,pair_cnt) */
      ulong key      = pair[ pair_idx ].mykey;
      FD_TEST( !bplus_insert( bplus, &key ) );
      break;
    }

    case 4: { /* insert (key does not exist) */
      if( FD_UNLIKELY( pair_cnt==pair_max ) ) break; /* Full */
      ulong key = ((ulong)fd_uint_hash( (uint)iter )) << 1; /* Generate a random looking unique even key (uint_hash is a perm) */
      ulong val = fd_rng_ulong( rng );
      pair_t * q = &pair[ pair_cnt++ ];
      q->mykey = key;
      q->myval = val;
      pair_t * p = bplus_insert( bplus, &key );
      FD_TEST( p );
      FD_TEST( p->mykey==key );
      p->myval = val;
      FD_TEST( bplus_query( bplus, &key )==p );
      min_key = fd_ulong_min( min_key, key );
      max_key = fd_ulong_max( max_key, key );
      break;
    }

    case 5: { /* upsert (key exists) (changes the val associated with key) */
      if( FD_UNLIKELY( !pair_cnt ) ) { FD_TEST( bplus_is_empty( bplus ) ); break; } /* empty */
      FD_TEST( !bplus_is_empty( bplus ) );
      ulong pair_idx = fd_rng_ulong_roll( rng, pair_cnt ); /* In [0,pair_cnt) */
      pair_t * q = &pair[ pair_idx ];
      int insert; pair_t * p = bplus_upsert( bplus, &q->mykey, &insert );
      FD_TEST( p );
      FD_TEST( insert==0 );
      FD_TEST( p->mykey==q->mykey );
      FD_TEST( p->myval==q->myval );
      ulong val = fd_rng_ulong( rng );
      p->myval = val;
      q->myval = val;
      break;
    }

    case 6: { /* upsert (key does not exist) */
      if( FD_UNLIKELY( pair_cnt==pair_max ) ) break; /* Full */
      ulong key = ((ulong)fd_uint_hash( (uint)iter )) << 1; /* Generate a random looking unique even key (uint_hash is a perm) */
      ulong val = fd_rng_ulong( rng );
      pair_t * q = &pair[ pair_cnt++ ];
      q->mykey = key;
      q->myval = val;
      int insert; pair_t * p = bplus_upsert( bplus, &key, &insert );
      FD_TEST( p );
      FD_TEST( insert==1 );
      FD_TEST( p->mykey==key );
      p->myval = val;
      FD_TEST( bplus_query( bplus, &key )==p );
      min_key = fd_ulong_min( min_key, key );
      max_key = fd_ulong_max( max_key, key );
      break;
    }

    case 7: { /* remove_key (key exists) */
      if( FD_UNLIKELY( !pair_cnt ) ) { FD_TEST( bplus_is_empty( bplus ) ); break; } /* empty */
      FD_TEST( !bplus_is_empty( bplus ) );
      ulong pair_idx = fd_rng_ulong_roll( rng, pair_cnt ); /* In [0,pair_cnt) */
      ulong key      = pair[ pair_idx ].mykey;
      pair[ pair_idx ] = pair[ --pair_cnt ];
      FD_TEST( !bplus_remove_key( bplus, &key ) );
      FD_TEST( !bplus_query( bplus, &key ) );
      if( FD_UNLIKELY( (!pair_cnt) | (key==min_key) | (key==max_key) ) ) { /* Update the min/max key */
        min_key = ULONG_MAX;
        max_key = 0UL;
        for( pair_idx=0UL; pair_idx<pair_cnt; pair_idx++ ) {
          key     = pair[ pair_idx ].mykey;
          min_key = fd_ulong_min( min_key, key );
          max_key = fd_ulong_max( max_key, key );
        }
      }
      break;
    }

    case 8: { /* remove_key (key does not exist) */
      ulong key = fd_rng_ulong( rng ) | 1UL; /* We only insert even keys in this unit test */
      FD_TEST( bplus_remove_key( bplus, &key )==-1 );
      break;
    }

    case 9: { /* remove */
      if( FD_UNLIKELY( !pair_cnt ) ) { FD_TEST( bplus_is_empty( bplus ) ); break; } /* empty */
      FD_TEST( !bplus_is_empty( bplus ) );
      ulong pair_idx = fd_rng_ulong_roll( rng, pair_cnt ); /* In [0,pair_cnt) */
      ulong key      = pair[ pair_idx ].mykey;
      pair[ pair_idx ] = pair[ --pair_cnt ];
      pair_t * p = bplus_query( bplus, &key );
      FD_TEST( p );
      bplus_remove( bplus, p );
      FD_TEST( !bplus_query( bplus, &key ) );
      if( FD_UNLIKELY( (!pair_cnt) | (key==min_key) | (key==max_key) ) ) { /* Update the min/max key */
        min_key = ULONG_MAX;
        max_key = 0UL;
        for( pair_idx=0UL; pair_idx<pair_cnt; pair_idx++ ) {
          key     = pair[ pair_idx ].mykey;
          min_key = fd_ulong_min( min_key, key );
          max_key = fd_ulong_max( max_key, key );
        }
      }
      break;
    }

    case 10: { /* whole iterators */
      bplus_iter_t iter_nul = bplus_iter_nul( bplus );
      bplus_iter_t iter_min = bplus_iter_min( bplus );
      bplus_iter_t iter_max = bplus_iter_max( bplus );
      if( FD_UNLIKELY( !pair_cnt ) ) {
        FD_TEST( bplus_is_empty( bplus ) );
        FD_TEST( bplus_iter_eq_nul( bplus, iter_min ) );
        FD_TEST( bplus_iter_eq_nul( bplus, iter_max ) );
      } else {
        FD_TEST( !bplus_is_empty( bplus ) );
        FD_TEST( bplus_iter_pair_const( bplus, iter_min )==bplus_min_const( bplus ) );
        FD_TEST( bplus_iter_pair      ( bplus, iter_min )==bplus_min      ( bplus ) );
        FD_TEST( bplus_iter_pair_const( bplus, iter_max )==bplus_max_const( bplus ) );
        FD_TEST( bplus_iter_pair      ( bplus, iter_max )==bplus_max      ( bplus ) );
        FD_TEST( bplus_iter_eq( bplus, bplus_iter_prev( bplus, iter_min ), iter_nul ) );
        FD_TEST( bplus_iter_eq( bplus, bplus_iter_next( bplus, iter_max ), iter_nul ) );
        FD_TEST( !bplus_iter_eq_nul( bplus, iter_min ) );
        FD_TEST( !bplus_iter_eq_nul( bplus, iter_max ) );
      }
      break;
    }

    case 11: { /* range iterators (key exists) */
      if( FD_UNLIKELY( !pair_cnt ) ) FD_TEST( bplus_is_empty( bplus ) );
      else {
        FD_TEST( !bplus_is_empty( bplus ) );
        ulong pair_idx = fd_rng_ulong_roll( rng, pair_cnt ); /* In [0,pair_cnt) */
        ulong key      = pair[ pair_idx ].mykey;
        bplus_iter_t iter_ge = bplus_iter_ge( bplus, &key );
        bplus_iter_t iter_gt = bplus_iter_gt( bplus, &key );
        bplus_iter_t iter_le = bplus_iter_le( bplus, &key );
        bplus_iter_t iter_lt = bplus_iter_lt( bplus, &key );

        FD_TEST( !bplus_iter_eq_nul( bplus, iter_le ) );
        FD_TEST( bplus_iter_eq( bplus, iter_le, iter_ge ) );
        pair_t const * pair_eq = bplus_iter_pair_const( bplus, iter_le );
        FD_TEST( pair_eq->mykey==key );

        if( FD_UNLIKELY( bplus_iter_eq_nul( bplus, iter_gt ) ) ) FD_TEST( pair_eq->mykey==max_key );
        else                                                     FD_TEST( key < bplus_iter_pair_const( bplus, iter_gt )->mykey );

        if( FD_UNLIKELY( bplus_iter_eq_nul( bplus, iter_lt ) ) ) FD_TEST( pair_eq->mykey==min_key );
        else                                                     FD_TEST( key > bplus_iter_pair_const( bplus, iter_lt )->mykey );
      }
      break;
    }

    case 12: { /* range iterators (key does not exist) */
      ulong key = fd_rng_ulong( rng ) | 1UL; /* We only insert even keys in this unit test */
      bplus_iter_t iter_ge = bplus_iter_ge( bplus, &key );
      bplus_iter_t iter_gt = bplus_iter_gt( bplus, &key );
      bplus_iter_t iter_le = bplus_iter_le( bplus, &key );
      bplus_iter_t iter_lt = bplus_iter_lt( bplus, &key );
      FD_TEST( bplus_iter_eq( bplus, iter_gt, iter_ge ) );
      FD_TEST( bplus_iter_eq( bplus, iter_lt, iter_le ) );

      if( FD_LIKELY( !bplus_iter_eq_nul( bplus, iter_lt ) ) ) {
        FD_TEST( bplus_iter_eq( bplus, bplus_iter_next( bplus, iter_lt ), iter_gt ) );
        pair_t const * pair_lt = bplus_iter_pair_const( bplus, iter_lt );
        FD_TEST( pair_lt->mykey < key );
        if( bplus_iter_eq_nul( bplus, iter_gt ) ) FD_TEST( pair_lt->mykey==max_key );
        else                                      FD_TEST( key < bplus_iter_pair_const( bplus, iter_gt )->mykey );
      }

      if( FD_LIKELY( !bplus_iter_eq_nul( bplus, iter_gt ) ) ) {
        FD_TEST( bplus_iter_eq( bplus, bplus_iter_prev( bplus, iter_gt ), iter_lt ) );
        pair_t const * pair_gt = bplus_iter_pair_const( bplus, iter_gt );
        FD_TEST( pair_gt->mykey > key );
        if( FD_UNLIKELY( bplus_iter_eq_nul( bplus, iter_lt ) ) ) FD_TEST( pair_gt->mykey==min_key );
        else                                                     FD_TEST( key > bplus_iter_pair_const( bplus, iter_lt )->mykey );
      }

      break;
    }

    /* case 13 unused */
    /* case 14 unused */

    case 15: { /* accessors and verify */
      FD_TEST( bplus_node_max( bplus )==node_max );
      FD_TEST( bplus_leaf_max( bplus )==leaf_max );
      if( FD_UNLIKELY( !pair_cnt ) ) FD_TEST( bplus_is_empty( bplus ) );
      else {
        FD_TEST( !bplus_is_empty( bplus ) );
        pair_t const * p;             pair_t * q;
        p = bplus_min_const( bplus ); q = bplus_min( bplus ); FD_TEST( p ); FD_TEST( p==q ); FD_TEST( p->mykey==min_key );
        p = bplus_max_const( bplus ); q = bplus_max( bplus ); FD_TEST( p ); FD_TEST( p==q ); FD_TEST( p->mykey==max_key );
      }
      FD_TEST( !bplus_verify( bplus ) );
      break;
    }

    default:
      break;
    }
  }

  /* Test bplus_flush */

  bplus_flush( bplus );
  FD_TEST( bplus_is_empty( bplus ) );

  /* Test destruction */

  FD_TEST( !bplus_leave( NULL )        ); /* NULL join */
  FD_TEST( bplus_leave( bplus )==shmem );

  FD_TEST( !bplus_delete( NULL        ) ); /* NULL shmem */
  FD_TEST( !bplus_delete( (void *)1UL ) ); /* misaligned shmem */
  /* bad magic tested below */

  FD_TEST( bplus_delete( shmem )==shmem );

  FD_TEST( !bplus_join  ( shmem ) ); /* bad magic */
  FD_TEST( !bplus_delete( shmem ) ); /* bad magic */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
