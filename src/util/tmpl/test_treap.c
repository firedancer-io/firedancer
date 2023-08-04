#include "../fd_util.h"

#define CIDX_T uchar
#define VAL_T  schar

struct ele {
  CIDX_T parent_cidx;
  CIDX_T left_cidx;
  CIDX_T right_cidx;
  CIDX_T prio_cidx;
  VAL_T  val;
};

typedef struct ele ele_t;

#define POOL_NAME  pool
#define POOL_T     ele_t
#define POOL_IDX_T CIDX_T
#define POOL_NEXT  parent_cidx
#include "fd_pool.c"

#define TREAP_NAME       treap
#define TREAP_T          ele_t
#define TREAP_QUERY_T    VAL_T
#define TREAP_CMP(q,e)   (((int)(q)) - ((int)((e)->val)))
#define TREAP_LT(e0,e1)  (((int)((e0)->val)) < ((int)((e1)->val)))
#define TREAP_IDX_T      CIDX_T
#define TREAP_PARENT     parent_cidx
#define TREAP_LEFT       left_cidx
#define TREAP_RIGHT      right_cidx
#define TREAP_PRIO       prio_cidx
#define TREAP_IMPL_STYLE 0
#include "fd_treap.c"

#define SCRATCH_ALIGN     (128UL)
#define SCRATCH_FOOTPRINT (2048UL)
static uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

#if 0
#include <stdio.h>

static void
dump_treap( ulong         i,
            ele_t const * ele,
            ulong         indent ) {
  if( treap_idx_is_null( i ) ) {
    for( ulong rem=indent; rem; rem-- ) fputc( ' ', stdout );
    printf( "  -\n" );
    return;
  }

  dump_treap( (ulong)ele[i].right_cidx, ele, indent+4UL );

  for( ulong rem=indent; rem; rem-- ) fputc( ' ', stdout );
  printf( "val %i (prio %lu idx %lu)\n", (int)ele[i].val, (ulong)ele[i].prio_cidx, i );

  dump_treap( (ulong)ele[i].left_cidx, ele, indent+4UL );
}
#endif

/* Returns the index to delete when you're at the index passed in the
   first parameter, or -1 to not delete anything. */
typedef int(delfn_t)(int);

static void
test_iteration( delfn_t del ) {
  treap_t _treap[1];

  /* Forward direction */
  if( 1 ) {
    treap_t * treap = treap_join( treap_new( _treap, 64UL ) );
    ele_t * pool = pool_join( pool_new( scratch, 64UL ) );

    for( ulong i=0UL; i<64UL; i++ ) {
      ulong idx = pool_idx_acquire( pool );
      pool[ idx ].val  = (schar)i;
      pool[ idx ].prio_cidx = (uchar)(i^36UL);
      treap_idx_insert( treap, idx, pool );
    }

    ulong seen = 0UL; /* bitflag */
    int largest = -1;
    treap_fwd_iter_t next;
    for( treap_fwd_iter_t iter = treap_fwd_iter_init( treap, pool ); !treap_fwd_iter_done( iter ); iter = next ) {
      next = treap_fwd_iter_next( iter, pool );
      int next_idx = treap_fwd_iter_done( next ) ? -2 : (int)treap_fwd_iter_idx( next );

      int i = treap_fwd_iter_ele( iter, pool )->val;

      FD_TEST( !(seen & (1UL<<i)) );          seen |= (1UL<<i);
      FD_TEST( i>largest          );          largest = i;

      int delete_idx = del( i );
      if( delete_idx != -1 ) {
        treap_idx_remove( treap, (ulong)delete_idx, pool );
        seen |= (1UL<<delete_idx);
      }

      if( delete_idx == next_idx ) next = treap_fwd_iter_next( iter, pool );
    }
    FD_TEST( seen == ~0UL );

    treap_delete( treap_leave( treap ) );
    pool_delete ( pool_leave ( pool  ) );
  }

  if( 1 ) {
    treap_t * treap = treap_join( treap_new( _treap, 64UL ) );
    ele_t * pool = pool_join( pool_new( scratch, 64UL ) );

    for( ulong i=0UL; i<64UL; i++ ) {
      ulong idx = pool_idx_acquire( pool );
      pool[ idx ].val  = (schar)i;
      pool[ idx ].prio_cidx = (uchar)(i^36UL);
      treap_idx_insert( treap, idx, pool );
    }

    ulong seen = 0UL; /* bitflag */
    int smallest = 64;
    treap_rev_iter_t prev;
    for( treap_rev_iter_t iter = treap_rev_iter_init( treap, pool ); !treap_rev_iter_done( iter ); iter = prev ) {
      prev = treap_rev_iter_next( iter, pool );
      int prev_idx = treap_rev_iter_done( prev ) ? -2 : (int)treap_rev_iter_idx( prev );

      int i = treap_rev_iter_ele( iter, pool )->val;

      FD_TEST( !(seen & (1UL<<i)) );          seen |= (1UL<<i);
      FD_TEST( i<smallest         );          smallest = i;

      int delete_idx = del( i );
      if( delete_idx != -1 ) {
        treap_idx_remove( treap, (ulong)delete_idx, pool );
        seen |= (1UL<<delete_idx);
      }

      if( delete_idx == prev_idx ) prev = treap_rev_iter_next( iter, pool );
    }
    FD_TEST( seen == ~0UL );

    treap_delete( treap_leave( treap ) );
    pool_delete ( pool_leave ( pool  ) );
  }
}

static int del_fn_self_0( int i ) { (void)i; return          -1; }
static int del_fn_self_1( int i ) { return (( i&1)       )?i:-1; }
static int del_fn_self_2( int i ) { return ((~i&1)       )?i:-1; }
static int del_fn_self_3( int i ) { return (( i&1)&(i<32))?i:-1; }
static int del_fn_self_4( int i ) { return ((~i&1)&(i<32))?i:-1; }
static int del_fn_self_5( int i ) { return (( i&1)&(i>31))?i:-1; }
static int del_fn_self_6( int i ) { return ((~i&1)&(i>31))?i:-1; }
static int del_fn_self_7( int i ) { return                 i;    }

static int del_fn_next  ( int i ) { return  i<63?i+1:-1; }
static int del_fn_prev  ( int i ) { return  i> 0?i-1:-1; }
static int del_fn_3     ( int i ) { return  (i*3)%64;    }
static int del_fn_5     ( int i ) { return  (i*5)%64;    }

static void
test_iteration_all( void ) {
  test_iteration( del_fn_self_0 );
  test_iteration( del_fn_self_1 );
  test_iteration( del_fn_self_2 );
  test_iteration( del_fn_self_3 );
  test_iteration( del_fn_self_4 );
  test_iteration( del_fn_self_5 );
  test_iteration( del_fn_self_6 );
  test_iteration( del_fn_self_7 );

  test_iteration( del_fn_next );
  test_iteration( del_fn_prev );
  test_iteration( del_fn_3    );
  test_iteration( del_fn_5    );
}

static void
test_merge( fd_rng_t * rng ) {
  treap_t _treap[2];
  ulong ele_max = 254UL;

  ele_t * pool = pool_join( pool_new( scratch,   ele_max ) );
  treap_t * a = treap_join( treap_new( _treap+0, ele_max ) );
  treap_t * b = treap_join( treap_new( _treap+1, ele_max ) );

  fd_asan_poison( pool+ele_max, (ulong)((scratch+SCRATCH_FOOTPRINT) - (uchar*)(pool+ele_max)) );
  for( ulong i=0UL; i<=ele_max; i++ ) {
    treap_seed( pool, ele_max, i );

    /* [0, i) in a, [i, ele_max) in b */
    for( ulong j=0UL; j<ele_max; j++ ) {
      ulong idx = pool_idx_acquire( pool );
      pool[ idx ].val = (schar)j;
      treap_idx_insert( j<i?a:b, idx, pool );
    }
    FD_TEST( treap_ele_cnt( a )==i         );
    FD_TEST( treap_ele_cnt( b )==ele_max-i );

    treap_t * merged = treap_merge( a, b, pool );

    FD_TEST( merged==a );
    FD_TEST( treap_ele_cnt( a )==ele_max );
    FD_TEST( treap_ele_cnt( b )==0UL     );
    FD_TEST( !treap_verify( merged, pool ) );

    for( ulong j=0UL; j<ele_max; j++ ) {
      treap_idx_remove( merged, j, pool );
      pool_idx_release( pool, j );
    }
  }

  /* Now distribute the nodes randomly between the two heaps */
  for( ulong i=0UL; i<100UL; i++ ) {
    treap_seed( pool, ele_max, fd_ulong_hash( i ) );

    for( ulong j=0UL; j<ele_max; j++ ) {
      ulong idx = pool_idx_acquire( pool );
      pool[ idx ].val = (schar)j;
      treap_idx_insert( fd_rng_uint_roll( rng, 2U )?a:b, idx, pool );
    }
    treap_t * merged = treap_merge( a, b, pool );

    FD_TEST( treap_ele_cnt( merged )==ele_max );
    FD_TEST( !treap_verify( merged, pool ) );

    for( ulong j=0UL; j<ele_max; j++ ) {
      treap_idx_remove( merged, j, pool );
      pool_idx_release( pool, j );
    }
  }

  /* Exercise the degenerate case when the internal stack fills up */
  for( ulong i=0UL; i<4000UL; i++ ) {
    for( ulong j=0UL; j<ele_max; j++ ) {
      ulong idx = pool_idx_acquire( pool );
      pool[ idx ].val = (schar)j;
      pool[ idx ].prio_cidx = (uchar)( (long)(schar)j + 128L );
      treap_idx_insert( fd_rng_uint_roll( rng, 4U )?a:b, idx, pool );
    }
    treap_t * merged = treap_merge( a, b, pool );

    FD_TEST( treap_ele_cnt( merged )==ele_max );
    FD_TEST( !treap_verify( merged, pool ) );

    for( ulong j=0UL; j<ele_max; j++ ) {
      treap_idx_remove( merged, j, pool );
      pool_idx_release( pool, j );
    }
  }

  fd_asan_unpoison( pool+ele_max, (ulong)((scratch+SCRATCH_FOOTPRINT) - (uchar*)(pool+ele_max)) );
  treap_delete( treap_leave( a    ) );
  treap_delete( treap_leave( b    ) );
  pool_delete ( pool_leave ( pool ) );
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong ele_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--max",  "", 64UL );
  ulong seed    = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed", "",  0UL );
  if( FD_UNLIKELY( ele_max>64UL ) ) FD_LOG_ERR(( "Test only supports ele_max up to 64" ));

  FD_LOG_NOTICE(( "Testing with --max %lu --seed %lu", ele_max, seed ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong align     = pool_align();
  ulong footprint = pool_footprint( ele_max );
  if( FD_UNLIKELY( (align>SCRATCH_ALIGN) | (footprint>SCRATCH_FOOTPRINT) ) )
    FD_LOG_ERR(( "Increase SCRATCH_ALIGN and/or SCRATCH_FOOTPRINT for this --max" ));

  ele_t * pool = pool_join( pool_new( scratch, ele_max ) );

  /* Test special values */

  FD_TEST( treap_idx_null      ()==255UL );
  FD_TEST( treap_ele_null      ()==NULL  );
  FD_TEST( treap_ele_null_const()==NULL  );

  /* Test address conversion */

  for( ulong i=0UL; i<256UL; i++ ) {
    if( i<255UL ) {

      ele_t *       e = &pool[ i ];
      ele_t const * f = e;

      FD_TEST( treap_idx     ( e, pool )==i ); FD_TEST( treap_idx           ( f, pool )==i );
      FD_TEST( treap_idx_fast( e, pool )==i ); FD_TEST( treap_idx_fast      ( f, pool )==i );
      FD_TEST( treap_ele     ( i, pool )==e ); FD_TEST( treap_ele_const     ( i, pool )==f );
      FD_TEST( treap_ele_fast( i, pool )==e ); FD_TEST( treap_ele_fast_const( i, pool )==f );

      FD_TEST( !treap_idx_is_null( i ) );
      FD_TEST( !treap_ele_is_null( e ) );
      FD_TEST( !treap_ele_is_null( f ) );

    } else {

      ele_t *       e = NULL;
      ele_t const * f = NULL;

      FD_TEST( treap_idx( e, pool )==i ); FD_TEST( treap_idx      ( f, pool )==i );
      FD_TEST( treap_ele( i, pool )==e ); FD_TEST( treap_ele_const( i, pool )==f );

      FD_TEST( treap_idx_is_null( i ) );
      FD_TEST( treap_ele_is_null( e ) );
      FD_TEST( treap_ele_is_null( f ) );

    }
  }

  /* Test seed */

  treap_seed( pool, ele_max, seed );
  for( ulong i=0; i<ele_max; i++ ) FD_TEST( ((uint)pool[i].prio_cidx)<255U );

  /* Test align and footprint */

  align = treap_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  FD_TEST( !treap_footprint( 256UL ) ); /* Bigger than index representation */
  footprint = treap_footprint( ele_max );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  /* Test new and join */

  treap_t _treap[1];
  void * shmem = (void *)_treap;

  FD_TEST( !treap_new( NULL,        ele_max ) );
  FD_TEST( !treap_new( (void *)1UL, ele_max ) );
  FD_TEST( !treap_new( shmem,       256UL   ) );
  void * shtreap = treap_new( shmem, ele_max );
  FD_TEST( shtreap );

  FD_TEST( !treap_join( NULL        ) );
  FD_TEST( !treap_join( (void *)1UL ) );
  treap_t * treap = treap_join( shtreap );
  FD_TEST( treap );

  /* Do a bunch of operations, testing integrity as we go */

  ulong val_pmap = 0UL;
  ulong node_idx[ 64UL ]; ulong node_cnt = 0UL;
  int   free_val[ 64UL ]; ulong free_cnt = ele_max;
  for( ulong i=0UL; i<ele_max; i++ ) free_val[ i ] = (int)i;

  for( ulong iter=0UL; iter<10000000UL; iter++ ) {
    FD_TEST( !treap_verify( treap, pool ) );

    uint r  = fd_rng_uint( rng );
    int  op = (int)( r & 3U ); r >>= 2;
    switch( op ) {

    case 0: { /* Test query */
      FD_TEST( treap_ele_max( treap )==ele_max  );
      FD_TEST( treap_ele_cnt( treap )==node_cnt );
      int q = ((int)fd_rng_uint_roll( rng, 2U+(uint)ele_max ))-1; /* q in [-1,ele_max] */
      ulong idx = treap_idx_query( treap, (schar)q, pool );
      if( (q<0) | (q>=(int)ele_max) ) FD_TEST( treap_idx_is_null( idx ) );
      else if( !(val_pmap & (1UL << q)) ) FD_TEST( treap_idx_is_null( idx ) );
      else                                FD_TEST( (idx<ele_max) && q==(int)pool[idx].val );
      FD_TEST( treap_idx( treap_ele_query      ( treap, (schar)q, pool ), pool )==idx );
      FD_TEST( treap_idx( treap_ele_query_const( treap, (schar)q, pool ), pool )==idx );
      break;
    }

    case 1: { /* Test insert */
      if( !free_cnt ) break;
      ulong j   = (ulong)fd_rng_uint_roll( rng, (uint)free_cnt );
      int   val = free_val[ j ];

      ulong idx = pool_idx_acquire( pool );
      pool[ idx ].val = (schar)val;
      if( (r & 1U) ) FD_TEST( treap_idx_insert( treap, idx,          pool )==treap );
      else           FD_TEST( treap_ele_insert( treap, &pool[ idx ], pool )==treap );

      val_pmap |= (1UL << val);
      node_idx[ node_cnt++ ] = idx;
      free_val[ j          ] = free_val[ --free_cnt ];
      break;
    }

    case 2: { /* Test remove */
      if( !node_cnt ) break;
      ulong j   = (ulong)fd_rng_uint_roll( rng, (uint)node_cnt );
      ulong idx = node_idx[ j ];

      if( (r & 1U) ) FD_TEST( treap_idx_remove( treap, idx,          pool )==treap );
      else           FD_TEST( treap_ele_remove( treap, &pool[ idx ], pool )==treap );
      int val = (int)pool[ idx ].val;
      pool_idx_release( pool, idx );

      val_pmap &= ~(1UL << val);
      node_idx[ j          ] = node_idx[ --node_cnt ];
      free_val[ free_cnt++ ] = val;
      break;
    }

    case 3: {
      if( (r & 1U) ) { /* Test forward iteration */
        ulong iter_pmap = val_pmap;
        for( treap_fwd_iter_t iter = treap_fwd_iter_init( treap, pool );
             !treap_fwd_iter_done( iter );
             iter = treap_fwd_iter_next( iter, pool ) ) {
          ulong idx = treap_fwd_iter_idx( iter );

          int val = (int)pool[ idx ].val;
          FD_TEST( iter_pmap && val==fd_ulong_find_lsb( iter_pmap ) );
          iter_pmap = fd_ulong_pop_lsb( iter_pmap );

          FD_TEST( treap_fwd_iter_ele      ( iter, pool )==&pool[idx] );
          FD_TEST( treap_fwd_iter_ele_const( iter, pool )==&pool[idx] );
        }
      } else { /* Test reverse iteration */
        ulong iter_pmap = val_pmap;
        for( treap_rev_iter_t iter = treap_rev_iter_init( treap, pool );
             !treap_rev_iter_done( iter );
             iter = treap_rev_iter_next( iter, pool ) ) {
          ulong idx = treap_rev_iter_idx( iter );

          int   val = (int)pool[ idx ].val;
          FD_TEST( iter_pmap && val==fd_ulong_find_msb( iter_pmap ) );
          iter_pmap &= ~(1UL<<val);

          FD_TEST( treap_rev_iter_ele      ( iter, pool )==&pool[idx] );
          FD_TEST( treap_rev_iter_ele_const( iter, pool )==&pool[idx] );
        }
      }
      break;
    }

    default:
      break;
    }
  }

  FD_TEST( !treap_verify( treap, pool ) );

  /* Test leave */

  FD_TEST( !treap_leave( NULL ) );
  FD_TEST( treap_leave( treap )==shtreap );

  /* Test delete */

  FD_TEST( !treap_delete( NULL        ) );
  FD_TEST( !treap_delete( (void *)1UL ) );
  FD_TEST( treap_delete( shtreap )==(void *)shmem );

  pool_delete( pool_leave( pool ) );

  test_merge( rng );

  fd_rng_delete( fd_rng_leave( rng ) );

  test_iteration_all();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

