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
#define SCRATCH_FOOTPRINT (1024UL)
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

  /* Test accessors */

  FD_TEST( treap_ele_max( treap )==ele_max );
  FD_TEST( treap_ele_cnt( treap )==0UL     );

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
      if( (r & 1U) ) treap_idx_insert( treap, idx,          pool );
      else           treap_ele_insert( treap, &pool[ idx ], pool );

      val_pmap |= (1UL << val);
      node_idx[ node_cnt++ ] = idx;
      free_val[ j          ] = free_val[ --free_cnt ];
      break;
    }

    case 2: { /* Test remove */
      if( !node_cnt ) break;
      ulong j   = (ulong)fd_rng_uint_roll( rng, (uint)node_cnt );
      ulong idx = node_idx[ j ];

      if( (r & 1U) ) treap_idx_remove( treap, idx,          pool );
      else           treap_ele_remove( treap, &pool[ idx ], pool );
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

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

