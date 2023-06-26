#include "../fd_util.h"

#define CIDX_T uchar
#define VAL_T  schar

struct ele {
  CIDX_T left_cidx;
  CIDX_T right_cidx;
  VAL_T  val;
};

typedef struct ele ele_t;

#define POOL_NAME  pool
#define POOL_T     ele_t
#define POOL_IDX_T CIDX_T
#define POOL_NEXT  left_cidx
#include "fd_pool.c"

#define HEAP_NAME       heap
#define HEAP_T          ele_t
#define HEAP_LT(e0,e1)  (((int)((e0)->val)) < ((int)((e1)->val)))
#define HEAP_IDX_T      CIDX_T
#define HEAP_LEFT       left_cidx
#define HEAP_RIGHT      right_cidx
#define HEAP_IMPL_STYLE 0
#include "fd_heap.c"

#define SCRATCH_ALIGN     (128UL)
#define SCRATCH_FOOTPRINT (1024UL)
static uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

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

  FD_TEST( heap_idx_null      ()==255UL );
  FD_TEST( heap_ele_null      ()==NULL  );
  FD_TEST( heap_ele_null_const()==NULL  );

  /* Test address conversion */

  for( ulong i=0UL; i<256UL; i++ ) {
    if( i<255UL ) {

      ele_t *       e = &pool[ i ];
      ele_t const * f = e;

      FD_TEST( heap_idx     ( e, pool )==i ); FD_TEST( heap_idx           ( f, pool )==i );
      FD_TEST( heap_idx_fast( e, pool )==i ); FD_TEST( heap_idx_fast      ( f, pool )==i );
      FD_TEST( heap_ele     ( i, pool )==e ); FD_TEST( heap_ele_const     ( i, pool )==f );
      FD_TEST( heap_ele_fast( i, pool )==e ); FD_TEST( heap_ele_fast_const( i, pool )==f );

      FD_TEST( !heap_idx_is_null( i ) );
      FD_TEST( !heap_ele_is_null( e ) );
      FD_TEST( !heap_ele_is_null( f ) );

    } else {

      ele_t *       e = NULL;
      ele_t const * f = NULL;

      FD_TEST( heap_idx( e, pool )==i ); FD_TEST( heap_idx      ( f, pool )==i );
      FD_TEST( heap_ele( i, pool )==e ); FD_TEST( heap_ele_const( i, pool )==f );

      FD_TEST( heap_idx_is_null( i ) );
      FD_TEST( heap_ele_is_null( e ) );
      FD_TEST( heap_ele_is_null( f ) );

    }
  }

  /* Test align and footprint */

  align = heap_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  FD_TEST( !heap_footprint( 256UL ) ); /* Bigger than index representation */
  footprint = heap_footprint( ele_max );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  /* Test new and join */

  heap_t _heap[1];
  void * shmem = (void *)_heap;

  FD_TEST( !heap_new( NULL,        ele_max ) );
  FD_TEST( !heap_new( (void *)1UL, ele_max ) );
  FD_TEST( !heap_new( shmem,       256UL   ) );
  void * shheap = heap_new( shmem, ele_max );
  FD_TEST( shheap );

  FD_TEST( !heap_join( NULL        ) );
  FD_TEST( !heap_join( (void *)1UL ) );
  heap_t * heap = heap_join( shheap );
  FD_TEST( heap );

  /* Do a bunch of operations, testing integrity as we go */

  ulong pmap = 0UL;

  for( ulong iter=0UL; iter<10000000UL; iter++ ) {
    FD_TEST( !heap_verify( heap, pool ) );

    uint r  = fd_rng_uint( rng );
    int  op = (int)( r & 3U ); r >>= 2;
    switch( op ) {

    default: { /* Test peek_min */
      FD_TEST( heap_ele_max( heap )==ele_max                        );
      FD_TEST( heap_ele_cnt( heap )==(ulong)fd_ulong_popcnt( pmap ) );
      if( FD_UNLIKELY( !pmap ) ) {
        FD_TEST( heap_idx_is_null( heap_idx_peek_min( heap ) ) );
        FD_TEST( !heap_ele_peek_min      ( heap, pool ) );
        FD_TEST( !heap_ele_peek_min_const( heap, pool ) );
      } else {
        ulong idx = heap_idx_peek_min( heap );
        FD_TEST( idx<ele_max );
        FD_TEST( pool[ idx ].val==fd_ulong_find_lsb( pmap ) );
        FD_TEST( heap_idx( heap_ele_peek_min      ( heap, pool ), pool )==idx );
        FD_TEST( heap_idx( heap_ele_peek_min_const( heap, pool ), pool )==idx );
      }
      break;
    }

    case 1: { /* Test insert */
      ulong fmap = ~pmap; /* bit field of values not in heap currently */
      if( !fmap ) break;  /* all values currently in heap */
      /* select a free value uniform at random */
      int rot = (int)(r & 63U); r >>= 6;
      int val = (rot + fd_ulong_find_lsb( fd_ulong_rotate_right( fmap, rot ) )) & 63;
      if( ((ulong)val) >= ele_max ) break;

      ulong idx = pool_idx_acquire( pool );
      pool[ idx ].val = (schar)val;
      if( (r & 1U) ) FD_TEST( heap_idx_insert( heap, idx,          pool )==heap );
      else           FD_TEST( heap_ele_insert( heap, &pool[ idx ], pool )==heap );

      pmap |= (1UL << val);
      break;
    }

    case 2: { /* Test remove_min */
      if( !pmap ) break;

      ulong idx = heap_idx_peek_min( heap );
      FD_TEST( idx<ele_max );
      if( (r & 1U) ) FD_TEST( heap_idx_remove_min( heap, pool )==heap );
      else           FD_TEST( heap_ele_remove_min( heap, pool )==heap );
      pool_idx_release( pool, idx );

      pmap = fd_ulong_pop_lsb( pmap );
      break;
    }

    }
  }

  FD_TEST( !heap_verify( heap, pool ) );

  /* Test leave */

  FD_TEST( !heap_leave( NULL ) );
  FD_TEST( heap_leave( heap )==shheap );

  /* Test delete */

  FD_TEST( !heap_delete( NULL        ) );
  FD_TEST( !heap_delete( (void *)1UL ) );
  FD_TEST( heap_delete( shheap )==(void *)shmem );

  pool_delete( pool_leave( pool ) );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

