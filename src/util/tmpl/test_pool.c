#include "../fd_util.h"

#define HAS_SENTINEL 1

struct myele {
  ushort pool_next;
  ushort val;
};

typedef struct myele myele_t;

#define POOL_NAME     mypool
#define POOL_T        myele_t
#define POOL_NEXT     pool_next
#define POOL_IDX_T    ushort
#define POOL_SENTINEL HAS_SENTINEL
#define POOL_MAGIC    0x1UL
#include "fd_pool.c"

#define ACQUIRED_MAX (1024UL)
static ushort acquired_idx[ ACQUIRED_MAX ];
static ulong  acquired_cnt = 0UL;

#define SCRATCH_ALIGN     (128UL)
#define SCRATCH_FOOTPRINT (1024UL)
static uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# if HAS_SENTINEL
  FD_TEST( !mypool_footprint( 0UL ) );       /* Pools with a sentinel need at least one element */
# else
  FD_TEST(  mypool_footprint( 0UL ) );       /* Zero element pools fine otherwise */
# endif
  FD_TEST( !mypool_footprint( 1UL<<16   ) ); /* Overflow POOL_IDX_NULL */
  FD_TEST( !mypool_footprint( ULONG_MAX ) ); /* Overflow */

  ulong scratch_max = mypool_max_for_footprint( SCRATCH_FOOTPRINT );
  FD_TEST( mypool_footprint( scratch_max     )<=SCRATCH_FOOTPRINT );
  FD_TEST( mypool_footprint( scratch_max+1UL )> SCRATCH_FOOTPRINT );

  ulong max = fd_env_strip_cmdline_ulong( &argc, &argv, "--max", NULL, scratch_max );
  if( FD_UNLIKELY( max>scratch_max || max>ACQUIRED_MAX ) )  {
    FD_LOG_WARNING(( "skip: increase scratch_max and/or ACQUIRED_MAX to support this level of --max" ));
    return 0;
  }
  if( FD_UNLIKELY( (mypool_align()>SCRATCH_ALIGN) | (mypool_footprint( max )>SCRATCH_FOOTPRINT) ) ) {
    FD_LOG_WARNING(( "skip: adjust scratch region and footprint to support this level of --max" ));
    return 0;
  }
  FD_LOG_NOTICE(( "--max %lu", max ));

  FD_LOG_NOTICE(( "Testing construction" ));

  ulong align = mypool_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  ulong footprint = mypool_footprint( max );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  FD_TEST( !mypool_new( NULL,        max       ) ); /* NULL       shmem */
  FD_TEST( !mypool_new( (void *)1UL, max       ) ); /* misaligned shmem */
# if HAS_SENTINEL
  FD_TEST( !mypool_new( scratch,     0UL       ) ); /* Zero elements with a sentinel */
# endif
  FD_TEST( !mypool_new( scratch,     1UL<<16   ) ); /* Overflow POOL_IDX_NULL */
  FD_TEST( !mypool_new( scratch,     ULONG_MAX ) ); /* Overflow */
  void * shpool = mypool_new ( scratch, max ); FD_TEST( shpool );

  FD_TEST( !mypool_join( NULL        ) ); /* NULL       shpool */
  FD_TEST( !mypool_join( (void *)1UL ) ); /* misaligned shpool */
  /* bad magic test below */
  myele_t * pool = mypool_join( shpool ); FD_TEST( pool );

  FD_LOG_NOTICE(( "Testing special values" ));

  FD_TEST( mypool_idx_null      ( pool )==(ulong)USHORT_MAX );
  FD_TEST( mypool_ele_null      ( pool )==NULL              );
  FD_TEST( mypool_ele_null_const( pool )==NULL              );

# if HAS_SENTINEL
  FD_TEST( mypool_idx_sentinel      ( pool )==0UL  );
  FD_TEST( mypool_ele_sentinel      ( pool )==pool );
  FD_TEST( mypool_ele_sentinel_const( pool )==pool );
# endif

  FD_LOG_NOTICE(( "Testing conversions" ));

  FD_TEST( !mypool_ele_test( pool, (myele_t *)(((ulong)pool)+1UL) ) ); /* misaligned */

  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong     idx = fd_rng_ulong_roll( rng, max+2UL );
    myele_t * ele = &pool[ idx ];
    if( idx==(max+1UL) ) {
      idx = mypool_idx_null( pool );
      ele = NULL;
    }
    if( idx==max ) { /* Note: assumes max!=IDX_NULL */
      FD_TEST( !mypool_idx_test( pool, idx )       );
      FD_TEST( !mypool_ele_test( pool, ele )       );
    } else {
      FD_TEST(  mypool_idx_test ( pool, idx )      );
      FD_TEST(  mypool_ele_test ( pool, ele )      );
      FD_TEST(  mypool_idx      ( pool, ele )==idx );
      FD_TEST(  mypool_ele      ( pool, idx )==ele );
      FD_TEST(  mypool_ele_const( pool, idx )==ele );
    }
  }

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( mypool_max ( pool )==max );
# if HAS_SENTINEL
  FD_TEST( mypool_free( pool )==max-1UL );
  FD_TEST( mypool_used( pool )==1UL     );
# else
  FD_TEST( mypool_free( pool )==max );
  FD_TEST( mypool_used( pool )==0UL );
# endif

  FD_LOG_NOTICE(( "Testing operations" ));

  for( ulong iter=0UL; iter<100000000UL; iter++ ) {

    /* Randomly pick an operation to do */

    uint r = fd_rng_uint( rng );

    int op = (int)(r & 3U); r>>=2;

    switch( op ) {
    case 0: /* acquire by idx */
      if( mypool_free( pool ) ) {
        ulong idx = mypool_idx_acquire( pool );
        FD_TEST( mypool_idx_test( pool, idx ) && idx<max );
#       if FD_HAS_SENTINEL
        FD_TEST( !idx );
#       endif
        for( ulong acq=0UL; acq<acquired_cnt; acq++ ) FD_TEST( idx!=(ulong)acquired_idx[ acq ] );
        acquired_idx[ acquired_cnt++ ] = (ushort)idx;
      }
      break;

    case 1: /* release by idx */
      if( acquired_cnt ) {
        ulong acq = fd_rng_ulong_roll( rng, acquired_cnt );
        mypool_idx_release( pool, (ulong)acquired_idx[ acq ] );
        acquired_idx[ acq ] = acquired_idx[ --acquired_cnt ];
      }
      break;

    case 2: /* acquire by ele */
      if( mypool_free( pool ) ) {
        myele_t * ele = mypool_ele_acquire( pool );
        FD_TEST( mypool_ele_test( pool, ele ) && ele );
#       if FD_HAS_SENTINEL
        FD_TEST( ele!=pool );
#       endif
        ulong idx = mypool_idx( pool, ele );
        for( ulong acq=0UL; acq<acquired_cnt; acq++ ) FD_TEST( idx!=(ulong)acquired_idx[ acq ] );
        acquired_idx[ acquired_cnt++ ] = (ushort)mypool_idx( pool, ele );
      }
      break;

    case 3: /* release by ele */
      if( acquired_cnt ) {
        ulong acq = fd_rng_ulong_roll( rng, acquired_cnt );
        mypool_ele_release( pool, pool + acquired_idx[ acq ] );
        acquired_idx[ acq ] = acquired_idx[ --acquired_cnt ];
      }
      break;

    default: /* never get here */
      break;
    }

    FD_TEST( (mypool_free( pool ) + mypool_used( pool ))==max );
#   if HAS_SENTINEL
    FD_TEST( mypool_used( pool )==(acquired_cnt+1UL) );
#   else
    FD_TEST( mypool_used( pool )==acquired_cnt       );
#   endif
  }

  FD_TEST( !mypool_leave( NULL ) ); /* NULL join */
  FD_TEST( mypool_leave( pool )==shpool );

  FD_TEST( !mypool_delete( NULL        ) ); /* NULL shpool */
  FD_TEST( !mypool_delete( (void *)1UL ) ); /* misaligned shpool */

  FD_TEST( mypool_delete( shpool )==(void *)scratch );

  FD_TEST( !mypool_delete( scratch ) ); /* Bad magic */
  FD_TEST( !mypool_join  ( scratch ) ); /* Bad magic */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

