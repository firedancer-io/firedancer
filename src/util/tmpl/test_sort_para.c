#include "../fd_util.h"

#define TYPE float
#define MAX  65536UL

#define SORT_NAME        mysort
#define SORT_KEY_T       TYPE
#define SORT_BEFORE(a,b) ((a)<(b))
#define SORT_PARALLEL    1
#include "fd_sort.c"

static TYPE *
shuffle( fd_rng_t *   rng,
         TYPE *       y,
         TYPE const * x,
         ulong        cnt ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    y[i] = x[i];
    ulong j  = fd_rng_ulong( rng ) % (i+1UL);
    TYPE yi = y[i];
    TYPE yj = y[j];
    y[i] = yj;
    y[j] = yi;
  }
  return y;
}

static TYPE ref[ MAX ];
static TYPE tst[ MAX ];
static TYPE tmp[ MAX ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong iter_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max", NULL, (ulong)1e4 );
  ulong diag_int = fd_env_strip_cmdline_ulong( &argc, &argv, "--diag-int", NULL, (ulong)1e2 );

  ulong thread_cnt = fd_tile_cnt();

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Creating tpool from all %lu tiles", thread_cnt ));

  static uchar _tpool[ FD_TPOOL_FOOTPRINT( FD_TILE_MAX ) ] __attribute__((aligned(FD_TPOOL_ALIGN)));

  fd_tpool_t * tpool = fd_tpool_init( _tpool, thread_cnt, 0UL ); /* logs details */
  if( FD_UNLIKELY( !tpool ) ) FD_LOG_ERR(( "fd_tpool_init failed" ));

  for( ulong thread_idx=1UL; thread_idx<thread_cnt; thread_idx++ )
    if( FD_UNLIKELY( !fd_tpool_worker_push( tpool, thread_idx ) ) ) FD_LOG_ERR(( "fd_tpool_worker_push failed" ));

  FD_LOG_NOTICE(( "Running (--iter-max %lu --diag-int %lu)", iter_max, diag_int ));

  TYPE * out;

  ulong diag_rem = 0UL;
  for( ulong iter_idx=0UL; iter_idx<iter_max; iter_idx++ ) {
    ulong t0 = fd_rng_ulong_roll( rng, thread_cnt );
    ulong t1 = fd_rng_ulong_roll( rng, thread_cnt ); fd_swap_if( t1<t0, t0, t1 );
    t1++;

    ulong cnt  = fd_rng_ulong_roll( rng, MAX+1UL );
    ulong zcnt = fd_rng_ulong_roll( rng, cnt+1UL );

    if( FD_UNLIKELY( !diag_rem ) ) {
      FD_LOG_NOTICE(( "Iter %lu of %lu: threads [%lu,%lu) cnt %lu zcnt %lu", iter_idx, iter_max, t0, t1, cnt, zcnt ));
      diag_rem = diag_int;
    }
    diag_rem--;

    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)i;

    /* Monotonically increasing unique */

    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    FD_TEST( mysort_inplace_para( tpool,t0,t1, tst, cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    out = mysort_stable_fast_para( tpool,t0,t1, tst, cnt, tmp );
    FD_TEST( (out==tst || out==tmp) && !memcmp( out, ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    FD_TEST( mysort_stable_para( tpool,t0,t1, tst, cnt, tmp )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

#   if FD_HAS_ALLOCA
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    FD_TEST( mysort_fast_para( tpool,t0,t1, tst, cnt, tmp, iter_idx, 0 )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
    FD_TEST( mysort_fast_para( tpool,t0,t1, tst, cnt, tmp, iter_idx, 1 )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
#   endif

    /* Monotonically decreasing unique */

    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    FD_TEST( mysort_inplace_para( tpool,t0,t1, tst, cnt )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    out = mysort_stable_fast_para( tpool,t0,t1, tst, cnt, tmp );
    FD_TEST( (out==tst || out==tmp) && !memcmp( out, ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    FD_TEST( mysort_stable_para( tpool,t0,t1, tst, cnt, tmp )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

#   if FD_HAS_ALLOCA
    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    FD_TEST( mysort_fast_para( tpool,t0,t1, tst, cnt, tmp, iter_idx, 0 )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

    for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
    FD_TEST( mysort_fast_para( tpool,t0,t1, tst, cnt, tmp, iter_idx, 1 )==tst && !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
#   endif

    /* Unique shuffled */

#   if FD_HAS_ALLOCA
#   define TEST_ALL_PARA_SORTS                                                                             \
    FD_TEST( mysort_inplace_para( tpool,t0,t1, shuffle( rng, tst, ref, cnt ), cnt )==tst &&                \
             !memcmp( tst, ref, cnt*sizeof(TYPE) ) );                                                      \
                                                                                                           \
    out = mysort_stable_fast_para( tpool,t0,t1, shuffle( rng, tst, ref, cnt ), cnt, tmp );                 \
    FD_TEST( (out==tst || out==tmp) && !memcmp( out, ref, cnt*sizeof(TYPE) ) );                            \
                                                                                                           \
    FD_TEST( mysort_stable_para( tpool,t0,t1, shuffle( rng, tst, ref, cnt ), cnt, tmp )==tst &&            \
             !memcmp( tst, ref, cnt*sizeof(TYPE) ) );                                                      \
                                                                                                           \
    FD_TEST( mysort_fast_para( tpool,t0,t1, shuffle( rng, tst, ref, cnt ), cnt, tmp, iter_idx, 0 )==tst && \
             !memcmp( tst, ref, cnt*sizeof(TYPE) ) );                                                      \
                                                                                                           \
    FD_TEST( mysort_fast_para( tpool,t0,t1, shuffle( rng, tst, ref, cnt ), cnt, tmp, iter_idx, 1 )==tst && \
             !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
#   else
#   define TEST_ALL_PARA_SORTS                                                                  \
    FD_TEST( mysort_inplace_para( tpool,t0,t1, shuffle( rng, tst, ref, cnt ), cnt )==tst &&     \
             !memcmp( tst, ref, cnt*sizeof(TYPE) ) );                                           \
                                                                                                \
    out = mysort_stable_fast_para( tpool,t0,t1, shuffle( rng, tst, ref, cnt ), cnt, tmp );      \
    FD_TEST( (out==tst || out==tmp) && !memcmp( out, ref, cnt*sizeof(TYPE) ) );                 \
                                                                                                \
    FD_TEST( mysort_stable_para( tpool,t0,t1, shuffle( rng, tst, ref, cnt ), cnt, tmp )==tst && \
             !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
#   endif

    TEST_ALL_PARA_SORTS

    /* Random permutation of i 0s and cnt-i 1s */

    for( ulong i=0UL;  i<zcnt; i++ ) ref[i] = (TYPE)0;
    for( ulong i=zcnt; i< cnt; i++ ) ref[i] = (TYPE)1;

    TEST_ALL_PARA_SORTS

    /* Non-unique shuffled */

    for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)fd_rng_ulong_roll( rng, cnt );
    mysort_inplace( ref, cnt );

    TEST_ALL_PARA_SORTS

#   undef TEST_ALL_PARA_SORTS

  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  /* Note: fini automatically pops all worker threads */

  fd_tpool_fini( tpool ); /* logs details */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
