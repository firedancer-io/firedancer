#include "../fd_util.h"

#define TYPE float
#define MAX  1024UL

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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong thread_cnt = fd_tile_cnt();

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Creating tpool from all %lu tiles", thread_cnt ));

  static uchar _tpool[ FD_TPOOL_FOOTPRINT( FD_TILE_MAX ) ] __attribute__((aligned(FD_TPOOL_ALIGN)));

  fd_tpool_t * tpool = fd_tpool_init( _tpool, thread_cnt ); /* logs details */
  if( FD_UNLIKELY( !tpool ) ) FD_LOG_ERR(( "fd_tpool_init failed" ));

  for( ulong thread_idx=1UL; thread_idx<thread_cnt; thread_idx++ )
    if( FD_UNLIKELY( !fd_tpool_worker_push( tpool, thread_idx, NULL, 0UL ) ) ) FD_LOG_ERR(( "fd_tpool_worker_push failed" ));

  FD_LOG_NOTICE(( "Running" ));

  TYPE ref[ MAX ];
  TYPE tst[ MAX ];

  for( ulong t0=0UL; t0<thread_cnt; t0++ ) {
    for( ulong t1=t0+1UL; t1<=thread_cnt; t1++ ) {

      for( ulong cnt=0UL; cnt<256UL; cnt++ ) {

        for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)i;

        /* Monotonically increasing unique */

        for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)i;
        FD_TEST( mysort_inplace_para( tpool,t0,t1, tst, cnt )==tst &&
                 !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
        /* Monotonically decreasing unique */

        for( ulong i=0UL; i<cnt; i++ ) tst[i] = (TYPE)(cnt-i-1UL);
        FD_TEST( mysort_inplace_para( tpool,t0,t1, tst, cnt )==tst &&
                 !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

        /* Unique shuffled */

        for( ulong trial=0UL; trial<10UL; trial++ )
          FD_TEST( mysort_inplace_para( tpool,t0,t1, shuffle( rng, tst, ref, cnt ), cnt )==tst &&
                   !memcmp( tst, ref, cnt*sizeof(TYPE) ) );

        /* Random permutation with i 0s, cnt-i 1s for i in [0,cnt] */

        for( ulong i=0UL; i<cnt+1UL; i++ ) {
          for( ulong j=0UL; j<i;   j++ ) ref[j] = (TYPE)0;
          for( ulong j=i;   j<cnt; j++ ) ref[j] = (TYPE)1;
          for( ulong trial=0UL; trial<10UL; trial++ )
            FD_TEST( mysort_inplace_para( tpool,t0,t1, shuffle( rng, tst, ref, cnt ), cnt )==tst &&
                     !memcmp( tst, ref, cnt*sizeof(TYPE) ) );
        }

      }

      for( ulong trial=0UL; trial<1000UL; trial++ ) {
        ulong cnt = fd_rng_ulong( rng ) % (MAX+1UL);
        for( ulong i=0UL; i<cnt; i++ ) ref[i] = (TYPE)(fd_rng_ulong( rng ) % cnt);
        mysort_inplace( ref, cnt );
        FD_TEST( !memcmp( mysort_inplace_para( tpool,t0,t1, shuffle( rng, tst, ref, cnt ), cnt ), ref, cnt*sizeof(TYPE) ) );
      }

      FD_LOG_NOTICE(( "sorts distributed over main thread and tpool threads [%lu,%lu): pass", t0+1UL, t1 ));
    }
  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  /* Note: fini automatically pops all worker threads */

  fd_tpool_fini( tpool ); /* logs details */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
