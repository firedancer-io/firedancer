#include "../fd_vinyl.h"

FD_STATIC_ASSERT( FD_VINYL_COMP_ALIGN    ==32UL, unit_test );
FD_STATIC_ASSERT( FD_VINYL_COMP_FOOTPRINT==32UL, unit_test );

FD_STATIC_ASSERT( FD_VINYL_COMP_ALIGN    ==alignof(fd_vinyl_comp_t), unit_test );
FD_STATIC_ASSERT( FD_VINYL_COMP_FOOTPRINT==sizeof (fd_vinyl_comp_t), unit_test );

FD_STATIC_ASSERT( FD_VINYL_COMP_QUOTA_MAX==65535UL, unit_test );

FD_STATIC_ASSERT( FD_VINYL_CQ_MAGIC==0xfd3a7352dc03a6c0UL, unit_test );

static FD_FOR_ALL_BEGIN( test_tile, 1L ) {
  fd_vinyl_cq_t * cq     = (fd_vinyl_cq_t *)arg[0];
  long            t_stop = (long)           arg[1];

  static fd_vinyl_comp_t oob_comp[2];

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)(tpool_t0+1UL), 0UL ) );

  if( !tpool_t0 ) { /* Comp sender */

    memset( oob_comp, 0, 2*sizeof(fd_vinyl_comp_t) ); /* seq should be !=1 before sender sends to it and receiver expects it */

    FD_LOG_NOTICE(( "Starting transmitter" ));

    for(;;) {

      if( FD_UNLIKELY( fd_log_wallclock() > t_stop ) ) break;

      ulong val = fd_rng_ulong( rng );

      val += (ulong)!val; /* Use req_id==0 as termination for receivers in this test */

      ulong req_id    =         val++;
      ulong link_id   =         val++;
      int   err       = (int)  (val++);
      ulong batch_cnt = (ulong)(val++);
      ulong fail_cnt  = (ulong)(val++);
      ulong quota_rem = (ulong)(val++);

      fd_vinyl_cq_send( cq, NULL, req_id, link_id, err, batch_cnt, fail_cnt, quota_rem );

    }

    /* Send terminate */

    fd_vinyl_cq_send( cq, NULL, 0UL, 0UL, 0, 0UL, 0UL, 0UL );

    /* Do some oob and no-op sending */

    fd_vinyl_cq_send( NULL, NULL,         1UL, 2UL, 3, 4UL, 5UL, 6UL ); /* no-op */
    fd_vinyl_cq_send( NULL, &oob_comp[0], 2UL, 3UL, 4, 5UL, 6UL, 7UL ); /* to oob_comp 0 (no cq provided) */
    fd_vinyl_cq_send( cq,   &oob_comp[1], 3UL, 4UL, 5, 6UL, 7UL, 8UL ); /* to oob_comp 1 (cq override) */

  } else {

    FD_LOG_NOTICE(( "Starting receiver %lu", tpool_t0-1UL ));

    ulong seq = fd_vinyl_cq_seq( cq );

    for(;;) {

      fd_vinyl_comp_t comp[1];
      long diff = fd_vinyl_cq_recv( cq, seq, comp );

      if( FD_LIKELY( diff ) ) {
        if( FD_UNLIKELY( diff<0L ) ) {
          FD_LOG_WARNING(( "Receiver %lu overrun; resynchronizing", tpool_t0-1UL ));
          seq = fd_vinyl_cq_seq( cq );
        }
        FD_SPIN_PAUSE();
        continue;
      }

      ulong val = comp->req_id;
      if( FD_UNLIKELY( !val ) ) break;

      FD_TEST( comp->req_id    ==         val ); val++;
      FD_TEST( comp->link_id   ==         val ); val++;
      FD_TEST( comp->err       == (short) val ); val++;
      FD_TEST( comp->batch_cnt == (ushort)val ); val++;
      FD_TEST( comp->fail_cnt  == (ushort)val ); val++;
      FD_TEST( comp->quota_rem == (ushort)val ); val++;

      seq++;
    }

    ulong volatile * _seq;

    /* Wait to receive oob_comp 0 */

    _seq = &oob_comp[0].seq; while( !_seq[0] ) FD_SPIN_PAUSE();

    FD_TEST( oob_comp[0].req_id    ==         2UL );
    FD_TEST( oob_comp[0].link_id   ==         3UL );
    FD_TEST( oob_comp[0].err       == (schar) 4UL );
    FD_TEST( oob_comp[0].batch_cnt == (ushort)5UL );
    FD_TEST( oob_comp[0].fail_cnt  == (ushort)6UL );
    FD_TEST( oob_comp[0].quota_rem == (ushort)7UL );

    /* Wait to receive oob_comp 1 */

    _seq = &oob_comp[1].seq; while( !_seq[0] ) FD_SPIN_PAUSE();

    FD_TEST( oob_comp[1].req_id    ==         3UL );
    FD_TEST( oob_comp[1].link_id   ==         4UL );
    FD_TEST( oob_comp[1].err       == (schar) 5UL );
    FD_TEST( oob_comp[1].batch_cnt == (ushort)6UL );
    FD_TEST( oob_comp[1].fail_cnt  == (ushort)7UL );
    FD_TEST( oob_comp[1].quota_rem == (ushort)8UL );

  }

  fd_rng_delete( fd_rng_leave( rng ) );

} FD_FOR_ALL_END

#define SHMEM_ALIGN     (128)
#define SHMEM_FOOTPRINT (1UL<<20)

static uchar shmem[ SHMEM_FOOTPRINT ] __attribute__((aligned(SHMEM_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong comp_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--comp-cnt", NULL, 8192UL  );

  FD_LOG_NOTICE(( "Testing (--comp-cnt %lu)", comp_cnt ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong thread_cnt = fd_tile_cnt();

  FD_LOG_NOTICE(( "Creating tpool from all %lu tiles", thread_cnt ));

  static uchar _tpool[ FD_TPOOL_FOOTPRINT( FD_TILE_MAX ) ] __attribute__((aligned(FD_TPOOL_ALIGN)));

  fd_tpool_t * tpool = fd_tpool_init( _tpool, thread_cnt, 0UL ); /* logs details */
  if( FD_UNLIKELY( !tpool ) ) FD_LOG_ERR(( "fd_tpool_init failed" ));

  for( ulong thread_idx=1UL; thread_idx<thread_cnt; thread_idx++ )
    if( FD_UNLIKELY( !fd_tpool_worker_push( tpool, thread_idx ) ) ) FD_LOG_ERR(( "fd_tpool_worker_push failed" ));

  ulong align = fd_vinyl_cq_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  FD_TEST( !fd_vinyl_cq_footprint( 2UL     ) ); /* too small */
  FD_TEST( !fd_vinyl_cq_footprint( 1UL<<63 ) ); /* too large */
  FD_TEST( !fd_vinyl_cq_footprint( 5UL     ) ); /* not power-of-2 */

  ulong footprint = fd_vinyl_cq_footprint( comp_cnt );
  FD_TEST( !!footprint );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  if( FD_UNLIKELY( (align > SHMEM_ALIGN) | (footprint > SHMEM_FOOTPRINT) ) )
    FD_LOG_ERR(( "Update SHMEM_ALIGN and/or SHMEM_FOOTPRINT for this comp_cnt" ));

  FD_TEST( !fd_vinyl_cq_new( NULL,        comp_cnt ) ); /* NULL shmem */
  FD_TEST( !fd_vinyl_cq_new( (void *)1UL, comp_cnt ) ); /* misaligned shmem */
  FD_TEST( !fd_vinyl_cq_new( shmem,       0UL      ) ); /* bad comp_cnt */
  void * shcq = fd_vinyl_cq_new( shmem, comp_cnt ); FD_TEST( !!shcq );

  FD_TEST( !fd_vinyl_cq_join( NULL        ) ); /* NULL shmem */
  FD_TEST( !fd_vinyl_cq_join( (void *)1UL ) ); /* misaligned shmem */
  fd_vinyl_cq_t * cq = fd_vinyl_cq_join( shcq ); FD_TEST( !!cq );

  fd_vinyl_comp_t * comp = fd_vinyl_cq_comp( cq ); FD_TEST( !!comp );
  FD_TEST( fd_vinyl_cq_comp_const( cq )==comp );

  FD_TEST( fd_vinyl_cq_comp_cnt( cq )==comp_cnt );

  for( ulong rem=10000UL; rem; rem-- ) {
    ulong seq = fd_rng_ulong( rng );
    FD_TEST( fd_vinyl_cq_comp_idx( seq, comp_cnt )==(seq & (comp_cnt-1UL)) );
  }

  FD_TEST( !fd_vinyl_cq_seq( cq ) ); /* Initial sequence number at zero */

  long t_stop = fd_log_wallclock() + (long)1e9;

  FD_FOR_ALL( test_tile, tpool,0UL,thread_cnt, 0L,(long)thread_cnt, cq, t_stop );

  FD_TEST( !fd_vinyl_cq_leave( NULL )     ); /* NULL cq */
  FD_TEST(  fd_vinyl_cq_leave( cq )==shcq );

  FD_TEST( !fd_vinyl_cq_delete( NULL        ) ); /* NULL shmem */
  FD_TEST( !fd_vinyl_cq_delete( (void *)1UL ) ); /* misaligned shmem */
  FD_TEST(  fd_vinyl_cq_delete( shcq )==shmem );

  FD_TEST( !fd_vinyl_cq_join  ( shcq ) ); /* bad magic */
  FD_TEST( !fd_vinyl_cq_delete( shcq ) ); /* bad magic */

  FD_LOG_NOTICE(( "Cleaning up" ));

  /* Note: fini automatically pops all worker threads */

  fd_tpool_fini( tpool ); /* logs details */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
