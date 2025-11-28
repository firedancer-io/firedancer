#include "../fd_vinyl.h"

FD_STATIC_ASSERT( FD_VINYL_REQ_ALIGN    ==64UL, unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_FOOTPRINT==64UL, unit_test );

FD_STATIC_ASSERT( FD_VINYL_REQ_ALIGN    ==alignof(fd_vinyl_req_t), unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_FOOTPRINT==sizeof (fd_vinyl_req_t), unit_test );

FD_STATIC_ASSERT( FD_VINYL_REQ_TYPE_ACQUIRE==0, unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_TYPE_RELEASE==1, unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_TYPE_ERASE  ==2, unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_TYPE_MOVE   ==3, unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_TYPE_FETCH  ==4, unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_TYPE_FLUSH  ==5, unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_TYPE_TRY    ==6, unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_TYPE_TEST   ==7, unit_test );

FD_STATIC_ASSERT( FD_VINYL_REQ_FLAG_MODIFY==(1UL<<0), unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_FLAG_IGNORE==(1UL<<1), unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_FLAG_CREATE==(1UL<<2), unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_FLAG_EXCL  ==(1UL<<3), unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_FLAG_ERASE ==(1UL<<4), unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_FLAG_BY_KEY==(1UL<<5), unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_FLAG_MRU   ==(0UL<<6), unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_FLAG_LRU   ==(1UL<<6), unit_test );
FD_STATIC_ASSERT( FD_VINYL_REQ_FLAG_UNC   ==(2UL<<6), unit_test );

FD_STATIC_ASSERT( FD_VINYL_RQ_MAGIC==0xfd3a7352d703a6c0UL, unit_test );

static FD_FOR_ALL_BEGIN( test_tile, 1L ) {
  fd_vinyl_rq_t * rq     = (fd_vinyl_rq_t *)arg[0];
  long            t_stop = (long)           arg[1];

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)(tpool_t0+1UL), 0UL ) );

  if( !tpool_t0 ) { /* Req sender */

    FD_LOG_NOTICE(( "Starting transmitter" ));

    for(;;) {

      if( FD_UNLIKELY( fd_log_wallclock() > t_stop ) ) break;

      ulong val = fd_rng_ulong( rng );

      val += (ulong)!val; /* Use req_id==0 as termination for receivers in this test */

      ulong req_id          =       val++;
      ulong link_id         =       val++;
      int   type            = (int)(val++);
      ulong flags           =       val++;
      ulong batch_cnt       =       val++;
      ulong val_max         =       val++;
      ulong key_gaddr       =       val++;
      ulong val_gaddr_gaddr =       val++;
      ulong err_gaddr       =       val++;
      ulong comp_gaddr      =       val++;

      fd_vinyl_rq_send( rq, req_id, link_id, type, flags, batch_cnt, val_max, key_gaddr, val_gaddr_gaddr, err_gaddr, comp_gaddr );

    }

    /* Send terminate */

    fd_vinyl_rq_send( rq, 0UL, 0UL, 0, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );

  } else {

    FD_LOG_NOTICE(( "Starting receiver %lu", tpool_t0-1UL ));

    ulong seq = fd_vinyl_rq_seq( rq );

    for(;;) {

      fd_vinyl_req_t req[1];
      long diff = fd_vinyl_rq_recv( rq, seq, req );

      if( FD_LIKELY( diff ) ) {
        if( FD_UNLIKELY( diff<0L ) ) {
          FD_LOG_WARNING(( "Receiver %lu overrun; resynchronizing", tpool_t0-1UL ));
          seq = fd_vinyl_rq_seq( rq );
        }
        FD_SPIN_PAUSE();
        continue;
      }

      ulong val = req->req_id;
      if( FD_UNLIKELY( !val ) ) break;

      FD_TEST( req->req_id          ==         val ); val++;
      FD_TEST( req->link_id         ==         val ); val++;
      FD_TEST( req->type            == (schar) val ); val++;
      FD_TEST( req->flags           == (uchar) val ); val++;
      FD_TEST( req->batch_cnt       == (ushort)val ); val++;
      FD_TEST( req->val_max         == (uint)  val ); val++;
      FD_TEST( req->key_gaddr       ==         val ); val++;
      FD_TEST( req->val_gaddr_gaddr ==         val ); val++;
      FD_TEST( req->err_gaddr       ==         val ); val++;
      FD_TEST( req->comp_gaddr      ==         val ); val++;

      seq++;
    }

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

  ulong req_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--req-cnt", NULL, 8192UL  );

  FD_LOG_NOTICE(( "Testing (--req-cnt %lu)", req_cnt ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( ulong rem=1000000UL; rem; rem-- ) {
    ulong flags = fd_rng_ulong( rng );
    FD_TEST( fd_vinyl_req_flag_modify( flags )==!!(flags & FD_VINYL_REQ_FLAG_MODIFY) );
    FD_TEST( fd_vinyl_req_flag_ignore( flags )==!!(flags & FD_VINYL_REQ_FLAG_IGNORE) );
    FD_TEST( fd_vinyl_req_flag_create( flags )==!!(flags & FD_VINYL_REQ_FLAG_CREATE) );
    FD_TEST( fd_vinyl_req_flag_excl  ( flags )==!!(flags & FD_VINYL_REQ_FLAG_EXCL  ) );
    FD_TEST( fd_vinyl_req_flag_erase ( flags )==!!(flags & FD_VINYL_REQ_FLAG_ERASE ) );
    FD_TEST( fd_vinyl_req_flag_by_key( flags )==!!(flags & FD_VINYL_REQ_FLAG_BY_KEY) );
    FD_TEST( fd_vinyl_req_evict_prio ( flags )==(int)((flags>>6) & 3UL)              );
  }

  ulong thread_cnt = fd_tile_cnt();

  FD_LOG_NOTICE(( "Creating tpool from all %lu tiles", thread_cnt ));

  static uchar _tpool[ FD_TPOOL_FOOTPRINT( FD_TILE_MAX ) ] __attribute__((aligned(FD_TPOOL_ALIGN)));

  fd_tpool_t * tpool = fd_tpool_init( _tpool, thread_cnt, 0UL ); /* logs details */
  if( FD_UNLIKELY( !tpool ) ) FD_LOG_ERR(( "fd_tpool_init failed" ));

  for( ulong thread_idx=1UL; thread_idx<thread_cnt; thread_idx++ )
    if( FD_UNLIKELY( !fd_tpool_worker_push( tpool, thread_idx ) ) ) FD_LOG_ERR(( "fd_tpool_worker_push failed" ));

  ulong align = fd_vinyl_rq_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  FD_TEST( !fd_vinyl_rq_footprint( 2UL     ) ); /* too small */
  FD_TEST( !fd_vinyl_rq_footprint( 1UL<<63 ) ); /* too large */
  FD_TEST( !fd_vinyl_rq_footprint( 5UL     ) ); /* not power-of-2 */

  ulong footprint = fd_vinyl_rq_footprint( req_cnt );
  FD_TEST( !!footprint );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  if( FD_UNLIKELY( (align > SHMEM_ALIGN) | (footprint > SHMEM_FOOTPRINT) ) )
    FD_LOG_ERR(( "Update SHMEM_ALIGN and/or SHMEM_FOOTPRINT for this req_cnt" ));

  FD_TEST( !fd_vinyl_rq_new( NULL,        req_cnt ) ); /* NULL shmem */
  FD_TEST( !fd_vinyl_rq_new( (void *)1UL, req_cnt ) ); /* misaligned shmem */
  FD_TEST( !fd_vinyl_rq_new( shmem,       0UL     ) ); /* bad req_cnt */
  void * shrq = fd_vinyl_rq_new( shmem, req_cnt ); FD_TEST( !!shrq );

  FD_TEST( !fd_vinyl_rq_join( NULL        ) ); /* NULL shmem */
  FD_TEST( !fd_vinyl_rq_join( (void *)1UL ) ); /* misaligned shmem */
  fd_vinyl_rq_t * rq = fd_vinyl_rq_join( shrq ); FD_TEST( !!rq );

  fd_vinyl_req_t * req = fd_vinyl_rq_req( rq ); FD_TEST( !!req );
  FD_TEST( fd_vinyl_rq_req_const( rq )==req );

  FD_TEST( fd_vinyl_rq_req_cnt( rq )==req_cnt );

  for( ulong rem=10000UL; rem; rem-- ) {
    ulong seq = fd_rng_ulong( rng );
    FD_TEST( fd_vinyl_rq_req_idx( seq, req_cnt )==(seq & (req_cnt-1UL)) );
  }

  FD_TEST( !fd_vinyl_rq_seq( rq ) ); /* Initial sequence number at zero */

  long t_stop = fd_log_wallclock() + (long)1e9;

  FD_FOR_ALL( test_tile, tpool,0UL,thread_cnt, 0L,(long)thread_cnt, rq, t_stop );

  FD_TEST( !fd_vinyl_rq_leave( NULL )     ); /* NULL rq */
  FD_TEST(  fd_vinyl_rq_leave( rq )==shrq );

  FD_TEST( !fd_vinyl_rq_delete( NULL        ) ); /* NULL shmem */
  FD_TEST( !fd_vinyl_rq_delete( (void *)1UL ) ); /* misaligned shmem */
  FD_TEST(  fd_vinyl_rq_delete( shrq )==shmem );

  FD_TEST( !fd_vinyl_rq_join  ( shrq ) ); /* bad magic */
  FD_TEST( !fd_vinyl_rq_delete( shrq ) ); /* bad magic */

  FD_LOG_NOTICE(( "Cleaning up" ));

  /* Note: fini automatically pops all worker threads */

  fd_tpool_fini( tpool ); /* logs details */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
