#include "../fd_util.h"

FD_STATIC_ASSERT( FD_TPOOL_ALIGN            == 128UL, unit_test );

FD_STATIC_ASSERT( FD_TPOOL_WORKER_STATE_BOOT==0, unit_test );
FD_STATIC_ASSERT( FD_TPOOL_WORKER_STATE_IDLE==1, unit_test );
FD_STATIC_ASSERT( FD_TPOOL_WORKER_STATE_EXEC==2, unit_test );
FD_STATIC_ASSERT( FD_TPOOL_WORKER_STATE_HALT==3, unit_test );

static int
tile_self_push_main( int     argc,
                     char ** argv ) {
  (void)argc;
  fd_tpool_t * tpool = (fd_tpool_t *)argv;
  FD_TEST( !fd_tpool_worker_push( tpool, fd_tile_idx(), NULL, 0UL ) ); /* self push */
  return 0;
}

static int
tile_spin_main( int     argc,
                char ** argv ) {
  (void)argc; (void)argv;
  ulong const * done = (ulong const *)argv;
  while( !FD_VOLATILE_CONST( *done ) ) FD_SPIN_PAUSE();
  return 0;
}

static void
worker_spin( void * tpool,
             ulong  t0,     ulong t1,
             void * args,
             void * reduce, ulong stride,
             ulong  l0,     ulong l1,
             ulong  m0,     ulong m1,
             ulong  n0,     ulong n1 ) {
  FD_TEST( t0== 1UL ); FD_TEST( t1== 2UL ); FD_TEST( args==(void *)3UL ); FD_TEST( reduce==(void *)4UL ); FD_TEST( stride==5UL );
  FD_TEST( l0== 6UL ); FD_TEST( l1== 7UL ); FD_TEST( m0== 8UL ); FD_TEST( m1== 9UL ); FD_TEST( n0==10UL ); FD_TEST( n1==11UL );
  ulong const * done = (ulong const *)tpool; FD_TEST( done );
  while( !FD_VOLATILE_CONST( *done ) ) FD_SPIN_PAUSE();
}

struct test_args {
  void * tpool;
  ulong  t0;     ulong t1;
  void * args;
  void * reduce; ulong stride;
  ulong  l0;     ulong l1;
  ulong  m0;     ulong m1;
  ulong  n0;     ulong n1;
};

typedef struct test_args test_args_t;

test_args_t worker_tx[ FD_TILE_MAX ];
test_args_t worker_rx[ FD_TILE_MAX ];

static void
worker_bulk( void * tpool,
             ulong  t0,     ulong t1,
             void * args,
             void * reduce, ulong stride,
             ulong  l0,     ulong l1,
             ulong  m0,     ulong m1,
             ulong  n0,     ulong n1 ) {
  FD_TEST( n0<FD_TILE_MAX );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( worker_rx[ n0 ].tpool  ) = tpool;
  FD_VOLATILE( worker_rx[ n0 ].t0     ) = t0;     FD_VOLATILE( worker_rx[ n0 ].t1     ) = t1;
  FD_VOLATILE( worker_rx[ n0 ].args   ) = args;
  FD_VOLATILE( worker_rx[ n0 ].reduce ) = reduce; FD_VOLATILE( worker_rx[ n0 ].stride ) = stride;
  FD_VOLATILE( worker_rx[ n0 ].l0     ) = l0;     FD_VOLATILE( worker_rx[ n0 ].l1     ) = l1;
  FD_VOLATILE( worker_rx[ n0 ].m0     ) = m0;     FD_VOLATILE( worker_rx[ n0 ].m1     ) = m1;
  FD_VOLATILE( worker_rx[ n0 ].n0     ) = n0;     FD_VOLATILE( worker_rx[ n0 ].n1     ) = n1;
  FD_COMPILER_MFENCE();
}

static void
worker_scalar( void * tpool,
               ulong  t0,     ulong t1,
               void * args,
               void * reduce, ulong stride,
               ulong  l0,     ulong l1,
               ulong  m0,     ulong m1,
               ulong  n0,     ulong n1 ) {
  FD_TEST( m0<FD_TILE_MAX );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( worker_rx[ m0 ].tpool  ) = tpool;
  FD_VOLATILE( worker_rx[ m0 ].t0     ) = t0;     FD_VOLATILE( worker_rx[ m0 ].t1     ) = t1;
  FD_VOLATILE( worker_rx[ m0 ].args   ) = args;
  FD_VOLATILE( worker_rx[ m0 ].reduce ) = reduce; FD_VOLATILE( worker_rx[ m0 ].stride ) = stride;
  FD_VOLATILE( worker_rx[ m0 ].l0     ) = l0;     FD_VOLATILE( worker_rx[ m0 ].l1     ) = l1;
  FD_VOLATILE( worker_rx[ m0 ].m0     ) = m0;     FD_VOLATILE( worker_rx[ m0 ].m1     ) = m1;
  FD_VOLATILE( worker_rx[ m0 ].n0     ) = n0;     FD_VOLATILE( worker_rx[ m0 ].n1     ) = n1;
  FD_COMPILER_MFENCE();
}

#if FD_HAS_ATOMIC
static void
worker_taskq( void * tpool,
              ulong  t0,     ulong t1,
              void * args,
              void * reduce, ulong stride,
              ulong  l0,     ulong l1,
              ulong  m0,     ulong m1,
              ulong  n0,     ulong n1 ) {
  FD_TEST( m0<FD_TILE_MAX );
  FD_TEST( t0<=n0 ); FD_TEST( n1==n0+1UL ); FD_TEST( n1<=t1 ); /* these are otherwise non-deterministic for taskq */
  FD_COMPILER_MFENCE();
  FD_VOLATILE( worker_rx[ m0 ].tpool  ) = tpool;
  FD_VOLATILE( worker_rx[ m0 ].t0     ) = t0;     FD_VOLATILE( worker_rx[ m0 ].t1     ) = t1;
  FD_VOLATILE( worker_rx[ m0 ].args   ) = args;
  FD_VOLATILE( worker_rx[ m0 ].reduce ) = reduce; FD_VOLATILE( worker_rx[ m0 ].stride ) = stride;
  FD_VOLATILE( worker_rx[ m0 ].l0     ) = l0;     FD_VOLATILE( worker_rx[ m0 ].l1     ) = l1;
  FD_VOLATILE( worker_rx[ m0 ].m0     ) = m0;     FD_VOLATILE( worker_rx[ m0 ].m1     ) = m1;
  FD_VOLATILE( worker_rx[ m0 ].n0     ) = 0UL;    FD_VOLATILE( worker_rx[ m0 ].n1     ) = 0UL;
  FD_COMPILER_MFENCE();
}
#endif

static void
worker_bench( void * tpool,
              ulong  t0,     ulong t1,
              void * args,
              void * reduce, ulong stride,
              ulong  l0,     ulong l1,
              ulong  m0,     ulong m1,
              ulong  n0,     ulong n1 ) {
  (void)tpool; (void)t0; (void)t1; (void)args; (void)reduce; (void)stride;
  (void)l0; (void)l1; (void)m0; (void)m1; (void)n0; (void)n1;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Testing FD_TPOOL_PARTITION" ));

  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    uint  r          = fd_rng_uint( rng );
    ulong ta         = fd_rng_ulong( rng ) >> (int)(r & 63U); r >>=  6;
    ulong tb         = fd_rng_ulong( rng ) >> (int)(r & 63U); r >>=  6;
    ulong lane_cnt   = 1UL+ (ulong)(r & 15U);                 r >>=  4;
    ulong worker_cnt = 1UL+ (ulong)(r & 1023U);               r >>= 10;
    ulong task0      = fd_ulong_min( ta, tb );
    ulong task1      = fd_ulong_max( ta, tb );

    ulong block_cnt        = (task1 - task0) / lane_cnt;
    ulong worker_task_min  = lane_cnt*(block_cnt / worker_cnt);
    ulong worker_extra_cnt =           block_cnt % worker_cnt;
    ulong w1_exp           = task0;
    for( ulong worker_idx=0UL; worker_idx<worker_cnt; worker_idx++ ) {
      ulong w0_exp = w1_exp;
      w1_exp = fd_ulong_if( worker_idx==worker_cnt-1UL, task1,
                            w0_exp + fd_ulong_if( worker_idx<worker_extra_cnt, worker_task_min+lane_cnt, worker_task_min ) );
      ulong w0; ulong w1; FD_TPOOL_PARTITION( task0,task1,lane_cnt, worker_idx,worker_cnt, w0,w1 );
      FD_TEST( (w0==w0_exp) & (w1==w1_exp) );
    }
  }

  FD_LOG_NOTICE(( "Testing align and footprint" ));

  FD_TEST( fd_tpool_align()==FD_TPOOL_ALIGN );
  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong worker_cnt    = fd_rng_ulong( rng ) >> (int)(fd_rng_uint( rng ) & 63U);
    ulong footprint     = fd_tpool_footprint( worker_cnt );
    FD_TEST( !(footprint % FD_TPOOL_ALIGN) );
    FD_TEST( footprint==fd_ulong_if( ((1UL<=worker_cnt) & (worker_cnt<=FD_TILE_MAX)), FD_TPOOL_FOOTPRINT( worker_cnt ), 0UL ) );
  }

  uchar tpool_mem[ FD_TPOOL_FOOTPRINT(FD_TILE_MAX) ] __attribute__((aligned(FD_TPOOL_ALIGN)));

  FD_LOG_NOTICE(( "Testing init and fini" ));

  fd_tpool_t * tpool;
  FD_TEST( !fd_tpool_init( NULL,        1UL             ) ); /* NULL mem */
  FD_TEST( !fd_tpool_init( (void *)1UL, 1UL             ) ); /* misaligned mem */
  FD_TEST( !fd_tpool_init( tpool_mem,   0UL             ) ); /* bad worker_max */
  FD_TEST( !fd_tpool_init( tpool_mem,   FD_TILE_MAX+1UL ) ); /* bad worker_max */
  FD_TEST( !fd_tpool_fini( NULL ) );                         /* NULL tpool */
  for( ulong worker_max=1UL; worker_max<=FD_TILE_MAX; worker_max++ ) {
    tpool = fd_tpool_init( tpool_mem, worker_max ); FD_TEST( tpool );
    FD_TEST( fd_tpool_worker_cnt       ( tpool      )==1UL                        );
    FD_TEST( fd_tpool_worker_max       ( tpool      )==worker_max                 );
    FD_TEST( fd_tpool_worker_scratch   ( tpool, 0UL )==NULL                       );
    FD_TEST( fd_tpool_worker_scratch_sz( tpool, 0UL )==0UL                        );
    FD_TEST( fd_tpool_worker_state     ( tpool, 0UL )==FD_TPOOL_WORKER_STATE_EXEC );
    FD_TEST( fd_tpool_fini( tpool )==(void *)tpool_mem );
  }

  FD_LOG_NOTICE(( "Testing push" ));

  ulong tile_cnt = fd_tile_cnt();
  tpool = fd_tpool_init( tpool_mem, tile_cnt ); FD_TEST( tpool );

  FD_TEST( !fd_tpool_worker_push( NULL,  1UL,      NULL, 0UL ) ); /* NULL tpool */
  FD_TEST( !fd_tpool_worker_push( tpool, 0UL,      NULL, 0UL ) ); /* cant push to tile idx 0 */
  FD_TEST( !fd_tpool_worker_push( tpool, tile_cnt, NULL, 0UL ) ); /* cant push non-existent tile */
  if( tile_cnt>1L ) {
    FD_TEST( !fd_tpool_worker_push( tpool, 1UL, NULL,        1UL ) ); /* NULL scratch */
    FD_TEST( !fd_tpool_worker_push( tpool, 1UL, (void *)1UL, 1UL ) ); /* misaligned scratch */
  }
  for( ulong worker_idx=1UL; worker_idx<tile_cnt; worker_idx++ ) {
    ulong tile_idx = tile_cnt-worker_idx;
    FD_TEST( fd_tpool_worker_push( tpool, tile_idx, (void *)tile_idx, 0UL )==tpool );
    FD_TEST( fd_tpool_worker_cnt       ( tpool )            ==worker_idx+1UL             );
    FD_TEST( fd_tpool_worker_max       ( tpool )            ==tile_cnt                   );
    FD_TEST( fd_tpool_worker_scratch   ( tpool, worker_idx )==(void *)tile_idx           );
    FD_TEST( fd_tpool_worker_scratch_sz( tpool, worker_idx )==0UL                        );
    FD_TEST( fd_tpool_worker_state     ( tpool, worker_idx )==FD_TPOOL_WORKER_STATE_IDLE );
    FD_TEST( !fd_tpool_worker_push( tpool, tile_idx, NULL, 0UL ) ); /* Already added and/or too many */
  }

  FD_TEST( fd_tpool_fini( tpool )==(void *)tpool_mem );

  ulong spin_done;

  if( tile_cnt>1L ) {
    tpool = fd_tpool_init( tpool_mem, 2UL ); FD_TEST( tpool );

    fd_tile_exec_delete( fd_tile_exec_new( 1UL, tile_self_push_main, 0, (char **)tpool ), NULL );

    FD_COMPILER_MFENCE();
    FD_VOLATILE( spin_done ) = 0;
    FD_COMPILER_MFENCE();
    fd_tile_exec_t * exec = fd_tile_exec_new( 1UL, tile_spin_main, 0, (char **)fd_type_pun( &spin_done ) ); /* self push */

    FD_TEST( !fd_tpool_worker_push( tpool, 1UL, NULL, 0UL ) ); /* Already in use */

    FD_COMPILER_MFENCE();
    FD_VOLATILE( spin_done ) = 1;
    FD_COMPILER_MFENCE();
    fd_tile_exec_delete( exec, NULL );

    FD_TEST( fd_tpool_fini( tpool )==(void *)tpool_mem );
  }

  FD_LOG_NOTICE(( "Testing pop, exec and wait" ));

  tpool = fd_tpool_init( tpool_mem, tile_cnt ); FD_TEST( tpool );

  FD_TEST( !fd_tpool_worker_pop( NULL  ) ); /* NULL tpool */
  FD_TEST( !fd_tpool_worker_pop( tpool ) ); /* no workers */
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) FD_TEST( fd_tpool_worker_push( tpool, tile_idx, NULL, 0UL )==tpool );

  if( tile_cnt>1L ) {
    ulong worker_idx = tile_cnt-1UL;
    FD_COMPILER_MFENCE();
    FD_VOLATILE( spin_done ) = 0;
    FD_COMPILER_MFENCE();
    fd_tpool_exec( tpool,worker_idx, worker_spin, &spin_done, 1UL,2UL,(void *)3UL,(void *)4UL,5UL,6UL,7UL,8UL,9UL,10UL,11UL );
    FD_TEST( fd_tpool_worker_state( tpool, worker_idx )==FD_TPOOL_WORKER_STATE_EXEC );
    FD_TEST( !fd_tpool_worker_pop( tpool ) ); /* already in use */
    FD_COMPILER_MFENCE();
    FD_VOLATILE( spin_done ) = 1;
    FD_COMPILER_MFENCE();
    fd_tpool_wait( tpool,worker_idx );
    FD_TEST( fd_tpool_worker_state( tpool, worker_idx )==FD_TPOOL_WORKER_STATE_IDLE );
  }

  for( ulong worker_idx=tile_cnt-1UL; worker_idx; worker_idx-- ) {
    FD_TEST( fd_tpool_worker_pop( tpool )==tpool      );
    FD_TEST( fd_tpool_worker_cnt( tpool )==worker_idx );
    FD_TEST( fd_tpool_worker_max( tpool )==tile_cnt   );
  }

  FD_TEST( fd_tpool_fini( tpool )==(void *)tpool_mem );

  FD_LOG_NOTICE(( "Testing fd_tpool_exec_all_raw" ));

  tpool = fd_tpool_init( tpool_mem, tile_cnt ); FD_TEST( tpool );
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) FD_TEST( fd_tpool_worker_push( tpool, tile_idx, NULL, 0UL )==tpool );

  for( ulong rem=100000UL; rem; rem-- ) {
    ulong  tmp0       = fd_rng_ulong_roll( rng, tile_cnt );
    ulong  tmp1       = fd_rng_ulong_roll( rng, tile_cnt );
    ulong  job_t0     = fd_ulong_min( tmp0, tmp1 );
    ulong  job_t1     = fd_ulong_max( tmp0, tmp1 ) + 1UL;
    void * job_tpool  = (void *)fd_rng_ulong( rng );
    void * job_args   = (void *)fd_rng_ulong( rng );
    void * job_reduce = (void *)fd_rng_ulong( rng ); ulong  job_stride = fd_rng_ulong( rng );
    ulong  job_l0     = fd_rng_ulong( rng );         ulong  job_l1     = fd_rng_ulong( rng );
    fd_memset( worker_tx, 0, FD_TILE_MAX*sizeof(test_args_t) );
    fd_memset( worker_rx, 0, FD_TILE_MAX*sizeof(test_args_t) );
    for( ulong t=job_t0; t<job_t1; t++ ) {
      worker_tx[t].tpool  = job_tpool;
      worker_tx[t].t0     = job_t0;     worker_tx[t].t1     = job_t1;
      worker_tx[t].args   = job_args;
      worker_tx[t].reduce = job_reduce; worker_tx[t].stride = job_stride;
      worker_tx[t].l0     = job_l0;     worker_tx[t].l1     = job_l1;
      worker_tx[t].m0     = job_l0;     worker_tx[t].m1     = job_l1;
      worker_tx[t].n0     = t;          worker_tx[t].n1     = t+1UL;
    }
    fd_tpool_exec_all_raw( tpool,job_t0,job_t1, worker_bulk, job_tpool, job_args, job_reduce,job_stride, job_l0,job_l1 );
    FD_TEST( !memcmp( worker_tx, worker_rx, FD_TILE_MAX*sizeof(test_args_t) ) );
  }

  FD_LOG_NOTICE(( "Testing fd_tpool_exec_all_batch" ));

  for( ulong rem=100000UL; rem; rem-- ) {
    ulong  tmp0       = fd_rng_ulong_roll( rng, tile_cnt );
    ulong  tmp1       = fd_rng_ulong_roll( rng, tile_cnt );
    ulong  job_t0     = fd_ulong_min( tmp0, tmp1 );
    ulong  job_t1     = fd_ulong_max( tmp0, tmp1 ) + 1UL;
    void * job_tpool  = (void *)fd_rng_ulong( rng );
    void * job_args   = (void *)fd_rng_ulong( rng );
    void * job_reduce = (void *)fd_rng_ulong( rng ); ulong  job_stride = fd_rng_ulong( rng );
    /**/   tmp0       = fd_rng_ulong( rng );
    /**/   tmp1       = fd_rng_ulong( rng );
    ulong  job_l0     = fd_ulong_min( tmp0, tmp1 );
    ulong  job_l1     = fd_ulong_max( tmp0, tmp1 );

    fd_memset( worker_tx, 0, FD_TILE_MAX*sizeof(test_args_t) );
    fd_memset( worker_rx, 0, FD_TILE_MAX*sizeof(test_args_t) );
    for( ulong t=job_t0; t<job_t1; t++ ) {
      ulong batch_l0;
      ulong batch_l1;
      FD_TPOOL_PARTITION( job_l0,job_l1,1UL, t-job_t0,job_t1-job_t0, batch_l0,batch_l1 );
      worker_tx[t].tpool  = job_tpool;
      worker_tx[t].t0     = job_t0;     worker_tx[t].t1     = job_t1;
      worker_tx[t].args   = job_args;
      worker_tx[t].reduce = job_reduce; worker_tx[t].stride = job_stride;
      worker_tx[t].l0     = job_l0;     worker_tx[t].l1     = job_l1;
      worker_tx[t].m0     = batch_l0;   worker_tx[t].m1     = batch_l1;
      worker_tx[t].n0     = t;          worker_tx[t].n1     = t+1UL;
    }
    fd_tpool_exec_all_batch( tpool,job_t0,job_t1, worker_bulk, job_tpool, job_args, job_reduce,job_stride, job_l0,job_l1 );
    FD_TEST( !memcmp( worker_tx, worker_rx, FD_TILE_MAX*sizeof(test_args_t) ) );
  }

  FD_LOG_NOTICE(( "Testing fd_tpool_exec_all_rrobin" ));

  for( ulong rem=100000UL; rem; rem-- ) {
    ulong  tmp0       = fd_rng_ulong_roll( rng, tile_cnt );
    ulong  tmp1       = fd_rng_ulong_roll( rng, tile_cnt );
    ulong  job_t0     = fd_ulong_min( tmp0, tmp1 );
    ulong  job_t1     = fd_ulong_max( tmp0, tmp1 ) + 1UL;
    void * job_tpool  = (void *)fd_rng_ulong( rng );
    void * job_args   = (void *)fd_rng_ulong( rng );
    void * job_reduce = (void *)fd_rng_ulong( rng ); ulong  job_stride = fd_rng_ulong( rng );
    /**/   tmp0       = fd_rng_ulong_roll( rng, FD_TILE_MAX+1UL );
    /**/   tmp1       = fd_rng_ulong_roll( rng, FD_TILE_MAX+1UL );
    ulong  job_l0     = fd_ulong_min( tmp0, tmp1 );
    ulong  job_l1     = fd_ulong_max( tmp0, tmp1 );

    fd_memset( worker_tx, 0, FD_TILE_MAX*sizeof(test_args_t) );
    fd_memset( worker_rx, 0, FD_TILE_MAX*sizeof(test_args_t) );
    for( ulong l=job_l0; l<job_l1; l++ ) {
      ulong t = job_t0 + ((l-job_l0) % (job_t1-job_t0));
      worker_tx[l].tpool  = job_tpool;
      worker_tx[l].t0     = job_t0;     worker_tx[l].t1     = job_t1;
      worker_tx[l].args   = job_args;
      worker_tx[l].reduce = job_reduce; worker_tx[l].stride = job_stride;
      worker_tx[l].l0     = job_l0;     worker_tx[l].l1     = job_l1;
      worker_tx[l].m0     = l;          worker_tx[l].m1     = l+1UL;
      worker_tx[l].n0     = t;          worker_tx[l].n1     = t+1UL;
    }
    fd_tpool_exec_all_rrobin( tpool,job_t0,job_t1, worker_scalar, job_tpool, job_args, job_reduce,job_stride, job_l0,job_l1 );
    FD_TEST( !memcmp( worker_tx, worker_rx, FD_TILE_MAX*sizeof(test_args_t) ) );
  }

  FD_LOG_NOTICE(( "Testing fd_tpool_exec_all_block" ));

  for( ulong rem=100000UL; rem; rem-- ) {
    ulong  tmp0       = fd_rng_ulong_roll( rng, tile_cnt );
    ulong  tmp1       = fd_rng_ulong_roll( rng, tile_cnt );
    ulong  job_t0     = fd_ulong_min( tmp0, tmp1 );
    ulong  job_t1     = fd_ulong_max( tmp0, tmp1 ) + 1UL;
    void * job_tpool  = (void *)fd_rng_ulong( rng );
    void * job_args   = (void *)fd_rng_ulong( rng );
    void * job_reduce = (void *)fd_rng_ulong( rng ); ulong  job_stride = fd_rng_ulong( rng );
    /**/   tmp0       = fd_rng_ulong_roll( rng, FD_TILE_MAX+1UL );
    /**/   tmp1       = fd_rng_ulong_roll( rng, FD_TILE_MAX+1UL );
    ulong  job_l0     = fd_ulong_min( tmp0, tmp1 );
    ulong  job_l1     = fd_ulong_max( tmp0, tmp1 );

    fd_memset( worker_tx, 0, FD_TILE_MAX*sizeof(test_args_t) );
    fd_memset( worker_rx, 0, FD_TILE_MAX*sizeof(test_args_t) );
    for( ulong t=job_t0; t<job_t1; t++ ) {
      ulong batch_l0;
      ulong batch_l1;
      FD_TPOOL_PARTITION( job_l0,job_l1,1UL, t-job_t0,job_t1-job_t0, batch_l0,batch_l1 );
      for( ulong l=batch_l0; l<batch_l1; l++ ) {
        worker_tx[l].tpool  = job_tpool;
        worker_tx[l].t0     = job_t0;     worker_tx[l].t1     = job_t1;
        worker_tx[l].args   = job_args;
        worker_tx[l].reduce = job_reduce; worker_tx[l].stride = job_stride;
        worker_tx[l].l0     = job_l0;     worker_tx[l].l1     = job_l1;
        worker_tx[l].m0     = l;          worker_tx[l].m1     = l+1UL;
        worker_tx[l].n0     = t;          worker_tx[l].n1     = t+1UL;
      }
    }
    fd_tpool_exec_all_block( tpool,job_t0,job_t1, worker_scalar, job_tpool, job_args, job_reduce,job_stride, job_l0,job_l1 );
    FD_TEST( !memcmp( worker_tx, worker_rx, FD_TILE_MAX*sizeof(test_args_t) ) );
  }

# if FD_HAS_ATOMIC
  FD_LOG_NOTICE(( "Testing fd_tpool_exec_all_taskq" ));

  for( ulong rem=100000UL; rem; rem-- ) {
    ulong  tmp0       = fd_rng_ulong_roll( rng, tile_cnt );
    ulong  tmp1       = fd_rng_ulong_roll( rng, tile_cnt );
    ulong  job_t0     = fd_ulong_min( tmp0, tmp1 );
    ulong  job_t1     = fd_ulong_max( tmp0, tmp1 ) + 1UL;
    void * job_tpool  = (void *)fd_rng_ulong( rng );
    void * job_args   = (void *)fd_rng_ulong( rng );
    void * job_reduce = (void *)fd_rng_ulong( rng ); ulong  job_stride = fd_rng_ulong( rng );
    /**/   tmp0       = fd_rng_ulong_roll( rng, FD_TILE_MAX+1UL );
    /**/   tmp1       = fd_rng_ulong_roll( rng, FD_TILE_MAX+1UL );
    ulong  job_l0     = fd_ulong_min( tmp0, tmp1 );
    ulong  job_l1     = fd_ulong_max( tmp0, tmp1 );

    fd_memset( worker_tx, 0, FD_TILE_MAX*sizeof(test_args_t) );
    fd_memset( worker_rx, 0, FD_TILE_MAX*sizeof(test_args_t) );
    for( ulong t=job_t0; t<job_t1; t++ ) {
      ulong batch_l0;
      ulong batch_l1;
      FD_TPOOL_PARTITION( job_l0,job_l1,1UL, t-job_t0,job_t1-job_t0, batch_l0,batch_l1 );
      for( ulong l=batch_l0; l<batch_l1; l++ ) {
        worker_tx[l].tpool  = job_tpool;
        worker_tx[l].t0     = job_t0;     worker_tx[l].t1     = job_t1;
        worker_tx[l].args   = job_args;
        worker_tx[l].reduce = job_reduce; worker_tx[l].stride = job_stride;
        worker_tx[l].l0     = job_l0;     worker_tx[l].l1     = job_l1;
        worker_tx[l].m0     = l;          worker_tx[l].m1     = l+1UL;
        worker_tx[l].n0     = 0UL;        worker_tx[l].n1     = 0UL;
      }
    }
    fd_tpool_exec_all_taskq( tpool,job_t0,job_t1, worker_taskq, job_tpool, job_args, job_reduce,job_stride, job_l0,job_l1 );
    FD_TEST( !memcmp( worker_tx, worker_rx, FD_TILE_MAX*sizeof(test_args_t) ) );
  }
# endif

  FD_TEST( fd_tpool_fini( tpool )==(void *)tpool_mem );

  FD_LOG_NOTICE(( "Testing fd_tpool_worker_state_cstr" ));

  char const * cstr;
  cstr = fd_tpool_worker_state_cstr( FD_TPOOL_WORKER_STATE_BOOT ); FD_TEST( cstr && !strcmp( cstr, "boot"    ) );
  cstr = fd_tpool_worker_state_cstr( FD_TPOOL_WORKER_STATE_IDLE ); FD_TEST( cstr && !strcmp( cstr, "idle"    ) );
  cstr = fd_tpool_worker_state_cstr( FD_TPOOL_WORKER_STATE_EXEC ); FD_TEST( cstr && !strcmp( cstr, "exec"    ) );
  cstr = fd_tpool_worker_state_cstr( FD_TPOOL_WORKER_STATE_HALT ); FD_TEST( cstr && !strcmp( cstr, "halt"    ) );
  cstr = fd_tpool_worker_state_cstr( -1 );                         FD_TEST( cstr && !strcmp( cstr, "unknown" ) );

  FD_LOG_NOTICE(( "Benching dispatch" ));

  tpool = fd_tpool_init( tpool_mem, tile_cnt ); FD_TEST( tpool );
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ ) FD_TEST( fd_tpool_worker_push( tpool, tile_idx, NULL, 0UL )==tpool );

  ulong iter_cnt = 65536UL;
  float overhead;
  for( ulong worker_cnt=1UL; worker_cnt<=tile_cnt; worker_cnt++ ) {

    /* warmup */
    for( ulong rem=1024UL; rem; rem-- ) fd_tpool_exec_all_raw( tpool, 0L,worker_cnt, worker_bench, NULL,NULL,NULL,0UL,0UL,0UL );

    /* for real */
    long elapsed = -fd_log_wallclock();
    for( ulong rem=iter_cnt; rem; rem-- ) fd_tpool_exec_all_raw( tpool, 0L,worker_cnt, worker_bench, NULL,NULL,NULL,0UL,0UL,0UL );
    elapsed += fd_log_wallclock();

    float dt           = ((float)elapsed) / ((float)iter_cnt);
    if( worker_cnt==1UL ) {
      overhead = dt;
      FD_LOG_NOTICE(( "%4lu workers %9.3f ns (%9.3f overhead)", worker_cnt, (double)dt, (double)overhead ));
    } else {
      float dt_per_level = (dt-overhead) / (float)fd_ulong_find_msb( worker_cnt );
      FD_LOG_NOTICE(( "%4lu workers %9.3f ns (%9.3f dt_per_level)", worker_cnt, (double)dt, (double)dt_per_level ));
    }
  }

  FD_TEST( fd_tpool_fini( tpool )==(void *)tpool_mem );

  /* FIXME: better coverage of scratch attach / detach */

  fd_rng_delete( fd_rng_leave( rng ) );
  
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

