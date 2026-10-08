#include "fd_pack_bundle_obs.h"

#define ELE_MAX      (4UL)
#define PACK_IDX_MAX (16UL)

static uchar mem[ 1UL<<16 ] __attribute__((aligned(64)));

static void
test_blocked( fd_pack_bobs_t * bobs ) {
  ulong const * blocked = fd_pack_bobs_blocked( bobs );
  for( ulong i=0UL; i<FD_PACK_BOBS_REASON_CNT; i++ ) FD_TEST( blocked[ i ]==0UL );

  /* Time before the first reason is not charged */
  fd_pack_bobs_charge( bobs, 100L, FD_PACK_BOBS_REASON_LANE_VOTE );
  /* A arrives while the lane is busy with a vote */
  fd_pack_bobs_ele_t * a = fd_pack_bobs_acquire( bobs );
  FD_TEST( a );
  fd_pack_bobs_charge( bobs, 110L, FD_PACK_BOBS_REASON_VOTE_PREEMPT );    /* 10 lane_vote */
  fd_pack_bobs_charge( bobs, 115L, FD_PACK_BOBS_REASON_NONE );            /*  5 vote_preempt */
  fd_pack_bobs_charge( bobs, 200L, FD_PACK_BOBS_REASON_CONFLICT_TPU );    /* not charged */
  /* B arrives during the conflict */
  fd_pack_bobs_ele_t * b = fd_pack_bobs_acquire( bobs );
  FD_TEST( b && b!=a );
  fd_pack_bobs_charge( bobs, 230L, FD_PACK_BOBS_REASON_CONFLICT_TPU );    /* 30 conflict_tpu */
  fd_pack_bobs_flush ( bobs, 240L );                                      /* 10 more */

  FD_TEST( blocked[ FD_PACK_BOBS_REASON_LANE_VOTE    ]==10UL );
  FD_TEST( blocked[ FD_PACK_BOBS_REASON_VOTE_PREEMPT ]== 5UL );
  FD_TEST( blocked[ FD_PACK_BOBS_REASON_CONFLICT_TPU ]==40UL );

  ulong d[ FD_PACK_BOBS_REASON_CNT ];
  fd_pack_bobs_delta( bobs, a, d );
  FD_TEST( d[ FD_PACK_BOBS_REASON_LANE_VOTE ]==10UL && d[ FD_PACK_BOBS_REASON_VOTE_PREEMPT ]==5UL && d[ FD_PACK_BOBS_REASON_CONFLICT_TPU ]==40UL );
  FD_TEST( fd_pack_bobs_cause_unscheduled( FD_PACK_BUNDLE_LEAVE_EXPIRED, d, FD_PACK_BOBS_PHASE_MID )==FD_PACK_BOBS_CAUSE_BLOCKED_BASE+FD_PACK_BOBS_REASON_CONFLICT_TPU );

  fd_pack_bobs_delta( bobs, b, d );
  FD_TEST( d[ FD_PACK_BOBS_REASON_LANE_VOTE ]==0UL && d[ FD_PACK_BOBS_REASON_CONFLICT_TPU ]==40UL );

  /* Scheduling freezes the wait */
  fd_pack_bobs_register( bobs, b, 0UL );
  fd_pack_bobs_scheduled( bobs, b );
  fd_pack_bobs_charge( bobs, 300L, FD_PACK_BOBS_REASON_DOES_NOT_FIT ); /* 60 more conflict_tpu */
  fd_pack_bobs_flush ( bobs, 310L );                                   /* 10 does_not_fit */
  fd_pack_bobs_delta( bobs, b, d );
  FD_TEST( d[ FD_PACK_BOBS_REASON_CONFLICT_TPU ]==40UL && d[ FD_PACK_BOBS_REASON_DOES_NOT_FIT ]==0UL );
  fd_pack_bobs_delta( bobs, a, d );
  FD_TEST( d[ FD_PACK_BOBS_REASON_CONFLICT_TPU ]==100UL && d[ FD_PACK_BOBS_REASON_DOES_NOT_FIT ]==10UL );

  /* Time going backwards is ignored */
  fd_pack_bobs_charge( bobs, 100L, FD_PACK_BOBS_REASON_NONE );
  FD_TEST( blocked[ FD_PACK_BOBS_REASON_DOES_NOT_FIT ]==10UL );

  fd_pack_bobs_release( bobs, a );
  fd_pack_bobs_release( bobs, b );
  FD_TEST( fd_pack_bobs_used( bobs )==0UL );
}

static void
test_pool( fd_pack_bobs_t * bobs ) {
  fd_pack_bobs_ele_t * e[ ELE_MAX ];
  for( ulong i=0UL; i<ELE_MAX; i++ ) {
    e[ i ] = fd_pack_bobs_acquire( bobs );
    FD_TEST( e[ i ] );
    FD_TEST( e[ i ]->state==FD_PACK_BOBS_STATE_PENDING );
    fd_pack_bobs_register( bobs, e[ i ], 3UL*i );
  }
  FD_TEST( !fd_pack_bobs_acquire( bobs ) );
  FD_TEST( fd_pack_bobs_used( bobs )==ELE_MAX );

  for( ulong i=0UL; i<ELE_MAX; i++ ) FD_TEST( fd_pack_bobs_query( bobs, 3UL*i )==e[ i ] );
  for( ulong i=0UL; i<ELE_MAX; i++ ) FD_TEST( fd_pack_bobs_query_id( bobs, fd_pack_bobs_id( bobs, e[ i ] ) )==e[ i ] );
  ulong id0 = fd_pack_bobs_id( bobs, e[ 1 ] );
  FD_TEST( !fd_pack_bobs_query( bobs, 1UL ) );
  FD_TEST( !fd_pack_bobs_query( bobs, PACK_IDX_MAX ) );

  /* Schedule two; they leave the pack index */
  ulong id1 = fd_pack_bobs_scheduled( bobs, e[ 1 ] );
  FD_TEST( id1==id0 );
  ulong id2 = fd_pack_bobs_scheduled( bobs, e[ 2 ] );
  FD_TEST( id1 && id2 && id1!=id2 );
  FD_TEST( !fd_pack_bobs_query( bobs, 3UL ) );
  FD_TEST( fd_pack_bobs_query_id( bobs, id1 )==e[ 1 ] );
  FD_TEST( fd_pack_bobs_query_id( bobs, id2 )==e[ 2 ] );
  FD_TEST( !fd_pack_bobs_query_id( bobs, 0UL ) );
  FD_TEST( !fd_pack_bobs_query_id( bobs, id1+(1UL<<32) ) ); /* wrong generation */
  FD_TEST( fd_pack_bobs_oldest_scheduled( bobs )==e[ 1 ] );

  /* Release the oldest; the id becomes stale even after reuse */
  fd_pack_bobs_release( bobs, e[ 1 ] );
  FD_TEST( !fd_pack_bobs_query_id( bobs, id1 ) );
  FD_TEST( fd_pack_bobs_oldest_scheduled( bobs )==e[ 2 ] );
  fd_pack_bobs_ele_t * r = fd_pack_bobs_acquire( bobs );
  FD_TEST( r==e[ 1 ] );
  fd_pack_bobs_register( bobs, r, 5UL );
  ulong id3 = fd_pack_bobs_scheduled( bobs, r );
  FD_TEST( id3!=id1 );
  FD_TEST( !fd_pack_bobs_query_id( bobs, id1 ) );
  FD_TEST( fd_pack_bobs_query_id( bobs, id3 )==r );

  /* Release from the middle and the tail of the scheduled list */
  fd_pack_bobs_release( bobs, r );
  FD_TEST( fd_pack_bobs_oldest_scheduled( bobs )==e[ 2 ] );
  fd_pack_bobs_release( bobs, e[ 2 ] );
  FD_TEST( !fd_pack_bobs_oldest_scheduled( bobs ) );

  /* Releasing a pending element frees its pack index */
  fd_pack_bobs_release( bobs, e[ 0 ] );
  fd_pack_bobs_release( bobs, e[ 3 ] );
  FD_TEST( !fd_pack_bobs_query( bobs, 0UL ) );
  FD_TEST( !fd_pack_bobs_query( bobs, 9UL ) );
  FD_TEST( fd_pack_bobs_used( bobs )==0UL );
}

static void
test_phase( void ) {
  /* Leader slot [1000, 1300) */
  FD_TEST( fd_pack_bobs_phase(  900L, 1, 1000L, 1300L, 0L, ULONG_MAX, 400L )==FD_PACK_BOBS_PHASE_EARLY );
  FD_TEST( fd_pack_bobs_phase( 1099L, 1, 1000L, 1300L, 0L, ULONG_MAX, 400L )==FD_PACK_BOBS_PHASE_EARLY );
  FD_TEST( fd_pack_bobs_phase( 1100L, 1, 1000L, 1300L, 0L, ULONG_MAX, 400L )==FD_PACK_BOBS_PHASE_MID   );
  FD_TEST( fd_pack_bobs_phase( 1199L, 1, 1000L, 1300L, 0L, ULONG_MAX, 400L )==FD_PACK_BOBS_PHASE_MID   );
  FD_TEST( fd_pack_bobs_phase( 1200L, 1, 1000L, 1300L, 0L, ULONG_MAX, 400L )==FD_PACK_BOBS_PHASE_LATE  );
  FD_TEST( fd_pack_bobs_phase( 1400L, 1, 1000L, 1300L, 0L, ULONG_MAX, 400L )==FD_PACK_BOBS_PHASE_LATE  );

  /* Never leader */
  FD_TEST( fd_pack_bobs_phase( 5000L, 0, 0L, 0L, 0L, ULONG_MAX, 400L )==FD_PACK_BOBS_PHASE_BEFORE_WINDOW );
  /* Just after the last slot of a rotation (slot 103) */
  FD_TEST( fd_pack_bobs_phase( 1350L, 0, 0L, 0L, 1300L, 103UL, 400L )==FD_PACK_BOBS_PHASE_AFTER_WINDOW );
  /* Between two of our slots (slot 101 ended, 102 next) */
  FD_TEST( fd_pack_bobs_phase( 1350L, 0, 0L, 0L, 1300L, 101UL, 400L )==FD_PACK_BOBS_PHASE_EARLY );
  /* Long after our window */
  FD_TEST( fd_pack_bobs_phase( 1700L, 0, 0L, 0L, 1300L, 103UL, 400L )==FD_PACK_BOBS_PHASE_BEFORE_WINDOW );
}

static void
test_cause( void ) {
  FD_TEST( fd_pack_bobs_cause_exec( 1, FD_PACK_BOBS_EXEC_ERR_UNKNOWN, 0UL )==FD_PACK_BOBS_CAUSE_LANDED );
  FD_TEST( fd_pack_bobs_cause_exec( 0, FD_PACK_BOBS_EXEC_ERR_INSTRUCTION, FD_PACK_WRITER_TXN    | (2UL<<8) )==FD_PACK_BOBS_CAUSE_EXEC_STATE_TPU    );
  FD_TEST( fd_pack_bobs_cause_exec( 0, FD_PACK_BOBS_EXEC_ERR_INSTRUCTION, FD_PACK_WRITER_BUNDLE | (1UL<<8) )==FD_PACK_BOBS_CAUSE_EXEC_STATE_BUNDLE );
  FD_TEST( fd_pack_bobs_cause_exec( 0, FD_PACK_BOBS_EXEC_ERR_INSTRUCTION, FD_PACK_WRITER_VOTE   | (1UL<<8) )==FD_PACK_BOBS_CAUSE_EXEC_STATE_OTHER  );
  FD_TEST( fd_pack_bobs_cause_exec( 0, FD_PACK_BOBS_EXEC_ERR_INSTRUCTION, FD_PACK_WRITER_NONE              )==FD_PACK_BOBS_CAUSE_EXEC_STATE_OTHER  );
  FD_TEST( fd_pack_bobs_cause_exec( 0, FD_PACK_BOBS_EXEC_ERR_DUPLICATE,   FD_PACK_WRITER_TXN               )==FD_PACK_BOBS_CAUSE_EXEC_DUPLICATE    );
  FD_TEST( fd_pack_bobs_cause_exec( 0, FD_PACK_BOBS_EXEC_ERR_OTHER,       0UL                              )==FD_PACK_BOBS_CAUSE_EXEC_OTHER        );
  FD_TEST( fd_pack_bobs_cause_exec( 0, FD_PACK_BOBS_EXEC_ERR_UNKNOWN,     0UL                              )==FD_PACK_BOBS_CAUSE_EXEC_UNKNOWN      );

  ulong zero[ FD_PACK_BOBS_REASON_CNT ] = {0};
  ulong d   [ FD_PACK_BOBS_REASON_CNT ] = {0};
  d[ FD_PACK_BOBS_REASON_LANE_BUNDLE ] = 5UL;
  d[ FD_PACK_BOBS_REASON_LANE_VOTE   ] = 7UL;

  /* A copy landed elsewhere beats everything */
  FD_TEST( fd_pack_bobs_cause_unscheduled( FD_PACK_BUNDLE_LEAVE_DELETED, d,    FD_PACK_BOBS_PHASE_AFTER_WINDOW )==FD_PACK_BOBS_CAUSE_DUP_DELETED );
  /* Then the largest blocked reason */
  FD_TEST( fd_pack_bobs_cause_unscheduled( FD_PACK_BUNDLE_LEAVE_EXPIRED, d,    FD_PACK_BOBS_PHASE_AFTER_WINDOW )==FD_PACK_BOBS_CAUSE_BLOCKED_BASE+FD_PACK_BOBS_REASON_LANE_VOTE );
  FD_TEST( fd_pack_bobs_cause_unscheduled( FD_PACK_BUNDLE_LEAVE_EVICTED, d,    FD_PACK_BOBS_PHASE_EARLY        )==FD_PACK_BOBS_CAUSE_BLOCKED_BASE+FD_PACK_BOBS_REASON_LANE_VOTE );
  /* Never waited in a window */
  FD_TEST( fd_pack_bobs_cause_unscheduled( FD_PACK_BUNDLE_LEAVE_EXPIRED, zero, FD_PACK_BOBS_PHASE_AFTER_WINDOW  )==FD_PACK_BOBS_CAUSE_LATE    );
  FD_TEST( fd_pack_bobs_cause_unscheduled( FD_PACK_BUNDLE_LEAVE_EXPIRED, zero, FD_PACK_BOBS_PHASE_BEFORE_WINDOW )==FD_PACK_BOBS_CAUSE_EXPIRED );
  FD_TEST( fd_pack_bobs_cause_unscheduled( FD_PACK_BUNDLE_LEAVE_EVICTED, zero, FD_PACK_BOBS_PHASE_BEFORE_WINDOW )==FD_PACK_BOBS_CAUSE_EVICTED );
  FD_TEST( fd_pack_bobs_cause_unscheduled( FD_PACK_BUNDLE_LEAVE_REPLACED,zero, FD_PACK_BOBS_PHASE_MID           )==FD_PACK_BOBS_CAUSE_EVICTED );

  FD_TEST( !fd_pack_bobs_cause_is_missed( FD_PACK_BOBS_CAUSE_LANDED            ) );
  FD_TEST( !fd_pack_bobs_cause_is_missed( FD_PACK_BOBS_CAUSE_EXEC_STATE_BUNDLE ) );
  FD_TEST( !fd_pack_bobs_cause_is_missed( FD_PACK_BOBS_CAUSE_DUP_DELETED       ) );
  FD_TEST(  fd_pack_bobs_cause_is_missed( FD_PACK_BOBS_CAUSE_LATE              ) );
  FD_TEST(  fd_pack_bobs_cause_is_missed( FD_PACK_BOBS_CAUSE_EXEC_STATE_TPU    ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_pack_bobs_footprint( ELE_MAX, PACK_IDX_MAX )<=sizeof(mem) );
  FD_TEST( !fd_pack_bobs_new( NULL, ELE_MAX, PACK_IDX_MAX ) );
  FD_TEST( !fd_pack_bobs_new( mem,  0UL,     PACK_IDX_MAX ) );
  fd_pack_bobs_t * bobs = fd_pack_bobs_join( fd_pack_bobs_new( mem, ELE_MAX, PACK_IDX_MAX ) );
  FD_TEST( bobs );

  test_blocked( bobs );
  test_pool( bobs );
  test_phase();
  test_cause();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
