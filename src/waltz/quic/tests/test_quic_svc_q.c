#include "../fd_quic_svc_q.h"
#include "../fd_quic_private.h"
#include "../fd_quic_conn.h"

#include <stdlib.h>

/* Mock connection structure for testing */
static uchar *
create_mock_conns( fd_quic_limits_t * limits,
                   ulong              conn_cnt ) {

  ulong   footprint = fd_quic_conn_footprint( limits );
  uchar * conn_mem  = aligned_alloc( fd_quic_conn_align(), footprint * conn_cnt );
  FD_TEST( conn_mem );

  for( uint i=0; i<conn_cnt; i++ ) {
    fd_quic_conn_t * conn = (fd_quic_conn_t *)(conn_mem + i * footprint);
    conn->conn_idx        = i;
    fd_quic_svc_timers_init_conn( conn );
  }

  return conn_mem;
}

static fd_quic_svc_timers_t *
test_svc_timers_init( ulong   max_conn,
                      uchar** out_to_free ) {
  FD_LOG_NOTICE(( "Testing fd_quic_svc_timers_init" ));

  ulong footprint = fd_quic_svc_timers_footprint( max_conn );
  FD_TEST( footprint > 0UL );

  uchar * mem = aligned_alloc( fd_quic_svc_timers_align(), footprint );
  FD_TEST( mem );
  *out_to_free = mem;

  fd_quic_svc_timers_t * timers = fd_quic_svc_timers_init( mem, max_conn );
  FD_TEST( timers );

  FD_LOG_NOTICE(( "fd_quic_svc_timers_init test passed" ));

  return timers;
}

static void
test_svc_schedule( fd_quic_svc_timers_t * timers,
                   fd_quic_conn_t       * conn ) {
  FD_LOG_NOTICE(( "Testing fd_quic_svc_schedule" ));

  /* Test basic scheduling */
  long now = 1000L;
  conn->svc_meta.next_timeout = now + 100L;
  fd_quic_svc_schedule( timers, conn );

  /* Verify the connection is scheduled */
  FD_TEST( conn->svc_meta.idx != FD_QUIC_SVC_IDX_INVAL );

  /* Test rescheduling with earlier time */
  conn->svc_meta.next_timeout = now + 50L;
  fd_quic_svc_schedule( timers, conn );
  FD_TEST( conn->svc_meta.idx != FD_QUIC_SVC_IDX_INVAL );

  /* Test rescheduling with later time (should be ignored) */
  conn->svc_meta.next_timeout = now + 150L;
  fd_quic_svc_schedule( timers, conn );

  /* Verify we kept the earlier time */
  fd_quic_svc_event_t next = fd_quic_svc_timers_next( timers, now, 0 );
  FD_TEST( next.timeout == now + 50UL );

  FD_LOG_NOTICE(( "fd_quic_svc_schedule test passed" ));
}

static void
test_svc_cancel( fd_quic_svc_timers_t * timers,
                 fd_quic_conn_t       * conn ) {
  FD_LOG_NOTICE(( "Testing fd_quic_svc_cancel" ));

  /* Schedule event */
  long now = 1000UL;
  conn->svc_meta.next_timeout = now + 100UL;
  fd_quic_svc_schedule( timers, conn );
  FD_TEST( conn->svc_meta.idx != FD_QUIC_SVC_IDX_INVAL );

  /* Cancel and verify */
  fd_quic_svc_cancel( timers, conn );
  FD_TEST( conn->svc_meta.idx == FD_QUIC_SVC_IDX_INVAL );

  /* Verify queue is empty */
  fd_quic_svc_event_t next = fd_quic_svc_timers_next( timers, now, 0 );
  FD_TEST( next.conn == NULL );

  FD_LOG_NOTICE(( "fd_quic_svc_cancel test passed" ));
}

static void
test_multiple_connections( fd_quic_svc_timers_t * timers,
                           fd_quic_limits_t     * limits ) {
  FD_LOG_NOTICE(( "Testing multiple connections" ));

  ulong   conn_cnt  = limits->conn_cnt;
  uchar * conn_base = create_mock_conns( limits, conn_cnt );
  ulong   conn_sz   = fd_quic_conn_footprint( limits );

  fd_quic_conn_t * conns[conn_cnt]; /* array of conn ptrs */
  for( uint i=0; i<conn_cnt; i++ ) {
    conns[i] = (fd_quic_conn_t *)(conn_base + i * conn_sz);
  }

  long now = 1000UL;

  /* Schedule connections in order */
  for( int i=0; i<10; i++ ) {
    conns[i]->svc_meta.next_timeout = now + (ulong)(i * 10);
    fd_quic_svc_schedule( timers, conns[i] );
  }

  /* Pop them in order and verify */
  for( int i=0; i<10; i++ ) {
    fd_quic_svc_event_t next = fd_quic_svc_timers_next( timers, now + 100UL, 1 );
    FD_TEST( next.conn    == conns[i] );
    FD_TEST( next.timeout == now + (ulong)(i * 10) );
  }

  /* Queue should be empty now */
  fd_quic_svc_event_t next = fd_quic_svc_timers_next( timers, now + 100UL, 0 );
  FD_TEST( next.conn == NULL );

  /* Schedule out of order and verify they come out in order */
  for( int i=9; i>=0; i-- ) {
    conns[i]->svc_meta.next_timeout = now + (ulong)(i * 10);
    fd_quic_svc_schedule( timers, conns[i] );
  }

  do {
    /* sad stuff for connection validation */
    ulong quic_footprint       = fd_quic_footprint( limits );
    ulong quic_align           = fd_quic_align();
    ulong quic_ftprint_aligned = fd_ulong_align_up( quic_footprint, quic_align );
    FD_TEST( quic_ftprint_aligned > 0UL );

    fd_quic_t *      quic  = aligned_alloc( fd_quic_align(), quic_ftprint_aligned );
    fd_quic_state_t* state = fd_quic_get_state( quic );
    quic->limits           = *limits;
    state->conn_base       = (ulong)conn_base;
    state->conn_sz         = conn_sz;

    fd_quic_conn_validate_init( quic );
    FD_TEST( fd_quic_svc_timers_validate( timers, quic ) );
    free( quic );

  } while( 0 );

  /* Pop them in order and verify */
  for( int i=0; i<10; i++ ) {
    fd_quic_svc_event_t next = fd_quic_svc_timers_next( timers, now + 100UL, 1 );
    FD_TEST( next.conn    == conns[i] );
    FD_TEST( next.timeout == now + (ulong)(i * 10) );
  }

  /* Queue should be empty now */
  next = fd_quic_svc_timers_next( timers, now + 100UL, 0 );
  FD_TEST( next.conn == NULL );

  free( conn_base );

  FD_LOG_NOTICE(( "Multiple connections test passed" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  const ulong max_conn = 10UL;

  /* Allocate a large buffer upfront */
  fd_quic_limits_t limits = {
    .inflight_frame_cnt = 10*max_conn,
    .conn_cnt           = max_conn,
    .conn_id_cnt        = max_conn,
    .handshake_cnt      = 10,
    .log_depth          = 1,
    .tx_buf_sz          = 256,
    .stream_pool_cnt    = 10,
    .stream_id_cnt      = 10
  };

  FD_LOG_NOTICE(( "Starting fd_quic_svc_q tests" ));

  uchar* timer_base;
  fd_quic_svc_timers_t * timers = test_svc_timers_init( max_conn, &timer_base );

  {
    fd_quic_conn_t * conn = (fd_quic_conn_t *)create_mock_conns( &limits , 1);
    test_svc_schedule( timers, conn );
    test_svc_cancel( timers, conn );
    free( conn );
  }

  test_multiple_connections( timers, &limits );

  free( timer_base );

  FD_LOG_NOTICE(( "All fd_quic_svc_q tests passed" ));

  return 0;
}
