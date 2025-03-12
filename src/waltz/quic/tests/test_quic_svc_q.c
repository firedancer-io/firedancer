#include "../fd_quic_svc_q.h"
#include "../fd_quic_private.h"
#include "../fd_quic_conn.h"

/* Mock connection structure for testing */
static fd_quic_conn_t *
create_mock_conn( uchar ** buf_ptr ) {
  fd_quic_conn_t * conn = (fd_quic_conn_t *)*buf_ptr;
  *buf_ptr += sizeof( fd_quic_conn_t );

  fd_quic_svc_timers_init_conn( conn );

  return conn;
}

static fd_quic_svc_timers_t *
test_svc_timers_init( uchar ** buf_ptr, ulong max_conn, ulong reserved_sz ) {
  FD_LOG_NOTICE(( "Testing fd_quic_svc_timers_init" ));

  ulong footprint = fd_quic_svc_timers_footprint( max_conn );
  FD_TEST( footprint > 0UL );
  FD_TEST( reserved_sz >= footprint ); /* if this fails, increase reserved_sz */

  uchar * mem = *buf_ptr;
  mem = (uchar *)fd_ulong_align_up( (ulong)mem, fd_quic_svc_timers_align() );
  FD_TEST( mem );

  fd_quic_svc_timers_t * timers = fd_quic_svc_timers_init( mem, max_conn );
  FD_TEST( timers );

  FD_LOG_NOTICE(( "fd_quic_svc_timers_init test passed" ));

  *buf_ptr = (uchar*)(mem+footprint);
  return timers;
}

static void
test_svc_schedule( fd_quic_svc_timers_t * timers, fd_quic_conn_t * conn ) {
  FD_LOG_NOTICE(( "Testing fd_quic_svc_schedule" ));

  /* Test scheduling for each service type */
  ulong now = 1000UL;
  for( uint svc_type = 0; svc_type < FD_QUIC_SVC_CNT; svc_type++ ) {
    ulong expiry = now + 100UL * (svc_type + 1);
    fd_quic_svc_schedule( timers, conn, svc_type, expiry );

    /* Verify the connection is scheduled */
    FD_TEST( conn->svc_meta.idx[svc_type] != FD_QUIC_SVC_IDX_INVAL );

    /* Test rescheduling with earlier time */
    ulong earlier_expiry = expiry - 50UL;
    fd_quic_svc_schedule( timers, conn, svc_type, earlier_expiry );

    /* Test rescheduling with later time (should be ignored) */
    ulong later_expiry = expiry + 50UL;
    fd_quic_svc_schedule( timers, conn, svc_type, later_expiry );
  }

  /* Validate the queue structure */
  FD_TEST( fd_quic_svc_timers_validate( timers ) );

  FD_LOG_NOTICE(( "fd_quic_svc_schedule test passed" ));
}

static void
test_svc_schedule_later( fd_quic_svc_timers_t * timers, fd_quic_conn_t * conn ) {
  FD_LOG_NOTICE(( "Testing fd_quic_svc_schedule_later" ));

  /* Test scheduling for each service type */
  ulong now = 1000UL;
  for( uint svc_type = 0; svc_type < FD_QUIC_SVC_CNT; svc_type++ ) {
    ulong expiry = now + 100UL * (svc_type + 1);
    fd_quic_svc_schedule_later( timers, conn, svc_type, expiry );

    /* Verify the connection is scheduled */
    FD_TEST( conn->svc_meta.idx[svc_type] != FD_QUIC_SVC_IDX_INVAL );

    /* Test rescheduling with earlier time (should be ignored) */
    ulong earlier_expiry = expiry - 50UL;
    fd_quic_svc_schedule_later( timers, conn, svc_type, earlier_expiry );

    /* Test rescheduling with later time (should be accepted) */
    ulong later_expiry = expiry + 50UL;
    fd_quic_svc_schedule_later( timers, conn, svc_type, later_expiry );
  }

  /* Validate the queue structure */
  FD_TEST( fd_quic_svc_timers_validate( timers ) );

  FD_LOG_NOTICE(( "fd_quic_svc_schedule_later test passed" ));
}

static void
test_svc_cancel( fd_quic_svc_timers_t * timers, fd_quic_conn_t * conn ) {
  FD_LOG_NOTICE(( "Testing fd_quic_svc_cancel" ));

  /* Schedule events for all service types */
  ulong now = 1000UL;
  for( uint svc_type = 0; svc_type < FD_QUIC_SVC_CNT; svc_type++ ) {
    ulong expiry = now + 100UL * (svc_type + 1);
    fd_quic_svc_schedule( timers, conn, svc_type, expiry );
    FD_TEST( conn->svc_meta.idx[svc_type] != FD_QUIC_SVC_IDX_INVAL );
  }

  /* Cancel each service type one by one */
  for( uint svc_type = 0; svc_type < FD_QUIC_SVC_CNT; svc_type++ ) {
    fd_quic_svc_cancel( timers, conn, svc_type );
    FD_TEST( conn->svc_meta.idx[svc_type] == FD_QUIC_SVC_IDX_INVAL );

    /* Validate the queue structure after each cancellation */
    FD_TEST( fd_quic_svc_timers_validate( timers ) );
  }

  /* Test cancel_all */
  for( uint svc_type = 0; svc_type < FD_QUIC_SVC_CNT; svc_type++ ) {
    ulong expiry = now + 100UL * (svc_type + 1);
    fd_quic_svc_schedule( timers, conn, svc_type, expiry );
  }

  fd_quic_svc_cancel_all( timers, conn );

  for( uint svc_type = 0; svc_type < FD_QUIC_SVC_CNT; svc_type++ ) {
    FD_TEST( conn->svc_meta.idx[svc_type] == FD_QUIC_SVC_IDX_INVAL );
  }

  FD_LOG_NOTICE(( "fd_quic_svc_cancel test passed" ));
}

static void
test_svc_timers_next( fd_quic_svc_timers_t * timers, uchar ** buf_ptr ) {
  FD_LOG_NOTICE(( "Testing fd_quic_svc_timers_next" ));

  fd_quic_conn_t * conns[5];
  for( int i = 0; i < 5; i++ ) {
    conns[i] = create_mock_conn( buf_ptr );
  }

  ulong now = 1000UL;

  /* Schedule events with different priorities and times */
  fd_quic_svc_schedule( timers, conns[0], FD_QUIC_SVC_INSTANT, now + 10UL );
  fd_quic_svc_schedule( timers, conns[1], FD_QUIC_SVC_ACK_TX, now + 5UL );
  fd_quic_svc_schedule( timers, conns[2], FD_QUIC_SVC_RETX, now + 15UL );
  fd_quic_svc_schedule( timers, conns[3], FD_QUIC_SVC_RTT_SAMPLE, now + 20UL );
  fd_quic_svc_schedule( timers, conns[4], FD_QUIC_SVC_IDLE, now + 25UL );

  /* Test next without popping */
  fd_quic_svc_event_and_type_t next = fd_quic_svc_timers_next( timers, now + 30UL, 0 );
  FD_TEST( next.svc_type == FD_QUIC_SVC_INSTANT );
  FD_TEST( next.event.conn == conns[0] );

  /* Test next with popping */
  next = fd_quic_svc_timers_next( timers, now + 30UL, 1 );
  FD_TEST( next.svc_type == FD_QUIC_SVC_INSTANT );
  FD_TEST( next.event.conn == conns[0] );
  FD_TEST( conns[0]->svc_meta.idx[FD_QUIC_SVC_INSTANT] == FD_QUIC_SVC_IDX_INVAL );

  /* Next should be ACK_TX */
  next = fd_quic_svc_timers_next( timers, now + 30UL, 1 );
  FD_TEST( next.svc_type == FD_QUIC_SVC_ACK_TX );
  FD_TEST( next.event.conn == conns[1] );

  /* Next should be RETX */
  next = fd_quic_svc_timers_next( timers, now + 30UL, 1 );
  FD_TEST( next.svc_type == FD_QUIC_SVC_RETX );
  FD_TEST( next.event.conn == conns[2] );

  /* Next should be RTT_SAMPLE */
  next = fd_quic_svc_timers_next( timers, now + 30UL, 1 );
  FD_TEST( next.svc_type == FD_QUIC_SVC_RTT_SAMPLE );
  FD_TEST( next.event.conn == conns[3] );

  /* Next should be IDLE */
  next = fd_quic_svc_timers_next( timers, now + 30UL, 1 );
  FD_TEST( next.svc_type == FD_QUIC_SVC_IDLE );
  FD_TEST( next.event.conn == conns[4] );

  /* Queue should be empty now */
  next = fd_quic_svc_timers_next( timers, now + 30UL, 1 );
  FD_TEST( next.svc_type == FD_QUIC_SVC_CNT );

  FD_LOG_NOTICE(( "fd_quic_svc_timers_next test passed" ));
}

static void
test_multiple_connections( fd_quic_svc_timers_t * timers, uchar ** buf_ptr ) {
  FD_LOG_NOTICE(( "Testing multiple connections" ));

  fd_quic_conn_t * conns[10];
  for( uint i = 0; i < 10; i++ ) {
    conns[i] = create_mock_conn( buf_ptr );
    conns[i]->conn_idx = i;
  }

  ulong now = 1000UL;

  /* Schedule instant out of order */
  for( int i = 9; i >= 0; i-- ) {
    fd_quic_svc_schedule( timers, conns[i], FD_QUIC_SVC_INSTANT, now + (ulong)(i * 10) );
  }
  /* Validate it gets angry */
  FD_TEST( !fd_quic_svc_timers_validate( timers ) );
  /* cancel all */
  for( int i = 0; i < 10; i++ ) {
    fd_quic_svc_cancel_all( timers, conns[i] );
  }
  /* Confirm it's empty */
  FD_TEST( fd_quic_svc_timers_next( timers, now, 0 ).svc_type == FD_QUIC_SVC_CNT );

  /* Schedule instant in order */
  for( int i = 0; i < 10; i++ ) {
    fd_quic_svc_schedule( timers, conns[i], FD_QUIC_SVC_INSTANT, now + (ulong)(i * 10) );
  }
  /* Validate it gets happy */
  FD_TEST( fd_quic_svc_timers_validate( timers ) );

  /* Pop them in order */
  for( int i = 0; i < 10; i++ ) {
    fd_quic_svc_event_and_type_t next = fd_quic_svc_timers_next( timers, now + 100UL, 1 );
    FD_TEST( next.svc_type == FD_QUIC_SVC_INSTANT );
    FD_TEST( next.event.conn == conns[i] );
    FD_TEST( next.event.timeout == now + (ulong)(i * 10) );
  }

  /* Queue should be empty now */
  fd_quic_svc_event_and_type_t next = fd_quic_svc_timers_next( timers, now + 100UL, 1 );
  FD_TEST( next.svc_type == FD_QUIC_SVC_CNT );

  /* Do the same thing with SVC_RETX, but don't need ordering */

  /* Schedule out of order */
  for( int i = 9; i >= 0; i-- ) {
    fd_quic_svc_schedule( timers, conns[i], FD_QUIC_SVC_RETX, now + (ulong)(i * 10) );
  }
  /* Validate still OK */
  FD_TEST( fd_quic_svc_timers_validate( timers ) );

  /* Pop them in order */
  for( int i = 0; i < 10; i++ ) {
    fd_quic_svc_event_and_type_t next = fd_quic_svc_timers_next( timers, now + 100UL, 1 );
    FD_TEST( next.svc_type == FD_QUIC_SVC_RETX );
    FD_TEST( next.event.conn == conns[i] );
    FD_TEST( next.event.timeout == now + (ulong)(i * 10) );
  }

  /* Queue should be empty now */
  next = fd_quic_svc_timers_next( timers, now + 100UL, 0 );
  FD_TEST( next.svc_type == FD_QUIC_SVC_CNT );

  FD_LOG_NOTICE(( "Multiple connections test passed" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  /* Allocate a large buffer upfront */
  uchar buf[1024*1024] __attribute__(( aligned(8) ));
  uchar * buf_ptr = buf;

  ulong max_conn = 100UL;

  FD_LOG_NOTICE(( "Starting fd_quic_svc_q tests" ));

  fd_quic_svc_timers_t * timers = test_svc_timers_init( &buf_ptr, max_conn, sizeof(buf) );
  fd_quic_conn_t * conn = create_mock_conn( &buf_ptr );
  test_svc_schedule( timers, conn );
  test_svc_schedule_later( timers, conn );
  test_svc_cancel( timers, conn );
  test_svc_timers_next( timers, &buf_ptr );
  test_multiple_connections( timers, &buf_ptr );

  FD_LOG_NOTICE(( "All fd_quic_svc_q tests passed" ));

  return 0;
}
