#include "../../util/fd_util.h"
#include "fd_circq.h"

static void
test_fuzz( void ) {
  uchar buf[ 128UL+4096UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 128 ) );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( ulong i=0UL; i<8192UL*8192UL; i++ ) {
    uchar * msg = fd_circq_push_back( circq, fd_ulong_pow2( (int)fd_rng_ulong_roll( rng, 5 ) ), 1UL+fd_rng_ulong_roll( rng, 64 ) );
    FD_TEST( msg );
  }
}

static void
test_cursor_lifecycle( void ) {
  uchar buf[ 256UL+4096UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 256UL ) );
  ulong msg_sz;

  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );

  uchar * msg1 = fd_circq_push_back( circq, 1UL, 8UL );
  msg1[0] = 'A';
  msg1[7] = 'B';

  uchar const * out1 = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( out1[0]=='A' && out1[7]=='B' );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );

  uchar * msg2 = fd_circq_push_back( circq, 1UL, 8UL );
  msg2[0] = 'C';
  msg2[7] = 'D';

  uchar const * out2 = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( out2[0]=='C' && out2[7]=='D' );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );

  fd_circq_reset_cursor( circq );
  out1 = fd_circq_cursor_advance( circq, &msg_sz );
  out2 = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( out1[0]=='A' && out2[0]=='C' );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );
}

static void
test_ack_protocol( void ) {
  uchar buf[ 512UL+4096UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 512UL ) );
  ulong msg_sz;

  for( ulong i=0; i<5; i++ ) {
    uchar * msg = fd_circq_push_back( circq, 1UL, 16UL );
    msg[0] = (uchar)('A' + i);
  }

  FD_TEST( circq->cnt==5 );

  ulong cursors[5];
  for( ulong i=0; i<5; i++ ) {
    uchar const * msg = fd_circq_cursor_advance( circq, &msg_sz );
    FD_TEST( msg[0]==(uchar)('A'+i) );
    cursors[i] = circq->cursor_seq - 1;
  }

  FD_TEST( fd_circq_pop_until( circq, cursors[2] )==0 );
  FD_TEST( circq->cnt==2 );

  fd_circq_reset_cursor( circq );
  uchar const * msg = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( msg[0]=='D' );

  FD_TEST( fd_circq_pop_until( circq, cursors[4] )==0 );
  FD_TEST( circq->cnt==0 );
}

static void
test_wraparound_iteration( void ) {
  uchar buf[ 256UL+4096UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 256UL ) );
  ulong msg_sz;

  for( ulong round=0; round<3; round++ ) {
    for( ulong i=0; i<8; i++ ) {
      uchar * msg = fd_circq_push_back( circq, 1UL, 20UL );
      msg[0] = (uchar)('0' + round);
      msg[1] = (uchar)('a' + i);
    }

    fd_circq_reset_cursor( circq );
    for( ulong i=0; i<circq->cnt; i++ ) {
      uchar const * msg = fd_circq_cursor_advance( circq, &msg_sz );
      FD_TEST( msg );
      FD_TEST( msg[0]>='0' && msg[0]<='9' );
      FD_TEST( msg[1]>='a' && msg[1]<='z' );
    }
  }
}

static void
test_interleaved_ops( void ) {
  uchar buf[ 512UL+4096UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 512UL ) );
  ulong msg_sz;

  for( ulong i=0; i<4; i++ ) {
    uchar * msg = fd_circq_push_back( circq, 1UL, 16UL );
    msg[0] = (uchar)('W' + i);
  }

  uchar const * m1 = fd_circq_cursor_advance( circq, &msg_sz );
  uchar const * m2 = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( m1[0]=='W' && m2[0]=='X' );

  ulong cursor_x = circq->cursor_seq - 1;

  for( ulong i=0; i<3; i++ ) {
    uchar * msg = fd_circq_push_back( circq, 1UL, 16UL );
    msg[0] = (uchar)('a' + i);
  }

  uchar const * m3 = fd_circq_cursor_advance( circq, &msg_sz );
  uchar const * m4 = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( m3[0]=='Y' && m4[0]=='Z' );

  FD_TEST( fd_circq_pop_until( circq, cursor_x )==0 );

  fd_circq_reset_cursor( circq );
  uchar const * first = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( first[0]=='Y' );
}

static void
test_stale_cursor_handling( void ) {
  uchar buf[ 256UL+4096UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 256UL ) );
  ulong msg_sz;

  for( ulong i=0; i<10; i++ ) {
    uchar * msg = fd_circq_push_back( circq, 1UL, 8UL );
    msg[0] = (uchar)('0' + i);
  }

  uchar const * msg = fd_circq_cursor_advance( circq, &msg_sz );
  ulong old_cursor = circq->cursor_seq - 1;
  ulong old_cnt = circq->cnt;

  uchar * evict = fd_circq_push_back( circq, 1UL, 200UL );
  FD_TEST( evict );
  FD_TEST( circq->cnt < old_cnt );

  FD_TEST( fd_circq_pop_until( circq, old_cursor )==0 );

  fd_circq_reset_cursor( circq );
  msg = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( msg );
}

static void
test_cursor_sequence_monotonicity( void ) {
  uchar buf[ 512UL+4096UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 512UL ) );
  ulong msg_sz;

  ulong last_push_seq = circq->cursor_push_seq;
  ulong last_cursor_seq = 0;

  for( ulong i=0; i<100; i++ ) {
    uchar * msg = fd_circq_push_back( circq, 1UL, 4UL );
    FD_TEST( msg );
    FD_TEST( circq->cursor_push_seq > last_push_seq );
    last_push_seq = circq->cursor_push_seq;

    if( i % 10 == 0 ) {
      fd_circq_reset_cursor( circq );
      last_cursor_seq = 0;
    }

    uchar const * out = fd_circq_cursor_advance( circq, &msg_sz );
    if( out ) {
      FD_TEST( circq->cursor_seq > last_cursor_seq );
      last_cursor_seq = circq->cursor_seq;
    }
  }
}

static void
test_edge_cases( void ) {
  uchar buf[ 256UL+4096UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 256UL ) );
  ulong msg_sz;

  uchar * msg = fd_circq_push_back( circq, 1UL, 8UL );
  FD_TEST( msg );

  FD_TEST( fd_circq_pop_until( circq, ULONG_MAX )==-1 );
  FD_TEST( circq->cnt==1 );

  FD_TEST( fd_circq_pop_until( circq, 0 )==0 );
  FD_TEST( circq->cnt==0 );

  fd_circq_reset_cursor( circq );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );

  for( ulong i=0; i<3; i++ ) {
    msg = fd_circq_push_back( circq, 1UL, 8UL );
    FD_TEST( msg );
  }

  fd_circq_reset_cursor( circq );
  fd_circq_reset_cursor( circq );

  uchar const * out = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( out );
}

static void
test_bounds( void ) {
  uchar buf[ 128UL+4096UL ];
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 1024UL ) );

  FD_TEST( fd_circq_push_back( circq, 1UL, 1024UL-25UL ) );
  FD_TEST( fd_circq_push_back( circq, 1UL, 1024UL-24UL ) );
  FD_TEST( fd_circq_push_back( circq, 8UL, 1024UL-24UL ) );
  FD_TEST( !fd_circq_push_back( circq, 1UL, 1024UL-23UL ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_fuzz();                         FD_LOG_NOTICE(( "pass: fuzz" ));
  test_cursor_lifecycle();             FD_LOG_NOTICE(( "pass: cursor_lifecycle" ));
  test_ack_protocol();                 FD_LOG_NOTICE(( "pass: ack_protocol" ));
  test_wraparound_iteration();         FD_LOG_NOTICE(( "pass: wraparound_iteration" ));
  test_interleaved_ops();              FD_LOG_NOTICE(( "pass: interleaved_ops" ));
  test_stale_cursor_handling();        FD_LOG_NOTICE(( "pass: stale_cursor_handling" ));
  test_cursor_sequence_monotonicity(); FD_LOG_NOTICE(( "pass: cursor_sequence_monotonicity" ));
  test_edge_cases();                   FD_LOG_NOTICE(( "pass: edge_cases" ));
  test_bounds();                       FD_LOG_NOTICE(( "pass: bounds" ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
