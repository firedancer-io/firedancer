#define _GNU_SOURCE
#include "../../util/fd_util.h"
#include "fd_circq.h"

#include <sys/mman.h>
#include <unistd.h>

static void
test_fuzz( void ) {
  uchar buf[ 128UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 128 ) );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( ulong i=0UL; i<4UL*1024UL*1024UL; i++ ) {
    uchar * msg = fd_circq_push_back( circq, fd_ulong_pow2( (int)fd_rng_ulong_roll( rng, 5 ) ), 1UL+fd_rng_ulong_roll( rng, 64 ) );
    FD_TEST( msg );
  }
}

static void
test_cursor_lifecycle( void ) {
  uchar buf[ 256UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
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
  uchar buf[ 512UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
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
  msg = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( msg[0]=='E' );

  FD_TEST( fd_circq_pop_until( circq, cursors[4] )==0 );
  FD_TEST( circq->cnt==0 );
}

static void
test_pop_until_rejects_unadvanced_cursor( void ) {
  uchar buf[ 512UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 512UL ) );
  ulong msg_sz;

  for( ulong i=0UL; i<3UL; i++ ) {
    uchar * msg = fd_circq_push_back( circq, 1UL, 16UL );
    msg[0] = (uchar)('A' + i);
  }

  uchar const * advanced = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( advanced );
  FD_TEST( advanced[0]=='A' );

  ulong advanced_cursor   = circq->cursor_seq - 1UL;
  ulong unadvanced_cursor = advanced_cursor + 1UL;

  FD_TEST( unadvanced_cursor<circq->cursor_push_seq );
  FD_TEST( unadvanced_cursor>=circq->cursor_seq );

  FD_TEST( fd_circq_pop_until( circq, unadvanced_cursor )==-1 );
  FD_TEST( circq->cnt==3UL );

  FD_TEST( fd_circq_pop_until( circq, advanced_cursor )==0 );
  FD_TEST( circq->cnt==2UL );

  fd_circq_reset_cursor( circq );
  uchar const * first = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( first );
  FD_TEST( first[0]=='B' );
}

static void
test_wraparound_iteration( void ) {
  uchar buf[ 256UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
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
  uchar buf[ 512UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
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
  uchar buf[ 256UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
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

/* push so many elements that the cursor head got evicted */

static void
test_overrun_recover( void ) {
  uchar buf[ 192UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 192UL ) );
  ulong msg_sz = 0UL;

  uchar * a = fd_circq_push_back( circq, 1UL, 8UL );
  uchar * b = fd_circq_push_back( circq, 1UL, 8UL );
  FD_TEST( a && b );
  a[0] = 'A';
  b[0] = 'B';

  uchar const * first = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( first );
  FD_TEST( first[0]=='A' );
  FD_TEST( msg_sz==8UL );

  uchar * c = fd_circq_push_back( circq, 1UL, 112UL );
  FD_TEST( c );
  c[0] = 'C';

  FD_TEST( circq->cnt==1UL );
  FD_TEST( circq->cursor==ULONG_MAX );

  uchar const * survivor = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( survivor );
  /* B skipped */
  FD_TEST( survivor[0]=='C' );
  FD_TEST( msg_sz==112UL );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );
}

/* manually pop so much that cursor gets evicted */

static void
test_pop_recover( void ) {
  uchar buf[ 256UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 256UL ) );
  ulong msg_sz = 0UL;

  for( ulong i=0UL; i<3UL; i++ ) {
    uchar * msg = fd_circq_push_back( circq, 1UL, 8UL );
    FD_TEST( msg );
    msg[0] = (uchar)('A' + i);
  }

  uchar const * first = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( first );
  FD_TEST( first[0]=='A' );

  ulong cursor_a = circq->cursor_seq - 1UL;
  FD_TEST( fd_circq_pop_until( circq, cursor_a )==0 );
  FD_TEST( circq->cursor==ULONG_MAX );

  uchar const * next = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( next );
  FD_TEST( next[0]=='B' );
}

static void
test_cursor_sequence_monotonicity( void ) {
  uchar buf[ 512UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
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
  uchar buf[ 256UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 256UL ) );
  ulong msg_sz;

  uchar * msg = fd_circq_push_back( circq, 1UL, 8UL );
  FD_TEST( msg );

  FD_TEST( fd_circq_pop_until( circq, ULONG_MAX )==-1 );
  FD_TEST( circq->cnt==1 );

  uchar const * out0 = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( out0 );

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

/* Spool tests: a two-tier queue over a small memory window plus a
   file ring.  Messages carry their push seq at [0] so order and
   contiguity can be checked end to end. */

#define SPOOL_MSG_SZ (256UL)

static int
spool_fd_new( ulong cap ) {
  int fd = memfd_create( "test_circq_spool", 0U );
  FD_TEST( fd>=0 );
  FD_TEST( !ftruncate( fd, (off_t)cap ) );
  return fd;
}

static void
spool_push( fd_circq_t * circq,
            ulong        id ) {
  uchar * msg = fd_circq_push_back( circq, 1UL, SPOOL_MSG_SZ );
  FD_TEST( msg );
  FD_TEST( circq->cursor_push_seq-1UL==id );
  FD_STORE( ulong, msg, id );
  for( ulong i=8UL; i<SPOOL_MSG_SZ; i++ ) msg[ i ] = (uchar)(id+i);
}

static ulong
spool_check_next( fd_circq_t * circq ) {
  ulong msg_sz;
  uchar const * msg = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( msg );
  FD_TEST( msg_sz==SPOOL_MSG_SZ );
  ulong id = FD_LOAD( ulong, msg );
  for( ulong i=8UL; i<SPOOL_MSG_SZ; i++ ) FD_TEST( msg[ i ]==(uchar)(id+i) );
  return id;
}

static void
test_spool_migration( void ) {
  static uchar buf[ 4096UL+4096UL+SPOOL_MSG_SZ ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 4096UL ) );
  int fd = spool_fd_new( 1UL<<20UL );
  fd_circq_spool_init( circq, fd, 1UL<<20UL, SPOOL_MSG_SZ );
  ulong msg_sz;

  /* Push far more than the memory window holds: oldest migrate to the
     spool, nothing drops. */
  for( ulong i=0UL; i<100UL; i++ ) spool_push( circq, i );
  FD_TEST( circq->spool_cnt>0UL );
  FD_TEST( circq->cnt+circq->spool_cnt==100UL );
  FD_TEST( !circq->metrics.drop_cnt );
  FD_TEST( fd_circq_unsent_cnt( circq )==100UL );

  /* Iterate everything in order across both tiers. */
  for( ulong i=0UL; i<100UL; i++ ) FD_TEST( spool_check_next( circq )==i );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );
  FD_TEST( !fd_circq_unsent_cnt( circq ) );

  /* Ack into the spool region, then into the memory region. */
  FD_TEST( !fd_circq_pop_until( circq, 10UL ) );
  FD_TEST( circq->cnt+circq->spool_cnt==89UL );
  ulong ram_cnt = circq->cnt;
  FD_TEST( !fd_circq_pop_until( circq, 99UL-ram_cnt+2UL ) );
  FD_TEST( !circq->spool_cnt );
  FD_TEST( circq->cnt==ram_cnt-2UL );

  /* Reconnect: reset and resend the remaining unacked tail. */
  fd_circq_reset_cursor( circq );
  for( ulong i=0UL; i<ram_cnt-2UL; i++ ) FD_TEST( spool_check_next( circq )==99UL-ram_cnt+3UL+i );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );

  FD_TEST( !fd_circq_pop_until( circq, 99UL ) );
  FD_TEST( !circq->cnt && !circq->spool_cnt );
  FD_TEST( !circq->spool_bytes );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );
  FD_TEST( !close( fd ) );
}

static void
test_spool_drop_oldest( void ) {
  static uchar buf[ 4096UL+4096UL+SPOOL_MSG_SZ ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 4096UL ) );
  ulong cap = 4096UL;
  int fd = spool_fd_new( cap );
  fd_circq_spool_init( circq, fd, cap, SPOOL_MSG_SZ );
  ulong msg_sz;

  /* Overflow memory AND spool: oldest drop, the surviving window is a
     contiguous tail ending at the newest push. */
  for( ulong i=0UL; i<200UL; i++ ) spool_push( circq, i );
  FD_TEST( circq->metrics.drop_cnt>0UL );
  ulong live = circq->cnt+circq->spool_cnt;
  FD_TEST( live<200UL );

  ulong expected = 200UL-live;
  for( ulong i=0UL; i<live; i++ ) FD_TEST( spool_check_next( circq )==expected+i );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );
  FD_TEST( !close( fd ) );
}

static void
test_spool_wrap_cycles( void ) {
  static uchar buf[ 4096UL+4096UL+SPOOL_MSG_SZ ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 4096UL ) );
  ulong cap = 8192UL;
  int fd = spool_fd_new( cap );
  fd_circq_spool_init( circq, fd, cap, SPOOL_MSG_SZ );
  ulong msg_sz;

  /* Steady spill/ack cycles force the file ring tail to wrap many
     times without ever dropping. */
  ulong id = 0UL;
  ulong acked = 0UL;
  for( ulong round=0UL; round<50UL; round++ ) {
    for( ulong i=0UL; i<20UL; i++ ) spool_push( circq, id++ );
    fd_circq_reset_cursor( circq );
    ulong live = circq->cnt+circq->spool_cnt;
    FD_TEST( acked+live==id );
    for( ulong i=0UL; i<live; i++ ) FD_TEST( spool_check_next( circq )==acked+i );
    FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );
    /* Ack all but 5, leaving a tail that straddles the tiers over
       time. */
    FD_TEST( !fd_circq_pop_until( circq, id-6UL ) );
    acked = id-5UL;
    FD_TEST( circq->cnt+circq->spool_cnt==5UL );
  }
  FD_TEST( !circq->metrics.drop_cnt );
  FD_TEST( !close( fd ) );
}

static void
test_bounds( void ) {
  uchar buf[ 128UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
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
  test_pop_until_rejects_unadvanced_cursor();
  FD_LOG_NOTICE(( "pass: pop_until_rejects_unadvanced_cursor" ));
  test_wraparound_iteration();         FD_LOG_NOTICE(( "pass: wraparound_iteration" ));
  test_interleaved_ops();              FD_LOG_NOTICE(( "pass: interleaved_ops" ));
  test_stale_cursor_handling();        FD_LOG_NOTICE(( "pass: stale_cursor_handling" ));
  test_overrun_recover();              FD_LOG_NOTICE(( "pass: overrun_recover" ));
  test_pop_recover();                  FD_LOG_NOTICE(( "pass: pop_recover" ));
  test_cursor_sequence_monotonicity(); FD_LOG_NOTICE(( "pass: cursor_sequence_monotonicity" ));
  test_edge_cases();                   FD_LOG_NOTICE(( "pass: edge_cases" ));
  test_spool_migration();              FD_LOG_NOTICE(( "pass: spool_migration" ));
  test_spool_drop_oldest();            FD_LOG_NOTICE(( "pass: spool_drop_oldest" ));
  test_spool_wrap_cycles();            FD_LOG_NOTICE(( "pass: spool_wrap_cycles" ));
  test_bounds();                       FD_LOG_NOTICE(( "pass: bounds" ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
