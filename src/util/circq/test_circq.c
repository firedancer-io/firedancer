#include "../fd_util.h"
#include "fd_circq.h"

static void
test_fuzz( void ) {
  uchar buf[ 128UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 128 ) );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( ulong i=0UL; i<4UL*1024UL*1024UL; i++ ) {
    ulong   align = fd_ulong_pow2( (int)fd_rng_ulong_roll( rng, 5 ) );
    uchar * msg   = fd_circq_push_back( circq, align, 1UL+fd_rng_ulong_roll( rng, 64 ) );
    FD_TEST( msg );
    /* The returned payload must honor the requested alignment. */
    FD_TEST( fd_ulong_is_aligned( (ulong)msg, align ) );
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
  msg = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( msg[0]=='E' );

  FD_TEST( fd_circq_pop_until( circq, cursors[4] )==0 );
  FD_TEST( circq->cnt==0 );
}

static void
test_pop_until_rejects_unadvanced_cursor( void ) {
  uchar buf[ 512UL+4096UL ];
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
  uchar buf[ 256UL+4096UL ];
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

/* record the first byte and size of each evicted message in
   oldest-first order, plus the number of callback invocations */

struct evict_record {
  ulong cnt;
  ulong invocations;
  uchar tag[ 256UL ];
  ulong sz [ 256UL ];
};

typedef struct evict_record evict_record_t;

static void
record_evict_cb( void *                         ctx,
                 fd_circq_evict_entry_t const * batch,
                 ulong                          cnt ) {
  evict_record_t * rec = (evict_record_t *)ctx;
  FD_TEST( cnt>0UL );
  rec->invocations++;
  for( ulong i=0UL; i<cnt; i++ ) {
    FD_TEST( rec->cnt<256UL );
    rec->tag[ rec->cnt ] = batch[ i ].payload[ 0 ];
    rec->sz [ rec->cnt ] = batch[ i ].sz;
    rec->cnt++;
  }
}

static void
test_evict_callback_reactive( void ) {
  uchar buf[ 192UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 192UL ) );

  evict_record_t rec[1] = {0};
  fd_circq_set_batch_evict_cb( circq, record_evict_cb, rec );

  uchar * a = fd_circq_push_back( circq, 1UL, 8UL );
  uchar * b = fd_circq_push_back( circq, 1UL, 8UL );
  FD_TEST( a && b );
  a[0] = 'A';
  b[0] = 'B';

  FD_TEST( rec->cnt==0UL );

  /* This large push forces eviction of the front message(s). */
  uchar * c = fd_circq_push_back( circq, 1UL, 112UL );
  FD_TEST( c );
  c[0] = 'C';

  FD_TEST( circq->cnt==1UL );

  /* Both A and B were evicted, oldest-first, with their original
     first-byte tags and sizes; C itself is not evicted. */
  FD_TEST( rec->cnt==2UL );
  FD_TEST( rec->tag[0]=='A' && rec->sz[0]==8UL );
  FD_TEST( rec->tag[1]=='B' && rec->sz[1]==8UL );

  ulong msg_sz = 0UL;
  uchar const * survivor = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( survivor );
  FD_TEST( survivor[0]=='C' );
  FD_TEST( msg_sz==112UL );
}

/* fd_circq_pop_until delivers the popped messages to the batch eviction
   callback, oldest-first, and leaves the un-popped tail intact. */

static void
test_pop_until_callback( void ) {
  uchar buf[ 256UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 256UL ) );

  evict_record_t rec[1] = {0};
  fd_circq_set_batch_evict_cb( circq, record_evict_cb, rec );

  for( ulong i=0UL; i<5UL; i++ ) {
    uchar * m = fd_circq_push_back( circq, 1UL, 8UL );
    FD_TEST( m );
    m[0] = (uchar)('A' + i);
  }
  FD_TEST( rec->cnt==0UL ); /* no wrap yet -> no evictions during push */

  /* Advance the cursor over the three oldest messages, then pop_until
     the last of them.  The callback must observe exactly A,B,C in order. */
  ulong msg_sz   = 0UL;
  ulong last_seq = 0UL;
  for( ulong i=0UL; i<3UL; i++ ) {
    uchar const * m = fd_circq_cursor_advance( circq, &msg_sz );
    FD_TEST( m );
    last_seq = circq->cursor_seq-1UL; /* this message's own seq */
  }
  FD_TEST( !fd_circq_pop_until( circq, last_seq ) );

  FD_TEST( rec->cnt==3UL );
  FD_TEST( rec->tag[0]=='A' && rec->tag[1]=='B' && rec->tag[2]=='C' );
  FD_TEST( rec->sz[0]==8UL && rec->sz[1]==8UL && rec->sz[2]==8UL );

  /* The remaining two (D,E) are still present and in order. */
  fd_circq_reset_cursor( circq );
  uchar const * d = fd_circq_cursor_advance( circq, &msg_sz ); FD_TEST( d && d[0]=='D' );
  uchar const * e = fd_circq_cursor_advance( circq, &msg_sz ); FD_TEST( e && e[0]=='E' );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );
}

/* A single push that evicts a contiguous run of multiple messages
   delivers them in one oldest-first batch (one callback invocation), and
   a wrapping eviction that drops messages on both sides of the wrap
   arrives as separate invocations per contiguous run. */

static void
test_batch_evict_wrap( void ) {
  uchar buf[ 256UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 256UL ) );
  ulong msg_sz = 0UL;

  evict_record_t rec[1] = {0};
  fd_circq_set_batch_evict_cb( circq, record_evict_cb, rec );

  /* Each fp=1 message takes 24 (header) + 1 (payload), padded to a
     32-byte stride, so seven of them fill [0,224) of the 256-byte buffer
     without wrapping (head=0, tail=192). */
  for( ulong i=0UL; i<7UL; i++ ) {
    uchar * m = fd_circq_push_back( circq, 1UL, 1UL );
    FD_TEST( m );
    m[0] = (uchar)('a' + i);
  }
  FD_TEST( circq->cnt==7UL );
  FD_TEST( rec->cnt==0UL );

  /* This larger push evicts a contiguous run of more than one message in
     a single eviction: the callback fires exactly once with the dropped
     payloads in oldest-first order. */
  ulong before_cnt = rec->cnt;
  ulong before_inv = rec->invocations;
  uchar * big = fd_circq_push_back( circq, 1UL, 24UL );
  FD_TEST( big );
  big[0] = 'Z';

  FD_TEST( rec->invocations-before_inv==1UL );
  FD_TEST( rec->cnt-before_cnt>1UL );
  for( ulong i=before_cnt; i<rec->cnt; i++ ) {
    FD_TEST( rec->tag[ i ]==(uchar)('a' + (i-before_cnt)) );
    FD_TEST( rec->sz [ i ]==1UL );
  }

  /* Keep pushing alternating sizes until a single push yields >=2 cb
     invocations. */
  ulong baseline_invocations = rec->invocations;
  ulong push_invocations     = 0UL;
  for( ulong i=0UL; i<128UL; i++ ) {
    ulong before = rec->invocations;
    ulong fp = (i&1UL) ? 1UL : 48UL;
    uchar * m = fd_circq_push_back( circq, 1UL, fp );
    FD_TEST( m );
    m[0] = (uchar)('0' + (i%10UL));
    push_invocations = rec->invocations - before;
    if( push_invocations>=2UL ) break;
  }
  FD_TEST( push_invocations>=2UL );
  FD_TEST( rec->invocations>baseline_invocations );

  /* Sanity: the most recently pushed message is still retrievable. */
  fd_circq_reset_cursor( circq );
  uchar const * last = NULL;
  for(;;) {
    uchar const * m = fd_circq_cursor_advance( circq, &msg_sz );
    if( !m ) break;
    last = m;
  }
  FD_TEST( last );
}

static void
test_no_callback_regression( void ) {
  uchar buf[ 192UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 192UL ) );
  ulong msg_sz = 0UL;

  /* Explicitly clear (already none after new) to assert NULL is a safe
     no-op on the eviction path. */
  fd_circq_set_batch_evict_cb( circq, NULL, NULL );

  uchar * a = fd_circq_push_back( circq, 1UL, 8UL );
  uchar * b = fd_circq_push_back( circq, 1UL, 8UL );
  FD_TEST( a && b );
  a[0] = 'A';
  b[0] = 'B';

  uchar * c = fd_circq_push_back( circq, 1UL, 112UL );
  FD_TEST( c );
  c[0] = 'C';

  FD_TEST( circq->cnt==1UL );

  uchar const * survivor = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( survivor );
  FD_TEST( survivor[0]=='C' );
  FD_TEST( msg_sz==112UL );
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

static void
test_misaligned_payload_span( void ) {
  uchar buf[ 762UL+4096UL ] __attribute__((aligned(4096UL)));
  ulong size = 762UL;
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, size ) );

  /* Fill, wrap and drain to leave the tail ending at a 8-aligned but
     not 64-aligned offset, then push a 64-aligned message that must
     evict the head to fit. */
  ulong const seq[][2] = {
    {8,24},{8,24},{8,92},{32,45},{8,32},{8,25},{16,32},{8,163},{16,182},
    {8,32},{16,33},{8,38},{8,25},{8,24},{8,27},{8,168},{8,32},{32,122},
    {8,24},{8,178},{8,32},{64,216}
  };
  ulong n = sizeof(seq)/sizeof(seq[0]);

  for( ulong i=0UL; i<n; i++ ) {
    ulong align = seq[i][0];
    ulong fp    = seq[i][1];
    uchar * m = fd_circq_push_back( circq, align, fp );
    FD_TEST( m );
    FD_TEST( fd_ulong_is_aligned( (ulong)m, align ) ); /* honors requested align */
    memset( m, (int)(i&0xff), fp );             /* touch the whole payload */
    FD_TEST( fd_circq_bytes_used( circq )<=size ); /* never overruns */
  }

  /* Every live message must still iterate within bounds. */
  fd_circq_reset_cursor( circq );
  ulong msg_sz;
  while( fd_circq_cursor_advance( circq, &msg_sz ) ) FD_TEST( msg_sz<=size );
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
  test_evict_callback_reactive();      FD_LOG_NOTICE(( "pass: evict_callback_reactive" ));
  test_pop_until_callback();           FD_LOG_NOTICE(( "pass: pop_until_callback" ));
  test_batch_evict_wrap();             FD_LOG_NOTICE(( "pass: batch_evict_wrap" ));
  test_no_callback_regression();       FD_LOG_NOTICE(( "pass: no_callback_regression" ));
  test_bounds();                       FD_LOG_NOTICE(( "pass: bounds" ));
  test_misaligned_payload_span();      FD_LOG_NOTICE(( "pass: misaligned_payload_span" ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
