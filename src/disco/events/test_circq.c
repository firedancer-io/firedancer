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

/* bytes_used equals the extents of the queued messages, so a push that
   wraps does not count the skipped tail, and it returns to 0 when the
   queue drains.  Extents are recomputed by walking the queue. */

static ulong
walk_bytes( fd_circq_t const * circq ) {
  ulong total = 0UL;
  ulong off   = circq->head;
  uchar const * buf = (uchar const *)(circq+1);
  for( ulong i=0UL; i<circq->cnt; i++ ) {
    ulong const * m = (ulong const *)(buf+off); /* align, footprint, next */
    total += fd_ulong_align_up( off+3UL*sizeof(ulong), m[0] ) + m[1] - off;
    off = m[2];
  }
  return total;
}

static void
test_bytes_used( void ) {
  static uchar buf[ 4096UL+4096UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 4096UL ) );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1U, 0UL ) );

  for( ulong i=0UL; i<200000UL; i++ ) {
    ulong r = fd_rng_ulong_roll( rng, 8UL );
    if( r<5UL ) {
      ulong sz = 1UL+fd_rng_ulong_roll( rng, 900UL );
      FD_TEST( fd_circq_push_back( circq, fd_ulong_pow2( (int)fd_rng_ulong_roll( rng, 6 ) ), sz ) );
      if( fd_rng_uint_roll( rng, 2U ) ) fd_circq_resize_back( circq, fd_rng_ulong_roll( rng, sz+1UL ) );
    } else if( circq->cnt ) {
      ulong msg_sz;
      while( fd_rng_uint_roll( rng, 2U ) && fd_circq_cursor_advance( circq, &msg_sz ) );
      if( circq->cursor_seq ) FD_TEST( !fd_circq_pop_until( circq, circq->cursor_seq-1UL ) );
    }
    FD_TEST( fd_circq_bytes_used( circq )==walk_bytes( circq ) );
    FD_TEST( fd_circq_bytes_used( circq )<=circq->size );
  }

  FD_TEST( !circq->cnt || fd_circq_bytes_used( circq ) );
  fd_rng_delete( fd_rng_leave( rng ) );
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


/* Spool: two-tier queue over a small window plus a file ring.  Each
   message carries its push seq at [0]. */

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
  ulong peek_sz = 0UL;
  FD_TEST( fd_circq_cursor_peek( circq, &peek_sz ) );
  ulong msg_sz;
  uchar const * msg = fd_circq_cursor_advance( circq, &msg_sz );
  FD_TEST( msg );
  FD_TEST( msg_sz==SPOOL_MSG_SZ && peek_sz==msg_sz );
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

  FD_TEST( !fd_circq_push_back( circq, 1UL, SPOOL_MSG_SZ+1UL ) );

  for( ulong i=0UL; i<100UL; i++ ) spool_push( circq, i );
  FD_TEST( circq->spool_cnt>0UL );
  FD_TEST( circq->cnt+circq->spool_cnt==100UL );
  FD_TEST( !circq->metrics.drop_cnt );
  FD_TEST( fd_circq_unsent_cnt( circq )==100UL );
  FD_TEST( fd_circq_bytes_used( circq )==circq->bytes_used+circq->spool_bytes );

  for( ulong i=0UL; i<100UL; i++ ) FD_TEST( spool_check_next( circq )==i );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );
  FD_TEST( !fd_circq_cursor_peek( circq, &msg_sz ) );
  FD_TEST( !fd_circq_unsent_cnt( circq ) );

  FD_TEST( !fd_circq_pop_until( circq, 10UL ) );
  FD_TEST( circq->cnt+circq->spool_cnt==89UL );
  ulong ram_cnt = circq->cnt;
  FD_TEST( !fd_circq_pop_until( circq, 99UL-ram_cnt+2UL ) );
  FD_TEST( !circq->spool_cnt );
  FD_TEST( circq->cnt==ram_cnt-2UL );

  fd_circq_reset_cursor( circq );
  for( ulong i=0UL; i<ram_cnt-2UL; i++ ) FD_TEST( spool_check_next( circq )==99UL-ram_cnt+3UL+i );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );

  FD_TEST( !fd_circq_pop_until( circq, 99UL ) );
  FD_TEST( !circq->cnt && !circq->spool_cnt && !circq->spool_bytes && !fd_circq_bytes_used( circq ) );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );
  FD_TEST( !close( fd ) );
}

/* Pushes interleaved with sends: the in-flight cursor follows its
   message into the spool, so nothing is skipped or resent. */

static void
test_spool_cursor_follows( void ) {
  static uchar buf[ 4096UL+4096UL+SPOOL_MSG_SZ ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 4096UL ) );
  int fd = spool_fd_new( 1UL<<20UL );
  fd_circq_spool_init( circq, fd, 1UL<<20UL, SPOOL_MSG_SZ );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1U, 0UL ) );
  ulong pushed = 0UL, sent = 0UL, acked = 0UL, spilled = 0UL, mid = 0UL;
  for( ulong iter=0UL; iter<20000UL; iter++ ) {
    ulong r = fd_rng_ulong_roll( rng, 8UL );
    if( r<4UL ) {
      spool_push( circq, pushed++ );
    } else if( r<7UL ) {
      if( sent<pushed ) FD_TEST( spool_check_next( circq )==sent++ );
    } else if( sent>acked ) {
      ulong to = acked+fd_rng_ulong_roll( rng, sent-acked );
      FD_TEST( !fd_circq_pop_until( circq, to ) );
      acked = to+1UL;
    }
    FD_TEST( circq->cnt+circq->spool_cnt==pushed-acked );
    FD_TEST( fd_circq_unsent_cnt( circq )==pushed-sent );
    spilled += !!circq->spool_cnt;
    mid     += circq->cursor_spool && sent<pushed-circq->cnt;
  }
  FD_TEST( spilled && mid );
  FD_TEST( !circq->metrics.drop_cnt );
  fd_rng_delete( fd_rng_leave( rng ) );
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

  for( ulong i=0UL; i<5UL; i++ ) FD_TEST( spool_check_next( circq )==( spool_push( circq, i ), i ) );
  for( ulong i=5UL; i<200UL; i++ ) spool_push( circq, i );
  FD_TEST( circq->metrics.drop_cnt>0UL );
  ulong live = circq->cnt+circq->spool_cnt;
  FD_TEST( live<200UL );
  FD_TEST( fd_circq_unsent_cnt( circq )==live ); /* cursor overrun: resend from front */

  ulong expected = 200UL-live;
  for( ulong i=0UL; i<live; i++ ) FD_TEST( spool_check_next( circq )==expected+i );
  FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );
  FD_TEST( !close( fd ) );
}

static void
test_spool_wrap_cycles( void ) {
  static uchar buf[ 4096UL+4096UL+SPOOL_MSG_SZ ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 4096UL ) );
  ulong cap = 8192UL+40UL; /* not a record multiple: exercises the marker-less wrap too */
  int fd = spool_fd_new( cap );
  fd_circq_spool_init( circq, fd, cap, SPOOL_MSG_SZ );
  ulong msg_sz;

  ulong id = 0UL;
  ulong acked = 0UL;
  for( ulong round=0UL; round<50UL; round++ ) {
    for( ulong i=0UL; i<20UL; i++ ) spool_push( circq, id++ );
    fd_circq_reset_cursor( circq );
    ulong live = circq->cnt+circq->spool_cnt;
    FD_TEST( acked+live==id );
    for( ulong i=0UL; i<live; i++ ) FD_TEST( spool_check_next( circq )==acked+i );
    FD_TEST( !fd_circq_cursor_advance( circq, &msg_sz ) );
    FD_TEST( !fd_circq_pop_until( circq, id-6UL ) );
    acked = id-5UL;
    FD_TEST( circq->cnt+circq->spool_cnt==5UL );
  }
  FD_TEST( !circq->metrics.drop_cnt );
  FD_TEST( !close( fd ) );
}

/* Variable-size pure overflow with sparse sends/acks: many file-ring
   wraps with head and cursor parked on end-of-ring markers. */

static ulong
spool_var_sz( ulong id ) {
  return 8UL+( id*2654435761UL )%( SPOOL_MSG_SZ-7UL );
}

static void
test_spool_overflow_var( void ) {
  static uchar buf[ 4096UL+4096UL+SPOOL_MSG_SZ ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( buf, 4096UL ) );
  ulong cap = 16384UL+40UL;
  int fd = spool_fd_new( cap );
  fd_circq_spool_init( circq, fd, cap, SPOOL_MSG_SZ );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 2U, 0UL ) );
  for( ulong id=0UL; id<400000UL; id++ ) {
    ulong sz = spool_var_sz( id );
    uchar * msg = fd_circq_push_back( circq, 1UL, sz );
    FD_TEST( msg );
    FD_STORE( ulong, msg, id );
    for( ulong i=8UL; i<sz; i++ ) msg[ i ] = (uchar)(id+i);

    ulong r = fd_rng_ulong_roll( rng, 64UL );
    if( r<2UL ) {
      ulong msg_sz;
      uchar const * out = fd_circq_cursor_advance( circq, &msg_sz );
      FD_TEST( out );
      ulong got = FD_LOAD( ulong, out );
      FD_TEST( got==circq->cursor_seq-1UL && msg_sz==spool_var_sz( got ) );
      for( ulong i=8UL; i<msg_sz; i++ ) FD_TEST( out[ i ]==(uchar)(got+i) );
    } else if( r<3UL && circq->cursor_seq ) {
      fd_circq_pop_until( circq, circq->cursor_seq-1UL );
    }
  }
  FD_TEST( circq->metrics.drop_cnt );
  fd_rng_delete( fd_rng_leave( rng ) );
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
  test_bytes_used();                   FD_LOG_NOTICE(( "pass: bytes_used" ));
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
  test_spool_cursor_follows();         FD_LOG_NOTICE(( "pass: spool_cursor_follows" ));
  test_spool_drop_oldest();            FD_LOG_NOTICE(( "pass: spool_drop_oldest" ));
  test_spool_wrap_cycles();            FD_LOG_NOTICE(( "pass: spool_wrap_cycles" ));
  test_spool_overflow_var();           FD_LOG_NOTICE(( "pass: spool_overflow_var" ));
  test_bounds();                       FD_LOG_NOTICE(( "pass: bounds" ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
