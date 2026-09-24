#include "ag_hist.h"

#define TEST_ANCHOR (1000UL) /* first slot 992, so a slot below the bound exists */

/* Byte offsets into a serialized history whose records all lack a
   notar hash, the reject tests patch through these */

#define HDR_ANCHOR_OFF     (0UL)
#define REC_SLOT_OFF( i )  ( AG_HIST_HDR_SZ+(i)*AG_HIST_REC_MIN_SZ )
#define REC_FLAGS_OFF( i ) ( REC_SLOT_OFF( i )+sizeof(ulong) )

static void
fill_hash( ag_block_hash_t hash,
           uchar           seed ) {
  for( ulong i=0UL; i<sizeof(ag_block_hash_t); i++ ) hash[ i ] = (uchar)( seed+i );
}

/* round_trip serializes hist, decodes it back and checks every field
   survived, returning the serialized size */

static ulong
round_trip( ag_hist_t const * hist ) {
  uchar buf[ AG_HIST_SER_MAX ];
  ulong sz = 0UL;
  FD_TEST( !ag_hist_ser( hist, buf, sizeof(buf), &sz ) );

  ag_hist_t out; fd_memset( &out, 0xAA, sizeof(ag_hist_t) );
  FD_TEST( !ag_hist_de( buf, sz, &out ) );
  FD_TEST( out.anchor          ==hist->anchor           );
  FD_TEST( out.last_leader_slot==hist->last_leader_slot );
  FD_TEST( out.rec_cnt         ==hist->rec_cnt          );
  for( ulong i=0UL; i<hist->rec_cnt; i++ ) {
    FD_TEST( out.rec[ i ].slot ==hist->rec[ i ].slot  );
    FD_TEST( out.rec[ i ].flags==hist->rec[ i ].flags );
    if( hist->rec[ i ].flags & AG_HIST_FLAG_VOTED_NOTAR ) FD_TEST( fd_memeq( out.rec[ i ].notar_hash, hist->rec[ i ].notar_hash, sizeof(ag_block_hash_t) ) );
  }
  return sz;
}

/* de_fails checks the decoder refuses buf and leaves out untouched */

static void
de_fails( uchar const * buf,
          ulong         sz ) {
  ag_hist_t out; fd_memset( &out, 0xAA, sizeof(ag_hist_t) );
  ag_hist_t ref; fd_memset( &ref, 0xAA, sizeof(ag_hist_t) );
  FD_TEST( ag_hist_de( buf, sz, &out )==-1 );
  FD_TEST( fd_memeq( &out, &ref, sizeof(ag_hist_t) ) );
}

static void
test_empty( void ) {
  ag_hist_t hist = { .anchor = TEST_ANCHOR, .last_leader_slot = ULONG_MAX, .rec_cnt = 0UL };
  FD_TEST( round_trip( &hist )==AG_HIST_HDR_SZ );
  FD_TEST( ag_hist_tip( &hist )==ULONG_MAX );
}

static void
test_flags( void ) {
  ulong first = ag_hist_first_slot( TEST_ANCHOR );
  for( uint flags=0U; flags<=AG_HIST_FLAG_MASK; flags++ ) {
    ag_hist_t hist = { .anchor = TEST_ANCHOR, .last_leader_slot = TEST_ANCHOR-4UL, .rec_cnt = 1UL };
    hist.rec[ 0 ].slot  = first+3UL;
    hist.rec[ 0 ].flags = (uchar)flags;
    fill_hash( hist.rec[ 0 ].notar_hash, (uchar)flags );

    uchar buf[ AG_HIST_SER_MAX ];
    ulong sz = 0UL;
    if( !( flags & AG_HIST_FLAG_VOTED ) ) { FD_TEST( ag_hist_ser( &hist, buf, sizeof(buf), &sz )==-1 ); continue; }

    ulong want = AG_HIST_HDR_SZ+AG_HIST_REC_MIN_SZ+fd_ulong_if( flags & AG_HIST_FLAG_VOTED_NOTAR, sizeof(ag_block_hash_t), 0UL );
    FD_TEST( round_trip( &hist )==want );
    FD_TEST( ag_hist_tip( &hist )==first+3UL );
  }
}

static void
test_full( void ) {
  ulong first = ag_hist_first_slot( TEST_ANCHOR );
  ag_hist_t hist = { .anchor = TEST_ANCHOR, .last_leader_slot = first+AG_HIST_MAX-4UL, .rec_cnt = AG_HIST_MAX };
  for( ulong i=0UL; i<AG_HIST_MAX; i++ ) {
    hist.rec[ i ].slot  = first+i;
    hist.rec[ i ].flags = AG_HIST_FLAG_VOTED | AG_HIST_FLAG_VOTED_NOTAR;
    fill_hash( hist.rec[ i ].notar_hash, (uchar)i );
  }
  ulong sz = round_trip( &hist );
  FD_TEST( sz==AG_HIST_SER_MAX );
  FD_TEST( ag_hist_tip( &hist )==first+AG_HIST_MAX-1UL );

  uchar buf[ AG_HIST_SER_MAX ];
  ulong got = 0UL;
  FD_TEST( ag_hist_ser( &hist, buf, sz-1UL, &got )==-1 );
  FD_TEST( ag_hist_ser( &hist, buf, sz,     &got )==0 && got==sz );

  hist.rec_cnt = AG_HIST_MAX+1UL;
  FD_TEST( ag_hist_ser( &hist, buf, sizeof(buf), &got )==-1 );
}

static void
test_reject( void ) {
  ulong first = ag_hist_first_slot( TEST_ANCHOR );
  FD_TEST( first>0UL );

  ag_hist_t hist = { .anchor = TEST_ANCHOR, .last_leader_slot = ULONG_MAX, .rec_cnt = 3UL };
  hist.rec[ 0 ] = (ag_hist_rec_t){ .slot = first,     .flags = AG_HIST_FLAG_VOTED                         };
  hist.rec[ 1 ] = (ag_hist_rec_t){ .slot = first+1UL, .flags = AG_HIST_FLAG_VOTED | AG_HIST_FLAG_BAD_WINDOW };
  hist.rec[ 2 ] = (ag_hist_rec_t){ .slot = first+5UL, .flags = AG_HIST_FLAG_VOTED | AG_HIST_FLAG_RETIRED    };

  uchar good[ AG_HIST_SER_MAX ];
  ulong sz = 0UL;
  FD_TEST( !ag_hist_ser( &hist, good, sizeof(good), &sz ) );
  FD_TEST( sz==AG_HIST_HDR_SZ+3UL*AG_HIST_REC_MIN_SZ );
  FD_TEST( sz==round_trip( &hist ) );

  uchar buf[ AG_HIST_SER_MAX ];

  /* trailing byte and truncation */
  fd_memcpy( buf, good, sz ); buf[ sz ] = 0;
  de_fails( buf, sz+1UL );
  de_fails( buf, sz-1UL );
  de_fails( buf, AG_HIST_HDR_SZ-1UL );

  /* rec_cnt too large, with enough bytes that only the count is wrong */
  ulong off = 0UL;
  FD_STORE( ulong,  buf+off, TEST_ANCHOR              ); off += sizeof(ulong);
  FD_STORE( ulong,  buf+off, ULONG_MAX                ); off += sizeof(ulong);
  FD_STORE( ushort, buf+off, (ushort)(AG_HIST_MAX+1UL) ); off += sizeof(ushort);
  for( ulong i=0UL; i<AG_HIST_MAX+1UL; i++ ) {
    FD_STORE( ulong, buf+off, first+i ); off += sizeof(ulong);
    buf[ off ] = AG_HIST_FLAG_VOTED;     off += sizeof(uchar);
  }
  de_fails( buf, off );

  /* non-ascending slots */
  fd_memcpy( buf, good, sz ); FD_STORE( ulong, buf+REC_SLOT_OFF( 1 ), first ); de_fails( buf, sz ); /* equal */
  fd_memcpy( buf, good, sz ); FD_STORE( ulong, buf+REC_SLOT_OFF( 2 ), first ); de_fails( buf, sz ); /* lower */

  /* unknown flag bit */
  fd_memcpy( buf, good, sz ); buf[ REC_FLAGS_OFF( 0 ) ] = (uchar)( AG_HIST_FLAG_VOTED | (AG_HIST_FLAG_MASK+1U) ); de_fails( buf, sz );

  /* flags without VOTED */
  fd_memcpy( buf, good, sz ); buf[ REC_FLAGS_OFF( 0 ) ] = 0;                              de_fails( buf, sz );
  fd_memcpy( buf, good, sz ); buf[ REC_FLAGS_OFF( 2 ) ] = (uchar)AG_HIST_FLAG_RETIRED;    de_fails( buf, sz );
  fd_memcpy( buf, good, sz ); buf[ REC_FLAGS_OFF( 1 ) ] = (uchar)AG_HIST_FLAG_BAD_WINDOW; de_fails( buf, sz );

  /* slot below the anchor's first slot */
  fd_memcpy( buf, good, sz ); FD_STORE( ulong, buf+REC_SLOT_OFF( 0 ), first-1UL ); de_fails( buf, sz );

  /* anchor ULONG_MAX, on a history whose slots stay valid under that
     anchor so nothing else trips */
  ag_hist_t top = { .anchor = ULONG_MAX-1UL, .last_leader_slot = ULONG_MAX, .rec_cnt = 1UL };
  top.rec[ 0 ] = (ag_hist_rec_t){ .slot = ULONG_MAX-2UL, .flags = AG_HIST_FLAG_VOTED };
  FD_TEST( ULONG_MAX-2UL>=ag_hist_first_slot( ULONG_MAX ) );
  ulong top_sz = round_trip( &top );
  FD_TEST( !ag_hist_ser( &top, buf, sizeof(buf), &top_sz ) );
  FD_STORE( ulong, buf+HDR_ANCHOR_OFF, ULONG_MAX );
  de_fails( buf, top_sz );
  top.anchor = ULONG_MAX;
  FD_TEST( ag_hist_ser( &top, buf, sizeof(buf), &top_sz )==-1 );
}

static void
test_first_slot( void ) {
  FD_TEST( ag_hist_first_slot(  0UL )==0UL );
  FD_TEST( ag_hist_first_slot(  7UL )==0UL );
  FD_TEST( ag_hist_first_slot(  8UL )==0UL );
  FD_TEST( ag_hist_first_slot( 13UL )==4UL );
  FD_TEST( ag_hist_first_slot( TEST_ANCHOR )==992UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_empty();
  test_flags();
  test_full();
  test_reject();
  test_first_slot();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
