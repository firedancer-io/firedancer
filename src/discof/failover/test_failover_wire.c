#include "fd_failover_wire.h"
#include "../../util/fd_util.h"
#include "../../ballet/hmac/fd_hmac.h"

#include <string.h>

static uchar const secret[ 32 ] = { 0x5e, 0xc2, 0xe7 };
static uchar const nonce_a[ 16 ] = { 0xaa };
static uchar const nonce_b[ 16 ] = { 0xbb };

static uchar frame[ FD_FAILOVER_FRAME_MAX ];
static uchar big[ 2UL*FD_FAILOVER_FRAME_MAX ];

/* Two endpoints of one connection, a transmits with nonce_a first, b receives with the mirrored ordering. */
static void
paired_sessions( fd_failover_wire_session_t * a,
                 fd_failover_wire_session_t * b ) {
  fd_failover_wire_session_init( a, secret, 32UL, 1 );
  fd_failover_wire_session_init( b, secret, 32UL, 0 );
  fd_failover_wire_session_keys( a, secret, 32UL, nonce_a, nonce_b );
  fd_failover_wire_session_keys( b, secret, 32UL, nonce_b, nonce_a );
}

static void
test_roundtrip( void ) {
  fd_failover_wire_session_t a, b;
  paired_sessions( &a, &b );

  uchar payload[ 70 ];
  for( ulong i=0UL; i<70UL; i++ ) payload[ i ] = (uchar)i;

  ulong sz = fd_failover_wire_encode( &a, frame, (ushort)FD_FAILOVER_MSG_STATUS, payload, 70UL );
  FD_TEST( sz==FD_FAILOVER_FRAME_HDR_SZ+70UL+FD_FAILOVER_MAC_SZ );

  ushort        type;
  uchar const * out;
  ulong         out_sz;
  ulong         frame_sz;
  FD_TEST( fd_failover_wire_decode( &b, frame, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_SUCCESS );
  FD_TEST( type==(ushort)FD_FAILOVER_MSG_STATUS );
  FD_TEST( out_sz==70UL );
  FD_TEST( frame_sz==sz );
  FD_TEST( !memcmp( out, payload, 70UL ) );

  /* A second frame decodes with trailing garbage in the buffer. */
  ulong sz2 = fd_failover_wire_encode( &a, big, (ushort)FD_FAILOVER_MSG_HELLO, payload, 10UL );
  memset( big+sz2, 0x77, 64UL );
  FD_TEST( fd_failover_wire_decode( &b, big, sz2+64UL, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_SUCCESS );
  FD_TEST( frame_sz==sz2 );

  FD_LOG_NOTICE(( "pass: test_roundtrip" ));
}

static void
test_hello_phase( void ) {
  /* Before nonces exist, HELLO keys distinguish each direction. */
  fd_failover_wire_session_t a, b;
  fd_failover_wire_session_init( &a, secret, 32UL, 1 );
  fd_failover_wire_session_init( &b, secret, 32UL, 0 );

  uchar payload[ 8 ] = { 1, 2, 3 };
  ulong sz = fd_failover_wire_encode( &a, frame, (ushort)FD_FAILOVER_MSG_HELLO, payload, 8UL );

  ushort        type;
  uchar const * out;
  ulong         out_sz;
  ulong         frame_sz;
  FD_TEST( fd_failover_wire_decode( &b, frame, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_SUCCESS );

  /* A HELLO cannot be reflected to its sender. */
  FD_TEST( fd_failover_wire_decode( &a, frame, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_MAC );

  /* A different pair secret cannot decode it. */
  uchar const other[ 32 ] = { 0x99 };
  fd_failover_wire_session_t c;
  fd_failover_wire_session_init( &c, other, 32UL, 0 );
  FD_TEST( fd_failover_wire_decode( &c, frame, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_MAC );

  sz = fd_failover_wire_encode( &b, frame, (ushort)FD_FAILOVER_MSG_HELLO, payload, 8UL );
  FD_TEST( fd_failover_wire_decode( &a, frame, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_SUCCESS );

  FD_LOG_NOTICE(( "pass: test_hello_phase" ));
}

static void
test_tamper_replay_reflect( void ) {
  fd_failover_wire_session_t a, b;
  paired_sessions( &a, &b );

  uchar payload[ 27 ] = { 5 };
  ulong sz = fd_failover_wire_encode( &a, frame, (ushort)FD_FAILOVER_MSG_CONSENSUS_STATE, payload, 27UL );

  ushort        type;
  uchar const * out;
  ulong         out_sz;
  ulong         frame_sz;

  /* Tampered payload fails the MAC. */
  frame[ FD_FAILOVER_FRAME_HDR_SZ ] ^= 1;
  FD_TEST( fd_failover_wire_decode( &b, frame, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_MAC );
  frame[ FD_FAILOVER_FRAME_HDR_SZ ] ^= 1;

  /* Reflection: the sender cannot decode its own frame. */
  FD_TEST( fd_failover_wire_decode( &a, frame, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_MAC );

  /* First delivery succeeds, replay fails on the sequence. */
  FD_TEST( fd_failover_wire_decode( &b, frame, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_SUCCESS );
  FD_TEST( fd_failover_wire_decode( &b, frame, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_SEQ );

  FD_LOG_NOTICE(( "pass: test_tamper_replay_reflect" ));
}

static void
test_bounds( void ) {
  fd_failover_wire_session_t a, b;
  paired_sessions( &a, &b );

  uchar payload[ 8 ] = { 0 };
  ulong sz = fd_failover_wire_encode( &a, frame, (ushort)FD_FAILOVER_MSG_STATUS, payload, 8UL );

  ushort        type;
  uchar const * out;
  ulong         out_sz;
  ulong         frame_sz;

  /* Truncated buffers should ask for retries with more. */
  FD_TEST( fd_failover_wire_decode( &b, frame, 3UL,    &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_AGAIN );
  FD_TEST( fd_failover_wire_decode( &b, frame, sz-1UL, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_AGAIN );

  /* Oversize payload is unencodable. */
  FD_TEST( fd_failover_wire_encode( &a, big, (ushort)FD_FAILOVER_MSG_STATUS, big, FD_FAILOVER_PAYLOAD_MAX+1UL )==0UL );

  /* An oversize or undersize declared length should fatal. */
  memcpy( big, frame, sz );
  fd_failover_frame_hdr_t hdr;
  memcpy( &hdr, big, FD_FAILOVER_FRAME_HDR_SZ );
  hdr.len = (uint)( FD_FAILOVER_FRAME_MAX+1UL );
  memcpy( big, &hdr, FD_FAILOVER_FRAME_HDR_SZ );
  FD_TEST( fd_failover_wire_decode( &b, big, sizeof(big), &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_SZ );
  hdr.len = (uint)( FD_FAILOVER_FRAME_HDR_SZ+FD_FAILOVER_MAC_SZ-1UL );
  memcpy( big, &hdr, FD_FAILOVER_FRAME_HDR_SZ );
  FD_TEST( fd_failover_wire_decode( &b, big, sizeof(big), &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_SZ );

  /* Header fields other than the bounded length are interpreted only after authentication. */
  memcpy( big, frame, sz );
  memcpy( &hdr, big, FD_FAILOVER_FRAME_HDR_SZ );
  hdr.version = (ushort)( FD_FAILOVER_VERSION+1U );
  memcpy( big, &hdr, FD_FAILOVER_FRAME_HDR_SZ );
  FD_TEST( fd_failover_wire_decode( &b, big, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_MAC );
  fd_hmac_sha256( big, sz-FD_FAILOVER_MAC_SZ, a.tx_key, 32UL, big+sz-FD_FAILOVER_MAC_SZ );
  FD_TEST( fd_failover_wire_decode( &b, big, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_VERSION );

  a.tx_seq = ULONG_MAX;
  FD_TEST( !fd_failover_wire_encode( &a, frame, (ushort)FD_FAILOVER_MSG_STATUS, payload, sizeof(payload) ) );

  paired_sessions( &a, &b );
  sz = fd_failover_wire_encode( &a, frame, (ushort)FD_FAILOVER_MSG_STATUS, payload, sizeof(payload) );
  b.rx_seq = ULONG_MAX;
  FD_TEST( fd_failover_wire_decode( &b, frame, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_SEQ );

  FD_LOG_NOTICE(( "pass: test_bounds" ));
}

static void
test_unknown_type( void ) {
  fd_failover_wire_session_t a, b;
  paired_sessions( &a, &b );

  uchar payload[ 4 ] = { 0 };
  FD_TEST( !fd_failover_wire_encode( &a, frame, (ushort)FD_FAILOVER_MSG_RESERVED, payload, sizeof(payload) ) );
  FD_TEST( !a.tx_seq );

  ulong sz = fd_failover_wire_encode( &a, frame, (ushort)FD_FAILOVER_MSG_STATUS, payload, sizeof(payload) );
  fd_failover_frame_hdr_t hdr;
  memcpy( &hdr, frame, sizeof(hdr) );
  hdr.type = (ushort)FD_FAILOVER_MSG_RESERVED;
  memcpy( frame, &hdr, sizeof(hdr) );
  fd_hmac_sha256( frame, sz-FD_FAILOVER_MAC_SZ, a.tx_key, 32UL, frame+sz-FD_FAILOVER_MAC_SZ );

  ushort        type;
  uchar const * out;
  ulong         out_sz;
  ulong         frame_sz;
  FD_TEST( fd_failover_wire_decode( &b, frame, sz, &type, &out, &out_sz, &frame_sz )==FD_FAILOVER_WIRE_ERR_TYPE );

  FD_LOG_NOTICE(( "pass: test_unknown_type" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_roundtrip();
  test_hello_phase();
  test_tamper_replay_reflect();
  test_bounds();
  test_unknown_type();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
