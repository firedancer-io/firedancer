#include "fd_grpc_codec.h"
#include "../h2/fd_h2_rbuf.h"
#include "../h2/fd_hpack.h"

static void
test_h2_gen_request_hdr( void ) {
  fd_grpc_req_hdrs_t req = {
    .https    = 1,
    .host     = "example.org",
    .host_len = 11,
    .port     = 443,
    .path     = "/auth.AuthService/GenerateAuthChallenge",
    .path_len = 39,
  };
  uchar buf[ 2048 ];
  fd_h2_rbuf_t rbuf_tx[1];
  fd_h2_rbuf_init( rbuf_tx, buf, sizeof(buf) );
  FD_TEST( fd_grpc_h2_gen_request_hdrs( &req, rbuf_tx, "1.2.3", 5 )==1 );
  FD_TEST( rbuf_tx->lo_off==0 && rbuf_tx->lo==buf );
# define EXPECT_HDR( nam, val )                                        \
  do {                                                                 \
    FD_TEST( !fd_hpack_rd_done( hpack_rd ) );                          \
    FD_TEST( !fd_hpack_rd_next( hpack_rd, hdr, &scratch, 0UL ) );      \
    FD_TEST( hdr->name_len==sizeof(nam)-1 );                           \
    FD_TEST( fd_memeq( hdr->name, nam, sizeof(nam)-1 ) );              \
    FD_TEST( hdr->value_len==sizeof(val)-1 );                          \
    FD_TEST( fd_memeq( hdr->value, val, sizeof(val)-1 ) );             \
  } while(0)

  fd_hpack_rd_t hpack_rd[1];
  fd_hpack_rd_init( hpack_rd, buf, rbuf_tx->hi_off );
  fd_h2_hdr_t hdr[1];
  uchar * scratch = NULL;
  EXPECT_HDR( ":method", "POST" );
  EXPECT_HDR( ":scheme", "https" );
  EXPECT_HDR( ":path", "/auth.AuthService/GenerateAuthChallenge" );
  EXPECT_HDR( ":authority", "example.org:443" );
  EXPECT_HDR( "te", "trailers" );
  EXPECT_HDR( "content-type", "application/grpc+proto" );
  EXPECT_HDR( "user-agent", "grpc-firedancer/1.2.3" );
  FD_TEST( fd_hpack_rd_done( hpack_rd ) );

  char const example_jwt[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
  fd_grpc_req_hdrs_t req2 = {
    .https           = 1,
    .host            = "example.org",
    .host_len        = 11,
    .port            = 443,
    .path            = "/block_engine.BlockEngineValidator/SubscribePackets",
    .path_len        = 51,
    .bearer_auth     = example_jwt, /* example invalid JWT */
    .bearer_auth_len = sizeof(example_jwt)-1,
  };
  fd_h2_rbuf_init( rbuf_tx, buf, sizeof(buf) );
  FD_TEST( fd_grpc_h2_gen_request_hdrs( &req2, rbuf_tx, "1.2.3", 5 )==1 );
  FD_TEST( rbuf_tx->lo_off==0 && rbuf_tx->lo==buf );

  fd_hpack_rd_init( hpack_rd, buf, rbuf_tx->hi_off );
  EXPECT_HDR( ":method", "POST" );
  EXPECT_HDR( ":scheme", "https" );
  EXPECT_HDR( ":path", "/block_engine.BlockEngineValidator/SubscribePackets" );
  EXPECT_HDR( ":authority", "example.org:443" );
  EXPECT_HDR( "te", "trailers" );
  EXPECT_HDR( "content-type", "application/grpc+proto" );
  EXPECT_HDR( "user-agent", "grpc-firedancer/1.2.3" );
  FD_TEST( !fd_hpack_rd_done( hpack_rd ) );
  FD_TEST( !fd_hpack_rd_next( hpack_rd, hdr, &scratch, 0UL ) );
  FD_TEST( hdr->name_len==13 );
  FD_TEST( fd_memeq( hdr->name, "authorization", 13 ) );
  FD_TEST( hdr->value_len==7+req2.bearer_auth_len );
  FD_TEST( fd_memeq( hdr->value,   "Bearer ",        7                    ) );
  FD_TEST( fd_memeq( hdr->value+7, req2.bearer_auth, req2.bearer_auth_len ) );
  FD_TEST( fd_hpack_rd_done( hpack_rd ) );

# undef EXPECT_HDR
}

/* Build an HPACK literal-without-indexing header (new name).
   Returns number of bytes written. */
static ulong
hpack_literal( uchar * out, char const * name, ulong name_len,
                             char const * val,  ulong val_len ) {
  uchar * p = out;
  *p++ = 0x00;
  *p++ = (uchar)name_len;
  fd_memcpy( p, name, name_len ); p += name_len;
  *p++ = (uchar)val_len;
  fd_memcpy( p, val, val_len );   p += val_len;
  return (ulong)(p - out);
}

static void
test_read_response_hdrs( void ) {
  fd_h2_hdr_matcher_t matcher[1];
  FD_TEST( fd_h2_hdr_matcher_init( matcher, 1UL )==matcher );
  fd_h2_hdr_matcher_insert_literal( matcher, FD_GRPC_HDR_STATUS,  "grpc-status"  );
  fd_h2_hdr_matcher_insert_literal( matcher, FD_GRPC_HDR_MESSAGE, "grpc-message" );

  /* Helper: parse HPACK payload into resp_hdrs */
# define PARSE( payload, payload_sz ) do {                            \
    memset( &resp, 0, sizeof(resp) );                                 \
    resp.grpc_status = FD_GRPC_STATUS_UNKNOWN;                        \
    rc = fd_grpc_h2_read_response_hdrs( &resp, matcher,               \
                                        (payload), (payload_sz) );    \
  } while(0)

  fd_grpc_resp_hdrs_t resp;
  int rc;
  uchar buf[ 256 ];
  ulong off;

  /* ---- Valid cases ---- */

  /* :status: 200 via indexed representation (static table index 8) */
  { uchar hpack[] = { 0x88 };
    PARSE( hpack, sizeof(hpack) );
    FD_TEST( rc==FD_H2_SUCCESS );
    FD_TEST( resp.h2_status==200 ); }

  /* :status: 200 + grpc-status: 0 */
  { off = 0;
    uchar indexed_200[] = { 0x88 };
    fd_memcpy( buf, indexed_200, 1 ); off += 1;
    off += hpack_literal( buf+off, "grpc-status", 11, "0", 1 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_SUCCESS );
    FD_TEST( resp.h2_status==200 );
    FD_TEST( resp.grpc_status==FD_GRPC_STATUS_OK ); }

  /* :status: 200 + grpc-status: 16 (UNAUTHENTICATED, max valid) */
  { off = 0;
    buf[off++] = 0x88;
    off += hpack_literal( buf+off, "grpc-status", 11, "16", 2 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_SUCCESS );
    FD_TEST( resp.grpc_status==FD_GRPC_STATUS_UNAUTHENTICATED ); }

  /* :status: 100 (lowest valid HTTP status) */
  { off = 0;
    off += hpack_literal( buf, ":status", 7, "100", 3 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_SUCCESS );
    FD_TEST( resp.h2_status==100 ); }

  /* :status: 599 (highest valid HTTP status) */
  { off = 0;
    off += hpack_literal( buf, ":status", 7, "599", 3 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_SUCCESS );
    FD_TEST( resp.h2_status==599 ); }

  /* No :status or grpc-status headers → success with defaults */
  { uchar empty[] = "";
    PARSE( empty, 0 );
    FD_TEST( rc==FD_H2_SUCCESS );
    FD_TEST( resp.h2_status==0 );
    FD_TEST( resp.grpc_status==FD_GRPC_STATUS_UNKNOWN ); }

  /* grpc-message preserved on success */
  { off = 0;
    buf[off++] = 0x88;
    off += hpack_literal( buf+off, "grpc-status", 11, "2", 1 );
    off += hpack_literal( buf+off, "grpc-message", 12, "something broke", 15 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_SUCCESS );
    FD_TEST( resp.grpc_msg_len==15 );
    FD_TEST( fd_memeq( resp.grpc_msg, "something broke", 15 ) ); }

  /* ---- h2_status rejection cases ---- */

  /* :status: 0 (below 100) */
  { off = hpack_literal( buf, ":status", 7, "0", 1 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* :status: 99 (below 100) */
  { off = hpack_literal( buf, ":status", 7, "99", 2 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* :status: 600 (above 599) */
  { off = hpack_literal( buf, ":status", 7, "600", 3 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* :status: (empty) */
  { off = hpack_literal( buf, ":status", 7, "", 0 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* :status: OK (non-numeric) */
  { off = hpack_literal( buf, ":status", 7, "OK", 2 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* :status: 0x1F4 (hex, must be rejected under strict decimal parsing) */
  { off = hpack_literal( buf, ":status", 7, "0x1F4", 5 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* :status: 0310 (leading zero, parses as 310 decimal with base 10) */
  { off = hpack_literal( buf, ":status", 7, "0310", 4 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_SUCCESS );
    FD_TEST( resp.h2_status==310 ); }

  /* :status: 200abc (trailing junk) */
  { off = hpack_literal( buf, ":status", 7, "200abc", 6 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* ---- grpc_status rejection cases ---- */

  /* grpc-status: 17 (above UNAUTHENTICATED=16) */
  { off = 0;
    buf[off++] = 0x88;
    off += hpack_literal( buf+off, "grpc-status", 11, "17", 2 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* grpc-status: (empty) */
  { off = 0;
    buf[off++] = 0x88;
    off += hpack_literal( buf+off, "grpc-status", 11, "", 0 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* grpc-status: OK (non-numeric, would silently become 0 with old code) */
  { off = 0;
    buf[off++] = 0x88;
    off += hpack_literal( buf+off, "grpc-status", 11, "OK", 2 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* grpc-status: 0x10 (hex for 16, trailing junk after '0') */
  { off = 0;
    buf[off++] = 0x88;
    off += hpack_literal( buf+off, "grpc-status", 11, "0x10", 4 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* grpc-status: -1 (negative, not a digit) */
  { off = 0;
    buf[off++] = 0x88;
    off += hpack_literal( buf+off, "grpc-status", 11, "-1", 2 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* grpc-status: 999999 (large number) */
  { off = 0;
    buf[off++] = 0x88;
    off += hpack_literal( buf+off, "grpc-status", 11, "999999", 6 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* :status: " 200" (leading whitespace, strtoul would accept) */
  { off = hpack_literal( buf, ":status", 7, " 200", 4 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* :status: +200 (leading plus sign, strtoul would accept) */
  { off = hpack_literal( buf, ":status", 7, "+200", 4 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* grpc-status: " 0" (leading whitespace) */
  { off = 0;
    buf[off++] = 0x88;
    off += hpack_literal( buf+off, "grpc-status", 11, " 0", 2 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* grpc-status: +0 (leading plus) */
  { off = 0;
    buf[off++] = 0x88;
    off += hpack_literal( buf+off, "grpc-status", 11, "+0", 2 );
    PARSE( buf, off );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

  /* Corrupt HPACK payload */
  { uchar corrupt[] = { 0xff, 0xff, 0xff };
    PARSE( corrupt, sizeof(corrupt) );
    FD_TEST( rc==FD_H2_ERR_PROTOCOL ); }

# undef PARSE
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_h2_gen_request_hdr();
  test_read_response_hdrs();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
