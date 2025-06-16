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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_h2_gen_request_hdr();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
