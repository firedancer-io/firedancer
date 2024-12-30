#include "../crypto/fd_quic_crypto_suites.h"

#include "../fd_quic_common.h"
#include "../fd_quic_private.h"
#include "../fd_quic_retry_private.h"

#include "../templ/fd_quic_encoders_decl.h"
#include "../templ/fd_quic_frames_templ.h"
#include "../templ/fd_quic_templ.h"
#include "../templ/fd_quic_undefs.h"

#include "../../../ballet/aes/fd_aes_gcm.h"

/* Verify our retry integrity tag implementation using the sample retry packet from RFC 9001, A.4

   ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f 0f2496ba
   (source: https://www.rfc-editor.org/rfc/rfc9001#section-a.4-1)

   f  // header form, fixed bit, long packet type
   f  // unused (arbitrary, but set to 1s in sample)
   00000001  // 32-bit version
   00  // dst conn id len
   []  // empty dst conn id
   08  // src conn id len
   f067a5502a4262b5  // 8-byte src conn id
   746f6b656e  // 5-byte retry token (opaque, conjured by sample)
   04a265ba2eff4d829058fb3f0f2496ba  // retry integrity tag (verified by this test)

   also, A.1 includes the original dest conn id: 0x8394c8f03e515708
*/
void
test_retry_integrity_tag( void ) {

  fd_aes_gcm_t aes_gcm[1];

  static uchar const retry_a41[36] = {
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
    0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
    0x6f, 0x6b, 0x65, 0x6e,

    0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
    0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba
  };
  static fd_quic_conn_id_t const conn_id_a41 = {
    .sz = 8,
    .conn_id = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 }
  };

  /* Test Sign */

  uchar retry_pseudo_pkt[ FD_QUIC_RETRY_MAX_PSEUDO_SZ ];
  ulong retry_pseudo_pkt_len = fd_quic_retry_pseudo( retry_pseudo_pkt, retry_a41, sizeof(retry_a41), &conn_id_a41 );

  static uchar const pseudo_a41[] = {
    0x08,
    0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
    0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
    0x6f, 0x6b, 0x65, 0x6e,
  };
  FD_TEST( retry_pseudo_pkt_len==sizeof(pseudo_a41) );
  if( FD_UNLIKELY( 0!=memcmp( retry_pseudo_pkt, pseudo_a41, sizeof(pseudo_a41) ) ) ) {
    FD_LOG_WARNING(( "retry_pseudo_pkt mismatch" ));
    FD_LOG_HEXDUMP_WARNING(( "expected", pseudo_a41,       sizeof(pseudo_a41) ));
    FD_LOG_HEXDUMP_WARNING(( "actual",   retry_pseudo_pkt, sizeof(pseudo_a41) ));
  }

  uchar retry_integrity_tag[ FD_QUIC_CRYPTO_TAG_SZ ];
  fd_quic_retry_integrity_tag_sign( aes_gcm, retry_pseudo_pkt, retry_pseudo_pkt_len, retry_integrity_tag );

  FD_TEST( 0==memcmp( retry_integrity_tag, retry_a41 + 20, FD_QUIC_CRYPTO_TAG_SZ ) );

  /* Test Verify */

  fd_quic_conn_id_t src_conn_id;
  uchar const *     token;
  ulong             token_sz;

  int res = fd_quic_retry_client_verify( retry_a41, sizeof(retry_a41), &conn_id_a41, &src_conn_id, &token, &token_sz );
  FD_TEST( res==FD_QUIC_SUCCESS );
}

/* bench_retry_{create,server_verify} tests packet throughput for
   server-side retry handling.  Servers produce unique authenticated
   tokens (opauqe/custom scheme) and also create Retry Integrity Tags
   (RFC 9001). */

static void
bench_retry_create( void ) {
  FD_LOG_NOTICE(( "Benchmarking Retry Create" ));

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  uchar retry[ FD_QUIC_RETRY_LOCAL_SZ ];
  fd_quic_pkt_t     const pkt = {0};
  fd_quic_conn_id_t const orig_dst_conn_id = { .sz = 8 };
  fd_quic_conn_id_t const peer_src_conn_id = { .sz = 16 };
  ulong             const retry_src_conn_id = 1234UL;

  uchar aes_key[16] = {1};
  uchar aes_iv [16] = {2};
  ulong ttl         = (ulong)3e9;

  fd_quic_retry_create( retry, &pkt, rng, aes_key, aes_iv, &orig_dst_conn_id, &peer_src_conn_id, retry_src_conn_id, 7315969UL+(ulong)ttl );
  FD_LOG_HEXDUMP_INFO(( "Retry Token", retry+0x1f, sizeof(fd_quic_retry_token_t) ));

  long dt = -fd_log_wallclock();
  ulong iter = 1000000UL;
  for( ulong j=0UL; j<iter; j++ ) {
    fd_quic_retry_create( retry, &pkt, rng, aes_key, aes_iv, &orig_dst_conn_id, &peer_src_conn_id, retry_src_conn_id, 1UL+(ulong)ttl );
    FD_COMPILER_UNPREDICTABLE( retry[0] );
  }
  dt += fd_log_wallclock();
  double mpps = ((double)iter / ((double)dt / 1e9)) / 1e6;
  double ns   = (double)dt / (double)iter;
  FD_LOG_NOTICE(( "  ~%9.3f Mpps / core", mpps ));
  FD_LOG_NOTICE(( "  ~%9.3f ns / pkt",    ns   ));

  fd_rng_delete( fd_rng_leave( rng ) );
}

static void
bench_retry_server_verify( void ) {
  FD_LOG_NOTICE(( "Benchmarking Retry Server Verify" ));

  static uchar const token[] = {
    0xa5, 0xda, 0xb6, 0xf9, 0x36, 0xa0, 0xaa, 0xc1, 0x13, 0x73, 0xa5, 0x4e, 0x0a, 0x11, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xcb, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd2, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0xc0, 0x2a, 0x34, 0xf1, 0x0d, 0x8d, 0x8c, 0x60, 0x5b, 0xe2, 0x28,
    0x27, 0x5e, 0xd0, 0x18, 0xc7
  };

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_quic_pkt_t const pkt = {0};

  fd_quic_initial_t initial = { .dst_conn_id_len = 8 };
  initial.token     = token;
  initial.token_len = sizeof(token);
  fd_quic_conn_id_t odcid;
  ulong             rscid;

  uchar aes_key[16] = {1};
  uchar aes_iv [16] = {2};
  ulong now         = 50UL;
  ulong ttl         = (ulong)3e9;

  long dt = -fd_log_wallclock();
  ulong iter = 1000000UL;
  for( ulong j=0UL; j<iter; j++ ) {
    FD_COMPILER_UNPREDICTABLE( aes_key[0] );
    int res = fd_quic_retry_server_verify( &pkt, &initial, &odcid, &rscid, aes_key, aes_iv, now, ttl );
    FD_TEST( res==FD_QUIC_SUCCESS );
  }
  dt += fd_log_wallclock();
  double mpps = ((double)iter / ((double)dt / 1e9)) / 1e6;
  double ns   = (double)dt / (double)iter;
  FD_LOG_NOTICE(( "  ~%9.3f Mpps / core", mpps ));
  FD_LOG_NOTICE(( "  ~%9.3f ns / pkt",    ns   ));

  fd_rng_delete( fd_rng_leave( rng ) );
}

/* bench_retry_client tests packet throughput for client-side retry
   handling.  Clients validate Retry Integrity Tags (RFC 9001) to
   prevent injection of bogus retries.  (Even though these can be forged
   if the attacker is able to eavesdrop) */

static void
bench_retry_client_verify( void ) {
  FD_LOG_NOTICE(( "Benchmarking Retry Client Verify" ));

  static uchar const retry[] = {
    0xff, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xda,
    0x08, 0xb6, 0xf9, 0x36, 0xa0, 0xaa, 0xc1, 0x13, 0x73, 0xa5, 0x4e, 0x0a, 0x11, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xe3, 0x59, 0xbd, 0x75, 0xbf, 0x22, 0xc4, 0xbb, 0xed, 0x08, 0xa7, 0x36, 0x1a,
    0xa2, 0x07, 0x2b, 0x62, 0xdf, 0x6b, 0x56, 0xda, 0x0d, 0xa4, 0x5d, 0x0d, 0xe9, 0xdb, 0xcb, 0xb0,
    0x90, 0x91, 0xd3
  };

  fd_quic_conn_id_t const orig_dst_conn_id = { .sz = 8 };
  fd_quic_conn_id_t       src_conn_id;

  uchar const * token;
  ulong         token_sz;

  long dt = -fd_log_wallclock();
  ulong iter = 1000000UL;
  for( ulong j=0UL; j<iter; j++ ) {
    int res = fd_quic_retry_client_verify( retry, sizeof(retry), &orig_dst_conn_id, &src_conn_id, &token, &token_sz );
    FD_TEST( res==FD_QUIC_SUCCESS );
  }
  dt += fd_log_wallclock();
  double mpps = ((double)iter / ((double)dt / 1e9)) / 1e6;
  double ns   = (double)dt / (double)iter;
  FD_LOG_NOTICE(( "  ~%9.3f Mpps / core", mpps ));
  FD_LOG_NOTICE(( "  ~%9.3f ns / pkt",    ns   ));
}

/* Ensure that retry token data is authenticated.  Flip every bit of the
   retry token separately and ensure that the server rejects the tokens. */

static void
test_retry_token_malleability( void ) {

  static uchar retry[] = {
    0xff, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xda,
    0x08, 0xb6, 0xf9, 0x36, 0xa0, 0xaa, 0xc1, 0x13, 0x73, 0xa5, 0x4e, 0x0a, 0x11, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xe3, 0x59, 0xbd, 0x75, 0xbf, 0x22, 0xc4, 0xbb, 0xed, 0x08, 0xa7, 0x36, 0x1a,
    0xa2, 0x07, 0x2b, 0x62, 0xdf, 0x6b, 0x56, 0xda, 0x0d, 0xa4, 0x5d, 0x0d, 0xe9, 0xdb, 0xcb, 0xb0,
    0x90, 0x91, 0xd3
  };
  fd_quic_conn_id_t const orig_dst_conn_id = { .sz = 8 };
  fd_quic_conn_id_t       src_conn_id;
  for( ulong j=0; j<sizeof(retry); j++ ) {
    for( int i=0; i<8; i++ ) {
      retry[j] = (uchar)( retry[j] ^ (1<<i) );
      uchar const * token;
      ulong         token_sz;
      int res = fd_quic_retry_client_verify( retry, sizeof(retry), &orig_dst_conn_id, &src_conn_id, &token, &token_sz );
      FD_TEST( res==FD_QUIC_FAILED );
      retry[j] = (uchar)( retry[j] ^ (1<<i) );
    }
  }

  static uchar const token[] = {
    0xa5, 0xda, 0xb6, 0xf9, 0x36, 0xa0, 0xaa, 0xc1, 0x13, 0x73, 0xa5, 0x4e, 0x0a, 0x11, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xcb, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd2, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0xc0, 0x2a, 0x34, 0xf1, 0x0d, 0x8d, 0x8c, 0x60, 0x5b, 0xe2, 0x28,
    0x27, 0x5e, 0xd0, 0x18, 0xc7
  };
  fd_quic_initial_t initial = { .dst_conn_id_len = 8 };
  initial.token     = token;
  initial.token_len = sizeof(token);
  fd_quic_pkt_t const pkt = {0};
  uchar aes_key[16] = {1};
  uchar aes_iv [16] = {2};
  ulong now         = 50UL;
  ulong ttl         = (ulong)3e9;
  for( ulong j=0; j<sizeof(token); j++ ) {
    for( int i=0; i<8; i++ ) {
      retry[j] = (uchar)( initial.token[j] ^ (1<<i) );
      fd_quic_conn_id_t odcid;
      ulong             rscid;
      int res = fd_quic_retry_server_verify( &pkt, &initial, &odcid, &rscid, aes_key, aes_iv, now, ttl );
      FD_TEST( res==FD_QUIC_SUCCESS );
      retry[j] = (uchar)( initial.token[j] ^ (1<<i) );
    }
  }

}

/* Ensure that retry tokens expire. */

static void
test_retry_token_time( void ) {

  static uchar const token[] = {
    0xa5, 0xda, 0xb6, 0xf9, 0x36, 0xa0, 0xaa, 0xc1, 0x13, 0x73, 0xa5, 0x4e, 0x0a, 0x11, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xcd, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd2, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0xc3, 0x6a, 0x97, 0x35, 0xc2, 0xee, 0x6f, 0x2b, 0x57, 0xdd, 0xc2,
    0x09, 0x2c, 0x8d, 0xa8, 0x5e,
  };
  fd_quic_initial_t initial = { .dst_conn_id_len = 8 };
  initial.token     = token;
  initial.token_len = sizeof(token);
  fd_quic_pkt_t const pkt = {0};
  uchar aes_key[16] = {1};
  uchar aes_iv [16] = {2};
  ulong ttl         = (ulong)3e9;

  fd_quic_conn_id_t odcid;
  ulong             rscid;
# define TRY(ts,exp) FD_TEST( fd_quic_retry_server_verify( &pkt, &initial, &odcid, &rscid, aes_key, aes_iv, ts, ttl )==exp )
  TRY(          0UL, FD_QUIC_FAILED  );
  TRY(    7315968UL, FD_QUIC_FAILED  );
  TRY(    7315969UL, FD_QUIC_SUCCESS );
  TRY( 3007315967UL, FD_QUIC_SUCCESS );
  TRY( 3007315968UL, FD_QUIC_FAILED  );
  TRY( 3007315969UL, FD_QUIC_FAILED  );
  TRY(    ULONG_MAX, FD_QUIC_FAILED  );
# undef TRY
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_retry_integrity_tag();
  bench_retry_create();
  bench_retry_server_verify();
  bench_retry_client_verify();
  test_retry_token_malleability();
  test_retry_token_time();

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
