#include "../crypto/fd_quic_crypto_suites.h"
#include "../fd_quic.h"

#include "../fd_quic_common.h"
#include "../fd_quic_types.h"
#include "../fd_quic_retry.h"

#include "../templ/fd_quic_encoders_decl.h"
#include "../templ/fd_quic_frames_templ.h"
#include "../templ/fd_quic_templ.h"
#include "../templ/fd_quic_undefs.h"

#include "../../../util/net/fd_ip4.h"

void
test_retry_token_encrypt_decrypt( void ) {
#define NUM_TEST_CASES 3

  fd_quic_conn_id_t orig_dst_conn_ids[NUM_TEST_CASES] = {
  // RFC example
      { .sz = 8, .conn_id = "\x83\x94\xc8\xf0\x3e\x51\x57\x08" },
 // 20-byte handling
      { .sz = 20,
       .conn_id =
            "\x83\x94\xc8\xf0\x3e\x51\x57\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00\x00\x00" },
 // 0-byte handling
      { .sz = 0 },
  };

  fd_quic_conn_id_t retry_src_conn_ids[NUM_TEST_CASES] = {
  // RFC example
      { .sz = 0 },
 // 8-byte handling (our server default)
      { .sz = 8, .conn_id = "\x42\x41\x40\x3F\x3E\x3D\x3C\x3B" },
 // 20-byte handling
      { .sz = 20,
       .conn_id =
            "\x83\x94\xc8\xf0\x3e\x51\x57\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00\x00\x00" },
  };

  fd_quic_net_endpoint_t client = { .ip_addr = FD_IP4_ADDR(127, 0, 0, 1), .udp_port = 9000 };
  uchar                  retry_token[FD_QUIC_RETRY_TOKEN_SZ];
  ulong                  now = (ulong)fd_log_wallclock();

  uchar retry_secret[FD_QUIC_RETRY_SECRET_SZ] = { 151, 6, 238, 205, 153, 2, 103, 12, 63, 212, 88, 23 };

  for ( int i = 0; i < NUM_TEST_CASES; i++ ) {
    fd_quic_conn_id_t orig_dst_conn_id  = orig_dst_conn_ids[i];
    fd_quic_conn_id_t retry_src_conn_id = retry_src_conn_ids[i];

    fd_quic_retry_token_encrypt(
        retry_secret, &orig_dst_conn_id, now, &retry_src_conn_id, client.ip_addr, client.udp_port, retry_token
    );

    fd_quic_conn_id_t orig_dst_conn_id_decrypt;
    ulong             now_decrypt;

    fd_quic_retry_token_decrypt(
        retry_secret,
        retry_token,
        &retry_src_conn_id,
        client.ip_addr,
        client.udp_port,
        &orig_dst_conn_id_decrypt,
        &now_decrypt
    );

    FD_TEST( orig_dst_conn_id.sz == orig_dst_conn_id_decrypt.sz );
    for ( int j = 0; j < orig_dst_conn_id.sz; j++ ) {
      FD_TEST( orig_dst_conn_id.conn_id[j] == orig_dst_conn_id_decrypt.conn_id[j] );
    }
    FD_TEST( now_decrypt == now);
  }
}

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
  fd_quic_retry_pseudo_t retry_pseudo_pkt = {
      .odcid_len        = 8,
      .odcid            = "\x83\x94\xc8\xf0\x3e\x51\x57\x08",
      .hdr_form         = 1,
      .fixed_bit        = 1,
      .long_packet_type = 3,
      .unused           = 0xf,
      .version          = 1,
      .dst_conn_id_len  = 0,
      .src_conn_id_len  = 8,
      .src_conn_id      = "\xf0\x67\xa5\x50\x2a\x42\x62\xb5",
      .retry_token      = "\x74\x6f\x6b\x65\x6e",
  };

  ulong sz = fd_quic_encode_footprint_retry_pseudo( &retry_pseudo_pkt );
  uchar buf_[sz];
  fd_quic_encode_retry_pseudo( buf_, sz, &retry_pseudo_pkt );

  /* This is a hack to get our retry packet to encrypt exactly like the example
     given in the RFC. In practice, it doesn't matter because the token is
     opaque. */
  sz -= (FD_QUIC_TOKEN_SZ_MAX - 5);
  uchar buf[sz];
  memcpy( buf, buf_, sz );

  uchar retry_integrity_tag_actual[16];
  fd_quic_retry_integrity_tag_encrypt( buf, sz, retry_integrity_tag_actual );

  uchar retry_integrity_tag_expected[16] =
      "\x04\xa2\x65\xba\x2e\xff\x4d\x82\x90\x58\xfb\x3f\x0f\x24\x96\xba";

  for ( int i = 0; i < 16; i++ ) {
    FD_TEST( retry_integrity_tag_actual[i] == retry_integrity_tag_expected[i] );
  }

  // check the retry integrity tag tag authenticates successfully (AEAD)
  int rc = fd_quic_retry_integrity_tag_decrypt( buf, sz, retry_integrity_tag_expected );
  FD_TEST( rc == FD_QUIC_SUCCESS );
}

void
test_retry_token_invalid_length( void ) {
  uchar invalid_length_retry_token[77] = {0};
  uchar *invalid_length_retry_token_ptr = invalid_length_retry_token;
  fd_quic_conn_id_t retry_src_conn_id = { .sz = 8, .conn_id = "\x42\x41\x40\x3F\x3E\x3D\x3C\x3B" };
  fd_quic_conn_id_t orig_dst_conn_id = { .sz = 20,
       .conn_id =
            "\x83\x94\xc8\xf0\x3e\x51\x57\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00\x00\x00" };
  ulong now;
  uchar retry_secret[FD_QUIC_RETRY_SECRET_SZ] = {0};
  int rc = fd_quic_retry_token_decrypt(
    retry_secret,
    invalid_length_retry_token_ptr,
    &retry_src_conn_id,
    FD_IP4_ADDR(127, 0, 0, 1),
    9000,
    &orig_dst_conn_id,
    &now
  );
  FD_TEST ( rc == FD_QUIC_FAILED );
}

/* bench_retry_server tests packet throughput for server-side retry
   handling.  Servers produce unique authenticated tokens (opauqe/custom
   scheme) and also create Retry Integrity Tags (RFC 9001). */

static void
bench_retry_server( void ) {
  FD_LOG_NOTICE(( "Benchmarking Retry" ));

  fd_quic_retry_t retry_pkt = {
    .hdr_form  = 1,
    .fixed_bit = 1,
    .unused = 0xf,
    .version = 1,
    .dst_conn_id_len = 8,
    .src_conn_id_len = 20,
  };

  uchar             retry_secret[32] = {1};
  fd_quic_conn_id_t orig_dst_conn_id = { .sz = 20 };
  fd_quic_conn_id_t new_conn_id      = { .sz = 8 };

  fd_quic_retry_pseudo_t retry_pseudo_pkt = {
      .odcid_len        = 20,
      .hdr_form         = 1,
      .fixed_bit        = 1,
      .long_packet_type = 3,
      .version          = 1,
      .dst_conn_id_len  = 8,
      .src_conn_id_len  = 20,
  };
  uchar retry_phdr[ 256 ];
  ulong retry_phdr_sz = fd_quic_encode_retry_pseudo( retry_phdr, sizeof(retry_phdr), &retry_pseudo_pkt );
  FD_TEST( retry_phdr_sz!=FD_QUIC_PARSE_FAIL );

  long dt = -fd_log_wallclock();
  ulong iter = 1000000UL;
  for( ulong j=0UL; j<iter; j++ ) {
    int rc = fd_quic_retry_token_encrypt(
        retry_secret,
        &orig_dst_conn_id,
        1UL,
        &new_conn_id,
        FD_IP4_ADDR( 127, 0, 0, 1 ),
        80U,
        retry_pkt.retry_token
    );
    FD_TEST( rc==FD_QUIC_SUCCESS );

    fd_quic_retry_integrity_tag_encrypt( retry_phdr, retry_phdr_sz, retry_pkt.retry_integrity_tag );
    FD_COMPILER_UNPREDICTABLE( retry_pkt.retry_integrity_tag[0] );
  }
  dt += fd_log_wallclock();
  double mpps = ((double)iter / ((double)dt / 1e9)) / 1e6;
  double ns   = (double)dt / (double)iter;
  FD_LOG_NOTICE(( "  ~%9.3f Mpps / core", mpps ));
  FD_LOG_NOTICE(( "  ~%9.3f ns / pkt",    ns   ));
}

/* bench_retry_client tests packet throughput for client-side retry
   handling.  Clients validate Retry Integrity Tags (RFC 9001) to
   prevent injection of bogus retries.  (Even though these can be forged
   if the attacker is able to eavesdrop) */

static void
bench_retry_client( void ) {
  FD_LOG_NOTICE(( "Benchmarking Retry Integrity Tag Verify" ));

  fd_quic_retry_pseudo_t retry_pseudo_pkt = {
      .odcid_len        = 20,
      .hdr_form         = 1,
      .fixed_bit        = 1,
      .long_packet_type = 3,
      .version          = 1,
      .dst_conn_id_len  = 8,
      .src_conn_id_len  = 20,
  };
  uchar retry_phdr[ 256 ];
  ulong retry_phdr_sz = fd_quic_encode_retry_pseudo( retry_phdr, sizeof(retry_phdr), &retry_pseudo_pkt );
  FD_TEST( retry_phdr_sz!=FD_QUIC_PARSE_FAIL );

  long dt = -fd_log_wallclock();
  ulong iter = 1000000UL;
  for( ulong j=0UL; j<iter; j++ ) {
    uchar retry_integrity_tag[16];
    (void)fd_quic_retry_integrity_tag_decrypt( retry_phdr, retry_phdr_sz, retry_integrity_tag );
    FD_COMPILER_UNPREDICTABLE( retry_integrity_tag[0] );
  }
  dt += fd_log_wallclock();
  double mpps = ((double)iter / ((double)dt / 1e9)) / 1e6;
  double ns   = (double)dt / (double)iter;
  FD_LOG_NOTICE(( "  ~%9.3f Mpps / core", mpps ));
  FD_LOG_NOTICE(( "  ~%9.3f ns / pkt",    ns   ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_retry_token_encrypt_decrypt();
  test_retry_integrity_tag();
  // test_retry_token_invalid_length();  // FIXME after error change
  bench_retry_server();
  bench_retry_client();

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
