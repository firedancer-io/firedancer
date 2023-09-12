#include "../crypto/fd_quic_crypto_suites.h"
#include "../fd_quic.h"

#include "../fd_quic_common.h"
#include "../fd_quic_types.h"

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

  for ( int i = 0; i < NUM_TEST_CASES; i++ ) {
    fd_quic_conn_id_t orig_dst_conn_id  = orig_dst_conn_ids[i];
    fd_quic_conn_id_t retry_src_conn_id = retry_src_conn_ids[i];

    fd_quic_retry_token_encrypt(
        &orig_dst_conn_id, now, &retry_src_conn_id, client.ip_addr, client.udp_port, retry_token
    );

    fd_quic_conn_id_t orig_dst_conn_id_decrypt;
    ulong             now_decrypt;

    fd_quic_retry_token_decrypt(
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
  fd_quic_retry_integrity_tag_encrypt( buf, (int)sz, retry_integrity_tag_actual );

  uchar retry_integrity_tag_expected[16] =
      "\x04\xa2\x65\xba\x2e\xff\x4d\x82\x90\x58\xfb\x3f\x0f\x24\x96\xba";

  for ( int i = 0; i < 16; i++ ) {
    FD_TEST( retry_integrity_tag_actual[i] == retry_integrity_tag_expected[i] );
  }

  // check the retry integrity tag tag authenticates successfully (AEAD)
  int rc = fd_quic_retry_integrity_tag_decrypt( buf, (int)sz, retry_integrity_tag_expected );
  FD_TEST( rc == FD_QUIC_SUCCESS );
}

void
test_retry_token_invalid_length( void ) {
  uchar invalid_length_retry_token[42] = {0};
  uchar *invalid_length_retry_token_ptr = invalid_length_retry_token;
  fd_quic_conn_id_t retry_src_conn_id = { .sz = 8, .conn_id = "\x42\x41\x40\x3F\x3E\x3D\x3C\x3B" };
  fd_quic_conn_id_t orig_dst_conn_id = { .sz = 20,
       .conn_id =
            "\x83\x94\xc8\xf0\x3e\x51\x57\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00\x00\x00" };
  ulong now;
  int rc = fd_quic_retry_token_decrypt(
    invalid_length_retry_token_ptr,
    &retry_src_conn_id,
    FD_IP4_ADDR(127, 0, 0, 1),
    9000,
    &orig_dst_conn_id,
    &now
  );
  FD_TEST ( rc == FD_QUIC_FAILED );
}

/* Invariant: a valid token should always decrypt to the original inputs. */
void
test_property_retry_token_encrypt_decrypt( void ) {
  /* TODO */
}

/* Invariant: invalid-length tokens should always return an error. */
void
test_property_retry_token_invalid_length_decrypt( void ) {
  /* TODO */
}

/* Invariant: generating and checking the integrity tag should always match. */
void
test_property_retry_integrity_tag_encrypt_decrypt( void ) {
  /* TODO */
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_retry_token_encrypt_decrypt();
  test_retry_integrity_tag();
  // test_retry_token_invalid_length();  // FIXME after error change

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
