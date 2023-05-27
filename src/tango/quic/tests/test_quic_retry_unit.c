#include "../crypto/fd_quic_crypto_suites.h"
#include "../fd_quic.h"

#include "../fd_quic_common.h"
#include "../fd_quic_types.h"

#include "../templ/fd_quic_defs.h"
#include "../templ/fd_quic_templ.h"
#include "../templ/fd_quic_frames_templ.h"
#include "../templ/fd_quic_ipv4.h"
#include "../templ/fd_quic_udp.h"
#include "../templ/fd_quic_eth.h"
#include "../templ/fd_quic_undefs.h"

#include "../templ/fd_quic_encoders_decl.h"
#include "../templ/fd_quic_templ.h"
#include "../templ/fd_quic_frames_templ.h"
#include "../templ/fd_quic_ipv4.h"
#include "../templ/fd_quic_udp.h"
#include "../templ/fd_quic_eth.h"
#include "../templ/fd_quic_undefs.h"

void test_retry_token_encrypt_decrypt()
{
  fd_quic_conn_id_t orig_dst_conn_id = {
    .sz = 1,
    .conn_id = {42}
  };
  ulong retry_src_conn_id = 0x2a2a2a2a2a2a2a2a;
  fd_quic_net_endpoint_t client = {.ip_addr = 42, .udp_port = 42};
  uchar retry_token[FD_QUIC_RETRY_TOKEN_SZ];
  long now = fd_log_wallclock();

  fd_quic_retry_token_encrypt(
      &orig_dst_conn_id,
      &now,
      retry_src_conn_id,
      client.ip_addr,
      client.udp_port,
      retry_token);

  fd_quic_conn_id_t orig_dst_conn_id_decrypt;
  long now_decrypt;

  fd_quic_retry_token_decrypt(
      retry_token,
      retry_src_conn_id,
      client.ip_addr,
      client.udp_port,
      &orig_dst_conn_id_decrypt,
      &now_decrypt);

  FD_TEST(orig_dst_conn_id.sz == orig_dst_conn_id_decrypt.sz);
  for (int i = 0; i < orig_dst_conn_id.sz; i++) {
    FD_TEST(orig_dst_conn_id.conn_id[i] == orig_dst_conn_id_decrypt.conn_id[i]);
  }
}

void do_something(uchar **ptr, uchar **buf) {
  *ptr = *buf;
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
void test_retry_integrity_tag()
{
  fd_quic_retry_pseudo_t retry_pseudo_pkt = {
    .odcid_length = 8,
    .odcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08",
    .hdr_form = 1,
    .fixed_bit = 1,
    .long_packet_type = 3,
    .unused = 0xf,
    .version = 1,
    .dst_conn_id_len = 0,
    .src_conn_id_len = 8,
    .src_conn_id = "\xf0\x67\xa5\x50\x2a\x42\x62\xb5",
    .retry_token = "\x74\x6f\x6b\x65\x6e",
  };

  ulong sz = fd_quic_encode_footprint_retry_pseudo(&retry_pseudo_pkt);
  uchar buf_[sz];
  fd_quic_encode_retry_pseudo(buf_, sz, &retry_pseudo_pkt);

  // FIXME variable-length encodings without len field
  // FIXME hack around it by using 100-byte retry tokens -- but this sample use 5-byte
  sz -= 95;
  uchar buf[sz];
  memcpy(buf, buf_, sz);

  uchar retry_integrity_tag_actual[16];
  fd_quic_retry_integrity_tag_encrypt(buf, (int) sz, retry_integrity_tag_actual);

  uchar retry_integrity_tag_expected[16] = "\x04\xa2\x65\xba\x2e\xff\x4d\x82\x90\x58\xfb\x3f\x0f\x24\x96\xba";

  for (int i = 0; i < 16; i++)
  {
    FD_TEST( retry_integrity_tag_actual[i] == retry_integrity_tag_expected[i] );
  }
  // FD_LOG_HEXDUMP_NOTICE(("actual", retry_integrity_tag_actual, 16));
  // FD_LOG_HEXDUMP_NOTICE(("expected", retry_integrity_tag_expected, 16));

  // check the retry integrity tag tag authenticates successfully (AEAD)
  int rc = fd_quic_retry_integrity_tag_decrypt(buf, (int) sz, retry_integrity_tag_expected);
  FD_TEST( rc == FD_QUIC_SUCCESS );
}


void test_retry_token_invalid_length() {}

/* Invariant: a valid token should always decrypt to the original inputs. */
void test_property_retry_token_encrypt_decrypt() {}

/* Invariant: invalid-length tokens should always return an error. */
void test_property_retry_token_invalid_length_decrypt() {}

/* Invariant: generating and checking the integrity tag should always match. */
void test_property_retry_integrity_tag_encrypt_decrypt() {}

int main(int argc,
         char **argv)
{
  fd_boot(&argc, &argv);

  if (FD_UNLIKELY(argc > 1))
    FD_LOG_ERR(("unrecognized argument: %s", argv[1]));

  test_retry_token_encrypt_decrypt();
  test_retry_integrity_tag();

  FD_LOG_NOTICE(("pass"));
  fd_halt();
  return 0;
}
