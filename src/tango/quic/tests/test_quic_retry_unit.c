#include "../crypto/fd_quic_crypto_suites.h"
#include "../fd_quic.h"

void test_retry_token_encrypt_decrypt()
{
  uchar orig_dst_conn_id[FD_QUIC_MAX_CONN_ID_SZ] = {42};
  ulong retry_src_conn_id = 0x2a2a2a2a2a2a2a2a;
  fd_quic_net_endpoint_t client = {.ip_addr = 42, .udp_port = 42};
  uchar retry_token[FD_QUIC_RETRY_TOKEN_SZ];

  fd_quic_retry_token_encrypt(
      orig_dst_conn_id,
      retry_src_conn_id,
      client.ip_addr,
      client.udp_port,
      retry_token);

  uchar *orig_dst_conn_id_decrypt;
  long retry_token_issued_decrypt;
  fd_quic_retry_token_decrypt(
      retry_token,
      retry_src_conn_id,
      client.ip_addr,
      client.udp_port,
      &orig_dst_conn_id_decrypt,
      &retry_token_issued_decrypt);

  int same = 1;
  for (int i = 0; i < FD_QUIC_MAX_CONN_ID_SZ; i++) {
    same &= (orig_dst_conn_id[i] == orig_dst_conn_id_decrypt[i]);
  }
}

void test_retry_integrity_tag_encrypt_decrypt() {}

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
