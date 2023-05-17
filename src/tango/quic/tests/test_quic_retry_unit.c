#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "../fd_quic.h"
#include "../crypto/fd_quic_crypto_suites.h"

void test_token_encrypt_decrypt()
{
  uchar orig_dst_conn_id[FD_QUIC_MAX_CONN_ID_SZ] = "\x42";
  ulong retry_src_conn_id = 0x2a2a2a2a2a2a2a2a;
  fd_quic_net_endpoint_t client = {.ip_addr = 42, .udp_port = 42};
  uchar retry_token[FD_QUIC_RETRY_TOKEN_SZ];

  fd_quic_retry_token_encrypt(
      orig_dst_conn_id,
      retry_src_conn_id,
      client.ip_addr,
      client.udp_port,
      retry_token);

  uchar orig_dst_conn_id_decrypt[FD_QUIC_MAX_CONN_ID_SZ];
  long retry_token_ts_decrypt;
  fd_quic_retry_token_decrypt(
      retry_token,
      retry_src_conn_id,
      client.ip_addr,
      client.udp_port,
      orig_dst_conn_id_decrypt,
      &retry_token_ts_decrypt);

  FD_TEST(orig_dst_conn_id == orig_dst_conn_id_decrypt);
}

void test_token_invalid_length() {}

/* Invariant: a valid retry token should always decrypt to the original inputs. */
void test_property_token_encrypt_decrypt() {}

/* Invariant: invalid-length tokens should always return an error. */
void test_property_token_invalid_length_decrypt() {}

/* Invariant: invalid-length tokens should always return an error. */
void test_integrity_tag_encrypt_decrypt() {}

int main(int argc,
         char **argv)
{
  fd_boot(&argc, &argv);

  if (FD_UNLIKELY(argc > 1))
    FD_LOG_ERR(("unrecognized argument: %s", argv[1]));

  test_token_encrypt_decrypt();

  FD_LOG_NOTICE(("pass"));
  fd_halt();
  return 0;
}
