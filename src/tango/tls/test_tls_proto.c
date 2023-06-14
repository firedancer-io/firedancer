#include "fd_tls_proto.h"

/* test_client_hello is an example TLS v1.3 ClientHello captured from
   a Solana Labs v1.14.8 TPU/QUIC client. */

FD_IMPORT_BINARY( test_client_hello, "src/tango/tls/fixtures/client_hello_labs-1.14.8.bin" );

int
main( int     argc,
      char ** argv) {
  fd_boot( &argc, &argv );

  fd_tls_client_hello_t client_hello[1] = {0};
  long sz = fd_tls_decode_client_hello( client_hello, test_client_hello, test_client_hello_sz );
  FD_TEST( sz == (long)test_client_hello_sz );

  fd_tls_client_hello_t client_hello_expected[1] = {{
    .random = {
      0xb5, 0x17, 0xc7, 0x84, 0xdc, 0xf1, 0x03, 0x1b, 0x4a, 0x95, 0xab, 0x98, 0x89, 0x07, 0x0f, 0x13,
      0x93, 0x69, 0xeb, 0xb7, 0x27, 0x53, 0x5b, 0xa4, 0x22, 0xfe, 0xbc, 0x21, 0x4d, 0xc1, 0xc0, 0xe7
    },
    .cipher_suites = { .aes_128_gcm_sha256 = 1 },
    .supported_versions = { .tls13 = 1 },
    .server_name = {
      .host_name     = "connect",
      .host_name_len = 7
    },
    .supported_groups = { .x25519 = 1 },
    .signature_algorithms = { .ed25519 = 1 },
    .key_share = {
      .has_x25519 = 1,
      .x25519 = {
        0xcf, 0x24, 0x6d, 0x65, 0x48, 0xfd, 0xdf, 0x77, 0x52, 0xd5, 0x87, 0xac, 0xff, 0x9e, 0x93, 0xa5,
        0x3c, 0x8b, 0x46, 0xdd, 0xb2, 0x2d, 0x1f, 0xbc, 0xef, 0x82, 0xe6, 0x71, 0x57, 0xab, 0x11, 0x3c
      }
    }
  }};
  FD_TEST( 0==memcmp( client_hello, client_hello_expected, sizeof(fd_tls_client_hello_t) ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

