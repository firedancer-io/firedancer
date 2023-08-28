#include "fd_tls_proto.h"

FD_STATIC_ASSERT( sizeof( fd_tls_ext_cert_type_list_t )==1UL, layout );
FD_STATIC_ASSERT( sizeof( fd_tls_ext_cert_type_t      )==1UL, layout );

/* test_client_hello is an example TLS v1.3 ClientHello captured from
   a Solana Labs v1.14.8 TPU/QUIC client. */

FD_IMPORT_BINARY( test_client_hello, "src/tango/tls/fixtures/client_hello_labs-1.14.8.bin" );

/* Further captured TLS messages */

FD_IMPORT_BINARY( test_server_hello,       "src/tango/tls/fixtures/server_hello_openssl.bin"       );
FD_IMPORT_BINARY( test_certificate,        "src/tango/tls/fixtures/certificate_openssl.bin"        );
FD_IMPORT_BINARY( test_certificate_verify, "src/tango/tls/fixtures/certificate_verify_openssl.bin" );
FD_IMPORT_BINARY( test_server_finished,    "src/tango/tls/fixtures/server_finished_openssl.bin"    );

static void
test_client_hello_decode( void ) {
  fd_tls_client_hello_t client_hello = {0};
  long sz = fd_tls_decode_client_hello( &client_hello, test_client_hello, test_client_hello_sz );
  FD_LOG_DEBUG(( "fd_tls_decode_client_hello(%p) = %ld", (void *)&client_hello, sz ));
  FD_TEST( sz == (long)test_client_hello_sz );

  fd_tls_client_hello_t client_hello_expected = {
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
  };
  FD_TEST( 0==memcmp( &client_hello, &client_hello_expected, sizeof(fd_tls_client_hello_t) ) );
}

static void
test_server_hello_encode( void ) {
  fd_tls_server_hello_t server_hello = {
    .random = {
      0x2c, 0x5d, 0x29, 0x48, 0x20, 0x08, 0xe7, 0xc6, 0x6e, 0xef, 0x18, 0x57, 0x21, 0xb8, 0x87, 0x3b,
      0x78, 0xf8, 0x26, 0x7a, 0x14, 0x56, 0xad, 0xaa, 0x92, 0x92, 0xff, 0xdf, 0xbb, 0x59, 0x78, 0xa4
    },
    .cipher_suite = FD_TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
    .key_share = {
      .has_x25519 = 1,
      .x25519 = {
        0xac, 0x45, 0x04, 0x6e, 0x3a, 0x0d, 0xdc, 0x9b, 0x82, 0x7f, 0x70, 0x50, 0x0e, 0x89, 0xe5, 0xdf,
        0x31, 0xae, 0xed, 0x42, 0xc6, 0xec, 0x48, 0xa3, 0xcb, 0x95, 0x8e, 0xe1, 0x24, 0x3a, 0x6d, 0x3f
      }
    }
  };

  uchar server_hello_buf[ 1280 ];
  long sz = fd_tls_encode_server_hello( &server_hello, server_hello_buf, sizeof(server_hello_buf) );
  FD_TEST( sz>=0L );
  FD_LOG_HEXDUMP_DEBUG(( "fd_tls_encode_server_hello", server_hello_buf, (ulong)sz ));
}

static void
test_server_hello_decode( void ) {
  fd_tls_server_hello_t server_hello[1] = {0};
  long sz = fd_tls_decode_server_hello( server_hello, test_server_hello+4, test_server_hello_sz-4 );
  FD_TEST( sz>=0L );
}

static void
test_server_finished_decode( void ) {
  fd_tls_finished_t finished[1] = {0};
  long sz = fd_tls_decode_finished( finished, test_server_finished+4, test_server_finished_sz-4 );
  FD_TEST( sz>=0L );
}

int
main( int     argc,
      char ** argv) {
  fd_boot( &argc, &argv );

  test_client_hello_decode();
  test_server_hello_encode();
  test_server_hello_decode();
  test_server_finished_decode();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

