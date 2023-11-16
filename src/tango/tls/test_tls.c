#include "fd_tls_proto.h"

FD_STATIC_ASSERT( sizeof( fd_tls_ext_cert_type_list_t )==1UL, layout );
FD_STATIC_ASSERT( sizeof( fd_tls_ext_cert_type_t      )==1UL, layout );

static void test_tls_proto( void );
static void test_tls_pair ( void );

int
main( int     argc,
      char ** argv) {
  fd_boot( &argc, &argv );

  test_tls_proto();
  test_tls_pair();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

/* Serialization related testing **************************************/

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
  /* TODO compare QUIC transport params */
  /* Clear out QUIC transport params, as those will have to be compared separately */
  client_hello.quic_tp = (fd_tls_ext_quic_tp_t){0};
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

static void
test_tls_proto( void ) {
  test_client_hello_decode();
  test_server_hello_encode();
  test_server_hello_decode();
  test_server_finished_decode();
}

/* Client/server integration test *************************************/

/* TODO test with and without QUIC transport params */

#include "fd_tls.h"
#include "test_tls_helper.h"

#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_x25519.h"

static test_record_buf_t test_server_out = {0};
static test_record_buf_t test_client_out = {0};

static void const * test_server_hs = NULL;

int
test_tls_sendmsg( void const * hs,
                  void const * record,
                  ulong        record_sz,
                  uint         encryption_level,
                  int          flush ) {
  (void)flush;
  int from_server = hs==test_server_hs;
  test_record_log( record, record_sz, from_server );
  test_record_send( from_server ? &test_server_out : &test_client_out,
                    encryption_level, record, record_sz );
  return 1;
}

static void
test_tls_client_respond( fd_tls_t *            client,
                         fd_tls_estate_cli_t * hs ) {
  test_record_t * rec;
  while( (rec = test_record_recv( &test_server_out )) ) {
    long res = fd_tls_client_handshake( client, hs, rec->buf, rec->cur, rec->level );
    if( res<0L ) {
      FD_LOG_ERR(( "fd_tls_client_handshake failed (alert %ld-%s; reason %u-%s)",
                   res,             fd_tls_alert_cstr( (uint)-res ),
                   hs->base.reason, fd_tls_reason_cstr( hs->base.reason ) ));
      fd_halt();
    }
  }
}

static void
test_tls_server_respond( fd_tls_t *            server,
                         fd_tls_estate_srv_t * hs ) {
  test_record_t * rec;
  while( (rec = test_record_recv( &test_client_out )) ) {
    long res = fd_tls_server_handshake( server, hs, rec->buf, rec->cur, rec->level );
    if( res<0L ) {
      FD_LOG_ERR(( "fd_tls_server_handshake failed (alert %ld-%s; reason %u-%s)",
                   res,             fd_tls_alert_cstr( (uint)-res ),
                   hs->base.reason, fd_tls_reason_cstr( hs->base.reason ) ));
      fd_halt();
    }
  }
}

static void
test_tls_secrets( void const * handshake        FD_FN_UNUSED,
                  void const * recv_secret      FD_FN_UNUSED,
                  void const * send_secret      FD_FN_UNUSED,
                  uint         encryption_level FD_FN_UNUSED ) {}

static void
test_tls_pair( void ) {
  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  fd_rng_t  _rng[1];   fd_rng_t * rng    = fd_rng_join   ( fd_rng_new   ( _rng, 0U, 0UL ) );

  /* Set up client and server objects */

  fd_tls_t  _client[1];
  fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
  *client = (fd_tls_t) {
    .rand       =  fd_tls_test_rand( rng ),
    .secrets_fn = test_tls_secrets,
    .sendmsg_fn = test_tls_sendmsg,
  };

  fd_tls_t _server[1];
  fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
  *server = (fd_tls_t) {
    .rand       = fd_tls_test_rand( rng ),
    .secrets_fn = test_tls_secrets,
    .sendmsg_fn = test_tls_sendmsg,
  };

  /* Generate keys */

  for( ulong b=0; b<32UL; b++ ) server->kex_private_key [b] = fd_rng_uchar( rng );
  for( ulong b=0; b<32UL; b++ ) server->cert_private_key[b] = fd_rng_uchar( rng );
  for( ulong b=0; b<32UL; b++ ) client->kex_private_key [b] = fd_rng_uchar( rng );
  for( ulong b=0; b<32UL; b++ ) client->cert_private_key[b] = fd_rng_uchar( rng );

  fd_x25519_public( server->kex_public_key, server->kex_private_key );
  fd_x25519_public( client->kex_public_key, client->kex_private_key );

  fd_ed25519_public_from_private( server->cert_public_key, server->cert_private_key, sha );
  fd_ed25519_public_from_private( client->cert_public_key, client->cert_private_key, sha );

  /* Create handshake objects */

  fd_tls_estate_srv_t srv_hs[1];
  FD_TEST( fd_tls_estate_srv_new( srv_hs ) );
  test_server_hs = srv_hs;

  fd_tls_estate_cli_t cli_hs[1];
  FD_TEST( fd_tls_estate_cli_new( cli_hs ) );
  fd_memcpy( cli_hs->server_pubkey, server->cert_public_key, 32UL );

  /* Do handshake */

  /* ClientHello */
  fd_tls_client_handshake( client, cli_hs, NULL, 0UL, FD_TLS_LEVEL_INITIAL );
  /* ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished */
  test_tls_server_respond( server, srv_hs );
  /* Finished */
  test_tls_client_respond( client, cli_hs );
  /* Process final Finished */
  test_tls_server_respond( server, srv_hs );

  /* Check if connected */
  FD_TEST( srv_hs->base.state==FD_TLS_HS_CONNECTED );
  FD_TEST( cli_hs->base.state==FD_TLS_HS_CONNECTED );

  test_server_hs = NULL;
  fd_tls_estate_srv_delete( srv_hs );
  fd_tls_estate_cli_delete( cli_hs );
  fd_tls_delete( fd_tls_leave( server ) );
  fd_tls_delete( fd_tls_leave( client ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_sha512_delete( fd_sha512_leave( sha ) );
}
