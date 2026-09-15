#include "fd_tls_proto.h"
#include "../../ballet/x509/fd_x509_mock.h"

/* Serialization related testing **************************************/

/* test_client_hello is an example TLS v1.3 ClientHello captured from
   a Solana Labs v1.14.8 TPU/QUIC client. */

FD_IMPORT_BINARY( test_client_hello, "src/waltz/tls/fixtures/client_hello_labs-1.14.8.bin" );

/* Further captured TLS messages */

FD_IMPORT_BINARY( test_server_hello,       "src/waltz/tls/fixtures/server_hello_openssl.bin"       );
FD_IMPORT_BINARY( test_certificate,        "src/waltz/tls/fixtures/certificate_openssl.bin"        );
FD_IMPORT_BINARY( test_certificate_verify, "src/waltz/tls/fixtures/certificate_verify_openssl.bin" );
FD_IMPORT_BINARY( test_server_finished,    "src/waltz/tls/fixtures/server_finished_openssl.bin"    );

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
    .signature_algorithms = { .ed25519 = 1, .ecdsa_secp256r1_sha256 = 1, .ecdsa_secp384r1_sha384 = 1 },
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
  client_hello.quic_tp    = (fd_tls_ext_quic_tp_t){0};
  client_hello.alpn       = (fd_tls_ext_alpn_t   ){0};
  client_hello.session_id = (fd_tls_ext_opaque_t ){0};
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

static ulong
test_tls_append_ext( uchar *       wire,
                     ulong         sz,
                     ulong         ext_off,
                     ushort        type,
                     uchar const * data,
                     ushort        data_sz ) {
  FD_STORE( ushort, wire+sz,   fd_ushort_bswap( type ) );
  FD_STORE( ushort, wire+sz+2, fd_ushort_bswap( data_sz ) );
  if( data_sz ) fd_memcpy( wire+sz+4, data, data_sz );
  sz += 4UL+data_sz;
  FD_STORE( ushort, wire+ext_off, fd_ushort_bswap( (ushort)(sz-ext_off-2UL) ) );
  return sz;
}

static void
test_tls_extension_rules( void ) {
  uchar wire[1024];
  uchar copy[1024];
  fd_tls_client_hello_t ch = { .signature_algorithms = { .ed25519=1 } };
  long encoded = fd_tls_encode_client_hello( &ch, wire, sizeof(wire) );
  FD_TEST( encoded>0L );
  ulong sz = (ulong)encoded;
  ulong const ch_ext_off = 41UL;

  fd_memcpy( copy, wire, sz );
  copy[35] = copy[36] = 0;
  FD_TEST( fd_tls_decode_client_hello( &ch, copy, sz )==-FD_TLS_ALERT_DECODE_ERROR );

  /* Duplicate extensions are rejected (unknown types are not tracked) */
  sz = test_tls_append_ext( wire, sz, ch_ext_off, 0xfafa, NULL, 0 );
  ch = (fd_tls_client_hello_t){0};
  FD_TEST( fd_tls_decode_client_hello( &ch, wire, sz )==(long)sz );
  for( ulong off=ch_ext_off+2UL; off<sz; ) {
    ushort type = fd_ushort_bswap( FD_LOAD( ushort, wire+off ) );
    ushort len  = fd_ushort_bswap( FD_LOAD( ushort, wire+off+2UL ) );
    fd_memcpy( copy, wire, sz );
    ulong dup_sz = test_tls_append_ext( copy, sz, ch_ext_off, type, wire+off+4UL, len );
    ch = (fd_tls_client_hello_t){0};
    FD_TEST( fd_tls_decode_client_hello( &ch, copy, dup_sz )==( type<64 ? -FD_TLS_ALERT_ILLEGAL_PARAMETER : (long)dup_sz ) );
    if( type!=0xfafa ) {
      fd_memcpy( copy, wire, sz );
      FD_STORE( ushort, copy+off, fd_ushort_bswap( (ushort)0xfafb ) );
      ch = (fd_tls_client_hello_t){0};
      FD_TEST( fd_tls_decode_client_hello( &ch, copy, sz )==(long)sz );
    }
    if( type==FD_TLS_EXT_KEY_SHARE ) {
      fd_memcpy( copy, wire, sz );
      FD_TEST( len==38U );
      FD_STORE( ushort, copy+off+2UL, fd_ushort_bswap( (ushort)2 ) );
      FD_STORE( ushort, copy+off+4UL, 0 );
      memmove( copy+off+6UL, copy+off+4UL+len, sz-off-4UL-len );
      FD_STORE( ushort, copy+ch_ext_off, fd_ushort_bswap( (ushort)(sz-36UL-ch_ext_off-2UL) ) );
      ch = (fd_tls_client_hello_t){0};
      FD_TEST( fd_tls_decode_client_hello( &ch, copy, sz-36UL )==(long)(sz-36UL) );
      FD_TEST( !ch.key_share.has_x25519 );
    }
    off += 4UL+len;
  }

  fd_tls_server_hello_t sh = {0};
  encoded = fd_tls_encode_server_hello( &sh, wire, sizeof(wire) );
  FD_TEST( encoded>0L );
  sz = (ulong)encoded;
  ulong const sh_ext_off = 38UL;
  for( ulong off=sh_ext_off+2UL; off<sz; ) {
    ushort type = fd_ushort_bswap( FD_LOAD( ushort, wire+off ) );
    ushort len  = fd_ushort_bswap( FD_LOAD( ushort, wire+off+2UL ) );
    fd_memcpy( copy, wire, sz );
    ulong dup_sz = test_tls_append_ext( copy, sz, sh_ext_off, type, wire+off+4UL, len );
    sh = (fd_tls_server_hello_t){0};
    FD_TEST( fd_tls_decode_server_hello( &sh, copy, dup_sz )==-FD_TLS_ALERT_ILLEGAL_PARAMETER );
    fd_memcpy( copy, wire, sz );
    FD_STORE( ushort, copy+off, fd_ushort_bswap( (ushort)0xfafa ) );
    sh = (fd_tls_server_hello_t){0};
    FD_TEST( fd_tls_decode_server_hello( &sh, copy, sz )==-FD_TLS_ALERT_UNSUPPORTED_EXTENSION );
    fd_memcpy( copy, wire, sz );
    memmove( copy+off, copy+off+4UL+len, sz-off-4UL-len );
    FD_STORE( ushort, copy+sh_ext_off, fd_ushort_bswap( (ushort)(sz-4UL-len-sh_ext_off-2UL) ) );
    sh = (fd_tls_server_hello_t){0};
    FD_TEST( fd_tls_decode_server_hello( &sh, copy, sz-4UL-len )==
             (type==FD_TLS_EXT_SUPPORTED_VERSIONS ? -FD_TLS_ALERT_PROTOCOL_VERSION : -FD_TLS_ALERT_MISSING_EXTENSION) );
    off += 4UL+len;
  }
  sz = test_tls_append_ext( wire, sz, sh_ext_off, FD_TLS_EXT_QUIC_TRANSPORT_PARAMS, NULL, 0 );
  sh = (fd_tls_server_hello_t){0};
  FD_TEST( fd_tls_decode_server_hello( &sh, wire, sz )==-FD_TLS_ALERT_UNSUPPORTED_EXTENSION );

  uchar const groups[] = { 0, 2, 0, 29 };
  fd_tls_enc_ext_t ee = {0};
  sz = test_tls_append_ext( wire, 2UL, 0UL, FD_TLS_EXT_SUPPORTED_GROUPS, groups, sizeof(groups) );
  FD_TEST( fd_tls_decode_enc_ext( &ee, wire, sz )==(long)sz );
  sz = test_tls_append_ext( wire, sz, 0UL, FD_TLS_EXT_SUPPORTED_GROUPS, groups, sizeof(groups) );
  FD_TEST( fd_tls_decode_enc_ext( &ee, wire, sz )==-FD_TLS_ALERT_ILLEGAL_PARAMETER );
  sz = test_tls_append_ext( wire, 2UL, 0UL, FD_TLS_EXT_KEY_SHARE, NULL, 0 );
  FD_TEST( fd_tls_decode_enc_ext( &ee, wire, sz )==-FD_TLS_ALERT_UNSUPPORTED_EXTENSION );
  sz = test_tls_append_ext( wire, 2UL, 0UL, 0xfafa, NULL, 0 );
  FD_TEST( fd_tls_decode_enc_ext( &ee, wire, sz )==-FD_TLS_ALERT_UNSUPPORTED_EXTENSION );
}

static void
test_tls_vectors( void ) {
  uchar const empty[] = {0,0};
  fd_tls_ext_signature_algorithms_t sig = {0};
  fd_tls_ext_supported_groups_t groups = {0};
  fd_tls_ext_supported_versions_t versions = {0};
  fd_tls_ext_server_name_t sni = {0};
  fd_tls_key_share_t share = {0};
  fd_tls_ext_alpn_t alpn = {0};
  FD_TEST( fd_tls_decode_ext_signature_algorithms( &sig, empty, 2UL )==-FD_TLS_ALERT_DECODE_ERROR );
  FD_TEST( fd_tls_decode_ext_supported_groups( &groups, empty, 2UL )==-FD_TLS_ALERT_DECODE_ERROR );
  FD_TEST( fd_tls_decode_ext_supported_versions( &versions, empty, 1UL )==-FD_TLS_ALERT_DECODE_ERROR );
  FD_TEST( fd_tls_decode_ext_server_name( &sni, empty, 2UL )==-FD_TLS_ALERT_DECODE_ERROR );
  FD_TEST( fd_tls_decode_ext_alpn( &alpn, empty, 2UL )==-FD_TLS_ALERT_DECODE_ERROR );
  FD_TEST( fd_tls_decode_key_share_list( &share, empty, 2UL )==2L );
  uchar dup_share[ 2+2*36 ] = { 0,72, 0,29,0,32 };
  fd_memcpy( dup_share+38, dup_share+2, 4UL );
  share = (fd_tls_key_share_t){0};
  FD_TEST( fd_tls_decode_key_share_list( &share, dup_share, sizeof(dup_share) )==-FD_TLS_ALERT_ILLEGAL_PARAMETER );
  uchar const empty_share[] = { 0,4, 0xfa,0xfa,0,0 };
  FD_TEST( fd_tls_decode_key_share_list( &share, empty_share, sizeof(empty_share) )==-FD_TLS_ALERT_DECODE_ERROR );
  uchar const bad_alpn[][6] = {
    { 0,4, 1,'h',0,0 },
    { 0,4, 1,'h',2,'x' }
  };
  for( ulong i=0UL; i<2UL; i++ )
    FD_TEST( fd_tls_decode_ext_alpn( &alpn, bad_alpn[i], 6UL )==-FD_TLS_ALERT_DECODE_ERROR );
  uchar const multi_alpn[] = { 0,4, 1,'h',1,'x' };
  FD_TEST( fd_tls_decode_ext_alpn( &alpn, multi_alpn, sizeof(multi_alpn) )==6L );
  uchar wire[32];
  ulong sz = test_tls_append_ext( wire, 2UL, 0UL, FD_TLS_EXT_ALPN, multi_alpn, sizeof(multi_alpn) );
  fd_tls_enc_ext_t ee = {0};
  FD_TEST( fd_tls_decode_enc_ext( &ee, wire, sz )==-FD_TLS_ALERT_DECODE_ERROR );
}

/* Client/server integration test *************************************/

/* TODO test with and without QUIC transport params */

#include "fd_tls.h"
#include "test_tls_helper.h"

#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/hmac/fd_hmac.h"

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
      fd_halt();
      FD_LOG_ERR(( "fd_tls_client_handshake failed (alert %ld-%s; reason %u-%s)",
                   res,             fd_tls_alert_cstr( (uint)-res ),
                   hs->base.reason, fd_tls_reason_cstr( hs->base.reason ) ));
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
    }
  }
}

static void
test_tls_secrets( void const * handshake        FD_FN_UNUSED,
                  void const * recv_secret      FD_FN_UNUSED,
                  void const * send_secret      FD_FN_UNUSED,
                  uint         encryption_level FD_FN_UNUSED ) {}

static void
prepare_tls_pair( fd_rng_t * rng,
                  fd_tls_t * client,
                  fd_tls_t * server ) {
  static fd_tls_test_sign_ctx_t client_sign_ctx[1], server_sign_ctx[1];
  static fd_chacha_rng_t client_chacha[1], server_chacha[1];
  fd_tls_test_sign_ctx( client_sign_ctx, rng );
  fd_tls_test_sign_ctx( server_sign_ctx, rng );

  *client = (fd_tls_t) {
    .rng        = fd_tls_test_rand( client_chacha, rng ),
    .sign       = fd_tls_test_sign( &client_sign_ctx ),
    .secrets_fn = test_tls_secrets,
    .sendmsg_fn = test_tls_sendmsg,
  };

  *server = (fd_tls_t) {
    .rng        = fd_tls_test_rand( server_chacha, rng ),
    .sign       = fd_tls_test_sign( &server_sign_ctx ),
    .secrets_fn = test_tls_secrets,
    .sendmsg_fn = test_tls_sendmsg,
  };

  /* Generate keys */

  for( ulong b=0; b<32UL; b++ ) server->kex_private_key [b] = fd_rng_uchar( rng );
  fd_memcpy( server->cert_public_key, server_sign_ctx->public_key, 32UL );
  for( ulong b=0; b<32UL; b++ ) client->kex_private_key [b] = fd_rng_uchar( rng );
  fd_memcpy( client->cert_public_key, client_sign_ctx->public_key, 32UL );

  fd_x509_mock_cert( server->cert_x509, server->cert_public_key );
  server->cert_x509_sz = FD_X509_MOCK_CERT_SZ;
  fd_x509_mock_cert( client->cert_x509, client->cert_public_key );
  client->cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  fd_x25519_public( server->kex_public_key, server->kex_private_key );
  fd_x25519_public( client->kex_public_key, client->kex_private_key );
}

static void
test_tls_pair( fd_rng_t * rng ) {

  /* Set up client and server objects */

  fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
  fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
  prepare_tls_pair( rng, client, server );

  /* Create handshake objects */

  fd_tls_estate_srv_t srv_hs[1]; FD_TEST( fd_tls_estate_srv_new( srv_hs ) );
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
}

static void
test_tls_client_wrong_ciphersuite( fd_rng_t * rng ) {

  /* Set up client and server objects */

  fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
  fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
  prepare_tls_pair( rng, client, server );

  /* Create handshake objects */

  fd_tls_estate_srv_t srv_hs[1]; FD_TEST( fd_tls_estate_srv_new( srv_hs ) );
  test_server_hs = srv_hs;

  fd_tls_estate_cli_t cli_hs[1];
  FD_TEST( fd_tls_estate_cli_new( cli_hs ) );
  fd_memcpy( cli_hs->server_pubkey, server->cert_public_key, 32UL );

  /* Send a ClientHello with only an unsupported cipher suite
     (TLS_CHACHA20_POLY1305_SHA256) */

  static uchar const client_hello[] =
    { 0x01, 0x00, 0x00, 0xbb, 0x03, 0x03, 0x6a, 0x9d, 0xe3, 0xec, 0xd3, 0x52, 0x11, 0x55, 0x5d, 0x2c,
      0xe8, 0x1c, 0x96, 0xb2, 0x17, 0x0b, 0x23, 0x34, 0x8d, 0x1d, 0x82, 0x12, 0x89, 0xe0, 0x9d, 0x31,
      0x1b, 0xc0, 0x7f, 0xe8, 0x92, 0xa3, 0x00, 0x00, 0x02, 0x13, 0x03, 0x01, 0x00, 0x00, 0x90, 0x00,
      0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
      0x4e, 0xf4, 0x92, 0x5b, 0x61, 0x0f, 0x99, 0x8d, 0x6f, 0xbc, 0xb7, 0x58, 0x91, 0x6b, 0x5d, 0x31,
      0x26, 0x5f, 0xc0, 0x3f, 0xc0, 0xd1, 0x49, 0xab, 0xb9, 0xd3, 0x9e, 0x46, 0x20, 0x9a, 0xd4, 0x53,
      0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07,
      0x00, 0x10, 0x00, 0x0d, 0x00, 0x0b, 0x0a, 0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x2d, 0x74, 0x70,
      0x75, 0x00, 0x39, 0x00, 0x2c, 0x01, 0x02, 0x40, 0xc8, 0x03, 0x02, 0x45, 0xc0, 0x04, 0x01, 0x00,
      0x07, 0x04, 0x80, 0x01, 0x00, 0x00, 0x08, 0x01, 0x00, 0x09, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x0b,
      0x01, 0x0a, 0x0c, 0x00, 0x0e, 0x01, 0x10, 0x0f, 0x08, 0xb7, 0xcf, 0x30, 0xe6, 0x2e, 0x3b, 0xac,
      0xa4, 0x00, 0x14, 0x00, 0x03, 0x02, 0x02, 0x00, 0x00, 0x13, 0x00, 0x03, 0x02, 0x02, 0x00 };

  long alert = fd_tls_server_handshake( server, srv_hs, client_hello, sizeof(client_hello), FD_TLS_LEVEL_INITIAL );
  FD_TEST( alert == -FD_TLS_ALERT_HANDSHAKE_FAILURE );
  FD_TEST( srv_hs->base.reason == FD_TLS_REASON_CH_NEG_CIPHER );

  fd_tls_estate_srv_delete( srv_hs );
  fd_tls_estate_cli_delete( cli_hs );
  fd_tls_delete( fd_tls_leave( server ) );
  fd_tls_delete( fd_tls_leave( client ) );
}

static ulong test_tls_quic_tp_self( void * handshake, uchar * quic_tp, ulong quic_tp_bufsz );

/* ServerHello template with a 32 byte legacy_session_id_echo slot at
   offset 39 and the cipher suite at offset 71. */

static uchar const test_sh_template[] =
  { 0x02, 0x00, 0x00, 0x76, 0x03, 0x03, 0xb0, 0x4f, 0x8f, 0xf4, 0x62, 0xd2, 0x47, 0xca, 0x62, 0x37,
    0x19, 0x41, 0x70, 0xca, 0x83, 0x01, 0x00, 0x75, 0x76, 0xdf, 0x3b, 0xc3, 0x27, 0x1f, 0xa9, 0x85,
    0x51, 0x80, 0x8c, 0xe7, 0x0d, 0x0f, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02,
    0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xec, 0xcf, 0x96, 0x4f, 0xbe, 0xf6,
    0xf9, 0x1e, 0xaf, 0xe8, 0x03, 0x88, 0xb2, 0x7e, 0x50, 0x48, 0xf6, 0x4a, 0x61, 0x0f, 0x54, 0x40,
    0xca, 0xac, 0x3e, 0x66, 0x27, 0x93, 0xe4, 0x5b, 0x6d, 0x15 };

#define TEST_SH_SESSION_ID_OFF (39UL)
#define TEST_SH_CIPHER_OFF     (71UL)

static void
test_tls_server_wrong_ciphersuite( fd_rng_t * rng ) {

  /* Set up client and server objects */

  fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
  fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
  prepare_tls_pair( rng, client, server );

  /* Create handshake objects */

  fd_tls_estate_srv_t srv_hs[1]; FD_TEST( fd_tls_estate_srv_new( srv_hs ) );
  test_server_hs = srv_hs;

  fd_tls_estate_cli_t cli_hs[1];
  FD_TEST( fd_tls_estate_cli_new( cli_hs ) );
  fd_memcpy( cli_hs->server_pubkey, server->cert_public_key, 32UL );

  /* ClientHello */
  fd_tls_client_handshake( client, cli_hs, NULL, 0UL, FD_TLS_LEVEL_INITIAL );
  FD_TEST( cli_hs->session_id_sz == 32 );

  /* Send a ServerHello with the cipher suite the client didn't offer */
  uchar server_hello[ sizeof(test_sh_template) ];
  fd_memcpy( server_hello, test_sh_template, sizeof(test_sh_template) );
  fd_memcpy( server_hello+TEST_SH_SESSION_ID_OFF, cli_hs->session_id, 32UL );
  server_hello[ TEST_SH_CIPHER_OFF+1 ] = 0x02; /* TLS_AES_256_GCM_SHA384 */

  long alert = fd_tls_client_handshake( client, cli_hs, server_hello, sizeof(server_hello), FD_TLS_LEVEL_INITIAL );
  FD_TEST( alert == -FD_TLS_ALERT_ILLEGAL_PARAMETER );
  FD_TEST( cli_hs->base.reason == FD_TLS_REASON_SH_NEG_CIPHER );

  test_server_hs = NULL;
  fd_tls_estate_srv_delete( srv_hs );
  fd_tls_estate_cli_delete( cli_hs );
  fd_tls_delete( fd_tls_leave( server ) );
  fd_tls_delete( fd_tls_leave( client ) );
}

/* ServerHello.legacy_session_id_echo must match ClientHello.session_id
   (RFC 8446 Section 4.1.3).  TCP mode: echo of the wrong bytes.  QUIC
   mode: non-empty echo where an empty one was sent. */

static void
test_tls_server_session_id_mismatch( fd_rng_t * rng,
                                     int        quic ) {

  fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
  fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
  prepare_tls_pair( rng, client, server );
  client->quic            = !!quic;
  client->quic_tp_self_fn = test_tls_quic_tp_self;

  fd_tls_estate_srv_t srv_hs[1]; FD_TEST( fd_tls_estate_srv_new( srv_hs ) );
  test_server_hs = srv_hs;

  fd_tls_estate_cli_t cli_hs[1];
  FD_TEST( fd_tls_estate_cli_new( cli_hs ) );
  fd_memcpy( cli_hs->server_pubkey, server->cert_public_key, 32UL );

  fd_tls_client_handshake( client, cli_hs, NULL, 0UL, FD_TLS_LEVEL_INITIAL );
  FD_TEST( cli_hs->session_id_sz == ( quic ? 0 : 32 ) );

  uchar server_hello[ sizeof(test_sh_template) ];
  fd_memcpy( server_hello, test_sh_template, sizeof(test_sh_template) );
  if( !quic ) {
    fd_memcpy( server_hello+TEST_SH_SESSION_ID_OFF, cli_hs->session_id, 32UL );
    server_hello[ TEST_SH_SESSION_ID_OFF+31 ] ^= 0x01;
  }

  long alert = fd_tls_client_handshake( client, cli_hs, server_hello, sizeof(server_hello), FD_TLS_LEVEL_INITIAL );
  FD_TEST( alert == -FD_TLS_ALERT_ILLEGAL_PARAMETER );
  FD_TEST( cli_hs->base.reason == FD_TLS_REASON_SH_SESSION_ID );

  test_server_hs = NULL;
  fd_tls_estate_srv_delete( srv_hs );
  fd_tls_estate_cli_delete( cli_hs );
  fd_tls_delete( fd_tls_leave( server ) );
  fd_tls_delete( fd_tls_leave( client ) );
}

static void
test_tls_truncated_cert_extract( void ) {

  {
    fd_tls_extract_cert_pubkey_res_t res = fd_tls_extract_cert_pubkey( NULL, 0UL );
    FD_TEST( !res.pubkey );
    FD_TEST( res.alert  == FD_TLS_ALERT_DECODE_ERROR );
    FD_TEST( res.reason == FD_TLS_REASON_CERT_PARSE  );
  }

  {
    fd_tls_extract_cert_pubkey_res_t res = fd_tls_extract_cert_pubkey( (uchar const *)"", 0UL );
    FD_TEST( !res.pubkey );
    FD_TEST( res.alert  == FD_TLS_ALERT_DECODE_ERROR );
    FD_TEST( res.reason == FD_TLS_REASON_CERT_PARSE  );
  }

  {
    uchar const cert_body[] = { 0x00 };
    fd_tls_extract_cert_pubkey_res_t res = fd_tls_extract_cert_pubkey( cert_body, sizeof(cert_body) );
    FD_TEST( !res.pubkey );
    FD_TEST( res.alert  == FD_TLS_ALERT_DECODE_ERROR );
    FD_TEST( res.reason == FD_TLS_REASON_CERT_PARSE  );
  }

  {
    uchar const cert_body[] = { 0x00, 0x00, 0x00 };
    fd_tls_extract_cert_pubkey_res_t res = fd_tls_extract_cert_pubkey( cert_body, sizeof(cert_body) );
    FD_TEST( !res.pubkey );
    FD_TEST( res.alert  == FD_TLS_ALERT_DECODE_ERROR );
    FD_TEST( res.reason == FD_TLS_REASON_CERT_PARSE  );
  }

  {
    uchar const cert_body[] = {
      0x00,             /* certificate_request_context length = 0 */
      0x00, 0x00, 0x20, /* cert_list_sz = 32 (nonzero) */
    };
    fd_tls_extract_cert_pubkey_res_t res = fd_tls_extract_cert_pubkey( cert_body, sizeof(cert_body) );
    FD_TEST( !res.pubkey );
    FD_TEST( res.alert  == FD_TLS_ALERT_DECODE_ERROR );
    FD_TEST( res.reason == FD_TLS_REASON_CERT_PARSE  );
  }

  {
    uchar const cert_body[] = {
      0x00,             /* certificate_request_context length = 0 */
      0x00, 0x00, 0x20, /* cert_list_sz = 32 */
      0x00, 0x00, 0x20, /* cert_sz = 32 (but only 0 bytes follow) */
    };
    fd_tls_extract_cert_pubkey_res_t res = fd_tls_extract_cert_pubkey( cert_body, sizeof(cert_body) );
    FD_TEST( !res.pubkey );
    FD_TEST( res.alert  == FD_TLS_ALERT_DECODE_ERROR );
    FD_TEST( res.reason == FD_TLS_REASON_CERT_PARSE  );
  }

  {
    uchar const cert_body[] = {
      0x00,             /* certificate_request_context length = 0 */
      0x00, 0x00, 0x00, /* cert_list_sz = 0 */
    };
    fd_tls_extract_cert_pubkey_res_t res = fd_tls_extract_cert_pubkey( cert_body, sizeof(cert_body) );
    FD_TEST( !res.pubkey );
    FD_TEST( res.alert  == FD_TLS_ALERT_BAD_CERTIFICATE    );
    FD_TEST( res.reason == FD_TLS_REASON_CERT_CHAIN_EMPTY  );
  }

  uchar wire[2048];
  uchar original[2048];
  uchar cert[FD_X509_MOCK_CERT_SZ];
  uchar pubkey[32] = {0};
  fd_x509_mock_cert( cert, pubkey );
  long encoded = fd_tls_encode_cert_x509( cert, sizeof(cert), original, sizeof(original) );
  FD_TEST( encoded>4L );
  ulong sz = (ulong)encoded-4UL;
  fd_memcpy( wire, original+4UL, sz );
  FD_TEST( fd_tls_extract_cert_pubkey( wire, sz ).pubkey );
  for( ulong len=0UL; len<sz; len++ )
    FD_TEST( !fd_tls_extract_cert_pubkey( wire, len ).pubkey );
  wire[sz] = 0;
  FD_TEST( fd_tls_extract_cert_pubkey( wire, sz+1UL ).alert==FD_TLS_ALERT_DECODE_ERROR );
  wire[0] = 1;
  FD_TEST( fd_tls_extract_cert_pubkey( wire, sz ).alert==FD_TLS_ALERT_ILLEGAL_PARAMETER );
  wire[0] = 0;

  /* Adjust outer framing to expose a missing CertificateEntry extension
     vector, rather than just a truncated outer certificate_list. */
  fd_tls_u24_t list_sz = fd_tls_u24_bswap( fd_uint_to_tls_u24( (uint)(sz-6UL) ) );
  fd_memcpy( wire+1, &list_sz, 3UL );
  FD_TEST( fd_tls_extract_cert_pubkey( wire, sz-2UL ).alert==FD_TLS_ALERT_DECODE_ERROR );
  fd_memcpy( wire, original+4UL, sz );

  wire[sz-1UL] = 1;
  FD_TEST( fd_tls_extract_cert_pubkey( wire, sz ).alert==FD_TLS_ALERT_DECODE_ERROR );
  wire[sz-1UL] = 0;
  fd_memcpy( wire+sz, wire+4UL, sz-4UL );
  list_sz = fd_tls_u24_bswap( fd_uint_to_tls_u24( (uint)(2UL*(sz-4UL)) ) );
  fd_memcpy( wire+1, &list_sz, 3UL );
  FD_TEST( fd_tls_extract_cert_pubkey( wire, 2UL*sz-4UL ).pubkey );
  fd_memcpy( wire, original+4UL, sz );

  /* A valid leaf must not hide a malformed second certificate entry. */
  list_sz = fd_tls_u24_bswap( fd_uint_to_tls_u24( (uint)(sz-1UL) ) );
  fd_memcpy( wire+1, &list_sz, 3UL );
  fd_memset( wire+sz, 0, 3UL );
  FD_TEST( fd_tls_extract_cert_pubkey( wire, sz+3UL ).alert==FD_TLS_ALERT_DECODE_ERROR );
}

static void
test_tls_truncated_cert_handshake( fd_rng_t * rng ) {

  fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
  fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
  prepare_tls_pair( rng, client, server );

  fd_tls_estate_cli_t cli_hs[1];
  FD_TEST( fd_tls_estate_cli_new( cli_hs ) );

  cli_hs->base.state        = FD_TLS_HS_WAIT_CERT_CR;
  cli_hs->server_pubkey_pin = 0;

  uchar record[] = {
    FD_TLS_MSG_CERT,    /* type = Certificate */
    0x00, 0x00, 0x01,   /* msg body length = 1 byte */
    0x00,               /* certificate_request_context length = 0 */
  };

  long res = fd_tls_client_handshake( client, cli_hs, record, sizeof(record), FD_TLS_LEVEL_HANDSHAKE );
  FD_TEST( res == -(long)FD_TLS_ALERT_DECODE_ERROR );
  FD_TEST( cli_hs->base.reason == FD_TLS_REASON_CERT_PARSE );
  FD_TEST( cli_hs->base.state  != FD_TLS_HS_WAIT_CV );

  /* Zero-length body — FD_TLS_SKIP_FIELD fails at opaque_sz */
  FD_TEST( fd_tls_estate_cli_new( cli_hs ) );
  cli_hs->base.state        = FD_TLS_HS_WAIT_CERT_CR;
  cli_hs->server_pubkey_pin = 0;

  uchar record_empty[] = {
    FD_TLS_MSG_CERT,
    0x00, 0x00, 0x00,   /* msg body length = 0 */
  };

  res = fd_tls_client_handshake( client, cli_hs, record_empty, sizeof(record_empty), FD_TLS_LEVEL_HANDSHAKE );
  FD_TEST( res == -(long)FD_TLS_ALERT_DECODE_ERROR );
  FD_TEST( cli_hs->base.reason == FD_TLS_REASON_CERT_PARSE );
  FD_TEST( cli_hs->base.state  != FD_TLS_HS_WAIT_CV );

  fd_tls_estate_cli_delete( cli_hs );
  fd_tls_delete( fd_tls_leave( server ) );
  fd_tls_delete( fd_tls_leave( client ) );
}

/* fd_tls does not support the certificate_type extension (RFC 7250).
   A server that sends one anyway must be rejected. */

static void
test_tls_client_unsolicited_cert_type( fd_rng_t * rng ) {

  static uchar const ee_srv_ct[] = {
    FD_TLS_MSG_ENCRYPTED_EXT,
    0x00, 0x00, 0x07,        /* msg sz */
    0x00, 0x05,              /* extension list sz */
    0x00, FD_TLS_EXT_SERVER_CERT_TYPE,
    0x00, 0x01,              /* ext sz */
    0x02,                    /* RawPublicKey */
  };

  static uchar const ee_cli_ct[] = {
    FD_TLS_MSG_ENCRYPTED_EXT,
    0x00, 0x00, 0x07,        /* msg sz */
    0x00, 0x05,              /* extension list sz */
    0x00, FD_TLS_EXT_CLIENT_CERT_TYPE,
    0x00, 0x01,              /* ext sz */
    0x02,                    /* RawPublicKey */
  };

  uchar const * const records[2] = { ee_srv_ct, ee_cli_ct };
  ulong         const record_sz  = sizeof(ee_srv_ct);
  FD_TEST( sizeof(ee_srv_ct)==sizeof(ee_cli_ct) );

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
    fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
    prepare_tls_pair( rng, client, server );

    fd_tls_estate_cli_t cli_hs[1];
    FD_TEST( fd_tls_estate_cli_new( cli_hs ) );
    cli_hs->base.state = FD_TLS_HS_WAIT_EE;
    fd_sha256_init( &cli_hs->transcript );

    long res = fd_tls_client_handshake( client, cli_hs, records[i], record_sz, FD_TLS_LEVEL_HANDSHAKE );
    FD_TEST( res == -(long)FD_TLS_ALERT_UNSUPPORTED_EXTENSION );
    FD_TEST( cli_hs->base.reason == FD_TLS_REASON_EE_PARSE );

    fd_tls_estate_cli_delete( cli_hs );
    fd_tls_delete( fd_tls_leave( server ) );
    fd_tls_delete( fd_tls_leave( client ) );
  }
}

/* A client that cannot present a certificate answers with an empty
   Certificate message (RFC 8446 Section 4.4.2). */

static void
test_tls_client_accepts_cert_req( fd_rng_t * rng ) {

  static uchar const cert_req[] = {
    FD_TLS_MSG_CERT_REQ,
    0x00, 0x00, 0x0b,        /* msg sz */
    0x00,                    /* certificate_request_context */
    0x00, 0x08,              /* extensions length prefix */
    0x00, 0x0d, 0x00, 0x04, /* signature_algorithms */
    0x00, 0x02, 0x08, 0x07, /* Ed25519 */
  };

  /* No certificate installed */
  {
    fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
    fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
    prepare_tls_pair( rng, client, server );
    client->cert_x509_sz = 0UL;

    fd_tls_estate_cli_t cli_hs[1];
    FD_TEST( fd_tls_estate_cli_new( cli_hs ) );
    cli_hs->base.state = FD_TLS_HS_WAIT_CERT_CR;

    long res = fd_tls_client_handshake( client, cli_hs, cert_req, sizeof(cert_req), FD_TLS_LEVEL_HANDSHAKE );
    FD_TEST( res == (long)sizeof(cert_req) );
    FD_TEST( cli_hs->base.state == FD_TLS_HS_WAIT_CERT );
    FD_TEST( cli_hs->client_cert );

    fd_tls_estate_cli_delete( cli_hs );
    fd_tls_delete( fd_tls_leave( server ) );
    fd_tls_delete( fd_tls_leave( client ) );
  }

  /* Certificate installed, but no signer */
  {
    fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
    fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
    prepare_tls_pair( rng, client, server );
    client->sign.sign_fn = NULL;

    fd_tls_estate_cli_t cli_hs[1];
    FD_TEST( fd_tls_estate_cli_new( cli_hs ) );
    cli_hs->base.state = FD_TLS_HS_WAIT_CERT_CR;

    long res = fd_tls_client_handshake( client, cli_hs, cert_req, sizeof(cert_req), FD_TLS_LEVEL_HANDSHAKE );
    FD_TEST( res == (long)sizeof(cert_req) );
    FD_TEST( cli_hs->base.state == FD_TLS_HS_WAIT_CERT );
    FD_TEST( cli_hs->client_cert );

    fd_tls_estate_cli_delete( cli_hs );
    fd_tls_delete( fd_tls_leave( server ) );
    fd_tls_delete( fd_tls_leave( client ) );
  }
}

static void
test_tls_cert_req_rules( fd_rng_t * rng ) {
  uchar wire[128] = {0};
  uchar const ed25519[] = { 0,2,8,7 };
  fd_tls_ext_signature_algorithms_t sig = {0};
  ulong sz = test_tls_append_ext( wire, 3UL, 1UL, FD_TLS_EXT_SIGNATURE_ALGORITHMS, ed25519, sizeof(ed25519) );
  FD_TEST( fd_tls_decode_cert_req( &sig, wire, sz )==(long)sz );
  FD_TEST( sig.ed25519 );
  wire[0] = 1;
  FD_TEST( fd_tls_decode_cert_req( &sig, wire, sz )==-FD_TLS_ALERT_ILLEGAL_PARAMETER );
  wire[0] = 0;
  FD_TEST( fd_tls_decode_cert_req( &sig, wire, sz-1UL )==-FD_TLS_ALERT_DECODE_ERROR );
  FD_TEST( fd_tls_decode_cert_req( &sig, wire, sz+1UL )==(long)sz );
  sz = test_tls_append_ext( wire, sz, 1UL, 0xfafa, NULL, 0 );
  FD_TEST( fd_tls_decode_cert_req( &sig, wire, sz )==(long)sz );
  sz = test_tls_append_ext( wire, 3UL, 1UL, FD_TLS_EXT_SIGNATURE_ALGORITHMS, ed25519, sizeof(ed25519) );
  sz = test_tls_append_ext( wire, sz, 1UL, FD_TLS_EXT_SIGNATURE_ALGORITHMS, ed25519, sizeof(ed25519) );
  FD_TEST( fd_tls_decode_cert_req( &sig, wire, sz )==-FD_TLS_ALERT_ILLEGAL_PARAMETER );
  sz = test_tls_append_ext( wire, 3UL, 1UL, FD_TLS_EXT_KEY_SHARE, NULL, 0 );
  FD_TEST( fd_tls_decode_cert_req( &sig, wire, sz )==-FD_TLS_ALERT_MISSING_EXTENSION );
  uchar const missing[] = {0,0,0};
  FD_TEST( fd_tls_decode_cert_req( &sig, missing, sizeof(missing) )==-FD_TLS_ALERT_MISSING_EXTENSION );
  uchar const empty[] = {0,0};
  sz = test_tls_append_ext( wire, 3UL, 1UL, FD_TLS_EXT_SIGNATURE_ALGORITHMS, empty, sizeof(empty) );
  FD_TEST( fd_tls_decode_cert_req( &sig, wire, sz )==-FD_TLS_ALERT_DECODE_ERROR );

  /* Exercise the actual client response with credentials installed but
     only ECDSA offered, and with the largest supported certificate. */
  for( int compatible=0; compatible<2; compatible++ ) {
    fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
    fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
    prepare_tls_pair( rng, client, server );
    client->cert_x509_sz = FD_TLS_SERVER_CERT_SZ_MAX;
    fd_tls_estate_cli_t hs[1]; FD_TEST( fd_tls_estate_cli_new( hs ) );
    hs->base.state = FD_TLS_HS_WAIT_CERT_CR;
    fd_sha256_init( &hs->transcript );
    uchar req[] = { FD_TLS_MSG_CERT_REQ,0,0,11, 0,0,8, 0,13,0,4, 0,2,8,7 };
    if( !compatible ) {
      req[13] = 4;
      req[14] = 3;
    }
    FD_TEST( fd_tls_client_handshake( client, hs, req, sizeof(req), FD_TLS_LEVEL_HANDSHAKE )==(long)sizeof(req) );
    FD_TEST( hs->client_cert && hs->client_cert_empty==!compatible );

    /* Feed a valid Finished for this synthetic transcript. */
    hs->base.state = FD_TLS_HS_WAIT_FINISHED;
    uchar finished[36] = { FD_TLS_MSG_FINISHED,0,0,32 };
    uchar hash[32], key[32];
    fd_sha256_t transcript = hs->transcript;
    fd_sha256_fini( &transcript, hash );
    fd_tls_hkdf_expand_label( key, 32UL, hs->server_hs_secret, "finished", 8UL, NULL, 0UL );
    fd_hmac_sha256( hash, 32UL, key, 32UL, finished+4 );
    test_record_reset( &test_client_out );
    FD_TEST( fd_tls_client_handshake( client, hs, finished, sizeof(finished), FD_TLS_LEVEL_HANDSHAKE )==36L );
    test_record_t * rec = test_record_recv( &test_client_out );
    FD_TEST( rec && rec->buf[0]==FD_TLS_MSG_CERT );
    FD_TEST( rec->cur==(compatible ? FD_TLS_SERVER_CERT_MSG_SZ_MAX : 8UL) );
    if( !compatible ) FD_TEST( !memcmp( rec->buf+4, "\0\0\0\0", 4UL ) );
    rec = test_record_recv( &test_client_out );
    FD_TEST( rec && rec->buf[0]==(compatible ? FD_TLS_MSG_CERT_VERIFY : FD_TLS_MSG_FINISHED) );
    test_record_reset( &test_client_out );
    fd_tls_estate_cli_delete( hs );
    fd_tls_delete( fd_tls_leave( server ) );
    fd_tls_delete( fd_tls_leave( client ) );
  }
}

static void
test_tls_ee_solicitation( fd_rng_t * rng ) {
  fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
  fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
  prepare_tls_pair( rng, client, server );
  ushort const types[] = { FD_TLS_EXT_SERVER_NAME, FD_TLS_EXT_ALPN,
                           FD_TLS_EXT_QUIC_TRANSPORT_PARAMS, FD_TLS_EXT_SUPPORTED_GROUPS };
  uchar const alpn[]   = { 0,2,1,'h' };
  uchar const groups[] = { 0,2,0,29 };
  for( ulong i=0UL; i<4UL; i++ ) {
    uchar wire[64] = { FD_TLS_MSG_ENCRYPTED_EXT,0,0,0 };
    uchar const * data = i==1UL ? alpn : i==3UL ? groups : NULL;
    ushort len = data ? 4 : 0;
    ulong sz = test_tls_append_ext( wire, 6UL, 4UL, types[i], data, len );
    wire[3] = (uchar)(sz-4UL);
    fd_tls_estate_cli_t hs[1]; FD_TEST( fd_tls_estate_cli_new( hs ) );
    hs->base.state = FD_TLS_HS_WAIT_EE;
    fd_sha256_init( &hs->transcript );
    long res = fd_tls_client_handshake( client, hs, wire, sz, FD_TLS_LEVEL_HANDSHAKE );
    FD_TEST( res==(i==3UL ? (long)sz : -FD_TLS_ALERT_UNSUPPORTED_EXTENSION) );
    if( i<2UL ) {
      FD_TEST( fd_tls_estate_cli_new( hs ) );
      hs->base.state = FD_TLS_HS_WAIT_EE;
      fd_sha256_init( &hs->transcript );
      client->server_name_len = 1;
      client->alpn_sz = 2;
      fd_memcpy( client->alpn, alpn+2, 2UL );
      FD_TEST( fd_tls_client_handshake( client, hs, wire, sz, FD_TLS_LEVEL_HANDSHAKE )==(long)sz );
      client->server_name_len = 0;
      client->alpn_sz = 0;
    }
    fd_tls_estate_cli_delete( hs );
  }
  fd_tls_delete( fd_tls_leave( server ) );
  fd_tls_delete( fd_tls_leave( client ) );
}

/* Opaque QUIC transport params, required when the client runs in QUIC
   mode. */

static ulong
test_tls_quic_tp_self( void *  handshake,
                       uchar * quic_tp,
                       ulong   quic_tp_bufsz ) {
  (void)handshake;
  FD_TEST( quic_tp_bufsz>=1UL );
  quic_tp[0] = 0x00;
  return 1UL;
}

/* test_tls_client_hello_sigalgs checks that QUIC clients only advertise
   Ed25519, whereas TCP clients also accept the ECDSA schemes used by
   web PKI certs. */

static void
test_tls_client_hello_sigalgs( fd_rng_t * rng ) {

  for( uint quic=0U; quic<2U; quic++ ) {

    fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
    fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
    prepare_tls_pair( rng, client, server );
    client->quic            = !!quic;
    client->quic_tp_self_fn = test_tls_quic_tp_self;

    fd_tls_estate_cli_t cli_hs[1]; FD_TEST( fd_tls_estate_cli_new( cli_hs ) );
    test_record_reset( &test_client_out );
    FD_TEST( fd_tls_client_handshake( client, cli_hs, NULL, 0UL, FD_TLS_LEVEL_INITIAL )>=0L );

    /* Re-parse the ClientHello we just emitted */

    test_record_t * rec = test_record_recv( &test_client_out );
    FD_TEST( rec );
    fd_tls_msg_hdr_t hdr = {0};
    long hdr_sz = fd_tls_decode_msg_hdr( &hdr, rec->buf, rec->cur );
    FD_TEST( hdr_sz>0L );
    FD_TEST( hdr.type == FD_TLS_MSG_CLIENT_HELLO );

    fd_tls_client_hello_t ch = {0};
    FD_TEST( fd_tls_decode_client_hello( &ch, rec->buf+hdr_sz, rec->cur-(ulong)hdr_sz )>0L );

    FD_TEST( ch.signature_algorithms.ed25519 );
    FD_TEST( ch.signature_algorithms.ecdsa_secp256r1_sha256 == !quic );
    FD_TEST( !ch.signature_algorithms.ecdsa_secp384r1_sha384 );
    FD_TEST( ch.signature_algorithms_cert.ed25519 == !quic );
    FD_TEST( ch.signature_algorithms_cert.ecdsa_secp256r1_sha256 == !quic );
    FD_TEST( ch.signature_algorithms_cert.ecdsa_secp384r1_sha384 == !quic );
    FD_TEST( ch.cipher_suites.aes_128_gcm_sha256 );

    test_record_reset( &test_client_out );
    fd_tls_estate_cli_delete( cli_hs );
    fd_tls_delete( fd_tls_leave( server ) );
    fd_tls_delete( fd_tls_leave( client ) );
  }
}

static void
test_tls_client_rejects_oversz_sni( fd_rng_t * rng ) {
  fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
  fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
  prepare_tls_pair( rng, client, server );

  fd_memset( client->server_name, 'x', sizeof(client->server_name) );
  client->server_name_len = (ushort)sizeof(client->server_name);

  fd_tls_estate_cli_t hs[1]; FD_TEST( fd_tls_estate_cli_new( hs ) );
  FD_TEST( fd_tls_client_handshake( client, hs, NULL, 0UL, FD_TLS_LEVEL_INITIAL )==
           -(long)FD_TLS_ALERT_INTERNAL_ERROR );
  FD_TEST( hs->base.reason==FD_TLS_REASON_CH_ENCODE );

  fd_tls_estate_cli_delete( hs );
  fd_tls_delete( fd_tls_leave( server ) );
  fd_tls_delete( fd_tls_leave( client ) );
}

/* A QUIC client offers only Ed25519 in signature_algorithms, so a
   server presenting a P-256 certificate must be rejected before the
   CertificateVerify is ever looked at (RFC 8446 Section 4.4.3).  The
   same Certificate is acceptable to the TCP client, which also offers
   ecdsa_secp256r1_sha256. */

static void
test_tls_client_quic_rejects_p256_cert( fd_rng_t * rng ) {

  /* Self-signed P-256 certificate, CN=p256 */
  static uchar const p256_cert[ 376 ] = {
    0x30, 0x82, 0x01, 0x74, 0x30, 0x82, 0x01, 0x1b, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x7b,
    0xa7, 0x88, 0x50, 0xa0, 0xa5, 0x59, 0xe2, 0xe1, 0x86, 0x5b, 0x97, 0x6b, 0x2b, 0x51, 0xa1, 0x6f,
    0x49, 0xcb, 0x3a, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x70, 0x32, 0x35, 0x36,
    0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x31, 0x34, 0x30, 0x33, 0x33, 0x37, 0x30, 0x36,
    0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x36, 0x30, 0x38, 0x32, 0x31, 0x30, 0x33, 0x33, 0x37, 0x30,
    0x36, 0x5a, 0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x70,
    0x32, 0x35, 0x36, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xc1, 0xa5,
    0x8f, 0x6f, 0xef, 0xef, 0x73, 0xcd, 0xe3, 0xd2, 0x40, 0x99, 0x15, 0x85, 0x65, 0x42, 0x93, 0xb2,
    0x9f, 0x14, 0x78, 0xc3, 0x6f, 0xc3, 0xd8, 0x71, 0xf0, 0x13, 0x68, 0x0b, 0x0d, 0x57, 0x72, 0x9a,
    0x13, 0x27, 0xe4, 0xae, 0x1b, 0xce, 0x9b, 0x65, 0x74, 0x44, 0xb8, 0x7c, 0xae, 0x33, 0x84, 0xd8,
    0x95, 0x69, 0xed, 0x6c, 0xc2, 0x12, 0xb1, 0x3d, 0xf8, 0xee, 0xbc, 0x15, 0x2b, 0xae, 0xa3, 0x53,
    0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xac, 0xef, 0xef,
    0x48, 0x8f, 0x6f, 0x54, 0x88, 0x66, 0xbe, 0x7f, 0x34, 0x0d, 0x75, 0x10, 0x03, 0x49, 0xa8, 0x6f,
    0xa6, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xac, 0xef,
    0xef, 0x48, 0x8f, 0x6f, 0x54, 0x88, 0x66, 0xbe, 0x7f, 0x34, 0x0d, 0x75, 0x10, 0x03, 0x49, 0xa8,
    0x6f, 0xa6, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
    0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
    0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x1e, 0x84, 0xc0, 0xc8, 0x4e, 0xac, 0x4e, 0x96, 0x59, 0x4f,
    0x15, 0x20, 0x15, 0x24, 0xed, 0x71, 0xfe, 0x5a, 0xa4, 0xd2, 0x9e, 0x3b, 0x73, 0xe7, 0x23, 0xc1,
    0x0e, 0x56, 0x56, 0x8e, 0x58, 0x32, 0x02, 0x20, 0x18, 0xef, 0x53, 0xd8, 0xeb, 0x1b, 0x45, 0x11,
    0x75, 0x9e, 0x31, 0x84, 0xc5, 0xdb, 0x48, 0x5c, 0x76, 0x90, 0xc6, 0x7e, 0xa2, 0x25, 0x57, 0x45,
    0x49, 0x56, 0x78, 0x82, 0x4f, 0x4a, 0xfe, 0x25
  };

  uchar cert_msg[ 512 ];
  long cert_msg_sz = fd_tls_encode_cert_x509( p256_cert, sizeof(p256_cert), cert_msg, sizeof(cert_msg) );
  FD_TEST( cert_msg_sz>0L );

  for( int quic=0; quic<2; quic++ ) {
    fd_tls_t _client[1]; fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
    fd_tls_t _server[1]; fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
    prepare_tls_pair( rng, client, server );
    client->quic = !!quic;

    fd_tls_estate_cli_t cli_hs[1];
    FD_TEST( fd_tls_estate_cli_new( cli_hs ) );
    cli_hs->base.state = FD_TLS_HS_WAIT_CERT_CR;
    fd_sha256_init( &cli_hs->transcript );

    long res = fd_tls_client_handshake( client, cli_hs, cert_msg, (ulong)cert_msg_sz, FD_TLS_LEVEL_HANDSHAKE );
    if( quic ) {
      FD_TEST( res == -(long)FD_TLS_ALERT_UNSUPPORTED_CERTIFICATE );
      FD_TEST( cli_hs->base.reason == FD_TLS_REASON_CERT_KEY_TYPE );
    } else {
      FD_TEST( res == cert_msg_sz );
      FD_TEST( cli_hs->base.state == FD_TLS_HS_WAIT_CV );
      FD_TEST( cli_hs->server_key_type == FD_TLS_KEY_ECDSA_P256 );
      FD_TEST( cli_hs->server_pubkey_len == 65UL );
    }

    fd_tls_estate_cli_delete( cli_hs );
    fd_tls_delete( fd_tls_leave( server ) );
    fd_tls_delete( fd_tls_leave( client ) );
  }
}

int
main( int     argc,
      char ** argv) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_tls_proto();
  test_tls_extension_rules();
  test_tls_vectors();
  test_tls_pair( rng );
  test_tls_client_wrong_ciphersuite( rng );
  test_tls_server_wrong_ciphersuite( rng );
  test_tls_server_session_id_mismatch( rng, 0 );
  test_tls_server_session_id_mismatch( rng, 1 );
  test_tls_truncated_cert_extract();
  test_tls_truncated_cert_handshake( rng );
  test_tls_client_unsolicited_cert_type( rng );
  test_tls_client_accepts_cert_req( rng );
  test_tls_cert_req_rules( rng );
  test_tls_ee_solicitation( rng );
  test_tls_client_hello_sigalgs( rng );
  test_tls_client_rejects_oversz_sni( rng );
  test_tls_client_quic_rejects_p256_cert( rng );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
