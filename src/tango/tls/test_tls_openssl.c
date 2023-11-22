#include "fd_tls_base.h"
#include "fd_tls_proto.h"
#if !FD_HAS_OPENSSL
#error "This test requires OpenSSL"
#endif

/* Test OpenSSL client to fd_tls server handshake. */

#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_mock.h"
#include "../quic/fd_quic_common.h"
#include "../quic/templ/fd_quic_transport_params.h"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/tls1.h>

#include "fd_tls.h"
#include "test_tls_helper.h"

/* Map between encryption levels */

/* direction */
static uchar _is_ossl_to_fd = 0;

static uint const
_ossl_level_to_fdtls[] = {
  [ssl_encryption_initial]     = FD_TLS_LEVEL_INITIAL,
  [ssl_encryption_early_data]  = FD_TLS_LEVEL_EARLY,
  [ssl_encryption_handshake]   = FD_TLS_LEVEL_HANDSHAKE,
  [ssl_encryption_application] = FD_TLS_LEVEL_APPLICATION
};

static OSSL_ENCRYPTION_LEVEL const
_fdtls_level_to_ossl[] = {
  [ FD_TLS_LEVEL_INITIAL     ] = ssl_encryption_initial,
  [ FD_TLS_LEVEL_EARLY       ] = ssl_encryption_early_data,
  [ FD_TLS_LEVEL_HANDSHAKE   ] = ssl_encryption_handshake,
  [ FD_TLS_LEVEL_APPLICATION ] = ssl_encryption_application
};

/* Save secrets */

static uchar secret[ 32UL ][2][4][2] = {0};

static int
_ossl_secrets( SSL *                 ssl,
               OSSL_ENCRYPTION_LEVEL enc_level,
               uchar const *         read_secret,
               uchar const *         write_secret,
               ulong                 secret_len ) {
  (void)ssl;
  FD_TEST( secret_len==32UL );
  uint level = _ossl_level_to_fdtls[ enc_level ];
  memcpy( secret[1][ level ][0], write_secret, 32UL );
  memcpy( secret[1][ level ][1], read_secret,  32UL );
  return 1;
}

static void
_fdtls_secrets( void const * handshake,
                void const * recv_secret,
                void const * send_secret,
                uint         encryption_level ) {
  (void)handshake;
  memcpy( secret[0][ encryption_level ][0], recv_secret, 32UL );
  memcpy( secret[0][ encryption_level ][1], send_secret, 32UL );
}

/* Record transport */

static test_record_buf_t _ossl_out  = {0};
static test_record_buf_t _fdtls_out = {0};

static int
_ossl_sendmsg( SSL *                 ssl,
               OSSL_ENCRYPTION_LEVEL enc_level,
               uchar const *         record,
               ulong                 record_sz ) {
  (void)ssl;
  test_record_log( record, record_sz, !_is_ossl_to_fd );
  test_record_send( &_ossl_out, _ossl_level_to_fdtls[ enc_level ], record, record_sz );
  return 1;
}

int
_fdtls_sendmsg( void const * handshake,
                void const * record,
                ulong        record_sz,
                uint         encryption_level,
                int          flush ) {
  (void)handshake;  (void)flush;
  test_record_log( record, record_sz, !!_is_ossl_to_fd );
  test_record_send( &_fdtls_out, encryption_level, record, record_sz );
  return 1;
}

static void
_fd_client_respond( fd_tls_t *            client,
                    fd_tls_estate_cli_t * hs ) {
  test_record_t * rec;
  while( (rec = test_record_recv( &_ossl_out )) ) {
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
_fd_server_respond( fd_tls_t *            server,
                    fd_tls_estate_srv_t * hs ) {
  test_record_t * rec;
  while( (rec = test_record_recv( &_ossl_out )) ) {
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
_ossl_respond( SSL * ssl ) {
  test_record_t * rec;
  while( (rec = test_record_recv( &_fdtls_out )) ) {
    FD_LOG_DEBUG(( "Providing message to OpenSSL (%d)", rec->buf[0] ));
    FD_TEST( 1==SSL_provide_quic_data( ssl, _fdtls_level_to_ossl[ rec->level ], rec->buf, rec->cur ) );
    int res = SSL_do_handshake( ssl );
    FD_TEST( res!=0 );
    int err = SSL_get_error( ssl, res );
    FD_TEST( (err==0) | (err==SSL_ERROR_WANT_READ) | (err==SSL_ERROR_WANT_WRITE) );
    FD_TEST( ERR_get_error()==0UL );
    SSL_do_handshake( ssl );
    SSL_do_handshake( ssl );
    SSL_do_handshake( ssl );
  }
}

static int
_ossl_flush_flight( SSL * ssl ) {
  (void)ssl;
  return 1;
}

/* Hardcode QUIC transport parameters */

static uchar const tp_buf[] = { 0x01, 0x02, 0x47, 0xd0 };

static ulong
_fdtls_quic_tp_self( void *  handshake,
                     uchar * quic_tp,
                     ulong   quic_tp_bufsz ) {
  (void)handshake;
  FD_TEST( quic_tp_bufsz >= sizeof(tp_buf) );
  fd_memcpy( quic_tp, tp_buf, sizeof(tp_buf) );
  return 4UL;
}

static void
_fdtls_quic_tp_peer( void  *       handshake,
                     uchar const * quic_tp,
                     ulong         quic_tp_sz ) {
  (void)handshake;
  FD_TEST( quic_tp_sz == 4UL );
  FD_TEST( 0==memcmp( quic_tp, tp_buf, 4UL ) );
}

/* Miscellaneous OpenSSL callbacks */

static int
_ossl_send_alert( SSL *                 ssl,
                  OSSL_ENCRYPTION_LEVEL level,
                  uchar                 alert ) {
  (void)ssl; (void)level;

  ERR_print_errors_fp( stderr );

  FD_LOG_ERR(( "client: alert %u (%s-%s)",
               alert,
               SSL_alert_desc_string     ( alert ),
               SSL_alert_desc_string_long( alert ) ));
  return 1;
}

static void
_ossl_info( SSL const * ssl,
            int         type,
            int         val ) {
  (void)ssl; (void)type; (void)val;
  FD_LOG_DEBUG(( "OpenSSL info: type=%#x val=%d", type, val ));
  if( (type&SSL_CB_LOOP)==SSL_CB_LOOP )
    FD_LOG_INFO(( "OpenSSL state: %s", SSL_state_string_long( ssl ) ));
}

static void
_ossl_keylog( SSL const *  ssl,
              char const * line ) {
  (void)ssl;
  FD_LOG_DEBUG(( "OpenSSL: %s", line ));
}

static int
_ossl_verify_callback( int              preverify_ok,
                       X509_STORE_CTX * ctx ) {
  (void)preverify_ok; (void)ctx;
  return 1;
}

static int
_ossl_alpn_select( SSL *          ssl,
                   uchar const ** out,
                   uchar *        outlen,
                   uchar const *  in,
                   uint           inlen,
                   void *         arg ) {
  (void)ssl; (void)arg;
  if( SSL_select_next_proto( (unsigned char **)out, outlen, in, inlen, (uchar const *)"\xasolana-tpu", 11 )==OPENSSL_NPN_NEGOTIATED ) {
    return SSL_TLSEXT_ERR_OK;
  }
  FD_LOG_ERR(( "ALPN negotiation failed" ));
}

/* test_server connects an OpenSSL client to an fd_tls server */

void
test_server( SSL_CTX * ctx ) {
  FD_LOG_INFO(( "Testing OpenSSL client => fd_tls server" ));
  _is_ossl_to_fd = 1;
  test_record_reset( &_ossl_out  );
  test_record_reset( &_fdtls_out );

  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );

  /* Create fd_tls instance */

  fd_rng_t  _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)fd_log_wallclock(), 0UL ) );

  fd_tls_t _server[1];
  fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
  *server = (fd_tls_t) {
    .rand       = fd_tls_test_rand( rng ),
    .secrets_fn = _fdtls_secrets,
    .sendmsg_fn = _fdtls_sendmsg,

    .quic = 1,
    .quic_tp_peer_fn = _fdtls_quic_tp_peer,
    .quic_tp_self_fn = _fdtls_quic_tp_self,

    .alpn    = "\xasolana-tpu",
    .alpn_sz = 11UL,
  };

  fd_tls_estate_srv_t hs[1];
  FD_TEST( fd_tls_estate_srv_new( hs ) );

  /* Set up ECDH key */

  for( ulong b=0; b<32UL; b++ ) server->kex_private_key[b] = fd_rng_uchar( rng );
  fd_x25519_public( server->kex_public_key, server->kex_private_key );

  /* Set up Ed25519 key */

  for( ulong b=0; b<32UL; b++ ) server->cert_private_key[b] = fd_rng_uchar( rng );
  fd_ed25519_public_from_private( server->cert_public_key, server->cert_private_key, sha );

  /* Set up server cert */

  uchar cert[ FD_X509_MOCK_CERT_SZ ];
  fd_x509_mock_cert( cert, server->cert_public_key, fd_rng_ulong( rng ) );
  fd_tls_set_x509( server, cert, FD_X509_MOCK_CERT_SZ );

  /* Initialize OpenSSL */

  SSL * ssl = SSL_new( ctx );
  FD_TEST( ssl );

  /* Set up client cert */

  uchar client_private_key[ 32 ];
  for( ulong b=0; b<32UL; b++ ) client_private_key[b] = fd_rng_uchar( rng );
  uchar client_public_key[ 32 ];
  fd_ed25519_public_from_private( client_public_key, client_private_key, sha );
  EVP_PKEY * client_pkey = EVP_PKEY_new_raw_private_key( EVP_PKEY_ED25519, NULL, client_private_key, 32UL );
  FD_TEST( client_pkey );
  SSL_use_PrivateKey( ssl, client_pkey );
  EVP_PKEY_free( client_pkey );

  fd_x509_mock_cert( cert, client_public_key, fd_rng_ulong( rng ) );
  SSL_use_certificate_ASN1( ssl, cert, FD_X509_MOCK_CERT_SZ );

  SSL_set_connect_state( ssl );

  /* Set client QUIC transport params */

  ulong tp_sz = 4UL;
  FD_TEST( 1==SSL_set_quic_transport_params( ssl, tp_buf, tp_sz ) );

  /* Do handshake */

  /* ClientHello */
  int res = SSL_do_handshake( ssl );
  FD_TEST( SSL_get_error( ssl, res )==SSL_ERROR_WANT_READ );

  /* ServerHello, EncryptedExtensions, Certificate, CertificateVerify, server Finished */
  _fd_server_respond( server, hs );

  _ossl_respond( ssl );

  _fd_server_respond( server, hs );

  /* Check if connected */
  int ssl_res = SSL_do_handshake( ssl );
  if( FD_UNLIKELY( SSL_do_handshake( ssl )!=1 ) ) {
    FD_LOG_WARNING(( "OpenSSL handshake unsuccessful: %d", ssl_res ));
    FD_LOG_ERR(( "SSL_get_error: %d", SSL_get_error( ssl, ssl_res ) ));
  }
  FD_TEST( hs->base.state==FD_TLS_HS_CONNECTED );

  /* Clean up */

  fd_tls_estate_srv_delete( hs );
  fd_tls_delete( fd_tls_leave( _server ) );
  SSL_free( ssl );
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_sha512_delete( fd_sha512_leave( sha ) );
}

/* test_client connects an fd_tls client to an OpenSSL server */

void
test_client( SSL_CTX * ctx ) {
  FD_LOG_INFO(( "Testing fd_tls client => OpenSSL server" ));
  _is_ossl_to_fd = 0;
  test_record_reset( &_ossl_out  );
  test_record_reset( &_fdtls_out );

  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );

  fd_rng_t  _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Initialize OpenSSL */

  SSL * ssl = SSL_new( ctx );
  FD_TEST( ssl );

  SSL_set_accept_state( ssl );

  /* Set up server cert */

  uchar server_private_key[ 32 ];
  for( ulong b=0; b<32UL; b++ ) server_private_key[b] = fd_rng_uchar( rng );
  uchar server_public_key[ 32 ];
  fd_ed25519_public_from_private( server_public_key, server_private_key, sha );

  EVP_PKEY * server_pkey = EVP_PKEY_new_raw_private_key( EVP_PKEY_ED25519, NULL, server_private_key, 32UL );
  FD_TEST( server_pkey );
  SSL_use_PrivateKey( ssl, server_pkey );
  EVP_PKEY_free( server_pkey );

  uchar cert[ FD_X509_MOCK_CERT_SZ ];
  fd_x509_mock_cert( cert, server_public_key, fd_rng_ulong( rng ) );
  SSL_use_certificate_ASN1( ssl, cert, FD_X509_MOCK_CERT_SZ );

  /* Set server QUIC transport params */

  uchar tp_buf[] = { 0x01, 0x02, 0x47, 0xd0 };
  ulong tp_sz = 4UL;
  FD_TEST( 1==SSL_set_quic_transport_params( ssl, tp_buf, tp_sz ) );

  /* Create fd_tls instance */

  fd_tls_t  _client[1];
  fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
  *client = (fd_tls_t) {
    .rand       =  fd_tls_test_rand( rng ),
    .secrets_fn = _fdtls_secrets,
    .sendmsg_fn = _fdtls_sendmsg,

    .quic = 1,
    .quic_tp_peer_fn = _fdtls_quic_tp_peer,
    .quic_tp_self_fn = _fdtls_quic_tp_self,

    .alpn    = "\xasolana-tpu",
    .alpn_sz = 11UL,
  };

  fd_tls_estate_cli_t hs[1];
  FD_TEST( fd_tls_estate_cli_new( hs ) );
  memcpy( hs->server_pubkey, server_public_key, 32UL );

  /* Set up ECDH key */

  for( ulong b=0; b<32UL; b++ ) client->kex_private_key[b] = fd_rng_uchar( rng );
  fd_x25519_public( client->kex_public_key, client->kex_private_key );

  /* Set up Ed25519 key */

  for( ulong b=0; b<32UL; b++ ) client->cert_private_key[b] = fd_rng_uchar( rng );
  fd_ed25519_public_from_private( client->cert_public_key, client->cert_private_key, sha );

  /* Set up client cert */

  fd_x509_mock_cert( cert, client->cert_public_key, fd_rng_ulong( rng ) );
  fd_tls_set_x509( client, cert, FD_X509_MOCK_CERT_SZ );

  /* Do handshake */

  /* ClientHello */
  fd_tls_client_handshake( client, hs, NULL, 0UL, FD_TLS_LEVEL_INITIAL );
  /* ServerHello, EncryptedExtensions, Certificate, CertificateVerify, server Finished */
  _ossl_respond( ssl );
  /* client Finished */
  _fd_client_respond( client, hs );
  /* NewSessionTicket */
  _ossl_respond( ssl );

  /* Check if connected */
  FD_TEST( hs->base.state==FD_TLS_HS_CONNECTED );
  FD_TEST( SSL_do_handshake( ssl )==1 );

  /* Clean up */

  fd_tls_estate_cli_delete( hs );
  fd_tls_delete( fd_tls_leave( client ) );
  SSL_free( ssl );
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_sha512_delete( fd_sha512_leave( sha ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Initialize OpenSSL */

  SSL_METHOD const * method = TLS_method();
  FD_TEST( method );

  SSL_CTX * ctx = SSL_CTX_new( method );
  FD_TEST( ctx );

  SSL_CTX_set_verify( ctx, SSL_VERIFY_NONE, NULL );

  FD_TEST( SSL_CTX_set_min_proto_version( ctx, TLS1_3_VERSION ) );
  FD_TEST( SSL_CTX_set_max_proto_version( ctx, TLS1_3_VERSION ) );

  char const * ciphersuites = "TLS_AES_128_GCM_SHA256";
  FD_TEST( SSL_CTX_set_ciphersuites( ctx, ciphersuites ));

  SSL_QUIC_METHOD quic_method = {
    _ossl_secrets,
    _ossl_sendmsg,
    _ossl_flush_flight,
    _ossl_send_alert };
  FD_TEST( 1==SSL_CTX_set_quic_method( ctx, &quic_method ) );

  SSL_CTX_set_info_callback  ( ctx, _ossl_info   );
  SSL_CTX_set_keylog_callback( ctx, _ossl_keylog );

  SSL_CTX_set_alpn_protos( ctx, (uchar const *)"\xasolana-tpu", 11UL );
  SSL_CTX_set_alpn_select_cb( ctx, _ossl_alpn_select, NULL );

  test_server( ctx );

  /* Test client with and without cert */
  SSL_CTX_set_verify( ctx, SSL_VERIFY_NONE, NULL );
  test_client( ctx );
  SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER, _ossl_verify_callback );
  test_client( ctx );

  SSL_CTX_free( ctx );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

