#include "fd_tls.h"
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
#include <openssl/core_dispatch.h>

#include "fd_tls.h"
#include "test_tls_helper.h"

/* Map between encryption levels */

/* direction */
static uchar _is_ossl_to_fd = 0;

static uint const
_ossl_level_to_fdtls[] = {
  [OSSL_RECORD_PROTECTION_LEVEL_NONE]        = FD_TLS_LEVEL_INITIAL,
  [OSSL_RECORD_PROTECTION_LEVEL_EARLY]       = FD_TLS_LEVEL_EARLY,
  [OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE]   = FD_TLS_LEVEL_HANDSHAKE,
  [OSSL_RECORD_PROTECTION_LEVEL_APPLICATION] = FD_TLS_LEVEL_APPLICATION
};

/* Hardcode QUIC transport parameters */

static uchar const tp_buf[] = { 0x01, 0x02, 0x47, 0xd0 };

/* Save secrets */

static uchar secret[ 32UL ][2][4][2] = {0};

/* Track current OpenSSL encryption level for sending */
static uint _ossl_send_level = FD_TLS_LEVEL_INITIAL;

static int
_ossl_yield_secret( SSL *                 ssl,
                    uint32_t              enc_level,
                    int                   direction,
                    uchar const *         secret_data,
                    ulong                 secret_len,
                    void *                arg ) {
  (void)ssl; (void)arg;
  FD_TEST( secret_len==32UL );
  uint level = _ossl_level_to_fdtls[ enc_level ];
  /* direction: 0=read, 1=write */
  memcpy( secret[1][ level ][ direction ], secret_data, 32UL );

  /* Track the current send encryption level - when we get a write secret, update it */
  if( direction == 1 ) { /* write/send */
    _ossl_send_level = level;
  }

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
_ossl_crypto_send( SSL *           ssl,
                   uchar const *   buf,
                   ulong           buf_len,
                   ulong *         consumed,
                   void *          arg ) {
  (void)ssl; (void)arg;
  /* OpenSSL provides CRYPTO frame data to send.
     We track the current encryption level via the yield_secret callback. */
  test_record_log( buf, buf_len, !_is_ossl_to_fd );
  test_record_send( &_ossl_out, _ossl_send_level, buf, buf_len );
  *consumed = buf_len;
  return 1;
}

static int
_ossl_crypto_recv_rcd( SSL *                 ssl,
                       uchar const **        buf,
                       ulong *               bytes_read,
                       void *                arg ) {
  (void)ssl; (void)arg;
  test_record_t * rec = test_record_recv( &_fdtls_out );
  if( !rec ) {
    /* No data available - return success with 0 bytes to signal retry needed */
    *buf = NULL;
    *bytes_read = 0;
    return 1; /* Return 1 (success) with datalen=0 means "no data yet, retry" */
  }
  FD_LOG_DEBUG(( "OpenSSL receiving message (%d)", rec->buf[0] ));
  *buf = rec->buf;
  *bytes_read = rec->cur;
  return 1; /* Return 1 (success) with datalen>0 means "here's your data" */
}

static int
_ossl_crypto_release_rcd( SSL *    ssl,
                          ulong    bytes_read,
                          void *   arg ) {
  (void)ssl; (void)bytes_read; (void)arg;
  /* In our test, we can just acknowledge the read */
  return 1;
}

static int
_ossl_got_transport_params( SSL *                ssl,
                            uchar const *        params,
                            ulong                params_len,
                            void *               arg ) {
  (void)ssl; (void)arg;
  FD_TEST( params_len == 4UL );
  FD_TEST( 0==memcmp( params, tp_buf, 4UL ) );
  return 1;
}

static int
_ossl_alert( SSL *   ssl,
             uchar   alert_code,
             void *  arg ) {
  (void)ssl; (void)arg;

  ERR_print_errors_fp( stderr );

  FD_LOG_ERR(( "client: alert %u (%s-%s)",
               alert_code,
               SSL_alert_desc_string     ( alert_code ),
               SSL_alert_desc_string_long( alert_code ) ));
  return 1;
}

int
_fdtls_sendmsg( void const * handshake,
                void const * record,
                ulong        record_sz,
                uint         encryption_level,
                int          flush ) {
  (void)handshake; (void)flush;
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
  int res = SSL_do_handshake( ssl );
  if( res!=1 ) {
    int err = SSL_get_error( ssl, res );
    FD_TEST( (err==0) | (err==SSL_ERROR_WANT_READ) | (err==SSL_ERROR_WANT_WRITE) );
  }
  FD_TEST( ERR_get_error()==0UL );
}

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

static void
_ossl_info( SSL const * ssl,
            int         type,
            int         val ) {
  (void)ssl; (void)type; (void)val;
  FD_LOG_DEBUG(( "OpenSSL info: type=%#x val=%d", (uint)type, val ));
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


/* Set up OSSL_DISPATCH callbacks for QUIC TLS */

static OSSL_DISPATCH const quic_method[] = {
  { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND,          (void(*)(void))_ossl_crypto_send },
  { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD,      (void(*)(void))_ossl_crypto_recv_rcd },
  { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD,   (void(*)(void))_ossl_crypto_release_rcd },
  { OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,         (void(*)(void))_ossl_yield_secret },
  { OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, (void(*)(void))_ossl_got_transport_params },
  { OSSL_FUNC_SSL_QUIC_TLS_ALERT,                (void(*)(void))_ossl_alert },
  { 0, NULL }
};

/* Helper functions */

/* Reset global test state */
static void
_reset_test_state( uchar is_ossl_to_fd ) {
  _is_ossl_to_fd = is_ossl_to_fd;
  _ossl_send_level = FD_TLS_LEVEL_INITIAL;
  test_record_reset( &_ossl_out  );
  test_record_reset( &_fdtls_out );
}

/* Setup SSL with Ed25519 certificate and QUIC callbacks */
static void
_setup_ssl_cert_and_quic( SSL *           ssl,
                          fd_rng_t *      rng,
                          fd_sha512_t *   sha,
                          uchar *         public_key_out ) {  /* out: 32 bytes */
  /* Generate Ed25519 keypair */
  uchar private_key[ 32 ];
  for( ulong b=0; b<32UL; b++ ) private_key[b] = fd_rng_uchar( rng );
  fd_ed25519_public_from_private( public_key_out, private_key, sha );

  /* Set private key */
  EVP_PKEY * pkey = EVP_PKEY_new_raw_private_key( EVP_PKEY_ED25519, NULL, private_key, 32UL );
  FD_TEST( pkey );
  SSL_use_PrivateKey( ssl, pkey );
  EVP_PKEY_free( pkey );

  /* Generate and set certificate */
  uchar cert[ FD_X509_MOCK_CERT_SZ ];
  fd_x509_mock_cert( cert, public_key_out );
  SSL_use_certificate_ASN1( ssl, cert, FD_X509_MOCK_CERT_SZ );

  /* Set up QUIC callbacks and transport params */
  FD_TEST( 1==SSL_set_quic_tls_cbs( ssl, quic_method, NULL ) );
  FD_TEST( 1==SSL_set_quic_tls_transport_params( ssl, tp_buf, sizeof(tp_buf) ) );
}


static fd_tls_t
_fd_tls_t( void* sign_ctx, fd_rng_t* rng ) {
  return (fd_tls_t) {
    .rand       =  fd_tls_test_rand( rng ),
    .secrets_fn = _fdtls_secrets,
    .sendmsg_fn = _fdtls_sendmsg,

    .quic = 1,
    .quic_tp_peer_fn = _fdtls_quic_tp_peer,
    .quic_tp_self_fn = _fdtls_quic_tp_self,

    .sign = fd_tls_test_sign( sign_ctx ),

    .alpn    = "\xasolana-tpu",
    .alpn_sz = 11UL,
  };
}


/* test_server connects an OpenSSL client to an fd_tls server */

void
test_server( SSL_CTX * ctx ) {
  FD_LOG_INFO(( "Testing OpenSSL client => fd_tls server" ));
  _reset_test_state( 1 );

  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );

  /* Create fd_tls instance */

  fd_rng_t  _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)fd_log_wallclock(), 0UL ) );

  fd_tls_t _server[1];
  fd_tls_t * server = fd_tls_join( fd_tls_new( _server ) );
  fd_tls_test_sign_ctx_t server_sign_ctx[1];
  fd_tls_test_sign_ctx( server_sign_ctx, rng );
  *server = _fd_tls_t( &server_sign_ctx, rng );

  fd_tls_estate_srv_t hs[1];
  FD_TEST( fd_tls_estate_srv_new( hs ) );

  /* Set up ECDH key */

  for( ulong b=0; b<32UL; b++ ) server->kex_private_key[b] = fd_rng_uchar( rng );
  fd_x25519_public( server->kex_public_key, server->kex_private_key );

  /* Set up Ed25519 key */

  fd_memcpy( server->cert_public_key, server_sign_ctx->public_key, 32UL );

  /* Set up server cert */

  fd_x509_mock_cert( server->cert_x509, server->cert_public_key );
  server->cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  /* Initialize OpenSSL */

  SSL * ssl = SSL_new( ctx );
  FD_TEST( ssl );

  SSL_set_connect_state( ssl );

  /* Set up client cert and QUIC */

  uchar client_public_key[ 32 ];
  _setup_ssl_cert_and_quic( ssl, rng, sha, client_public_key );

  /* Do handshake */

  /* Initiate handshake - OpenSSL client sends ClientHello */
  SSL_do_handshake( ssl );

  /* Process handshake messages until connected. */
  while( hs->base.state != FD_TLS_HS_CONNECTED ) {
    /* fd_tls server processes incoming messages and generates responses */
    _fd_server_respond( server, hs );

    /* OpenSSL client does the same */
    _ossl_respond( ssl );
  }

  /* Verify both sides completed successfully */
  FD_TEST( SSL_is_init_finished( ssl ) );
  FD_TEST( hs->base.state == FD_TLS_HS_CONNECTED );

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
  _reset_test_state( 0 );

  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );

  fd_rng_t  _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Initialize OpenSSL */

  SSL * ssl = SSL_new( ctx );
  FD_TEST( ssl );

  SSL_set_accept_state( ssl );

  /* Set up server cert and QUIC */

  uchar server_public_key[ 32 ];
  _setup_ssl_cert_and_quic( ssl, rng, sha, server_public_key );

  /* Create fd_tls instance */

  fd_tls_t  _client[1];
  fd_tls_t * client = fd_tls_join( fd_tls_new( _client ) );
  fd_tls_test_sign_ctx_t client_sign_ctx[1];
  fd_tls_test_sign_ctx( client_sign_ctx, rng );
  *client = _fd_tls_t( &client_sign_ctx, rng );

  fd_tls_estate_cli_t hs[1];
  FD_TEST( fd_tls_estate_cli_new( hs ) );
  memcpy( hs->server_pubkey, server_public_key, 32UL );

  /* Set up ECDH key */

  for( ulong b=0; b<32UL; b++ ) client->kex_private_key[b] = fd_rng_uchar( rng );
  fd_x25519_public( client->kex_public_key, client->kex_private_key );

  /* Set up Ed25519 key */

  fd_memcpy( client->cert_public_key, client_sign_ctx->public_key, 32UL );

  /* Set up client cert */

  fd_x509_mock_cert( client->cert_x509, client->cert_public_key );
  client->cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  /* Do handshake */

  /* Initiate handshake - fd_tls client sends ClientHello */
  fd_tls_client_handshake( client, hs, NULL, 0UL, FD_TLS_LEVEL_INITIAL );

  /* Process handshake messages back and forth until connected */
  while( hs->base.state != FD_TLS_HS_CONNECTED ) {
    /* OpenSSL server processes incoming messages and generates responses */
    _ossl_respond( ssl );

    /* fd_tls client does the same */
    _fd_client_respond( client, hs );
  }

  /* OpenSSL may send NewSessionTicket after handshake completes */
  _ossl_respond( ssl );

  /* Verify both sides completed successfully */
  FD_TEST( hs->base.state == FD_TLS_HS_CONNECTED );
  FD_TEST( SSL_is_init_finished( ssl ) );

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

  SSL_CTX_set_info_callback  ( ctx, _ossl_info   );
  SSL_CTX_set_keylog_callback( ctx, _ossl_keylog );

  SSL_CTX_set_alpn_protos( ctx, (uchar const *)"\xasolana-tpu", 11UL );
  SSL_CTX_set_alpn_select_cb( ctx, _ossl_alpn_select, NULL );

  /* Test server with and without RetryHelloRequest */
  FD_TEST( 1==SSL_CTX_set1_groups_list( ctx, "ffdhe8192:X25519" ) );
  test_server( ctx );
  FD_TEST( 1==SSL_CTX_set1_groups_list( ctx, "X25519" ) );
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

