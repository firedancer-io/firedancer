#if !FD_HAS_OPENSSL
#error "This test requires OpenSSL"
#endif

/* Test OpenSSL client to fd_tls server handshake. */

#include "fd_tls.h"
#include "../../ballet/ed25519/fd_x25519.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/tls1.h>

/* Map between encryption levels */

static int const
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

static uchar client_hs_secret_ossl [ 32UL ];
static uchar client_hs_secret_fdtls[ 32UL ];
static uchar server_hs_secret_ossl [ 32UL ];
static uchar server_hs_secret_fdtls[ 32UL ];

static int
_ossl_secrets( SSL *                 ssl,
               OSSL_ENCRYPTION_LEVEL enc_level,
               uchar const *         read_secret,
               uchar const *         write_secret,
               ulong                 secret_len ) {

  (void)ssl;

  FD_TEST( secret_len==32UL );
  switch( enc_level ) {
  case ssl_encryption_handshake: {
    memcpy( client_hs_secret_ossl, write_secret, 32UL );
    memcpy( server_hs_secret_ossl, read_secret,  32UL );
    break;
  }
  default:
    break;
  }
  return 1;
}

static int
_fdtls_secrets( void const * handshake,
                void const * recv_secret,
                void const * send_secret,
                int          encryption_level ) {
  (void)handshake;
  FD_TEST( encryption_level==FD_TLS_LEVEL_HANDSHAKE );
  memcpy( client_hs_secret_fdtls, recv_secret, 32UL );
  memcpy( server_hs_secret_fdtls, send_secret, 32UL );
  return 1;
}

/* Record transport */

static int   _record_level;
static uchar _record_buf[ 1024 ];
static ulong _record_cur   = 0UL;
static int   _record_flush = 0;

static int
_ossl_sendmsg( SSL *                 ssl,
               OSSL_ENCRYPTION_LEVEL enc_level,
               uchar const *         record,
               ulong                 record_sz ) {

  (void)ssl;
  FD_LOG_HEXDUMP_INFO(( "client => server", record, record_sz ));

  _record_level = _ossl_level_to_fdtls[ enc_level ];
  fd_memcpy( _record_buf, record, record_sz );
  _record_cur = record_sz;

  return 1;
}

int
_fdtls_sendmsg( void const * handshake,
                void const * record,
                ulong        record_sz,
                int          encryption_level,
                int          flush ) {

  (void)handshake;
  FD_LOG_HEXDUMP_INFO(( "server => client", record, record_sz ));

  _record_level = encryption_level;
  fd_memcpy( _record_buf, record, record_sz );
  _record_cur   = record_sz;
  _record_flush = flush;

  return 1;
}

static int
_ossl_flush_flight( SSL * ssl ) {
  (void)ssl;
  _record_flush = 1;
  return 1;
}

/* Miscellaneous OpenSSL callbacks */

static int
_ossl_send_alert( SSL *                 ssl,
                  OSSL_ENCRYPTION_LEVEL level,
                  uchar                 alert ) {
  (void)ssl; (void)level;
  FD_LOG_ERR(( "client => server: alert %u (%s-%s)",
               alert,
               SSL_alert_desc_string     ( alert ),
               SSL_alert_desc_string_long( alert ) ));
  return 1;
}

static void
_ossl_keylog( SSL const *  ssl,
              char const * line ) {
  (void)ssl;
  FD_LOG_DEBUG(( "OpenSSL: %s", line ));
}

/* Miscellaneous fd_tls callbacks */

static fd_rng_t rng;

void *
_fdtls_rand( void * _buf,
             ulong    bufsz ) {
  uchar * buf = _buf;
  for( ulong j=0; j<bufsz; j++ ) buf[j] = fd_rng_uchar( &rng );
  return buf;
}

int
main( int     argc,
      char ** argv) {
  fd_boot( &argc, &argv );

  /* Create fd_tls instance */

  fd_rng_join( fd_rng_new( &rng, 0U, 0UL ) );

  fd_tls_server_t    server = {
    .rand_fn    = _fdtls_rand,
    .secrets_fn = _fdtls_secrets,
    .sendmsg_fn = _fdtls_sendmsg
  };

  fd_tls_server_hs_t hs;
  FD_TEST( fd_tls_server_hs_new( &hs ) );

  for( ulong b=0; b<32UL; b++ ) server.kex_private_key[b] = fd_rng_uchar( &rng );
  fd_x25519_public( server.kex_public_key, server.kex_private_key );

  /* Initialize OpenSSL */

  SSL_METHOD const * method = TLS_method();
  FD_TEST( method );

  SSL_CTX * ctx = SSL_CTX_new( method );
  FD_TEST( ctx );

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

  SSL_CTX_set_keylog_callback( ctx, _ossl_keylog );

  SSL * ssl = SSL_new( ctx );
  FD_TEST( ssl );

  SSL_set_connect_state( ssl );

  uchar client_hs_secret_expected[ 32 ];
  uchar server_hs_secret_expected[ 32 ];

  SSL_set_ex_data( ssl, 0, &server                   );
  SSL_set_ex_data( ssl, 1, &hs                       );
  SSL_set_ex_data( ssl, 2, client_hs_secret_expected );
  SSL_set_ex_data( ssl, 3, server_hs_secret_expected );

  /* Let OpenSSL send ClientHello */
  SSL_do_handshake( ssl );
  FD_TEST( ERR_get_error()==0UL );
  FD_TEST( _record_flush==1 );
  _record_flush = 0;

  /* Let fd_tls process ClientHello and send ServerHello */
  long hs_res = fd_tls_server_handshake( &server, &hs, _record_buf, _record_cur, _record_level );
  FD_TEST( hs_res>=0L );
  FD_TEST( _record_flush==1 );
  _record_flush = 0;

  /* Let OpenSSL process ServerHello */
  FD_TEST( 1==SSL_provide_quic_data( ssl, _fdtls_level_to_ossl[ _record_level ], _record_buf, _record_cur ) );
  SSL_do_handshake( ssl );
  FD_TEST( ERR_get_error()==0UL );

  /* Check handshake secrets */
  FD_TEST( 0==memcmp( client_hs_secret_ossl, client_hs_secret_fdtls, 32UL ) );
  FD_TEST( 0==memcmp( server_hs_secret_ossl, server_hs_secret_fdtls, 32UL ) );
  FD_LOG_INFO(( "client handshake secret: " FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT,
                FD_LOG_HEX16_FMT_ARGS( client_hs_secret_fdtls    ),
                FD_LOG_HEX16_FMT_ARGS( client_hs_secret_fdtls+16 ) ));
  FD_LOG_INFO(( "server handshake secret: " FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT,
                FD_LOG_HEX16_FMT_ARGS( server_hs_secret_fdtls    ),
                FD_LOG_HEX16_FMT_ARGS( server_hs_secret_fdtls+16 ) ));

  /* Clean up */

  SSL_free( ssl );
  SSL_CTX_free( ctx );
  fd_rng_delete( fd_rng_leave( &rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

