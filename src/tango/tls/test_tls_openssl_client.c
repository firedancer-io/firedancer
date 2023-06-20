#if !FD_HAS_OPENSSL
#error "This test requires OpenSSL"
#endif

/* Test OpenSSL client to fd_tls server handshake. */

#include "fd_tls.h"
#include "../../ballet/ed25519/fd_x25519.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/tls1.h>

static int
_ossl_level_to_fdtls( OSSL_ENCRYPTION_LEVEL enc_level ) {
  int level;
  switch( enc_level ) {
  case ssl_encryption_initial:     level = FD_TLS_LEVEL_INITIAL;     break;
  case ssl_encryption_early_data:  level = FD_TLS_LEVEL_EARLY;       break;
  case ssl_encryption_handshake:   level = FD_TLS_LEVEL_HANDSHAKE;   break;
  case ssl_encryption_application: level = FD_TLS_LEVEL_APPLICATION; break;
  default:                         level = (int)enc_level;           break;
  }
  return level;
}

static OSSL_ENCRYPTION_LEVEL
_fdtls_level_to_ossl( int level ) {
  OSSL_ENCRYPTION_LEVEL enc_level;
  switch( level ) {
  case FD_TLS_LEVEL_INITIAL:     enc_level = ssl_encryption_initial;       break;
  case FD_TLS_LEVEL_EARLY:       enc_level = ssl_encryption_early_data;    break;
  case FD_TLS_LEVEL_HANDSHAKE:   enc_level = ssl_encryption_handshake;     break;
  case FD_TLS_LEVEL_APPLICATION: enc_level = ssl_encryption_application;   break;
  default:                       enc_level = (OSSL_ENCRYPTION_LEVEL)level; break;
  }
  return enc_level;
}

static int
_ssl_set_encryption_secrets( SSL *                 ssl,
                             OSSL_ENCRYPTION_LEVEL enc_level,
                             uchar const *         read_secret,
                             uchar const *         write_secret,
                             ulong                 secret_len ) {

  FD_TEST( secret_len==32UL );
  switch( enc_level ) {
  case ssl_encryption_handshake: {
    void * client_hs_secret_expected = SSL_get_ex_data( ssl, 2 );
    memcpy( client_hs_secret_expected, write_secret, 32UL );
    void * server_hs_secret_expected = SSL_get_ex_data( ssl, 3 );
    memcpy( server_hs_secret_expected, read_secret,  32UL );
    break;
  }
  default:
    break;
  }
  return 1;
}

static int
_ssl_add_handshake_data( SSL *                 ssl,
                         OSSL_ENCRYPTION_LEVEL enc_level,
                         uchar const *         data,
                         ulong                 data_sz ) {
  (void)ssl; (void)enc_level;
  FD_LOG_HEXDUMP_INFO(( "client => server", data, data_sz ));

  fd_tls_server_t *    server = SSL_get_ex_data( ssl, 0 );
  fd_tls_server_hs_t * hs     = SSL_get_ex_data( ssl, 1 );

  int level = _ossl_level_to_fdtls( enc_level );
  FD_TEST( fd_tls_server_recvmsg( server, hs, data, data_sz, level )==(long)data_sz );

  return 1;
}

static int
_ssl_flush_flight( SSL * ssl ) {
  (void)ssl;
  return 1;
}

static int
_ssl_send_alert( SSL *                 ssl,
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
_ssl_keylog( SSL const *  ssl,
             char const * line ) {
  (void)ssl;
  FD_LOG_DEBUG(( "OpenSSL: %s", line ));
}

int
main( int     argc,
      char ** argv) {
  fd_boot( &argc, &argv );

  /* Create fd_tls instance */

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_tls_server_t    server = {0};
  fd_tls_server_hs_t hs     = {0};
  for( ulong b=0; b<32UL; b++ ) server.kex_private_key[b] = fd_rng_uchar( rng );
  fd_x25519_public( server.kex_public_key, server.kex_private_key );

  for( ulong b=0; b<32UL; b++ ) hs.server_random[b] = fd_rng_uchar( rng );

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
    _ssl_set_encryption_secrets,
    _ssl_add_handshake_data,
    _ssl_flush_flight,
    _ssl_send_alert };
  FD_TEST( 1==SSL_CTX_set_quic_method( ctx, &quic_method ) );

  SSL_CTX_set_keylog_callback( ctx, _ssl_keylog );

  SSL * ssl = SSL_new( ctx );
  FD_TEST( ssl );

  SSL_set_connect_state( ssl );

  uchar client_hs_secret_expected[ 32 ];
  uchar server_hs_secret_expected[ 32 ];

  SSL_set_ex_data( ssl, 0, &server                   );
  SSL_set_ex_data( ssl, 1, &hs                       );
  SSL_set_ex_data( ssl, 2, client_hs_secret_expected );
  SSL_set_ex_data( ssl, 3, server_hs_secret_expected );

  /* Send ClientHello */
  SSL_do_handshake( ssl );
  FD_TEST( ERR_get_error()==0UL );

  /* Send ServerHello */
  uchar record[ 1024 ];
  int   level;
  long send_res = fd_tls_server_sendmsg( &server, &hs, record, sizeof(record), &level );
  FD_TEST( send_res>=0L );
  FD_LOG_HEXDUMP_INFO(( "server => client", record, (ulong)send_res ));
  FD_TEST( 1==SSL_provide_quic_data( ssl, _fdtls_level_to_ossl( level ), record, (ulong)send_res ) );

  /* Process ServerHello */
  SSL_do_handshake( ssl );
  FD_TEST( ERR_get_error()==0UL );

  /* Check handshake secrets */
  FD_TEST( 0==memcmp( client_hs_secret_expected, hs.client_hs_secret, 32UL ) );
  FD_TEST( 0==memcmp( server_hs_secret_expected, hs.server_hs_secret, 32UL ) );
  FD_LOG_INFO(( "client handshake secret: " FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT,
                FD_LOG_HEX16_FMT_ARGS( hs.client_hs_secret    ),
                FD_LOG_HEX16_FMT_ARGS( hs.client_hs_secret+16 ) ));
  FD_LOG_INFO(( "server handshake secret: " FD_LOG_HEX16_FMT FD_LOG_HEX16_FMT,
                FD_LOG_HEX16_FMT_ARGS( hs.server_hs_secret    ),
                FD_LOG_HEX16_FMT_ARGS( hs.server_hs_secret+16 ) ));

  /* Clean up */

  SSL_free( ssl );
  SSL_CTX_free( ctx );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

