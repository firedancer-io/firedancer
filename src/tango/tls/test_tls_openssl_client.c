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
_ssl_set_encryption_secrets( SSL *                 ssl,
                             OSSL_ENCRYPTION_LEVEL enc_level,
                             uchar const *         read_secret,
                             uchar const *         write_secret,
                             ulong                 secret_len ) {
  (void)ssl; (void)enc_level; (void)read_secret; (void)write_secret; (void)secret_len;
  FD_LOG_HEXDUMP_INFO(( "secret read",  read_secret,  secret_len ));
  FD_LOG_HEXDUMP_INFO(( "secret write", write_secret, secret_len ));
  FD_LOG_NOTICE(( "_ssl_set_encryption_secrets" ));
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

  FD_TEST( fd_tls_server_recvmsg( server, hs, data, data_sz )==(long)data_sz );

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

  SSL * ssl = SSL_new( ctx );
  FD_TEST( ssl );

  SSL_set_connect_state( ssl );

  SSL_set_ex_data( ssl, 0, &server );
  SSL_set_ex_data( ssl, 1, &hs     );

  /* Send ClientHello */
  SSL_do_handshake( ssl );

  /* Send ServerHello */
  uchar record[ 1024 ];
  long send_res = fd_tls_server_sendmsg( &server, &hs, record, sizeof(record) );
  FD_TEST( send_res>=0L );
  FD_LOG_HEXDUMP_INFO(( "server => client", record, (ulong)send_res ));
  FD_TEST( 1==SSL_provide_quic_data( ssl, ssl_encryption_initial, record, (ulong)send_res ) );

  /* Process ServerHello */
  SSL_do_handshake( ssl );

  /* Clean up */

  SSL_free( ssl );
  SSL_CTX_free( ctx );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

