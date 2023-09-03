#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../../../util/fd_util.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../ballet/ed25519/fd_ed25519_openssl.h"
#include "../../../ballet/x509/fd_x509_mock.h"

// test transport parameters
uchar test_tp[] = "\x00\x39\x00\x39\x01\x04\x80\x00\xea\x60\x04\x04\x80\x10\x00\x00"
                  "\x05\x04\x80\x10\x00\x00\x06\x04\x80\x10\x00\x00\x07\x04\x80\x10"
                  "\x00\x00\x08\x02\x40\x80\x09\x02\x40\x80\x0a\x01\x03\x0b\x01\x19"
                  "\x0e\x01\x08\x0f\x08\xec\x73\x1b\x41\xa0\xd5\xc6\xfe";

struct fd_hs_data {
  OSSL_ENCRYPTION_LEVEL enc_level;
  int                   sz;
  struct fd_hs_data *   next;

  // data starts here
  uchar                 raw[];
};
typedef struct fd_hs_data fd_hs_data_t;


struct fd_quic_tls {
  fd_hs_data_t * hs_data;

  SSL * ssl;

  int is_server;
  int is_flush;
  int is_hs_complete;

  int state;
  int sec_level;
};
typedef struct fd_quic_tls fd_quic_tls_t;

fd_hs_data_t *
fd_hs_data_new( OSSL_ENCRYPTION_LEVEL enc_level,
                void const * data,
                ulong        sz ) {
  uchar *        block   = malloc( sizeof( fd_hs_data_t  ) + sz );
  fd_hs_data_t * self    = (fd_hs_data_t*)block;
  uchar *        payload = self->raw;

  self->enc_level = enc_level;
  self->sz        = (int)sz;
  self->next      = NULL;

  fd_memcpy( payload, data, sz );

  return self;
}

void
fd_hs_data_delete( fd_hs_data_t * self ) {
  free( self );
}

fd_quic_tls_t *
fd_quic_tls_new( int is_server, SSL_CTX * ssl_ctx ) {
  fd_quic_tls_t * self = malloc( sizeof( fd_quic_tls_t ) );
  FD_TEST( self );

  fd_memset( self, 0, sizeof( *self ) );

  self->hs_data = NULL;

  self->ssl = NULL;

  self->is_server = is_server;
  self->is_flush  = 0;
  self->sec_level = 0;

  // set up ssl
  SSL * ssl = SSL_new( ssl_ctx );

  // add the user context to the ssl
  SSL_set_app_data( ssl, self );

  // set ssl on self to this new object
  self->ssl = ssl;

  // returns void
  if( !is_server ) {
    SSL_set_connect_state( ssl );
    int host_rc = (int)SSL_set_tlsext_host_name( ssl, "localhost" );

    // TODO clean up error handling
    if( host_rc != 1 ) {
      FD_LOG_NOTICE(( "host_rc: %d", host_rc ));
      int err = SSL_get_error( ssl, host_rc );
      FD_LOG_NOTICE(( "err: %d", err ));
    }
  } else {
    SSL_set_accept_state( ssl );
  }

  // assuming this is not needed
  int alpn_rc = SSL_set_alpn_protos( ssl, 0, 0 );
  if( alpn_rc != 0 ) {
    FD_LOG_NOTICE(( "alpn_rc: %d", alpn_rc ));
    int err = SSL_get_error( ssl, alpn_rc );
    FD_LOG_NOTICE(( "err: %d", err ));
  }

  int tp_rc = SSL_set_quic_transport_params( ssl, NULL, 0 );
  if( tp_rc != 1 ) {
    int err = SSL_get_error( ssl, tp_rc );
    FD_LOG_NOTICE(( "SSL_set_quic_transport_params returned error: %d %d", tp_rc, err ));

    char err_buf[256];
    char const * file;
    int line;
    ERR_error_string_n(ERR_get_error_all(&file, &line, NULL, NULL, NULL), err_buf, sizeof(err_buf));
    FD_LOG_NOTICE(( "%s:%d %s", file, line, err_buf ));
  } else {
    FD_LOG_NOTICE(( "tp_rc ok" ));
  }

  return self;
}

void
fd_quic_tls_delete( fd_quic_tls_t * self ) {
  free( self );
}

int fd_quic_ssl_set_encryption_secrets(
      SSL *                 ssl,
      OSSL_ENCRYPTION_LEVEL level,
      uchar const *         read_secret,
      uchar const *         write_secret,
      ulong                 secret_len ) {
  FD_LOG_NOTICE(( "In %s", __func__ ));

  (void)read_secret;
  (void)write_secret;
  (void)secret_len;

  struct fd_quic_tls * ctx = SSL_get_app_data( ssl );
  ctx->sec_level = (int)level;

  return 1;
}

int fd_quic_ssl_add_handshake_data( SSL *                 ssl,
                                    OSSL_ENCRYPTION_LEVEL level,
                                    uchar const *         data,
                                    ulong                 len ) {

  FD_LOG_HEXDUMP_INFO(( "fd_quic_ssl_add_handshake_data", data, len ));

  struct fd_quic_tls * ctx = SSL_get_app_data( ssl );

  fd_hs_data_t * hs_data = fd_hs_data_new( level, data, len );

  // find the end of the list
  fd_hs_data_t ** tail = &ctx->hs_data;
  while( *tail ) tail = &(*tail)->next;

  *tail = hs_data;

  return 1;
}

int
fd_quic_ssl_flush_flight( SSL *ssl ) {
  FD_LOG_NOTICE(( "In %s", __func__ ));
  struct fd_quic_tls * ctx = SSL_get_app_data( ssl );
  ctx->is_flush = 1;
  return 1;
}

int
fd_quic_ssl_send_alert(
    SSL * ssl,
    enum ssl_encryption_level_t level,
    uchar alert ) {
  FD_LOG_NOTICE(( "In %s", __func__ ));

  (void)ssl;
  (void)level;

  FD_LOG_NOTICE(( "Alert: %d %s %s", (int)alert, SSL_alert_type_string_long( alert ), SSL_alert_desc_string_long( alert ) ));
  return 0;
}

int fd_quic_ssl_client_hello(
    SSL *  ssl,
    int *  alert,
    void * arg ) {
  FD_LOG_NOTICE(( "In %s", __func__ ));

  (void)ssl;
  (void)alert;
  (void)arg;

  return 1;
}

SSL_QUIC_METHOD quic_method = {
  fd_quic_ssl_set_encryption_secrets,
  fd_quic_ssl_add_handshake_data,
  fd_quic_ssl_flush_flight,
  fd_quic_ssl_send_alert };

static SSL_CTX *
fd_quic_create_context( int        is_server,
                        fd_rng_t * rng ) {

  SSL_METHOD const * method = TLS_method();

  SSL_CTX * ctx = SSL_CTX_new( method );
  FD_TEST( ctx );

  FD_TEST( 1==SSL_CTX_set_min_proto_version( ctx, TLS1_3_VERSION ) );

  // TODO set max version

  FD_TEST( 1==SSL_CTX_set_quic_method( ctx, &quic_method ) );

  uchar cert_private_key[ 32 ];
  for( ulong b=0; b<32UL; b++ ) cert_private_key[b] = fd_rng_uchar( rng );
  fd_sha512_t sha[1];
  uchar cert_public_key[ 32 ];
  fd_ed25519_public_from_private( cert_public_key, cert_private_key, sha );
  EVP_PKEY * cert_pkey = fd_ed25519_pkey_from_private( cert_private_key );
  FD_TEST( cert_pkey );

  /* Generate X509 certificate */
  uchar cert_asn1[ FD_X509_MOCK_CERT_SZ ];
  fd_x509_mock_cert( cert_asn1, cert_public_key );
  X509 * cert;
  do {
    uchar const * cert_ptr = cert_asn1;
    cert = d2i_X509( NULL, &cert_ptr, FD_X509_MOCK_CERT_SZ );
    FD_TEST( cert );
  } while(0);

  FD_TEST( 1==SSL_CTX_use_certificate( ctx, cert ) );
  X509_free( cert );

  FD_TEST( 1==SSL_CTX_use_PrivateKey( ctx, cert_pkey ) );
  EVP_PKEY_free( cert_pkey );

  // TODO set cipher suites?
  // TODO set verify clients?
  // TODO alpn?

  if( is_server ) {

    // TODO useful max here?
    SSL_CTX_set_max_early_data(ctx, 1024);

    // set callback for client hello
    SSL_CTX_set_client_hello_cb(ctx, fd_quic_ssl_client_hello, NULL);
  }

  return ctx;
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  //SSL_CTX *ctx_server;

  /* Ignore broken pipe signals */
  signal( SIGPIPE, SIG_IGN );

  //ctx_client =  fd_quic_create_context( 0, rng );
  SSL_CTX * ctx = fd_quic_create_context( 1, rng );

  fd_quic_tls_t * tls_client = fd_quic_tls_new( 0, ctx );
  fd_quic_tls_t * tls_server = fd_quic_tls_new( 1, ctx );

  SSL * ssl_client = tls_client->ssl;
  SSL * ssl_server = tls_server->ssl;

  int tp_rc = SSL_set_quic_transport_params( ssl_client, test_tp, sizeof( test_tp ) - 1 );
  if( tp_rc != 1 ) {
    int err = SSL_get_error( ssl_client, tp_rc );
    FD_LOG_NOTICE(( "SSL_set_quic_transport_params returned error: %d %d", tp_rc, err ));

    char err_buf[256];
    char const * file;
    int line;
    ERR_error_string_n(ERR_get_error_all(&file, &line, NULL, NULL, NULL), err_buf, sizeof(err_buf));
    FD_LOG_NOTICE(( "%s:%d %s", file, line, err_buf ));
  } else {
    FD_LOG_NOTICE(( "tp_rc ok" ));
  }

  tp_rc = SSL_set_quic_transport_params( ssl_server, test_tp, sizeof( test_tp ) - 1 );
  if( tp_rc != 1 ) {
    int err = SSL_get_error( ssl_server, tp_rc );
    FD_LOG_NOTICE(( "SSL_set_quic_transport_params returned error: %d %d", tp_rc, err ));

    char err_buf[256];
    char const * file;
    int line;
    ERR_error_string_n(ERR_get_error_all(&file, &line, NULL, NULL, NULL), err_buf, sizeof(err_buf));
    printf( "%s:%d %s\n", file, line, err_buf );
  } else {
    FD_LOG_NOTICE(( "tp_rc ok" ));
  }

  // start client handshake
  //printf( "start client handshake\n" );
  //int handshake_rc = SSL_do_handshake( ssl_client );

  //// handle errors, but not WANT_READ/WANT_WRITE
  //if( handshake_rc <= 0 ) {
  //  int err = SSL_get_error( ssl_client, handshake_rc );
  //  if( err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE ) {
  //    printf( "SSL_do_handshake error: %d\n", err );
  //    char err_buf[256];
  //    char const * file = 0;
  //    int line = 0;
  //    ERR_error_string_n(ERR_get_error_line(&file, &line), err_buf, sizeof(err_buf));
  //    printf( "%s:%d %s\n", file, line, err_buf );
  //    exit( EXIT_FAILURE );
  //  }
  //}

  FD_LOG_NOTICE(( "entering main handshake loop" ));

  while(1) {
    FD_LOG_NOTICE(( "start of handshake loop" ));

    // do we have data to transfer from client to server
    while( tls_client->hs_data ) {
      fd_hs_data_t * hs_data = tls_client->hs_data;

      FD_LOG_NOTICE(( "provide quic data client->server" ));

      FD_LOG_NOTICE(( "server provide_data. encryption level: %d", (int)hs_data->enc_level ));
      FD_TEST( 1==SSL_provide_quic_data( ssl_server, hs_data->enc_level, hs_data->raw, (ulong)hs_data->sz ) );

      // remove hs_data from head of list
      tls_client->hs_data = hs_data->next;

      // delete it
      fd_hs_data_delete( hs_data );
    }

    // do we have data to transfer from server to client
    while( tls_server->hs_data ) {
      fd_hs_data_t * hs_data = tls_server->hs_data;

      FD_LOG_NOTICE(( "provide quic data server->client" ));

      FD_LOG_NOTICE(( "server provide_data. encryption level: %d", (int)hs_data->enc_level ));
      FD_TEST( 1==SSL_provide_quic_data( ssl_client, hs_data->enc_level, hs_data->raw, (ulong)hs_data->sz ) );

      // remove hs_data from head of list
      tls_server->hs_data = hs_data->next;

      // delete it
      fd_hs_data_delete( hs_data );
    }

    if( !tls_client->is_hs_complete ) {
      FD_LOG_NOTICE(( "calling do_handshake on client" ));

      int handshake_rc = SSL_do_handshake( ssl_client );
      switch( handshake_rc ) {
        case 0: // failed
          FD_LOG_ERR(( "client reported handshake failed" ));
        case 1: // completed
          tls_client->is_hs_complete = 1;
          break;
        default:
          {
            int err = SSL_get_error( ssl_client, handshake_rc );
            if( err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE ) {
              FD_LOG_NOTICE(( "client reported error during handshake" ));
              char err_buf[256];
              char const * file = 0;
              int line = 0;
              ERR_error_string_n(ERR_get_error_all(&file, &line, NULL, NULL, NULL), err_buf, sizeof(err_buf));
              FD_LOG_ERR(( "%s:%d %s", file, line, err_buf ));
            }
          }
      }
    } else {
      int post_rc = SSL_process_quic_post_handshake( ssl_client );
      switch( post_rc ) {
        case 0: // failed
          FD_LOG_NOTICE(( "client SSL_process_quic_post_handshake reported error" ));
          {
            int err = SSL_get_error( ssl_client, post_rc );
            if( err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE ) {
              FD_LOG_NOTICE(( "client reported error during handshake" ));
              char err_buf[256];
              char const * file = 0;
              int line = 0;
              ERR_error_string_n(ERR_get_error_all(&file, &line, NULL, NULL, NULL), err_buf, sizeof(err_buf));
              FD_LOG_ERR(( "%s:%d %s", file, line, err_buf ));
            }
          }
          exit( EXIT_FAILURE );
        case 1: // success
          break;
        default:
          FD_LOG_ERR(( "client SSL_process_quic_post_handshake returned invalid rc %d", post_rc ));
      }
    }

    if( !tls_server->is_hs_complete ) {
      FD_LOG_NOTICE(( "calling do_handshake on server" ));

      int handshake_rc = SSL_do_handshake( ssl_server );
      switch( handshake_rc ) {
        case 0: // failed
          FD_LOG_ERR(( "client reported handshake failed" ));
          break;
        case 1: // completed
          tls_server->is_hs_complete = 1;
          break;
        default:
          {
            int err = SSL_get_error( ssl_server, handshake_rc );
            if( err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE ) {
              FD_LOG_NOTICE(( "server reported error during handshake" ));
              char err_buf[256];
              char const * file = 0;
              int line = 0;
              ERR_error_string_n(ERR_get_error_all(&file, &line, NULL, NULL, NULL), err_buf, sizeof(err_buf));
              FD_LOG_ERR(( "%s:%d %s", file, line, err_buf ));
            }
          }
      }
    } else {
      int post_rc = SSL_process_quic_post_handshake( ssl_server );
      switch( post_rc ) {
        case 0: // failed
          FD_LOG_NOTICE(( "server SSL_process_quic_post_handshake reported error" ));
          {
            int err = SSL_get_error( ssl_server, post_rc );
            if( err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE ) {
              FD_LOG_NOTICE(( "server reported error during handshake" ));
              char err_buf[256];
              char const * file = 0;
              int line = 0;
              ERR_error_string_n(ERR_get_error_all(&file, &line, NULL, NULL, NULL), err_buf, sizeof(err_buf));
              FD_LOG_ERR(( "%s:%d %s", file, line, err_buf ));
            }
          }
          exit( EXIT_FAILURE );
        case 1: // success
          break;
        default:
          FD_LOG_ERR(( "server SSL_process_quic_post_handshake returned invalid rc %d", post_rc ));
      }
    }

    if( tls_server->is_hs_complete && tls_client->is_hs_complete ) {
      FD_LOG_NOTICE(( "both handshakes complete" ));
      if( tls_server->hs_data ) {
        FD_LOG_NOTICE(( "tls_server still has hs_data" ));
      }

      if( tls_client->hs_data ) {
        FD_LOG_NOTICE(( "tls_client still has hs_data" ));
      }
      if( tls_server->hs_data == NULL && tls_client->hs_data == NULL ) break;
    }


    //if( tls_server->hs_data == NULL && tls_client->hs_data == NULL ) {
    //  FD_LOG_NOTICE(( "not complete, but no data in flight\n" );
    //  exit( EXIT_FAILURE );
    //}
  }

  FD_LOG_NOTICE(( "both client and server report handshake complete" ));

  if( tls_server->hs_data ) {
    FD_LOG_NOTICE(( "tls_server still has hs_data" ));
  }

  if( tls_client->hs_data ) {
    FD_LOG_NOTICE(( "tls_client still has hs_data" ));
  }

  // now how do we encode/decode actual data?

  // TODO free everything
  SSL_free( ssl_client );
  SSL_free( ssl_server );
  //SSL_CTX_free(ctx_client);
  SSL_CTX_free(ctx);

  free( tls_client );
  free( tls_server );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
