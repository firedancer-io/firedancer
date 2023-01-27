#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef unsigned char uchar;


// test transport parameters
uchar test_tp[] = "\x00\x39\x00\x39\x01\x04\x80\x00\xea\x60\x04\x04\x80\x10\x00\x00" 
                   "\x05\x04\x80\x10\x00\x00\x06\x04\x80\x10\x00\x00\x07\x04\x80\x10"
                   "\x00\x00\x08\x02\x40\x80\x09\x02\x40\x80\x0a\x01\x03\x0b\x01\x19"
                   "\x0e\x01\x08\x0f\x08\xec\x73\x1b\x41\xa0\xd5\xc6\xfe";

struct fd_hs_data {
  int                 enc_level;
  int                 sz;
  struct fd_hs_data * next;

  // data starts here
  uchar               raw[];
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
fd_hs_data_new( int enc_level, void const * data, size_t sz ) {
  uchar *        block   = malloc( sizeof( fd_hs_data_t  ) + sz );
  fd_hs_data_t * self    = (fd_hs_data_t*)block;
  uchar *        payload = self->raw;

  self->enc_level = enc_level;
  self->sz        = sz;
  self->next      = NULL;

  memcpy( payload, data, sz );

  return self;
}

void
fd_hs_data_delete( fd_hs_data_t * self ) {
  free( self );
}

fd_quic_tls_t *
fd_quic_tls_new( int is_server, SSL_CTX * ssl_ctx ) {
  fd_quic_tls_t * self = malloc( sizeof( fd_quic_tls_t ) );
  if( !self ) {
    fprintf( stderr, "fd_quic_tls_new: unable to create tls context\n" );
    exit( EXIT_FAILURE );
  }

  memset( self, 0, sizeof( *self ) );

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
    int host_rc = SSL_set_tlsext_host_name( ssl, "localhost" );

    // TODO clean up error handling
    if( host_rc != 1 ) {
      printf( "host_rc: %d\n", host_rc );
      int err = SSL_get_error( ssl, host_rc );
      printf( "err: %d\n", err );
    }
  } else {
    SSL_set_accept_state( ssl );
  }

  // assuming this is not needed
  int alpn_rc = SSL_set_alpn_protos( ssl, 0, 0 );
  if( alpn_rc != 0 ) {
    printf( "alpn_rc: %d\n", alpn_rc );
    int err = SSL_get_error( ssl, alpn_rc );
    printf( "err: %d\n", err );
  }

  int tp_rc = SSL_set_quic_transport_params( ssl, NULL, 0 );
  if( tp_rc != 1 ) {
    int err = SSL_get_error( ssl, tp_rc );
    printf( "SSL_set_quic_transport_params returned error: %d %d\n", tp_rc, err );

    char err_buf[256];
    char const * file;
    int line;
    ERR_error_string_n(ERR_get_error_line(&file, &line), err_buf, sizeof(err_buf));
    printf( "%s:%d %s\n", file, line, err_buf );
  } else {
    printf( "tp_rc ok\n" );
  }

  return self;
}

void
fd_quic_tls_delete( fd_quic_tls_t * self ) {
  free( self );
}

int fd_quic_ssl_set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                              const uint8_t *read_secret,
                              const uint8_t *write_secret, size_t secret_len) {
  printf( "In %s\n", __func__ );

  struct fd_quic_tls * ctx = SSL_get_app_data( ssl );
  ctx->sec_level = level;

  return 1;
}

int fd_quic_ssl_add_handshake_data( SSL *                 ssl,
                                    OSSL_ENCRYPTION_LEVEL level,
                                    uint8_t const *       data,
                                    size_t                len ) {
  printf( "In %s\n", __func__ );
  for( size_t j = 0; j < len; ++j ) {
    printf( "%2.2x ", data[j] );
  }
  printf( "\n" );

  struct fd_quic_tls * ctx = SSL_get_app_data( ssl );

  fd_hs_data_t * hs_data = fd_hs_data_new( level, data, len );

  // find the end of the list
  fd_hs_data_t ** tail = &ctx->hs_data;
  while( *tail ) tail = &(*tail)->next;

  *tail = hs_data;

  return 1;
}

int fd_quic_ssl_flush_flight(SSL *ssl) {
  printf( "In %s\n", __func__ );
  struct fd_quic_tls * ctx = SSL_get_app_data( ssl );
  ctx->is_flush = 1;
  return 1;
}

int fd_quic_ssl_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert) {
  printf( "In %s\n", __func__ );
  printf( "Alert: %d %s %s\n", (int)alert, SSL_alert_type_string_long( alert ), SSL_alert_desc_string_long( alert ) );
  return 0;
}

int fd_quic_ssl_client_hello(SSL *ssl, int * alert, void * arg ) {
  printf( "In %s\n", __func__ );
  return 1;
}

SSL_QUIC_METHOD quic_method = {
  fd_quic_ssl_set_encryption_secrets,
  fd_quic_ssl_add_handshake_data,
  fd_quic_ssl_flush_flight,
  fd_quic_ssl_send_alert };

SSL_CTX * fd_quic_create_context( int is_server )
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit( EXIT_FAILURE );
    }

    if (!SSL_CTX_set_min_proto_version( ctx, TLS1_3_VERSION ) ) {
      printf( "Unable to set TLS min proto version to 1.3\n" );
      exit( EXIT_FAILURE );
    }

    // TODO set max version

    if (!SSL_CTX_set_quic_method( ctx, &quic_method ) ) {
      printf( "Unable to set quic method\n" );
      exit( EXIT_FAILURE );
    }

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit( EXIT_FAILURE );
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit( EXIT_FAILURE );
    }

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


int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    //SSL_CTX *ctx_server;

    /* Ignore broken pipe signals */
    signal(SIGPIPE, SIG_IGN);

    //ctx_client =  fd_quic_create_context( 0 );
    ctx =  fd_quic_create_context( 1 );

    fd_quic_tls_t * tls_client = fd_quic_tls_new( 0, ctx );
    fd_quic_tls_t * tls_server = fd_quic_tls_new( 1, ctx );

    SSL * ssl_client = tls_client->ssl;
    SSL * ssl_server = tls_server->ssl;

    int tp_rc = SSL_set_quic_transport_params( ssl_client, test_tp, sizeof( test_tp ) - 1 );
    if( tp_rc != 1 ) {
      int err = SSL_get_error( ssl_client, tp_rc );
      printf( "SSL_set_quic_transport_params returned error: %d %d\n", tp_rc, err );

      char err_buf[256];
      char const * file;
      int line;
      ERR_error_string_n(ERR_get_error_line(&file, &line), err_buf, sizeof(err_buf));
      printf( "%s:%d %s\n", file, line, err_buf );
    } else {
      printf( "tp_rc ok\n" );
    }

    tp_rc = SSL_set_quic_transport_params( ssl_server, test_tp, sizeof( test_tp ) - 1 );
    if( tp_rc != 1 ) {
      int err = SSL_get_error( ssl_server, tp_rc );
      printf( "SSL_set_quic_transport_params returned error: %d %d\n", tp_rc, err );

      char err_buf[256];
      char const * file;
      int line;
      ERR_error_string_n(ERR_get_error_line(&file, &line), err_buf, sizeof(err_buf));
      printf( "%s:%d %s\n", file, line, err_buf );
    } else {
      printf( "tp_rc ok\n" );
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

    printf( "entering main handshake loop\n" );

    while(1) {
      printf( "start of handshake loop\n");

      // do we have data to transfer from client to server
      while( tls_client->hs_data ) {
        fd_hs_data_t * hs_data = tls_client->hs_data;

        printf( "provide quic data client->server\n" );

        printf( "server provide_data. encryption level: %d\n", (int)hs_data->enc_level );
        int provide_rc = SSL_provide_quic_data( ssl_server, hs_data->enc_level, hs_data->raw, hs_data->sz );
        if( provide_rc != 1 ) {
          fprintf( stderr, "SSL_provide_quic_data error line: %d\n", __LINE__ );
          exit( EXIT_FAILURE );
        }

        // remove hs_data from head of list
        tls_client->hs_data = hs_data->next;

        // delete it
        fd_hs_data_delete( hs_data );
      }

      // do we have data to transfer from server to client
      while( tls_server->hs_data ) {
        fd_hs_data_t * hs_data = tls_server->hs_data;

        printf( "provide quic data server->client\n" );

        printf( "server provide_data. encryption level: %d\n", (int)hs_data->enc_level );
        int provide_rc = SSL_provide_quic_data( ssl_client, hs_data->enc_level, hs_data->raw, hs_data->sz );
        if( provide_rc != 1 ) {
          fprintf( stderr, "SSL_provide_quic_data error line: %d\n", __LINE__ );
          exit( EXIT_FAILURE );
        }

        // remove hs_data from head of list
        tls_server->hs_data = hs_data->next;

        // delete it
        fd_hs_data_delete( hs_data );
      }

      if( !tls_client->is_hs_complete ) {
        printf( "calling do_handshake on client\n" );

        int handshake_rc = SSL_do_handshake( ssl_client );
        switch( handshake_rc ) {
          case 0: // failed
            printf( "client reported handshake failed\n" );
            exit( EXIT_FAILURE );
          case 1: // completed
            tls_client->is_hs_complete = 1;
            break;
          default:
            {
              int err = SSL_get_error( ssl_client, handshake_rc );
              if( err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE ) {
                printf( "client reported error during handshake\n" );
                char err_buf[256];
                char const * file = 0;
                int line = 0;
                ERR_error_string_n(ERR_get_error_line(&file, &line), err_buf, sizeof(err_buf));
                printf( "%s:%d %s\n", file, line, err_buf );
                exit( EXIT_FAILURE );
              }
            }
        }
      } else {
        int post_rc = SSL_process_quic_post_handshake( ssl_client );
        switch( post_rc ) {
          case 0: // failed
            printf( "client SSL_process_quic_post_handshake reported error\n" );
            {
              int err = SSL_get_error( ssl_client, post_rc );
              if( err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE ) {
                printf( "client reported error during handshake\n" );
                char err_buf[256];
                char const * file = 0;
                int line = 0;
                ERR_error_string_n(ERR_get_error_line(&file, &line), err_buf, sizeof(err_buf));
                printf( "%s:%d %s\n", file, line, err_buf );
                exit( EXIT_FAILURE );
              }
            }
            exit( EXIT_FAILURE );
          case 1: // success
            break;
          default:
            printf( "client SSL_process_quic_post_handshake returned invalid rc %d\n", post_rc );
            exit( EXIT_FAILURE );
        }
      }

      if( !tls_server->is_hs_complete ) {
        printf( "calling do_handshake on server\n" );

        int handshake_rc = SSL_do_handshake( ssl_server );
        switch( handshake_rc ) {
          case 0: // failed
            printf( "client reported handshake failed\n" );
            exit( EXIT_FAILURE );
          case 1: // completed
            tls_server->is_hs_complete = 1;
            break;
          default:
            {
              int err = SSL_get_error( ssl_server, handshake_rc );
              if( err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE ) {
                printf( "server reported error during handshake\n" );
                char err_buf[256];
                char const * file = 0;
                int line = 0;
                ERR_error_string_n(ERR_get_error_line(&file, &line), err_buf, sizeof(err_buf));
                printf( "%s:%d %s\n", file, line, err_buf );
                exit( EXIT_FAILURE );
              }
            }
        }
      } else {
        int post_rc = SSL_process_quic_post_handshake( ssl_server );
        switch( post_rc ) {
          case 0: // failed
            printf( "server SSL_process_quic_post_handshake reported error\n" );
            {
              int err = SSL_get_error( ssl_server, post_rc );
              if( err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE ) {
                printf( "server reported error during handshake\n" );
                char err_buf[256];
                char const * file = 0;
                int line = 0;
                ERR_error_string_n(ERR_get_error_line(&file, &line), err_buf, sizeof(err_buf));
                printf( "%s:%d %s\n", file, line, err_buf );
                exit( EXIT_FAILURE );
              }
            }
            exit( EXIT_FAILURE );
          case 1: // success
            break;
          default:
            printf( "server SSL_process_quic_post_handshake returned invalid rc %d\n", post_rc );
            exit( EXIT_FAILURE );
        }
      }

      if( tls_server->is_hs_complete && tls_client->is_hs_complete ) {
        printf( "both handshakes complete\n" );
        if( tls_server->hs_data ) {
          printf( "tls_server still has hs_data\n" );
        }

        if( tls_client->hs_data ) {
          printf( "tls_client still has hs_data\n" );
        }
        if( tls_server->hs_data == NULL && tls_client->hs_data == NULL ) break;
      }


      //if( tls_server->hs_data == NULL && tls_client->hs_data == NULL ) {
      //  printf( "not complete, but no data in flight\n" );
      //  exit( EXIT_FAILURE );
      //}
    }

    printf( "both client and server report handshake complete\n" );

    if( tls_server->hs_data ) {
      printf( "tls_server still has hs_data\n" );
    }

    if( tls_client->hs_data ) {
      printf( "tls_client still has hs_data\n" );
    }

    // now how do we encode/decode actual data?

    // TODO free everything
    SSL_free( ssl_client );
    SSL_free( ssl_server );
    //SSL_CTX_free(ctx_client);
    SSL_CTX_free(ctx);
}


