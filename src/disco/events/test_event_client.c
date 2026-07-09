#include "fd_event_client.c"
#include "../../util/tmpl/fd_unit_test.c"

#if FD_HAS_OPENSSL
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

typedef struct {
  SSL_CTX * client_ctx;
  SSL_CTX * server_ctx;
  SSL *     client_ssl;
  SSL *     server_ssl;
} test_tls_pair_t;

static void
test_tls_pair_fini( test_tls_pair_t * pair ) {
  if( pair->client_ssl ) SSL_free( pair->client_ssl );
  if( pair->server_ssl ) SSL_free( pair->server_ssl );
  if( pair->client_ctx  ) SSL_CTX_free( pair->client_ctx  );
  if( pair->server_ctx  ) SSL_CTX_free( pair->server_ctx  );
}

static void
test_tls_server_ctx_set_cert( SSL_CTX * server_ctx ) {
  EVP_PKEY_CTX * pkey_ctx = EVP_PKEY_CTX_new_id( EVP_PKEY_RSA, NULL );
  FD_TEST( pkey_ctx );
  FD_TEST( EVP_PKEY_keygen_init( pkey_ctx )==1 );
  FD_TEST( EVP_PKEY_CTX_set_rsa_keygen_bits( pkey_ctx, 2048 )==1 );

  EVP_PKEY * pkey = NULL;
  FD_TEST( EVP_PKEY_keygen( pkey_ctx, &pkey )==1 );
  EVP_PKEY_CTX_free( pkey_ctx );

  X509 * cert = X509_new();
  FD_TEST( cert );
  FD_TEST( X509_set_version( cert, 2L )==1 );
  FD_TEST( ASN1_INTEGER_set( X509_get_serialNumber( cert ), 1L )==1 );
  FD_TEST( X509_gmtime_adj( X509_getm_notBefore( cert ), 0L ) );
  FD_TEST( X509_gmtime_adj( X509_getm_notAfter ( cert ), 3600L ) );
  FD_TEST( X509_set_pubkey( cert, pkey )==1 );

  X509_NAME * name = X509_get_subject_name( cert );
  FD_TEST( X509_NAME_add_entry_by_txt( name, "CN", MBSTRING_ASC, (uchar const *)"localhost", -1, -1, 0 )==1 );
  FD_TEST( X509_set_issuer_name( cert, name )==1 );
  FD_TEST( X509_sign( cert, pkey, EVP_sha256() ) );

  FD_TEST( SSL_CTX_use_certificate( server_ctx, cert )==1 );
  FD_TEST( SSL_CTX_use_PrivateKey ( server_ctx, pkey )==1 );
  FD_TEST( SSL_CTX_check_private_key( server_ctx )==1 );

  X509_free( cert );
  EVP_PKEY_free( pkey );
}

static void
test_tls_pair_init( test_tls_pair_t * pair ) {
  *pair = (test_tls_pair_t){0};

  pair->client_ctx = SSL_CTX_new( TLS_client_method() );
  pair->server_ctx = SSL_CTX_new( TLS_server_method() );
  FD_TEST( pair->client_ctx );
  FD_TEST( pair->server_ctx );

  SSL_CTX_set_verify( pair->client_ctx, SSL_VERIFY_NONE, NULL );
  test_tls_server_ctx_set_cert( pair->server_ctx );

  pair->client_ssl = SSL_new( pair->client_ctx );
  pair->server_ssl = SSL_new( pair->server_ctx );
  FD_TEST( pair->client_ssl );
  FD_TEST( pair->server_ssl );

  BIO * client_bio = NULL;
  BIO * server_bio = NULL;
  FD_TEST( BIO_new_bio_pair( &client_bio, 0UL, &server_bio, 0UL )==1 );

  SSL_set_bio( pair->client_ssl, client_bio, client_bio );
  SSL_set_bio( pair->server_ssl, server_bio, server_bio );
  SSL_set_connect_state( pair->client_ssl );
  SSL_set_accept_state ( pair->server_ssl );

  for( ulong i=0UL; i<1000UL; i++ ) {
    int client_done = SSL_is_init_finished( pair->client_ssl );
    int server_done = SSL_is_init_finished( pair->server_ssl );
    if( client_done && server_done ) return;

    int cr = SSL_do_handshake( pair->client_ssl );
    if( cr!=1 ) {
      int err = SSL_get_error( pair->client_ssl, cr );
      FD_TEST( err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE );
    }

    int sr = SSL_do_handshake( pair->server_ssl );
    if( sr!=1 ) {
      int err = SSL_get_error( pair->server_ssl, sr );
      FD_TEST( err==SSL_ERROR_WANT_READ || err==SSL_ERROR_WANT_WRITE );
    }
  }

  FD_TEST( SSL_is_init_finished( pair->client_ssl ) );
  FD_TEST( SSL_is_init_finished( pair->server_ssl ) );
}

static void
test_tls_server_write( SSL *       ssl,
                       void const *data,
                       ulong       data_sz ) {
  uchar const * cur = data;
  while( data_sz ) {
    size_t write_sz = 0UL;
    int ok = SSL_write_ex( ssl, cur, data_sz, &write_sz );
    FD_TEST( ok==1 );
    FD_TEST( write_sz>0UL );
    cur     += write_sz;
    data_sz -= (ulong)write_sz;
  }
}

#endif /* FD_HAS_OPENSSL */

#if FD_HAS_OPENSSL
FD_UNIT_TEST( conn_ssl_lifecycle ) {
  static uchar circq_mem[ 4096UL+512UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 512UL ) );
  FD_TEST( circq );

  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  FD_TEST( rng );

  static uchar client_mem[ 131072UL ] __attribute__((aligned(128)));
  uchar identity_pubkey[32] = {0};
  fd_event_client_t * client = fd_event_client_join( fd_event_client_new(
      client_mem,
      NULL,
      rng,
      circq,
      1<<20,
      "https://localhost:1",
      identity_pubkey,
      "0.0.0",
      "0000000000000000000000000000000000000000",
      "test",
      1UL,
      2UL,
      3UL,
      4096UL,
      1,
      NULL ) );
  FD_TEST( client );

  test_tls_pair_t tls[1];
  test_tls_pair_init( tls );

  /* Attach an already-handshaked in-memory TLS connection to the event client. */
  fd_grpc_client_t * grpc = client->grpc_client;
  client->state            = FD_EVENT_CLIENT_STATE_CONNECTED;
  client->sockfd           = -1;
  client->ssl              = tls->client_ssl;
  client->defer_disconnect = INT_MAX;
  grpc->ssl_hs_done        = 1;
  grpc->h2_hs_done         = 1;
  grpc->conn->flags        = 0;

  fd_h2_ping_t ping = {
    .hdr = {
      .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ),
      .flags       = 0U,
      .r_stream_id = 0U
    },
    .payload = 0x0102030405060708UL
  };
  fd_h2_goaway_t goaway = {
    .hdr = {
      .typlen      = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_GOAWAY, 8UL ),
      .flags       = 0U,
      .r_stream_id = 0U
    },
    .last_stream_id = 0U,
    .error_code     = fd_uint_bswap( FD_H2_SUCCESS )
  };

  /* PING queues an ACK; GOAWAY synchronously fires conn_dead during rx. */
  uchar h2[ sizeof(ping)+sizeof(goaway) ];
  fd_memcpy( h2,              &ping,   sizeof(ping)   );
  fd_memcpy( h2+sizeof(ping), &goaway, sizeof(goaway) );
  test_tls_server_write( tls->server_ssl, h2, sizeof(h2) );

  /* rxtx must flush the ACK without conn_dead freeing the active SSL object. */
  int charge_busy = 0;
  int rc = fd_grpc_client_rxtx_ossl( grpc, tls->client_ssl, &charge_busy );

  FD_TEST( rc==0 );
  FD_TEST( client->ssl==tls->client_ssl );
  FD_TEST( client->state==FD_EVENT_CLIENT_STATE_CONNECTED );
  FD_TEST( client->defer_disconnect==DISCONNECT_REASON_PEER_CLOSED );
  FD_TEST( fd_h2_rbuf_used_sz( grpc->frame_tx )==0UL );

  tls->client_ssl = client->ssl;
  client->ssl = NULL;
  test_tls_pair_fini( tls );
  fd_rng_delete( fd_rng_leave( rng ) );
}
#endif

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
