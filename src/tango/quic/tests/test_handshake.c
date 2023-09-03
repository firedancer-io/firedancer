#include <unistd.h>
#include <string.h>
#include <signal.h>

#include "../../../util/fd_util.h"
#include "../tls/fd_quic_tls.h"
#include "../templ/fd_quic_transport_params.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../ballet/ed25519/fd_ed25519_openssl.h"
#include "../../../ballet/x509/fd_x509_mock.h"


// test transport parameters
uchar test_tp[] = "\x01\x04\x80\x00\xea\x60\x04\x04\x80\x10\x00\x00"
                   "\x05\x04\x80\x10\x00\x00\x06\x04\x80\x10\x00\x00\x07\x04\x80\x10"
                   "\x00\x00\x08\x02\x40\x80\x09\x02\x40\x80\x0a\x01\x03\x0b\x01\x19"
                   "\x0e\x01\x08\x0f\x08\xec\x73\x1b\x41\xa0\xd5\xc6\xfe";


typedef struct my_quic_tls my_quic_tls_t;
struct my_quic_tls {
  SSL * ssl;

  int is_server;
  int is_flush;
  int is_hs_complete;

  int state;
  int sec_level;
};

static void
my_hs_complete( fd_quic_tls_hs_t *           hs,
                void *                       context ) {
  (void)hs;
  (void)context;

  FD_LOG_DEBUG(( "callback handshake complete" ));

  my_quic_tls_t * ctx = (my_quic_tls_t*)context;
  ctx->is_hs_complete = 1;
}

static void
my_secrets( fd_quic_tls_hs_t *           hs,
            void *                       context,
            fd_quic_tls_secret_t const * secret ) {
  (void)hs;
  (void)context;
  (void)secret;

  FD_LOG_DEBUG(( "callback secrets" ));
}

void
my_alert( fd_quic_tls_hs_t * hs,
          void *             context,
          int                alert) {
  (void)hs;
  (void)context;
  (void)alert;

  FD_LOG_INFO(( "Alert: %d %s %s\n",
                (int)alert,
                SSL_alert_type_string_long( alert ),
                SSL_alert_desc_string_long( alert ) ));
}

int
my_client_hello( fd_quic_tls_hs_t * hs,
                 void *             context ) {
  (void)hs;
  (void)context;

  FD_LOG_INFO(( "callback client hello" ));
  return FD_QUIC_TLS_SUCCESS;
}

static uchar test_quic_tls_mem[ 272128UL ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  fd_rng_t  _rng[1];   fd_rng_t * rng    = fd_rng_join   ( fd_rng_new   ( _rng, 0U, 0UL ) );

  /* Generate certificate key */
  uchar cert_private_key[ 32 ];
  for( ulong b=0; b<32UL; b++ ) cert_private_key[b] = fd_rng_uchar( rng );
  EVP_PKEY * cert_pkey = fd_ed25519_pkey_from_private( cert_private_key );
  FD_TEST( cert_pkey );

  /* Generate X509 certificate */
  uchar cert_asn1[ FD_X509_MOCK_CERT_SZ ];
  fd_x509_mock_cert( cert_asn1, cert_private_key, fd_rng_ulong( rng ), sha );
  X509 * cert;
  do {
    uchar const * cert_ptr = cert_asn1;
    cert = d2i_X509( NULL, &cert_ptr, FD_X509_MOCK_CERT_SZ );
    FD_TEST( cert );
  } while(0);

  // config parameters
  fd_quic_tls_cfg_t cfg = {
    .client_hello_cb       = my_client_hello,
    .alert_cb              = my_alert,
    .secret_cb             = my_secrets,
    .handshake_complete_cb = my_hs_complete,

    .max_concur_handshakes = 16,

    .cert     = cert,
    .cert_key = cert_pkey
  };

  /* dump transport params */
  fd_quic_transport_params_t tmp_tp[1] = {0};
  uchar const * transport_params      = test_tp;
  ulong         transport_params_sz   = sizeof( test_tp ) - 1; /* test_tp has terminating NUL */
  uchar const * tp_p  = transport_params;
  ulong         tp_sz = transport_params_sz;

  FD_TEST( fd_quic_decode_transport_params( tmp_tp, tp_p, tp_sz )>=0 );

  fd_quic_dump_transport_params( tmp_tp, stdout );
  fflush( stdout );

  ulong tls_align     = fd_quic_tls_align();
  ulong tls_footprint = fd_quic_tls_footprint( cfg.max_concur_handshakes );

  FD_LOG_INFO(( "fd_quic_tls_t align:     %lu bytes", tls_align     ));
  FD_LOG_INFO(( "fd_quic_tls_t footprint: %lu bytes", tls_footprint ));
  FD_TEST( tls_footprint<=sizeof(test_quic_tls_mem) );

  fd_quic_tls_t * quic_tls = fd_quic_tls_new( test_quic_tls_mem, &cfg );
  FD_TEST( quic_tls );

  my_quic_tls_t tls_client[1] = {0};
  my_quic_tls_t tls_server[1] = {0};

  //uchar   cli_dst_conn_id[1] = {0};
  //ulong  cli_dst_conn_id_sz = 0;
  fd_quic_tls_hs_t * hs_client = fd_quic_tls_hs_new( quic_tls,
                                                     tls_client,
                                                     0 /* is_server */,
                                                     "localhost",
                                                     transport_params,
                                                     transport_params_sz );
  FD_TEST( hs_client );

  //uchar   svr_dst_conn_id[1] = {0};
  //ulong  svr_dst_conn_id_sz = 0;
  fd_quic_tls_hs_t * hs_server = fd_quic_tls_hs_new( quic_tls,
                                                     tls_server,
                                                     1 /* is_server */,
                                                     "localhost",
                                                     transport_params,
                                                     transport_params_sz );
  FD_TEST( hs_server );

  // generate initial secrets for client

  // server needs first packet with dst conn id in order to generate keys
  //   What happens when dst conn id changes?

  /* Ignore broken pipe signals */
  signal( SIGPIPE, SIG_IGN );

  // start client handshake
  // client fd_quic_tls_hs_t is primed upon creation

  FD_LOG_NOTICE(( "entering main handshake loop" ));

  for( int l = 0; l < 30; ++l ) {
    FD_LOG_INFO(( "start of handshake loop" ));

    int have_client_data = 0;
    int have_server_data = 0;

    // do we have data to transfer from client to server
    //while( tls_client->hs_data ) {
    while( 1 ) {
      //fd_hs_data_t * hs_data = tls_client->hs_data;
      fd_quic_tls_hs_data_t * hs_data   = NULL;
      for( int j = 0; j < 4; ++j ) {
        hs_data = fd_quic_tls_get_hs_data( hs_client, j );
        if( hs_data ) break;
      }
      if( !hs_data ) break;

      FD_LOG_NOTICE(( "client hs_data: %p", (void*)hs_data ));

      FD_LOG_NOTICE(( "provide quic data client->server" ));

      // here we need encrypt/decrypt
      // collect fragments at the same enc/sec level, then encrypt
      // ... then decrypt and forward

#if 0
      int provide_rc = fd_quic_tls_provide_data( hs_server, hs_data->enc_level, hs_data->data, hs_data->data_sz );
      if( provide_rc == FD_QUIC_TLS_FAILED ) {
        fprintf( stderr, "fd_quic_tls_provide_data error line: %d\n", __LINE__ );
        exit( EXIT_FAILURE );
      }
#else
      /* test providing data 1 byte at a time */
      ulong pdata_off = 0;
      ulong pdata_sz  = hs_data->data_sz;
      while( pdata_off < pdata_sz ) {
        FD_TEST( fd_quic_tls_provide_data( hs_server, hs_data->enc_level, hs_data->data + pdata_off, 1 )!=FD_QUIC_TLS_FAILED );
        pdata_off++;
      }
#endif

      // remove hs_data from head of list
      //tls_client->hs_data = hs_data->next;
      fd_quic_tls_pop_hs_data( hs_client, (int)hs_data->enc_level );

      // delete it
      //fd_hs_data_delete( hs_data );
    }

    // do we have data to transfer from server to client
    while( 1 ) {
      fd_quic_tls_hs_data_t * hs_data = NULL;
      for( int j=0; j<4; ++j ) {
        hs_data = fd_quic_tls_get_hs_data( hs_server, j );
        if( hs_data ) break;
      }
      if( !hs_data ) break;

      FD_LOG_INFO(( "server hs_data: %p", (void *)hs_data ));
      FD_LOG_DEBUG(( "provide quic data server->client" ));

      // here we need encrypt/decrypt
      FD_TEST( fd_quic_tls_provide_data( hs_client, hs_data->enc_level, hs_data->data, hs_data->data_sz )!=FD_QUIC_TLS_FAILED );

      // remove hs_data from head of list
      fd_quic_tls_pop_hs_data( hs_server, (int)hs_data->enc_level );
    }

    FD_LOG_NOTICE(( "fd_quic_tls_process( hs_client )..." ));
    int process_rc = fd_quic_tls_process( hs_client );
    FD_LOG_NOTICE(( "returned: %d", (int)process_rc ));
    if( process_rc != FD_QUIC_TLS_SUCCESS ) {
      FD_LOG_ERR(( "process failed. ssl_rc: %d  ssl_err: %d  line: %d", hs_client->err_ssl_rc, hs_client->err_ssl_err, hs_client->err_line ));
    }

    FD_LOG_NOTICE(( "fd_quic_tls_process( hs_server )..." ));
    process_rc = fd_quic_tls_process( hs_server );
    FD_LOG_NOTICE(( "returned: %d", (int)process_rc ));
    if( process_rc != FD_QUIC_TLS_SUCCESS ) {
      FD_LOG_ERR(( "process failed. ssl_rc: %d  ssl_err: %d  line: %d", hs_client->err_ssl_rc, hs_client->err_ssl_err, hs_client->err_line ));
    }

    /* check for hs data here */
    have_client_data = 1;
    for( int i=0; i<4; ++i ) {
      have_client_data &= (_Bool)fd_quic_tls_get_hs_data( hs_client, i );
    }

    have_server_data = 1;
    for( int i=0; i<4; ++i ) {
      have_server_data &= (_Bool)fd_quic_tls_get_hs_data( hs_server, i );
    }

    if( tls_server->is_hs_complete && tls_client->is_hs_complete ) {
      FD_LOG_INFO(( "both handshakes complete" ));
      if( have_server_data ) {
        FD_LOG_INFO(( "tls_server still has data" ));
      }

      if( have_client_data ) {
        FD_LOG_INFO(( "tls_client still has data" ));
      }
      if( !( have_server_data || have_client_data ) ) break;
    }

    if( !( have_server_data || have_client_data ) ) {
      FD_LOG_INFO(( "incomplete, but no more data to exchange" ));
    }

  }

  uchar const * peer_tp    = NULL;
  ulong        peer_tp_sz = 0;

  fd_quic_tls_get_peer_transport_params( hs_server, &peer_tp, &peer_tp_sz );
  FD_LOG_HEXDUMP_INFO(( "tls server peer transport params", peer_tp, peer_tp_sz ));

  peer_tp    = NULL;
  peer_tp_sz = 0;

  fd_quic_tls_get_peer_transport_params( hs_client, &peer_tp, &peer_tp_sz );
  FD_LOG_HEXDUMP_INFO(( "tls client peer transport params", peer_tp, peer_tp_sz ));

           fd_quic_tls_hs_delete( hs_client );
           fd_quic_tls_hs_delete( hs_server );
  FD_TEST( fd_quic_tls_delete   ( quic_tls  ) );

  fd_sha512_delete( fd_sha512_leave( sha ) );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
