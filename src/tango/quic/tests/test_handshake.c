#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>

#include "../../../util/fd_util.h"
#include "../tls/fd_quic_tls.h"
#include "../templ/fd_quic_transport_params.h"


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



int
my_client_hello( fd_quic_tls_hs_t * hs,
                 void *             context );

void
my_alert( fd_quic_tls_hs_t * hs,
          void *             context,
          int                alert );

void
my_secret( fd_quic_tls_hs_t * hs,
           void *             context,
           fd_quic_tls_secret_t * secret );

void
my_handshake_complete( fd_quic_tls_hs_t * hs,
                       void *             context  );


void
my_hs_complete( fd_quic_tls_hs_t *           hs,
                void *                       context ) {
  (void)hs;
  (void)context;

  printf( "In %s\n", __func__ );

  my_quic_tls_t * ctx = (my_quic_tls_t*)context;
  ctx->is_hs_complete = 1;
}

void
my_secrets( fd_quic_tls_hs_t *           hs,
            void *                       context,
            fd_quic_tls_secret_t const * secret ) {
  (void)hs;
  (void)context;
  (void)secret;

  printf( "In %s\n", __func__ );

  my_quic_tls_t * ctx = (my_quic_tls_t*)context;
  (void)ctx;
}

void
my_alert( fd_quic_tls_hs_t * hs,
          void *             context,
          int                alert) {
  (void)hs;
  (void)context;
  (void)alert;

  printf( "In %s\n", __func__ );
  printf( "Alert: %d %s %s\n", (int)alert, SSL_alert_type_string_long( alert ), SSL_alert_desc_string_long( alert ) );
}

int
my_client_hello( fd_quic_tls_hs_t * hs,
                 void *             context ) {
  (void)hs;
  (void)context;

  printf( "In %s\n", __func__ );
  return FD_QUIC_TLS_SUCCESS;
}


int main( int argc, char **argv )
{
  (void)argc;
  (void)argv;
  fd_boot( &argc, &argv );

  // config parameters
  fd_quic_tls_cfg_t cfg = {
    .client_hello_cb       = my_client_hello,
    .alert_cb              = my_alert,
    .secret_cb             = my_secrets,
    .handshake_complete_cb = my_hs_complete,

    .max_concur_handshakes = 16,

    .cert_file             = "cert.pem",
    .key_file              = "key.pem",

  };

  /* dump transport params */
  fd_quic_transport_params_t tmp_tp[1] = {0};
  uchar const * transport_params      = test_tp;
  size_t        transport_params_sz   = sizeof( test_tp ) - 1; /* test_tp has terminating NUL */
  uchar const * tp_p  = transport_params;
  size_t        tp_sz = transport_params_sz;
  int rc = fd_quic_decode_transport_params( tmp_tp, tp_p, tp_sz );
  if( rc < 0 ) {
    printf( "transport parameters failed to parse\n" );
    exit(1);
  }

  fd_quic_dump_transport_params( tmp_tp, stdout );
  fflush( stdout );

  fd_quic_tls_t * quic_tls = fd_quic_tls_new( &cfg );

  my_quic_tls_t tls_client[1] = {0};
  my_quic_tls_t tls_server[1] = {0};

  //uchar   cli_dst_conn_id[1] = {0};
  //size_t  cli_dst_conn_id_sz = 0;
  fd_quic_tls_hs_t * hs_client = fd_quic_tls_hs_new( quic_tls,
                                                     tls_client,
                                                     0 /* is_server */,
                                                     "localhost",
                                                     transport_params,
                                                     transport_params_sz );
  if( !hs_client ) {
    fprintf( stderr, "fd_quic_tls_hs_new returned NULL\n" );
    exit(1);
  }

  //uchar   svr_dst_conn_id[1] = {0};
  //size_t  svr_dst_conn_id_sz = 0;
  fd_quic_tls_hs_t * hs_server = fd_quic_tls_hs_new( quic_tls,
                                                     tls_server,
                                                     1 /* is_server */,
                                                     "localhost",
                                                     transport_params,
                                                     transport_params_sz );
  if( !hs_server ) {
    fprintf( stderr, "fd_quic_tls_hs_new returned NULL\n" );
    exit(1);
  }

  // generate initial secrets for client

  // server needs first packet with dst conn id in order to generate keys
  //   What happens when dst conn id changes?

  /* Ignore broken pipe signals */
  signal(SIGPIPE, SIG_IGN);

  // start client handshake
  // client fd_quic_tls_hs_t is primed upon creation

  printf( "entering main handshake loop\n" );

  for( int l = 0; l < 30; ++l ) {
    printf( "start of handshake loop\n");

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

      printf( "client hs_data: %p\n", (void*)hs_data );

      printf( "provide quic data client->server\n" );

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
      size_t pdata_off = 0;
      size_t pdata_sz  = hs_data->data_sz;
      while( pdata_off < pdata_sz ) {
        int provide_rc = fd_quic_tls_provide_data( hs_server, hs_data->enc_level, hs_data->data + pdata_off, 1 );
        if( provide_rc == FD_QUIC_TLS_FAILED ) {
          fprintf( stderr, "fd_quic_tls_provide_data error line: %d\n", __LINE__ );
          exit( EXIT_FAILURE );
        }

        pdata_off++;
      }
#endif

      // remove hs_data from head of list
      //tls_client->hs_data = hs_data->next;
      fd_quic_tls_pop_hs_data( hs_client, hs_data->enc_level );

      // delete it
      //fd_hs_data_delete( hs_data );
    }

    // do we have data to transfer from server to client
    while( 1 ) {
      fd_quic_tls_hs_data_t * hs_data   = NULL;
      for( int j = 0; j < 4; ++j ) {
        hs_data = fd_quic_tls_get_hs_data( hs_server, j );
        if( hs_data ) break;
      }
      if( !hs_data ) break;

      printf( "server hs_data: %p\n", (void*)hs_data );

      printf( "provide quic data server->client\n" );

      // here we need encrypt/decrypt

      int provide_rc = fd_quic_tls_provide_data( hs_client, hs_data->enc_level, hs_data->data, hs_data->data_sz );
      if( provide_rc == FD_QUIC_TLS_FAILED ) {
        fprintf( stderr, "fd_quic_tls_provide_data error line: %d\n", __LINE__ );
        exit( EXIT_FAILURE );
      }

      // remove hs_data from head of list
      fd_quic_tls_pop_hs_data( hs_server, hs_data->enc_level );
    }

    printf( "fd_quic_tls_process( hs_client )...\n" );
    int process_rc = fd_quic_tls_process( hs_client );
    printf( "returned: %d\n", (int)process_rc );
    if( process_rc != FD_QUIC_TLS_SUCCESS ) {
      printf( "process failed. ssl_rc: %d  ssl_err: %d  line: %d\n", hs_client->err_ssl_rc, hs_client->err_ssl_err, hs_client->err_line );
      exit(1);
    }

    printf( "fd_quic_tls_process( hs_server )...\n" );
    process_rc = fd_quic_tls_process( hs_server );
    printf( "returned: %d\n", (int)process_rc );
    if( process_rc != FD_QUIC_TLS_SUCCESS ) {
      printf( "process failed. ssl_rc: %d  ssl_err: %d  line: %d\n", hs_client->err_ssl_rc, hs_client->err_ssl_err, hs_client->err_line );
      exit(1);
    }

    /* check for hs data here */
    have_client_data = 1;
    for( int i = 0; i < 4; ++i ) {
      have_client_data &= (_Bool)fd_quic_tls_get_hs_data( hs_client, i );
    }

    have_server_data = 1;
    for( int i = 0; i < 4; ++i ) {
      have_server_data &= (_Bool)fd_quic_tls_get_hs_data( hs_server, i );
    }

    if( tls_server->is_hs_complete && tls_client->is_hs_complete ) {
      printf( "both handshakes complete\n" );
      if( have_server_data ) {
        printf( "tls_server still has data\n" );
      }

      if( have_client_data ) {
        printf( "tls_client still has data\n" );
      }
      if( !( have_server_data || have_client_data ) ) break;
    }

    if( !( have_server_data || have_client_data ) ) {
      printf( "incomplete, but no more data to exchange\n" );
    }

  }

  uchar const * peer_tp    = NULL;
  size_t        peer_tp_sz = 0;

  fd_quic_tls_get_peer_transport_params( hs_server, &peer_tp, &peer_tp_sz );
  printf( "tls_server returned peer transport params of length %lu\n", peer_tp_sz );
  for( size_t j = 0; j < peer_tp_sz; ++j ) {
    printf( "%2.2x ", peer_tp[j] );
  }
  printf( "\n" );

  peer_tp    = NULL;
  peer_tp_sz = 0;

  fd_quic_tls_get_peer_transport_params( hs_client, &peer_tp, &peer_tp_sz );
  printf( "tls_client returned peer transport params of length %lu\n", peer_tp_sz );
  for( size_t j = 0; j < peer_tp_sz; ++j ) {
    printf( "%2.2x ", peer_tp[j] );
  }
  printf( "\n" );


  fd_quic_tls_hs_delete( hs_client );
  fd_quic_tls_hs_delete( hs_server );
  fd_quic_tls_delete( quic_tls );
}
