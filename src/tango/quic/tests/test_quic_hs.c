#include "../fd_quic.h"

#include <stdio.h>
#include <stdlib.h>

#include "fd_pcap.h"

#define BUF_SZ (1<<20)

void
write_shb( FILE * file ) {
  pcap_shb_t shb[1] = {{ 0x0A0D0D0A, sizeof( pcap_shb_t ), 0x1A2B3C4D, 1, 0, (ulong)-1, sizeof( pcap_shb_t ) }};
  ulong rc = fwrite( shb, sizeof(shb), 1, file );
  if( rc != 1 ) {
    abort();
  }
}

void
write_idb( FILE * file ) {
  pcap_idb_t idb[1] = {{ 0x00000001, sizeof( pcap_idb_t ), 1, 0, 0, sizeof( pcap_idb_t ) }};
  ulong rc = fwrite( idb, sizeof(idb), 1, file );
  if( rc != 1 ) {
    abort();
  }
}

void
write_epb( FILE * file, uchar * buf, unsigned buf_sz, ulong ts ) {
  if( buf_sz == 0 ) return;

  uint ts_lo = (uint)ts;
  uint ts_hi = (uint)( ts >> 32u );

  unsigned align_sz = ( ( buf_sz - 1u ) | 0x03u ) + 1u;
  unsigned tot_len  = align_sz + (unsigned)sizeof( pcap_epb_t ) + 4;
  pcap_epb_t epb[1] = {{
    0x00000006,
    tot_len,
    0, /* intf id */
    ts_hi,
    ts_lo,
    buf_sz,
    buf_sz }};

  ulong rc = fwrite( epb, sizeof( epb ), 1, file );
  if( rc != 1 ) {
    abort();
  }

  rc = fwrite( buf, buf_sz, 1, file );
  if( rc != 1 ) {
    abort();
  }

  if( align_sz > buf_sz ) {
    /* write padding */
    uchar pad[4] = {0};
    fwrite( pad, align_sz - buf_sz, 1, file );
  }

  rc = fwrite( &tot_len, 4, 1, file );
  if( rc != 1 ) {
    abort();
  }

}


extern uchar  pkt_full[];
extern ulong pkt_full_sz;

ulong
aio_cb( void * context, fd_aio_pkt_info_t * batch, ulong batch_sz ) {
  (void)context;

  printf( "aio_cb callback\n" );
  for( ulong j = 0; j < batch_sz; ++j ) {
    printf( "batch %d\n", (int)j );
    uchar const * data = (uchar const *)batch[j].buf;
    for( ulong k = 0; k < batch[j].buf_sz; ++k ) {
      printf( "%2.2x ", (uint)data[k] );
    }
    printf( "\n\n" );
  }

  fflush( stdout );

  return batch_sz; /* consumed all */
}

uchar fail = 0;

void
my_stream_receive_cb( fd_quic_stream_t * stream,
                      void *             ctx,
                      uchar const *      data,
                      ulong             data_sz,
                      ulong           offset ) {
  (void)ctx;
  (void)stream;

  ulong expected_data_sz = 512ul;

  printf( "my_stream_receive_cb : received data from peer. size: %lu  offset: %lu\n",
      (ulong)data_sz, (ulong)offset );
  printf( "%s\n", data );

  if( data_sz != 512 ) {
    fprintf( stderr, "my_stream_receive_cb : data wrong size. Is: %lu, expected: %lu\n",
        data_sz, expected_data_sz );
    fail = 1;
  } else {
    if( memcmp( data, "Hello world", 11u ) != 0 ) {
      fprintf( stderr, "my_stream_receive_cb : value received incorrect" );
      fail = 1;
    }
  }
}

fd_quic_t *
new_quic( fd_quic_config_t * quic_config ) {

  ulong  align    = fd_quic_align();
  ulong  fp       = fd_quic_footprint( BUF_SZ,
                                       BUF_SZ,
                                       quic_config->max_concur_streams,
                                       quic_config->max_in_flight_acks,
                                       quic_config->max_concur_conns,
                                       quic_config->max_concur_conn_ids );
  void * mem      = malloc( fp + align );
  ulong smem     = (ulong)mem;
  ulong memalign = smem % align;
  void * aligned  = ((uchar*)mem) + ( memalign == 0 ? 0 : ( align - memalign ) );

  fd_quic_t * quic = fd_quic_new( aligned,
                                  BUF_SZ,
                                  BUF_SZ,
                                  quic_config->max_concur_streams,
                                  quic_config->max_in_flight_acks,
                                  quic_config->max_concur_conns,
                                  quic_config->max_concur_conn_ids );
  FD_TEST( quic );

  fd_quic_init( quic, quic_config );

  return quic;
}


struct my_context {
  int server;
};
typedef struct my_context my_context_t;

int server_complete = 0;
int client_complete = 0;

/* server connetion received in callback */
fd_quic_conn_t * server_conn = NULL;

void my_connection_new( fd_quic_conn_t * conn, void * vp_context ) {
  (void)conn;
  (void)vp_context;

  printf( "server handshake complete\n" );
  fflush( stdout );

  server_complete = 1;
  server_conn = conn;
}

void my_handshake_complete( fd_quic_conn_t * conn, void * vp_context ) {
  (void)conn;
  (void)vp_context;

  printf( "client handshake complete\n" );
  fflush( stdout );

  client_complete = 1;
}


/* pcap aio pipe */
struct aio_pipe {
  fd_aio_t * aio;
  FILE *     file;
};
typedef struct aio_pipe aio_pipe_t;


int
pipe_aio_receive( void * vp_ctx, fd_aio_pkt_info_t const * batch, ulong batch_sz, ulong * opt_batch_idx ) {
  static ulong ts = 0;
  ts += 100000ul;

  aio_pipe_t * pipe = (aio_pipe_t*)vp_ctx;

#if 1
  for( unsigned j = 0; j < batch_sz; ++j ) {
    write_epb( pipe->file, batch[j].buf, (unsigned)batch[j].buf_sz, ts );
  }
  fflush( pipe->file );
#endif

  /* forward */
  return fd_aio_send( pipe->aio, batch, batch_sz, opt_batch_idx );
}


/* global "clock" */
ulong now = 123;

ulong test_clock( void * ctx ) {
  (void)ctx;
  return now;
}

int
main( int argc, char ** argv ) {
  FILE * pcap = fopen( "test_quic_hs.pcapng", "wb" );
  if( !pcap ) abort();

  write_shb( pcap );
  write_idb( pcap );

  (void)argc;
  (void)argv;
  // Transport params:
  //   original_destination_connection_id (0x00)         :   len(0)
  //   max_idle_timeout (0x01)                           : * 60000
  //   stateless_reset_token (0x02)                      :   len(0)
  //   max_udp_payload_size (0x03)                       :   0
  //   initial_max_data (0x04)                           : * 1048576
  //   initial_max_stream_data_bidi_local (0x05)         : * 1048576
  //   initial_max_stream_data_bidi_remote (0x06)        : * 1048576
  //   initial_max_stream_data_uni (0x07)                : * 1048576
  //   initial_max_streams_bidi (0x08)                   : * 128
  //   initial_max_streams_uni (0x09)                    : * 128
  //   ack_delay_exponent (0x0a)                         : * 3
  //   max_ack_delay (0x0b)                              : * 25
  //   disable_active_migration (0x0c)                   :   0
  //   preferred_address (0x0d)                          :   len(0)
  //   active_connection_id_limit (0x0e)                 : * 8
  //   initial_source_connection_id (0x0f)               : * len(8) ec 73 1b 41 a0 d5 c6 fe
  //   retry_source_connection_id (0x10)                 :   len(0)

  /* all zeros transport params is a reasonable default */
  fd_quic_transport_params_t tp[1] = {0};

  /* establish these parameters as "present" */
  tp->max_idle_timeout                               = 60000;
  tp->max_idle_timeout_present                       = 1;
  tp->initial_max_data                               = 1048576;
  tp->initial_max_data_present                       = 1;
  tp->initial_max_stream_data_bidi_local             = 1048576;
  tp->initial_max_stream_data_bidi_local_present     = 1;
  tp->initial_max_stream_data_bidi_remote            = 1048576;
  tp->initial_max_stream_data_bidi_remote_present    = 1;
  tp->initial_max_stream_data_uni                    = 1048576;
  tp->initial_max_stream_data_uni_present            = 1;
  tp->initial_max_streams_bidi                       = 128;
  tp->initial_max_streams_bidi_present               = 1;
  tp->initial_max_streams_uni                        = 128;
  tp->initial_max_streams_uni_present                = 1;
  tp->ack_delay_exponent                             = 3;
  tp->ack_delay_exponent_present                     = 1;
  tp->max_ack_delay                                  = 25;
  tp->max_ack_delay_present                          = 1;
  tp->active_connection_id_limit                     = 8;
  tp->active_connection_id_limit_present             = 1;

  fd_quic_config_t quic_config = {0};

  quic_config.transport_params      = tp;
  quic_config.max_concur_conns      = 10;
  quic_config.max_concur_conn_ids   = 10;
  quic_config.max_concur_streams    = 10;
  quic_config.max_concur_handshakes = 10;
  quic_config.max_in_flight_pkts    = 100;
  quic_config.max_in_flight_acks    = 100;
  quic_config.conn_id_sparsity      = 4;

  quic_config.cert_file             = "cert.pem";
  quic_config.key_file              = "key.pem";

  quic_config.cb_stream_receive     = my_stream_receive_cb;

  quic_config.now_fn  = test_clock;
  quic_config.now_ctx = NULL;

  quic_config.tx_buf_sz = 1ul << 20ul;

  fd_quic_host_cfg_t server_cfg = { "server_host", 0x0a000001u, 4434 };
  fd_quic_host_cfg_t client_cfg = { "client_host", 0xc01a1a1au, 2001 };

  quic_config.host_cfg = client_cfg;
  fd_quic_t * client_quic = new_quic( &quic_config );

  quic_config.host_cfg = server_cfg;
  fd_quic_t * server_quic = new_quic( &quic_config );

  /* make use aio to point quic directly at quic */
  fd_aio_t * aio_n2q = fd_quic_get_aio_net_in( server_quic );
  fd_aio_t * aio_q2n = fd_quic_get_aio_net_in( client_quic );

#if 0
  fd_quic_set_aio_net_out( server_quic, aio_q2n );
  fd_quic_set_aio_net_out( client_quic, aio_n2q );
#else
  /* create a pipe for catching data as it passes thru */
  aio_pipe_t pipe[2] = { { aio_n2q, pcap }, { aio_q2n, pcap } };

  fd_aio_t * aio[2];
  uchar aio_mem[2][128] = {0};

  if( fd_aio_footprint() < sizeof( aio_mem[0] ) ) {
    FD_LOG_ERR(( "fd_aio_footprint returned value larger than reserved memory" ));
  }

  aio[0] = fd_aio_join( fd_aio_new( aio_mem[0], &pipe[0], pipe_aio_receive ) );
  aio[1] = fd_aio_join( fd_aio_new( aio_mem[1], &pipe[1], pipe_aio_receive ) );

  fd_quic_set_aio_net_out( server_quic, aio[1] );
  fd_quic_set_aio_net_out( client_quic, aio[0] );
#endif

  /* set up server_quic as server */
  fd_quic_listen( server_quic );

  /* set the callback for new connections */
  fd_quic_set_cb_conn_new( server_quic, my_connection_new );

  /* set the callback for handshake complete */
  fd_quic_set_cb_conn_handshake_complete( client_quic, my_handshake_complete );

  /* make a connection from client to server */
  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, server_cfg.ip_addr, server_cfg.udp_port );
  (void)client_conn;

  /* do general processing */
  for( ulong j = 0; j < 20; j++ ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      printf( "client and server have no schedule\n" );
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    printf( "running services at %lu\n", (ulong)next_wakeup );
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );

    if( server_complete && client_complete ) {
      printf( "***** both handshakes complete *****\n" );

      break;
    }
  }

  for( ulong j = 0; j < 20; j++ ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      printf( "client and server have no schedule\n" );
      break;
    }

    now = next_wakeup;

    fd_quic_service( client_quic );
    fd_quic_service( server_quic );
  }

  /* TODO we get callback before the call to fd_quic_conn_new_stream can complete
     must delay until the conn->state is ACTIVE */

  /* try sending */
  fd_quic_stream_t * client_stream = fd_quic_conn_new_stream( client_conn, FD_QUIC_TYPE_BIDIR );
  FD_TEST( client_stream );

  fd_quic_stream_t * client_stream_0 = fd_quic_conn_new_stream( client_conn, FD_QUIC_TYPE_BIDIR );
  FD_TEST( client_stream_0 );

  char buf[512] = "Hello world!\x00-   ";
  fd_aio_pkt_info_t batch[1] = {{ buf, sizeof( buf ) }};
  int rc = fd_quic_stream_send( client_stream, batch, 1 );

  printf( "fd_quic_stream_send returned %d\n", rc );

  for( unsigned j = 0; j < 5000; ++j ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      printf( "client and server have no schedule\n" );
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    printf( "running services at %lu\n", (ulong)next_wakeup );
    fflush( stdout );

    fd_quic_service( client_quic );
    fd_quic_service( server_quic );

    buf[12] = ' ';
    //buf[15] = (char)( ( j / 10 ) + '0' );
    buf[16] = (char)( ( j % 10 ) + '0' );
    int rc = 0;
    if( j&1 ) {
      rc = fd_quic_stream_send( client_stream, batch, 1 );
    } else {
      rc = fd_quic_stream_send( client_stream_0, batch, 1 );
    }

    printf( "fd_quic_stream_send returned %d\n", rc );
  }

  /* allow acks to go */
  for( unsigned j = 0; j < 10; ++j ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      /* indicates no schedule, which is correct after connection
         instances have been reclaimed */
      printf( "Finished cleaning up connections\n" );
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    printf( "running services at %lu\n", (ulong)next_wakeup );
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );

  }

  fd_quic_delete( server_quic );
  fd_quic_delete( client_quic );

  if( fail ) {
    fprintf( stderr, "FAIL\n" );
    exit(1);
  }

  printf( "PASS\n" );

  return 0;
}


