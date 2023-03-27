#include "../fd_quic.h"

#include <stdio.h>
#include <stdlib.h>

#include "fd_pcap.h"


#define SEND_SZ 1400ul
#define BUF_SZ (1<<20)


extern uchar pkt_full[];
extern ulong pkt_full_sz;

ulong
gettime( void ) {
  struct timespec ts;
  clock_gettime( CLOCK_REALTIME, &ts );
  return (ulong)ts.tv_nsec + (ulong)1e9 * (ulong)ts.tv_sec;
}

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

ulong rx_tot_sz = 0;

void
my_stream_receive_cb( fd_quic_stream_t * stream,
                      void *             ctx,
                      uchar const *      data,
                      ulong              data_sz,
                      ulong              offset,
                      int                fin ) {
  (void)ctx;
  (void)stream;
  (void)data;
  (void)data_sz;
  (void)offset;
  (void)fin;

#if 0
  printf( "my_stream_receive_cb : received data from peer. size: %lu  offset: %lu\n",
      (ulong)data_sz, (ulong)offset );
  printf( "%s\n", data );
#endif

  rx_tot_sz += data_sz;}


struct my_context {
  int server;
};
typedef struct my_context my_context_t;

int server_complete = 0;
int client_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;

void my_connection_new( fd_quic_conn_t * conn,
                        void *           vp_context ) {
  (void)vp_context;

  FD_LOG_INFO(( "server handshake complete" ));
  fd_log_flush();

  server_complete = 1;
  server_conn = conn;
}

void my_handshake_complete( fd_quic_conn_t * conn,
                            void *           vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_INFO(( "client handshake complete" ));
  fd_log_flush();

  client_complete = 1;
}


/* pcap aio pipe */
struct aio_pipe {
  fd_aio_t * aio;
  FILE *     file;
};
typedef struct aio_pipe aio_pipe_t;


int
pipe_aio_receive( void *              vp_ctx,
                  fd_aio_pkt_info_t * batch,
                  ulong               batch_sz,
                  ulong *             opt_batch_idx ) {
  static ulong ts = 0;
  ts += 100000ul;
  (void)ts;

  aio_pipe_t * pipe = (aio_pipe_t*)vp_ctx;

  /* forward */
  return fd_aio_send( pipe->aio, batch, batch_sz, opt_batch_idx );
}


ulong test_clock( void * ctx ) {
  (void)ctx;
  return gettime();
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _pcap = fd_env_strip_cmdline_cstr( &argc, &argv, "--pcap", NULL, "test_quic_hs.pcapng" );

  FILE * pcap = fopen( _pcap, "wb" );
  FD_TEST( pcap );

  fd_quic_limits_t quic_limits = {
    .conn_cnt         = 10,
    .conn_id_cnt      = 10,
    .conn_id_sparsity = 4.0,
    .handshake_cnt    = 10,
    .stream_cnt       = 4,
    .inflight_pkt_cnt = 100
  };

  quic_cfg.transport_params      = tp;

  strcpy( quic_cfg.cert_file, "cert.pem" );
  strcpy( quic_cfg.key_file, "key.pem"  );

  fd_quic_callbacks_t quic_cb = {
    .stream_receive = my_stream_receive_cb,
    .now     = test_clock,
    .now_ctx = NULL
  };

  fd_quic_host_cfg_t server_cfg = { "server_host", 0x0a000001u, 4434 };
  fd_quic_host_cfg_t client_cfg = { "client_host", 0xc01a1a1au, 2001 };

  quic_cfg.host_cfg = client_cfg;
  fd_quic_t * client_quic = new_quic( &quic_cfg );

  quic_cfg.host_cfg = server_cfg;
  fd_quic_t * server_quic = new_quic( &quic_cfg );

  /* make use aio to point quic directly at quic */
  fd_aio_t const * aio_n2q = fd_quic_get_aio_net_in( server_quic );
  fd_aio_t const * aio_q2n = fd_quic_get_aio_net_in( client_quic );

  fd_quic_set_aio_net_out( server_quic, aio_q2n );
  fd_quic_set_aio_net_out( client_quic, aio_n2q );

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

    fd_quic_service( client_quic );
    fd_quic_service( server_quic );
  }

  /* try sending */
  fd_quic_stream_t * client_stream = fd_quic_conn_new_stream( client_conn, FD_QUIC_TYPE_BIDIR );

  char buf[SEND_SZ] = "Hello world!\x00-   ";
  ulong buf_sz = sizeof( buf );
  fd_aio_pkt_info_t batch[1] = {{ buf, (ushort)buf_sz }};
  int rc = fd_quic_stream_send( client_stream, batch, 1, 0 );

  printf( "fd_quic_stream_send returned %d\n", rc );

  ulong tot     = 0;
  ulong last_ts = gettime();
  ulong rprt_ts = gettime() + (ulong)1e9;

  ulong start_ts = gettime();
  ulong end_ts   = start_ts + (ulong)10e9; /* ten seconds */
  while(1) {
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );

    rc = fd_quic_stream_send( client_stream, batch, 1, 0 );
    if( rc == 1 ) {
      tot += buf_sz;
    }

    ulong t = gettime();
    if( t >= rprt_ts ) {
      ulong dt = t - last_ts;
      float bps = (float)tot / (float)dt;
      printf( "bw: %f  dt: %f  bytes: %f\n", (double)bps, (double)dt, (double)tot );

      tot     = 0;
      last_ts = t;
      rprt_ts = t + (ulong)1e9;

      if( t > end_ts ) break;
    }
  }

  /* close the connections */
  fd_quic_conn_close( client_conn, 0 );
  fd_quic_conn_close( server_conn, 0 );

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

  fclose( pcap );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}


