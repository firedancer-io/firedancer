#include "../fd_quic.h"

#include <stdio.h>
#include <stdlib.h>

#include "fd_pcap.h"
#include "test_helpers.c"

ulong
aio_cb( void *              context,
        fd_aio_pkt_info_t * batch,
        ulong               batch_sz ) {
  (void)context;

  FD_LOG_DEBUG(( "aio_cb callback" ));
  for( ulong j = 0; j < batch_sz; ++j ) {
    FD_LOG_DEBUG(( "batch %d", (int)j ));
    FD_LOG_HEXDUMP_DEBUG(( "batch data", batch[ j ].buf, batch[ j ].buf_sz ));
  }
  fd_log_flush();

  return batch_sz; /* consumed all */
}

uchar fail = 0;

void
my_stream_receive_cb( fd_quic_stream_t * stream,
                      void *             ctx,
                      uchar const *      data,
                      ulong              data_sz,
                      ulong              offset,
                      int                fin ) {
  (void)ctx;
  (void)stream;
  (void)fin;

  ulong expected_data_sz = 512ul;

  FD_LOG_INFO(( "received data from peer. size: %lu offset: %lu\n",
                data_sz, offset ));
  FD_LOG_HEXDUMP_DEBUG(( "received data", data, data_sz ));

  if( FD_UNLIKELY( data_sz!=512UL ) ) {
    FD_LOG_WARNING(( "data wrong size. Is: %lu, expected: %lu",
                     data_sz, expected_data_sz ));
    fail = 1;
    return;
  }

  if( FD_UNLIKELY( 0!=memcmp( data, "Hello world", 11u ) ) ) {
    FD_LOG_WARNING(( "value received incorrect" ));
    fail = 1;
    return;
  }

  FD_LOG_DEBUG(( "recv ok" ));
}

struct my_context {
  int server;
};
typedef struct my_context my_context_t;

int server_complete = 0;
int client_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;

void
my_connection_new( fd_quic_conn_t * conn,
                   void *           vp_context ) {
  (void)vp_context;

  FD_LOG_NOTICE(( "server handshake complete" ));
  fd_log_flush();

  server_complete = 1;
  server_conn = conn;
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_NOTICE(( "client handshake complete" ));
  fd_log_flush();

  client_complete = 1;
}


/* pcap aio pipe */
struct aio_pipe {
  fd_aio_t const * aio;
  FILE *           file;
  char *           recv_name;
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
  char thread_name[ 32UL ]={0};
  strncpy( thread_name, fd_log_thread(), 31UL );
  fd_log_thread_set( pipe->recv_name );
  int rc = fd_aio_send( pipe->aio, batch, batch_sz, opt_batch_idx );
  fd_log_thread_set( thread_name );
  return rc;
}


/* global "clock" */
ulong now = 123;

ulong test_clock( void * ctx ) {
  (void)ctx;
  return now;
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_log_thread_set( "main" );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 2UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );
  char const * _pcap     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--pcap",      NULL, "test_quic_hs.pcapng"        );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_quic_limits_t const quic_limits = {
    .conn_cnt         = 10,
    .conn_id_cnt      = 10,
    .conn_id_sparsity = 4.0,
    .handshake_cnt    = 10,
    .stream_cnt       = 10,
    .inflight_pkt_cnt = 100,
    .tx_buf_sz        = 1<<20,
    .rx_buf_sz        = 1<<20
  };

  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );
  FD_LOG_NOTICE(( "QUIC footprint: %lu bytes", quic_footprint ));

  FD_LOG_NOTICE(( "Creating server QUIC" ));
  fd_quic_t * server_quic = fd_quic_new(
      fd_wksp_alloc_laddr( wksp, fd_quic_align(), fd_quic_footprint( &quic_limits ), 1UL ),
      &quic_limits );
  FD_TEST( server_quic );

  FD_LOG_NOTICE(( "Creating client QUIC" ));
  fd_quic_t * client_quic = fd_quic_new(
      fd_wksp_alloc_laddr( wksp, fd_quic_align(), fd_quic_footprint( &quic_limits ), 1UL ),
      &quic_limits );
  FD_TEST( client_quic );

  FD_LOG_NOTICE(( "Writing to pcap: %s", _pcap ));
  FILE * pcap = fopen( _pcap, "wb" );
  FD_TEST( pcap );

  write_shb( pcap );
  write_idb( pcap );

  init_quic( server_quic, "server_host", 0x0a000001u, 4434 );
  init_quic( client_quic, "client_host", 0xc01a1a1au, 2001 );

  server_quic->config.role = FD_QUIC_ROLE_SERVER;
  client_quic->config.role = FD_QUIC_ROLE_CLIENT;

  server_quic->join.cb.conn_new         = my_connection_new;
  client_quic->join.cb.conn_hs_complete = my_handshake_complete;

  /* make use aio to point quic directly at quic */
  fd_aio_t _aio[2];
  fd_aio_t const * aio_n2q = fd_quic_get_aio_net_rx( server_quic, &_aio[ 0 ] );
  fd_aio_t const * aio_q2n = fd_quic_get_aio_net_rx( client_quic, &_aio[ 1 ] );

#if 0
  fd_quic_set_aio_net_tx( server_quic, aio_q2n );
  fd_quic_set_aio_net_tx( client_quic, aio_n2q );
#else
  /* create a pipe for catching data as it passes thru */
  aio_pipe_t pipe[2] = { { aio_n2q, pcap, "server" }, { aio_q2n, pcap, "client" } };

  fd_aio_t * aio[2];
  uchar aio_mem[2][128] = {0};

  if( fd_aio_footprint() > sizeof( aio_mem[0] ) ) {
    FD_LOG_WARNING(( "aio footprint: %lu", fd_aio_footprint() ));
    FD_LOG_ERR(( "fd_aio_footprint returned value larger than reserved memory" ));
  }

  aio[0] = fd_aio_join( fd_aio_new( aio_mem[0], &pipe[0], pipe_aio_receive ) );
  aio[1] = fd_aio_join( fd_aio_new( aio_mem[1], &pipe[1], pipe_aio_receive ) );

  fd_quic_set_aio_net_tx( server_quic, aio[1] );
  fd_quic_set_aio_net_tx( client_quic, aio[0] );
#endif

  FD_LOG_NOTICE(( "Joining QUICs" ));
  fd_log_thread_set( "server" );
  FD_TEST( fd_quic_join( server_quic ) );
  fd_log_thread_set( "client" );
  FD_TEST( fd_quic_join( client_quic ) );
  fd_log_thread_set( "main" );

  /* make a connection from client to server */
  fd_log_thread_set( "client" );
  fd_quic_conn_t * client_conn = fd_quic_connect(
      client_quic,
      server_quic->config.net.ip_addr,
      server_quic->config.net.listen_udp_port,
      server_quic->config.sni );
  fd_log_thread_set( "main" );

  /* do general processing */
  for( ulong j = 0; j < 20; j++ ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      FD_LOG_INFO(( "client and server have no schedule" ));
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    FD_LOG_INFO(( "running services at %lu", next_wakeup ));
    fd_log_thread_set( "client" );
    fd_quic_service( client_quic );
    fd_log_thread_set( "server" );
    fd_quic_service( server_quic );
    fd_log_thread_set( "main" );

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "***** both handshakes complete *****" ));
      break;
    }
  }

  for( ulong j = 0; j < 20; j++ ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      FD_LOG_INFO(( "client and server have no schedule" ));
      break;
    }

    now = next_wakeup;

    fd_log_thread_set( "client" );
    fd_quic_service( client_quic );
    fd_log_thread_set( "server" );
    fd_quic_service( server_quic );
    fd_log_thread_set( "main" );
  }

  /* TODO we get callback before the call to fd_quic_conn_new_stream can complete
     must delay until the conn->state is ACTIVE */

  /* try sending */
  fd_log_thread_set( "client" );
  fd_quic_stream_t * client_stream = fd_quic_conn_new_stream( client_conn, FD_QUIC_TYPE_UNIDIR );
  fd_log_thread_set( "main" );
  FD_TEST( client_stream );

  fd_log_thread_set( "client" );
  fd_quic_stream_t * client_stream_0 = fd_quic_conn_new_stream( client_conn, FD_QUIC_TYPE_UNIDIR );
  fd_log_thread_set( "main" );
  FD_TEST( client_stream_0 );

  char buf[512] = "Hello world!\x00-   ";
  fd_aio_pkt_info_t batch[1] = {{ buf, sizeof( buf ) }};
  fd_log_thread_set( "client" );
  int rc = fd_quic_stream_send( client_stream, batch, 1, 0 );
  fd_log_thread_set( "main" );

  FD_LOG_INFO(( "fd_quic_stream_send returned %d", rc ));

  for( unsigned j = 0; j < 16; ++j ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      FD_LOG_INFO(( "client and server have no schedule" ));
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    FD_LOG_INFO(( "running services at %lu", (ulong)next_wakeup ));
    fd_log_flush();

    fd_log_thread_set( "client" );
    fd_quic_service( client_quic );
    fd_log_thread_set( "server" );
    fd_quic_service( server_quic );
    fd_log_thread_set( "main" );

    buf[12] = ' ';
    //buf[15] = (char)( ( j / 10 ) + '0' );
    buf[16] = (char)( ( j % 10 ) + '0' );
    int rc = 0;
    fd_log_thread_set( "client" );
    if( j&1 ) {
      rc = fd_quic_stream_send( client_stream, batch, 1, 0 );
    } else {
      rc = fd_quic_stream_send( client_stream_0, batch, 1, 0 );
    }
    fd_log_thread_set( "main" );

    FD_LOG_INFO(( "fd_quic_stream_send returned %d", rc ));
  }

  /* allow acks to go */
  for( uint j=0; j<10U; ++j ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      /* indicates no schedule, which is correct after connection
         instances have been reclaimed */
      FD_LOG_INFO(( "Finished cleaning up connections" ));
      break;
    }

    if( next_wakeup > now ) now = next_wakeup;

    FD_LOG_INFO(( "running services at %lu", next_wakeup ));
    fd_log_thread_set( "client" );
    fd_quic_service( client_quic );
    fd_log_thread_set( "server" );
    fd_quic_service( server_quic );
    fd_log_thread_set( "main" );
  }

  fclose( pcap );

  FD_LOG_NOTICE(( "Cleaning up" ));
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( server_quic ) ) );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( client_quic ) ) );
  fd_wksp_delete_anonymous( wksp );

  if( fail ) FD_LOG_ERR(( "fail" ));
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

