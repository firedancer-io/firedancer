#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"
#include "fd_quic_stream_spam.h"

ulong recvd = 0;

void
my_stream_receive_cb( fd_quic_stream_t * stream,
                      void *             ctx,
                      uchar const *      data,
                      ulong              data_sz,
                      ulong              offset,
                      int                fin ) {
  (void)ctx;
  (void)fin;

  /* Derive expected payload */

  uchar payload_buf[ 4096UL ];
  fd_aio_pkt_info_t pkt = { .buf=payload_buf, .buf_sz=4096UL };
  fd_quic_stream_spam_gen( NULL, &pkt, stream );

  FD_LOG_DEBUG(( "server rx stream data stream=%lu size=%lu offset=%lu",
        stream->stream_id, data_sz, offset ));

  if( FD_UNLIKELY( fin && offset+data_sz != pkt.buf_sz ) )
    FD_LOG_ERR(( "data wrong size. expected: %u, actual: %lu",
                 (uint)pkt.buf_sz, offset+data_sz ));

  if( FD_UNLIKELY( 0!=memcmp( data, (uchar *)pkt.buf + offset, data_sz ) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "FAIL: expected data", payload_buf + offset, data_sz ));
    FD_LOG_HEXDUMP_WARNING(( "FAIL: actual data",   data,                 data_sz    ));
    FD_LOG_ERR(( "received unexpected data" ));
  }

  recvd++;
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
  FD_LOG_DEBUG(( "server handshake complete" ));
  server_complete = 1;
  server_conn     = conn;
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)conn;
  (void)vp_context;
  FD_LOG_DEBUG(( "client handshake complete" ));
  client_complete = 1;
}


/* global "clock" */
ulong now = 123;

ulong test_clock( void * ctx ) {
  (void)ctx;
  return now;
}

int
main( int     argc,
      char ** argv ) {

  fd_boot          ( &argc, &argv );
  fd_quic_test_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 2UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  FD_LOG_NOTICE(( "Creating server QUIC" ));

  fd_quic_limits_t const quic_server_limits = {
    .conn_cnt           = 2,
    .conn_id_cnt        = 4,
    .conn_id_sparsity   = 4.0,
    .handshake_cnt      = 10,
    .stream_cnt         = { 20, 20, 20, 20 },
    .initial_stream_cnt = { 20, 20, 20, 20 },
    .inflight_pkt_cnt   = 100,
    .tx_buf_sz          = 1<<15,
    .stream_pool_cnt    = 512
  };
  fd_quic_t * server_quic = fd_quic_new_anonymous( wksp, &quic_server_limits, FD_QUIC_ROLE_SERVER, rng );
  FD_TEST( server_quic );

  FD_LOG_NOTICE(( "Creating client QUIC" ));

  fd_quic_limits_t const quic_client_limits = {
    .conn_cnt           = 2,
    .conn_id_cnt        = 4,
    .conn_id_sparsity   = 4.0,
    .handshake_cnt      = 10,
    .stream_cnt         = { 20, 20, 20, 20 },
    .initial_stream_cnt = { 20, 20, 20, 20 },
    .inflight_pkt_cnt   = 100,
    .tx_buf_sz          = 1<<15,
    .stream_pool_cnt    = 512
  };
  fd_quic_t * client_quic = fd_quic_new_anonymous( wksp, &quic_client_limits, FD_QUIC_ROLE_CLIENT, rng );
  FD_TEST( client_quic );

  server_quic->cb.now              = test_clock;
  server_quic->cb.conn_new         = my_connection_new;
  server_quic->cb.stream_receive   = my_stream_receive_cb;

  client_quic->cb.now              = test_clock;
  client_quic->cb.conn_hs_complete = my_handshake_complete;
  client_quic->cb.stream_notify    = fd_quic_stream_spam_notify;

  server_quic->config.initial_rx_max_stream_data = 1<<21;
  client_quic->config.initial_rx_max_stream_data = 1<<15;

  FD_LOG_NOTICE(( "Creating virtual pair" ));
  fd_quic_virtual_pair_t vp;
  fd_quic_virtual_pair_init( &vp, server_quic, client_quic );

  FD_LOG_NOTICE(( "Creating spammer" ));
  fd_quic_stream_spam_t * spammer =
  fd_quic_stream_spam_join( fd_quic_stream_spam_new(
    fd_wksp_alloc_laddr(
        wksp,
        fd_quic_stream_spam_align(),
        fd_quic_stream_spam_footprint( quic_client_limits.stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT ] ),
        1UL ),
      quic_client_limits.stream_cnt[ FD_QUIC_STREAM_TYPE_UNI_CLIENT ],
      fd_quic_stream_spam_gen,
      NULL ) );
  FD_TEST( spammer );

  FD_LOG_NOTICE(( "Initializing QUICs" ));
  FD_TEST( fd_quic_init( server_quic ) );
  FD_TEST( fd_quic_init( client_quic ) );

  FD_LOG_NOTICE(( "Creating connection" ));
  fd_quic_conn_t * client_conn = fd_quic_connect(
      client_quic,
      server_quic->config.net.ip_addr,
      server_quic->config.net.listen_udp_port,
      server_quic->config.sni );
  FD_TEST( client_conn );

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
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "***** both handshakes complete *****" ));
      break;
    }
  }

  FD_LOG_NOTICE(( "Running" ));

  long cum_sent_cnt = 0L;

  while( recvd < 10000 ) {
    long sent_cnt = fd_quic_stream_spam_service( client_conn, spammer );
    FD_TEST( sent_cnt >= 0 );
    cum_sent_cnt += sent_cnt;
    if( sent_cnt>0 ) FD_LOG_INFO(( "sent %ld streams (total %ld)", sent_cnt, cum_sent_cnt ));

    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      FD_LOG_INFO(( "client and server have no schedule" ));
      break;
    }

    if( next_wakeup > now ) {
      now = next_wakeup;
    } else {
      now += (ulong)10e6;
    }

    FD_LOG_DEBUG(( "running services at %lu", next_wakeup ));

    fd_quic_service( server_quic );
    fd_quic_service( client_quic );
  }

  FD_LOG_NOTICE(( "received: %lu", recvd ));

  FD_LOG_NOTICE(( "Closing connection" ));

  fd_quic_conn_close( client_conn, 0 );

  FD_LOG_NOTICE(( "Waiting for ACKs" ));

  for( unsigned j = 0; j < 10; ++j ) {
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
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );
  }

  FD_LOG_NOTICE(( "Cleaning up" ));
  fd_quic_virtual_pair_fini( &vp );
  fd_wksp_free_laddr( fd_quic_stream_spam_delete( fd_quic_stream_spam_delete( spammer ) ) );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini( server_quic ) ) ) );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini( client_quic ) ) ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_quic_test_halt();
  fd_halt();
  return 0;
}
