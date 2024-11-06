#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

uchar conn_final_cnt = 0;

ulong rx_tot_sz = 0;

static void
my_conn_final( fd_quic_conn_t * conn,
               void *           quic_ctx ) {
  (void)conn;
  (void)quic_ctx;
  conn_final_cnt++;
}

static void
my_stream_new_cb( fd_quic_stream_t * stream,
                  void *             quic_ctx ) {
  (void)stream; (void)quic_ctx;
}

static void
my_stream_notify_cb( fd_quic_stream_t * stream,
                     void *             stream_ctx,
                     int                notify_type ) {
  (void)stream; (void)stream_ctx; (void)notify_type;
}

static void
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

  rx_tot_sz += data_sz;
}

int server_complete = 0;
int client_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;

void my_connection_new( fd_quic_conn_t * conn,
                        void *           vp_context ) {
  (void)vp_context;

  FD_LOG_INFO(( "server handshake complete" ));

  server_complete = 1;
  server_conn = conn;
}

void my_handshake_complete( fd_quic_conn_t * conn,
                            void *           vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_INFO(( "client handshake complete" ));

  client_complete = 1;
}

/* Force client and server servicing to render separately in a flamegraph */

__attribute__((noinline)) int
service_client( fd_quic_t * quic ) {
  uchar buf[16] = {0}; FD_COMPILER_UNPREDICTABLE( buf[0] );
  fd_quic_service( quic );
  return 0;
}

__attribute__((noinline)) int
service_server( fd_quic_t * quic ) {
  uchar buf[16] = {0}; FD_COMPILER_UNPREDICTABLE( buf[0] );
  fd_quic_service( quic );
  return 0;
}

int
main( int     argc,
      char ** argv ) {

  fd_boot          ( &argc, &argv );
  fd_quic_test_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

# define FRAG_SZ (1163UL) /* Usable QUIC stream data space FIXME increase IPv4 MTU */

  char const * _page_sz = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",  NULL, 2UL                          );
  ulong        numa_idx = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );
  float        loss     = fd_env_strip_cmdline_float ( &argc, &argv, "--loss",      NULL, 0.0f                         );
  float        reorder  = fd_env_strip_cmdline_float ( &argc, &argv, "--reorder",   NULL, 0.0f                         );
  float        duration = fd_env_strip_cmdline_float ( &argc, &argv, "--duration",  NULL, 10.0f                        );
  ushort       sz       = fd_env_strip_cmdline_ushort( &argc, &argv, "--sz",        NULL, FRAG_SZ                      );
  FD_TEST( sz<=FRAG_SZ );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Tune QUIC client and server such that server ACKs just before
     client runs out of space. */
  ulong ack_threshold = 8192UL; //FD_QUIC_DEFAULT_ACK_THRESHOLD;
  ulong client_burst  = ack_threshold / sz + 1;

  fd_quic_limits_t const server_limits = {
    .conn_cnt           = 1,
    .conn_id_cnt        = 4,
    .handshake_cnt      = 1,
    .rx_stream_cnt      = 1,
    .stream_pool_cnt    = 1,
    .inflight_pkt_cnt   = 128,
  };
  FD_LOG_NOTICE(( "Creating server QUIC (%lu bytes)", fd_quic_footprint( &server_limits ) ));
  fd_quic_t * server_quic = fd_quic_new_anonymous( wksp, &server_limits, FD_QUIC_ROLE_SERVER, rng );
  FD_TEST( server_quic );

  fd_quic_limits_t const client_limits = {
    .conn_cnt           = 1,
    .conn_id_cnt        = 4,
    .handshake_cnt      = 1,
    .stream_id_cnt      = client_burst,
    .stream_pool_cnt    = client_burst,
    .inflight_pkt_cnt   = 1024,
    .tx_buf_sz          = FRAG_SZ
  };
  FD_LOG_NOTICE(( "Creating client QUIC (%lu bytes)", fd_quic_footprint( &client_limits ) ));
  fd_quic_t * client_quic = fd_quic_new_anonymous( wksp, &client_limits, FD_QUIC_ROLE_CLIENT, rng );
  FD_TEST( client_quic );

  server_quic->config.ack_threshold = ack_threshold;
  server_quic->config.role = FD_QUIC_ROLE_SERVER;
  client_quic->config.role = FD_QUIC_ROLE_CLIENT;

  server_quic->cb.conn_new         = my_connection_new;
  server_quic->cb.conn_final       = my_conn_final;
  server_quic->cb.stream_new       = my_stream_new_cb;
  server_quic->cb.stream_receive   = my_stream_receive_cb;
  server_quic->cb.stream_notify    = my_stream_notify_cb;

  client_quic->cb.conn_hs_complete = my_handshake_complete;
  client_quic->cb.conn_final       = my_conn_final;
  client_quic->cb.stream_notify    = my_stream_notify_cb;

  server_quic->config.initial_rx_max_stream_data = FRAG_SZ;

  FD_LOG_NOTICE(( "Creating virtual pair" ));
  fd_quic_virtual_pair_t vp;
  fd_quic_virtual_pair_init( &vp, /*a*/ client_quic, /*b*/ server_quic );

  fd_quic_netem_t _netem[1];
  fd_aio_t        netem_aio;
  if( loss>=FLT_EPSILON || reorder>=FLT_EPSILON ) {
    FD_LOG_NOTICE(( "Adding client network emulation (loss=%g reorder=%g)", (double)loss, (double)reorder ));
    fd_quic_netem_t * netem = fd_quic_netem_init( _netem, loss, reorder );
    /* Inject a netem instance along the path */
    netem_aio = client_quic->aio_tx;
    fd_quic_set_aio_net_tx( client_quic, &netem->local );
    netem->dst = &netem_aio;
  }

  FD_LOG_NOTICE(( "Initializing QUICs" ));
  FD_TEST( fd_quic_init( server_quic ) );
  FD_TEST( fd_quic_init( client_quic ) );

  /* make a connection from client to server */
  fd_quic_conn_t * client_conn = fd_quic_connect(
      client_quic,
      server_quic->config.net.ip_addr,
      server_quic->config.net.listen_udp_port,
      server_quic->config.sni );

  FD_TEST( conn_final_cnt==0 );

  /* do general processing */
  for( ulong j = 0; j < 20; j++ ) {
    FD_LOG_INFO(( "running services" ));
    service_client( client_quic );;
    service_server( server_quic );;

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "***** both handshakes complete *****" ));
      break;
    }
  }

  FD_LOG_DEBUG(( "client_conn->state: %u", client_conn->state ));

  for( ulong j = 0; j < 20; j++ ) {
    service_client( client_quic );;
    service_server( server_quic );;
  }

  FD_LOG_DEBUG(( "client_conn->state: %u", client_conn->state ));

  FD_TEST( client_conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  FD_TEST( conn_final_cnt==0 );

  /* try sending */
  fd_quic_stream_t * client_stream = fd_quic_conn_new_stream( client_conn );
  FD_TEST( client_stream );

  char buf[ FRAG_SZ ] = "Hello world!\x00-   ";
  int rc = fd_quic_stream_send( client_stream, buf, sz, 1 );
  FD_LOG_INFO(( "fd_quic_stream_send returned %d", rc ));

  long last_ts = fd_log_wallclock();
  long rprt_ts = fd_log_wallclock() + (long)1e9;

  long start_ts = fd_log_wallclock();
  long end_ts   = start_ts + (long)(duration * 1e9f);
  while(1) {
    service_client( client_quic );;
    service_server( server_quic );;

    client_stream = fd_quic_conn_new_stream( client_conn );
    if( !client_stream ) continue;
    fd_quic_stream_send( client_stream, buf, sz, 1 );

    long t = fd_log_wallclock();
    if( t >= rprt_ts ) {
      long  dt        = t - last_ts;
      float net_rx_gbps   = (float)(8UL*server_quic->metrics.net_rx_byte_cnt) / (float)dt;
      float net_rx_gpps   = (float)server_quic->metrics.net_rx_pkt_cnt        / (float)dt;
      float net_tx_gbps   = (float)(8UL*server_quic->metrics.net_tx_byte_cnt) / (float)dt;
      float net_tx_gpps   = (float)server_quic->metrics.net_tx_pkt_cnt        / (float)dt;
      float data_rate = (8 * (float)rx_tot_sz) / (float)dt;
      FD_LOG_NOTICE(( "data=%6.4g Gbps  net_rx=(%6.4g Gbps %6.4g Mpps)  net_tx=(%6.4g Gbps %6.4g Mpps)  bytes=%g",
                      (double)data_rate,
                      (double)net_rx_gbps, (double)net_rx_gpps * 1e3,
                      (double)net_tx_gbps, (double)net_tx_gpps * 1e3,
                      (double)rx_tot_sz ));
      server_quic->metrics.net_rx_byte_cnt = 0;
      server_quic->metrics.net_rx_pkt_cnt  = 0;
      server_quic->metrics.net_tx_byte_cnt = 0;
      server_quic->metrics.net_tx_pkt_cnt  = 0;

      rx_tot_sz = 0;
      last_ts   = t;
      rprt_ts   = t + (long)1e9;

      if( t > end_ts ) break;
    }
  }

  /* close the connections */
  fd_quic_conn_close( client_conn, 0 );
  fd_quic_conn_close( server_conn, 0 );

  FD_TEST( client_conn->state == FD_QUIC_CONN_STATE_CLOSE_PENDING );
  FD_TEST( server_conn->state == FD_QUIC_CONN_STATE_CLOSE_PENDING );

  /* allow acks to go */
  for( unsigned j = 0; j < 10; ++j ) {
    FD_LOG_INFO(( "running services" ));
    service_client( client_quic );;
    service_server( server_quic );;
  }

  FD_TEST( client_quic->metrics.conn_closed_cnt==1 );
  FD_TEST( server_quic->metrics.conn_closed_cnt==1 );
  FD_TEST( conn_final_cnt==2 );

  FD_LOG_NOTICE(( "Cleaning up" ));
  fd_quic_virtual_pair_fini( &vp );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini( server_quic ) ) ) );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini( client_quic ) ) ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
