#include "../fd_quic_test_helpers.h"

#include "../../fd_quic.h"
#include <stdlib.h>
#include <time.h>

int state           = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;


extern uchar pkt_full[];
extern ulong pkt_full_sz;

int done = 0;

void
my_stream_notify_cb( fd_quic_stream_t * stream, void * ctx, int type ) {
  (void)stream;
  (void)ctx;
  (void)type;
}

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

  FD_LOG_NOTICE(( "SERVER received data from peer. size: %lu offset: %lu\n",
                data_sz, offset ));
  FD_LOG_HEXDUMP_NOTICE(( "SERVER received data", data, data_sz ));

  char EXPECTED[] = "request";
  FD_TEST( data_sz >= strlen( EXPECTED ) && strcmp( (char*)data, EXPECTED ) == 0 );

  /* send back "received" */
  int               send_fin = 0UL; /* do not close stream */
  char              reply[]  = "received";
  fd_aio_pkt_info_t batch[1] = {{ .buf = reply, .buf_sz = sizeof( reply ) }};
  ulong             batch_sz = 1UL;

  int rc = fd_quic_stream_send( stream, batch, batch_sz, send_fin );
  if( rc != 1 ) {
    FD_LOG_WARNING(( "SERVER fd_quic_stream_send failed. rc: %d", rc ));
  }

  done = 1;
}


struct my_context {
  int server;
};
typedef struct my_context my_context_t;

void
my_cb_conn_final( fd_quic_conn_t * conn,
                  void *           context ) {
  (void)conn;
  (void)context;

  server_conn = NULL;
}

void
my_connection_new( fd_quic_conn_t * conn,
                   void *           vp_context ) {
  (void)vp_context;

  FD_LOG_NOTICE(( "SERVER server handshake complete" ));

  server_conn = conn;
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_NOTICE(( "SERVER handshake complete" ));
}

ulong test_clock( void * ctx ) {
  (void)ctx;

  struct timespec ts;
  clock_gettime( CLOCK_REALTIME, &ts );

  return (ulong)ts.tv_sec * (ulong)1e9 + (ulong)ts.tv_nsec;
}

int
main( int argc, char ** argv ) {
  fd_boot          ( &argc, &argv );
  fd_quic_test_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

#if 0
  fd_quic_limits_t quic_limits = {0};
  fd_quic_limits_from_env( &argc, &argv, &quic_limits);
#else
  fd_quic_limits_t const quic_limits = {
    .conn_cnt         = 10,
    .conn_id_cnt      = 10,
    .conn_id_sparsity = 4.0,
    .handshake_cnt    = 10,
    .stream_cnt       = { 2, 2, 2, 2 },
    .inflight_pkt_cnt = 1024,
    .tx_buf_sz        = 1<<14,
    .routing_entries  = 32,
    .arp_entries      = 32
  };
#endif

  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );

  FD_LOG_NOTICE(( "SERVER Creating server QUIC" ));
  fd_quic_t * server_quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_SERVER );
  FD_TEST( server_quic );

  server_quic->cb.conn_new       = my_connection_new;
  server_quic->cb.stream_receive = my_stream_receive_cb;
  server_quic->cb.stream_notify  = my_stream_notify_cb;
  server_quic->cb.conn_final     = my_cb_conn_final;

  server_quic->cb.now     = test_clock;
  server_quic->cb.now_ctx = NULL;

  server_quic->config.initial_rx_max_stream_data = 1<<14;

  fd_quic_udpsock_t _udpsock[1];
  fd_quic_udpsock_t * udpsock = fd_quic_udpsock_create( _udpsock, &argc, &argv, wksp, fd_quic_get_aio_net_rx( server_quic ) );
  FD_TEST( udpsock );

  fd_quic_config_t * server_config = &server_quic->config;
  FD_TEST( server_config );

  FD_TEST( server_config->role == FD_QUIC_ROLE_SERVER );

  server_config->retry = 0; /* set retry */

  /* set up an idle timeout */
  server_config->idle_timeout = 10e9;

  /* set network parameters */
  memcpy( server_config->link.src_mac_addr, udpsock->self_mac, 6UL );
  server_config->net.ip_addr         = udpsock->listen_ip;
  server_config->net.listen_udp_port = udpsock->listen_port;

  /* set aio */
  fd_quic_set_aio_net_tx( server_quic, udpsock->aio );

  FD_LOG_NOTICE(( "SERVER Initializing QUICs" ));
  FD_TEST( fd_quic_init( server_quic ) );

  /* runs for DURATION seconds */
  ulong DURATION = (ulong)10e9;
  ulong end_time = (ulong)test_clock(NULL) + (ulong)DURATION;

  while( !done ) {
    ulong now = (ulong)test_clock(NULL);
    if( now >= end_time ) break;

    fd_quic_service( server_quic );
    fd_quic_udpsock_service( udpsock );
  }

  /* now wait for client to close */
  while( server_conn ) {
    ulong now = (ulong)test_clock(NULL);
    if( now >= end_time ) break;

    fd_quic_service( server_quic );
    fd_quic_udpsock_service( udpsock );
  }

  FD_LOG_NOTICE(( "SERVER Cleaning up" ));
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini( server_quic ) ) ) );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "SERVER pass" ));
  fd_quic_test_halt();
  fd_halt();

  return 0;
}
