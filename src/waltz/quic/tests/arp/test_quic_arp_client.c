#include "../fd_quic_test_helpers.h"

#include "../../fd_quic.h"
#include "../../../../util/fibre/fd_fibre.h"
#include "../../../../util/net/fd_ip4.h"
#include <stdlib.h>
#include <time.h>


/* clocks */
ulong test_clock( void * ctx ) {
  (void)ctx;

  struct timespec ts;
  clock_gettime( CLOCK_REALTIME, &ts );

  return (ulong)ts.tv_sec * (ulong)1e9 + (ulong)ts.tv_nsec;
}

long
test_fibre_clock(void) {
  return (long)test_clock(NULL);;
}

int done            = 0;
int state           = 0;
int client_complete = 0;
int handshake       = 0;
int received        = 0;

fd_quic_t *         client_quic = NULL;
fd_quic_udpsock_t * udpsock     = NULL;

/* client connection and stream */
fd_quic_conn_t *   client_conn   = NULL;
fd_quic_stream_t * client_stream = NULL;

/* fibres */
fd_fibre_t * service_fibre = NULL;
fd_fibre_t * send_fibre    = NULL;


void
service_fibre_main( void * vp_args ) {
  (void)vp_args;
  while( !done ) {
    fd_fibre_yield();
    if( client_quic ) fd_quic_service( client_quic );
    if( udpsock )     fd_quic_udpsock_service( udpsock );
  }
}

struct send_fibre_args {
  uint   server_ip;
  ushort server_port;
  ulong  end_time;
};
typedef struct send_fibre_args send_fibre_args_t;

void
send_fibre_main( void * vp_args ) {
  send_fibre_args_t * args = (send_fibre_args_t*)vp_args;

  ulong now            = test_clock(NULL);
  ulong next_send_time = now;
  ulong end_time       = args->end_time;

  while( !done && !received ) {
    FD_TEST( client_quic );

    now = test_clock(NULL);
    if( now < next_send_time ) {
      fd_fibre_wait_until( (long)next_send_time );
      continue;
    }

    FD_TEST( now < end_time );

    if( !client_conn ) {
      FD_LOG_NOTICE(( "CLIENT No connection: connecting and waiting" ));

      /* create a connection and wait for connected */
      char const * sni = "test_quic_arp"; /* TODO what's this used for */
      client_conn = fd_quic_connect( client_quic, args->server_ip, args->server_port, sni );
      FD_TEST( client_conn );

      /* wait for connection handshake to complete */
      while( client_conn && client_conn->state != FD_QUIC_CONN_STATE_ACTIVE ) {
        ulong now = (ulong)test_clock(NULL);
        FD_TEST( now < end_time );

        fd_fibre_yield();
      }

      FD_TEST( client_conn );
      FD_TEST( client_conn->state == FD_QUIC_CONN_STATE_ACTIVE );

      FD_LOG_NOTICE(( "CLIENT Connected" ));
    }

    if( !client_stream ) {
      client_stream = fd_quic_conn_new_stream( client_conn, FD_QUIC_TYPE_BIDIR );
      FD_TEST( client_stream );
      fd_fibre_yield();
      continue;
    }

    /* attempt to send to server */
    int               fin       = 0;
    char              request[] = "request";
    fd_aio_pkt_info_t batch[1]  = {{ .buf = request, .buf_sz = sizeof( request ) }};
    ulong             batch_sz  = 1UL;

    int rc = fd_quic_stream_send( client_stream, batch, batch_sz, fin );

    FD_LOG_WARNING(( "CLIENT fd_quic_stream_send returned %d", rc ));

    FD_TEST( rc == 1 );

    ulong DURATION = (ulong)100e6;
    next_send_time = now + DURATION;
  }

  FD_TEST( received );

  FD_LOG_NOTICE(( "CLIENT Received successfully. Closing" ));

  /* we've passed at this point, but try to close cleanly */
  if( client_conn ) {
    fd_quic_conn_close( client_conn, 0 );

    while( client_conn ) {
      ulong now = test_clock(NULL);
      if( now > end_time ) break;

      fd_fibre_yield();
    }

    done = 1;
  }
}


uchar fail = 0;

void
my_stream_notify_cb( fd_quic_stream_t * stream, void * ctx, int type ) {
  (void)stream;
  (void)ctx;
  (void)type;
  client_stream = NULL;
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

  /* We received data on a stream. Verify */
  char EXPECTED[] = "received";
  FD_TEST( data_sz >= strlen( EXPECTED ) && strcmp( EXPECTED, (char*)data ) == 0 );

  received = 1;

  FD_LOG_NOTICE(( "CLIENT received data from peer. size: %lu offset: %lu\n",
                data_sz, offset ));
  FD_LOG_HEXDUMP_NOTICE(( "CLIENT received data", data, data_sz ));

}


struct my_context {
  int client;
};
typedef struct my_context my_context_t;

void
my_cb_conn_final( fd_quic_conn_t * conn,
                  void *           context ) {
  (void)conn;
  (void)context;

  /* cannot refer to the connection anymore */
  FD_LOG_NOTICE(( "CLIENT Connection closed" ));
  client_conn = NULL;
}

void
my_connection_new( fd_quic_conn_t * conn,
                   void *           vp_context ) {
  (void)conn;
  (void)vp_context;
  /* unused by clients */
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_NOTICE(( "CLIENT handshake complete" ));

  handshake = 1;
}

int
main( int argc, char ** argv ) {
  fd_boot          ( &argc, &argv );
  fd_quic_test_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz    = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",     NULL, "gigantic"                   );
  ulong        page_cnt    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",    NULL, 1UL                          );
  ulong        numa_idx    = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx",    NULL, fd_shmem_numa_idx( cpu_idx ) );
  char const * _server_ip  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--server-ip",   NULL, "0.0.0.0"                    );
  ushort       server_port = fd_env_strip_cmdline_ushort( &argc, &argv, "--server-port", NULL, 4242                         );

  uint server_ip = 0;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _server_ip, &server_ip ) ) ) FD_LOG_ERR(( "invalid --server-ip" ));

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
    .conn_cnt           = 10,
    .conn_id_cnt        = 10,
    .conn_id_sparsity   = 4.0,
    .handshake_cnt      = 10,
    .stream_cnt         = { 2, 2, 2, 2 },
    .initial_stream_cnt = { 2, 2, 2, 2 },
    .stream_pool_cnt    = 100,
    .inflight_pkt_cnt   = 1024,
    .tx_buf_sz          = 1<<14,
  };
#endif

  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );

  FD_LOG_NOTICE(( "CLIENT Creating client QUIC" ));
  client_quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_CLIENT, rng );
  FD_TEST( client_quic );

  client_quic->cb.conn_new       = my_connection_new;
  client_quic->cb.stream_receive = my_stream_receive_cb;
  client_quic->cb.stream_notify  = my_stream_notify_cb;
  client_quic->cb.conn_final     = my_cb_conn_final;

  client_quic->cb.now     = test_clock;
  client_quic->cb.now_ctx = NULL;

  fd_quic_udpsock_t _udpsock[1];
  udpsock = fd_quic_udpsock_create( _udpsock, &argc, &argv, wksp, fd_quic_get_aio_net_rx( client_quic ) );
  FD_TEST( udpsock );

  fd_quic_config_t * client_config = &client_quic->config;
  FD_TEST( client_config );

  FD_TEST( client_config->role == FD_QUIC_ROLE_CLIENT );

  client_config->retry = 0; /* set retry */

  /* set up an idle timeout */
  client_config->idle_timeout = 10e9;

  /* set network parameters */
  memcpy( client_config->link.src_mac_addr, udpsock->self_mac, 6UL );
  client_config->net.ip_addr                = udpsock->listen_ip;
  client_config->net.listen_udp_port        = udpsock->listen_port;
  client_config->initial_rx_max_stream_data = 1<<14;
  client_config->net.ephem_udp_port.lo      = udpsock->listen_port;
  client_config->net.ephem_udp_port.hi      = udpsock->listen_port;

  /* set aio */
  fd_quic_set_aio_net_tx( client_quic, udpsock->aio );

  FD_LOG_NOTICE(( "CLIENT Initializing QUICs" ));
  FD_TEST( fd_quic_init( client_quic ) );

  /* runs for DURATION seconds */
  ulong DURATION = (ulong)60e9;
  ulong end_time = (ulong)test_clock(NULL) + (ulong)DURATION;

  /* initialize fibres */
  void * this_fibre_mem = fd_wksp_alloc_laddr( wksp, fd_fibre_init_align(), fd_fibre_init_footprint( ), 1UL );

  /* the currently executing context becomes the first fibre */
  fd_fibre_t * this_fibre = fd_fibre_init( this_fibre_mem ); (void)this_fibre;

  /* set fibre scheduler clock */
  fd_fibre_set_clock( test_fibre_clock );

  /* create fibre for service */
  ulong stack_sz = 1<<20;
  void * service_fibre_mem = fd_wksp_alloc_laddr( wksp, fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ), 1UL );
  service_fibre = fd_fibre_start( service_fibre_mem, stack_sz, service_fibre_main, NULL );
  FD_TEST( service_fibre );

  /* start send fibre */
  send_fibre_args_t send_fibre_args[1] = {{ .server_ip   = server_ip,
                                            .server_port = server_port,
                                            .end_time    = end_time }};
  void * send_fibre_mem = fd_wksp_alloc_laddr( wksp, fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ), 1UL );
  send_fibre = fd_fibre_start( send_fibre_mem, stack_sz, send_fibre_main, send_fibre_args );
  FD_TEST( send_fibre );

  /* schedule the service and send fibres */
  fd_fibre_schedule( service_fibre );
  fd_fibre_schedule( send_fibre );

  /* run the fibres */
  while(1) {
    long timeout = fd_fibre_schedule_run();

    /* occurs when the schedule is empty */
    if( timeout < 0 ) break;
  }

  FD_LOG_NOTICE(( "CLIENT Cleaning up" ));
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini( client_quic ) ) ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "CLIENT pass" ));
  fd_quic_test_halt();
  fd_halt();

  return 0;
}
