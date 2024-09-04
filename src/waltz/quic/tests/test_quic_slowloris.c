#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"
#include "../../../util/rng/fd_rng.h"
#include "../../../util/net/fd_pcapng.h"

#include "../../../util/fibre/fd_fibre.h"

#include <stdlib.h>

/* number of streams to send/receive */
#define NUM_CONNS 20

#ifndef FD_DEBUG
#  define FD_DEBUG(...)
#endif

#ifndef TEST_PCAP
#  define TEST_PCAP 0
#endif

/* done flags */

int running = 1;

/* some randomness stuff */

typedef float rng_t;

/* fibres for client and server */

fd_fibre_t * client_fibre  = NULL;
fd_fibre_t * server_fibre  = NULL;

/* "net" fibre for pcapping etc */

fd_fibre_t * net_fibre = NULL;

struct net_fibre_args {
  fd_fibre_pipe_t * input;
  fd_fibre_pipe_t * release;
  int               dir; /* 0=client->server  1=server->client */
};
typedef struct net_fibre_args net_fibre_args_t;


/* global "clock" */
ulong now = (ulong)1e18;

ulong test_clock( void * ctx ) {
  (void)ctx;
  return now;
}

long
test_fibre_clock(void) {
  return (long)now;
}


/* man-in-the-middle for pcap etc */

struct mitm_ctx {
  fd_aio_t         local;
  fd_aio_t const * dst;
  fd_aio_t const * pcap;
  int              server;
};
typedef struct mitm_ctx mitm_ctx_t;

static int
mitm_tx( void *                    ctx,
         fd_aio_pkt_info_t const * batch,
         ulong                     batch_cnt,
         ulong *                   opt_batch_idx,
         int                       flush ) {
  (void)flush;
  (void)opt_batch_idx;

  mitm_ctx_t * mitm_ctx = (mitm_ctx_t*)ctx;

  /* each time data transfers, the schedule might change
     so wake the other fibre */
  if( client_fibre &&  mitm_ctx->server ) fd_fibre_wake( client_fibre );
  if( server_fibre && !mitm_ctx->server ) fd_fibre_wake( server_fibre );

  /* write to pcap */
#define PCAP( batch, batch_cnt ) \
  if( mitm_ctx->pcap ) { \
    fd_aio_send( mitm_ctx->pcap, (batch), (batch_cnt), NULL, 1 ); \
  }

  /* go packet by packet */
  for( ulong j = 0UL; j < batch_cnt; ++j ) {
    /* send new packet */
    fd_aio_pkt_info_t batch_0[1] = { batch[j] };
    fd_aio_send( mitm_ctx->dst, batch_0, 1UL, NULL, 1 );

#if TEST_PCAP
    PCAP(batch_0,1UL);
#endif
  }

  return FD_AIO_SUCCESS;
}

static void
mitm_link( fd_quic_t * quic_a, fd_quic_t * quic_b, mitm_ctx_t * mitm, fd_aio_t const * pcap ) {
  fd_aio_t const * rx_b = fd_quic_get_aio_net_rx( quic_b );

  /* create a new aio for mitm */

  FD_TEST( fd_aio_join( fd_aio_new( &mitm->local, mitm, mitm_tx ) ) );

  mitm->dst  = rx_b;
  mitm->pcap = pcap;

  fd_quic_set_aio_net_tx( quic_a, &mitm->local );
}

static void
mitm_set_server( mitm_ctx_t * mitm_ctx, int server ) {
  mitm_ctx->server = server;
}


fd_aio_pcapng_t pcap_client_to_server;
fd_aio_pcapng_t pcap_server_to_client;

static void
my_tls_keylog( void *       quic_ctx,
               char const * line ) {
  (void)quic_ctx;
  (void)line;

#if TEST_PCAP
  FD_DEBUG(
    FD_LOG_NOTICE(( "SECRET: %s", line ));
    fd_pcapng_fwrite_tls_key_log( (uchar const *)line, (uint)strlen( line ), pcap_server_to_client.pcapng );
    )
#endif
}


int state           = 0;

extern uchar pkt_full[];
extern ulong pkt_full_sz;

uchar fail = 0;

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
  (void)data;
  (void)data_sz;
  (void)offset;
  (void)fin;
}


struct my_context {
  int server;
};
typedef struct my_context my_context_t;

long client_conn_cnt   = 0; /* concurrent number of client connections */
long server_conn_cnt   = 0; /* concurrent number of server connections */
long tot_client_opened = 0; /* total number of client connections opened */
long tot_client_closed = 0; /* total number of client connections closed */

void
my_cb_conn_final( fd_quic_conn_t * conn,
                  void *           context ) {
  (void)context;

  fd_quic_conn_t ** ppconn = (fd_quic_conn_t**)fd_quic_conn_get_context( conn );
  if( ppconn ) {
    if( (*ppconn)->server ) {
      server_conn_cnt--; /* reduce number of running server connectrions */
    } else {
      client_conn_cnt--; /* reduce number of running client connectrions */
      tot_client_closed++;
    }

    FD_DEBUG( FD_LOG_NOTICE(( "my_cb_conn_final %p SUCCESS", (void*)*ppconn )); )
    *ppconn = NULL;
  }
}

void
my_connection_new( fd_quic_conn_t * conn,
                   void *           vp_context ) {
  (void)vp_context;

  //FD_LOG_NOTICE(( "server handshake complete" ));

  server_conn_cnt++;

  (void)conn;
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)vp_context;

  //FD_LOG_NOTICE(( "client handshake complete" ));

  /* only increment tot_client_opened when handshake complete */
  tot_client_opened++;

  (void)conn;
}


struct client_args {
  fd_quic_t * client_quic;
  fd_quic_t * server_quic;
};
typedef struct client_args client_args_t;

void
client_fibre_fn( void * vp_arg ) {
  client_args_t * args = (client_args_t*)vp_arg;

  fd_quic_t * client_quic = args->client_quic;
  fd_quic_t * server_quic = args->server_quic;

  fd_quic_conn_t ** conns = (fd_quic_conn_t**)malloc( NUM_CONNS * sizeof(*conns) );
  memset( conns, 0, NUM_CONNS * sizeof(*conns) );

  ulong period_ns = (ulong)1e6;

  ulong ping_time = now;
  while( running ) {
    ulong next_wakeup = fd_quic_get_next_wakeup( client_quic );
    next_wakeup = fd_ulong_min( next_wakeup, now + period_ns );
    next_wakeup = fd_ulong_max( next_wakeup, now + (ulong)50e3 );

    /* wake up at either next service or next send, whichever is sooner */
    fd_fibre_wait_until( (long)next_wakeup );

    if( tot_client_opened > 1000 ) {
      running = 0;
      break;
    }

    do {
      fd_quic_service( client_quic );
      next_wakeup = fd_quic_get_next_wakeup( client_quic );

    } while( running && next_wakeup <= now );

    ulong conn_idx = -1UL;
    for( ulong j = 0UL; j < NUM_CONNS; ++j ) {
      if( !conns[j] ) {
        conn_idx = j;
      } else {
        /* keep alive */
        if( now > ping_time ) {
          fd_quic_conn_send_ping( conns[j] );
          ping_time = now + (ulong)50e6;
        }
      }
    }

    if( conn_idx != -0UL ) {
      fd_quic_conn_t * conn = fd_quic_connect( client_quic,
                                          server_quic->config.net.ip_addr,
                                          server_quic->config.net.listen_udp_port,
                                          server_quic->config.sni );

      if( conn ) {
        client_conn_cnt++;

        conns[conn_idx] = conn;
        fd_quic_conn_set_context( conn, &conns[conn_idx] );

        FD_DEBUG( FD_LOG_NOTICE(( "client_conn_cnt: %lu  server_conn_cnt: %lu",
            client_conn_cnt, server_conn_cnt )); )
      }
    }

  }

  free( conns );
}


struct server_args {
  fd_quic_t * quic;
};
typedef struct server_args server_args_t;


void
server_fibre_fn( void * vp_arg ) {
  server_args_t * args = (server_args_t*)vp_arg;

  fd_quic_t * quic = args->quic;

  /* wake up at least every 1ms */
  ulong period_ns = (ulong)1e6;
  while( running ) {
    ulong next_wakeup = fd_quic_get_next_wakeup( quic );
    next_wakeup = fd_ulong_min( next_wakeup, now + period_ns );
    next_wakeup = fd_ulong_max( next_wakeup, now + (ulong)50e3 );

    fd_fibre_wait_until( (long)next_wakeup );

    fd_quic_service( quic );
  }
}


int
main( int argc, char ** argv ) {

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

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                  page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_quic_limits_t const client_limits = {
    .conn_cnt           = 20,
    .conn_id_cnt        = 10,
    .conn_id_sparsity   = 4.0,
    .handshake_cnt      = 10,
    .stream_cnt         = { 0, 0, 16, 0 },
    .initial_stream_cnt = { 0, 0, 16, 0 },
    .stream_pool_cnt    = 512,
    .inflight_pkt_cnt   = 1024,
    .tx_buf_sz          = 1<<14
  };

  fd_quic_limits_t const server_limits = {
    .conn_cnt           = 10,
    .conn_id_cnt        = 10,
    .conn_id_sparsity   = 4.0,
    .handshake_cnt      = 10,
    .stream_cnt         = { 0, 0, 10, 0 },
    .initial_stream_cnt = { 0, 0, 10, 0 },
    .stream_pool_cnt    = 512,
    .inflight_pkt_cnt   = 1024,
    .tx_buf_sz          = 1<<14
  };

  ulong server_footprint = fd_quic_footprint( &server_limits );
  FD_TEST( server_footprint );
  FD_LOG_NOTICE(( "QUIC footprint: %lu bytes", server_footprint ));

  FD_LOG_NOTICE(( "Creating server QUIC" ));
  fd_quic_t * server_quic = fd_quic_new_anonymous( wksp, &server_limits, FD_QUIC_ROLE_SERVER, rng );
  FD_TEST( server_quic );

  ulong client_footprint = fd_quic_footprint( &client_limits );
  FD_TEST( client_footprint );
  FD_LOG_NOTICE(( "Creating client QUIC" ));
  fd_quic_t * client_quic = fd_quic_new_anonymous( wksp, &client_limits, FD_QUIC_ROLE_CLIENT, rng );
  FD_TEST( client_quic );

  fd_quic_config_t * client_config = &client_quic->config;
  client_config->idle_timeout = 100e6;
  client_config->service_interval = 1e6;

  client_quic->cb.conn_hs_complete = my_handshake_complete;
  client_quic->cb.stream_receive   = my_stream_receive_cb;
  client_quic->cb.stream_notify    = my_stream_notify_cb;
  client_quic->cb.conn_final       = my_cb_conn_final;

  client_quic->cb.now     = test_clock;
  client_quic->cb.now_ctx = NULL;

  client_quic->config.initial_rx_max_stream_data = 1<<15;

  fd_quic_config_t * server_config = &server_quic->config;
  server_config->idle_timeout = 100e6;
  server_config->service_interval = 1e6;

  server_quic->cb.conn_new       = my_connection_new;
  server_quic->cb.stream_receive = my_stream_receive_cb;
  server_quic->cb.stream_notify  = my_stream_notify_cb;
  server_quic->cb.conn_final     = my_cb_conn_final;
  server_quic->cb.tls_keylog     = my_tls_keylog;

  server_quic->cb.now     = test_clock;
  server_quic->cb.now_ctx = NULL;

  server_quic->config.initial_rx_max_stream_data = 1<<15;

#if TEST_PCAP
  /* pcap */
  FILE * pcap_file = fopen( "test_quic_slowloris.pcapng", "wb" );
  FD_TEST( pcap_file );
  printf( "pcap_file: %p\n", (void*)pcap_file ); fflush( stdout );

  FD_TEST( 1UL == fd_aio_pcapng_start( pcap_file ) );
  fflush( pcap_file );
#else
  FILE * pcap_file  = NULL;
#endif

  FD_TEST( fd_aio_pcapng_join( &pcap_client_to_server, NULL, pcap_file ) );
  FD_TEST( fd_aio_pcapng_join( &pcap_server_to_client, NULL, pcap_file ) );

  FD_LOG_NOTICE(( "Attaching AIOs" ));
  mitm_ctx_t mitm_client_to_server;
  mitm_ctx_t mitm_server_to_client;

  mitm_link( client_quic, server_quic, &mitm_client_to_server, fd_aio_pcapng_get_aio( &pcap_client_to_server ) );
  mitm_link( server_quic, client_quic, &mitm_server_to_client, fd_aio_pcapng_get_aio( &pcap_server_to_client ) );

  mitm_set_server( &mitm_client_to_server, 0 );
  mitm_set_server( &mitm_server_to_client, 1 );

  FD_LOG_NOTICE(( "Initializing QUICs" ));
  FD_TEST( fd_quic_init( client_quic ) );
  FD_TEST( fd_quic_init( server_quic ) );

  /* initialize fibres */
  void * this_fibre_mem = fd_wksp_alloc_laddr( wksp, fd_fibre_init_align(), fd_fibre_init_footprint( ), 1UL );
  fd_fibre_t * this_fibre = fd_fibre_init( this_fibre_mem ); (void)this_fibre;

  /* set fibre scheduler clock */
  fd_fibre_set_clock( test_fibre_clock );

  /* create fibres for client and server */
  ulong stack_sz = 1<<20;
  void * client_mem = fd_wksp_alloc_laddr( wksp, fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ), 1UL );
  client_args_t client_args[1] = {{ .client_quic = client_quic, .server_quic = server_quic }};
  client_fibre = fd_fibre_start( client_mem, stack_sz, client_fibre_fn, client_args );
  FD_TEST( client_fibre );

  void * server_mem = fd_wksp_alloc_laddr( wksp, fd_fibre_start_align(), fd_fibre_start_footprint( stack_sz ), 1UL );
  server_args_t server_args[1] = {{ .quic = server_quic }};
  server_fibre = fd_fibre_start( server_mem, stack_sz, server_fibre_fn, server_args );
  FD_TEST( server_fibre );

  /* schedule the fibres
     they will execute during the call to fibre_schedule_run */
  fd_fibre_schedule( client_fibre );
  fd_fibre_schedule( server_fibre );

  /* run the fibres until done */
  while(1) {
    long timeout = fd_fibre_schedule_run();
    if( timeout < 0 ) break;

    now = (ulong)timeout;
  }

  FD_TEST( fd_aio_pcapng_leave( &pcap_client_to_server ) );
  FD_TEST( fd_aio_pcapng_leave( &pcap_server_to_client ) );

  FD_LOG_NOTICE(( "tot_client_opened: %lu  tot_client_closed: %lu",
      tot_client_opened, tot_client_closed ));

  FD_LOG_NOTICE(( "Cleaning up" ));
  //fd_quic_virtual_pair_fini( &vp );
  // TODO clean up mitm_ctx and aio
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( server_quic ) ) );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( client_quic ) ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_quic_test_halt();
  fd_halt();
  return 0;
}
