#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"
#include "../../../util/rng/fd_rng.h"
#include "../../../util/net/fd_pcapng.h"

#include "../../../util/fibre/fd_fibre.h"

#include <stdlib.h>

/* number of streams to send/receive */
#define NUM_STREAMS 1000

/* done flags */

int client_done = 0;
int server_done = 0;

/* received count */
ulong rcvd     = 0;
ulong tot_rcvd = 0;

/* some randomness stuff */

typedef float rng_t;

rng_t rnd( void ) {
  static uint seed = 0;

  ulong l = fd_rng_private_expand( seed++ );
  return (rng_t)l * (rng_t)0x1p-64;
}

/* fibres for client and server */

fd_fibre_t * client_fibre = NULL;
fd_fibre_t * server_fibre = NULL;

/* "net" fibre for dropping and pcapping */

fd_fibre_t * net_fibre = NULL;

struct net_fibre_args {
  fd_fibre_pipe_t * input;
  fd_fibre_pipe_t * release;
  float             thresh;
  int               dir; /* 0=client->server  1=server->client */
};
typedef struct net_fibre_args net_fibre_args_t;


/* man-in-the-middle for testing drops */

struct mitm_ctx {
  fd_aio_t         local;
  fd_aio_t const * dst;
  fd_aio_t const * pcap;
  rng_t            thresh_drop;
  rng_t            thresh_reorder;
  int              server;

  ulong reorder_sz;
  uchar reorder_buf[2048];
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
    /* generate a random number and compare with threshold, and either pass thru or drop */

    rng_t rnd_num = rnd();

    if( rnd_num < mitm_ctx->thresh_drop ) {
      /* dropping behaves as-if the send was successful */
      continue;
    }

    if( rnd_num < mitm_ctx->thresh_reorder ) {
      /* reorder */

      /* logic:
           if we already have a reordered buffer, delay it another packet
           else store the current packet into the reorder buffer */
      if( mitm_ctx->reorder_sz > 0UL ) {
        fd_aio_pkt_info_t lcl_batch[1] = { batch[j] };
        fd_aio_send( mitm_ctx->dst, lcl_batch, 1UL, NULL, 1 );
        PCAP(lcl_batch,1UL);

        /* clear buffer */
        mitm_ctx->reorder_sz = 0UL;
      } else {
        fd_memcpy( mitm_ctx->reorder_buf, batch[j].buf, batch[j].buf_sz );
        mitm_ctx->reorder_sz = batch[j].buf_sz;
      }
      continue;
    }
    
    /* send new packet */
    fd_aio_pkt_info_t batch_0[1] = { batch[j] };
    fd_aio_send( mitm_ctx->dst, batch_0, 1UL, NULL, 1 );
    PCAP(batch_0,1UL);
      
    /* we aren't dropping or reordering, but we might have a prior reorder */
    if( mitm_ctx->reorder_sz > 0UL ) {
      fd_aio_pkt_info_t batch_1[1] = {{ .buf = mitm_ctx->reorder_buf, .buf_sz = (ushort)mitm_ctx->reorder_sz }};
      fd_aio_send( mitm_ctx->dst, batch_1, 1UL, NULL, 1 );
      PCAP(batch_1,1UL);

      /* clear the sent buffer */
      mitm_ctx->reorder_sz = 0UL;
    }
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
mitm_set_thresh( mitm_ctx_t * mitm_ctx, rng_t thresh_drop, rng_t thresh_reorder ) {
  mitm_ctx->thresh_drop    = thresh_drop;
  mitm_ctx->thresh_reorder = thresh_reorder;
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
  FD_LOG_WARNING(( "SECRET: %s", line ));
  fd_pcapng_fwrite_tls_key_log( (uchar const *)line, (uint)strlen( line ), pcap_server_to_client.pcapng );
}


int state           = 0;
int server_complete = 0;
int client_complete = 0;

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
  (void)fin;

  FD_LOG_NOTICE(( "received data from peer.  stream_id: %lu  size: %lu offset: %lu\n",
                (ulong)stream->stream_id, data_sz, offset ));
  FD_LOG_HEXDUMP_DEBUG(( "received data", data, data_sz ));

  FD_LOG_DEBUG(( "recv ok" ));

  rcvd++;
  tot_rcvd++;

  if( tot_rcvd == NUM_STREAMS ) client_done = 1;
}


struct my_context {
  int server;
};
typedef struct my_context my_context_t;

void
my_cb_conn_final( fd_quic_conn_t * conn,
                  void *           context ) {
  (void)context;

  fd_quic_conn_t ** ppconn = (fd_quic_conn_t**)fd_quic_conn_get_context( conn );
  if( ppconn ) {
    FD_LOG_NOTICE(( "my_cb_conn_final %p SUCCESS", (void*)*ppconn ));
    *ppconn = NULL;
  }}

void
my_connection_new( fd_quic_conn_t * conn,
                   void *           vp_context ) {
  (void)vp_context;

  FD_LOG_NOTICE(( "server handshake complete" ));

  server_complete = 1;

  (void)conn;
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)vp_context;

  FD_LOG_NOTICE(( "client handshake complete" ));

  client_complete = 1;

  (void)conn;
}

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


struct client_args {
  fd_quic_t * quic;
  fd_quic_t * server_quic;
};
typedef struct client_args client_args_t;

void
client_fibre_fn( void * vp_arg ) {
  client_args_t * args = (client_args_t*)vp_arg;

  fd_quic_t * quic        = args->quic;
  fd_quic_t * server_quic = args->server_quic;

  fd_quic_conn_t *   conn   = NULL;
  fd_quic_stream_t * stream = NULL;

  uchar buf[] = "Hello World!";
  fd_aio_pkt_info_t batch[1] = {{ .buf = buf, .buf_sz = sizeof( buf ) }};

  ulong period_ns = (ulong)1e6;
  ulong next_send = now + period_ns;
  ulong sent      = 0;

  while( !client_done ) {
    ulong next_wakeup = fd_quic_get_next_wakeup( quic );

    /* wake up at either next service or next send, whichever is sooner */
    fd_fibre_wait_until( (long)fd_ulong_min( next_wakeup, next_send ) );

    fd_quic_service( quic );

    if( !conn ) {
      rcvd = sent = 0;

      conn = fd_quic_connect( quic,
              server_quic->config.net.ip_addr,
              server_quic->config.net.listen_udp_port,
              server_quic->config.sni );

      if( !conn ) {
        FD_LOG_WARNING(( "Client unable to obtain a connection. now: %lu", (ulong)now ));
        continue;
      }

      fd_quic_conn_set_context( conn, &conn );

      /* wait for connection handshake */
      while( conn && conn->state != FD_QUIC_CONN_STATE_ACTIVE ) {
        /* service client */
        fd_quic_service( quic );

        /* allow server to process */
        fd_fibre_wait_until( (long)fd_quic_get_next_wakeup( quic ) );
      }

      continue;
    }

    if( !stream ) {
      if( rcvd != sent ) {
        fd_quic_service( quic );
        fd_fibre_wait_until( (long)fd_quic_get_next_wakeup( quic ) );

        continue;
      }

      stream = fd_quic_conn_new_stream( conn, FD_QUIC_TYPE_UNIDIR );

      if( !stream ) {
        if( conn->state == FD_QUIC_CONN_STATE_ACTIVE ) {
          FD_LOG_WARNING(( "Client unable to obtain a stream. now: %lu", (ulong)now ));
          ulong live = next_wakeup + (ulong)1e9;
          do {
            next_wakeup = fd_quic_get_next_wakeup( quic );

            if( next_wakeup > live ) {
              live = next_wakeup + (ulong)next_wakeup;
              FD_LOG_WARNING(( "Client waiting for a stream time: %lu", (ulong)now ));
            }

            /* wake up at either next service or next send, whichever is sooner */
            fd_fibre_wait_until( (long)next_wakeup );

            fd_quic_service( quic );

            if( !conn ) break;

            stream = fd_quic_conn_new_stream( conn, FD_QUIC_TYPE_UNIDIR );
          } while( !stream );
          FD_LOG_WARNING(( "Client obtained a stream" ));
        }
        next_send = now + period_ns; /* ensure we make progress */
        continue;
      }
    }

    /* set next send time */
    next_send = now + period_ns;

    /* have a stream, so send */
    int rc = fd_quic_stream_send( stream, batch, 1 /* batch_sz */, 1 /* fin */ );

    if( rc == 1 ) {
      /* successful - stream will begin closing */

      if( ++sent % 15 == 0 ) {
        /* wait for last sends to complete */
        /* TODO add callback for this */
        ulong timeout = now + (ulong)3e6;
        while( now < timeout ) {
          fd_quic_service( quic );

          /* allow server to process */
          fd_fibre_wait_until( (long)fd_quic_get_next_wakeup( quic ) );
        }

        fd_quic_conn_close( conn, 0 );
        sent = 0;

        /* wait for connection to be reaped
           (it's set to NULL in final callback */
        while( conn ) {
          fd_quic_service( quic );

          /* allow server to process */
          fd_fibre_wait_until( (long)fd_quic_get_next_wakeup( quic ) );
        }

        stream = NULL;

        continue;
      }

      /* ensure new stream used for next send */
      stream = fd_quic_conn_new_stream( conn, FD_QUIC_TYPE_UNIDIR );

      /* TODO close logic */

    } else {
      FD_LOG_WARNING(( "send failed" ));
    }
  }

  if( conn ) {
    fd_quic_conn_close( conn, 0 );

    /* keep servicing until connection closed */
    while( conn ) {
      fd_quic_service( quic );
      fd_fibre_yield();
    }
  }

  /* tell the server to shutdown */
  server_done = 1;
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
  while( !server_done ) {
    fd_quic_service( quic );

    ulong next_wakeup = fd_quic_get_next_wakeup( quic );
    ulong next_period = now + period_ns;

    fd_fibre_wait_until( (long)fd_ulong_min( next_wakeup, next_period ) );
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

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_quic_limits_t const quic_limits = {
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

  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );
  FD_LOG_NOTICE(( "QUIC footprint: %lu bytes", quic_footprint ));

  FD_LOG_NOTICE(( "Creating server QUIC" ));
  fd_quic_t * server_quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_SERVER, rng );
  FD_TEST( server_quic );

  FD_LOG_NOTICE(( "Creating client QUIC" ));
  fd_quic_t * client_quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_CLIENT, rng );
  FD_TEST( client_quic );

  fd_quic_config_t * client_config = &client_quic->config;
  client_config->idle_timeout = 5e9;
  client_config->service_interval = 1e6;

  client_quic->cb.conn_hs_complete = my_handshake_complete;
  client_quic->cb.stream_receive   = my_stream_receive_cb;
  client_quic->cb.stream_notify    = my_stream_notify_cb;
  client_quic->cb.conn_final       = my_cb_conn_final;

  client_quic->cb.now     = test_clock;
  client_quic->cb.now_ctx = NULL;

  client_quic->config.initial_rx_max_stream_data = 1<<15;

  fd_quic_config_t * server_config = &server_quic->config;
  server_config->idle_timeout = 5e9;
  server_config->service_interval = 1e6;

  server_quic->cb.conn_new       = my_connection_new;
  server_quic->cb.stream_receive = my_stream_receive_cb;
  server_quic->cb.stream_notify  = my_stream_notify_cb;
  server_quic->cb.conn_final     = my_cb_conn_final;
  server_quic->cb.tls_keylog     = my_tls_keylog;

  server_quic->cb.now     = test_clock;
  server_quic->cb.now_ctx = NULL;

  server_quic->config.initial_rx_max_stream_data = 1<<15;

  /* pcap */
  FILE * pcap_file = fopen( "test_quic_drops.pcapng", "wb" );
  FD_TEST( pcap_file );
  printf( "pcap_file: %p\n", (void*)pcap_file ); fflush( stdout );

  FD_TEST( 1UL == fd_aio_pcapng_start( pcap_file ) );
  fflush( pcap_file );

  FD_TEST( fd_aio_pcapng_join( &pcap_client_to_server, NULL, pcap_file ) );
  FD_TEST( fd_aio_pcapng_join( &pcap_server_to_client, NULL, pcap_file ) );

  FD_LOG_NOTICE(( "Attaching AIOs" ));
  mitm_ctx_t mitm_client_to_server;
  mitm_ctx_t mitm_server_to_client;

  mitm_link( client_quic, server_quic, &mitm_client_to_server, fd_aio_pcapng_get_aio( &pcap_client_to_server ) );
  mitm_link( server_quic, client_quic, &mitm_server_to_client, fd_aio_pcapng_get_aio( &pcap_server_to_client ) );

  mitm_set_thresh( &mitm_client_to_server, 0.05f, 0.40f );
  mitm_set_thresh( &mitm_server_to_client, 0.05f, 0.40f );

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
  client_args_t client_args[1] = {{ .quic = client_quic, .server_quic = server_quic }};
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
