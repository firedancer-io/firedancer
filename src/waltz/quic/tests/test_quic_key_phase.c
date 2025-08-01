#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"
#include "../../../util/fibre/fd_fibre.h"

#include <stdlib.h>

/* number of streams to send/receive between key phase changes */
#define NUM_STREAMS 1000

/* number of key phase changes to test */
#define NUM_KEY_PHASE_CHANGES 16

/* done flags */

static int client_done = 0;
static int server_done = 0;

/* received count */
static ulong rcvd                 = 0;
static ulong tot_rcvd             = 0;
static ulong tot_key_phase_change = 0;

/* some randomness stuff */

/* fibres for client and server */

static fd_fibre_t * client_fibre = NULL;
static fd_fibre_t * server_fibre = NULL;

static int server_complete = 0;
static int client_complete = 0;

int
my_stream_rx_cb( fd_quic_conn_t * conn,
                 ulong            stream_id,
                 ulong            offset,
                 uchar const *    data,
                 ulong            data_sz,
                 int              fin ) {
  (void)conn; (void)stream_id; (void)offset; (void)data; (void)data_sz; (void)fin;
  rcvd++;
  tot_rcvd++;
  return FD_QUIC_SUCCESS;
}


struct my_context {
  int server;
};
typedef struct my_context my_context_t;

fd_quic_conn_t * server_conn = NULL;

void
my_cb_conn_final( fd_quic_conn_t * conn,
                  void *           context ) {
  (void)context;

  fd_quic_conn_t ** ppconn = (fd_quic_conn_t**)fd_quic_conn_get_context( conn );
  if( ppconn ) {
    FD_LOG_INFO(( "my_cb_conn_final %p SUCCESS", (void*)*ppconn ));
    *ppconn = NULL;
  }}

void
my_connection_new( fd_quic_conn_t * conn,
                   void *           vp_context ) {
  (void)vp_context;

  FD_LOG_INFO(( "SERVER - handshake complete" ));

  server_complete = 1;

  if( server_conn ) {
    FD_LOG_ERR(( "SERVER - Unexpected new connection" ));
  }

  server_conn = conn;
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)conn; (void)vp_context;

  FD_LOG_INFO(( "CLIENT - handshake complete" ));

  client_complete = 1;
}

/* global "clock" */
static long now = (ulong)1e18;

static long
test_fibre_clock(void) {
  return now;
}


struct client_args {
  fd_quic_t * quic;
  fd_quic_t * server_quic;
};
typedef struct client_args client_args_t;

static void
client_fibre_fn( void * vp_arg ) {
  client_args_t * args = (client_args_t*)vp_arg;

  fd_quic_t * quic = args->quic;

  fd_quic_conn_t *   conn   = NULL;
  fd_quic_stream_t * stream = NULL;

  static uchar const buf[] = "Hello World!";

  long  period_ns = (long)1e6;
  long  next_send = now;
  ulong sent      = 0;

  rcvd = sent = 0;

  conn = fd_quic_connect( quic, 0U, 0, 0U, 0, now );
  if( !conn ) {
    FD_LOG_ERR(( "Client unable to obtain a connection. now: %ld", now ));
  }

  fd_quic_conn_set_context( conn, &conn );

  /* service client until connection is established */
  while( conn && conn->state != FD_QUIC_CONN_STATE_ACTIVE ) {
    fd_quic_service( quic, now );

    ulong next_wakeup = fd_quic_get_next_wakeup( quic );

    /* wake up at either next service or next send, whichever is sooner */
    fd_fibre_wait_until( (long)next_wakeup );
  }

  next_send = now;

  uint last_key_phase = conn->key_phase;

  FD_LOG_INFO(( "CLIENT - connection established - key_phase: %u", (uint)conn->key_phase ));

  while( !client_done ) {
    long next_wakeup = (long)fd_quic_get_next_wakeup( quic );

    /* wake up at either next service or next send, whichever is sooner */
    fd_fibre_wait_until( fd_long_min( next_wakeup, next_send ) );

    fd_quic_service( quic, now );

    /* in this controlled test, connections should not terminate */
    if( !conn ) {
      FD_LOG_ERR(( "Connection aborted unexpectedly" ));
    }

    /* report key phase changes, when complete */
    if( !conn->key_update && last_key_phase != conn->key_phase ) {
      FD_LOG_INFO(( "CLIENT - key phase changed to %u", (uint)conn->key_phase ));
      last_key_phase = conn->key_phase;

      tot_key_phase_change++;
      if( tot_key_phase_change == NUM_KEY_PHASE_CHANGES ) {
        client_done = 1;
      }
    }

    if( rcvd == NUM_STREAMS ) {
      if( conn->key_update ) {
        /* key phase update should have completed long ago */
        FD_LOG_ERR(( "Unexpectedly in a key phase change" ));
      }

      FD_LOG_INFO(( "CLIENT - received %u - starting key phase change", (uint)rcvd ));

      /* reset count */
      rcvd = 0;

      conn->key_update = 1;  /* force a key update */
    }

    if( !stream ) {
      stream = fd_quic_conn_new_stream( conn );

      if( !stream ) {
        continue;
      }
    }

    if( now < next_send ) continue;

    /* set next send time */
    next_send = now + period_ns;

    /* have a stream, so send */
    int rc = fd_quic_stream_send( stream, buf, sizeof(buf), 1 /* fin */ );

    if( rc == FD_QUIC_SUCCESS ) {
      /* successful - stream will begin closing */

      /* ensure new stream used for next send */
      stream = fd_quic_conn_new_stream( conn );

    } else {
      FD_LOG_WARNING(( "CLIENT - send failed" ));
    }
  }

  if( conn ) {
    fd_quic_conn_close( conn, 0 );

    /* keep servicing until connection closed */
    while( conn ) {
      fd_quic_service( quic, now );
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


static void
server_fibre_fn( void * vp_arg ) {
  server_args_t * args = (server_args_t*)vp_arg;

  fd_quic_t * quic = args->quic;

  /* track key phase changes */
  uint last_key_phase = -1u;

  /* wake up at least every 1ms */
  long period_ns = (long)1e6;
  while( !server_done ) {
    fd_quic_service( quic, now );

    if( server_conn ) {
      if( last_key_phase == -1u ) {
        last_key_phase = server_conn->key_phase;
        FD_LOG_INFO(( "SERVER - connection established - key_phase: %u", (uint)last_key_phase ));
      } else if( last_key_phase != server_conn->key_phase ) {
        FD_LOG_INFO(( "SERVER - key phase changed to %u", (uint)server_conn->key_phase ));
        last_key_phase = server_conn->key_phase;
      }
    }

    long next_wakeup = (long)fd_quic_get_next_wakeup( quic );
    long next_period = now + period_ns;

    fd_fibre_wait_until( fd_long_min( next_wakeup, next_period ) );
  }
}


int
main( int argc, char ** argv ) {

  fd_boot          ( &argc, &argv );
  fd_quic_test_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "normal"                     );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 800UL                        );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  FD_LOG_INFO(( "Creating server QUIC" ));
  fd_quic_limits_t const server_limits = {
    .conn_cnt           =  2,
    .conn_id_cnt        =  4,
    .handshake_cnt      =  2,
    .inflight_frame_cnt = 16 * 2
  };
  fd_quic_t * server_quic = fd_quic_new_anonymous( wksp, &server_limits, FD_QUIC_ROLE_SERVER, rng );
  FD_TEST( server_quic );

  FD_LOG_INFO(( "Creating client QUIC" ));
  fd_quic_limits_t const client_limits = {
    .conn_cnt           =       2,
    .conn_id_cnt        =       4,
    .handshake_cnt      =       2,
    .inflight_frame_cnt = 530 * 2,
    .stream_id_cnt      =     512,
    .stream_pool_cnt    =     512,
    .tx_buf_sz          =      32,
  };
  fd_quic_t * client_quic = fd_quic_new_anonymous( wksp, &client_limits, FD_QUIC_ROLE_CLIENT, rng );
  FD_TEST( client_quic );

  client_quic->cb.conn_hs_complete = my_handshake_complete;
  client_quic->cb.conn_final       = my_cb_conn_final;

  client_quic->config.initial_rx_max_stream_data = 1<<15;

  server_quic->cb.conn_new       = my_connection_new;
  server_quic->cb.stream_rx      = my_stream_rx_cb;
  server_quic->cb.conn_final     = my_cb_conn_final;

  server_quic->config.initial_rx_max_stream_data = 1<<15;

  fd_quic_virtual_pair_t vp;
  fd_quic_virtual_pair_init( &vp, /*a*/ client_quic, /*b*/ server_quic );

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

    now = timeout;
  }

  FD_LOG_NOTICE(( "Passed %lu key updates", tot_key_phase_change ));
  FD_LOG_NOTICE(( "Cleaning up" ));
  fd_quic_virtual_pair_fini( &vp );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( server_quic ) ) );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( client_quic ) ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_quic_test_halt();
  fd_halt();
  return 0;
}
