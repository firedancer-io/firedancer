#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

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
                  void *           context  FD_PARAM_UNUSED) {
  fd_quic_conn_t ** ppconn = (fd_quic_conn_t**)fd_quic_conn_get_context( conn );
  if( ppconn ) {
    FD_LOG_INFO(( "my_cb_conn_final %p SUCCESS", (void*)*ppconn ));
    *ppconn = NULL;
  }
}

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
static long now = 1e18L;

static void
sync_clocks( fd_quic_t * x, fd_quic_t * y ) {
  fd_quic_sync_clocks( x, y, now );
}

struct client_state {
  fd_quic_conn_t *   conn;
  fd_quic_stream_t * stream;
  long               next_send;
  uint               last_key_phase;
  int                active_logged;
  int                closing;
};
typedef struct client_state client_state_t;

struct server_state {
  long        next_period;
  uint        last_key_phase;
};
typedef struct server_state server_state_t;

static uchar const buf[] = "Hello World!";

static void
client_state_init( client_state_t * client,
                   fd_quic_t *      quic ) {
  client->conn           = NULL;
  client->stream         = NULL;
  client->next_send      = now;
  client->last_key_phase = 0U;
  client->active_logged  = 0;
  client->closing        = 0;

  rcvd = 0;

  client->conn = fd_quic_connect( quic, FD_QUIC_TEST_SERVER_IP4, 0, FD_QUIC_TEST_CLIENT_IP4, 0, now );
  if( !client->conn ) {
    FD_LOG_ERR(( "Client unable to obtain a connection. now: %ld", now ));
  }

  fd_quic_conn_set_context( client->conn, &client->conn );
}

static void
client_step( client_state_t * client ) {
  fd_quic_conn_t * conn = client->conn;

  if( !conn ) {
    if( !client->closing ) FD_LOG_ERR(( "Connection aborted unexpectedly" ));
    server_done = 1;
    return;
  }

  if( client_done ) {
    if( !client->closing ) {
      fd_quic_conn_close( conn, 0 );
      client->closing = 1;
    }
    return;
  }

  if( conn->state != FD_QUIC_CONN_STATE_ACTIVE ) return;

  if( !client->active_logged ) {
    FD_TEST( client_complete );
    client->next_send      = now;
    client->last_key_phase = conn->key_phase;
    client->active_logged  = 1;
    FD_LOG_INFO(( "CLIENT - connection established - key_phase: %u", (uint)conn->key_phase ));
  }

  /* report key phase changes, when complete */
  if( !conn->key_update && client->last_key_phase != conn->key_phase ) {
    tot_key_phase_change++;
    FD_LOG_INFO(( "CLIENT - key phase changed to %u, %lu changes done", (uint)conn->key_phase, tot_key_phase_change ));
    client->last_key_phase = conn->key_phase;

    if( tot_key_phase_change == NUM_KEY_PHASE_CHANGES ) client_done = 1;
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

  if( !client->stream ) {
    client->stream = fd_quic_conn_new_stream( conn );
    if( !client->stream ) return;
  }

  if( now < client->next_send ) return;

  /* set next send time */
  client->next_send = now + (long)1e6;

  /* have a stream, so send */
  int rc = fd_quic_stream_send( client->stream, buf, sizeof(buf), 1 /* fin */ );

  if( rc == FD_QUIC_SUCCESS ) {
    /* successful - stream will begin closing */

    /* ensure new stream used for next send */
    client->stream = fd_quic_conn_new_stream( conn );

  } else {
    FD_LOG_WARNING(( "CLIENT - send failed" ));
  }
}

static void
server_state_init( server_state_t * server ) {
  server->next_period    = now;
  server->last_key_phase = -1u;
}

static void
server_step( server_state_t * server ) {
  if( server_conn ) {
    if( server->last_key_phase == -1u ) {
      server->last_key_phase = server_conn->key_phase;
      FD_LOG_INFO(( "SERVER - connection established - key_phase: %u", (uint)server->last_key_phase ));
    } else if( server->last_key_phase != server_conn->key_phase ) {
      FD_LOG_INFO(( "SERVER - key phase changed to %u", (uint)server_conn->key_phase ));
      server->last_key_phase = server_conn->key_phase;
    }
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
  client_quic->cb.quic_ctx         = &client_quic;

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

  client_state_t client[1];
  server_state_t server[1];
  client_state_init( client, client_quic );
  server_state_init( server );

  while( !server_done ) {
    sync_clocks( client_quic, server_quic );

    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );

    server_step( server );
    client_step( client );

    long next_wakeup_client = fd_quic_get_next_wakeup( client_quic );
    long next_wakeup_server = fd_quic_get_next_wakeup( server_quic );
    long next_wakeup        = fd_long_min( next_wakeup_client, next_wakeup_server );

    if( client->conn && !client_done ) next_wakeup = fd_long_min( next_wakeup, client->next_send );

    /* wake the server side at least every 1ms */
    server->next_period = fd_long_max( server->next_period, now ) + (long)1e6;
    next_wakeup = fd_long_min( next_wakeup, server->next_period );

    FD_TEST( next_wakeup < LONG_MAX );
    now = fd_long_max( now+1L, next_wakeup );
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
