#include "../fd_quic.h"
#include "../fd_quic_private.h"
#include "fd_quic_test_helpers.h"
#include "../../../util/net/fd_ip4.h"

#include <stdio.h>
#include <stdlib.h>

int
my_stream_rx_cb( fd_quic_conn_t * conn,
                 ulong            stream_id,
                 ulong            offset,
                 uchar const *    data,
                 ulong            data_sz,
                 int              fin ) {
  (void)conn;
  FD_LOG_DEBUG(( "server rx stream data stream=%lu size=%lu offset=%lu",
                 stream_id, data_sz, offset ));
  FD_TEST( fd_ulong_is_aligned( offset, 512UL ) );
  FD_LOG_HEXDUMP_DEBUG(( "received data", data, data_sz ));

  FD_TEST( data_sz==512UL );
  FD_TEST( !fin );
  FD_TEST( 0==memcmp( data, "Hello world", 11u ) );
  return FD_QUIC_SUCCESS;
}

int server_complete = 0;
int client_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;

void
my_connection_new( fd_quic_conn_t * conn,
                   void *           vp_context ) {
  (void)vp_context;

  FD_LOG_NOTICE(( "server handshake complete" ));

  server_complete = 1;
  server_conn = conn;
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_NOTICE(( "client handshake complete" ));

  client_complete = 1;
}


/* global "clock" */
long now = 123;

/* Test that server responds with Retry packet when receiving Initial
   with a token that has a size that we couldn't have possibly emitted. */
void
test_initial_token_odd_sz( fd_quic_t * server_quic,
                           fd_quic_t * client_quic ) {
  FD_LOG_NOTICE(( "Testing Initial packet with 46-byte token" ));

  /* Create an arbitrary 46-byte token */
  uchar token_46[46];
  for( ulong i = 0; i < 46; i++ ) {
    token_46[i] = (uchar)(i + 1);
  }

  ulong initial_retry_count = server_quic->metrics.conn_retry_cnt;
  ulong initial_token_len_other = server_quic->metrics.initial_token_len_cnt[2];
  ulong initial_token_len_our = server_quic->metrics.initial_token_len_cnt[1];
  ulong conn_created_count = server_quic->metrics.conn_created_cnt;

  /* Create a new connection with 46-byte token */
  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, FD_QUIC_TEST_SERVER_IP4, 0, FD_QUIC_TEST_CLIENT_IP4, 0, now );
  FD_TEST( client_conn );

  /* Override the token in the connection state to be our 46-byte token */
  memcpy( client_conn->token, token_46, 46 );
  client_conn->token_len = 46;

  /* Process packets - should trigger retry response */
  for( ulong j = 0; j < 5; j++ ) {
    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );
  }

  /* Verify server sent a retry packet (difference-based check) */
  FD_TEST( server_quic->metrics.conn_retry_cnt == initial_retry_count + 1 );

  /* Verify the 46-byte token was counted in the "other sizes" category
     See test_retry_integration for details on the expected increases */
  FD_TEST( server_quic->metrics.initial_token_len_cnt[2] == initial_token_len_other + 1 );
  FD_TEST( server_quic->metrics.initial_token_len_cnt[1] == initial_token_len_our + 2 );

  /* Verify the connection was created */
  FD_TEST( server_quic->metrics.conn_created_cnt == conn_created_count + 1 );

  FD_LOG_NOTICE(( "46-byte token test pass" ));
}

/* capture_aio keeps a copy of the last datagram it forwards. */

static fd_aio_t const * capture_next;
static uchar            capture_buf[ 2048 ];
static ulong            capture_sz;

static int
capture_aio_send( void *                    ctx,
                  fd_aio_pkt_info_t const * batch,
                  ulong                     batch_cnt,
                  ulong *                   opt_batch_idx,
                  int                       flush ) {
  (void)ctx;
  for( ulong i=0UL; i<batch_cnt; i++ ) {
    if( batch[ i ].buf_sz>sizeof(capture_buf) ) continue;
    fd_memcpy( capture_buf, batch[ i ].buf, batch[ i ].buf_sz );
    capture_sz = batch[ i ].buf_sz;
  }
  return fd_aio_send( capture_next, batch, batch_cnt, opt_batch_idx, flush );
}

/* Test that a post-Retry Initial whose token expired is answered with
   CONNECTION_CLOSE(INVALID_TOKEN), which the client takes as the end of
   the dial, instead of being dropped silently. */
void
test_retry_token_expired( fd_quic_t * server_quic,
                          fd_quic_t * client_quic ) {
  FD_LOG_NOTICE(( "Testing Initial with an expired Retry token" ));

  ulong retry_cnt   = server_quic->metrics.retry_tx_cnt;
  ulong fail_cnt    = server_quic->metrics.conn_err_retry_fail_cnt;
  ulong expired_cnt = server_quic->metrics.conn_err_retry_expired_cnt;
  ulong created_cnt = server_quic->metrics.conn_created_cnt;
  ulong client_closed_cnt = client_quic->metrics.conn_closed_cnt;

  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, FD_QUIC_TEST_SERVER_IP4, 0, FD_QUIC_TEST_CLIENT_IP4, 0, now );
  FD_TEST( client_conn );

  /* The client's first Initial gets a Retry; its token Initial then
     arrives after the token expired. */
  fd_quic_service( client_quic, now );
  fd_quic_service( server_quic, now );
  FD_TEST( server_quic->metrics.retry_tx_cnt==retry_cnt+1UL );
  fd_quic_service( server_quic, now+server_quic->config.retry_ttl ); /* only the server's clock moves */
  for( ulong j=0UL; j<5UL; j++ ) fd_quic_service( client_quic, now );

  FD_TEST( server_quic->metrics.conn_err_retry_fail_cnt   ==fail_cnt+1UL    );
  FD_TEST( server_quic->metrics.conn_err_retry_expired_cnt==expired_cnt+1UL );
  FD_TEST( server_quic->metrics.conn_created_cnt          ==created_cnt     ); /* no conn for the stale token */
  FD_TEST( client_quic->metrics.conn_closed_cnt==client_closed_cnt+1UL ); /* the close decrypted and ended the dial */

  FD_LOG_NOTICE(( "expired token test pass" ));
}

/* Replays of an expired-token Initial are answered at most once per
   FD_QUIC_INVALID_TOKEN_INTERVAL_NS. */
void
test_retry_token_expired_replay( fd_quic_t * server_quic,
                                 fd_quic_t * client_quic ) {
  FD_LOG_NOTICE(( "Testing replays of an expired Retry token" ));

  fd_aio_t capture[1];
  capture_next = fd_quic_get_aio_net_rx( server_quic );
  FD_TEST( fd_aio_join( fd_aio_new( capture, NULL, capture_aio_send ) ) );
  fd_aio_t saved = client_quic->aio_tx;
  fd_quic_set_aio_net_tx( client_quic, capture );

  /* Capture a token Initial, delivered while its token is valid.  Both
     clocks start past the server's, which earlier tests moved. */
  now = fd_quic_get_state( server_quic )->now + 1000000000L;
  fd_quic_get_state( server_quic )->now = fd_quic_get_state( client_quic )->now = now;
  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, FD_QUIC_TEST_SERVER_IP4, 0, FD_QUIC_TEST_CLIENT_IP4, 0, now );
  FD_TEST( client_conn );
  fd_quic_service( client_quic, now );
  fd_quic_service( server_quic, now );
  fd_quic_service( client_quic, now );
  fd_quic_set_aio_net_tx( client_quic, &saved );
  FD_TEST( capture_sz );
  uchar replay[ 2048 ];
  ulong replay_sz = capture_sz;
  fd_memcpy( replay, capture_buf, replay_sz );

  /* fd_quic_retry_token_check accepts the token Initial while fresh and
     only from the address it was issued to. */
  {
    fd_ip4_hdr_t const * ip4 = (fd_ip4_hdr_t const *)replay;
    ulong                iplen = FD_IP4_GET_LEN( *ip4 );
    fd_udp_hdr_t const * udp = (fd_udp_hdr_t const *)( replay+iplen );
    uchar const *        pay = replay+iplen+sizeof(fd_udp_hdr_t);
    ulong                psz = replay_sz-iplen-sizeof(fd_udp_hdr_t);
    uint                 src = FD_LOAD( uint, ip4->saddr_c );
    ushort               sp  = fd_ushort_bswap( udp->net_sport );
    FD_TEST(  fd_quic_retry_token_check( server_quic, pay, psz, src,     sp,              now ) );
    FD_TEST( !fd_quic_retry_token_check( server_quic, pay, psz, src+1U,  sp,              now ) );
    FD_TEST( !fd_quic_retry_token_check( server_quic, pay, psz, src,     (ushort)(sp+1U), now ) );
    FD_TEST( !fd_quic_retry_token_check( server_quic, pay, psz, src,     sp,              now+server_quic->config.retry_ttl+100000000L ) );
    uchar bad[ 2048 ]; fd_memcpy( bad, pay, psz ); bad[ 40 ] ^= 1;
    FD_TEST( !fd_quic_retry_token_check( server_quic, bad, psz, src,     sp,              now ) );
  }

  /* Replayed after expiry, once the conn it opened timed out, ten times
     within one interval.  The server stamped the token with its own
     clock. */
  long  t        = now + server_quic->config.retry_ttl + 100000000L;
  for( ulong i=0UL; i<16UL && server_quic->metrics.conn_alloc_cnt; i++ ) fd_quic_service( server_quic, t );
  FD_TEST( !server_quic->metrics.conn_alloc_cnt );
  ulong expired  = server_quic->metrics.conn_err_retry_expired_cnt;
  ulong tx       = server_quic->metrics.net_tx_pkt_cnt;
  for( ulong i=0UL; i<10UL; i++ ) {
    uchar pkt[ 2048 ];
    fd_memcpy( pkt, replay, replay_sz );
    fd_quic_process_packet( server_quic, pkt, replay_sz, t+(long)i );
  }
  FD_TEST( server_quic->metrics.conn_err_retry_expired_cnt>=expired+9UL );
  FD_TEST( server_quic->metrics.net_tx_pkt_cnt<=tx+1UL );

  /* After the interval, one more reply. */
  uchar pkt[ 2048 ];
  fd_memcpy( pkt, replay, replay_sz );
  fd_quic_process_packet( server_quic, pkt, replay_sz, t+FD_QUIC_INVALID_TOKEN_INTERVAL_NS+100L );
  FD_TEST( server_quic->metrics.net_tx_pkt_cnt<=tx+2UL );

  FD_LOG_NOTICE(( "expired token replay test pass" ));
}

void
test_retry_integration( fd_quic_t * server_quic,
                        fd_quic_t * client_quic ) {

  FD_LOG_NOTICE(( "Creating connection" ));
  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, FD_QUIC_TEST_SERVER_IP4, 0, FD_QUIC_TEST_CLIENT_IP4, 0, now );
  FD_TEST( client_conn );

  /* do general processing */
  for( ulong j = 0; j < 20; j++ ) {
    FD_LOG_INFO(( "running services" ));
    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "***** both handshakes complete *****" ));
      break;
    }
  }

  FD_TEST( client_quic->metrics.conn_created_cnt== 1 );
  FD_TEST( client_quic->metrics.conn_retry_cnt  == 0 );
  FD_TEST( server_quic->metrics.conn_created_cnt== 1 );
  FD_TEST( server_quic->metrics.conn_retry_cnt  == 1 );

  /* Check initial token length metrics - should have seen:
     * 1 packet with no token (idx 0), the very first initial
     * 2 packets with retry token with correct fd_quic len (idx 1):
       - first the Initial with crypto frames triggered by Retry
       - second an Initial with ack frame, ACKing server Initial */
  FD_TEST( server_quic->metrics.initial_token_len_cnt[0] == 1 ); /* no token */
  FD_TEST( server_quic->metrics.initial_token_len_cnt[1] == 2 ); /* retry token */
  FD_TEST( server_quic->metrics.initial_token_len_cnt[2] == 0 ); /* other sizes */
  /* Server: Retry, Initial, Handshake
     Client: Initial, Initial, Handshake */
  FD_TEST( client_quic->metrics.net_rx_pkt_cnt  == 3 );
  FD_TEST( client_quic->metrics.net_tx_pkt_cnt  == 3 );
  FD_TEST( server_quic->metrics.net_rx_pkt_cnt  == 3 );
  FD_TEST( server_quic->metrics.net_tx_pkt_cnt  == 3 );
  FD_TEST( client_quic->metrics.net_tx_byte_cnt > server_quic->metrics.net_tx_byte_cnt );

  /* TODO we get callback before the call to fd_quic_conn_new_stream can complete
     must delay until the conn->state is ACTIVE */

  FD_LOG_NOTICE(( "Creating streams" ));

  fd_quic_stream_t * client_stream   = fd_quic_conn_new_stream( client_conn );
  FD_TEST( client_stream );

  fd_quic_stream_t * client_stream_0 = fd_quic_conn_new_stream( client_conn );
  FD_TEST( client_stream_0 );

  FD_LOG_NOTICE(( "Sending data over streams" ));

  char buf[512] = "Hello world!\x00-   ";

  for( unsigned j = 0; j < 16; ++j ) {
    FD_LOG_INFO(( "running services" ));

    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );

    buf[12] = ' ';
    //buf[15] = (char)( ( j / 10 ) + '0' );
    buf[16] = (char)( ( j % 10 ) + '0' );
    int rc = 0;
    if( j&1 ) {
      rc = fd_quic_stream_send( client_stream,   buf, sizeof(buf), 0 );
    } else {
      rc = fd_quic_stream_send( client_stream_0, buf, sizeof(buf), 0 );
    }

    FD_LOG_INFO(( "fd_quic_stream_send returned %d", rc ));
  }

  FD_LOG_NOTICE(( "Closing connections" ));

  fd_quic_conn_close( client_conn, 0 );
  fd_quic_conn_close( server_conn, 0 );

  FD_LOG_NOTICE(( "Waiting for ACKs" ));

  for( uint j=0; j<10U; ++j ) {
    FD_LOG_INFO(( "running services" ));
    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );
  }

  FD_TEST( client_quic->metrics.conn_created_cnt== 1 );

  FD_LOG_NOTICE(( "retry integration test pass" ));
}

int
main( int argc, char ** argv ) {
  fd_boot          ( &argc, &argv );
  fd_quic_test_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

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

  fd_quic_limits_t const quic_limits = {
    .conn_cnt           = 10,
    .conn_id_cnt        = 10,
    .handshake_cnt      = 10,
    .stream_id_cnt      = 10,
    .stream_pool_cnt    = 400,
    .inflight_frame_cnt = 1024 * 10,
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

  server_quic->cb.conn_new         = my_connection_new;
  server_quic->cb.stream_rx        = my_stream_rx_cb;
  server_quic->config.retry = 1;

  client_quic->cb.conn_hs_complete = my_handshake_complete;

  server_quic->config.initial_rx_max_stream_data = 1<<16;
  client_quic->config.initial_rx_max_stream_data = 1<<16;

  FD_LOG_NOTICE(( "Creating virtual pair" ));
  fd_quic_virtual_pair_t vp;
  fd_quic_virtual_pair_init( &vp, server_quic, client_quic );

  FD_LOG_NOTICE(( "Initializing QUICs" ));
  FD_TEST( fd_quic_init( server_quic ) );
  FD_TEST( fd_quic_init( client_quic ) );

  /* Run normal retry integration test */
  test_retry_integration( server_quic, client_quic );

  /* Run the 46-byte token test */
  test_initial_token_odd_sz( server_quic, client_quic );

  /* Run the expired token test */
  test_retry_token_expired( server_quic, client_quic );
  test_retry_token_expired_replay( server_quic, client_quic );

  FD_LOG_NOTICE(( "Cleaning up" ));
  fd_quic_virtual_pair_fini( &vp );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini ( server_quic ) ) ) );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini ( client_quic ) ) ) );

  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_quic_test_halt();
  fd_halt();
  return 0;
}
