#include "test_bundle_common.c"
#include "proto/block_engine.pb.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/nanopb/pb_encode.h"

FD_IMPORT_BINARY( test_bundle_response, "src/disco/bundle/test_bundle_response.binpb" );

__attribute__((weak)) char const fdctl_version_string[] = "0.0.0";

static long g_clock = 1L;

__attribute__((weak)) long
fd_bundle_now( void ) {
  return g_clock;
}

/* Test that packets and bundles get forwarded correctly to Firedancer
   components. */

static void
test_bundle_rx( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1]; test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;

  /* A SubscribePacketsResponse message with 2 packets included. The
     first packet is 1 byte { 0x48 }, the second packet is 2 bytes
     {0x48, 0x48}.

     message SubscribePacketsResponse {
      shared.Header header = 1;
      packet.PacketBatch batch = 2;
    }
  */
  static uchar subscribe_packets_msg[] = {
    0x12, 0x13, 0x0a, 0x07, 0x0a, 0x01, 0x48, 0x12,
    0x02, 0x08, 0x01, 0x0a, 0x08, 0x0a, 0x02, 0x48,
    0x48, 0x12, 0x02, 0x08, 0x02
  };
  fd_bundle_client_grpc_rx_msg(
      state,
      subscribe_packets_msg, sizeof(subscribe_packets_msg),
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==2UL );
  FD_TEST( pending_txn_peek_head( state->pending_txns )->sig==0UL );

  state->builder_info_avail = 1;

  fd_bundle_client_grpc_rx_msg(
      state,
      test_bundle_response, test_bundle_response_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )>2UL );

  test_bundle_env_destroy( env );
}

static void
test_bundle_rx_too_many_txns( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1]; test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;

  /*
  Contains a single bundle with 6 transactions
  {
    "bundles": [
      {
        "bundle": {
          "header": null,
          "packets": [
            {
              "data": [
                72
              ],
              "meta": {
                "size": 1,
                "addr": "",
                "port": 0,
                "flags": null,
                "sender_stake": 0
              }
            },
            ...x5
          ]
        },
        "uuid": [0, 0, 0]
      }
    ]
  }
  */
  static uchar subscribe_bundles_msg_x5[] = {
    0x0a, 0x52, 0x0a, 0x4b, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12, 0x08,
    0x08, 0x01, 0x12, 0x00, 0x18, 0x00, 0x28, 0x00, 0x1a, 0x0d, 0x0a,
    0x01, 0x48, 0x12, 0x08, 0x08, 0x01, 0x12, 0x00, 0x18, 0x00, 0x28,
    0x00, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12, 0x08, 0x08, 0x01, 0x12,
    0x00, 0x18, 0x00, 0x28, 0x00, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12,
    0x08, 0x08, 0x01, 0x12, 0x00, 0x18, 0x00, 0x28, 0x00, 0x1a, 0x0d,
    0x0a, 0x01, 0x48, 0x12, 0x08, 0x08, 0x01, 0x12, 0x00, 0x18, 0x00,
    0x28, 0x00, 0x12, 0x03, 0x00, 0x00, 0x00
  };

  state->builder_info_avail = 1;
  fd_bundle_client_grpc_rx_msg(
      state,
      subscribe_bundles_msg_x5, sizeof(subscribe_bundles_msg_x5),
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==5UL );
  test_bundle_env_destroy( env );

  test_bundle_env_create( env, wksp );
  state = env->state;

  /* Same as above, now with 6 transactions. Should be a NOP */
  static uchar subscribe_bundles_msg_x6[] = {
    0x0a, 0x61, 0x0a, 0x5a, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12, 0x08,
    0x08, 0x01, 0x12, 0x00, 0x18, 0x00, 0x28, 0x00, 0x1a, 0x0d, 0x0a,
    0x01, 0x48, 0x12, 0x08, 0x08, 0x01, 0x12, 0x00, 0x18, 0x00, 0x28,
    0x00, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12, 0x08, 0x08, 0x01, 0x12,
    0x00, 0x18, 0x00, 0x28, 0x00, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12,
    0x08, 0x08, 0x01, 0x12, 0x00, 0x18, 0x00, 0x28, 0x00, 0x1a, 0x0d,
    0x0a, 0x01, 0x48, 0x12, 0x08, 0x08, 0x01, 0x12, 0x00, 0x18, 0x00,
    0x28, 0x00, 0x1a, 0x0d, 0x0a, 0x01, 0x48, 0x12, 0x08, 0x08, 0x01,
    0x12, 0x00, 0x18, 0x00, 0x28, 0x00, 0x12, 0x03, 0x00, 0x00, 0x00
  };

  state->builder_info_avail = 1;
  fd_bundle_client_grpc_rx_msg(
      state,
      subscribe_bundles_msg_x6, sizeof(subscribe_bundles_msg_x6),
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );

  FD_TEST( state->bundle_txn_cnt==6 );
  FD_TEST( pending_txn_cnt( state->pending_txns )==0UL );
  test_bundle_env_destroy( env );
}

/* Ensure forwarding of bundles stops when builder fee info is missing. */

static void
test_bundle_no_builder_fee_info( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1]; test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->builder_info_avail = 0;

  /* Regular packets are always forwarded */
  static uchar subscribe_packets_msg[] = {
    0x12, 0x09, 0x0a, 0x07, 0x0a, 0x01, 0x48, 0x12,
    0x02, 0x08, 0x01
  };
  fd_bundle_client_grpc_rx_msg(
      state,
      subscribe_packets_msg, sizeof(subscribe_packets_msg),
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );
  FD_TEST( pending_txn_cnt( state->pending_txns )==1UL );
  FD_TEST( state->metrics.packet_received_cnt          ==1UL );
  FD_TEST( state->metrics.missing_builder_info_fail_cnt==0UL );

  /* Bundles are no longer forwarded */

  fd_bundle_client_grpc_rx_msg(
      state,
      test_bundle_response, test_bundle_response_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );
  FD_TEST( pending_txn_cnt( state->pending_txns )==1UL );
  FD_TEST( state->metrics.bundle_received_cnt          ==0UL );
  FD_TEST( state->metrics.missing_builder_info_fail_cnt==1UL );

  test_bundle_env_destroy( env );
}

/* Ensure that the client reconnects (with a new TCP socket) if the
   server ends the stream */

static void
test_bundle_stream_ended( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state = env->state;
  fd_h2_rbuf_t * rbuf_tx = fd_grpc_client_rbuf_tx( state->grpc_client );
  FD_TEST( rbuf_tx->hi_off==0UL );
  fd_grpc_resp_hdrs_t hdrs = {
    .h2_status   = 200,
    .grpc_status = FD_GRPC_STATUS_OK
  };
  FD_TEST( state->defer_reset==0 );
  fd_bundle_client_grpc_rx_end( state, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles, &hdrs );
  FD_TEST( state->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Same as above, but with hard stream resets */

static void
test_bundle_stream_reset( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state   = env->state;
  fd_grpc_client_t * client  = state->grpc_client;
  fd_h2_conn_t *     h2_conn = fd_grpc_client_h2_conn( client );

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status     = 200;
  stream->hdrs.is_grpc_proto = 1;

  FD_TEST( state->defer_reset==0 );
  fd_grpc_client_h2_callbacks.rst_stream( h2_conn, &stream->s, 0U, 1 );
  FD_TEST( state->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Test response header timeout */

static void
test_bundle_header_timeout( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state  = env->state;
  fd_grpc_client_t * client = state->grpc_client;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status        = 200;
  stream->hdrs.is_grpc_proto    = 1;
  stream->has_header_deadline   = 1;
  stream->header_deadline_nanos = 99L;

  /* FIXME ensure that receiving a header disarms the timeout */

  fd_grpc_client_service_streams( client, 100L );
  FD_TEST( state->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Test response timeout */

static void
test_bundle_rx_end_timeout( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state  = env->state;
  fd_grpc_client_t * client = state->grpc_client;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status        = 200;
  stream->hdrs.is_grpc_proto    = 1;
  stream->has_rx_end_deadline   = 1;
  stream->rx_end_deadline_nanos = 99L;

  fd_grpc_client_service_streams( client, 100L );
  FD_TEST( state->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Test ping timeout */

static void
test_bundle_ping( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state       = env->state;
  fd_grpc_client_t * grpc_client = state->grpc_client;
  long const ts_ping_tx = g_clock;
  fd_keepalive_tx( state->keepalive, state->rng, ts_ping_tx );
  state->grpc_client->conn->ping_tx = 1;
  FD_TEST( state->keepalive->inflight==1 );
  FD_TEST( !!state->keepalive->ts_deadline );
  FD_TEST( state->keepalive->ts_next_tx >= ts_ping_tx + (state->keepalive->interval>>1) );
  FD_TEST( state->keepalive->ts_last_tx==ts_ping_tx );
  FD_TEST( fd_keepalive_is_timeout( state->keepalive, ts_ping_tx )==0 );
  FD_TEST( fd_keepalive_should_tx ( state->keepalive, ts_ping_tx )==0 );

  /* PING ACK should update timer */
  g_clock += (long)10e6; /* 10ms passed */
  long const ts_ping_rx = g_clock;
  grpc_client->conn->ping_tx = 1;
  fd_h2_frame_hdr_t ping_ack_hdr = {
    .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ),
    .flags  = FD_H2_FLAG_ACK
  };
  fd_h2_rbuf_push( grpc_client->frame_rx, &ping_ack_hdr, sizeof(fd_h2_frame_hdr_t) );
  ulong const ping_seq = 1UL;
  fd_h2_rbuf_push( grpc_client->frame_rx, &ping_seq, sizeof(ulong) );
  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_rx )==0UL );
  FD_TEST( grpc_client->conn->ping_tx == 0 );
  FD_TEST( state->defer_reset==0 );
  FD_TEST( state->keepalive->ts_last_tx==ts_ping_tx );
  FD_TEST( state->keepalive->ts_last_rx==ts_ping_rx );
  FD_TEST( !state->keepalive->inflight );
  FD_TEST( state->metrics.ping_ack_cnt==1UL );
  FD_TEST( state->rtt->latest_rtt==10e6f );
  FD_TEST( fd_keepalive_is_timeout( state->keepalive, ts_ping_rx )==0 );
  FD_TEST( fd_keepalive_should_tx ( state->keepalive, ts_ping_rx )==0 );

  /* Test PING TX */
  g_clock = state->keepalive->ts_next_tx;
  long const ts_ping_tx2 = g_clock;
  FD_TEST( fd_keepalive_is_timeout( state->keepalive, ts_ping_tx2 )==0 );
  FD_TEST( fd_keepalive_should_tx ( state->keepalive, ts_ping_tx2 )==1 );
  FD_TEST( state->keepalive->inflight==0 );
  charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->defer_reset==0 );
  FD_TEST( fd_keepalive_is_timeout( state->keepalive, ts_ping_tx2 )==0 );
  FD_TEST( fd_keepalive_should_tx ( state->keepalive, ts_ping_tx2 )==0 );
  FD_TEST( state->keepalive->inflight==1 );
  FD_TEST( charge_busy==1 );
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )==sizeof(fd_h2_ping_t) );
  fd_h2_ping_t ping;
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &ping, sizeof(fd_h2_ping_t) );
  FD_TEST( ping.hdr.typlen==fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ) );
  FD_TEST( ping.hdr.flags==0 );
  FD_TEST( state->keepalive->inflight==1 );
  charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( charge_busy==0 );
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )==0 );

  /* Test timeout */
  g_clock = state->keepalive->ts_deadline + 1L;
  long const ts_ping_timeout = g_clock;
  FD_TEST( fd_keepalive_is_timeout( state->keepalive, ts_ping_timeout )==1 );

  /* Stepping should cause a reset due to timeout */
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->defer_reset==1 );

  test_bundle_env_destroy( env );
}

/* Check the client's behavior if an oversized message is received */

static void
test_bundle_msg_oversized( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );

  fd_bundle_tile_t * state  = env->state;
  fd_grpc_client_t * client = state->grpc_client;

  fd_grpc_h2_stream_t * stream = fd_grpc_client_stream_acquire( client, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( stream );
  stream->hdrs.h2_status     = 200;
  stream->hdrs.is_grpc_proto = 1;

  fd_h2_conn_t * h2_conn = fd_grpc_client_h2_conn( state->grpc_client );
  fd_grpc_hdr_t hdr = {
    .compressed = 0,
    .msg_sz     = fd_uint_bswap( USHORT_MAX )
  };

  FD_TEST( state->bundle_subscription_live );
  fd_grpc_client_h2_callbacks.data( h2_conn, &stream->s, &hdr, sizeof(fd_grpc_hdr_t), 0UL );
  FD_TEST( !state->bundle_subscription_live );
  FD_TEST( state->defer_reset );

  test_bundle_env_destroy( env );
}

/* Ensure that the client resets after switching keys */

static void
test_bundle_keyswitch( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * state = env->state;

  void * keyswitch_mem = fd_wksp_alloc_laddr( wksp, fd_keyswitch_align(), fd_keyswitch_footprint(), 1UL );
  FD_TEST( keyswitch_mem );
  state->keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  memset( state->auther.pubkey, 0, 32 );

  fd_bundle_tile_housekeeping( state ); /* should not switch */
  FD_TEST( !state->defer_reset );

  fd_keyswitch_state( state->keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  state->keyswitch->bytes[0] = 0x01;
  fd_bundle_tile_housekeeping( state ); /* should switch */
  FD_TEST( state->defer_reset );
  FD_TEST( state->auther.pubkey[0] == 0x01 );

  test_bundle_env_destroy( env );
  fd_wksp_free_laddr( keyswitch_mem );
}

/* Verify that the bundle client status is reported correctly */

static void
test_bundle_client_status( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * state = env->state;
  fd_bundle_tile_t state_backup  = *state;
  fd_grpc_client_t client_backup = *state->grpc_client;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->tcp_sock_connected = 0;
  FD_TEST( fd_bundle_client_status( state )==0 );
  *state = state_backup;

  ushort const conn_dead_flags[] = {
    FD_H2_CONN_FLAGS_DEAD,
    FD_H2_CONN_FLAGS_SEND_GOAWAY
  };
  for( ulong i=0; i<sizeof(conn_dead_flags)/sizeof(ushort); i++ ) {
    FD_TEST( fd_bundle_client_status( state )==2 );
    state->grpc_client->conn->flags |= conn_dead_flags[ i ];
    FD_TEST( fd_bundle_client_status( state )==0 );
    *state->grpc_client = client_backup;
  }

  ushort const conn_prog_flags[] = {
    FD_H2_CONN_FLAGS_CLIENT_INITIAL,
    FD_H2_CONN_FLAGS_WAIT_SETTINGS_ACK_0,
    FD_H2_CONN_FLAGS_WAIT_SETTINGS_0,
    FD_H2_CONN_FLAGS_SERVER_INITIAL
  };
  for( ulong i=0; i<sizeof(conn_prog_flags)/sizeof(ushort); i++ ) {
    FD_TEST( fd_bundle_client_status( state )==2 );
    state->grpc_client->conn->flags |= conn_prog_flags[ i ];
    FD_TEST( fd_bundle_client_status( state )==1 );
    *state->grpc_client = client_backup;
  }

  for( int auth_state=0; auth_state<FD_BUNDLE_AUTH_STATE_DONE_WAIT; auth_state++ ) {
    FD_TEST( fd_bundle_client_status( state )==2 );
    state->auther.state = auth_state;
    FD_TEST( fd_bundle_client_status( state )==1 );
    state->auther.state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;
  }

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->builder_info_wait = 1;
  FD_TEST( fd_bundle_client_status( state )==2 ); /* rotate builder info without downtime */
  state->auther.state = FD_BUNDLE_AUTH_STATE_DONE_WAIT;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->builder_info_avail = 0;
  FD_TEST( fd_bundle_client_status( state )==1 );
  *state = state_backup;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->packet_subscription_live = 0;
  FD_TEST( fd_bundle_client_status( state )==1 );
  *state = state_backup;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->bundle_subscription_live = 0;
  FD_TEST( fd_bundle_client_status( state )==1 );
  *state = state_backup;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->keepalive->inflight     = 1;
  state->keepalive->ts_deadline -= g_clock-1L;
  FD_TEST( fd_bundle_client_status( state )==0 );
  *state = state_backup;

  FD_TEST( fd_bundle_client_status( state )==2 );
  state->grpc_client->h2_hs_done = 0;
  FD_TEST( fd_bundle_client_status( state )==1 );
  *state->grpc_client = client_backup;

  test_bundle_env_destroy( env );
}

/* Verify that reset clears everything */

static void
test_bundle_client_reset( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * state = env->state;

  FD_TEST( state->tcp_sock!=-1 );
  FD_TEST( state->tcp_sock_connected==1 );
  FD_TEST( state->defer_reset==0 );
  FD_TEST( state->builder_info_avail==1 );
  FD_TEST( state->builder_info_wait==0 );
  FD_TEST( state->packet_subscription_live==1 );
  FD_TEST( state->packet_subscription_wait==0 );
  FD_TEST( state->bundle_subscription_live==1 );
  FD_TEST( state->bundle_subscription_wait==0 );
  FD_TEST( state->rtt->is_rtt_valid==0 );
  FD_TEST( state->auther.state==FD_BUNDLE_AUTH_STATE_DONE_WAIT );
  FD_TEST( state->auther.needs_poll==0 );
  FD_TEST( state->grpc_client->ssl_hs_done==0 );
  FD_TEST( state->grpc_client->h2_hs_done==1 );
  FD_TEST( state->grpc_client->stream_cnt==2 );

  fd_bundle_client_reset( state );

  FD_TEST( state->tcp_sock==-1 );
  FD_TEST( state->tcp_sock_connected==0 );
  FD_TEST( state->defer_reset==0 );
  FD_TEST( state->builder_info_avail==0 );
  FD_TEST( state->builder_info_wait==0 );
  FD_TEST( state->packet_subscription_live==0 );
  FD_TEST( state->packet_subscription_wait==0 );
  FD_TEST( state->bundle_subscription_live==0 );
  FD_TEST( state->bundle_subscription_wait==0 );
  FD_TEST( state->rtt->is_rtt_valid==0 );
  FD_TEST( state->auther.state==FD_BUNDLE_AUTH_STATE_REQ_CHALLENGE );
  FD_TEST( state->auther.needs_poll==1 );
  FD_TEST( state->grpc_client->ssl_hs_done==0 );
  FD_TEST( state->grpc_client->h2_hs_done==0 );
  FD_TEST( state->grpc_client->stream_cnt==0 );

  test_bundle_env_destroy( env );
}

/* Utility to parse a request header */

static void
expect_h2_hdr( fd_h2_rbuf_t *       rbuf,
               ulong                stream_id,
               char const * const * pstr ) {
  fd_h2_frame_hdr_t frame_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( rbuf )>=sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_pop_copy( rbuf, &frame_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_HEADERS );
  FD_TEST( fd_uint_bswap( frame_hdr.r_stream_id )==stream_id );
  FD_TEST( frame_hdr.flags==FD_H2_FLAG_END_HEADERS );

  uchar frame_body[ 512 ];
  ulong frame_sz = fd_h2_frame_length( frame_hdr.typlen );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf )>=frame_sz );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf )<=sizeof(frame_body) );
  fd_h2_rbuf_pop_copy( rbuf, frame_body, frame_sz );

  fd_hpack_rd_t hpack_rd[1];
  FD_TEST( fd_hpack_rd_init( hpack_rd, frame_body, frame_sz ) );

  while( *pstr ) {
    char const * exp_name = *(pstr++);
    char const * exp_val  = *(pstr++);
    fd_h2_hdr_t hdr;
    uchar scratch[ 128 ];
    uchar * pscratch = scratch;
    FD_TEST( !fd_hpack_rd_done( hpack_rd ) );
    FD_TEST( fd_hpack_rd_next( hpack_rd, &hdr, &pscratch, scratch+sizeof(scratch) )==FD_H2_SUCCESS );

    FD_LOG_DEBUG(( "Header: %.*s: %.*s",
                   (int)hdr.name_len,  hdr.name,
                   (int)hdr.value_len, hdr.value ));
    FD_TEST( hdr.name_len ==strlen( exp_name ) && 0==memcmp( hdr.name, exp_name, hdr.name_len  ) );
    FD_TEST( hdr.value_len==strlen( exp_val  ) && 0==memcmp( hdr.value, exp_val, hdr.value_len ) );
  }
  FD_TEST( fd_hpack_rd_done( hpack_rd ) );
}

/* Verify that the client requests builder fee info */

static void
test_bundle_client_request_builder_fee_info( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state       = env->state;
  fd_grpc_client_t * const grpc_client = state->grpc_client;

  /* Client should request new builder info */
  state->builder_info_avail = 0;
  FD_TEST( state->builder_info_wait==0 );

  /* But it's blocked on stream count ... */
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==0 );
  FD_TEST( state->grpc_client->stream_cnt==2 );
  state->grpc_client->conn->peer_settings.max_concurrent_streams = 2;
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==1 );
  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->builder_info_wait==0 );

  /* Unblock it ... */
  state->grpc_client->conn->peer_settings.max_concurrent_streams = 3;
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==0 );
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->builder_info_wait==1 );

  /* Get newly created stream */
  FD_TEST( !grpc_client->request_stream ); /* request instantly flushed */
  ulong const stream_id = state->grpc_client->stream_ids[ 2 ];
  fd_grpc_h2_stream_t * stream = &state->grpc_client->stream_pool[ 2 ];
  FD_TEST( stream->s.stream_id==stream_id );
  FD_TEST( stream->request_ctx==FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );

  /* Request header */
  char const * const hdrs[] = {
    ":method",      "POST",
    ":scheme",      "https",
    ":path",        "/block_engine.BlockEngineValidator/GetBlockBuilderFeeInfo",
    "te",           "trailers",
    "content-type", "application/grpc+proto",
    "user-agent",   "grpc-firedancer/0.0.0",
    NULL
  };
  expect_h2_hdr( grpc_client->frame_tx, stream_id, hdrs );

  /* Request body */
  fd_h2_frame_hdr_t frame_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )>=sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &frame_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_DATA );
  FD_TEST( fd_h2_frame_length( frame_hdr.typlen )==5UL );
  FD_TEST( fd_uint_bswap( frame_hdr.r_stream_id )==stream_id );
  FD_TEST( frame_hdr.flags==FD_H2_FLAG_END_STREAM );
  fd_grpc_hdr_t grpc_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )>=sizeof(fd_grpc_hdr_t) );
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &grpc_hdr, sizeof(fd_grpc_hdr_t) );
  FD_TEST( grpc_hdr.compressed==0 );
  FD_TEST( grpc_hdr.msg_sz==0 );

  /* Inject a response */
  fd_bundle_client_grpc_rx_start( state, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );

  uchar prev_builder_pubkey[ 32 ];
  for( ulong i=0UL; i<sizeof(prev_builder_pubkey); i++ ) prev_builder_pubkey[ i ] = (uchar)( i + 1U );
  fd_memcpy( state->builder_pubkey, prev_builder_pubkey, sizeof(prev_builder_pubkey) );
  uchar prev_builder_commission = 11U;
  state->builder_commission = prev_builder_commission;
  long prev_builder_valid_until = 123456789L;
  state->builder_info_valid_until = prev_builder_valid_until;

  /* Protobuf encoder util */
  uchar pb_buf[ 128 ];
  ulong pb_sz = 0UL;
  block_engine_BlockBuilderFeeInfoResponse resp = block_engine_BlockBuilderFeeInfoResponse_init_default;
#define ENCODE_MSG() do { \
    pb_ostream_t ostream = pb_ostream_from_buffer( pb_buf, sizeof(pb_buf) ); \
    FD_TEST( pb_encode( &ostream, &block_engine_BlockBuilderFeeInfoResponse_msg, &resp ) ); \
    pb_sz = ostream.bytes_written; \
  } while(0)

  /* Invalid Base58 */
  strcpy( resp.pubkey, "hello" );
  resp.commission = 2;
  ENCODE_MSG();
  fd_bundle_client_grpc_rx_msg( state, pb_buf, pb_sz, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );
  FD_TEST( state->builder_info_avail==0 );
  FD_TEST( state->builder_info_wait==1 ); /* retry ... */
  FD_TEST( state->builder_commission==prev_builder_commission );
  FD_TEST( 0==memcmp( state->builder_pubkey, prev_builder_pubkey, sizeof(prev_builder_pubkey) ) );
  FD_TEST( state->builder_info_valid_until==prev_builder_valid_until );

  /* Invalid commission */
  uchar const pubkey[32] = { 1,2,3,4,5 };
  fd_base58_encode_32( pubkey, NULL, resp.pubkey );
  resp.commission = 101;
  ENCODE_MSG();
  fd_bundle_client_grpc_rx_msg( state, pb_buf, pb_sz, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );
  FD_TEST( state->builder_info_avail==0 );
  FD_TEST( state->builder_info_wait==1 ); /* retry ... */
  FD_TEST( state->builder_commission==prev_builder_commission );
  FD_TEST( 0==memcmp( state->builder_pubkey, prev_builder_pubkey, sizeof(prev_builder_pubkey) ) );
  FD_TEST( state->builder_info_valid_until==prev_builder_valid_until );

  /* Valid response */
  resp.commission = 2;
  ENCODE_MSG();
  fd_bundle_client_grpc_rx_msg( state, pb_buf, pb_sz, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo );
  FD_TEST( state->builder_info_avail==1 );
  FD_TEST( state->builder_info_wait==1 );
  FD_TEST( state->builder_commission==2U );
  uchar decoded_builder_pubkey[ 32 ];
  FD_TEST( fd_base58_decode_32( resp.pubkey, decoded_builder_pubkey ) );
  FD_TEST( 0==memcmp( state->builder_pubkey, decoded_builder_pubkey, sizeof(decoded_builder_pubkey) ) );
  FD_TEST( state->builder_info_valid_until!=prev_builder_valid_until );

  /* End stream */
  fd_grpc_resp_hdrs_t grpc_resp_hdrs = {
    .h2_status   = 200,
    .grpc_status = FD_GRPC_STATUS_OK
  };
  fd_bundle_client_grpc_rx_end( state, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo, &grpc_resp_hdrs );
  FD_TEST( state->builder_info_wait==0 );

#undef ENCODE_MSG

  test_bundle_env_destroy( env );
}

/* Verify that the client subscribes to packets */

static void
test_bundle_client_subscribe_packets( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state       = env->state;
  fd_grpc_client_t * const grpc_client = state->grpc_client;

  state->packet_subscription_live = 0;
  FD_TEST( state->packet_subscription_wait==0 );

  /* But it's blocked on stream count ... */
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==0 );
  FD_TEST( state->grpc_client->stream_cnt==2 );
  state->grpc_client->conn->peer_settings.max_concurrent_streams = 2;
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==1 );
  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->packet_subscription_wait==0 );

  /* Unblock it ... */
  state->grpc_client->conn->peer_settings.max_concurrent_streams = 3;
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==0 );
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->packet_subscription_wait==1 );

  /* Get newly created stream */
  FD_TEST( !grpc_client->request_stream ); /* request instantly flushed */
  ulong const stream_id = state->grpc_client->stream_ids[ 2 ];
  fd_grpc_h2_stream_t * stream = &state->grpc_client->stream_pool[ 2 ];
  FD_TEST( stream->s.stream_id==stream_id );
  FD_TEST( stream->request_ctx==FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets );

  /* Request header */
  char const * const hdrs[] = {
    ":method",      "POST",
    ":scheme",      "https",
    ":path",        "/block_engine.BlockEngineValidator/SubscribePackets",
    "te",           "trailers",
    "content-type", "application/grpc+proto",
    "user-agent",   "grpc-firedancer/0.0.0",
    NULL
  };
  expect_h2_hdr( grpc_client->frame_tx, stream_id, hdrs );

  /* Request body */
  fd_h2_frame_hdr_t frame_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )>=sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &frame_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_DATA );
  FD_TEST( fd_h2_frame_length( frame_hdr.typlen )==5UL );
  FD_TEST( fd_uint_bswap( frame_hdr.r_stream_id )==stream_id );
  FD_TEST( frame_hdr.flags==FD_H2_FLAG_END_STREAM );
  fd_grpc_hdr_t grpc_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )>=sizeof(fd_grpc_hdr_t) );
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &grpc_hdr, sizeof(fd_grpc_hdr_t) );
  FD_TEST( grpc_hdr.compressed==0 );
  FD_TEST( grpc_hdr.msg_sz==0 );

  /* Inject a response */
  FD_TEST( state->packet_subscription_wait==1 );
  fd_bundle_client_grpc_rx_start( state, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets );
  FD_TEST( state->packet_subscription_wait==0 );

  test_bundle_env_destroy( env );
}

/* Verify that the client subscribes to bundles */

static void
test_bundle_client_subscribe_bundles( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * const state       = env->state;
  fd_grpc_client_t * const grpc_client = state->grpc_client;

  state->bundle_subscription_live = 0;
  FD_TEST( state->bundle_subscription_wait==0 );

  /* But it's blocked on stream count ... */
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==0 );
  FD_TEST( state->grpc_client->stream_cnt==2 );
  state->grpc_client->conn->peer_settings.max_concurrent_streams = 2;
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==1 );
  int charge_busy = 0;
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->bundle_subscription_wait==0 );

  /* Unblock it ... */
  state->grpc_client->conn->peer_settings.max_concurrent_streams = 3;
  FD_TEST( fd_grpc_client_request_is_blocked( state->grpc_client )==0 );
  fd_bundle_client_step( state, &charge_busy );
  FD_TEST( state->bundle_subscription_wait==1 );

  /* Get newly created stream */
  FD_TEST( !grpc_client->request_stream ); /* request instantly flushed */
  ulong const stream_id = state->grpc_client->stream_ids[ 2 ];
  fd_grpc_h2_stream_t * stream = &state->grpc_client->stream_pool[ 2 ];
  FD_TEST( stream->s.stream_id==stream_id );
  FD_TEST( stream->request_ctx==FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );

  /* Request header */
  char const * const hdrs[] = {
    ":method",      "POST",
    ":scheme",      "https",
    ":path",        "/block_engine.BlockEngineValidator/SubscribeBundles",
    "te",           "trailers",
    "content-type", "application/grpc+proto",
    "user-agent",   "grpc-firedancer/0.0.0",
    NULL
  };
  expect_h2_hdr( grpc_client->frame_tx, stream_id, hdrs );

  /* Request body */
  fd_h2_frame_hdr_t frame_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )>=sizeof(fd_h2_frame_hdr_t) );
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &frame_hdr, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_DATA );
  FD_TEST( fd_h2_frame_length( frame_hdr.typlen )==5UL );
  FD_TEST( fd_uint_bswap( frame_hdr.r_stream_id )==stream_id );
  FD_TEST( frame_hdr.flags==FD_H2_FLAG_END_STREAM );
  fd_grpc_hdr_t grpc_hdr;
  FD_TEST( fd_h2_rbuf_used_sz( grpc_client->frame_tx )>=sizeof(fd_grpc_hdr_t) );
  fd_h2_rbuf_pop_copy( grpc_client->frame_tx, &grpc_hdr, sizeof(fd_grpc_hdr_t) );
  FD_TEST( grpc_hdr.compressed==0 );
  FD_TEST( grpc_hdr.msg_sz==0 );

  /* Inject a response */
  FD_TEST( state->bundle_subscription_wait==1 );
  fd_bundle_client_grpc_rx_start( state, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  FD_TEST( state->bundle_subscription_wait==0 );

  test_bundle_env_destroy( env );
}

#define TEST_STEM_BURST (5UL)

typedef struct {
  uchar const * payload;
  ulong         payload_sz;
} test_packet_desc_t;

typedef struct {
  test_packet_desc_t const * packets;
  ulong                      packet_cnt;
} test_packet_list_t;

typedef struct {
  test_packet_desc_t const * packets;
  ulong                      packet_cnt;
  uchar                      uuid[ 16 ];
  ulong                      uuid_sz;
} test_bundle_desc_t;

typedef struct {
  test_bundle_desc_t const * bundles;
  ulong                      bundle_cnt;
} test_bundle_list_t;

static bool
encode_test_packet_list( pb_ostream_t *     stream,
                         pb_field_t const * field,
                         void * const *     arg ) {
  test_packet_list_t const * packet_list = *arg;

  for( ulong i=0UL; i<packet_list->packet_cnt; i++ ) {
    test_packet_desc_t const * desc = &packet_list->packets[ i ];
    packet_Packet packet = packet_Packet_init_default;
    FD_TEST( desc->payload_sz<=sizeof(packet.data.bytes) );
    packet.data.size = (pb_size_t)desc->payload_sz;
    fd_memcpy( packet.data.bytes, desc->payload, desc->payload_sz );

    if( FD_UNLIKELY( !pb_encode_tag_for_field( stream, field ) ) ) return false;
    if( FD_UNLIKELY( !pb_encode_submessage( stream, &packet_Packet_msg, &packet ) ) ) return false;
  }

  return true;
}

static bool
encode_test_bundle_list( pb_ostream_t *     stream,
                         pb_field_t const * field,
                         void * const *     arg ) {
  test_bundle_list_t const * bundle_list = *arg;

  for( ulong i=0UL; i<bundle_list->bundle_cnt; i++ ) {
    test_bundle_desc_t const * desc = &bundle_list->bundles[ i ];
    test_packet_list_t packet_list = {
      .packets    = desc->packets,
      .packet_cnt = desc->packet_cnt,
    };
    bundle_BundleUuid bundle_uuid = bundle_BundleUuid_init_default;
    bundle_uuid.has_bundle = true;
    bundle_uuid.bundle.packets = (pb_callback_t) {
      .funcs.encode = encode_test_packet_list,
      .arg          = &packet_list,
    };
    FD_TEST( desc->uuid_sz<=sizeof(bundle_uuid.uuid.bytes) );
    bundle_uuid.uuid.size = (pb_size_t)desc->uuid_sz;
    fd_memcpy( bundle_uuid.uuid.bytes, desc->uuid, desc->uuid_sz );

    if( FD_UNLIKELY( !pb_encode_tag_for_field( stream, field ) ) ) return false;
    if( FD_UNLIKELY( !pb_encode_submessage( stream, &bundle_BundleUuid_msg, &bundle_uuid ) ) ) return false;
  }

  return true;
}

static ulong
encode_subscribe_packets_response( uchar const *          payload_buf,
                                   ulong                  payload_buf_sz,
                                   test_packet_desc_t *   packets,
                                   ulong                  packet_cnt ) {
  block_engine_SubscribePacketsResponse resp = block_engine_SubscribePacketsResponse_init_default;
  test_packet_list_t packet_list = {
    .packets    = packets,
    .packet_cnt = packet_cnt,
  };
  resp.has_batch = true;
  resp.batch.packets = (pb_callback_t) {
    .funcs.encode = encode_test_packet_list,
    .arg          = &packet_list,
  };

  pb_ostream_t ostream = pb_ostream_from_buffer( (pb_byte_t *)payload_buf, payload_buf_sz );
  FD_TEST( pb_encode( &ostream, &block_engine_SubscribePacketsResponse_msg, &resp ) );
  return ostream.bytes_written;
}

static ulong
encode_subscribe_bundles_response( uchar const *          payload_buf,
                                   ulong                  payload_buf_sz,
                                   test_bundle_desc_t *   bundles,
                                   ulong                  bundle_cnt ) {
  block_engine_SubscribeBundlesResponse resp = block_engine_SubscribeBundlesResponse_init_default;
  test_bundle_list_t bundle_list = {
    .bundles    = bundles,
    .bundle_cnt = bundle_cnt,
  };
  resp.bundles = (pb_callback_t) {
    .funcs.encode = encode_test_bundle_list,
    .arg          = &bundle_list,
  };

  pb_ostream_t ostream = pb_ostream_from_buffer( (pb_byte_t *)payload_buf, payload_buf_sz );
  FD_TEST( pb_encode( &ostream, &block_engine_SubscribeBundlesResponse_msg, &resp ) );
  return ostream.bytes_written;
}

static ulong
published_txn_cnt( test_bundle_env_t const * env ) {
  return env->stem_seqs[ 0 ];
}

static fd_txn_m_t const *
published_txn( test_bundle_env_t const *  env,
               ulong                      seq,
               fd_frag_meta_t const **    opt_meta ) {
  FD_TEST( seq<published_txn_cnt( env ) );
  fd_frag_meta_t const * meta = env->out_mcache + fd_mcache_line_idx( seq, env->stem_depths[ 0 ] );
  FD_TEST( meta->seq==seq );
  if( opt_meta ) *opt_meta = meta;
  return (fd_txn_m_t const *)fd_chunk_to_laddr( env->out_dcache, meta->chunk );
}

static void
expect_published_txn( test_bundle_env_t const * env,
                      ulong                     seq,
                      ulong                     sig,
                      uchar const *             payload,
                      ulong                     payload_sz,
                      ulong                     bundle_id,
                      ulong                     bundle_txn_cnt,
                      uchar                     commission,
                      uchar const *             commission_pubkey ) {
  fd_frag_meta_t const * meta = NULL;
  fd_txn_m_t const * txnm = published_txn( env, seq, &meta );

  FD_TEST( meta->sig==sig );
  FD_TEST( txnm->payload_sz==payload_sz );
  FD_TEST( txnm->txn_t_sz==0U );
  FD_TEST( txnm->source_tpu==FD_TXN_M_TPU_SOURCE_BUNDLE );
  FD_TEST( txnm->block_engine.bundle_id==bundle_id );
  FD_TEST( txnm->block_engine.bundle_txn_cnt==bundle_txn_cnt );
  FD_TEST( txnm->block_engine.commission==commission );
  FD_TEST( 0==memcmp( txnm->block_engine.commission_pubkey, commission_pubkey, 32UL ) );
  FD_TEST( 0==memcmp( fd_txn_m_payload_const( txnm ), payload, payload_sz ) );
}

/* Mirror the production after_credit publish loop so tests can verify
   actual published output without exposing the static callback. */

static ulong
publish_after_credit( fd_bundle_tile_t * state ) {
  if( pending_txn_empty( state->pending_txns ) ) return 0UL;

  fd_stem_context_t * stem = state->stem;
  fd_bundle_pending_txn_t * head = pending_txn_peek_head( state->pending_txns );
  ulong drain_seq = head->bundle_seq;
  ulong drain_sig = head->sig;
  ulong drain_cnt = 0UL;

  do {
    fd_bundle_pending_txn_t const * txn = pending_txn_peek_head( state->pending_txns );

    fd_txn_m_t * txnm = fd_chunk_to_laddr( state->verify_out.mem, state->verify_out.chunk );
    *txnm = (fd_txn_m_t) {
      .reference_slot = 0UL,
      .payload_sz     = txn->payload_sz,
      .txn_t_sz       = 0U,
      .source_ipv4    = txn->source_ipv4,
      .source_tpu     = FD_TXN_M_TPU_SOURCE_BUNDLE,
      .block_engine   = {
        .bundle_id      = txn->bundle_seq,
        .bundle_txn_cnt = txn->bundle_txn_cnt,
        .commission     = txn->commission,
      },
    };
    fd_memcpy( txnm->block_engine.commission_pubkey, txn->commission_pubkey, 32UL );
    fd_memcpy( fd_txn_m_payload( txnm ), txn->payload, txn->payload_sz );

    ulong sz    = fd_txn_m_realized_footprint( txnm, 0, 0 );
    ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_bundle_now() );
    fd_stem_publish( stem, state->verify_out.idx, txn->sig, state->verify_out.chunk, sz, 0UL, 0UL, tspub );
    state->verify_out.chunk = fd_dcache_compact_next( state->verify_out.chunk, sz, state->verify_out.chunk0, state->verify_out.wmark );

    pending_txn_remove_head( state->pending_txns );
    drain_cnt++;
  } while( fd_bundle_drain_continue( state->pending_txns, drain_sig, drain_seq, drain_cnt, TEST_STEM_BURST ) );

  return drain_cnt;
}

/* Simulate after_credit drain using the same continuation logic as
   production (fd_bundle_drain_continue). */

static ulong
drain_one_bundle( fd_bundle_pending_txn_t * deque ) {
  if( pending_txn_empty( deque ) ) return 0UL;

  fd_bundle_pending_txn_t * head = pending_txn_peek_head( deque );
  ulong drain_seq = head->bundle_seq;
  ulong drain_sig = head->sig;
  ulong cnt = 0UL;

  do {
    pending_txn_pop_head( deque );
    cnt++;
  } while( fd_bundle_drain_continue( deque, drain_sig, drain_seq, cnt, TEST_STEM_BURST ) );

  return cnt;
}

/* Verify that the drain logic publishes one complete bundle
   atomically, stopping at bundle boundaries. */

static void
test_packet_publish_after_credit( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;

  uchar const payload0[] = { 0x48 };
  uchar const payload1[] = { 0xAA, 0xBB };
  test_packet_desc_t packets[] = {
    { .payload=payload0, .payload_sz=sizeof(payload0) },
    { .payload=payload1, .payload_sz=sizeof(payload1) },
  };
  uchar pb_buf[ 256 ];
  ulong pb_sz = encode_subscribe_packets_response( pb_buf, sizeof(pb_buf), packets, 2UL );

  fd_bundle_client_grpc_rx_msg(
      state,
      pb_buf, pb_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==2UL );
  FD_TEST( published_txn_cnt( env )==0UL );

  uchar const zero_pubkey[ 32 ] = {0};
  FD_TEST( publish_after_credit( state )==2UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );
  FD_TEST( published_txn_cnt( env )==2UL );
  expect_published_txn( env, 0UL, 0UL, payload0, sizeof(payload0), 0UL, 1UL, 0U, zero_pubkey );
  expect_published_txn( env, 1UL, 0UL, payload1, sizeof(payload1), 0UL, 1UL, 0U, zero_pubkey );

  test_bundle_env_destroy( env );
}

/* Verify that bundles publish atomically: one full bundle per
   after_credit-style drain, never crossing into the next bundle. */

static void
test_packet_publish_after_credit_atomic( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->builder_info_avail  = 1;
  state->builder_commission  = 7U;
  uchar builder_pubkey[ 32 ];
  for( ulong i=0UL; i<32UL; i++ ) builder_pubkey[ i ] = (uchar)( i + 1U );
  fd_memcpy( state->builder_pubkey, builder_pubkey, sizeof(builder_pubkey) );

  uchar const bundle_a0[] = { 0xA0 };
  uchar const bundle_a1[] = { 0xA1 };
  uchar const bundle_a2[] = { 0xA2 };
  uchar const bundle_b0[] = { 0xB0 };
  uchar const bundle_b1[] = { 0xB1 };
  test_packet_desc_t bundle_a[] = {
    { .payload=bundle_a0, .payload_sz=sizeof(bundle_a0) },
    { .payload=bundle_a1, .payload_sz=sizeof(bundle_a1) },
    { .payload=bundle_a2, .payload_sz=sizeof(bundle_a2) },
  };
  test_packet_desc_t bundle_b[] = {
    { .payload=bundle_b0, .payload_sz=sizeof(bundle_b0) },
    { .payload=bundle_b1, .payload_sz=sizeof(bundle_b1) },
  };
  test_bundle_desc_t bundles[] = {
    { .packets=bundle_a, .packet_cnt=3UL, .uuid={1,2,3}, .uuid_sz=3UL },
    { .packets=bundle_b, .packet_cnt=2UL, .uuid={4,5,6}, .uuid_sz=3UL },
  };
  uchar pb_buf[ 512 ];
  ulong pb_sz = encode_subscribe_bundles_response( pb_buf, sizeof(pb_buf), bundles, 2UL );

  fd_bundle_client_grpc_rx_msg(
      state,
      pb_buf, pb_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==5UL );
  FD_TEST( published_txn_cnt( env )==0UL );

  FD_TEST( publish_after_credit( state )==3UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==2UL );
  FD_TEST( pending_txn_peek_head( state->pending_txns )->bundle_seq==2UL );
  expect_published_txn( env, 0UL, 1UL, bundle_a0, sizeof(bundle_a0), 1UL, 3UL, 7U, builder_pubkey );
  expect_published_txn( env, 1UL, 1UL, bundle_a1, sizeof(bundle_a1), 1UL, 3UL, 7U, builder_pubkey );
  expect_published_txn( env, 2UL, 1UL, bundle_a2, sizeof(bundle_a2), 1UL, 3UL, 7U, builder_pubkey );

  FD_TEST( publish_after_credit( state )==2UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );
  FD_TEST( published_txn_cnt( env )==5UL );
  expect_published_txn( env, 3UL, 1UL, bundle_b0, sizeof(bundle_b0), 2UL, 2UL, 7U, builder_pubkey );
  expect_published_txn( env, 4UL, 1UL, bundle_b1, sizeof(bundle_b1), 2UL, 2UL, 7U, builder_pubkey );

  test_bundle_env_destroy( env );
}

/* Bundles are all-or-nothing at the head of the queue: after_credit
   must publish the entire bundle before touching following packets. */

static void
test_bundle_publish_all_or_nothing( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->builder_info_avail = 1;

  uchar const b0[] = { 0x10 };
  uchar const b1[] = { 0x11 };
  uchar const b2[] = { 0x12 };
  uchar const b3[] = { 0x13 };
  uchar const b4[] = { 0x14 };
  uchar const pkt[] = { 0x99 };
  test_packet_desc_t bundle_packets[] = {
    { .payload=b0, .payload_sz=sizeof(b0) },
    { .payload=b1, .payload_sz=sizeof(b1) },
    { .payload=b2, .payload_sz=sizeof(b2) },
    { .payload=b3, .payload_sz=sizeof(b3) },
    { .payload=b4, .payload_sz=sizeof(b4) },
  };
  test_bundle_desc_t bundles[] = {
    { .packets=bundle_packets, .packet_cnt=5UL, .uuid={7,7,7}, .uuid_sz=3UL },
  };
  test_packet_desc_t trailing_packet[] = {
    { .payload=pkt, .payload_sz=sizeof(pkt) },
  };
  uchar bundle_buf[ 512 ];
  uchar packet_buf[ 128 ];
  ulong bundle_sz = encode_subscribe_bundles_response( bundle_buf, sizeof(bundle_buf), bundles, 1UL );
  ulong packet_sz = encode_subscribe_packets_response( packet_buf, sizeof(packet_buf), trailing_packet, 1UL );

  fd_bundle_client_grpc_rx_msg(
      state,
      bundle_buf, bundle_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );
  fd_bundle_client_grpc_rx_msg(
      state,
      packet_buf, packet_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==6UL );
  FD_TEST( publish_after_credit( state )==5UL );
  FD_TEST( published_txn_cnt( env )==5UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==1UL );
  FD_TEST( pending_txn_peek_head( state->pending_txns )->sig==0UL );

  uchar const zero_pubkey[ 32 ] = {0};
  expect_published_txn( env, 0UL, 1UL, b0, sizeof(b0), 1UL, 5UL, 0U, zero_pubkey );
  expect_published_txn( env, 1UL, 1UL, b1, sizeof(b1), 1UL, 5UL, 0U, zero_pubkey );
  expect_published_txn( env, 2UL, 1UL, b2, sizeof(b2), 1UL, 5UL, 0U, zero_pubkey );
  expect_published_txn( env, 3UL, 1UL, b3, sizeof(b3), 1UL, 5UL, 0U, zero_pubkey );
  expect_published_txn( env, 4UL, 1UL, b4, sizeof(b4), 1UL, 5UL, 0U, zero_pubkey );

  FD_TEST( publish_after_credit( state )==1UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );
  expect_published_txn( env, 5UL, 0UL, pkt, sizeof(pkt), 0UL, 1UL, 0U, zero_pubkey );

  test_bundle_env_destroy( env );
}

/* Verify queue boundary behavior with mixed packets and bundles. */

static void
test_mixed_queue_boundary_behavior( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->builder_info_avail = 1;

  uchar const p0[] = { 0x20 };
  uchar const p1[] = { 0x21 };
  uchar const p2[] = { 0x22 };
  uchar const p3[] = { 0x23 };
  uchar const b0[] = { 0x30 };
  uchar const b1[] = { 0x31 };
  uchar const p4[] = { 0x24 };
  uchar const p5[] = { 0x25 };
  test_packet_desc_t leading_packets[] = {
    { .payload=p0, .payload_sz=sizeof(p0) },
    { .payload=p1, .payload_sz=sizeof(p1) },
    { .payload=p2, .payload_sz=sizeof(p2) },
    { .payload=p3, .payload_sz=sizeof(p3) },
  };
  test_packet_desc_t bundle_packets[] = {
    { .payload=b0, .payload_sz=sizeof(b0) },
    { .payload=b1, .payload_sz=sizeof(b1) },
  };
  test_bundle_desc_t bundles[] = {
    { .packets=bundle_packets, .packet_cnt=2UL, .uuid={9,9,9}, .uuid_sz=3UL },
  };
  test_packet_desc_t trailing_packets[] = {
    { .payload=p4, .payload_sz=sizeof(p4) },
    { .payload=p5, .payload_sz=sizeof(p5) },
  };
  uchar packet_buf0[ 256 ];
  uchar bundle_buf [ 256 ];
  uchar packet_buf1[ 256 ];
  ulong packet_sz0 = encode_subscribe_packets_response( packet_buf0, sizeof(packet_buf0), leading_packets, 4UL );
  ulong bundle_sz  = encode_subscribe_bundles_response( bundle_buf, sizeof(bundle_buf), bundles, 1UL );
  ulong packet_sz1 = encode_subscribe_packets_response( packet_buf1, sizeof(packet_buf1), trailing_packets, 2UL );

  fd_bundle_client_grpc_rx_msg( state, packet_buf0, packet_sz0, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets );
  fd_bundle_client_grpc_rx_msg( state, bundle_buf,  bundle_sz,  FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles );
  fd_bundle_client_grpc_rx_msg( state, packet_buf1, packet_sz1, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets );

  uchar const zero_pubkey[ 32 ] = {0};
  FD_TEST( pending_txn_cnt( state->pending_txns )==8UL );

  FD_TEST( publish_after_credit( state )==4UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==4UL );
  expect_published_txn( env, 0UL, 0UL, p0, sizeof(p0), 0UL, 1UL, 0U, zero_pubkey );
  expect_published_txn( env, 1UL, 0UL, p1, sizeof(p1), 0UL, 1UL, 0U, zero_pubkey );
  expect_published_txn( env, 2UL, 0UL, p2, sizeof(p2), 0UL, 1UL, 0U, zero_pubkey );
  expect_published_txn( env, 3UL, 0UL, p3, sizeof(p3), 0UL, 1UL, 0U, zero_pubkey );

  FD_TEST( publish_after_credit( state )==2UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==2UL );
  expect_published_txn( env, 4UL, 1UL, b0, sizeof(b0), 1UL, 2UL, 0U, zero_pubkey );
  expect_published_txn( env, 5UL, 1UL, b1, sizeof(b1), 1UL, 2UL, 0U, zero_pubkey );

  FD_TEST( publish_after_credit( state )==2UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );
  expect_published_txn( env, 6UL, 0UL, p4, sizeof(p4), 0UL, 1UL, 0U, zero_pubkey );
  expect_published_txn( env, 7UL, 0UL, p5, sizeof(p5), 0UL, 1UL, 0U, zero_pubkey );

  test_bundle_env_destroy( env );
}

/* Messages are only buffered by grpc_rx_msg. Nothing should hit the
   output link until after_credit runs. */

static void
test_no_publish_before_after_credit( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->builder_info_avail = 1;

  uchar const packet_payload[] = { 0x55 };
  uchar const bundle_payload0[] = { 0x66 };
  uchar const bundle_payload1[] = { 0x67 };
  test_packet_desc_t packets[] = {
    { .payload=packet_payload, .payload_sz=sizeof(packet_payload) },
  };
  test_packet_desc_t bundle_packets[] = {
    { .payload=bundle_payload0, .payload_sz=sizeof(bundle_payload0) },
    { .payload=bundle_payload1, .payload_sz=sizeof(bundle_payload1) },
  };
  test_bundle_desc_t bundles[] = {
    { .packets=bundle_packets, .packet_cnt=2UL, .uuid={5,4,3}, .uuid_sz=3UL },
  };
  uchar packet_buf[ 128 ];
  uchar bundle_buf[ 256 ];
  ulong packet_sz = encode_subscribe_packets_response( packet_buf, sizeof(packet_buf), packets, 1UL );
  ulong bundle_sz = encode_subscribe_bundles_response( bundle_buf, sizeof(bundle_buf), bundles, 1UL );

  fd_bundle_client_grpc_rx_msg(
      state,
      packet_buf, packet_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );
  FD_TEST( pending_txn_cnt( state->pending_txns )==1UL );
  FD_TEST( published_txn_cnt( env )==0UL );

  fd_bundle_client_grpc_rx_msg(
      state,
      bundle_buf, bundle_sz,
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles
  );
  FD_TEST( pending_txn_cnt( state->pending_txns )==3UL );
  FD_TEST( published_txn_cnt( env )==0UL );

  test_bundle_env_destroy( env );
}

static void
test_bundle_drain_atomicity( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->builder_info_avail = 1;

  /* Push bundle A (3 txns, bundle_seq=1) */
  for( ulong i=0; i<3; i++ ) {
    fd_bundle_pending_txn_t entry = { .sig=1UL, .bundle_seq=1UL };
    pending_txn_push_tail( state->pending_txns, entry );
  }

  /* Push bundle B (2 txns, bundle_seq=2) */
  for( ulong i=0; i<2; i++ ) {
    fd_bundle_pending_txn_t entry = { .sig=1UL, .bundle_seq=2UL };
    pending_txn_push_tail( state->pending_txns, entry );
  }

  FD_TEST( pending_txn_cnt( state->pending_txns )==5UL );

  /* First drain: should pop exactly bundle A (3 txns) */
  ulong drained = drain_one_bundle( state->pending_txns );
  FD_TEST( drained==3UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==2UL );
  FD_TEST( pending_txn_peek_head( state->pending_txns )->bundle_seq==2UL );

  /* Second drain: should pop exactly bundle B (2 txns) */
  drained = drain_one_bundle( state->pending_txns );
  FD_TEST( drained==2UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );

  test_bundle_env_destroy( env );
}

/* Verify that individual packets drain up to STEM_BURST per call. */

static void
test_packet_drain_batch( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;

  /* Push 4 packets (< STEM_BURST) -- should drain in one call */
  for( ulong i=0; i<4; i++ ) {
    fd_bundle_pending_txn_t entry = { .sig=0UL, .bundle_seq=0UL };
    pending_txn_push_tail( state->pending_txns, entry );
  }
  FD_TEST( drain_one_bundle( state->pending_txns )==4UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );

  /* Push 8 packets (> STEM_BURST) -- should drain 5 then 3 */
  for( ulong i=0; i<8; i++ ) {
    fd_bundle_pending_txn_t entry = { .sig=0UL, .bundle_seq=0UL };
    pending_txn_push_tail( state->pending_txns, entry );
  }
  FD_TEST( drain_one_bundle( state->pending_txns )==TEST_STEM_BURST );
  FD_TEST( pending_txn_cnt( state->pending_txns )==3UL );
  FD_TEST( drain_one_bundle( state->pending_txns )==3UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );

  test_bundle_env_destroy( env );
}

/* Verify correct drain ordering when bundles and packets are
   interleaved in the deque. */

static void
test_interleaved_drain( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;
  state->builder_info_avail = 1;

  /* packet, bundle(3 txns), packet, packet */
  fd_bundle_pending_txn_t pkt = { .sig=0UL, .bundle_seq=0UL };
  pending_txn_push_tail( state->pending_txns, pkt );

  for( ulong i=0; i<3; i++ ) {
    fd_bundle_pending_txn_t b = { .sig=1UL, .bundle_seq=5UL };
    pending_txn_push_tail( state->pending_txns, b );
  }

  pending_txn_push_tail( state->pending_txns, pkt );
  pending_txn_push_tail( state->pending_txns, pkt );

  FD_TEST( pending_txn_cnt( state->pending_txns )==6UL );

  /* Drain 1: leading packet (1, stops because next entry is a bundle) */
  FD_TEST( drain_one_bundle( state->pending_txns )==1UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==5UL );

  /* Drain 2: bundle (3 txns, same bundle_seq) */
  FD_TEST( drain_one_bundle( state->pending_txns )==3UL );
  FD_TEST( pending_txn_cnt( state->pending_txns )==2UL );

  /* Drain 3: trailing 2 packets batched (2 < STEM_BURST) */
  FD_TEST( drain_one_bundle( state->pending_txns )==2UL );
  FD_TEST( pending_txn_empty( state->pending_txns ) );

  test_bundle_env_destroy( env );
}

/* Verify that the pending_txn_full guard fires and counts drops. */

static void
test_deque_overflow_guard( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  fd_bundle_tile_t * state = env->state;

  ulong cap = pending_txn_max( state->pending_txns );
  for( ulong i=0; i<cap; i++ ) {
    fd_bundle_pending_txn_t entry = {0};
    entry.sig = 0UL;
    pending_txn_push_tail( state->pending_txns, entry );
  }
  FD_TEST( pending_txn_full( state->pending_txns ) );
  FD_TEST( state->metrics.backpressure_drop_cnt==0UL );

  static uchar single_packet_msg[] = {
    0x12, 0x09, 0x0a, 0x07, 0x0a, 0x01, 0x48, 0x12,
    0x02, 0x08, 0x01
  };
  fd_bundle_client_grpc_rx_msg(
      state,
      single_packet_msg, sizeof(single_packet_msg),
      FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets
  );

  FD_TEST( pending_txn_cnt( state->pending_txns )==cap );
  FD_TEST( state->metrics.backpressure_drop_cnt==1UL );

  test_bundle_env_destroy( env );
}

/* Verify that an HTTP error on each request type clears the
   corresponding wait flag so that step_reconnect can retry. */

static void
test_request_failed_clears_wait( fd_wksp_t * wksp ) {
  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn( env );
  fd_bundle_tile_t * state = env->state;

  fd_grpc_resp_hdrs_t hdrs = {
    .h2_status   = 503,
    .grpc_status = FD_GRPC_STATUS_OK
  };

  /* GetBlockBuilderFeeInfo: builder_info_wait should be cleared */
  state->builder_info_wait = 1;
  fd_bundle_client_grpc_rx_end( state, FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo, &hdrs );
  FD_TEST( state->builder_info_wait==0 );

  /* SubscribePackets: packet_subscription_wait should be cleared */
  state->packet_subscription_wait = 1;
  state->packet_subscription_live = 1;
  fd_bundle_client_grpc_rx_end( state, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets, &hdrs );
  FD_TEST( state->packet_subscription_wait==0 );
  FD_TEST( state->packet_subscription_live==0 );

  /* SubscribeBundles: bundle_subscription_wait should be cleared */
  state->bundle_subscription_wait = 1;
  state->bundle_subscription_live = 1;
  fd_bundle_client_grpc_rx_end( state, FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles, &hdrs );
  FD_TEST( state->bundle_subscription_wait==0 );
  FD_TEST( state->bundle_subscription_live==0 );

  test_bundle_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",     NULL, "normal"                     );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",    NULL, 256UL                        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",    NULL, fd_shmem_numa_idx( cpu_idx ) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 16UL );
  FD_TEST( wksp );

  test_bundle_rx( wksp );
  test_bundle_rx_too_many_txns( wksp );
  test_bundle_stream_ended( wksp );
  test_bundle_stream_reset( wksp );
  test_bundle_header_timeout( wksp );
  test_bundle_rx_end_timeout( wksp );
  test_bundle_ping( wksp );
  test_bundle_msg_oversized( wksp );
  test_bundle_keyswitch( wksp );
  test_bundle_client_status( wksp );
  test_bundle_client_reset( wksp );
  test_bundle_no_builder_fee_info( wksp );
  test_bundle_client_request_builder_fee_info( wksp );
  test_bundle_client_subscribe_packets( wksp );
  test_bundle_client_subscribe_bundles( wksp );
  test_packet_publish_after_credit( wksp );
  test_packet_publish_after_credit_atomic( wksp );
  test_bundle_publish_all_or_nothing( wksp );
  test_mixed_queue_boundary_behavior( wksp );
  test_no_publish_before_after_credit( wksp );
  test_bundle_drain_atomicity( wksp );
  test_packet_drain_batch( wksp );
  test_interleaved_drain( wksp );
  test_deque_overflow_guard( wksp );
  test_request_failed_clears_wait( wksp );

  /* Check for memory leaks */
  fd_wksp_usage_t wksp_usage;
  FD_TEST( fd_wksp_usage( wksp, NULL, 0UL, &wksp_usage ) );
  FD_TEST( wksp_usage.free_cnt==wksp_usage.total_cnt );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
