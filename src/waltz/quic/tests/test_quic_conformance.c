/* test_quic_conformance verifies that fd_quic adheres to various
   assertions made in the QUIC specification (RFC 9000). */

#include "fd_quic_sandbox.h"
#include "../fd_quic_proto.h"
#include "../fd_quic_proto.c"
#include "../fd_quic_private.h"
#include "../templ/fd_quic_parse_util.h"
#include "../../tls/fd_tls_proto.h"
#include "../../../disco/metrics/generated/fd_metrics_enums.h"

/* RFC 9000 Section 4.1. Data Flow Control

   > A receiver MUST close the connection with an error of type
   > FLOW_CONTROL_ERROR if the sender violates the advertised connection
   > or stream data limits */

static __attribute__ ((noinline)) void
test_quic_stream_data_limit_enforcement( fd_quic_sandbox_t * sandbox,
                                         fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  sandbox->quic->config.initial_rx_max_stream_data = 1UL;
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->srx->rx_sup_stream_id = (2UL<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  uchar buf[ 1024 ];
  ulong sz = fd_quic_encode_stream_frame(
    buf, buf+sizeof(buf),
    /* stream_id */ FD_QUIC_STREAM_TYPE_UNI_CLIENT,
    /* offset */ 0, /* length */ 2UL, /* fin */ 1 );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
  memset( buf+sz, '0', 2 );
  sz += 2;

  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state  == FD_QUIC_CONN_STATE_ABORT );
  FD_TEST( conn->reason == FD_QUIC_CONN_REASON_FLOW_CONTROL_ERROR );

  /* Test shm log infra */
  fd_frag_meta_t const * log_rec = fd_quic_log_rx_tail( sandbox->log_rx, 0UL );
  FD_TEST( fd_quic_log_sig_event( log_rec->sig )==FD_QUIC_EVENT_CONN_QUIC_CLOSE );
  FD_TEST( log_rec->sz == sizeof(fd_quic_log_error_t) );
  fd_quic_log_error_t const * error = fd_quic_log_rx_data_const( sandbox->log_rx, log_rec->chunk );
  FD_TEST( error->code[0] == FD_QUIC_CONN_REASON_FLOW_CONTROL_ERROR );
  FD_TEST( 0==memcmp( "fd_quic.c\x00", error->src_file, 10 ) );
  FD_LOG_DEBUG(( "Flow control error emitted by %s(%u)", error->src_file, error->src_line ));

}

/* RFC 9000 Section 4.6. Controlling Concurrency

   > Endpoints MUST NOT exceed the limit set by their peer. An endpoint
   > that receives a frame with a stream ID exceeding the limit it has
   > sent MUST treat this as a connection error of type
   > STREAM_LIMIT_ERROR */

static __attribute__ ((noinline)) void
test_quic_stream_limit_enforcement( fd_quic_sandbox_t * sandbox,
                                    fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->srx->rx_sup_stream_id = 0UL + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  uchar buf[ 1024 ];
  ulong sz = fd_quic_encode_stream_frame(
    buf, buf+sizeof(buf),
    /* stream_id */ FD_QUIC_STREAM_TYPE_UNI_CLIENT,
    /* offset */ 0, /* length */ 0UL, /* fin */ 1 );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );

  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state  == FD_QUIC_CONN_STATE_ABORT );
  FD_TEST( conn->reason == FD_QUIC_CONN_REASON_STREAM_LIMIT_ERROR );

  /* Test shm log infra */
  fd_frag_meta_t const * log_rec = fd_quic_log_rx_tail( sandbox->log_rx, 0UL );
  FD_TEST( fd_quic_log_sig_event( log_rec->sig )==FD_QUIC_EVENT_CONN_QUIC_CLOSE );
  fd_quic_log_error_t const * error = fd_quic_log_rx_data_const( sandbox->log_rx, log_rec->chunk );
  FD_TEST( error->code[0] == FD_QUIC_CONN_REASON_STREAM_LIMIT_ERROR );
  FD_TEST( 0==memcmp( "fd_quic.c\x00", error->src_file, 10 ) );
  FD_LOG_DEBUG(( "Stream limit error emitted by %s(%u)", error->src_file, error->src_line ));
}

/* Ensure that worst-case stream pool allocations are bounded.

   This is a custom protocol restriction that goes beyond QUIC's limits. */

static __attribute__ ((noinline)) void
test_quic_stream_concurrency( fd_quic_sandbox_t * sandbox,
                              fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->srx->rx_sup_stream_id = (1024UL<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  // ulong const max_streams = 32UL;

  /* Each frame initiates a new stream without closing it */
  for( ulong j=0UL; j<512UL; j++ ) {
    uchar buf[ 1024 ];
    ulong sz = fd_quic_encode_stream_frame(
      buf, buf+sizeof(buf),
      /* stream_id */ FD_QUIC_STREAM_TYPE_UNI_CLIENT,
      /* offset */ 0, /* length */ 1UL, /* fin */ 0 );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  }

}

/* RFC 9000 Section 19.2. PING Frames */

static __attribute__((noinline)) void
test_quic_ping_frame( fd_quic_sandbox_t * sandbox,
                      fd_rng_t *          rng ) {
  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->ack_gen->is_elicited = 0;
  FD_TEST( conn->svc_type == FD_QUIC_SVC_WAIT );

  uchar buf[1] = {0x01};
  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sizeof(buf) );
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  FD_TEST( conn->ack_gen->is_elicited == 1 );
  FD_TEST( conn->svc_type == FD_QUIC_SVC_ACK_TX );
}

/* Test an ALPN failure when acting as a server */

static __attribute__((noinline)) void
test_quic_server_alpn_fail( fd_quic_sandbox_t * sandbox,
                            fd_rng_t *          rng ) {
  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );

  /* The first CRYPTO frame extracted from an Initial Packet crafted by
     golang.org/x/net/quic v0.30.0 */

  static uchar const crypto_frame[] = {
    0x06, 0x00, 0x40, 0xe0, 0x01, 0x00, 0x00, 0xdc, 0x03, 0x03, 0x4b, 0xf2, 0x76, 0x2e, 0xb7, 0x28,
    0x13, 0x93, 0x43, 0xc0, 0x2a, 0x63, 0x65, 0xa1, 0xe1, 0x19, 0xcf, 0xd6, 0x6d, 0x40, 0xd3, 0x1c,
    0x1f, 0x5a, 0xcf, 0x68, 0x15, 0x29, 0xd1, 0x25, 0xe6, 0xc9, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13,
    0x02, 0x13, 0x03, 0x01, 0x00, 0x00, 0xad, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b,
    0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x1a, 0x00, 0x18, 0x08, 0x04, 0x04, 0x03, 0x08, 0x07,
    0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x05, 0x03, 0x06, 0x03, 0x02, 0x01,
    0x02, 0x03, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
    0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
    0x41, 0xd0, 0x5a, 0xdd, 0x74, 0x7b, 0x0e, 0x05, 0xeb, 0x25, 0xe3, 0x6a, 0x52, 0x30, 0x69, 0x70,
    0x08, 0x93, 0x61, 0x90, 0x81, 0x2c, 0x29, 0x72, 0x6c, 0x8e, 0x52, 0x1e, 0xaa, 0x74, 0x66, 0x7b,
    0x00, 0x39, 0x00, 0x30, 0x03, 0x02, 0x45, 0xc0, 0x04, 0x04, 0x80, 0x10, 0x00, 0x00, 0x05, 0x04,
    0x80, 0x10, 0x00, 0x00, 0x06, 0x04, 0x80, 0x10, 0x00, 0x00, 0x07, 0x04, 0x80, 0x10, 0x00, 0x00,
    0x08, 0x02, 0x40, 0x64, 0x09, 0x02, 0x40, 0x64, 0x0c, 0x00, 0x0f, 0x08, 0x3d, 0xf3, 0x9a, 0xc8,
    0xd7, 0xbd, 0xbd, 0xd4
  };

  /* Bootstrap a connection object, as fd_quic_process_packet would
     construct it upon seeing the Initial Packet header. */

  fd_quic_t *       quic  = sandbox->quic;
  fd_quic_state_t * state = fd_quic_get_state( quic );

  ulong             our_conn_id_u64  = fd_rng_ulong( rng );
  ulong             peer_conn_id_u64 = fd_rng_ulong( rng );
  fd_quic_conn_id_t peer_conn_id     = fd_quic_conn_id_new( &peer_conn_id_u64, 8UL );

  fd_quic_conn_t * conn = fd_quic_conn_create(
      /* quic         */ quic,
      /* our_conn_id  */ our_conn_id_u64,
      /* peer_conn_id */ &peer_conn_id,
      /* dst_ip_addr  */ FD_QUIC_SANDBOX_PEER_IP4,
      /* dst_udp_addr */ FD_QUIC_SANDBOX_PEER_PORT,
      /* src_ip_addr  */ FD_QUIC_SANDBOX_SELF_IP4,
      /* src_udp_addr */ FD_QUIC_SANDBOX_SELF_PORT,
      /* server       */ quic->config.role == FD_QUIC_ROLE_SERVER );
  FD_TEST( conn );

  fd_quic_transport_params_t tp[1] = {0};
  fd_quic_tls_hs_t * tls_hs = fd_quic_tls_hs_new(
      fd_quic_tls_hs_pool_ele_acquire( state->hs_pool ),
      state->tls,
      (void*)conn,
      1 /*is_server*/,
      tp,
      quic->now );
  conn->tls_hs = tls_hs;

  /* Send the TLS handshake message */

  fd_quic_pkt_t pkt = { .enc_level = fd_quic_enc_level_initial_id };
  fd_quic_sandbox_send_frame( sandbox, conn, &pkt, crypto_frame, sizeof(crypto_frame) );

  /* Verify that fd_quic derived the correct error code */

  FD_TEST( conn->state == FD_QUIC_CONN_STATE_ABORT );
  FD_TEST( conn->reason == FD_QUIC_CONN_REASON_CRYPTO_BASE + FD_TLS_ALERT_NO_APPLICATION_PROTOCOL );

  /* Verify that the response looks correct */

  fd_quic_service( quic, sandbox->wallclock );
  fd_frag_meta_t const * frag = fd_quic_sandbox_next_packet( sandbox );
  FD_TEST( frag );

  uchar *       resp_ptr = fd_chunk_to_laddr( sandbox, frag->chunk );
  uchar const * resp_end = resp_ptr + frag->sz;
  resp_ptr += sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t);
  FD_TEST( resp_ptr<resp_end );

  fd_quic_initial_t initial[1];
  ulong hdr_sz = fd_quic_decode_initial( initial, resp_ptr, (ulong)( resp_end-resp_ptr ) );
  FD_TEST( hdr_sz!=FD_QUIC_PARSE_FAIL );
  ulong initial_sz = initial->pkt_num_pnoff + initial->len;
  FD_TEST( resp_ptr+initial_sz <= resp_end );

  FD_TEST( fd_quic_crypto_decrypt_hdr( resp_ptr, initial_sz, initial->pkt_num_pnoff, &conn->keys[0][1] )==FD_QUIC_SUCCESS );
  uint  pkt_number_sz = fd_quic_h0_pkt_num_len( resp_ptr[0] ) + 1u;
  ulong pkt_number    = fd_quic_pktnum_decode( resp_ptr+initial->pkt_num_pnoff, pkt_number_sz );
  FD_TEST( fd_quic_crypto_decrypt( resp_ptr, initial_sz, initial->pkt_num_pnoff, pkt_number, &conn->keys[0][1] )==FD_QUIC_SUCCESS );
  resp_ptr += hdr_sz;

  while( resp_ptr<resp_end && resp_ptr[0]==0x00 ) resp_ptr++;
  FD_TEST( resp_ptr<resp_end );
  FD_TEST( resp_ptr[0]==0x1c ); /* conn_close_0 */
  fd_quic_conn_close_0_frame_t close[1];
  FD_TEST( fd_quic_decode_conn_close_0_frame( close, resp_ptr, (ulong)( resp_end-resp_ptr ) )!=FD_QUIC_PARSE_FAIL );
  FD_TEST( close->error_code == FD_QUIC_CONN_REASON_CRYPTO_BASE + FD_TLS_ALERT_NO_APPLICATION_PROTOCOL );
  FD_TEST( close->frame_type == 0x00 );
  FD_TEST( close->reason_phrase_length == 0x00 );

}

/* Ensure that outgoing ACKs and metrics are done correctly if incoming
   packets skip packet numbers aggressively. */

void
test_quic_pktnum_skip( fd_quic_sandbox_t * sandbox,
                       fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t *    conn    = fd_quic_sandbox_new_conn_established( sandbox, rng );
  fd_quic_ack_gen_t * ack_gen = conn->ack_gen;
  fd_quic_metrics_t * metrics = &conn->quic->metrics;
  FD_TEST( ack_gen->tail==0 && ack_gen->head==0 );

  /* Fill the ACK TX buffer with pending ACK frames */
  ulong pktnum = 60UL;
  for( ulong j=0UL; j<FD_QUIC_ACK_QUEUE_CNT; j++ ) {
    fd_quic_sandbox_send_ping_pkt( sandbox, conn, pktnum );
    pktnum += 2UL;
  }
  FD_TEST( metrics->pkt_decrypt_fail_cnt[ fd_quic_enc_level_appdata_id ]==0 );
  FD_TEST( ack_gen->head - ack_gen->tail == FD_QUIC_ACK_QUEUE_CNT );
  FD_TEST( metrics->ack_tx[ FD_QUIC_ACK_TX_NOOP   ] == 0                     );
  FD_TEST( metrics->ack_tx[ FD_QUIC_ACK_TX_NEW    ] == FD_QUIC_ACK_QUEUE_CNT );
  FD_TEST( metrics->ack_tx[ FD_QUIC_ACK_TX_MERGED ] == 0                     );
  FD_TEST( metrics->ack_tx[ FD_QUIC_ACK_TX_ENOSPC ] == 0                     );
  FD_TEST( metrics->ack_tx[ FD_QUIC_ACK_TX_CANCEL ] == 0                     );

  /* Overflow the ACK queue */
  fd_quic_sandbox_send_ping_pkt( sandbox, conn, pktnum );
  pktnum += 2UL;
  FD_TEST( metrics->ack_tx[ FD_QUIC_ACK_TX_ENOSPC ] == 1 );

}

__attribute__((noinline)) void
test_quic_conn_initial_limits( fd_quic_sandbox_t * sandbox,
                               fd_rng_t *          rng ) {
  (void)rng;

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_transport_params_t * params = &fd_quic_get_state( sandbox->quic )->transport_params;
  params->initial_max_data        = 987654321UL;
  params->initial_max_streams_uni =      8192UL;

  /* Create a connection that's not yet established */
  ulong             our_conn_id  = 1234UL;
  fd_quic_conn_id_t peer_conn_id = fd_quic_conn_id_new( &our_conn_id, 8UL );
  uint              dst_ip_addr  = FD_IP4_ADDR( 192, 168, 1, 1 );
  ushort            dst_udp_port = 8080;
  fd_quic_conn_t * conn = fd_quic_conn_create( sandbox->quic, our_conn_id, &peer_conn_id, dst_ip_addr, dst_udp_port, 0, 0, 1 );
  FD_TEST( conn );
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_HANDSHAKE );

  /* Ensure stream frames are accepted
     (Rationale: The application encryption level becomes available before
     the handshake is confirmed; Quota would have been granted already via
     QUIC transport params) */
  uchar buf[ 1024 ];
  ulong sz = fd_quic_encode_stream_frame(
    buf, buf+sizeof(buf),
    /* stream_id */ FD_QUIC_STREAM_TYPE_UNI_CLIENT,
    /* offset */ 0, /* length */ 1UL, /* fin */ 0 );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
  buf[ sz++ ] = '0';
  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_HANDSHAKE ); /* conn not killed */

  /* Double check RX limits */
  FD_TEST( conn->srx->rx_sup_stream_id ==     32770UL ); /* (8192<<2)+2 */
  FD_TEST( conn->srx->rx_max_data      == 987654321UL );
}

__attribute__((noinline)) void
test_quic_rx_max_data_frame( fd_quic_sandbox_t * sandbox,
                             fd_rng_t *          rng ) {
  uchar buf[128];
  ulong sz;
  fd_quic_max_data_frame_t frame = {0};

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  sandbox->quic->config.initial_rx_max_stream_data = 1UL;
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );

  frame.max_data = 0x30;
  sz = fd_quic_encode_max_data_frame( buf, sizeof(buf), &frame );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  FD_TEST( conn->ack_gen->is_elicited == 1 );
  FD_TEST( conn->tx_max_data == 0x30 );

  conn->ack_gen->is_elicited = 0;
  frame.max_data = 0x10;
  sz = fd_quic_encode_max_data_frame( buf, sizeof(buf), &frame );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  FD_TEST( conn->ack_gen->is_elicited == 1 );
  FD_TEST( conn->tx_max_data == 0x30 );
}

__attribute__((noinline)) void
test_quic_rx_max_streams_frame( fd_quic_sandbox_t * sandbox,
                                fd_rng_t *          rng ) {
  uchar buf[128];
  ulong sz;
  fd_quic_max_streams_frame_t frame = {0};

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_CLIENT );
  sandbox->quic->config.initial_rx_max_stream_data = 1UL;
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );

  frame.type        = 0x13; /* unidirectional */
  frame.max_streams = 0x30;
  sz = fd_quic_encode_max_streams_frame( buf, sizeof(buf), &frame );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
  FD_TEST( sz>=2UL );
  FD_TEST( buf[0]==0x13 );
  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  FD_TEST( conn->ack_gen->is_elicited == 1 );
  FD_TEST( conn->tx_sup_stream_id == 0xc2 );

  conn->ack_gen->is_elicited = 0;
  frame.max_streams = 0x10; /* decrease limit */
  sz = fd_quic_encode_max_streams_frame( buf, sizeof(buf), &frame );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  FD_TEST( conn->ack_gen->is_elicited == 1 );
  FD_TEST( conn->tx_sup_stream_id == 0xc2 ); /* ignored */

  frame.type        = 0x12; /* bidirectional */
  frame.max_streams = 0x60;
  sz = fd_quic_encode_max_streams_frame( buf, sizeof(buf), &frame );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
  FD_TEST( sz>=2UL );
  FD_TEST( buf[0]==0x12 );
  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  FD_TEST( conn->ack_gen->is_elicited == 1 );
  FD_TEST( conn->tx_sup_stream_id == 0xc2 ); /* ignored */
}

__attribute__((noinline)) void
test_quic_small_pkt_ping( fd_quic_sandbox_t * sandbox,
                             fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_CLIENT );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->state = FD_QUIC_CONN_STATE_ACTIVE;

  conn->flags |= FD_QUIC_CONN_FLAGS_PING;
  fd_quic_conn_service( sandbox->quic, conn, 0 );

  /* grab sent packet */
  fd_frag_meta_t const * frag = fd_quic_sandbox_next_packet( sandbox );
  FD_TEST( frag );
  uchar* data = fd_chunk_to_laddr( sandbox, frag->chunk );
  FD_LOG_HEXDUMP_DEBUG(( "sent packet", data, frag->sz ));
  FD_LOG_HEXDUMP_DEBUG(( "pkt_key", &conn->keys[3][1].pkt_key, FD_AES_128_KEY_SZ ));
  FD_LOG_HEXDUMP_DEBUG(( "iv", &conn->keys[3][1].iv, FD_AES_GCM_IV_SZ ));
  FD_LOG_HEXDUMP_DEBUG(( "hp_key", &conn->keys[3][1].hp_key, FD_AES_128_KEY_SZ ));

  /* internal connection_map setup to process packet */
  do {
    fd_quic_conn_map_t * insert_entry = fd_quic_conn_map_insert( fd_quic_get_state(sandbox->quic)->conn_map,
      FD_LOAD( ulong, conn->peer_cids[0].conn_id ) ); /* insert peer_cid.conn_id */
    FD_TEST( insert_entry );
    insert_entry->conn = conn;
  } while(0);

  ulong before = sandbox->quic->metrics.ack_tx[ FD_QUIC_ACK_TX_NEW ];
  fd_quic_process_packet( sandbox->quic, data, frag->sz, sandbox->wallclock );
  ulong after = sandbox->quic->metrics.ack_tx[ FD_QUIC_ACK_TX_NEW ]; /* correctly parsed small ping packet */
  FD_TEST( after == before + 1 );
}

static __attribute__((noinline)) void
test_quic_parse_path_challenge( void ) {
  fd_quic_path_challenge_frame_t path_challenge[1];
  fd_quic_path_response_frame_t  path_response[1];

  do {
    uchar data[10] = {0x1a};
    FD_TEST( fd_quic_decode_path_challenge_frame( path_challenge, data,  1UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_path_challenge_frame( path_challenge, data,  8UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_path_challenge_frame( path_challenge, data,  9UL )==9UL );
    FD_TEST( fd_quic_decode_path_challenge_frame( path_challenge, data, 10UL )==9UL );

    data[0] = 0x1b;
    FD_TEST( fd_quic_decode_path_response_frame( path_response, data,  1UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_path_response_frame( path_response, data,  8UL )==FD_QUIC_PARSE_FAIL );
    FD_TEST( fd_quic_decode_path_response_frame( path_response, data,  9UL )==9UL );
    FD_TEST( fd_quic_decode_path_response_frame( path_response, data, 10UL )==9UL );
  } while(0);
}

static int
in_stream_list( fd_quic_stream_t * stream, fd_quic_stream_t * sentinel ) {
  fd_quic_stream_t * curr = sentinel->next;
  while( curr != sentinel && curr ) {
    if( curr == stream ) return 1;
    curr = curr->next;
  }
  return 0;
}

/*
  Tests edge cases for send_streams
*/
static __attribute__ ((noinline)) void
test_quic_send_streams( fd_quic_sandbox_t * sandbox,
                        fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->tx_sup_stream_id = 20; /* some large number */

  /* empty stream in send_streams gets moved out */
  do {
    fd_quic_stream_t * empty_stream = fd_quic_conn_new_stream( conn );
    FD_TEST( empty_stream );

    /* manually add to send_streams */
    FD_QUIC_STREAM_LIST_REMOVE( empty_stream );
    FD_QUIC_STREAM_LIST_INSERT_BEFORE( conn->send_streams, empty_stream );

    FD_TEST( in_stream_list( empty_stream, conn->send_streams ) );

    uchar buf[10];
    fd_quic_pkt_meta_t pkt_meta_tmpl = {.enc_level = fd_quic_enc_level_appdata_id};

    fd_quic_gen_stream_frames( conn, buf, buf+sizeof(buf), &pkt_meta_tmpl, &conn->pkt_meta_tracker );

    FD_TEST( !in_stream_list( empty_stream, conn->send_streams ) );
    FD_TEST( in_stream_list( empty_stream, conn->used_streams ) );

  } while(0);

  /* independent of fin, streams with more data than space stay in send_streams */
  for( int fin=0; fin<2; fin++ ) {
    fd_quic_stream_t * big_stream = fd_quic_conn_new_stream( conn );
    conn->tx_max_data = big_stream->tx_max_stream_data = 100;
    FD_TEST( big_stream );
    const char data[] = "SOME BIG STRING TO SEND";
    fd_quic_stream_send( big_stream, data, sizeof(data), fin );

    FD_TEST( in_stream_list( big_stream, conn->send_streams ) );

    uchar buf[FD_QUIC_MAX_FOOTPRINT( stream_e_frame ) + 2]; /* only 2 bytes for actual data*/
    fd_quic_pkt_meta_t pkt_meta = {0};

    fd_quic_gen_stream_frames( conn, buf, buf+sizeof(buf), &pkt_meta, &conn->pkt_meta_tracker );

    FD_TEST( in_stream_list( big_stream, conn->send_streams ) );
    conn->send_streams->next->sentinel = 1; /* rm this one to reset for next test */
  }

}

static void pretend_stream( fd_quic_stream_t * stream ) {
  stream->stream_flags |= FD_QUIC_STREAM_FLAGS_UNSENT;
  stream->tx_buf.head = 1;
  stream->tx_sent = 0;
}

static __attribute__ ((noinline)) void
test_quic_inflight_pkt_limit( fd_quic_sandbox_t * sandbox,
                              fd_rng_t *          rng ) {

  /* min_inflight reserved AND max enforced */
  fd_quic_t * quic = sandbox->quic;
  do {
    fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
    FD_TEST( conn );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
    FD_TEST( conn->used_pkt_meta == 0UL );

    conn->tx_sup_stream_id = 4; /* we'll just use one stream */
    fd_quic_stream_t * empty_stream = fd_quic_conn_new_stream( conn );

    for( int i=0; i<12; i++ ) {
      empty_stream->upd_pkt_number = ~0UL;

      /* manually add to send_streams */
      FD_QUIC_STREAM_LIST_REMOVE( empty_stream );
      pretend_stream( empty_stream );
      FD_QUIC_STREAM_LIST_INSERT_BEFORE( conn->send_streams, empty_stream );
      FD_TEST( in_stream_list( empty_stream, conn->send_streams ) );

      ulong conn_max_fails_before = quic->metrics.frame_tx_alloc_cnt[2];
      fd_quic_conn_service( quic, conn, 0 );
      ulong metrics_after = quic->metrics.frame_tx_alloc_cnt[2];
      if( i==11 ) {
        /* 12th packet should fail */
        FD_TEST( metrics_after == conn_max_fails_before + 1 );
      } else {
        /* 11th packet should succeed */
        FD_TEST( metrics_after == conn_max_fails_before );
      }
    }

  } while(0);


  /* test conn_cnt*min_inflight_frame_cnt_conn <= inflight_frame_cnt */
  do {
    fd_quic_limits_t quic_limits = {
      .conn_cnt           =   2UL,
      .inflight_frame_cnt =   8UL,
      .handshake_cnt      =   1UL,
      .conn_id_cnt        =   4UL,
      .stream_id_cnt      =   8UL,
      .tx_buf_sz          = 512UL,
      .stream_pool_cnt    =  32UL,
    };

    quic_limits.min_inflight_frame_cnt_conn = 5UL;
    FD_TEST( !fd_quic_footprint( &quic_limits ) );
  } while(0);

}

static __attribute__((noinline)) void
test_quic_conn_free( fd_quic_sandbox_t * sandbox,
                     fd_rng_t *          rng ) {
  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_t *       quic     = sandbox->quic;
  fd_quic_state_t * state    = fd_quic_get_state( quic );
  ulong             conn_max = quic->limits.conn_cnt;

  /* If no CIDs are cached, our_conn_id must be initialized to zero
     (zero acts as the conn_map key sentinel) */
  for( ulong j=0UL; j<conn_max; j++ ) {
    FD_TEST( fd_quic_conn_at_idx( state, j )->our_conn_id == 0UL );
  }
  fd_quic_svc_validate( quic );

  /* Create a bunch of conns */
  for( ulong j=0UL; j<conn_max; j++ ) {
    FD_TEST( fd_quic_sandbox_new_conn_established( sandbox, rng ) );
  }
  fd_quic_svc_validate( quic );

  /* Ensure each conn is in conn_id_map */
  static fd_quic_conn_map_t sentinel[1] = {0};
  for( ulong j=0UL; j<conn_max; j++ ) {
    fd_quic_conn_t * conn = fd_quic_conn_at_idx( state, j );
    ulong const cid = conn->our_conn_id;
    FD_TEST( fd_quic_conn_query( state->conn_map, cid )==conn );

    /* Free conn */
    fd_quic_conn_free( quic, conn );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_INVALID );
    FD_TEST( conn->our_conn_id == cid ); /* CID is kept */
    FD_TEST( fd_quic_conn_query1( state->conn_map, cid, sentinel )->conn==conn );
  }
  fd_quic_svc_validate( quic );

  /* Now, allocate new conns.  CIDs should be replaced one by one. */
  for( ulong i=0UL; i<conn_max; i++ ) {
    /* LIFO allocation policy */
    ulong j = conn_max - 1UL - i;

    fd_quic_conn_t * conn = fd_quic_conn_at_idx( state, j );
    ulong const old_cid = conn->our_conn_id;
    FD_TEST( fd_quic_conn_query1( state->conn_map, old_cid, sentinel )->conn==conn );

    FD_TEST( fd_quic_sandbox_new_conn_established( sandbox, rng )==conn );
    FD_TEST( fd_quic_conn_query1( state->conn_map, old_cid, sentinel )->conn==NULL );
    ulong const new_cid = conn->our_conn_id;
    FD_TEST( fd_quic_conn_query1( state->conn_map, new_cid, sentinel )->conn==conn );
  }
  fd_quic_svc_validate( quic );

  /* Finally, validate that packet handlers count freed conns as
     "keys not available" in metrics.  (Logically, for the receiver
     side, a dead conn is comparable to a conn where all receive keys
     were discarded) */
  fd_quic_conn_t * conn = fd_quic_conn_at_idx( state, 0UL );
  ulong const old_cid = conn->our_conn_id;
  fd_quic_conn_free( quic, conn );
  conn->keys_avail = UINT_MAX;
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_INVALID );
  FD_TEST( fd_quic_conn_query1( state->conn_map, old_cid, sentinel )->conn==conn );

  FD_TEST( quic->metrics.pkt_no_key_cnt[ fd_quic_enc_level_initial_id   ]==0 );
  FD_TEST( quic->metrics.pkt_no_key_cnt[ fd_quic_enc_level_handshake_id ]==0 );
  FD_TEST( quic->metrics.pkt_no_key_cnt[ fd_quic_enc_level_appdata_id   ]==0 );
  fd_quic_handle_v1_initial( quic, &conn, NULL, NULL, NULL, NULL, 0UL );
  FD_TEST( quic->metrics.pkt_no_key_cnt[ fd_quic_enc_level_initial_id   ]==1 );
  fd_quic_handle_v1_handshake( quic, conn, NULL, NULL, 0UL );
  FD_TEST( quic->metrics.pkt_no_key_cnt[ fd_quic_enc_level_handshake_id ]==1 );
  fd_quic_handle_v1_one_rtt( quic, conn, NULL, NULL, 0UL );
  FD_TEST( quic->metrics.pkt_no_key_cnt[ fd_quic_enc_level_appdata_id   ]==1 );
}

/* Ensure that packet numbers aren't skipped when pkt-meta runs out */

void
test_quic_pktmeta_pktnum_skip( fd_quic_sandbox_t * sandbox,
                               fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_t *                  quic    = sandbox->quic;
  fd_quic_conn_t *             conn    = fd_quic_sandbox_new_conn_established( sandbox, rng );
  fd_quic_metrics_t *          metrics = &conn->quic->metrics;
  fd_quic_pkt_meta_tracker_t * tracker = &conn->pkt_meta_tracker;
  fd_quic_pkt_meta_t         * pool    = tracker->pool;

  ulong next_pkt_number = conn->pkt_number[2];

  /* trigger a few pings */
  for( uint j = 0; j < 5; ++j ) {
    conn->flags          = ( conn->flags & ~FD_QUIC_CONN_FLAGS_PING_SENT ) | FD_QUIC_CONN_FLAGS_PING;
    conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
    sandbox->wallclock += (long)10e6;
    fd_quic_svc_schedule1( conn, FD_QUIC_SVC_INSTANT );
    fd_quic_service( quic, sandbox->wallclock );
    FD_TEST( conn->pkt_number[2] == next_pkt_number + 1UL );
    next_pkt_number++;
  }

  fd_quic_pkt_meta_t sentinel[1]   = {0};
  fd_quic_pkt_meta_t *cur_pkt_meta = sentinel;

  /* allocate all the pkt-meta */
  while( fd_quic_pkt_meta_pool_free( pool ) ) {
    fd_quic_pkt_meta_t * pkt_meta = fd_quic_pkt_meta_pool_ele_acquire( pool );

    cur_pkt_meta->next = (ulong)pkt_meta;
    cur_pkt_meta       = pkt_meta;
    pkt_meta->next     = 0UL;
  }

  ulong * metrics_alloc_fail_cnt =
      &metrics->frame_tx_alloc_cnt[FD_METRICS_ENUM_FRAME_TX_ALLOC_RESULT_V_FAIL_EMPTY_POOL_IDX];
  FD_TEST(( *metrics_alloc_fail_cnt == 0UL ));

  /* trigger a few pings
     with no pkt_meta available, no packets should be sent, and the test
     is to ensure the packet number does NOT increase */
  ulong alloc_fail_cnt = 0UL;
  for( uint j = 0; j < 15; ++j ) {
    conn->flags          = ( conn->flags & ~FD_QUIC_CONN_FLAGS_PING_SENT ) | FD_QUIC_CONN_FLAGS_PING;
    conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
    sandbox->wallclock += (long)10e6;
    fd_quic_svc_schedule1( conn, FD_QUIC_SVC_INSTANT );
    fd_quic_service( quic, sandbox->wallclock );
    FD_TEST( conn->pkt_number[2] == next_pkt_number );
    FD_TEST( *metrics_alloc_fail_cnt > alloc_fail_cnt );
    alloc_fail_cnt = *metrics_alloc_fail_cnt;
  }

  /* acks should still be possible
     send pings from peer, and we should send acks, incrementing pktnum */
  ulong pktnum = 42;

  for( uint j = 0; j < 5; ++j ) {
    fd_quic_sandbox_send_ping_pkt( sandbox, conn, pktnum++ );

    /* wait for the ack delay timeout */
    sandbox->wallclock += (long)100e6;
    fd_quic_service( quic, sandbox->wallclock );

    /* verify packet sent */
    FD_TEST( conn->pkt_number[2] == next_pkt_number + 1UL );
    next_pkt_number++;
  }

  /* return a few pkt_meta */
  for( uint j = 0; j < 5; ++j ) {
    fd_quic_pkt_meta_t * pkt_meta = (fd_quic_pkt_meta_t*)sentinel->next;
    FD_TEST( pkt_meta );

    /* move up linked list head */
    sentinel->next = (ulong)pkt_meta->next;

    fd_quic_pkt_meta_pool_ele_release( pool, pkt_meta );
  }

  /* trigger a few pings */
  for( uint j = 0; j < 5; ++j ) {
    conn->flags          = ( conn->flags & ~FD_QUIC_CONN_FLAGS_PING_SENT ) | FD_QUIC_CONN_FLAGS_PING;
    conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
    sandbox->wallclock += (long)10e6;
    fd_quic_svc_schedule1( conn, FD_QUIC_SVC_INSTANT );
    fd_quic_service( quic, sandbox->wallclock );
    FD_TEST( conn->pkt_number[2] == next_pkt_number + 1UL );
    next_pkt_number++;
  }

  FD_TEST( *metrics_alloc_fail_cnt == alloc_fail_cnt );
}

static void
test_quic_rtt_sample( void ) {
  fd_quic_t quic = {0};
  fd_quic_conn_t conn = {
    .quic = &quic
  };

  fd_quic_transport_params_t peer_tp = {
    .ack_delay_exponent_present = 1,
    .ack_delay_exponent         = 2, /* 4us */
    .max_ack_delay_present      = 1,
    .max_ack_delay              = 100 /* 100ms */
  };
  fd_quic_apply_peer_params( &conn, &peer_tp );
  FD_TEST( conn.peer_ack_delay_scale     ==  10e3f );
  FD_TEST( conn.peer_max_ack_delay_ticks == 250e6f );

  #define SAMPLE( rtt_sample, ack_delay ) do { \
      fd_quic_sample_rtt( &conn, (rtt_sample), (ack_delay) ); \
      FD_LOG_DEBUG(( "min_rtt %f latest_rtt %f smoothed_rtt %f var_rtt %f", \
          (double)conn.rtt->min_rtt, (double)conn.rtt->latest_rtt, (double)conn.rtt->smoothed_rtt, (double)conn.rtt->var_rtt )); \
    } while(0)

  SAMPLE( (long)9000e3, (long)250 );
  FD_TEST( conn.rtt->min_rtt      == 9000000.0f );
  FD_TEST( conn.rtt->latest_rtt   == 9000000.0f );
  FD_TEST( conn.rtt->smoothed_rtt == 9000000.0f );
  FD_TEST( conn.rtt->var_rtt      == 4500000.0f );
  /* ack_delay: 250*(2 us^2) = 1e6 ns = 2.5e6 ticks */

  SAMPLE( (long)5000e3, 0L );
  FD_TEST( conn.rtt->min_rtt      == 5000000.0f );
  FD_TEST( conn.rtt->latest_rtt   == 5000000.0f );
  FD_TEST( conn.rtt->smoothed_rtt == 8500000.0f );
  FD_TEST( conn.rtt->var_rtt      == 4250000.0f );

  fd_rtt_estimate_t est2 = conn.rtt[0];
  SAMPLE( (long)8000e3, (long)0 );
  FD_TEST( conn.rtt->min_rtt      == 5000000.0f );
  FD_TEST( conn.rtt->latest_rtt   == 8000000.0f );
  FD_TEST( conn.rtt->smoothed_rtt == 8437500.0f );
  FD_TEST( conn.rtt->var_rtt      == 3296875.0f );

  conn.rtt[0] = est2;
  SAMPLE( (long)8000e3, (long)250 );
  /* 250 ack_delay = 250 * 4us = 1000us = 2500e3 ticks */
  FD_TEST( conn.rtt->min_rtt      == 5000000.0f );
  FD_TEST( conn.rtt->latest_rtt   == 5500000.0f );
  FD_TEST( conn.rtt->smoothed_rtt == 8125000.0f );
  FD_TEST( conn.rtt->var_rtt      == 3843750.0f );

  SAMPLE( (long)2500e3, 0L );
  FD_TEST( conn.rtt->min_rtt      == 2500000.0f );
  FD_TEST( conn.rtt->latest_rtt   == 2500000.0f );
  FD_TEST( conn.rtt->smoothed_rtt == 7421875.0f );
  FD_TEST( conn.rtt->var_rtt      == 4113281.25f );

#undef SAMPLE
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",  NULL, "gigantic"                 );
  ulong        page_cnt = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt", NULL, 2UL                        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx(cpu_idx) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  fd_quic_limits_t quic_limits = {
    .conn_cnt                    =  4UL,
    .handshake_cnt               =  1UL,
    .conn_id_cnt                 =  4UL,
    .stream_id_cnt               =  8UL,
    .inflight_frame_cnt          =  8UL * 4,
    .min_inflight_frame_cnt_conn =  7UL, /* for test_quic_inflight_pkt_limit */
    .tx_buf_sz                   =  512UL,
    .stream_pool_cnt             =  32UL,
  };

  ulong const pkt_cnt = 128UL;
  ulong const pkt_mtu = 1500UL;

  FD_LOG_NOTICE(( "Creating anonymous workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Allocate a sandbox object */

  void * sandbox_mem = fd_wksp_alloc_laddr(
      /* wksp  */ wksp,
      /* align */ fd_quic_sandbox_align(),
      /* size  */ fd_quic_sandbox_footprint( &quic_limits, pkt_cnt, pkt_mtu ),
      /* tag   */ 1UL );

  fd_quic_sandbox_t * sandbox = fd_quic_sandbox_new( sandbox_mem, &quic_limits, pkt_cnt, pkt_mtu );
  FD_TEST( sandbox );

  /* Run tests */
  test_quic_stream_data_limit_enforcement( sandbox, rng );
  test_quic_stream_limit_enforcement     ( sandbox, rng );
  test_quic_stream_concurrency           ( sandbox, rng );
  test_quic_ping_frame                   ( sandbox, rng );
  test_quic_server_alpn_fail             ( sandbox, rng );
  test_quic_pktnum_skip                  ( sandbox, rng );
  test_quic_conn_initial_limits          ( sandbox, rng );
  test_quic_rx_max_data_frame            ( sandbox, rng );
  test_quic_rx_max_streams_frame         ( sandbox, rng );
  test_quic_small_pkt_ping               ( sandbox, rng );
  test_quic_send_streams                 ( sandbox, rng );
  test_quic_inflight_pkt_limit           ( sandbox, rng );
  test_quic_parse_path_challenge();
  test_quic_conn_free                    ( sandbox, rng );
  test_quic_pktmeta_pktnum_skip          ( sandbox, rng );
  test_quic_rtt_sample();

  /* Wind down */

  fd_wksp_free_laddr( fd_quic_sandbox_delete( sandbox ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
