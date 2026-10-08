#define _GNU_SOURCE
#include "../keyguard/fd_keyguard_client.h"
static ulong test_sign_cnt;
static void
test_sign( fd_keyguard_client_t * kg, uchar * sig, uchar const * data, ulong sz, int type ) {
  (void)kg; (void)data; (void)sz; (void)type;
  memset( sig, 0, 64UL );
  test_sign_cnt++;
}
#define fd_keyguard_client_sign test_sign
#include "fd_event_client.c"
#undef fd_keyguard_client_sign
#include "../../waltz/tls/test_tls_helper.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_mock.h"
#include "../../util/tmpl/fd_unit_test.c"
#include <fcntl.h>

#include <sys/epoll.h>

static int g_epoll_fd;

/* test_tls_pair_handshake drives a TLS 1.3 handshake between two
   fd_tlsrec conns in memory, using throwaway Ed25519 identities and
   mock X.509 certs.  On return both conns are ready for app data. */

static void
test_tls_pair_handshake( fd_tlsrec_conn_t * client_conn,
                         fd_tlsrec_conn_t * server_conn,
                         fd_rng_t *         rng ) {
  static fd_tls_test_sign_ctx_t client_sign_ctx[1];
  static fd_tls_test_sign_ctx_t server_sign_ctx[1];
  fd_tls_test_sign_ctx( client_sign_ctx, rng );
  fd_tls_test_sign_ctx( server_sign_ctx, rng );
  static fd_chacha_rng_t client_chacha[1], server_chacha[1];

  fd_tls_t client_tls = {
    .rng     = fd_tls_test_rand( client_chacha, rng ),
    .sign    = fd_tls_test_sign( client_sign_ctx ),
    .alpn    = { 2, 'h', '2' },
    .alpn_sz = 3UL,
  };
  fd_tls_t server_tls = {
    .rng     = fd_tls_test_rand( server_chacha, rng ),
    .sign    = fd_tls_test_sign( server_sign_ctx ),
    .alpn    = { 2, 'h', '2' },
    .alpn_sz = 3UL,
  };
  for( ulong j=0UL; j<32UL; j++ ) {
    client_tls.kex_private_key[j] = fd_rng_uchar( rng );
    server_tls.kex_private_key[j] = fd_rng_uchar( rng );
  }
  fd_x25519_public( client_tls.kex_public_key, client_tls.kex_private_key );
  fd_x25519_public( server_tls.kex_public_key, server_tls.kex_private_key );
  fd_memcpy( client_tls.cert_public_key, client_sign_ctx->public_key, 32UL );
  fd_memcpy( server_tls.cert_public_key, server_sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( client_tls.cert_x509, client_tls.cert_public_key );
  fd_x509_mock_cert( server_tls.cert_x509, server_tls.cert_public_key );
  client_tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;
  server_tls.cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  FD_TEST( fd_tlsrec_conn_init( client_conn, &client_tls, 0 )==client_conn );
  FD_TEST( fd_tlsrec_conn_init( server_conn, &server_tls, 1 )==server_conn );
  fd_memcpy( client_conn->hs.cli.server_pubkey, server_tls.cert_public_key, 32UL );

  static uchar c2s[ FD_TLSREC_CAP ], s2c[ FD_TLSREC_CAP ], app[ FD_TLSREC_CAP ];
  ulong c2s_sz = sizeof(c2s), app_sz = sizeof(app);
  FD_TEST( fd_tlsrec_conn_rx( client_conn, NULL, c2s, &c2s_sz, app, &app_sz )==FD_TLSREC_SUCCESS );
  for( ulong iter=0UL; iter<8UL; iter++ ) {
    fd_tlsrec_slice_t rx[1];
    fd_tlsrec_slice_init( rx, c2s, c2s_sz );
    ulong s2c_sz = sizeof(s2c); app_sz = sizeof(app);
    FD_TEST( fd_tlsrec_conn_rx( server_conn, rx, s2c, &s2c_sz, app, &app_sz )==FD_TLSREC_SUCCESS );
    fd_tlsrec_slice_init( rx, s2c, s2c_sz );
    c2s_sz = sizeof(c2s); app_sz = sizeof(app);
    FD_TEST( fd_tlsrec_conn_rx( client_conn, rx, c2s, &c2s_sz, app, &app_sz )==FD_TLSREC_SUCCESS );
    if( fd_tlsrec_conn_is_ready( client_conn ) && fd_tlsrec_conn_is_ready( server_conn ) && !c2s_sz ) break;
  }
  FD_TEST( fd_tlsrec_conn_is_ready( client_conn ) );
  FD_TEST( fd_tlsrec_conn_is_ready( server_conn ) );
  FD_TEST( client_conn->hs.cli.alpn_negotiated );
}

/* A GOAWAY that fires conn_dead synchronously during rx must not stop
   the pending PING ACK from being flushed through the still-live TLS
   conn, and the disconnect must be deferred to the poll loop. */

FD_UNIT_TEST( conn_tls_lifecycle ) {
  static uchar circq_mem[ 4096UL+512UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 512UL ) );
  FD_TEST( circq );

  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  FD_TEST( rng );

  uchar * client_mem = aligned_alloc( fd_event_client_align(), fd_event_client_footprint( 4096UL ) );
  FD_TEST( client_mem );
  uchar identity_pubkey[32] = {0};
  static fd_x509_ca_store_t ca_store[1]; /* empty: the pinned mock cert bypasses chain verification */
  fd_event_client_t * client = fd_event_client_join( fd_event_client_new(
      client_mem, NULL, rng, circq, g_epoll_fd, 1<<20, "https://localhost:1", identity_pubkey, "0.0.0",
      "0000000000000000000000000000000000000000", "test", 1UL, 2UL, 3UL, 4096UL, 1, ca_store ) );
  FD_TEST( client );

  static fd_tlsrec_conn_t server_conn[1];
  test_tls_pair_handshake( client->tls_conn, server_conn, rng );

  int sv[2];
  FD_TEST( 0==socketpair( AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0, sv ) );

  /* Attach the handshaked TLS conn to a connected event client. */
  fd_grpc_client_t * grpc = client->grpc_client;
  client->state             = FD_EVENT_CLIENT_STATE_CONNECTED;
  client->sockfd            = sv[0]; /* disconnect() closes it */
  client->defer_disconnect  = INT_MAX;
  client->has_genesis_hash  = 1;
  client->has_shred_version = 1;
  grpc->h2_hs_done          = 1;
  grpc->conn->flags         = 0;

  fd_h2_ping_t ping = {
    .hdr = { .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING, 8UL ), .flags = 0U, .r_stream_id = 0U },
    .payload = 0x0102030405060708UL
  };
  fd_h2_goaway_t goaway = {
    .hdr = { .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_GOAWAY, 8UL ), .flags = 0U, .r_stream_id = 0U },
    .last_stream_id = 0U,
    .error_code     = fd_uint_bswap( FD_H2_SUCCESS )
  };

  /* PING queues an ACK; GOAWAY synchronously fires conn_dead during rx. */
  uchar h2[ sizeof(ping)+sizeof(goaway) ];
  fd_memcpy( h2,              &ping,   sizeof(ping)   );
  fd_memcpy( h2+sizeof(ping), &goaway, sizeof(goaway) );
  fd_tlsrec_slice_t app_tx[1];
  fd_tlsrec_slice_init( app_tx, h2, sizeof(h2) );
  static uchar wire[ FD_TLSREC_CAP ];
  ulong wire_sz = sizeof(wire);
  FD_TEST( fd_tlsrec_conn_tx( server_conn, wire, &wire_sz, app_tx )==FD_TLSREC_SUCCESS );
  FD_TEST( fd_tlsrec_slice_is_empty( app_tx ) );
  FD_TEST( (long)wire_sz==send( sv[1], wire, wire_sz, 0 ) );

  int charge_busy = 0;
  int rc = fd_grpc_client_rxtx_tls( grpc, client->tls_conn, sv[0], fd_log_wallclock(), &charge_busy );
  FD_TEST( rc==0 );
  FD_TEST( charge_busy );
  FD_TEST( client->state==FD_EVENT_CLIENT_STATE_CONNECTED );
  FD_TEST( client->defer_disconnect==DISCONNECT_REASON_PEER_CLOSED );
  FD_TEST( grpc->conn->flags & FD_H2_CONN_FLAGS_DEAD );
  FD_TEST( fd_h2_rbuf_used_sz( grpc->frame_tx )==0UL );
  FD_TEST( !fd_grpc_client_tls_tx_pending( grpc ) );
  FD_TEST( fd_tlsrec_conn_is_ready( client->tls_conn ) );

  /* The ACK made it onto the wire, encrypted under the live conn. */
  long ack_wire_sz = recv( sv[1], wire, sizeof(wire), 0 );
  FD_TEST( ack_wire_sz>0L );
  fd_tlsrec_slice_t ack_rx[1];
  fd_tlsrec_slice_init( ack_rx, wire, (ulong)ack_wire_sz );
  static uchar ack[ 64 ];
  ulong ack_sz = sizeof(ack);
  FD_TEST( fd_tlsrec_conn_rx( server_conn, ack_rx, NULL, NULL, ack, &ack_sz )==FD_TLSREC_SUCCESS );
  FD_TEST( ack_sz==sizeof(fd_h2_ping_t) );
  fd_h2_ping_t ack_ping; fd_memcpy( &ack_ping, ack, sizeof(ack_ping) );
  FD_TEST( fd_h2_frame_type( ack_ping.hdr.typlen )==FD_H2_FRAME_TYPE_PING );
  FD_TEST( ack_ping.hdr.flags & FD_H2_FLAG_ACK );
  FD_TEST( ack_ping.payload==ping.payload );

  /* The poll loop then performs the deferred disconnect. */
  int poll_busy = 0;
  fd_event_client_poll( client, fd_log_wallclock(), &poll_busy );
  FD_TEST( client->state==FD_EVENT_CLIENT_STATE_DISCONNECTED );
  FD_TEST( client->defer_disconnect==INT_MAX );
  FD_TEST( client->sockfd==-1 );

  close( sv[1] );
  free( client_mem );
  fd_rng_delete( fd_rng_leave( rng ) );
}

FD_UNIT_TEST( stream_heartbeat ) {
  static uchar circq_mem[ 4096UL+512UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 512UL ) );
  FD_TEST( circq );

  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  FD_TEST( rng );

  uchar * client_mem = aligned_alloc( fd_event_client_align(), fd_event_client_footprint( 1UL<<20 ) );
  FD_TEST( client_mem );
  uchar identity_pubkey[32] = {0};
  fd_event_client_t * client = fd_event_client_join( fd_event_client_new(
      client_mem,
      NULL,
      rng,
      circq,
      g_epoll_fd,
      1<<20,
      "http://localhost:1",
      identity_pubkey,
      "0.0.0",
      "0000000000000000000000000000000000000000",
      "test",
      1UL,
      2UL,
      3UL,
      4096UL,
      0,
      NULL ) );
  FD_TEST( client );

  fd_grpc_client_t * grpc = client->grpc_client;
  client->state     = FD_EVENT_CLIENT_STATE_CONNECTED;
  grpc->h2_hs_done  = 1;
  grpc->conn->flags = 0;
  client->event_stream = fd_grpc_client_stream_acquire( grpc, FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS );
  FD_TEST( client->event_stream );

  /* Idle circq, stream sent recently: no heartbeat. */
  client->last_stream_send_ns = fd_log_wallclock();
  int charge_busy = 0;
  tx( client, fd_log_wallclock(), &charge_busy );
  FD_TEST( !charge_busy );
  FD_TEST( !grpc->request_tx_op->chunk_sz );

  /* Idle circq, stream quiet past the heartbeat interval: a zero-length
     StreamEventsRequest goes out — exactly one 5-byte gRPC frame header
     (compressed=0, msg_sz=0). */
  client->last_stream_send_ns = fd_log_wallclock()-FD_EVENT_CLIENT_HEARTBEAT_NANOS-1L;
  tx( client, fd_log_wallclock(), &charge_busy );
  FD_TEST( charge_busy );
  /* frame_tx now holds one HTTP/2 DATA frame: 9 byte frame header plus
     the 5 byte gRPC message header (compressed=0, msg_sz=0). */
  FD_TEST( fd_h2_rbuf_used_sz( grpc->frame_tx )==sizeof(fd_h2_frame_hdr_t)+sizeof(fd_grpc_hdr_t) );
  uchar frame[ sizeof(fd_h2_frame_hdr_t)+sizeof(fd_grpc_hdr_t) ];
  fd_h2_rbuf_pop_copy( grpc->frame_tx, frame, sizeof(frame) );
  fd_h2_frame_hdr_t frame_hdr; memcpy( &frame_hdr, frame, sizeof(fd_h2_frame_hdr_t) );
  FD_TEST( fd_h2_frame_type( frame_hdr.typlen )==FD_H2_FRAME_TYPE_DATA );
  FD_TEST( fd_h2_frame_length( frame_hdr.typlen )==sizeof(fd_grpc_hdr_t) );
  fd_grpc_hdr_t hdr; memcpy( &hdr, frame+sizeof(fd_h2_frame_hdr_t), sizeof(fd_grpc_hdr_t) );
  FD_TEST( !hdr.compressed );
  FD_TEST( !hdr.msg_sz );
  FD_TEST( client->last_stream_send_ns>fd_log_wallclock()-FD_EVENT_CLIENT_HEARTBEAT_NANOS );

  /* The server's no-op ack reply (nonce=ULONG_MAX) is ignored: no circq
     pop, no disconnect. */
  uchar resp[ 11 ] = { 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 }; /* field 1 varint ULONG_MAX */
  client->defer_disconnect = INT_MAX;
  fd_event_client_handle_stream_events_resp( client, resp, sizeof(resp), FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS|(1UL<<8) );
  FD_TEST( client->defer_disconnect==INT_MAX );
  FD_TEST( client->metrics.last_acked_id==0UL );

  free( client_mem );
  fd_rng_delete( fd_rng_leave( rng ) );
}

static fd_event_client_t *
test_connected_client( fd_circq_t * circq,
                       fd_rng_t *   rng,
                       ulong        buf_max ) {
  void * client_mem = aligned_alloc( fd_event_client_align(), fd_event_client_footprint( buf_max ) );
  FD_TEST( client_mem );
  uchar identity_pubkey[32] = {0};
  fd_event_client_t * client = fd_event_client_join( fd_event_client_new(
      client_mem, NULL, rng, circq, g_epoll_fd, 1<<20, "http://localhost:1", identity_pubkey, "0.0.0",
      "0000000000000000000000000000000000000000", "test", 1UL, 2UL, 3UL, buf_max, 0, NULL ) );
  FD_TEST( client );
  fd_grpc_client_t * grpc = client->grpc_client;
  client->state       = FD_EVENT_CLIENT_STATE_CONNECTED;
  client->has_genesis_hash  = 1;
  client->has_shred_version = 1;
  client->consecutive_failure_count = 0UL;
  grpc->h2_hs_done    = 1;
  grpc->conn->flags   = 0;
  grpc->conn->tx_wnd  = UINT_MAX>>1;
  client->event_stream = fd_grpc_client_stream_acquire( grpc, FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS );
  FD_TEST( client->event_stream );
  client->event_stream->s.tx_wnd = UINT_MAX>>1;
  return client;
}

/* One poll's worth of sending without a socket. */
static void
test_poll_tx( fd_event_client_t * client,
              long                now ) {
  int charge_busy = 0;
  tx( client, now, &charge_busy );
}

/* Drain frame_tx as if the socket had taken it; returns bytes drained. */
static ulong
test_drain( fd_grpc_client_t * grpc ) {
  ulong sz = fd_h2_rbuf_used_sz( grpc->frame_tx );
  fd_h2_rbuf_skip( grpc->frame_tx, sz );
  return sz;
}

FD_UNIT_TEST( tx_pacing ) {
  static uchar circq_mem[ 4096UL+(1UL<<20) ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 1UL<<20 ) );
  FD_TEST( circq );
  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  fd_event_client_t * client = test_connected_client( circq, rng, 65536UL );
  fd_grpc_client_t * grpc = client->grpc_client;

  /* 2x burst worth of 1 KiB messages queued */
  ulong const msg_sz   = 1024UL;
  ulong const msg_cnt  = 2UL*(ulong)FD_EVENT_CLIENT_TX_BURST/msg_sz;
  ulong const frame_sz = msg_sz+sizeof(fd_grpc_hdr_t)+sizeof(fd_h2_frame_hdr_t);
  for( ulong i=0UL; i<msg_cnt; i++ ) { uchar * b = fd_circq_push_back( circq, 1UL, msg_sz ); FD_TEST( b ); memset( b, 0, msg_sz ); }

  /* Same instant: whole messages go out until the bucket is empty. */
  long now = fd_log_wallclock();
  client->tx_tokens = FD_EVENT_CLIENT_TX_BURST; client->tx_tokens_ns = now;
  ulong sent = 0UL, wire = 0UL;
  for( ulong i=0UL; i<msg_cnt; i++ ) {
    ulong before = client->metrics.events_sent;
    test_poll_tx( client, now );
    wire += test_drain( grpc );
    if( client->metrics.events_sent==before ) break;
    sent++;
  }
  FD_TEST( sent>0UL && sent<=(ulong)FD_EVENT_CLIENT_TX_BURST/msg_sz+1UL );
  FD_TEST( wire==sent*frame_sz ); /* one DATA frame per message, never sliced */
  FD_TEST( client->tx_tokens<=0L && client->tx_tokens>-(long)msg_sz );
  client->last_response_ns = now;
  long dl = fd_event_client_next_deadline( client, now );
  FD_TEST( dl>now && dl<=now+(long)1e9 );

  /* Polls shorter than one token's worth of time keep accruing. */
  long const ns_per_byte = (long)1e9/FD_EVENT_CLIENT_TX_RATE_BPS;
  long tokens0 = client->tx_tokens, tokens_ns0 = client->tx_tokens_ns;
  for( long i=1L; i<ns_per_byte; i++ ) {
    test_poll_tx( client, now+i );
    FD_TEST( client->tx_tokens==tokens0 && client->tx_tokens_ns==tokens_ns0 );
  }
  test_poll_tx( client, now+ns_per_byte );
  FD_TEST( client->tx_tokens_ns==tokens_ns0+ns_per_byte );
  test_drain( grpc );

  /* One second later: another burst's worth is allowed (refill clamps at burst). */
  now += (long)1e9;
  ulong wire2 = 0UL;
  for( ulong i=0UL; i<msg_cnt; i++ ) {
    test_poll_tx( client, now );
    ulong got = test_drain( grpc );
    if( !got ) break;
    wire2 += got;
  }
  FD_TEST( wire2>0UL && wire2<=((ulong)FD_EVENT_CLIENT_TX_BURST/msg_sz+1UL)*frame_sz );

  free( client );
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* A message larger than the burst still goes out whole; the bucket goes
   negative and the next message waits for the refill. */
FD_UNIT_TEST( tx_pacing_large_msg ) {
  static uchar circq_mem[ 4096UL+(2UL<<20) ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 2UL<<20 ) );
  FD_TEST( circq );
  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  fd_event_client_t * client = test_connected_client( circq, rng, 1UL<<20 );
  fd_grpc_client_t * grpc = client->grpc_client;

  ulong const msg_sz = 3UL*(ulong)FD_EVENT_CLIENT_TX_BURST;
  uchar * b = fd_circq_push_back( circq, 1UL, msg_sz ); FD_TEST( b ); memset( b, 0, msg_sz );
  b = fd_circq_push_back( circq, 1UL, 16UL ); FD_TEST( b ); memset( b, 0, 16UL );

  long now = fd_log_wallclock();
  client->tx_tokens = FD_EVENT_CLIENT_TX_BURST; client->tx_tokens_ns = now;
  test_poll_tx( client, now );
  ulong wire = test_drain( grpc );
  FD_TEST( client->metrics.events_sent==1UL );
  FD_TEST( wire>=msg_sz+sizeof(fd_grpc_hdr_t) );
  FD_TEST( grpc->request_tx_op->chunk_sz==0UL );
  FD_TEST( client->tx_tokens==-2L*FD_EVENT_CLIENT_TX_BURST );
  FD_TEST( !fd_grpc_client_tx_starved( grpc ) );
  FD_TEST( !credit_stall_check( client, now ) );
  FD_TEST( !client->stall_since );

  /* Same instant: the small message waits. */
  test_poll_tx( client, now );
  FD_TEST( client->metrics.events_sent==1UL && !test_drain( grpc ) );
  client->last_response_ns = now;
  long const ns_per_byte = (long)1e9/FD_EVENT_CLIENT_TX_RATE_BPS;
  long dl = fd_event_client_next_deadline( client, now );
  FD_TEST( dl==now+(2L*FD_EVENT_CLIENT_TX_BURST+1L)*ns_per_byte );

  /* At the deadline the bucket is back to one token: it goes out. */
  test_poll_tx( client, dl-1L );
  FD_TEST( client->metrics.events_sent==1UL );
  test_poll_tx( client, dl );
  FD_TEST( client->metrics.events_sent==2UL );
  FD_TEST( test_drain( grpc )==16UL+sizeof(fd_grpc_hdr_t)+sizeof(fd_h2_frame_hdr_t) );

  free( client );
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* Zero peer credit with no progress for the stall window reconnects;
   genuine progress resets the timer. */
FD_UNIT_TEST( credit_stall ) {
  static uchar circq_mem[ 4096UL+(1UL<<20) ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 1UL<<20 ) );
  FD_TEST( circq );
  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  fd_event_client_t * client = test_connected_client( circq, rng, 65536UL );
  fd_grpc_client_t * grpc = client->grpc_client;
  int sv[2];
  FD_TEST( 0==socketpair( AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0, sv ) );
  client->sockfd = sv[0]; /* disconnect() closes it */

  ulong const msg_sz = 4096UL;
  uchar * b = fd_circq_push_back( circq, 1UL, msg_sz ); FD_TEST( b ); memset( b, 0, msg_sz );

  /* Peer grants only 100 bytes: the message parks on zero stream credit. */
  long now = fd_log_wallclock();
  client->tx_tokens = FD_EVENT_CLIENT_TX_BURST; client->tx_tokens_ns = now;
  client->event_stream->s.tx_wnd = 100U;
  test_poll_tx( client, now );
  test_drain( grpc );
  FD_TEST( client->event_stream->s.tx_wnd==0U );
  ulong rem = fd_grpc_client_tx_starved( grpc );
  FD_TEST( rem==msg_sz+sizeof(fd_grpc_hdr_t)-100UL );

  /* Timer arms, does not fire early. */
  FD_TEST( !credit_stall_check( client, now ) );
  FD_TEST( client->stall_since==now );
  FD_TEST( !credit_stall_check( client, now+FD_EVENT_CLIENT_CREDIT_STALL_NANOS ) );
  FD_TEST( client->state==FD_EVENT_CLIENT_STATE_CONNECTED );
  long dl = fd_event_client_next_deadline( client, now );
  FD_TEST( dl<=now+FD_EVENT_CLIENT_CREDIT_STALL_NANOS );

  /* The bucket keeps refilling while parked, so an expired pacing
     deadline does not pin the tile awake. */
  long const ns_per_byte = (long)1e9/FD_EVENT_CLIENT_TX_RATE_BPS;
  b = fd_circq_push_back( circq, 1UL, 16UL ); FD_TEST( b ); memset( b, 0, 16UL );
  client->tx_tokens = -1000L; client->tx_tokens_ns = now;
  long t0 = now+2000L*ns_per_byte;
  client->last_response_ns = t0; client->last_stream_send_ns = t0;
  test_poll_tx( client, t0 );
  FD_TEST( client->tx_tokens==1000L );
  FD_TEST( fd_grpc_client_tx_starved( grpc )==rem ); /* still parked */
  FD_TEST( fd_event_client_next_deadline( client, t0 )>t0 );

  /* A late grant makes progress: timer restarts from the new remainder. */
  long t1 = now+FD_EVENT_CLIENT_CREDIT_STALL_NANOS-(long)1e9;
  client->event_stream->s.tx_wnd = 50U;
  grpc->window_update_pending = 1;
  int charge_busy = 0;
  FD_TEST( 0==fd_grpc_client_rxtx_socket( grpc, client->sockfd, t1, &charge_busy ) );
  FD_TEST( fd_grpc_client_tx_starved( grpc )==rem-50UL );
  FD_TEST( !credit_stall_check( client, t1 ) );
  FD_TEST( client->stall_since==t1 );
  FD_TEST( !credit_stall_check( client, t1+FD_EVENT_CLIENT_CREDIT_STALL_NANOS ) );

  /* No further progress: reconnect with backoff, counter bumped. */
  long t2 = t1+FD_EVENT_CLIENT_CREDIT_STALL_NANOS+1L;
  FD_TEST( credit_stall_check( client, t2 ) );
  FD_TEST( client->state==FD_EVENT_CLIENT_STATE_DISCONNECTED );
  FD_TEST( client->metrics.credit_stall_cnt==1UL );
  FD_TEST( client->stall_since==0L );
  FD_TEST( client->disconnected.reconnect_deadline>t2 );
  FD_TEST( client->sockfd==-1 );

  close( sv[1] );
  free( client );
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* Stream deadlines expire on the caller's clock, not the wallclock. */
FD_UNIT_TEST( stream_deadline_clock ) {
  static uchar circq_mem[ 4096UL+512UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 512UL ) );
  FD_TEST( circq );
  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  fd_event_client_t * client = test_connected_client( circq, rng, 65536UL );
  fd_grpc_client_t * grpc = client->grpc_client;
  int sv[2];
  FD_TEST( 0==socketpair( AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0, sv ) );

  long now = 1000L;
  fd_grpc_client_deadline_set( client->event_stream, FD_GRPC_DEADLINE_HEADER, now+1L );
  int charge_busy = 0;
  FD_TEST( 0==fd_grpc_client_rxtx_socket( grpc, sv[0], now, &charge_busy ) );
  FD_TEST( client->event_stream && client->defer_disconnect==INT_MAX );
  FD_TEST( 0==fd_grpc_client_rxtx_socket( grpc, sv[0], now+2L, &charge_busy ) );
  FD_TEST( !client->event_stream && client->defer_disconnect==DISCONNECT_REASON_TRANSPORT_FAILED );

  close( sv[0] ); close( sv[1] );
  free( client );
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* A callback can defer a disconnect before flushing its response fails.
   The transport failure must consume that reason before the next redial. */
FD_UNIT_TEST( disconnect_transport_failure ) {
  static uchar circq_mem[ 4096UL+512UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 512UL ) );
  FD_TEST( circq );
  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  fd_event_client_t * client = test_connected_client( circq, rng, 4096UL );

  int sv[2];
  FD_TEST( 0==socketpair( AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0, sv ) );
  client->sockfd = sv[0];
  struct {
    fd_h2_ping_t   ping;
    fd_h2_goaway_t goaway;
  } const h2 = {
    .ping   = { .hdr = { .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_PING,   8UL ) }, .payload = 1UL },
    .goaway = { .hdr = { .typlen = fd_h2_frame_typlen( FD_H2_FRAME_TYPE_GOAWAY, 8UL ) } }
  };
  FD_TEST( (long)sizeof(h2)==send( sv[1], &h2, sizeof(h2), MSG_NOSIGNAL ) );
  /* GOAWAY queues the deferred reason; the PING ACK then fails with EPIPE. */
  FD_TEST( 0==shutdown( sv[1], SHUT_RD ) );
  long now = fd_log_wallclock();
  int charge_busy = 0;
  fd_event_client_poll( client, now, &charge_busy );
  FD_TEST( client->state==FD_EVENT_CLIENT_STATE_DISCONNECTED && client->sockfd==-1 );
  FD_TEST( client->metrics.transport_fail_cnt==1UL && client->consecutive_failure_count==1UL );
  FD_TEST( !charge_busy );

  /* Without an immediate repoll, the tile parks until the reconnect timer.
     A stale reason must not disconnect the replacement opened by that poll. */
  int listener = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  FD_TEST( listener>=0 );
  struct sockaddr_in addr = { .sin_family=AF_INET, .sin_addr.s_addr=htonl( INADDR_LOOPBACK ) };
  FD_TEST( 0==bind( listener, fd_type_pun_const( &addr ), sizeof(addr) ) );
  FD_TEST( 0==listen( listener, 1 ) );
  socklen_t addr_sz = sizeof(addr);
  FD_TEST( 0==getsockname( listener, fd_type_pun( &addr ), &addr_sz ) );
  fd_cstr_ncpy( client->server_fqdn, "127.0.0.1", sizeof(client->server_fqdn) );
  client->server_fqdn_len = strlen( client->server_fqdn );
  client->server_tcp_port = ntohs( addr.sin_port );
  long retry = fd_event_client_next_deadline( client, now );
  FD_TEST( retry>now );
  charge_busy = 0;
  fd_event_client_poll( client, retry, &charge_busy );
  FD_TEST( client->state==FD_EVENT_CLIENT_STATE_CONNECTING && client->sockfd>=0 );
  FD_TEST( client->defer_disconnect==INT_MAX );
  FD_TEST( client->metrics.connect_attempt_cnt==1UL && client->metrics.transport_fail_cnt==1UL );
  FD_TEST( client->consecutive_failure_count==1UL );

  close( listener ); close( client->sockfd ); close( sv[1] );
  free( client );
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* A stream about to cross the body cap half-closes, and a new one opens
   on the same connection after a fresh token.  Acks on the new stream
   are held until the old one is fully acked, then the old stream is
   cancelled. */
FD_UNIT_TEST( stream_rotation ) {
  static uchar circq_mem[ 4096UL+(1UL<<20) ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 1UL<<20 ) );
  FD_TEST( circq );
  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  fd_event_client_t * client = test_connected_client( circq, rng, 65536UL );
  fd_grpc_client_t * grpc = client->grpc_client;
  grpc->conn->peer_settings.max_concurrent_streams = 100U;
  client->stream_gen = 1UL;
  client->event_stream->request_ctx = FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS|(1UL<<8);
  ulong const ctx1 = FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS|(1UL<<8);
  ulong const ctx2 = FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS|(2UL<<8);

  for( ulong i=0UL; i<4UL; i++ ) { uchar * b = fd_circq_push_back( circq, 1UL, 16UL ); FD_TEST( b ); memset( b, 0, 16UL ); }
  long now = fd_log_wallclock();
  client->tx_tokens = FD_EVENT_CLIENT_TX_BURST; client->tx_tokens_ns = now;
  test_poll_tx( client, now ); test_drain( grpc );
  test_poll_tx( client, now ); test_drain( grpc );
  FD_TEST( client->metrics.events_sent==2UL );

  /* The next message fits exactly: it goes out. */
  client->stream_tx_sz = (FD_EVENT_CLIENT_STREAM_BODY_CAP-FD_EVENT_CLIENT_STREAM_BODY_MARGIN)-sizeof(fd_grpc_hdr_t)-16UL;
  test_poll_tx( client, now ); test_drain( grpc );
  FD_TEST( client->metrics.events_sent==3UL && client->event_stream );

  /* One more would cross the cap: half-close and request a token. */
  fd_grpc_h2_stream_t * old = client->event_stream;
  test_poll_tx( client, now );
  FD_TEST( client->metrics.events_sent==3UL );
  FD_TEST( !client->event_stream && client->drain_stream==old );
  FD_TEST( old->s.state==FD_H2_STREAM_STATE_CLOSING_TX && old->has_rx_end_deadline );
  FD_TEST( client->drain_gen==1UL && client->drain_last==2UL );
  FD_TEST( client->auth_send_pending && client->state==FD_EVENT_CLIENT_STATE_CONNECTED );
  test_drain( grpc );

  /* No new stream before the token arrives. */
  client->auth_bearer_len = 0UL;
  test_poll_tx( client, now );
  FD_TEST( !client->event_stream );

  /* Token arrives: new stream opens with generation 2. */
  client->auth_bearer_len = 4UL; memcpy( client->auth_bearer, "abcd", 5UL );
  test_poll_tx( client, now ); test_drain( grpc );
  FD_TEST( client->event_stream && client->event_stream!=old );
  FD_TEST( client->event_stream->request_ctx==ctx2 );
  FD_TEST( client->stream_gen==2UL && !client->stream_tx_sz && !client->auth_bearer_len );
  client->event_stream->s.tx_wnd = UINT_MAX>>1;
  test_poll_tx( client, now ); test_drain( grpc );
  FD_TEST( client->metrics.events_sent==4UL );

  /* While the old stream drains, a full new stream waits instead of
     rotating again. */
  {
    uchar * b = fd_circq_push_back( circq, 1UL, 16UL ); FD_TEST( b ); memset( b, 0, 16UL );
  }
  client->stream_tx_sz = (FD_EVENT_CLIENT_STREAM_BODY_CAP-FD_EVENT_CLIENT_STREAM_BODY_MARGIN);
  test_poll_tx( client, now );
  FD_TEST( client->metrics.events_sent==4UL && client->event_stream && !test_drain( grpc ) );
  client->stream_tx_sz = 0UL;

  /* A new-stream ack is held; old-stream acks apply. */
  uchar ack[2] = { 0x08, 0x03 };
  fd_event_client_handle_stream_events_resp( client, ack, 2UL, ctx2 );
  FD_TEST( client->held_ack==3UL && circq->cnt==5UL );
  ack[1] = 0x01;
  fd_event_client_handle_stream_events_resp( client, ack, 2UL, ctx1 );
  FD_TEST( client->metrics.last_acked_id==1UL && circq->cnt==3UL && client->drain_gen );

  /* The old stream's last event acked: the held ack applies and the
     still-open old stream is cancelled on the next poll. */
  ack[1] = 0x02;
  fd_event_client_handle_stream_events_resp( client, ack, 2UL, ctx1 );
  FD_TEST( !client->drain_gen && client->held_ack==ULONG_MAX );
  FD_TEST( client->metrics.last_acked_id==3UL && circq->cnt==1UL );
  FD_TEST( client->drain_stream==old );
  ulong stream_cnt = grpc->stream_cnt;
  test_poll_tx( client, now );
  FD_TEST( !client->drain_stream && grpc->stream_cnt==stream_cnt-1UL );
  fd_h2_frame_hdr_t rst; FD_TEST( fd_h2_rbuf_used_sz( grpc->frame_tx )>=sizeof(fd_h2_rst_stream_t) );
  fd_h2_rbuf_pop_copy( grpc->frame_tx, &rst, sizeof(rst) );
  FD_TEST( fd_h2_frame_type( rst.typlen )==FD_H2_FRAME_TYPE_RST_STREAM );
  test_drain( grpc );

  /* A late watermark from the drained stream is ignored. */
  ack[1] = 0x02;
  fd_event_client_handle_stream_events_resp( client, ack, 2UL, ctx1 );
  FD_TEST( client->metrics.last_acked_id==3UL );
  test_poll_tx( client, now ); test_drain( grpc );
  FD_TEST( client->metrics.events_sent==5UL );

  /* A rotated stream the server ends before acking it reconnects. */
  fd_grpc_resp_hdrs_t hdrs = { .h2_status=200, .grpc_status=FD_GRPC_STATUS_OK };
  client->stream_tx_sz = (FD_EVENT_CLIENT_STREAM_BODY_CAP-FD_EVENT_CLIENT_STREAM_BODY_MARGIN);
  {
    uchar * b = fd_circq_push_back( circq, 1UL, 16UL ); FD_TEST( b ); memset( b, 0, 16UL );
  }
  test_poll_tx( client, now ); test_drain( grpc );
  FD_TEST( client->drain_gen==2UL && client->drain_last==4UL && client->drain_stream );
  fd_event_client_grpc_rx_end( client, ctx2, &hdrs );
  FD_TEST( !client->drain_stream );
  FD_TEST( client->defer_disconnect==DISCONNECT_REASON_PEER_CLOSED );

  free( client );
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* With one concurrent stream allowed, a fully acked drain stream the
   server has not ended holds the only slot: it is cancelled even though
   the replacement stream is still waiting for its token. */
FD_UNIT_TEST( stream_rotation_single_slot ) {
  static uchar circq_mem[ 4096UL+(1UL<<20) ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 1UL<<20 ) );
  FD_TEST( circq );
  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  fd_event_client_t * client = test_connected_client( circq, rng, 65536UL );
  fd_grpc_client_t * grpc = client->grpc_client;
  grpc->conn->peer_settings.max_concurrent_streams = 1U;
  client->stream_gen = 1UL;
  ulong const ctx1 = FD_EVENT_CLIENT_REQ_CTX_STREAM_EVENTS|(1UL<<8);
  client->event_stream->request_ctx = ctx1;

  uchar * b = fd_circq_push_back( circq, 1UL, 16UL ); FD_TEST( b ); memset( b, 0, 16UL );
  b = fd_circq_push_back( circq, 1UL, 16UL ); FD_TEST( b ); memset( b, 0, 16UL );
  long now = fd_log_wallclock();
  client->tx_tokens = FD_EVENT_CLIENT_TX_BURST; client->tx_tokens_ns = now;
  test_poll_tx( client, now ); test_drain( grpc );
  FD_TEST( client->metrics.events_sent==1UL );

  /* Rotate: the half-closed stream keeps the only slot. */
  client->stream_tx_sz = (FD_EVENT_CLIENT_STREAM_BODY_CAP-FD_EVENT_CLIENT_STREAM_BODY_MARGIN);
  test_poll_tx( client, now ); test_drain( grpc );
  fd_grpc_h2_stream_t * old = client->drain_stream;
  FD_TEST( old && !client->event_stream && client->drain_gen==1UL );
  FD_TEST( !fd_grpc_client_stream_acquire_is_safe( grpc ) );
  FD_TEST( !fd_event_client_try_send_authenticate( client, now ) );
  long dl = fd_event_client_next_deadline( client, now );
  FD_TEST( dl>now && dl<=now+FD_EVENT_CLIENT_STREAM_DRAIN_NANOS ); /* no busy retry */

  /* Fully acked: the next poll frees the slot without a token. */
  uchar ack[2] = { 0x08, 0x00 };
  fd_event_client_handle_stream_events_resp( client, ack, 2UL, ctx1 );
  FD_TEST( !client->drain_gen && client->drain_stream==old );
  client->auth_bearer_len = 0UL;
  test_poll_tx( client, now );
  FD_TEST( !client->drain_stream );
  FD_TEST( fd_grpc_client_stream_acquire_is_safe( grpc ) );
  test_drain( grpc );
  FD_TEST( fd_event_client_next_deadline( client, now )==now );
  FD_TEST( fd_event_client_try_send_authenticate( client, now ) );

  free( client );
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* The Authenticate response takes the challenge and an optional stream
   body cap in either order; anything else fails authentication. */
FD_UNIT_TEST( auth_resp_fields ) {
  static uchar circq_mem[ 4096UL+512UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 512UL ) );
  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  fd_event_client_t * client = test_connected_client( circq, rng, 4096UL );
  ulong const def = FD_EVENT_CLIENT_STREAM_BODY_CAP-FD_EVENT_CLIENT_STREAM_BODY_MARGIN;

  uchar tok[ 3UL+FD_EVENT_CLIENT_TOKEN_SZ ] = { 0x0a, 0xd9, 0x01 }; /* field 1, len 217 */
  uchar cap[ 5 ] = { 0x10, 0x80, 0x80, 0x80, 0x01 };               /* field 2 = 2^21 */
  uchar small[ 4 ] = { 0x10, 0x80, 0x80, 0x01 };                     /* field 2 = 2^14, below buf_max */
  uchar buf[ 512 ];

  /* challenge only: default cap */
  client->defer_disconnect = INT_MAX; test_sign_cnt = 0UL;
  fd_event_client_handle_auth_challenge_resp( client, tok, sizeof(tok) );
  FD_TEST( client->defer_disconnect==INT_MAX && test_sign_cnt==1UL );
  FD_TEST( client->stream_body_max==def );

  /* cap before challenge */
  memcpy( buf, cap, 5UL ); memcpy( buf+5UL, tok, sizeof(tok) );
  test_sign_cnt = 0UL;
  fd_event_client_handle_auth_challenge_resp( client, buf, 5UL+sizeof(tok) );
  FD_TEST( client->defer_disconnect==INT_MAX && test_sign_cnt==1UL );
  FD_TEST( client->stream_body_max==(1UL<<21)-FD_EVENT_CLIENT_STREAM_BODY_MARGIN );

  /* cap after challenge */
  memcpy( buf, tok, sizeof(tok) ); memcpy( buf+sizeof(tok), cap, 5UL );
  client->stream_body_max = 0UL;
  fd_event_client_handle_auth_challenge_resp( client, buf, sizeof(tok)+5UL );
  FD_TEST( client->defer_disconnect==INT_MAX );
  FD_TEST( client->stream_body_max==(1UL<<21)-FD_EVENT_CLIENT_STREAM_BODY_MARGIN );

  /* missing challenge, wrong size, truncated, unknown field, cap below the
     largest event: auth fails without signing */
  uchar bad_size[ 4 ] = { 0x0a, 0x02, 0x00, 0x00 };
  uchar unknown[ 3UL+FD_EVENT_CLIENT_TOKEN_SZ+2UL ];
  memcpy( unknown, tok, sizeof(tok) ); unknown[ sizeof(tok) ] = 0x18; unknown[ sizeof(tok)+1UL ] = 0x01;
  uchar too_small[ sizeof(tok)+4UL ];
  memcpy( too_small, tok, sizeof(tok) ); memcpy( too_small+sizeof(tok), small, 4UL );
  struct { uchar const * p; ulong sz; } bad[] = {
    { cap, 5UL }, { bad_size, 4UL }, { tok, sizeof(tok)-1UL }, { unknown, sizeof(unknown) }, { tok, 0UL }, { too_small, sizeof(too_small) }
  };
  for( ulong i=0UL; i<sizeof(bad)/sizeof(bad[0]); i++ ) {
    client->defer_disconnect = INT_MAX; test_sign_cnt = 0UL;
    fd_event_client_handle_auth_challenge_resp( client, bad[ i ].p, bad[ i ].sz );
    FD_TEST( client->defer_disconnect==DISCONNECT_REASON_AUTH_FAILED && !test_sign_cnt );
  }

  free( client );
  fd_rng_delete( fd_rng_leave( rng ) );
}

/* A rotation Authenticate that ends without a challenge reconnects. */
FD_UNIT_TEST( rotation_auth_no_challenge ) {
  static uchar circq_mem[ 4096UL+512UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 512UL ) );
  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  fd_event_client_t * client = test_connected_client( circq, rng, 4096UL );
  fd_grpc_resp_hdrs_t hdrs = { .h2_status=200, .grpc_status=FD_GRPC_STATUS_OK };

  /* Challenge received: the stream opens on the next poll, no disconnect */
  client->event_stream    = NULL;
  client->auth_bearer_len = 4UL;
  fd_event_client_grpc_rx_end( client, FD_EVENT_CLIENT_REQ_CTX_AUTHENTICATE, &hdrs );
  FD_TEST( client->defer_disconnect==INT_MAX );

  /* No challenge */
  client->auth_bearer_len = 0UL;
  fd_event_client_grpc_rx_end( client, FD_EVENT_CLIENT_REQ_CTX_AUTHENTICATE, &hdrs );
  FD_TEST( client->defer_disconnect==DISCONNECT_REASON_AUTH_FAILED );

  free( client );
  fd_rng_delete( fd_rng_leave( rng ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  g_epoll_fd = epoll_create1( 0 );
  FD_TEST( -1!=g_epoll_fd );
  fd_unit_tests( argc, argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
