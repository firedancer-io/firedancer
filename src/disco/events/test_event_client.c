#include "fd_event_client.c"
#include "../../util/tmpl/fd_unit_test.c"

/* TODO: The conn_ssl_lifecycle test previously used OpenSSL to set up a
   mock TLS server with in-memory BIO pairs.  This needs to be rewritten
   to use fd_tlsrec once a suitable in-memory test harness is available. */

FD_UNIT_TEST( stream_heartbeat ) {
  static uchar circq_mem[ 4096UL+512UL ] __attribute__((aligned(FD_CIRCQ_ALIGN)));
  fd_circq_t * circq = fd_circq_join( fd_circq_new( circq_mem, 512UL ) );
  FD_TEST( circq );

  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 1UL ) );
  FD_TEST( rng );

  static uchar client_mem[ 131072UL ] __attribute__((aligned(128)));
  uchar identity_pubkey[32] = {0};
  fd_event_client_t * client = fd_event_client_join( fd_event_client_new(
      client_mem,
      NULL,
      rng,
      circq,
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
  client->last_stream_send_ticks = fd_tickcount();
  int charge_busy = 0;
  tx( client, &charge_busy );
  FD_TEST( !charge_busy );
  FD_TEST( !grpc->request_tx_op->chunk_sz );

  /* Idle circq, stream quiet past the heartbeat interval: a zero-length
     StreamEventsRequest goes out — exactly one 5-byte gRPC frame header
     (compressed=0, msg_sz=0). */
  client->last_stream_send_ticks = fd_tickcount()-client->heartbeat_ticks-1L;
  tx( client, &charge_busy );
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
  FD_TEST( client->last_stream_send_ticks>fd_tickcount()-client->heartbeat_ticks );

  /* The server's no-op ack reply (nonce=ULONG_MAX) is ignored: no circq
     pop, no disconnect. */
  uchar resp[ 11 ] = { 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 }; /* field 1 varint ULONG_MAX */
  client->defer_disconnect = INT_MAX;
  fd_event_client_handle_stream_events_resp( client, resp, sizeof(resp) );
  FD_TEST( client->defer_disconnect==INT_MAX );
  FD_TEST( client->metrics.last_acked_id==0UL );

  fd_rng_delete( fd_rng_leave( rng ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_unit_tests( argc, argv );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
