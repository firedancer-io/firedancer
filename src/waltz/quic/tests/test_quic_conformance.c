/* test_quic_conformance verifies that fd_quic adheres to various
   assertions made in the QUIC specification (RFC 9000). */

#include "fd_quic_sandbox.h"
#include "../fd_quic_proto.h"
#include "../fd_quic_proto.c"
#include "../fd_quic_private.h"
#include "../templ/fd_quic_parse_util.h"
#include "../../tls/fd_tls_proto.h"

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
  conn->rx_sup_stream_id = (2UL<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  uchar buf[ 1024 ];
  fd_quic_stream_frame_t stream_frame =
    { .stream_id  = FD_QUIC_STREAM_TYPE_UNI_CLIENT,
      .fin_opt    = 1,
      .length_opt = 2,
      .length     = 2UL };
  ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
  memset( buf+sz, '0', 2 );
  sz += 2;

  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state  == FD_QUIC_CONN_STATE_ABORT );
  FD_TEST( conn->reason == FD_QUIC_CONN_REASON_FLOW_CONTROL_ERROR );
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
  conn->rx_sup_stream_id = 0UL + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  uchar buf[ 1024 ];
  fd_quic_stream_frame_t stream_frame =
    { .stream_id = FD_QUIC_STREAM_TYPE_UNI_CLIENT,
      .fin_opt   = 1 };
  ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );

  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state  == FD_QUIC_CONN_STATE_ABORT );
  FD_TEST( conn->reason == FD_QUIC_CONN_REASON_STREAM_LIMIT_ERROR );
}

/* Ensure that worst-case stream pool allocations are bounded.

   This is a custom protocol restriction that goes beyond QUIC's limits. */

static __attribute__ ((noinline)) void
test_quic_stream_concurrency( fd_quic_sandbox_t * sandbox,
                              fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->rx_sup_stream_id = (1024UL<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  // ulong const max_streams = 32UL;

  /* Each frame initiates a new stream without closing it */
  for( ulong j=0UL; j<512UL; j++ ) {
    uchar buf[ 1024 ];
    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = FD_QUIC_STREAM_TYPE_UNI_CLIENT,
        .length_opt = 1,
        .length     = 1UL };
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  }

}

/* - Ensure that a high stream ID prunes low stream IDs
   - Ensure that pruned low stream IDs are not received multiple times */

static __attribute__((noinline)) void
test_quic_stream_skip( fd_quic_sandbox_t * sandbox,
                       fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->rx_sup_stream_id = (1024UL<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  /* Fill the current stream window with unfinished streams */
  ulong window_cnt = sandbox->quic->limits.rx_stream_cnt;
  for( ulong j=0UL; j<window_cnt; j++ ) {
    uchar buf[ 64 ];
    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = (j<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT,
        .length_opt = 1,
        .length     = 1UL };
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  }
  FD_TEST( sandbox->quic->metrics.stream_opened_cnt   == window_cnt );
  FD_TEST( sandbox->quic->metrics.stream_closed_cnt[3]== 0UL        );
  FD_TEST( sandbox->quic->metrics.stream_rx_event_cnt == window_cnt );
  FD_TEST( sandbox->quic->metrics.stream_active_cnt   == window_cnt );

  /* Send one more stream frame without a gap.  This moves the stream
     receive window one up.  The oldest stream thereby drops below the
     window and gets aborted. */
  do {
    uchar buf[ 64 ];
    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = (window_cnt<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT,
        .length_opt = 1,
        .length     = 1UL };
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  } while(0);
  FD_TEST( sandbox->quic->metrics.stream_opened_cnt   == window_cnt+1UL );
  FD_TEST( sandbox->quic->metrics.stream_closed_cnt[3]==            1UL ); /* drop */
  FD_TEST( sandbox->quic->metrics.stream_rx_event_cnt == window_cnt+1UL );
  FD_TEST( sandbox->quic->metrics.frame_rx_cnt[6]     == window_cnt+1UL );
  FD_TEST( sandbox->quic->metrics.stream_active_cnt   == window_cnt     );

  /* Send data on a closed stream.  Frame should be ignored */
  do {
    uchar buf[ 64 ];
    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = FD_QUIC_STREAM_TYPE_UNI_CLIENT,
        .length_opt = 1,
        .length     = 1UL,
        .offset_opt = 1,
        .offset     = 1UL,
        .fin_opt    = 1 };
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  } while(0);
  FD_TEST( sandbox->quic->metrics.stream_opened_cnt   == window_cnt+1UL );
  FD_TEST( sandbox->quic->metrics.stream_closed_cnt[0]==            0UL ); /* end */
  FD_TEST( sandbox->quic->metrics.stream_closed_cnt[3]==            1UL ); /* drop */
  FD_TEST( sandbox->quic->metrics.stream_rx_event_cnt == window_cnt+1UL );
  FD_TEST( sandbox->quic->metrics.stream_active_cnt   == window_cnt     );

  /* Send a stream, skipping one stream ID.  This moves up the window
     by two, dropping two streams. */
  do {
    uchar buf[ 64 ];
    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = ((window_cnt+2)<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT,
        .length_opt = 1,
        .length     = 1UL };
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  } while(0);
  FD_TEST( sandbox->quic->metrics.stream_opened_cnt   == window_cnt+2UL );
  FD_TEST( sandbox->quic->metrics.stream_closed_cnt[3]==            3UL ); /* drop */
  FD_TEST( sandbox->quic->metrics.stream_rx_event_cnt == window_cnt+2UL );
  FD_TEST( sandbox->quic->metrics.stream_active_cnt   == window_cnt-1UL );

  /* All streams should close when the connection winds down */
  do {
    uchar buf[ 64 ];
    fd_quic_conn_close_1_frame_t close_frame = {0};
    ulong sz = fd_quic_encode_conn_close_1_frame( buf, sizeof(buf), &close_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  } while(0);

  /* Mark conn as free */
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_PEER_CLOSE );
  fd_quic_conn_service( sandbox->quic, conn, fd_quic_now( sandbox->quic ) );
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_DEAD );
  FD_TEST( sandbox->quic->metrics.conn_closed_cnt == 1UL );

  /* Actually free conn */
  fd_quic_conn_free( sandbox->quic, conn );
  FD_TEST( sandbox->quic->metrics.stream_closed_cnt[3] ==            3UL ); /* drop */
  FD_TEST( sandbox->quic->metrics.stream_closed_cnt[4] == window_cnt-1UL ); /* conn */
  FD_TEST( sandbox->quic->metrics.stream_active_cnt    ==            0UL );
}

static __attribute__((noinline)) void
test_quic_stream_retransmit( fd_quic_sandbox_t * sandbox,
                             fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->rx_sup_stream_id = (1024UL<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  /* Send same stream multiple times */
  uchar buf[ 64 ];
  fd_quic_stream_frame_t stream_frame =
    { .stream_id  = FD_QUIC_STREAM_TYPE_UNI_CLIENT,
      .length_opt = 1,
      .length     = 1UL,
      .fin_opt    = 1 };

  for( ulong j=0; j<32; j++ ) {
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  }
  FD_TEST( sandbox->quic->metrics.stream_rx_event_cnt == 1UL );
  FD_TEST( sandbox->quic->metrics.stream_active_cnt == 0UL );
}

/* reorder: ensure that reordered fragments arrive without corruption */

/* Ensure that the server-side spends less than O(n) time handling
   skipped stream IDs.  (Otherwise, this test would run for a very long
   time) */

static __attribute__((noinline)) void
test_quic_stream_skip_long( fd_quic_sandbox_t * sandbox,
                            fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->rx_sup_stream_id = (1UL<<62)-1;

  for( ulong j=0UL; j<1024UL; j++ ) {
    uchar buf[ 256 ] = {0};
    ulong stream_id = (j<<32) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;
    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = stream_id,
        .length_opt = 1,
        .length     = 1UL };
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
    FD_TEST( sandbox->quic->metrics.stream_rx_event_cnt == j+1UL );
    FD_TEST( sandbox->quic->metrics.stream_active_cnt == 1 );
  }
}

/* Replay a traffic pattern generated by solana-connection-cache v2.0.3
   The table below is created from captured metadata running
   contrib/quic/agave_compat in spam-server mode.
   This version of Agave uses the quinn QUIC client in way that creates
   unnecessary fragmentation, making for a good unit test.  */

struct stream_frame {
  ulong                  pkt_num;
  fd_quic_stream_frame_t s;
};

static __attribute__((noinline)) void
test_quic_stream_agave_2_0_3( fd_quic_sandbox_t * sandbox,
                              fd_rng_t *          rng ) {

  FD_LOG_INFO(( "test_quic_stream_agave_2_0_3 start" ));

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->rx_sup_stream_id = (1UL<<62)-1;
  conn->rx_max_data      = (1UL<<62)-1;
  sandbox->quic->config.initial_rx_max_stream_data = 1232UL;

  struct stream_frame frames[] = {
    { .pkt_num= 1, .s={ .stream_id= 2, .offset=  0, .length= 153, .fin_opt=1 } },
    { .pkt_num= 5, .s={ .stream_id= 6, .offset=  0, .length=1018, .fin_opt=1 } },
    { .pkt_num= 5, .s={ .stream_id=10, .offset=  0, .length= 276, .fin_opt=0 } },
    { .pkt_num= 6, .s={ .stream_id=14, .offset=  0, .length=1136, .fin_opt=1 } },
    { .pkt_num= 6, .s={ .stream_id=18, .offset=  0, .length= 158, .fin_opt=0 } },
    { .pkt_num= 7, .s={ .stream_id=22, .offset=  0, .length= 845, .fin_opt=1 } },
    { .pkt_num= 7, .s={ .stream_id=26, .offset=  0, .length= 394, .fin_opt=1 } },
    { .pkt_num= 7, .s={ .stream_id=30, .offset=  0, .length=  51, .fin_opt=0 } },
    { .pkt_num= 8, .s={ .stream_id=34, .offset=  0, .length= 368, .fin_opt=1 } },
    { .pkt_num= 8, .s={ .stream_id=38, .offset=  0, .length= 926, .fin_opt=0 } },
    { .pkt_num= 9, .s={ .stream_id=42, .offset=  0, .length= 404, .fin_opt=1 } },
    { .pkt_num= 9, .s={ .stream_id=46, .offset=  0, .length= 890, .fin_opt=0 } },
    { .pkt_num=10, .s={ .stream_id=50, .offset=  0, .length= 386, .fin_opt=1 } },
    { .pkt_num=10, .s={ .stream_id=54, .offset=  0, .length= 112, .fin_opt=1 } },
    { .pkt_num=10, .s={ .stream_id=58, .offset=  0, .length= 792, .fin_opt=0 } },
    { .pkt_num=11, .s={ .stream_id=62, .offset=  0, .length= 567, .fin_opt=1 } },
    { .pkt_num=11, .s={ .stream_id=10, .offset=276, .length= 302, .fin_opt=1 } },
    { .pkt_num=11, .s={ .stream_id=18, .offset=158, .length= 317, .fin_opt=1 } },
    { .pkt_num=11, .s={ .stream_id=30, .offset= 51, .length=  95, .fin_opt=0 } },
    { .pkt_num=12, .s={ .stream_id=38, .offset=926, .length= 142, .fin_opt=1 } },
    { .pkt_num=12, .s={ .stream_id=46, .offset=890, .length= 199, .fin_opt=1 } },
    { .pkt_num=12, .s={ .stream_id=58, .offset=792, .length= 342, .fin_opt=1 } },
    { .pkt_num=12, .s={ .stream_id=30, .offset=146, .length= 374, .fin_opt=1 } },
    { .pkt_num=13, .s={ .stream_id=66, .fin_opt=1 } } /* dummy */
  };
  ulong const frame_cnt = sizeof(frames)/sizeof(struct stream_frame);

  ulong last_pkt_num              = 0UL;
  int   last_pkt_contained_stream = 0;
  for( ulong j=0UL; j<frame_cnt; j++ ) {
    struct stream_frame * frame = frames+j;
    frame->s.offset_opt = 1;
    frame->s.length_opt = 1;

    /* ACK previous packet numbers */
    while( last_pkt_num < frame->pkt_num ) {
      if( last_pkt_contained_stream ) {
        fd_quic_ack_pkt( conn->ack_gen, last_pkt_num, fd_quic_enc_level_appdata_id, sandbox->wallclock );
        last_pkt_contained_stream = 0;
      }
      last_pkt_num++;
    }

    /* Send stream frame */
    uchar buf[ 1500 ];
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &frame->s );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    fd_memset( buf+sz, '0', frame->s.length );
    sz += frame->s.length;

    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
    FD_TEST( conn->ack_gen->is_elicited==1 );
    last_pkt_contained_stream = 1;
    FD_LOG_DEBUG(( "stream_id=%lu active=%lu", frame->s.stream_id, sandbox->quic->metrics.stream_active_cnt ));
  }

  FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  if( FD_UNLIKELY( sandbox->quic->metrics.stream_active_cnt ) ) FD_LOG_WARNING(( "%lu active streams", sandbox->quic->metrics.stream_active_cnt ));
  FD_TEST( sandbox->quic->metrics.stream_active_cnt  ==    0UL );
  FD_TEST( sandbox->quic->metrics.stream_rx_byte_cnt == 9159UL );
  FD_TEST( conn->unacked_sz == 10247UL );

  FD_LOG_INFO(( "test_quic_stream_agave_2_0_3 end" ));
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
      /* server       */ quic->config.role == FD_QUIC_ROLE_SERVER );
  FD_TEST( conn );

  fd_quic_transport_params_t tp[1] = {0};
  fd_quic_tls_hs_t * tls_hs = fd_quic_tls_hs_new(
      state->tls,
      (void*)conn,
      1 /*is_server*/,
      quic->config.sni,
      tp );
  conn->tls_hs = tls_hs;

  /* Send the TLS handshake message */

  fd_quic_pkt_t pkt = { .enc_level = fd_quic_enc_level_initial_id };
  fd_quic_sandbox_send_frame( sandbox, conn, &pkt, crypto_frame, sizeof(crypto_frame) );

  /* Verify that fd_quic derived the correct error code */

  FD_TEST( conn->state == FD_QUIC_CONN_STATE_ABORT );
  FD_TEST( conn->reason == FD_QUIC_CONN_REASON_CRYPTO_BASE + FD_TLS_ALERT_NO_APPLICATION_PROTOCOL );

  /* Verify that the response looks correct */

  fd_quic_service( quic );
  fd_frag_meta_t const * frag = fd_quic_sandbox_next_packet( sandbox );
  FD_TEST( frag );

  uchar *       resp_ptr = fd_chunk_to_laddr( sandbox, frag->chunk );
  uchar const * resp_end = resp_ptr + frag->sz;
  resp_ptr += sizeof(fd_eth_hdr_t) + sizeof(fd_ip4_hdr_t) + sizeof(fd_udp_hdr_t);
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

/* Test FIN arriving out of place */

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
    .conn_cnt         =   4UL,
    .handshake_cnt    =   1UL,
    .conn_id_cnt      =   4UL,
    .stream_id_cnt    =   8UL,
    .rx_stream_cnt    =   8UL,
    .inflight_pkt_cnt =   8UL,
    .tx_buf_sz        = 512UL,
    .stream_pool_cnt  =  32UL,
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

  fd_quic_sandbox_t * sandbox = fd_quic_sandbox_join( fd_quic_sandbox_new(
      sandbox_mem, &quic_limits, pkt_cnt, pkt_mtu ) );
  FD_TEST( sandbox );

  /* Run tests */
  test_quic_stream_data_limit_enforcement( sandbox, rng );
  test_quic_stream_limit_enforcement     ( sandbox, rng );
  test_quic_stream_concurrency           ( sandbox, rng );
  test_quic_stream_retransmit            ( sandbox, rng );
  test_quic_stream_skip                  ( sandbox, rng );
  test_quic_stream_skip_long             ( sandbox, rng );
  test_quic_stream_agave_2_0_3           ( sandbox, rng );
  test_quic_ping_frame                   ( sandbox, rng );
  test_quic_server_alpn_fail             ( sandbox, rng );

  /* Wind down */

  fd_wksp_free_laddr( fd_quic_sandbox_delete( fd_quic_sandbox_leave( sandbox ) ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
