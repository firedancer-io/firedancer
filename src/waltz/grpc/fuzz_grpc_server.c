/* fuzz_grpc_server.c drives fd_grpc_server with arbitrary HTTP/2 frame
   streams from a client: request field blocks, gRPC message framing,
   flow control, and the zstd coded request path.  It looks for crashes,
   spin loops, leaked stream slots, and unbalanced callbacks, and checks:

   - the send ring and stream treap invariants after every step (every
     pending reference still lies in the live part of the ring, the
     treap holds exactly the streams with pending output, in order),
   - the bytes the server sends: every gRPC message a client receives
     is one the handler sent on that stream, intact and in order,
   - that a connection keeps reading while its peer drains the output,
   - that a connection going away accepts no new calls and its close
     deadline only moves earlier,
   - that a frame a client may still send on a stream the server just
     reset (RFC 9113 Section 5.4.2) does not end the connection.

   FUZZ_ORACLE_OFF in the environment is a bit mask of checks to skip
   (ORACLE_* below), so that a known failure does not hide others. */

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "fd_grpc_server_private.h"
#include "../h2/fd_h2_proto.h"
#include "../../util/fd_util.h"

/* The server's treap, instantiated again so that it can be walked */
#define TREAP_NAME      stream_treap
#define TREAP_T         fd_grpc_server_stream_t
#define TREAP_QUERY_T   void *
#define TREAP_CMP(q,e)  (__extension__({ (void)(q); (void)(e); -1; }))
#define TREAP_IDX_T     uint
#define TREAP_PARENT    treap_parent
#define TREAP_LEFT      treap_left
#define TREAP_RIGHT     treap_right
#define TREAP_PRIO      treap_prio
#define TREAP_NEXT      treap_next
#define TREAP_PREV      treap_prev
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_LT(e0,e1) ((e0)->refs[ (e0)->ref_idx ].off < (e1)->refs[ (e1)->ref_idx ].off)
#include "../../util/tmpl/fd_treap.c"

#define FUZZ_ROUTE_UNARY  "/fuzz.Svc/Unary"
#define FUZZ_ROUTE_STREAM "/fuzz.Svc/Stream"

#define ORACLE_RING    (1UL<<0) /* send ring and treap invariants */
#define ORACLE_OUTPUT  (1UL<<1) /* received messages match what was sent */
#define ORACLE_H2_RX   (1UL<<2) /* an HTTP/2 connection keeps reading */
#define ORACLE_WEB_RX  (1UL<<3) /* an HTTP/1.1 connection keeps reading */
#define ORACLE_GOAWAY  (1UL<<4) /* no new calls, close deadline never later */
#define ORACLE_LATE    (1UL<<5) /* frames a peer may send on a stream just reset are tolerated */

static ulong g_oracle_off;
static int   g_trace;     /* FUZZ_TRACE: print the frames the server sends */
static int   g_stats;     /* FUZZ_STATS: print how far inputs got at exit */
static ulong g_stat_input;
static ulong g_stat_lapped;       /* inputs whose output wrapped the ring */
static ulong g_stat_lapped_lag;   /* ... with a lagging stream across the wrap */
static ulong g_stat_rx_full;      /* inputs that filled the receive buffer */
static int   g_input_lapped;
static int   g_input_lag;
static int   g_input_rx_full;

#define CHECK(cls,c,...) do {                                          \
    if( FD_UNLIKELY( !( g_oracle_off & (cls) ) && !(c) ) ) {           \
      FD_LOG_CRIT(( "oracle " #cls ": " __VA_ARGS__ ));                \
    }                                                                  \
  } while(0)

static FD_TL fd_rng_t g_rng[1];

/* Stream accounting: every stream the app accepted must be closed
   exactly once */
static FD_TL long g_stream_cnt;
static FD_TL long g_conn_cnt;

/* The compression context that zstd sizes for level 1 dominates. */
static uchar g_server_mem[ 8UL<<20 ] __attribute__((aligned(FD_GRPC_SERVER_ALIGN)));
static fd_grpc_server_t * g_server;

static fd_grpc_server_params_t g_params[1];

/* Output oracle ******************************************************/

/* Every message the handler sends on an HTTP/2 stream is logged by
   length and hash.  The bytes the server sends are parsed back as a
   client would, and each message received must be the next one logged
   for its stream.  A stream may stop early (it was reset, or ended
   with trailers after its pending output was dropped), so what is
   received is always a prefix of what was sent. */

#define ORC_SLOT_MAX (8UL)
#define ORC_FIFO_MAX (64UL)
#define ORC_MSG_MAX  (32768UL+5UL)

typedef struct {
  uint  sid;        /* 0 when the slot is free */
  int   overflow;   /* more messages than the log holds: stop checking */
  ulong fifo_len [ ORC_FIFO_MAX ];
  ulong fifo_hash[ ORC_FIFO_MAX ];
  ulong fifo_head;
  ulong fifo_cnt;
  ulong rx_sz;      /* bytes of the message being reassembled */
  uchar rx[ ORC_MSG_MAX ];
} orc_stream_t;

static orc_stream_t g_orc[ ORC_SLOT_MAX ];
static int          g_orc_on;    /* checking this input */
static uint         g_orc_done[ 64 ]; /* recently ended stream ids */
static ulong        g_orc_done_idx;

static uint  g_reset[ 16 ];      /* streams the server reset, not yet probed */
static ulong g_reset_cnt;

static uchar g_out[ 1UL<<16 ];   /* server output not yet parsed */
static ulong g_out_sz;
static uchar g_unz[ ORC_MSG_MAX ];

static ulong
orc_hash( uchar const * p,
          ulong         sz ) {
  ulong h = 0xcbf29ce484222325UL;
  for( ulong i=0UL; i<sz; i++ ) { h ^= (ulong)p[i]; h *= 0x100000001b3UL; }
  return h;
}

static void
orc_reset( int on ) {
  for( ulong i=0UL; i<ORC_SLOT_MAX; i++ ) { g_orc[i].sid = 0U; }
  fd_memset( g_orc_done, 0, sizeof(g_orc_done) );
  g_orc_done_idx = 0UL;
  g_out_sz       = 0UL;
  g_reset_cnt    = 0UL;
  g_orc_on       = on;
}

static orc_stream_t *
orc_query( uint sid ) {
  for( ulong i=0UL; i<ORC_SLOT_MAX; i++ ) if( g_orc[i].sid==sid ) return g_orc+i;
  return NULL;
}

static int
orc_is_done( uint sid ) {
  for( ulong i=0UL; i<64UL; i++ ) if( g_orc_done[i]==sid ) return 1;
  return 0;
}

static void
orc_end( orc_stream_t * s ) {
  g_orc_done[ g_orc_done_idx++ & 63UL ] = s->sid;
  s->sid = 0U;
}

/* orc_record logs a message the handler sent successfully. */

static void
orc_record( fd_grpc_server_stream_t * stream,
            uchar const *             msg,
            ulong                     msg_sz ) {
  if( !g_orc_on ) return;
  uint sid = stream->h2->stream_id;
  if( !sid ) return; /* HTTP/1.1 */
  orc_stream_t * s = orc_query( sid );
  if( !s ) {
    s = orc_query( 0U );
    if( !s ) { g_orc_on = 0; return; } /* too many live streams to track */
    s->sid       = sid;
    s->overflow  = 0;
    s->fifo_head = 0UL;
    s->fifo_cnt  = 0UL;
    s->rx_sz     = 0UL;
  }
  if( s->fifo_cnt==ORC_FIFO_MAX ) { s->overflow = 1; return; }
  ulong i = ( s->fifo_head + s->fifo_cnt++ ) % ORC_FIFO_MAX;
  s->fifo_len [ i ] = msg_sz;
  s->fifo_hash[ i ] = orc_hash( msg, msg_sz );
}

/* orc_msg checks one gRPC message received on a stream. */

static void
orc_msg( orc_stream_t * s,
         uchar const *  msg,
         ulong          sz,
         int            compressed ) {
  if( s->overflow ) return;
  uchar const * body    = msg;
  ulong         body_sz = sz;
  if( compressed ) {
    ulong n = ZSTD_decompress( g_unz, sizeof(g_unz), msg, sz );
    CHECK( ORACLE_OUTPUT, !ZSTD_isError( n ), "stream %u: compressed message does not decompress (%s)",
           s->sid, ZSTD_getErrorName( n ) );
    if( FD_UNLIKELY( ZSTD_isError( n ) ) ) return;
    body = g_unz; body_sz = n;
  }
  CHECK( ORACLE_OUTPUT, s->fifo_cnt, "stream %u: received a message the handler never sent (%lu bytes)", s->sid, body_sz );
  ulong i = s->fifo_head;
  CHECK( ORACLE_OUTPUT, s->fifo_len[ i ]==body_sz && s->fifo_hash[ i ]==orc_hash( body, body_sz ),
         "stream %u: message differs from the one sent (got %lu bytes, sent %lu)", s->sid, body_sz, s->fifo_len[ i ] );
  s->fifo_head = ( s->fifo_head+1UL ) % ORC_FIFO_MAX;
  s->fifo_cnt--;
}

/* orc_data takes the payload of a DATA frame. */

static void
orc_data( uint          sid,
          uchar const * p,
          ulong         sz ) {
  orc_stream_t * s = orc_query( sid );
  if( !s ) {
    CHECK( ORACLE_OUTPUT, !orc_is_done( sid ), "stream %u: DATA after the stream ended", sid );
    CHECK( ORACLE_OUTPUT, !sz, "stream %u: DATA on a stream with no message sent", sid );
    return;
  }
  if( s->overflow ) return;
  while( sz ) {
    ulong want = 5UL;
    if( s->rx_sz>=5UL ) want = 5UL + fd_uint_bswap( FD_LOAD( uint, s->rx+1 ) );
    ulong take = fd_ulong_min( sz, want-s->rx_sz );
    fd_memcpy( s->rx+s->rx_sz, p, take );
    s->rx_sz += take; p += take; sz -= take;
    if( s->rx_sz==5UL ) {
      uint len = fd_uint_bswap( FD_LOAD( uint, s->rx+1 ) );
      CHECK( ORACLE_OUTPUT, s->rx[0]<=1U, "stream %u: bad gRPC compressed flag %u", sid, (uint)s->rx[0] );
      CHECK( ORACLE_OUTPUT, (ulong)len+5UL<=ORC_MSG_MAX, "stream %u: gRPC message length %u too large", sid, len );
      if( FD_UNLIKELY( (ulong)len+5UL>ORC_MSG_MAX ) ) { s->overflow = 1; return; }
      want = 5UL+len;
    }
    if( s->rx_sz>=5UL && s->rx_sz==want ) {
      orc_msg( s, s->rx+5, s->rx_sz-5UL, s->rx[0]==1U );
      s->rx_sz = 0UL;
    }
  }
}

/* orc_parse takes the server's output, which it parses as frames. */

static void
orc_parse( uchar const * p,
           ulong         sz ) {
  if( !g_orc_on ) return;
  if( sz>sizeof(g_out)-g_out_sz ) { g_orc_on = 0; return; }
  fd_memcpy( g_out+g_out_sz, p, sz );
  g_out_sz += sz;

  ulong off = 0UL;
  for(;;) {
    if( g_out_sz-off<9UL ) break;
    uchar const * f   = g_out+off;
    ulong         len = ( (ulong)f[0]<<16 ) | ( (ulong)f[1]<<8 ) | (ulong)f[2];
    uint          typ = f[3];
    uint          flg = f[4];
    uint          sid = fd_uint_bswap( FD_LOAD( uint, f+5 ) ) & 0x7fffffffU;
    if( len>sizeof(g_out)-9UL ) { g_orc_on = 0; return; }
    if( g_out_sz-off<9UL+len ) break;
    uchar const * pl = f+9;
    if( g_trace ) fprintf( stderr, "server frame type=%u flags=0x%02x stream=%u len=%lu\n", typ, flg, sid, len );

    if( typ==FD_H2_FRAME_TYPE_DATA ) {
      CHECK( ORACLE_OUTPUT, !( flg & 0x08U ), "stream %u: padded DATA", sid );
      orc_data( sid, pl, len );
      if( flg & 0x01U ) {
        orc_stream_t * s = orc_query( sid );
        if( s ) {
          CHECK( ORACLE_OUTPUT, !s->rx_sz, "stream %u: END_STREAM part way through a message", sid );
          orc_end( s );
        }
      }
    } else if( typ==FD_H2_FRAME_TYPE_HEADERS ) {
      orc_stream_t * s = orc_query( sid );
      if( flg & 0x01U ) {
        /* Trailers: no message may be left half received */
        if( s ) {
          CHECK( ORACLE_OUTPUT, !s->rx_sz, "stream %u: trailers part way through a message", sid );
          orc_end( s );
        }
      } else {
        CHECK( ORACLE_OUTPUT, !orc_is_done( sid ), "stream %u: HEADERS after the stream ended", sid );
      }
    } else if( typ==FD_H2_FRAME_TYPE_RST_STREAM ) {
      orc_stream_t * s = orc_query( sid );
      if( s ) orc_end( s ); /* a message cut short is allowed here */
      if( sid && g_reset_cnt<16UL ) g_reset[ g_reset_cnt++ ] = sid;
    }
    off += 9UL+len;
  }
  memmove( g_out, g_out+off, g_out_sz-off );
  g_out_sz -= off;
}

/* Client frame boundaries *********************************************/

/* The input is pushed as HTTP/2 frames, so the harness can tell when
   the server has seen a whole number of frames, which is when it can
   add one of its own. */

static uchar g_cli_hdr[ 9 ];
static ulong g_cli_hdr_sz;  /* bytes of the next frame header seen */
static ulong g_cli_rem;     /* payload bytes of the current frame still to come */

static void
cli_track( uchar const * p,
           ulong         sz ) {
  while( sz ) {
    if( g_cli_rem ) {
      ulong take = fd_ulong_min( sz, g_cli_rem );
      g_cli_rem -= take; p += take; sz -= take;
      continue;
    }
    g_cli_hdr[ g_cli_hdr_sz++ ] = *p++; sz--;
    if( g_cli_hdr_sz==9UL ) {
      g_cli_rem    = ( (ulong)g_cli_hdr[0]<<16 ) | ( (ulong)g_cli_hdr[1]<<8 ) | (ulong)g_cli_hdr[2];
      g_cli_hdr_sz = 0UL;
    }
  }
}

static int
cli_at_boundary( void ) {
  return !g_cli_hdr_sz && !g_cli_rem;
}

/* late_probe sends, on a stream the server reset, one frame a client
   may still send there, and checks the connection survives it. */

static void
late_probe( fd_grpc_server_conn_t * conn,
            fd_rng_t *              rng,
            long                    now ) {
  if( ( g_oracle_off & ORACLE_LATE ) || !g_reset_cnt ) return;
  if( !cli_at_boundary() ) return;
  if( !fd_grpc_server_conn_is_open( conn ) ) return;
  if( conn->flags & ( FD_GRPC_SERVER_CONN_FLAG_HTTP1|FD_GRPC_SERVER_CONN_FLAG_CLOSING|FD_GRPC_SERVER_CONN_FLAG_GOAWAY ) ) return;
  if( conn->h2->flags & ( FD_H2_CONN_FLAGS_DEAD|FD_H2_CONN_FLAGS_SEND_GOAWAY|FD_H2_CONN_FLAGS_HANDSHAKING ) ) return;
  if( fd_h2_rbuf_used_sz( conn->rbuf_rx ) ) return; /* only this frame will be read */
  if( fd_h2_rbuf_free_sz( conn->rbuf_tx )<256UL ) return; /* room to answer it */

  uint sid = g_reset[ --g_reset_cnt ];
  uchar f[ 9+8 ];
  ulong sz;
  uint  kind = fd_rng_uint( rng )&3U;
  if( kind==0U ) {        /* request trailers */
    static uchar const block[] = { 0x00, 0x01, 'x', 0x01, 'y' }; /* literal without indexing */
    f[0]=0; f[1]=0; f[2]=sizeof(block); f[3]=FD_H2_FRAME_TYPE_HEADERS; f[4]=0x05; /* END_STREAM|END_HEADERS */
    fd_memcpy( f+9, block, sizeof(block) ); sz = 9UL+sizeof(block);
  } else if( kind==1U ) { /* the end of the request body */
    f[0]=0; f[1]=0; f[2]=0; f[3]=FD_H2_FRAME_TYPE_DATA; f[4]=0x01; sz = 9UL;
  } else if( kind==2U ) { /* a window update */
    f[0]=0; f[1]=0; f[2]=4; f[3]=FD_H2_FRAME_TYPE_WINDOW_UPDATE; f[4]=0;
    f[9]=0; f[10]=0; f[11]=0; f[12]=1; sz = 13UL;
  } else {                /* a reset of its own */
    f[0]=0; f[1]=0; f[2]=4; f[3]=FD_H2_FRAME_TYPE_RST_STREAM; f[4]=0;
    f[9]=0; f[10]=0; f[11]=0; f[12]=0x08; sz = 13UL; /* CANCEL */
  }
  f[5]=(uchar)( (sid>>24)&0x7f ); f[6]=(uchar)(sid>>16); f[7]=(uchar)(sid>>8); f[8]=(uchar)sid;

  ulong n = fd_grpc_server_conn_push_rx( conn, f, sz, now );
  if( n!=sz ) return;
  CHECK( ORACLE_LATE, !( conn->h2->flags & ( FD_H2_CONN_FLAGS_DEAD|FD_H2_CONN_FLAGS_SEND_GOAWAY ) ),
         "a %s frame on stream %u, which the server reset, ended the connection",
         kind==0U ? "HEADERS" : kind==1U ? "DATA" : kind==2U ? "WINDOW_UPDATE" : "RST_STREAM", sid );
}

/* Ring and treap invariants ******************************************/

static void
check_ring( fd_grpc_server_t const * server ) {
  ulong ring       = server->tx_ring_sz;
  ulong stream_cnt = server->params.max_conn_cnt * server->params.max_stream_cnt;
  if( g_stats && server->stage_off>=ring ) {
    g_input_lapped = 1;
    for( ulong i=0UL; i<stream_cnt; i++ ) {
      fd_grpc_server_stream_t const * s = server->stream+i;
      if( s->ref_cnt && s->refs[ s->ref_idx ].off < server->stage_off-ring/2UL ) g_input_lag = 1;
    }
  }
  if( g_oracle_off & ORACLE_RING ) return;

  ulong ref_max = server->params.stream_tx_ref_max;
  ulong live_lo = server->stage_off>=ring ? server->stage_off-ring : 0UL;
  CHECK( ORACLE_RING, !server->stage_len, "a message is still being staged between calls" );

  ulong pending = 0UL;
  for( ulong i=0UL; i<stream_cnt; i++ ) {
    fd_grpc_server_stream_t const * s = server->stream+i;
    CHECK( ORACLE_RING, s->ref_cnt<=ref_max, "stream %lu: %lu references, at most %lu", i, s->ref_cnt, ref_max );
    if( !s->ref_cnt ) continue;
    pending++;
    CHECK( ORACLE_RING, !( s->flags & FD_GRPC_SERVER_STREAM_FLAG_TOO_SLOW ),
           "stream %lu: closed for being too slow but still holds references", i );
    CHECK( ORACLE_RING, s->state==FD_GRPC_SERVER_STREAM_ACTIVE || s->state==FD_GRPC_SERVER_STREAM_FINISH,
           "stream %lu: references in state %u", i, s->state );
    ulong prev_end = 0UL;
    for( ulong k=0UL; k<s->ref_cnt; k++ ) {
      fd_grpc_server_tx_ref_t const * r = s->refs + ( s->ref_idx+k )%ref_max;
      CHECK( ORACLE_RING, r->off>=live_lo,
             "stream %lu: reference at %lu was overwritten (ring holds %lu..%lu)", i, r->off, live_lo, server->stage_off );
      CHECK( ORACLE_RING, r->off+r->len<=server->stage_off, "stream %lu: reference past the staged bytes", i );
      CHECK( ORACLE_RING, r->len>=5UL, "stream %lu: reference shorter than a message header", i );
      CHECK( ORACLE_RING, ( r->off%ring )+r->len<=ring, "stream %lu: reference wraps the ring", i );
      CHECK( ORACLE_RING, r->off>=prev_end, "stream %lu: references out of order", i );
      prev_end = r->off+r->len;
    }
    CHECK( ORACLE_RING, s->ref_written<s->refs[ s->ref_idx ].len, "stream %lu: oldest reference already sent", i );
  }

  CHECK( ORACLE_RING, !stream_treap_verify( server->stream_treap, server->stream ), "treap corrupt" );
  ulong seen = 0UL;
  ulong key  = 0UL;
  for( stream_treap_fwd_iter_t it = stream_treap_fwd_iter_init( server->stream_treap, server->stream );
       !stream_treap_fwd_iter_done( it );
       it = stream_treap_fwd_iter_next( it, server->stream ) ) {
    fd_grpc_server_stream_t const * s = stream_treap_fwd_iter_ele_const( it, server->stream );
    CHECK( ORACLE_RING, s->ref_cnt, "treap holds a stream with no references" );
    ulong k = s->refs[ s->ref_idx ].off;
    CHECK( ORACLE_RING, k>=key, "treap out of order" );
    key = k;
    seen++;
  }
  CHECK( ORACLE_RING, seen==pending, "treap holds %lu streams, %lu have references", seen, pending );
}

static void
stats_print( void ) {
  fprintf( stderr, "stats: inputs=%lu lapped=%lu lapped_with_lag=%lu rx_full=%lu\n",
           g_stat_input, g_stat_lapped, g_stat_lapped_lag, g_stat_rx_full );
}

/* close_nanos of the connection when it was first seen closing */
static long g_close_first;

static void
check_conn( fd_grpc_server_conn_t const * conn ) {
  if( !conn->active ) return;
  if( conn->flags & FD_GRPC_SERVER_CONN_FLAG_CLOSING ) {
    if( !g_close_first ) g_close_first = conn->close_nanos;
    CHECK( ORACLE_GOAWAY, conn->close_nanos<=g_close_first,
           "close deadline moved later (%ld after %ld)", conn->close_nanos, g_close_first );
  }
}

static void
check_all( fd_grpc_server_conn_t const * conn ) {
  check_ring( g_server );
  check_conn( conn );
}

/* Callbacks **********************************************************/

static int
cb_conn_open( void *                  ctx,
              fd_grpc_server_conn_t * conn ) {
  (void)ctx; (void)conn;
  g_conn_cnt++;
  return 0;
}

static void
cb_conn_close( void *                  ctx,
               fd_grpc_server_conn_t * conn ) {
  (void)ctx; (void)conn;
  g_conn_cnt--;
  assert( g_conn_cnt>=0L );
}

static void
cb_stream_hdr( void *                    ctx,
               fd_grpc_server_stream_t * stream,
               char const *              name,
               ulong                     name_len,
               char const *              value,
               ulong                     value_len ) {
  (void)ctx; (void)stream;
  assert( name_len );
  /* Touch the bytes so that a use-after-free or bad length shows up */
  ulong sum = 0UL;
  for( ulong i=0UL; i<name_len;  i++ ) sum += (ulong)(uchar)name [i];
  for( ulong i=0UL; i<value_len; i++ ) sum += (ulong)(uchar)value[i];
  FD_COMPILER_UNPREDICTABLE( sum );
}

static int
cb_stream_open( void *                    ctx,
                fd_grpc_server_stream_t * stream,
                char const *              path,
                ulong                     path_len ) {
  (void)ctx;
  fd_grpc_server_conn_t const * conn = stream->conn;
  CHECK( ORACLE_GOAWAY, !( conn->flags & FD_GRPC_SERVER_CONN_FLAG_CLOSING ), "call opened on a closing connection" );
  CHECK( ORACLE_GOAWAY, !( conn->h2->flags & ( FD_H2_CONN_FLAGS_DEAD|FD_H2_CONN_FLAGS_SEND_GOAWAY ) ),
         "call opened on a connection that is going away" );
  if( path_len==sizeof(FUZZ_ROUTE_UNARY)-1UL && fd_memeq( path, FUZZ_ROUTE_UNARY, path_len ) ) {
    g_stream_cnt++;
    return FD_GRPC_SERVER_ACCEPT_UNARY;
  }
  if( path_len==sizeof(FUZZ_ROUTE_STREAM)-1UL && fd_memeq( path, FUZZ_ROUTE_STREAM, path_len ) ) {
    g_stream_cnt++;
    return FD_GRPC_SERVER_ACCEPT_STREAM;
  }
  return FD_GRPC_SERVER_REJECT;
}

static void
app_send( fd_grpc_server_stream_t * stream,
          uchar const *             msg,
          ulong                     msg_sz ) {
  int err = fd_grpc_server_send( stream, msg, msg_sz, 0U );
  assert( err==FD_GRPC_SERVER_SUCCESS || err==FD_GRPC_SERVER_ERR_CLOSED ||
          err==FD_GRPC_SERVER_ERR_TOOBIG );
  if( err==FD_GRPC_SERVER_SUCCESS ) orc_record( stream, msg, msg_sz );
}

static void
cb_stream_msg( void *                    ctx,
               fd_grpc_server_stream_t * stream,
               uchar const *             msg,
               ulong                     msg_sz ) {
  (void)ctx;
  static uchar big[ 1500 ];
  for( ulong i=0UL; i<sizeof(big); i++ ) big[i] = (uchar)( i&0x07 );

  if( msg_sz && msg[0]=='L' ) {
    /* A message far larger than one frame, staged whole in the ring */
    static uchar huge[ 9000 ];
    for( ulong i=0UL; i<sizeof(huge); i++ ) huge[i] = (uchar)( i*3UL );
    ulong sz = 1025UL + ( (ulong)msg[ msg_sz>1UL ] * 17UL ) % 3500UL; /* past max_msg_sz sometimes */
    app_send( stream, huge, sz );
    return;
  }

  if( msg_sz && msg[0]=='B' ) {
    /* Large, compressible response: exercises the compressor */
    app_send( stream, big, sizeof(big) );
    return;
  }

  if( msg_sz && msg[0]=='R' ) {
    /* A burst of small replies of fuzzer chosen sizes, so that message
       boundaries land everywhere in the ring as it wraps */
    ulong cnt = 1UL + ( msg_sz>1UL ? (ulong)msg[1]%16UL : 0UL );
    for( ulong i=0UL; i<cnt; i++ ) {
      ulong sz = 1UL + ( ( msg_sz>2UL ? (ulong)msg[2] : 7UL ) * ( i+1UL ) * 13UL ) % 200UL;
      app_send( stream, big, fd_ulong_min( sz, sizeof(big) ) );
    }
    return;
  }

  app_send( stream, msg, msg_sz );
  if( msg_sz && msg[0]=='F' ) fd_grpc_server_finish( stream, FD_GRPC_STATUS_OK, "done", 4UL );
}

static void
cb_stream_half_close( void *                    ctx,
                      fd_grpc_server_stream_t * stream ) {
  (void)ctx;
  fd_grpc_server_finish( stream, FD_GRPC_STATUS_OK, NULL, 0UL );
}

static void
cb_stream_close( void *                    ctx,
                 fd_grpc_server_stream_t * stream,
                 int                       reason ) {
  (void)ctx; (void)stream;
  assert( reason>=FD_GRPC_SERVER_CLOSE_FINISHED && reason<=FD_GRPC_SERVER_CLOSE_TOO_SLOW );
  g_stream_cnt--;
  assert( g_stream_cnt>=0L );
}

static fd_grpc_server_callbacks_t const fuzz_callbacks = {
  .conn_open         = cb_conn_open,
  .conn_close        = cb_conn_close,
  .stream_hdr        = cb_stream_hdr,
  .stream_open       = cb_stream_open,
  .stream_msg        = cb_stream_msg,
  .stream_half_close = cb_stream_half_close,
  .stream_close      = cb_stream_close
};

/* Driver *************************************************************/

/* drain takes up to max bytes of output, which the output oracle
   parses. */

static void
drain( fd_grpc_server_conn_t * conn,
       ulong                   max ) {
  static uchar buf[ 4096 ];
  while( max ) {
    ulong n = fd_grpc_server_conn_pop_tx( conn, buf, fd_ulong_min( max, sizeof(buf) ) );
    if( !n ) break;
    orc_parse( buf, n );
    max -= n;
  }
}

/* step services the server after input was pushed, with a peer that
   reads its output at a pace the input picks. */

static void
step( fd_grpc_server_conn_t * conn,
      fd_rng_t *              rng,
      long *                  now ) {
  uint r = fd_rng_uint( rng );
  if( r&3U ) drain( conn, ULONG_MAX );    /* a peer that keeps up */
  else       drain( conn, (r>>2)&4095U ); /* or one that falls behind */
  check_all( conn );

  *now += (long)( fd_rng_uint( rng ) & 0xffffff );
  fd_grpc_server_service( g_server, *now );
  check_all( conn );
  if( r&3U ) drain( conn, ULONG_MAX );
  check_all( conn );
}

/* cooperate plays a peer that reads everything and sends nothing more,
   for a few rounds. */

static void
cooperate( fd_grpc_server_conn_t * conn,
           long *                  now ) {
  for( ulong i=0UL; i<8UL && fd_grpc_server_conn_is_open( conn ); i++ ) {
    drain( conn, ULONG_MAX );
    fd_grpc_server_conn_push_rx( conn, NULL, 0UL, *now ); /* retries buffered input */
    drain( conn, ULONG_MAX );
    *now += 100L*1000L*1000L;
    fd_grpc_server_service( g_server, *now );
    check_all( conn );
  }
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  (void)atexit( fd_halt );
  fd_log_level_core_set(1); /* crash on info log */

  char const * off = getenv( "FUZZ_ORACLE_OFF" );
  g_oracle_off = off ? strtoul( off, NULL, 0 ) : 0UL;
  g_trace      = !!getenv( "FUZZ_TRACE" );
  g_stats      = !!getenv( "FUZZ_STATS" );
  if( g_stats ) (void)atexit( stats_print );

  fd_grpc_server_params_t * params = g_params;
  fd_grpc_server_params_default( params );
  params->max_conn_cnt       = 1UL;
  params->max_stream_cnt     = 3UL;
  params->max_request_msg_sz = 2048UL;
  /* A ring that holds only a few messages, and a short message queue,
     so that both ways of falling behind are reachable, and the smallest
     buffers allowed, so that an input can wrap the ring and fill them */
  params->max_msg_sz         = 4096UL;
  params->tx_ring_sz         = 3UL*( 4096UL+5UL );
  params->stream_tx_ref_max  = 8UL;
  params->conn_rx_buf_sz     = 16384UL+9UL;
  params->conn_tx_buf_sz     = 16384UL+9UL+128UL;
  if( getenv( "FUZZ_LEGACY_SIZES" ) ) {
    /* The sizes this target used to run with, for comparison */
    params->max_msg_sz     = 32768UL;
    params->tx_ring_sz     = 3UL*( 32768UL+5UL );
    params->conn_rx_buf_sz = 20480UL;
    params->conn_tx_buf_sz = 20480UL;
  }
  params->max_frame_sz       = 16384UL;
  params->conn_rx_wnd_sz     = 1UL<<20;
  params->stream_rx_wnd_sz   = 1UL<<18;
  params->compression        = FD_GRPC_SERVER_COMPRESSION_ZSTD;
  params->compression_min_sz = 128UL;
  params->compression_level  = 1;
  params->seed               = 1UL;
  params->web                = 1;
  params->web_index          = "<html></html>";
  params->web_index_sz       = 13UL;

  assert( fd_grpc_server_footprint( params )<=sizeof(g_server_mem) );
  g_server = fd_grpc_server_join( fd_grpc_server_new( g_server_mem, params, &fuzz_callbacks, NULL ) );
  assert( g_server );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( size<4UL ) return -1;
  uint seed = FD_LOAD( uint, data );
  data += 4UL; size -= 4UL;

  fd_rng_t * rng = fd_rng_join( fd_rng_new( g_rng, seed, 0UL ) );
  long now = 1000L*1000L*1000L;
  int  web = !!( seed&2u );
  orc_reset( !web );
  g_close_first   = 0L;
  g_input_lapped  = 0;
  g_input_lag     = 0;
  g_input_rx_full = 0;
  g_cli_hdr_sz    = 0UL;
  g_cli_rem       = 0UL;

  fd_grpc_server_conn_t * conn = fd_grpc_server_conn_open_direct( g_server, now );
  assert( conn );
  assert( g_conn_cnt==1L );

  if( web ) {
    /* An HTTP/1.1 request head, so the remaining input reaches the
       gRPC-Web parser as more header lines and the body */
    static uchar const req[] =
      "POST " FUZZ_ROUTE_UNARY " HTTP/1.1\r\ncontent-type: application/grpc-web\r\n";
    assert( fd_grpc_server_conn_push_rx( conn, req, sizeof(req)-1UL, now )==sizeof(req)-1UL );
  } else {
    /* The connection preface and a client SETTINGS frame, so that the
       fuzzer spends its bytes on requests instead of rediscovering the
       handshake */
    static uchar const hello[] =
      "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
      "\x00\x00\x00\x04\x00\x00\x00\x00\x00"  /* SETTINGS */
      "\x00\x00\x00\x04\x01\x00\x00\x00\x00"; /* SETTINGS ACK */
    assert( fd_grpc_server_conn_push_rx( conn, hello, sizeof(hello)-1UL, now )==sizeof(hello)-1UL );

    if( seed&8u ) {
      /* A small initial stream window, so that responses stall on flow
         control and their bytes stay referenced while the ring wraps */
      uint  wnd = 1U + ( ( seed>>8 ) & 2047U );
      uchar settings[ 15 ] = { 0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x04, (uchar)( wnd>>24 ), (uchar)( wnd>>16 ), (uchar)( wnd>>8 ), (uchar)wnd };
      assert( fd_grpc_server_conn_push_rx( conn, settings, sizeof(settings), now )==sizeof(settings) );
    }

    if( seed&1u ) {
      /* Open a unary call that declares zstd request messages, so the
         remaining input reaches the decompressor as DATA frames.  The
         field block spells out every header as an HPACK literal without
         indexing. */
      static uchar const request[] =
        "\x00\x00\x8e\x01\x04\x00\x00\x00\x01"       /* HEADERS, END_HEADERS, stream 1 */
        "\x00\x07" ":method" "\x04" "POST"
        "\x00\x07" ":scheme" "\x04" "http"
        "\x00\x05" ":path"   "\x0f" FUZZ_ROUTE_UNARY
        "\x00\x0c" "content-type" "\x10" "application/grpc"
        "\x00\x02" "te" "\x08" "trailers"
        "\x00\x0d" "grpc-encoding" "\x04" "zstd"
        "\x00\x14" "grpc-accept-encoding" "\x04" "zstd";
      assert( sizeof(request)-1UL==0x8eUL+9UL );
      assert( fd_grpc_server_conn_push_rx( conn, request, sizeof(request)-1UL, now )==sizeof(request)-1UL );
    }
  }
  check_all( conn );

  /* A shutdown part way through the input, after which the server is
     replaced for the next input */
  ulong shutdown_at = ( seed&4u ) ? size/2UL : ULONG_MAX;

  while( size && fd_grpc_server_conn_is_open( conn ) ) {
    if( FD_UNLIKELY( size<=shutdown_at && shutdown_at!=ULONG_MAX ) ) {
      fd_grpc_server_shutdown( g_server );
      shutdown_at = ULONG_MAX;
      check_all( conn );
      if( !fd_grpc_server_conn_is_open( conn ) ) break;
    }
    ulong chunk = fd_ulong_min( size, ( (ulong)fd_rng_uint( rng ) & 255UL )+1UL );
    ulong n     = fd_grpc_server_conn_push_rx( conn, data, chunk, now );
    if( !web ) cli_track( data, n );
    data += n; size -= n;
    check_all( conn );

    step( conn, rng, &now );
    if( !web ) { late_probe( conn, rng, now ); check_all( conn ); }

    if( !n ) g_input_rx_full = 1;
    if( !n ) {
      /* The connection took no input.  A peer that reads everything
         must get it reading again, or see it closed. */
      cooperate( conn, &now );
      if( fd_grpc_server_conn_is_open( conn ) ) {
        n = fd_grpc_server_conn_push_rx( conn, data, fd_ulong_min( size, 1UL ), now );
        if( !web ) cli_track( data, n );
        data += n; size -= n;
        check_all( conn );
        int is_web = !!( conn->flags & FD_GRPC_SERVER_CONN_FLAG_HTTP1 );
        CHECK( is_web ? ORACLE_WEB_RX : ORACLE_H2_RX, n || !size,
               "%s connection stopped reading with its output drained (rx %lu/%lu bytes)",
               is_web ? "HTTP/1.1" : "HTTP/2",
               fd_h2_rbuf_used_sz( conn->rbuf_rx ), conn->rbuf_rx->bufsz );
      }
      if( !n ) break;
    }
  }

  cooperate( conn, &now );

  if( fd_grpc_server_conn_is_open( conn ) ) fd_grpc_server_conn_close( conn );
  check_ring( g_server );
  if( FD_UNLIKELY( seed&4u ) ) {
    fd_grpc_server_delete( fd_grpc_server_leave( g_server ) );
    g_server = fd_grpc_server_join( fd_grpc_server_new( g_server_mem, g_params, &fuzz_callbacks, NULL ) );
    assert( g_server );
  }
  assert( g_conn_cnt    ==0L );
  assert( g_stream_cnt  ==0L );
  assert( fd_grpc_server_is_idle( g_server ) );

  g_stat_input++;
  g_stat_lapped     += (ulong)g_input_lapped;
  g_stat_lapped_lag += (ulong)g_input_lag;
  g_stat_rx_full    += (ulong)g_input_rx_full;

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}
