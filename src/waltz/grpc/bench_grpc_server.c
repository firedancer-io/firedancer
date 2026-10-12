/* bench_grpc_server measures how many response messages one
   fd_grpc_server can emit per second with no kernel involved.  It opens
   N connections over the direct (in-memory) transport, subscribes one
   streaming call on each, stages one message per iteration to every
   stream with fd_grpc_server_send_multi, and drains every connection
   into a sink that parses frame headers only.

     bench_grpc_server --conns 1024 --msg-sz 512 --compression zstd --seconds 5

   Output is one line per run: messages staged per second, messages and
   bytes delivered per second, frames, and the server metrics.

   With --listen PORT the server instead serves real sockets on
   0.0.0.0:PORT (every address of the host, so a load generator can
   spread its connections over several destination addresses), accepts
   any gRPC path as a streaming call, and publishes --rate messages per
   second of --msg-sz bytes to every open stream for --seconds, printing
   connections, streams and throughput once a second.  This is the
   synthetic publisher the load generator is pointed at. */

#include <sys/socket.h>
#include <netinet/in.h>

#include "fd_grpc_server_private.h"
#include "../h2/fd_hpack_wr.h"
#include "../../util/fd_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROUTE "/bench.Svc/Stream"

/* Per-connection sink state: a partial frame header, the current
   frame, and the per-connection and per-stream consumed byte counts
   that drive WINDOW_UPDATE replenishment. */

struct sink {
  fd_grpc_server_conn_t *   conn;
  fd_grpc_server_stream_t * stream;
  uchar hdr[ 9 ];
  uint  hdr_sz;
  uint  frame_rem;
  uchar frame_type;
  uint  frame_sid;
  ulong conn_consumed;
  ulong stream_consumed;
  ulong data_bytes;
  ulong frame_cnt;
  int   rst;
  int   goaway;
};
typedef struct sink sink_t;

static sink_t * g_sink;
static ulong    g_conn_cnt;
static long     g_now = 1000L*1000L*1000L;

/* Socket mode: every open stream, so a publish touches each once. */
static int                         g_sock_mode;
static fd_grpc_server_stream_t **  g_live;
static ulong                       g_live_cnt;
static ulong                       g_live_max;

/* App callbacks: accept the bench route as a stream and remember the
   stream object on its connection's sink. */

static int
app_conn_open( void * ctx, fd_grpc_server_conn_t * conn ) {
  (void)ctx; (void)conn;
  return 0;
}

static void
app_conn_close( void * ctx, fd_grpc_server_conn_t * conn ) {
  (void)ctx; (void)conn;
}

static void
app_stream_hdr( void * ctx, fd_grpc_server_stream_t * stream,
                char const * name, ulong name_len, char const * value, ulong value_len ) {
  (void)ctx; (void)stream; (void)name; (void)name_len; (void)value; (void)value_len;
}

static int
app_stream_open( void * ctx, fd_grpc_server_stream_t * stream, char const * path, ulong path_len ) {
  (void)ctx;
  if( g_sock_mode ) {
    (void)path; (void)path_len;
    if( FD_UNLIKELY( g_live_cnt>=g_live_max ) ) return FD_GRPC_SERVER_REJECT;
    g_live[ g_live_cnt ] = stream;
    fd_grpc_server_stream_set_ctx( stream, (void *)( g_live_cnt+1UL ) );
    g_live_cnt++;
    return FD_GRPC_SERVER_ACCEPT_STREAM;
  }
  if( path_len!=sizeof(ROUTE)-1UL || memcmp( path, ROUTE, path_len ) ) return FD_GRPC_SERVER_REJECT;
  fd_grpc_server_conn_t * conn = fd_grpc_server_stream_conn( stream );
  sink_t * s = fd_grpc_server_conn_ctx( conn );
  s->stream = stream;
  return FD_GRPC_SERVER_ACCEPT_STREAM;
}

static void
app_stream_msg( void * ctx, fd_grpc_server_stream_t * stream, uchar const * msg, ulong msg_sz ) {
  (void)ctx; (void)stream; (void)msg; (void)msg_sz;
}

static void
app_stream_half_close( void * ctx, fd_grpc_server_stream_t * stream ) {
  (void)ctx; (void)stream;
}

static void
app_stream_close( void * ctx, fd_grpc_server_stream_t * stream, int reason ) {
  (void)ctx; (void)reason;
  if( g_sock_mode ) {
    ulong idx = (ulong)fd_grpc_server_stream_ctx( stream );
    if( !idx ) return;
    idx--;
    g_live_cnt--;
    g_live[ idx ] = g_live[ g_live_cnt ];
    fd_grpc_server_stream_set_ctx( g_live[ idx ], (void *)( idx+1UL ) );
    return;
  }
  fd_grpc_server_conn_t * conn = fd_grpc_server_stream_conn( stream );
  sink_t * s = fd_grpc_server_conn_ctx( conn );
  if( s && s->stream==stream ) s->stream = NULL;
}

static fd_grpc_server_callbacks_t const app_callbacks = {
  .conn_open         = app_conn_open,
  .conn_close        = app_conn_close,
  .stream_hdr        = app_stream_hdr,
  .stream_open       = app_stream_open,
  .stream_msg        = app_stream_msg,
  .stream_half_close = app_stream_half_close,
  .stream_close      = app_stream_close,
};

/* Client-side frame writers */

static ulong
put_frame( uchar * out, uint type, uint flags, uint stream_id, void const * payload, ulong payload_sz ) {
  fd_h2_frame_hdr_t hdr = {
    .typlen      = fd_h2_frame_typlen( type, payload_sz ),
    .flags       = (uchar)flags,
    .r_stream_id = fd_uint_bswap( stream_id )
  };
  memcpy( out, &hdr, 9UL );
  if( payload_sz ) memcpy( out+9UL, payload, payload_sz );
  return 9UL+payload_sz;
}

static ulong
put_hdr_lit( uchar * p, char const * name, char const * value ) {
  ulong name_len = strlen( name ), value_len = strlen( value );
  ulong o = 0UL;
  p[ o++ ] = 0x00;
  p[ o++ ] = (uchar)name_len;  memcpy( p+o, name,  name_len  ); o += name_len;
  p[ o++ ] = (uchar)value_len; memcpy( p+o, value, value_len ); o += value_len;
  return o;
}

static ulong
put_window_update( uchar * out, uint stream_id, uint increment ) {
  uint be = fd_uint_bswap( increment );
  return put_frame( out, FD_H2_FRAME_TYPE_WINDOW_UPDATE, 0U, stream_id, &be, 4UL );
}

#define WND_MAX  (0x7fffffffU)
#define WND_INIT (65535U)

static void
push_all( sink_t * s, uchar const * buf, ulong sz ) {
  ulong off = 0UL;
  while( off<sz ) {
    ulong n = fd_grpc_server_conn_push_rx( s->conn, buf+off, sz-off, g_now );
    if( !n ) FD_LOG_ERR(( "conn %lu: server receive ring full during setup", (ulong)( s-g_sink ) ));
    off += n;
  }
}

/* sink_drain pops everything the connection has to send and parses
   frame headers to count DATA bytes, replenishing windows when half of
   the initial grant was consumed. */

static ulong
sink_drain( sink_t * s, uchar * scratch, ulong scratch_sz ) {
  ulong total = 0UL;
  for(;;) {
    ulong n = fd_grpc_server_conn_pop_tx( s->conn, scratch, scratch_sz );
    if( !n ) break;
    total += n;
    ulong off = 0UL;
    while( off<n ) {
      if( s->frame_rem ) {
        ulong take = fd_ulong_min( s->frame_rem, n-off );
        if( s->frame_type==FD_H2_FRAME_TYPE_DATA ) {
          s->data_bytes      += take;
          s->conn_consumed   += take;
          s->stream_consumed += take;
        }
        s->frame_rem -= (uint)take;
        off          += take;
        continue;
      }
      ulong take = fd_ulong_min( 9UL-s->hdr_sz, n-off );
      memcpy( s->hdr+s->hdr_sz, scratch+off, take );
      s->hdr_sz += (uint)take;
      off       += take;
      if( s->hdr_sz<9U ) continue;
      fd_h2_frame_hdr_t hdr; memcpy( &hdr, s->hdr, 9UL );
      s->hdr_sz     = 0U;
      s->frame_rem  = (uint)fd_h2_frame_length( hdr.typlen );
      s->frame_type = (uchar)fd_h2_frame_type( hdr.typlen );
      s->frame_sid  = fd_h2_frame_stream_id( hdr.r_stream_id );
      s->frame_cnt++;
      if( s->frame_type==FD_H2_FRAME_TYPE_RST_STREAM ) s->rst    = 1;
      if( s->frame_type==FD_H2_FRAME_TYPE_GOAWAY     ) s->goaway = 1;
    }
  }
  if( s->conn_consumed >= (WND_MAX>>1) || s->stream_consumed >= (WND_MAX>>1) ) {
    uchar wu[ 26 ];
    ulong sz = 0UL;
    sz += put_window_update( wu+sz, 0U, (uint)s->conn_consumed   );
    sz += put_window_update( wu+sz, 1U, (uint)s->stream_consumed );
    s->conn_consumed   = 0UL;
    s->stream_consumed = 0UL;
    push_all( s, wu, sz );
  }
  return total;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong        conn_cnt    = fd_env_strip_cmdline_ulong( &argc, &argv, "--conns",       NULL, 64UL  );
  ulong        msg_sz      = fd_env_strip_cmdline_ulong( &argc, &argv, "--msg-sz",      NULL, 512UL );
  char const * compression = fd_env_strip_cmdline_cstr ( &argc, &argv, "--compression", NULL, "none" );
  ulong        seconds     = fd_env_strip_cmdline_ulong( &argc, &argv, "--seconds",     NULL, 5UL   );
  ulong        ring_mb     = fd_env_strip_cmdline_ulong( &argc, &argv, "--ring-mb",     NULL, 64UL  );
  ulong        ref_max     = fd_env_strip_cmdline_ulong( &argc, &argv, "--refs",        NULL, 1024UL );
  ulong        batch       = fd_env_strip_cmdline_ulong( &argc, &argv, "--batch",       NULL, 16UL  );
  ulong        listen_port = fd_env_strip_cmdline_ulong( &argc, &argv, "--listen",      NULL, 0UL   );
  ulong        rate        = fd_env_strip_cmdline_ulong( &argc, &argv, "--rate",        NULL, 14UL  );
  ulong        tx_buf_kb   = fd_env_strip_cmdline_ulong( &argc, &argv, "--tx-buf-kb",   NULL, 256UL );
    ulong        rx_buf_kb   = fd_env_strip_cmdline_ulong( &argc, &argv, "--rx-buf-kb",   NULL, 32UL  );
  ulong        send_ms     = fd_env_strip_cmdline_ulong( &argc, &argv, "--send-interval-ms", NULL, 0UL );

  if( FD_UNLIKELY( conn_cnt<1UL || conn_cnt>=(1UL<<24) ) ) FD_LOG_ERR(( "--conns must be in [1,2^24)" ));
  g_sock_mode = listen_port!=0UL;

  fd_grpc_server_params_t params[1];
  fd_grpc_server_params_default( params );
  params->max_conn_cnt       = conn_cnt;
  params->max_stream_cnt     = 1UL;
  params->max_request_msg_sz = 4096UL;
  params->max_msg_sz         = fd_ulong_max( msg_sz, 64UL );
  params->tx_ring_sz         = fd_ulong_max( ring_mb<<20, 3UL*( params->max_msg_sz+sizeof(fd_grpc_hdr_t) ) );
  params->stream_tx_ref_max  = ref_max;
  params->conn_rx_buf_sz     = fd_ulong_max( rx_buf_kb<<10, 16384UL+9UL );
  params->conn_tx_buf_sz     = fd_ulong_max( tx_buf_kb<<10, 32768UL );
  params->conn_rx_wnd_sz     = 1UL<<20;
  params->stream_rx_wnd_sz   = 1UL<<20;
  params->compression        = strcmp( compression, "zstd" ) ? FD_GRPC_SERVER_COMPRESSION_NONE : FD_GRPC_SERVER_COMPRESSION_ZSTD;
  params->compression_min_sz = 64UL;
  params->compression_level  = 1;
  params->seed               = 42UL;
  params->idle_timeout_nanos = 0L;
    params->epoll_fd           = -1;
  params->send_interval_nanos = (long)send_ms*1000L*1000L;

  ulong footprint = fd_grpc_server_footprint( params );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "invalid server params" ));
  void * mem = aligned_alloc( fd_grpc_server_align(), fd_ulong_align_up( footprint, fd_grpc_server_align() ) );
  if( FD_UNLIKELY( !mem ) ) FD_LOG_ERR(( "out of memory (%lu MiB)", footprint>>20 ));
  fd_grpc_server_t * server = fd_grpc_server_join( fd_grpc_server_new( mem, params, &app_callbacks, NULL ) );
  if( FD_UNLIKELY( !server ) ) FD_LOG_ERR(( "fd_grpc_server_new failed" ));
  FD_LOG_NOTICE(( "server footprint %lu MiB for %lu connections (%lu KiB each)",
                  footprint>>20, conn_cnt, ( footprint/conn_cnt )>>10 ));

  g_sink     = calloc( conn_cnt, sizeof(sink_t) );
  g_conn_cnt = conn_cnt;
  static uchar scratch[ 1UL<<20 ];

  if( g_sock_mode ) {
    g_live_max = conn_cnt;
    g_live     = malloc( conn_cnt*sizeof(fd_grpc_server_stream_t *) );
    int *   errs = malloc( conn_cnt*sizeof(int) );
    uchar * msg  = malloc( msg_sz );
    for( ulong i=0UL; i<msg_sz; i++ ) msg[i] = (uchar)( ( i*7919UL ) >> 3 );
    if( FD_UNLIKELY( fd_grpc_server_listen( server, 0U, (ushort)listen_port )<0 ) ) FD_LOG_ERR(( "listen on :%lu failed", listen_port ));
    FD_LOG_NOTICE(( "serving on 0.0.0.0:%lu: up to %lu conns, %lu B messages at %lu/s, %s, %lu s",
                    listen_port, conn_cnt, msg_sz, rate, compression, seconds ));
    long  t0       = fd_log_wallclock();
    long  deadline = t0 + (long)seconds*1000L*1000L*1000L;
    long  period   = rate ? 1000L*1000L*1000L/(long)rate : LONG_MAX;
    long  next_pub = t0 + period;
    long  next_rep = t0 + 1000L*1000L*1000L;
    ulong staged = 0UL, last_staged = 0UL, pubs = 0UL;
    ulong last_wire = 0UL;
    for(;;) {
      long now = fd_log_wallclock();
      if( now>=deadline ) break;
      int timeout = (int)fd_long_max( 0L, fd_long_min( next_pub, next_rep )-now )/1000000;
      fd_grpc_server_poll( server, timeout, fd_log_wallclock() );
      now = fd_log_wallclock();
      if( now>=next_pub ) {
        next_pub += period;
        if( g_live_cnt ) {
          msg[0] = (uchar)pubs;
          staged += fd_grpc_server_send_multi( g_live, g_live_cnt, msg, msg_sz, 0U, errs );
        }
        pubs++;
        fd_grpc_server_service( server, now );
      }
      if( now>=next_rep ) {
        fd_grpc_server_metrics_t const * m = fd_grpc_server_metrics( server );
        FD_LOG_NOTICE(( "t=%4lds conns=%lu streams=%lu staged %lu msg/s wire %.1f MB/s refused=%lu too_slow=%lu/%lu closed=%lu",
                        ( now-t0 )/1000000000L, m->conn_open_cnt-m->conn_close_cnt, g_live_cnt,
                        staged-last_staged, (double)( m->tx_byte_cnt_wire-last_wire )/1e6,
                        m->accept_refused_cnt, m->tx_too_slow_ring_cnt, m->tx_too_slow_refs_cnt, m->conn_close_cnt ));
        last_staged = staged; last_wire = m->tx_byte_cnt_wire;
        next_rep += 1000L*1000L*1000L;
      }
    }
    fd_grpc_server_metrics_t const * m = fd_grpc_server_metrics( server );
    printf( "{\"mode\":\"listen\",\"port\":%lu,\"conns_open\":%lu,\"streams\":%lu,\"conns_opened\":%lu,\"conns_closed\":%lu,"
            "\"refused\":%lu,\"msgs_staged\":%lu,\"wire_bytes\":%lu,\"too_slow_ring\":%lu,\"too_slow_refs\":%lu,\"footprint_bytes\":%lu}\n",
            listen_port, m->conn_open_cnt-m->conn_close_cnt, g_live_cnt, m->conn_open_cnt, m->conn_close_cnt,
            m->accept_refused_cnt, staged, m->tx_byte_cnt_wire, m->tx_too_slow_ring_cnt, m->tx_too_slow_refs_cnt, footprint );
    fd_grpc_server_delete( fd_grpc_server_leave( server ) );
    fd_halt();
    return 0;
  }

  /* Handshake and subscribe on every connection */
  uchar req[ 2048 ];
  for( ulong i=0UL; i<conn_cnt; i++ ) {
    sink_t * s = g_sink+i;
    s->conn = fd_grpc_server_conn_open_direct( server, g_now );
    if( FD_UNLIKELY( !s->conn ) ) FD_LOG_ERR(( "conn %lu: open failed", i ));
    fd_grpc_server_conn_set_ctx( s->conn, s );

    ulong sz = 0UL;
    memcpy( req, fd_h2_client_preface, 24UL ); sz = 24UL;
    fd_h2_setting_t settings[2] = {
      { .id = FD_H2_SETTINGS_INITIAL_WINDOW_SIZE, .value = fd_uint_bswap( WND_MAX ) },
      { .id = FD_H2_SETTINGS_MAX_FRAME_SIZE,      .value = fd_uint_bswap( 1U<<20 ) },
    };
    settings[0].id = fd_ushort_bswap( settings[0].id );
    settings[1].id = fd_ushort_bswap( settings[1].id );
    sz += put_frame( req+sz, FD_H2_FRAME_TYPE_SETTINGS, 0U, 0U, settings, sizeof(settings) );
    sz += put_window_update( req+sz, 0U, WND_MAX-WND_INIT );
    push_all( s, req, sz );
    sink_drain( s, scratch, sizeof(scratch) );

    sz = put_frame( req, FD_H2_FRAME_TYPE_SETTINGS, FD_H2_FLAG_ACK, 0U, NULL, 0UL );
    uchar block[ 256 ];
    ulong o = 0UL;
    block[ o++ ] = FD_HPACK_INDEXED_SHORT( 3 ); /* :method: POST */
    block[ o++ ] = FD_HPACK_INDEXED_SHORT( 6 ); /* :scheme: http */
    o += put_hdr_lit( block+o, ":path",        ROUTE );
    o += put_hdr_lit( block+o, ":authority",   "bench" );
    o += put_hdr_lit( block+o, "content-type", "application/grpc" );
    o += put_hdr_lit( block+o, "te",           "trailers" );
    if( params->compression==FD_GRPC_SERVER_COMPRESSION_ZSTD ) o += put_hdr_lit( block+o, "grpc-accept-encoding", "zstd" );
    sz += put_frame( req+sz, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, 1U, block, o );
    uchar grpc_msg[ 5 ] = {0};
    sz += put_frame( req+sz, FD_H2_FRAME_TYPE_DATA, 0U, 1U, grpc_msg, 5UL );
    push_all( s, req, sz );
    fd_grpc_server_service( server, g_now );
    sink_drain( s, scratch, sizeof(scratch) );
    if( FD_UNLIKELY( !s->stream ) ) FD_LOG_ERR(( "conn %lu: subscribe was not accepted", i ));
  }

  fd_grpc_server_stream_t ** streams = malloc( conn_cnt*sizeof(fd_grpc_server_stream_t *) );
  int *                      errs    = malloc( conn_cnt*sizeof(int) );
  uchar * msg = malloc( msg_sz );
  for( ulong i=0UL; i<msg_sz; i++ ) msg[i] = (uchar)( ( i*7919UL ) >> 3 ); /* mildly compressible */

  FD_LOG_NOTICE(( "bench: %lu conns, %lu B messages, %s, %lu s", conn_cnt, msg_sz, compression, seconds ));

  long  t0        = fd_log_wallclock();
  long  deadline  = t0 + (long)seconds*1000L*1000L*1000L;
  ulong staged    = 0UL;
  ulong iters     = 0UL;
  ulong sink_bytes = 0UL;
  ulong send_err  = 0UL;
  for(;;) {
    long now = fd_log_wallclock();
    if( now>=deadline ) break;
    g_now = now;
    for( ulong b=0UL; b<batch; b++ ) {
      ulong n = 0UL;
      for( ulong i=0UL; i<conn_cnt; i++ ) if( g_sink[i].stream ) streams[ n++ ] = g_sink[i].stream;
      if( !n ) FD_LOG_ERR(( "all streams gone" ));
      msg[0] = (uchar)iters; /* a changing byte so the compressor sees distinct messages */
      ulong sent = fd_grpc_server_send_multi( streams, n, msg, msg_sz, 0U, errs );
      staged += sent;
      if( sent<n ) send_err += n-sent;
      iters++;
    }
    fd_grpc_server_service( server, g_now );
    for( ulong i=0UL; i<conn_cnt; i++ ) sink_bytes += sink_drain( g_sink+i, scratch, sizeof(scratch) );
  }
  /* Final drain */
  fd_grpc_server_service( server, g_now );
  for( ulong i=0UL; i<conn_cnt; i++ ) sink_bytes += sink_drain( g_sink+i, scratch, sizeof(scratch) );
  double secs = (double)( fd_log_wallclock()-t0 )/1e9;

  ulong data_bytes = 0UL, frames = 0UL, rst = 0UL, goaway = 0UL, live = 0UL;
  for( ulong i=0UL; i<conn_cnt; i++ ) {
    data_bytes += g_sink[i].data_bytes;
    frames     += g_sink[i].frame_cnt;
    rst        += (ulong)g_sink[i].rst;
    goaway     += (ulong)g_sink[i].goaway;
    live       += (ulong)!!g_sink[i].stream;
  }
  fd_grpc_server_metrics_t const * m = fd_grpc_server_metrics( server );
  double msgs_per_s = (double)staged/secs;
  double bytes_per_s = (double)sink_bytes/secs;
  FD_LOG_NOTICE(( "result: %.0f msgs/s staged (%.0f per stream), %.1f MB/s on the wire, %.1f MB/s payload, "
                  "%.0f frames/s, %.1f B/msg on wire, %lu send errors, %lu rst, %lu goaway, %lu/%lu streams live, "
                  "%lu msgs compressed of %lu, %.0f ns/msg",
                  msgs_per_s, msgs_per_s/(double)conn_cnt, bytes_per_s/1e6, (double)data_bytes/secs/1e6,
                  (double)frames/secs, staged ? (double)sink_bytes/(double)staged : 0.0,
                  send_err, rst, goaway, live, conn_cnt, m->tx_msg_compressed_cnt, m->tx_msg_cnt,
                  staged ? secs*1e9/(double)staged : 0.0 ));
  printf( "{\"conns\":%lu,\"msg_sz\":%lu,\"compression\":\"%s\",\"seconds\":%.3f,\"msgs_staged\":%lu,"
          "\"msgs_per_s\":%.0f,\"wire_bytes_per_s\":%.0f,\"payload_bytes_per_s\":%.0f,\"frames_per_s\":%.0f,"
          "\"send_err\":%lu,\"rst\":%lu,\"goaway\":%lu,\"streams_live\":%lu,\"footprint_bytes\":%lu}\n",
          conn_cnt, msg_sz, compression, secs, staged, msgs_per_s, bytes_per_s, (double)data_bytes/secs,
          (double)frames/secs, send_err, rst, goaway, live, footprint );

  fd_grpc_server_delete( fd_grpc_server_leave( server ) );
  free( mem ); free( g_sink ); free( streams ); free( errs ); free( msg );
  fd_halt();
  return 0;
}
