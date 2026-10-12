/* bench_grpc_load is a light gRPC streaming load generator: one thread,
   epoll, N non-blocking TCP connections speaking raw h2c.  Every
   connection sends the preface, SETTINGS with a large initial window, a
   connection WINDOW_UPDATE, one HEADERS frame with literal HPACK fields
   and one DATA frame carrying the request message, then reads frames
   and discards payloads while counting DATA bytes and gRPC messages,
   answering PING and SETTINGS, and replenishing flow control windows.
   Per-connection state is a few hundred bytes and the read scratch is
   shared, so the client stays light at tens of thousands of
   connections.

     bench_grpc_load --host 127.0.0.1 --port 10000 --conns 1000 --ramp 500 \
                     --sub slots --commitment processed --seconds 30

   --sub is one of slots, status, transactions, accounts, blocks_meta, or
   file:<path> holding a serialized SubscribeRequest.  --path overrides
   the gRPC method, --x-token adds the header. */

#define _GNU_SOURCE
#include "../h2/fd_h2_proto.h"
#include "../h2/fd_hpack_wr.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define ST_CONNECTING (1)
#define ST_OPEN       (2)
#define ST_CLOSED     (3)

#define WND_MAX  (0x7fffffffU)
#define WND_INIT (65535U)
#define TX_MAX   (4096UL)

struct conn {
  int   fd;
  uchar state;
  uchar hdr_sz;
  uchar frame_type;
  uchar frame_flags;
    uchar pfx_sz;
  uchar ack_due;       /* a SETTINGS frame is being read and owes an ACK */
  uchar ping_sz;       /* bytes of the PING payload gathered so far */
  uchar pfx[ 5 ];
  uchar hdr[ 9 ];
  uchar ping[ 8 ];
  uint  frame_rem;
  uint  frame_sid;
  uint  msg_rem;
  uint  conn_consumed;
  uint  stream_consumed;
  uint  tx_off;
  uint  tx_sz;
  uchar * tx;          /* pending bytes to write, TX_MAX */
  ulong msgs;
  ulong data_bytes;
    int   close_reason;  /* 0 open, 1 rst, 2 goaway, 3 trailers, 4 eof, 5 error */
  uint  rst_code;
  long  retry_at;      /* wallclock to reconnect a connection that never connected, 0 if none */
  uint  retries;
};
typedef struct conn conn_t;

static conn_t *      g_conn;
static ulong         g_conn_cnt;
static int           g_ep;
static union { struct sockaddr sa; struct sockaddr_in in; } g_addr;
static union { struct sockaddr sa; struct sockaddr_in in; } g_bind;   /* source address, unset when sin_family is 0 */
static uchar *       g_req;        /* preface..DATA, sent once per connection */
static ulong         g_req_sz;
static ulong         g_open, g_connecting, g_closed;
static ulong         g_close_by[ 6 ];
static ulong         g_retries;
static ulong         g_retry_max;

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
  if( FD_UNLIKELY( name_len>=127UL || value_len>=127UL ) ) FD_LOG_ERR(( "header too long" ));
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

/* Built-in SubscribeRequest encodings (geyser.proto field numbers:
   accounts 1, slots 2, transactions 3, blocks_meta 5, commitment 6,
   transactions_status 10).  Each is one map entry keyed "b" with an
   empty filter, which subscribes to everything of that kind. */

static ulong
build_request( uchar * out, char const * sub, int commitment ) {
  ulong o = 0UL;
  uchar tag;
  if     ( !strcmp( sub, "accounts"     ) ) tag = 0x0a;
  else if( !strcmp( sub, "slots"        ) ) tag = 0x12;
  else if( !strcmp( sub, "transactions" ) ) tag = 0x1a;
  else if( !strcmp( sub, "blocks_meta"  ) ) tag = 0x2a;
  else if( !strcmp( sub, "status"       ) ) tag = 0x52;
  else FD_LOG_ERR(( "unknown --sub %s", sub ));
  out[ o++ ] = tag; out[ o++ ] = 0x03; out[ o++ ] = 0x0a; out[ o++ ] = 0x01; out[ o++ ] = 'b';
    if( !strcmp( sub, "slots" ) ) {
    /* interslot_updates=true: entry value { field 2 varint 1 } */
    out[ 1 ] = 0x07; out[ o++ ] = 0x12; out[ o++ ] = 0x02; out[ o++ ] = 0x10; out[ o++ ] = 0x01;
  }
  if( commitment ) { out[ o++ ] = 0x30; out[ o++ ] = (uchar)commitment; }
  return o;
}

static void
conn_close( conn_t * c, int reason ) {
  if( c->state==ST_CLOSED ) return;
  if( c->state==ST_OPEN ) g_open--; else g_connecting--;
  epoll_ctl( g_ep, EPOLL_CTL_DEL, c->fd, NULL );
  close( c->fd );
  c->fd    = -1;
  c->state = ST_CLOSED;
  c->close_reason = reason;
  g_closed++;
  g_close_by[ reason ]++;
}

static void
conn_want_write( conn_t * c, int on ) {
  struct epoll_event ev = { .events = (uint)( EPOLLIN | ( on ? EPOLLOUT : 0 ) ), .data.ptr = c };
  epoll_ctl( g_ep, EPOLL_CTL_MOD, c->fd, &ev );
}

static int
conn_flush( conn_t * c ) {
  while( c->tx_off<c->tx_sz ) {
    long n = send( c->fd, c->tx+c->tx_off, c->tx_sz-c->tx_off, MSG_NOSIGNAL|MSG_DONTWAIT );
    if( n<0L ) {
      if( errno==EAGAIN || errno==EWOULDBLOCK ) { conn_want_write( c, 1 ); return 0; }
      conn_close( c, 5 ); return -1;
    }
    c->tx_off += (uint)n;
  }
  c->tx_off = c->tx_sz = 0U;
  conn_want_write( c, 0 );
  return 0;
}

static void
conn_queue( conn_t * c, void const * data, ulong sz ) {
  if( FD_UNLIKELY( c->tx_sz+sz>TX_MAX ) ) {
    /* Make room by flushing; if the kernel will not take it, drop the
       control frame (window replenishment is retried next time). */
    conn_flush( c );
    if( c->state==ST_CLOSED || c->tx_sz+sz>TX_MAX ) return;
  }
  memcpy( c->tx+c->tx_sz, data, sz );
  c->tx_sz += (uint)sz;
}

static int
conn_open( conn_t * c ) {
  int fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  if( FD_UNLIKELY( fd<0 ) ) { FD_LOG_WARNING(( "socket failed (%i-%s)", errno, strerror( errno ) )); return -1; }
  int one = 1;
  setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one) );
  if( g_bind.in.sin_family && 0!=bind( fd, &g_bind.sa, sizeof(g_bind.in) ) ) { close( fd ); return -1; }
  int rc = connect( fd, &g_addr.sa, sizeof(g_addr.in) );
  if( rc<0 && errno!=EINPROGRESS ) { close( fd ); return -1; }
  c->fd    = fd;
  c->state = ST_CONNECTING;
  struct epoll_event ev = { .events = EPOLLIN|EPOLLOUT, .data.ptr = c };
  epoll_ctl( g_ep, EPOLL_CTL_ADD, fd, &ev );
  g_connecting++;
  return 0;
}

/* A connect that failed is retried after a short backoff, up to
   --retries times, so a SYN the server's backlog dropped does not
   remove the client from the test. */

static void
conn_retry_later( conn_t * c,
                  long     now ) {
  if( c->retries>=g_retry_max ) return;
  c->retries++;
  c->retry_at = now + 500L*1000L*1000L*(long)c->retries;
  g_retries++;
}

static void
conn_connected( conn_t * c ) {
  int err = 0; socklen_t len = sizeof(err);
  getsockopt( c->fd, SOL_SOCKET, SO_ERROR, &err, &len );
  if( err ) { conn_close( c, 5 ); conn_retry_later( c, fd_log_wallclock() ); return; }
  c->state = ST_OPEN;
  g_connecting--; g_open++;
  memcpy( c->tx, g_req, g_req_sz );
  c->tx_sz = (uint)g_req_sz;
  conn_flush( c );
}

/* conn_rx parses frames from a read chunk.  Payloads are consumed in
   place; only the 9 byte frame header and the 5 byte gRPC prefix may
   straddle reads. */

static void
conn_rx( conn_t * c, uchar const * p, ulong sz ) {
  ulong off = 0UL;
  while( off<sz && c->state==ST_OPEN ) {
    if( c->frame_rem ) {
      ulong take = fd_ulong_min( c->frame_rem, sz-off );
      switch( c->frame_type ) {
      case FD_H2_FRAME_TYPE_DATA: {
        c->data_bytes      += take;
        c->conn_consumed   += (uint)take;
        c->stream_consumed += (uint)take;
        /* Count gRPC messages: 5 byte prefix then msg_rem bytes */
        ulong q = 0UL;
        while( q<take ) {
          if( c->msg_rem ) {
            ulong m = fd_ulong_min( c->msg_rem, take-q );
            c->msg_rem -= (uint)m; q += m;
            if( !c->msg_rem ) c->msgs++;
            continue;
          }
          ulong m = fd_ulong_min( 5UL-c->pfx_sz, take-q );
          memcpy( c->pfx+c->pfx_sz, p+off+q, m );
          c->pfx_sz += (uchar)m; q += m;
          if( c->pfx_sz==5U ) {
            uint be; memcpy( &be, c->pfx+1, 4UL );
            c->msg_rem = fd_uint_bswap( be );
            c->pfx_sz  = 0U;
            if( !c->msg_rem ) c->msgs++;
          }
        }
        break;
      }
            case FD_H2_FRAME_TYPE_SETTINGS:
        break; /* acknowledged when the frame is complete, below */
      case FD_H2_FRAME_TYPE_PING: {
        /* The 8 byte payload may straddle reads */
        ulong room = 8UL-c->ping_sz;
        ulong m    = fd_ulong_min( room, take );
        memcpy( c->ping+c->ping_sz, p+off, m );
        c->ping_sz += (uchar)m;
        break;
      }
      case FD_H2_FRAME_TYPE_RST_STREAM:
        if( take>=4UL ) { uint be; memcpy( &be, p+off, 4UL ); c->rst_code = fd_uint_bswap( be ); }
        break;
      default: break;
      }
            c->frame_rem -= (uint)take;
      off          += take;
      if( !c->frame_rem ) {
        if( c->frame_type==FD_H2_FRAME_TYPE_SETTINGS && c->ack_due ) {
          c->ack_due = 0;
          uchar ack[ 9 ]; put_frame( ack, FD_H2_FRAME_TYPE_SETTINGS, FD_H2_FLAG_ACK, 0U, NULL, 0UL );
          conn_queue( c, ack, 9UL );
        }
        if( c->frame_type==FD_H2_FRAME_TYPE_PING && c->ping_sz==8U && !( c->frame_flags & FD_H2_FLAG_ACK ) ) {
          uchar pong[ 17 ]; put_frame( pong, FD_H2_FRAME_TYPE_PING, FD_H2_FLAG_ACK, 0U, c->ping, 8UL );
          conn_queue( c, pong, 17UL );
        }
        c->ping_sz = 0U;
        if( c->frame_type==FD_H2_FRAME_TYPE_RST_STREAM ) { conn_close( c, 1 ); return; }
        if( c->frame_type==FD_H2_FRAME_TYPE_GOAWAY     ) { conn_close( c, 2 ); return; }
        if( c->frame_type==FD_H2_FRAME_TYPE_HEADERS && ( c->frame_flags & FD_H2_FLAG_END_STREAM ) ) { conn_close( c, 3 ); return; }
        if( c->frame_type==FD_H2_FRAME_TYPE_DATA    && ( c->frame_flags & FD_H2_FLAG_END_STREAM ) ) { conn_close( c, 3 ); return; }
      }
      continue;
    }
    ulong take = fd_ulong_min( 9UL-c->hdr_sz, sz-off );
    memcpy( c->hdr+c->hdr_sz, p+off, take );
    c->hdr_sz += (uchar)take;
    off       += take;
    if( c->hdr_sz<9U ) continue;
    fd_h2_frame_hdr_t hdr; memcpy( &hdr, c->hdr, 9UL );
    c->hdr_sz      = 0U;
    c->frame_rem   = (uint)fd_h2_frame_length( hdr.typlen );
    c->frame_type  = (uchar)fd_h2_frame_type( hdr.typlen );
        c->frame_flags = hdr.flags;
    c->frame_sid   = fd_h2_frame_stream_id( hdr.r_stream_id );
    c->ack_due     = (uchar)( c->frame_type==FD_H2_FRAME_TYPE_SETTINGS && !( c->frame_flags & FD_H2_FLAG_ACK ) && c->frame_rem );
    c->ping_sz     = 0U;
    if( !c->frame_rem ) {
      /* Empty frames: SETTINGS ACK, empty DATA/HEADERS with END_STREAM */
      if( c->frame_type==FD_H2_FRAME_TYPE_SETTINGS && !( c->frame_flags & FD_H2_FLAG_ACK ) ) {
        uchar ack[ 9 ]; put_frame( ack, FD_H2_FRAME_TYPE_SETTINGS, FD_H2_FLAG_ACK, 0U, NULL, 0UL );
        conn_queue( c, ack, 9UL );
      }
      if( ( c->frame_type==FD_H2_FRAME_TYPE_DATA || c->frame_type==FD_H2_FRAME_TYPE_HEADERS ) &&
          ( c->frame_flags & FD_H2_FLAG_END_STREAM ) ) { conn_close( c, 3 ); return; }
    }
  }
  if( c->state!=ST_OPEN ) return;
  if( c->conn_consumed >= (WND_MAX>>2) || c->stream_consumed >= (WND_MAX>>2) ) {
    uchar wu[ 26 ]; ulong n = 0UL;
    n += put_window_update( wu+n, 0U, c->conn_consumed   );
    n += put_window_update( wu+n, 1U, c->stream_consumed );
    c->conn_consumed = c->stream_consumed = 0U;
    conn_queue( c, wu, n );
  }
  if( c->tx_sz ) conn_flush( c );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * host       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--host",       NULL, "127.0.0.1" );
  char const * bind_addr  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--bind",       NULL, NULL        );
  ulong        port       = fd_env_strip_cmdline_ulong( &argc, &argv, "--port",       NULL, 10000UL );
  ulong        conn_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--conns",      NULL, 16UL );
  ulong        ramp       = fd_env_strip_cmdline_ulong( &argc, &argv, "--ramp",       NULL, 200UL );
  char const * sub        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--sub",        NULL, "slots" );
  char const * commit     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--commitment", NULL, "processed" );
  char const * path       = fd_env_strip_cmdline_cstr ( &argc, &argv, "--path",       NULL, "/geyser.Geyser/Subscribe" );
  char const * x_token    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--x-token",    NULL, NULL );
  ulong        seconds    = fd_env_strip_cmdline_ulong( &argc, &argv, "--seconds",    NULL, 10UL );
    ulong        report_s   = fd_env_strip_cmdline_ulong( &argc, &argv, "--report",     NULL, 1UL );
  g_retry_max             = fd_env_strip_cmdline_ulong( &argc, &argv, "--retries",    NULL, 5UL );
  int          spin        = fd_env_strip_cmdline_contains( &argc, &argv, "--spin" ); /* busy-poll instead of sleeping in epoll_wait */

  int commitment = !strcmp( commit, "finalized" ) ? 2 : !strcmp( commit, "confirmed" ) ? 1 : 0;

  /* Resolve */
  struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
  struct addrinfo * res = NULL;
  if( FD_UNLIKELY( getaddrinfo( host, NULL, &hints, &res ) || !res ) ) FD_LOG_ERR(( "cannot resolve %s", host ));
  memcpy( &g_addr.in, res->ai_addr, sizeof(g_addr.in) );
  g_addr.in.sin_port = fd_ushort_bswap( (ushort)port );
  if( bind_addr ) {
    g_bind.in.sin_family = AF_INET;
    if( FD_UNLIKELY( 1!=inet_pton( AF_INET, bind_addr, &g_bind.in.sin_addr ) ) ) FD_LOG_ERR(( "bad --bind %s", bind_addr ));
  }
  freeaddrinfo( res );

  /* Request message */
  static uchar msg[ 1UL<<20 ];
  ulong msg_sz;
  if( !strncmp( sub, "file:", 5UL ) ) {
    FILE * f = fopen( sub+5, "rb" );
    if( FD_UNLIKELY( !f ) ) FD_LOG_ERR(( "cannot open %s", sub+5 ));
    msg_sz = fread( msg, 1UL, sizeof(msg), f );
    fclose( f );
  } else {
    msg_sz = build_request( msg, sub, commitment );
  }

  /* Connection preamble, identical for every connection */
  g_req = malloc( 2048UL+msg_sz );
  ulong o = 0UL;
  memcpy( g_req, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24UL ); o = 24UL;
  fd_h2_setting_t settings[2] = {
    { .id = fd_ushort_bswap( FD_H2_SETTINGS_INITIAL_WINDOW_SIZE ), .value = fd_uint_bswap( WND_MAX ) },
    { .id = fd_ushort_bswap( FD_H2_SETTINGS_MAX_FRAME_SIZE      ), .value = fd_uint_bswap( 1U<<20 ) },
  };
  o += put_frame( g_req+o, FD_H2_FRAME_TYPE_SETTINGS, 0U, 0U, settings, sizeof(settings) );
  o += put_window_update( g_req+o, 0U, WND_MAX-WND_INIT );
  uchar block[ 512 ]; ulong b = 0UL;
  block[ b++ ] = FD_HPACK_INDEXED_SHORT( 3 ); /* :method: POST */
  block[ b++ ] = FD_HPACK_INDEXED_SHORT( 6 ); /* :scheme: http */
  b += put_hdr_lit( block+b, ":path",        path );
  b += put_hdr_lit( block+b, ":authority",   host );
  b += put_hdr_lit( block+b, "content-type", "application/grpc" );
  b += put_hdr_lit( block+b, "te",           "trailers" );
  b += put_hdr_lit( block+b, "user-agent",   "bench_grpc_load/1" );
  if( x_token ) b += put_hdr_lit( block+b, "x-token", x_token );
  o += put_frame( g_req+o, FD_H2_FRAME_TYPE_HEADERS, FD_H2_FLAG_END_HEADERS, 1U, block, b );
  uchar * grpc = malloc( 5UL+msg_sz );
  grpc[0] = 0; uint be = fd_uint_bswap( (uint)msg_sz ); memcpy( grpc+1, &be, 4UL ); memcpy( grpc+5, msg, msg_sz );
  o += put_frame( g_req+o, FD_H2_FRAME_TYPE_DATA, 0U, 1U, grpc, 5UL+msg_sz );
  g_req_sz = o;
  if( FD_UNLIKELY( g_req_sz>TX_MAX ) ) FD_LOG_ERR(( "request too large for the per-connection send buffer (%lu > %lu)", g_req_sz, TX_MAX ));

  /* File descriptor budget */
  struct rlimit rl;
  if( !getrlimit( RLIMIT_NOFILE, &rl ) && rl.rlim_cur < conn_cnt+64UL ) {
    rl.rlim_cur = fd_ulong_min( conn_cnt+64UL, rl.rlim_max );
    setrlimit( RLIMIT_NOFILE, &rl );
    if( rl.rlim_cur < conn_cnt+64UL ) FD_LOG_WARNING(( "RLIMIT_NOFILE %lu is below %lu connections", (ulong)rl.rlim_cur, conn_cnt ));
  }

  g_conn     = calloc( conn_cnt, sizeof(conn_t) );
  g_conn_cnt = conn_cnt;
  uchar * txmem = malloc( conn_cnt*TX_MAX );
  for( ulong i=0UL; i<conn_cnt; i++ ) { g_conn[i].fd = -1; g_conn[i].tx = txmem+i*TX_MAX; }
  g_ep = epoll_create1( EPOLL_CLOEXEC );
  if( FD_UNLIKELY( g_ep<0 ) ) FD_LOG_ERR(( "epoll_create1 failed" ));

  static uchar   scratch[ 1UL<<20 ];
  static struct epoll_event evs[ 4096 ];

  FD_LOG_NOTICE(( "bench_grpc_load: %s:%lu, %lu conns at %lu/s, sub %s @%s, %lu s", host, port, conn_cnt, ramp, sub, commit, seconds ));

  long t0       = fd_log_wallclock();
  long deadline = t0 + (long)seconds*1000L*1000L*1000L;
  long next_rep = t0 + (long)report_s*1000L*1000L*1000L;
  ulong opened  = 0UL;
  ulong last_msgs = 0UL, last_bytes = 0UL;
  double ramp_per_ns = (double)ramp/1e9;
  for(;;) {
    long now = fd_log_wallclock();
    if( now>=deadline ) break;
    /* Ramp connections */
        ulong want = fd_ulong_min( conn_cnt, (ulong)( (double)( now-t0 )*ramp_per_ns )+1UL );
    while( opened<want ) {
      if( conn_open( g_conn+opened )<0 ) break;
      opened++;
    }
    /* Retries due, a few per pass so they ramp too */
    for( ulong i=0UL, n=0UL; i<opened && n<64UL; i++ ) {
      conn_t * c = g_conn+i;
      if( c->state!=ST_CLOSED || !c->retry_at || c->retry_at>now ) continue;
      c->retry_at = 0L;
      memset( c, 0, offsetof(conn_t, retry_at) ); c->fd = -1;
      c->tx = txmem+i*TX_MAX;
      g_closed--; g_close_by[5]--;
      if( conn_open( c )<0 ) { conn_retry_later( c, now ); continue; }
      n++;
    }
    int n = epoll_wait( g_ep, evs, 4096, spin ? 0 : 10 );
    for( int i=0; i<n; i++ ) {
      conn_t * c = evs[i].data.ptr;
      if( c->state==ST_CLOSED ) continue;
            if( c->state==ST_CONNECTING ) {
        if( evs[i].events & (EPOLLERR|EPOLLHUP) ) { conn_close( c, 5 ); conn_retry_later( c, now ); continue; }
        if( evs[i].events & EPOLLOUT ) conn_connected( c );
        continue;
      }
      if( evs[i].events & EPOLLOUT ) conn_flush( c );
      if( c->state!=ST_OPEN ) continue;
      if( evs[i].events & EPOLLIN ) {
        for(;;) {
          long r = recv( c->fd, scratch, sizeof(scratch), MSG_DONTWAIT );
          if( r>0L ) { conn_rx( c, scratch, (ulong)r ); if( c->state!=ST_OPEN ) break; if( (ulong)r<sizeof(scratch) ) break; continue; }
          if( r==0L ) { conn_close( c, 4 ); break; }
          if( errno==EAGAIN || errno==EWOULDBLOCK ) break;
          conn_close( c, 5 ); break;
        }
        continue;
      }
      if( evs[i].events & (EPOLLERR|EPOLLHUP) ) conn_close( c, 5 );
    }
    if( now>=next_rep ) {
      ulong msgs = 0UL, bytes = 0UL;
      for( ulong i=0UL; i<conn_cnt; i++ ) { msgs += g_conn[i].msgs; bytes += g_conn[i].data_bytes; }
      double dt = (double)report_s;
            FD_LOG_NOTICE(( "t=%4lds open=%lu connecting=%lu closed=%lu (rst %lu goaway %lu trailers %lu eof %lu err %lu) retries=%lu "
                      "%.0f msg/s %.2f MB/s total %lu msgs",
                      ( now-t0 )/1000000000L, g_open, g_connecting, g_closed,
                      g_close_by[1], g_close_by[2], g_close_by[3], g_close_by[4], g_close_by[5], g_retries,
                      (double)( msgs-last_msgs )/dt, (double)( bytes-last_bytes )/dt/1e6, msgs ));
      last_msgs = msgs; last_bytes = bytes;
      next_rep += (long)report_s*1000L*1000L*1000L;
    }
  }

  ulong msgs = 0UL, bytes = 0UL, zero = 0UL;
  for( ulong i=0UL; i<conn_cnt; i++ ) { msgs += g_conn[i].msgs; bytes += g_conn[i].data_bytes; zero += (ulong)!g_conn[i].msgs; }
  double secs = (double)( fd_log_wallclock()-t0 )/1e9;
  printf( "{\"host\":\"%s\",\"port\":%lu,\"conns\":%lu,\"sub\":\"%s\",\"commitment\":\"%s\",\"seconds\":%.1f,"
          "\"open\":%lu,\"closed\":%lu,\"closed_rst\":%lu,\"closed_goaway\":%lu,\"closed_trailers\":%lu,\"closed_eof\":%lu,\"closed_err\":%lu,"
                    "\"conns_without_msgs\":%lu,\"retries\":%lu,\"msgs\":%lu,\"msgs_per_s\":%.0f,\"bytes\":%lu,\"bytes_per_s\":%.0f}\n",
          host, port, conn_cnt, sub, commit, secs, g_open, g_closed,
          g_close_by[1], g_close_by[2], g_close_by[3], g_close_by[4], g_close_by[5],
          zero, g_retries, msgs, (double)msgs/secs, bytes, (double)bytes/secs );
  for( ulong i=0UL; i<conn_cnt; i++ ) if( g_conn[i].fd>=0 ) close( g_conn[i].fd );
  fd_halt();
  return 0;
}
