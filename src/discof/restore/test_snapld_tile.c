#define _GNU_SOURCE
#include "../../disco/stem/fd_stem.h"
#include "utils/fd_sshttp_private.h"
#include "utils/fd_ssctrl.h"
#include "../../util/io/fd_io.h"

#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <errno.h>
#include "../../ballet/base58/fd_base58.h"

static ulong publish_cnt;
static ulong publish_sig;
static ulong init_cnt;
static ulong rearm_cnt;
static ulong init_slot; /* slot the forwarded INIT must carry */
static uchar output[ 4UL*FD_SNAPSHOT_DATA_MTU ] __attribute__((aligned(FD_CHUNK_ALIGN)));

static fd_stem_context_t test_stem[1]; /* no sleep object: the tile nanosleeps when idle */

static ulong
test_stem_publish( fd_stem_context_t * stem FD_PARAM_UNUSED,
                   ulong               out_idx FD_PARAM_UNUSED,
                   ulong               sig,
                   ulong               chunk,
                   ulong               sz,
                   ulong               ctl     FD_PARAM_UNUSED,
                   ulong               tsorig  FD_PARAM_UNUSED,
                   ulong               tspub   FD_PARAM_UNUSED ) {
  publish_cnt++;
  publish_sig = sig;
  if( sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL || sig==FD_SNAPSHOT_MSG_CTRL_INIT_INCR ) {
    FD_TEST( sz==sizeof(fd_ssctrl_init_t) );
    fd_ssctrl_init_t const * init = fd_chunk_to_laddr_const( output, chunk );
    FD_TEST( init->slot==init_slot );
  }
  return 0UL;
}

static int
test_sshttp_init( fd_sshttp_t * http,
                  fd_ip4_port_t addr,
                  char const *  hostname,
                  int           is_https,
                  char const *  path,
                  ulong         path_len,
                  ulong         hops,
                  long          now,
                  ulong         range_start,
                  int           is_stream ) {
  init_cnt++;
  return fd_sshttp_init( http, addr, hostname, is_https, path, path_len, hops, now, range_start, is_stream );
}

static void
test_waker_client_rearm( ulong idx ) {
  FD_TEST( idx==7UL );
  rearm_cnt++;
}

#define fd_stem_publish       test_stem_publish
#define fd_sshttp_init        test_sshttp_init
#define fd_waker_client_rearm test_waker_client_rearm
#include "fd_snapld_tile.c"

static int test_epoll_fd = -1;
#undef fd_waker_client_rearm
#undef fd_sshttp_init
#undef fd_stem_publish

static void
test_start( int file,
            int bad_target ) {
  static fd_sshttp_t http[1];
  static uchar      input[ sizeof(fd_ssctrl_start_t) ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  static ulong waker_fseq[ FD_FSEQ_FOOTPRINT/sizeof(ulong) ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  fd_snapld_tile_t ctx[1] = {0};
  ctx->sshttp        = fd_sshttp_join( fd_sshttp_new( http, test_epoll_fd ) );
  ctx->waker_fseq    = fd_fseq_join( fd_fseq_new( waker_fseq, 0UL ) );
  fd_clock_tile_init( ctx->clock );
  ctx->in_rd.base    = input;
  ctx->out_dc.mem    = (fd_wksp_t *)output;
  ctx->out_dc.mtu    = FD_SNAPSHOT_DATA_MTU;
  ctx->out_dc.wmark  = 2UL*FD_SNAPSHOT_DATA_MTU/FD_CHUNK_SZ;
  ctx->local_full_fd = -1;

  int           server = -1;
  fd_ip4_port_t addr   = {0};
  if( file ) {
    ctx->local_full_fd = memfd_create( "snapshot-test", 0 );
    FD_TEST( ctx->local_full_fd>=0 );
    ulong wsz;
    FD_TEST( !fd_io_write( ctx->local_full_fd, "snapshot", 8UL, 8UL, &wsz ) );
    FD_TEST( wsz==8UL );
  } else if( !bad_target ) {
    server = socket( AF_INET, SOCK_STREAM, 0 );
    FD_TEST( server>=0 );
    struct sockaddr_in sa = {
      .sin_family = AF_INET,
      .sin_addr   = { .s_addr = htonl( INADDR_LOOPBACK ) }
    };
    FD_TEST( !bind( server, fd_type_pun( &sa ), sizeof(sa) ) );
    socklen_t sa_sz = sizeof(sa);
    FD_TEST( !getsockname( server, fd_type_pun( &sa ), &sa_sz ) );
    FD_TEST( !listen( server, 1 ) );
    addr.addr = sa.sin_addr.s_addr;
    addr.port = sa.sin_port;
  }
  fd_ssctrl_init_t * init = (fd_ssctrl_init_t *)input;
  fd_memset( init, 0, sizeof(*init) );
  init->file    = file;
  init->slot    = 123UL;
  init->file_sz = file ? 8UL : 0UL;
  init_slot   = init->slot;
  publish_cnt = init_cnt = 0UL;
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_FULL, 0UL, sizeof(*init), 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( publish_cnt==1UL && publish_sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL );
  FD_TEST( !init_cnt && !ctx->pipeline_ready && http->state==FD_SSHTTP_STATE_INIT && http->sockfd==-1 );
  /* Spend some time waiting for START.  The request deadline must not
     start until then. */
  fd_log_sleep( 2000000L );
  int busy = 0;
  for( int i=0; i<3; i++ ) after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( publish_cnt==1UL && !init_cnt && !ctx->sent_meta );
  fd_ssctrl_start_t * start = (fd_ssctrl_start_t *)input;
  fd_memset( start, 0, sizeof(*start) );
  start->addr = addr;
  fd_cstr_ncpy( start->hostname, "localhost", sizeof(start->hostname) );
  fd_cstr_ncpy( start->path, "/snapshot.tar.bz2", sizeof(start->path) );
  start->path_len = strlen( start->path );
  if( bad_target ) {
    /* A path that cannot fit in an HTTP request fails
       deterministically. */
    fd_memset( start->path, 'x', sizeof(start->path) );
    start->path_len = sizeof(start->path);
  }
  long before = fd_clock_tile_now( ctx->clock );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_START, 0UL, file ? 0UL : sizeof(*start), 0UL, 0UL, 0UL, NULL ) );
  if( bad_target ) {
    FD_TEST( init_cnt==1UL && !ctx->pipeline_ready && ctx->state==FD_SNAPSHOT_STATE_ERROR );
    FD_TEST( publish_cnt==2UL && publish_sig==FD_SNAPSHOT_MSG_CTRL_ERROR );
    after_credit( ctx, test_stem, NULL, &busy );
    FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_START, 0UL, sizeof(*start), 0UL, 0UL, 0UL, NULL ) );
    FD_TEST( publish_cnt==2UL && init_cnt==1UL );
  } else {
    FD_TEST( ctx->pipeline_ready && publish_cnt==1UL );
    FD_TEST( init_cnt==(file ? 0UL : 1UL) );
    if( !file ) {
      FD_TEST( http->deadline>=before+FD_SSHTTP_DEADLINE_NANOS );
      fd_memset( input, 0xa5, sizeof(input) );
      FD_TEST( !strcmp( http->hostname, "localhost" ) );
      FD_TEST( strstr( http->request, "GET /snapshot.tar.bz2 HTTP/1.1" ) );
    } else {
      after_credit( ctx, test_stem, NULL, &busy );
      FD_TEST( publish_cnt>1UL && ctx->sent_meta );
    }
  }
  fd_sshttp_cancel( http );
  if( server>=0 ) FD_TEST( !close( server ) );
  if( file      ) FD_TEST( !close( ctx->local_full_fd ) );
}

/* wait_queued waits until sz bytes are queued unread on fd */

static void
wait_queued( int   fd,
             ulong sz ) {
  for( ulong i=0UL;; i++ ) {
    int queued = 0;
    FD_TEST( !ioctl( fd, SIOCINQ, &queued ) );
    if( (ulong)queued==sz ) return;
    FD_TEST( i<5000UL );
    fd_log_sleep( (long)1e6 );
  }
}

/* Once a read finds the download socket empty, after_credit leaves
   queued bytes alone until the waker fires, then reads and rearms
   exactly once.  A download that is never woken again is still
   cancelled when its progress window runs out. */

static void
test_parked( void ) {
  static fd_sshttp_t http[1];
  static uchar      input[ sizeof(fd_ssctrl_start_t) ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  static ulong waker_fseq[ FD_FSEQ_FOOTPRINT/sizeof(ulong) ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  fd_snapld_tile_t ctx[1] = {0};
  ctx->sshttp              = fd_sshttp_join( fd_sshttp_new( http, test_epoll_fd ) );
  ctx->waker_fseq          = fd_fseq_join( fd_fseq_new( waker_fseq, 0UL ) );
  ctx->waker_client_idx    = 7UL;
  fd_clock_tile_init( ctx->clock );
  ctx->in_rd.base          = input;
  ctx->out_dc.mem          = (fd_wksp_t *)output;
  ctx->out_dc.mtu          = FD_SNAPSHOT_DATA_MTU;
  ctx->out_dc.wmark        = 2UL*FD_SNAPSHOT_DATA_MTU/FD_CHUNK_SZ;
  ctx->local_full_fd       = -1;
  ctx->min_bytes_in_window = 1UL<<20;

  int listener = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( listener>=0 );
  struct sockaddr_in sa = {
    .sin_family = AF_INET,
    .sin_addr   = { .s_addr = htonl( INADDR_LOOPBACK ) }
  };
  FD_TEST( !bind( listener, fd_type_pun( &sa ), sizeof(sa) ) );
  socklen_t sa_sz = sizeof(sa);
  FD_TEST( !getsockname( listener, fd_type_pun( &sa ), &sa_sz ) );
  FD_TEST( !listen( listener, 1 ) );

  fd_ssctrl_init_t * init = (fd_ssctrl_init_t *)input;
  fd_memset( init, 0, sizeof(*init) );
  init->slot = 123UL;
  publish_cnt = init_cnt = rearm_cnt = 0UL;
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_FULL, 0UL, sizeof(*init), 0UL, 0UL, 0UL, NULL ) );
  fd_ssctrl_start_t * start = (fd_ssctrl_start_t *)input;
  fd_memset( start, 0, sizeof(*start) );
  start->addr = (fd_ip4_port_t){ .addr = sa.sin_addr.s_addr, .port = sa.sin_port };
  fd_cstr_ncpy( start->hostname, "localhost", sizeof(start->hostname) );
  fd_cstr_ncpy( start->path, "/snapshot.tar.bz2", sizeof(start->path) );
  start->path_len = strlen( start->path );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_START, 0UL, sizeof(*start), 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->pipeline_ready && init_cnt==1UL && publish_cnt==1UL );
  int server = accept( listener, NULL, NULL );
  FD_TEST( server>=0 );

  int  busy = 0;
  char request[ 4096 ] = {0};
  ulong request_len = 0UL;
  for( ulong i=0UL; !strstr( request, "\r\n\r\n" ); i++ ) {
    FD_TEST( i<1024UL );
    after_credit( ctx, test_stem, NULL, &busy );
    long n = recv( server, request+request_len, sizeof(request)-1UL-request_len, MSG_DONTWAIT );
    if( n>0L ) request_len += (ulong)n;
    else FD_TEST( n<0L && (errno==EAGAIN || errno==EINTR) );
    request[ request_len ] = '\0';
  }

  /* Headers and the first body bytes arrive together; the read after
     them finds the socket empty and parks. */
  ulong const chunk_sz = 100UL;
  char  resp[ 256 ];
  ulong resp_len;
  FD_TEST( fd_cstr_printf_check( resp, sizeof(resp)-chunk_sz, &resp_len, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n", 3UL*chunk_sz ) );
  fd_memset( resp+resp_len, 'a', chunk_sz );
  resp_len += chunk_sz;
  FD_TEST( (long)resp_len==send( server, resp, resp_len, 0 ) );
  wait_queued( http->sockfd, resp_len );
  for( ulong i=0UL; !fd_sshttp_rx_parked( http ); i++ ) {
    FD_TEST( i<16UL );
    after_credit( ctx, test_stem, NULL, &busy );
  }
  FD_TEST( ctx->sent_meta && publish_cnt==3UL && publish_sig==FD_SNAPSHOT_MSG_DATA && !rearm_cnt );

  /* Parked and not woken: queued bytes are left alone */
  FD_TEST( (long)chunk_sz==send( server, resp, chunk_sz, 0 ) );
  wait_queued( http->sockfd, chunk_sz );
  for( int i=0; i<3; i++ ) after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( publish_cnt==3UL && !rearm_cnt && fd_sshttp_rx_parked( http ) );
  wait_queued( http->sockfd, chunk_sz );

  /* Woken: one read, one rearm, then parked again */
  fd_fseq_update( ctx->waker_fseq, 1UL );
  after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( publish_cnt==4UL && publish_sig==FD_SNAPSHOT_MSG_DATA && rearm_cnt==1UL );
  FD_TEST( !fd_fseq_query( ctx->waker_fseq ) );
  after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( publish_cnt==4UL && rearm_cnt==1UL && fd_sshttp_rx_parked( http ) );

  /* Never woken again: the progress window runs out and cancels */
  ctx->window_deadline = fd_clock_tile_now( ctx->clock )-1L;
  after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR && publish_cnt==5UL && publish_sig==FD_SNAPSHOT_MSG_CTRL_ERROR );
  FD_TEST( rearm_cnt==1UL && http->sockfd==-1 && !fd_sshttp_rx_parked( http ) );

  FD_TEST( !close( server ) );
  FD_TEST( !close( listener ) );
}

/* woken_credit runs one pass of the tile with the waker reporting the
   download socket readable, as the waker tile does when bytes
   arrive. */
static void
woken_credit( fd_snapld_tile_t * ctx,
              int *              busy ) {
  fd_fseq_update( ctx->waker_fseq, 1UL );
  after_credit( ctx, test_stem, NULL, busy );
}

/* serve_one_open accepts the tile's next connection, drives the tile
   until its request has arrived, checks the request holds expect,
   answers with resp and returns the open connection.  serve_one also
   closes it. */
static int
serve_one_open( fd_snapld_tile_t * ctx,
                int                server,
                char const *       expect,
                char const *       resp ) {
  int   busy    = 0;
  int   conn    = -1;
  char  req[ 4096 ];
  ulong req_len = 0UL;
  for( ulong i=0UL; i<100000UL; i++ ) {
    woken_credit( ctx, &busy );
    if( conn==-1 ) {
      conn = accept4( server, NULL, NULL, SOCK_NONBLOCK );
      if( conn==-1 ) {
        FD_TEST( errno==EAGAIN || errno==EWOULDBLOCK );
        continue;
      }
    }
    long n = recv( conn, req+req_len, sizeof(req)-1UL-req_len, 0 );
    if( n>0L ) req_len += (ulong)n;
    req[ req_len ] = '\0';
    if( strstr( req, "\r\n\r\n" ) ) break;
  }
  FD_TEST( conn!=-1 && strstr( req, "\r\n\r\n" ) );
  FD_TEST( strstr( req, expect ) );
  FD_TEST( (long)strlen( resp )==send( conn, resp, strlen( resp ), 0 ) );
  return conn;
}

static void
serve_one( fd_snapld_tile_t * ctx,
           int                server,
           char const *       expect,
           char const *       resp ) {
  FD_TEST( !close( serve_one_open( ctx, server, expect, resp ) ) );
}

/* drive_until runs the tile until *var equals val. */
static void
drive_until( fd_snapld_tile_t * ctx,
             ulong *            var,
             ulong              val ) {
  int busy = 0;
  for( ulong i=0UL; i<100000UL && *var!=val; i++ ) woken_credit( ctx, &busy );
  FD_TEST( *var==val );
}

/* init_full_download sends INIT_FULL and START for a plain full
   snapshot download from the test server. */
static void
init_full_download( fd_snapld_tile_t *   ctx,
                    uchar *              input,
                    struct sockaddr_in * sa ) {
  fd_ssctrl_init_t * init = (fd_ssctrl_init_t *)input;
  fd_memset( init, 0, sizeof(*init) );
  init->slot = 123UL;
  init_slot  = init->slot;
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_FULL, 0UL, sizeof(*init), 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->request_retries==FD_SNAPLD_REQUEST_RETRY_MAX );
  fd_ssctrl_start_t * start = (fd_ssctrl_start_t *)input;
  fd_memset( start, 0, sizeof(*start) );
  start->addr = (fd_ip4_port_t){ .addr = sa->sin_addr.s_addr, .port = sa->sin_port };
  fd_cstr_ncpy( start->hostname, "localhost", sizeof(start->hostname) );
  fd_cstr_ncpy( start->path, "/snapshot.tar.bz2", sizeof(start->path) );
  start->path_len = strlen( start->path );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_START, 0UL, sizeof(*start), 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->pipeline_ready && ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
}

/* init_stream_download sends INIT_FULL and START for the fast boot
   stream at slot, at /name on the test server. */
static void
init_stream_download( fd_snapld_tile_t *   ctx,
                      uchar *              input,
                      struct sockaddr_in * sa,
                      ulong                slot,
                      char const *         name ) {
  fd_ssctrl_init_t * init = (fd_ssctrl_init_t *)input;
  fd_memset( init, 0, sizeof(*init) );
  init->slot             = slot;
  init->fast_boot_stream = 1;
  init_slot = init->slot;
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_FULL, 0UL, sizeof(*init), 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->fast_boot_stream.active && ctx->fast_boot_stream.slot==slot && ctx->fast_boot_stream.wait==LONG_MAX && !ctx->is_redirect );
  fd_ssctrl_start_t * start = (fd_ssctrl_start_t *)input;
  fd_memset( start, 0, sizeof(*start) );
  start->addr = (fd_ip4_port_t){ .addr = sa->sin_addr.s_addr, .port = sa->sin_port };
  fd_cstr_ncpy( start->hostname, "localhost", sizeof(start->hostname) );
  FD_TEST( fd_cstr_printf_check( start->path, sizeof(start->path), &start->path_len, "/%s", name ) );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_START, 0UL, sizeof(*start), 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->pipeline_ready && ctx->state==FD_SNAPSHOT_STATE_PROCESSING );
}

/* retry_now waits for the tile to schedule its next stream request
   and makes it due. */
static void
retry_now( fd_snapld_tile_t * ctx ) {
  int busy = 0;
  for( ulong i=0UL; i<100000UL && ctx->fast_boot_stream.wait==LONG_MAX; i++ ) woken_credit( ctx, &busy );
  FD_TEST( ctx->fast_boot_stream.wait!=LONG_MAX );
  ctx->fast_boot_stream.wait = 0L;
}

/* A fast boot stream: a response holds what the server has (read
   that far is reported once as caught up) and then what the stream
   grows by, until the server closes the connection.  A 404 means the
   stream ended with nothing after it yet, and a redirect sends the
   peer on to the next stream, which must be newer than the one that
   ended.  A request that ends is asked again from the offset, only a
   SHUTDOWN ends the load. */
static void
test_stream( void ) {
  static fd_sshttp_t http[1];
  static uchar      input[ sizeof(fd_ssctrl_start_t) ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  static ulong waker_fseq[ FD_FSEQ_FOOTPRINT/sizeof(ulong) ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  fd_snapld_tile_t ctx[1] = {0};
  int busy = 0;
  ctx->sshttp        = fd_sshttp_join( fd_sshttp_new( http, test_epoll_fd ) );
  ctx->waker_fseq    = fd_fseq_join( fd_fseq_new( waker_fseq, 0UL ) );
  ctx->waker_client_idx = 7UL;
  fd_clock_tile_init( ctx->clock );
  ctx->in_rd.base    = input;
  ctx->out_dc.mem    = (fd_wksp_t *)output;
  ctx->out_dc.mtu    = FD_SNAPSHOT_DATA_MTU;
  ctx->out_dc.wmark  = 2UL*FD_SNAPSHOT_DATA_MTU/FD_CHUNK_SZ;
  ctx->local_full_fd = -1;

  int server = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  FD_TEST( server>=0 );
  struct sockaddr_in sa = {
    .sin_family = AF_INET,
    .sin_addr   = { .s_addr = htonl( INADDR_LOOPBACK ) }
  };
  FD_TEST( !bind( server, fd_type_pun( &sa ), sizeof(sa) ) );
  socklen_t sa_sz = sizeof(sa);
  FD_TEST( !getsockname( server, fd_type_pun( &sa ), &sa_sz ) );
  FD_TEST( !listen( server, 1 ) );

  uchar hash[ 32 ];
  fd_memset( hash, 0x5a, sizeof(hash) );
  char hash_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( hash, NULL, hash_b58 );
  char name[ 128 ];
  FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "fast-boot-stream-123-%s.tar.zst", hash_b58 ) );
  char get[ 160 ];
  FD_TEST( fd_cstr_printf_check( get, sizeof(get), NULL, "GET /%s HTTP/1.1", name ) );

  publish_cnt = init_cnt = 0UL;
  init_stream_download( ctx, input, &sa, 123UL, name );
  FD_TEST( init_cnt==1UL );
  ulong meta_chunk = ctx->out_dc.chunk; /* META goes out next */

  /* No stream at the server yet: ask again later. */
  serve_one( ctx, server, get, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" );
  drive_until( ctx, &init_cnt, 1UL );
  for( int i=0; i<100; i++ ) woken_credit( ctx, &busy );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && ctx->fast_boot_stream.wait!=LONG_MAX && publish_cnt==1UL );
  ctx->fast_boot_stream.wait = 0L;

  /* The server had 12 bytes and the connection drops after 8: not
     caught up, asked again from the offset. */
  serve_one( ctx, server, get, "HTTP/1.1 200 OK\r\nStream-Offset: 0\r\nStream-Size: 12\r\n\r\nsnapshot" );
  drive_until( ctx, &ctx->fast_boot_stream.off, 8UL );
  FD_TEST( ctx->sent_meta && ctx->fast_boot_stream.slot==123UL && publish_cnt==3UL && publish_sig==FD_SNAPSHOT_MSG_DATA );
  FD_TEST( http->location[ 0 ]=='/' && !strcmp( http->location+1, name ) );
  fd_ssctrl_meta_t const * meta = fd_chunk_to_laddr_const( output, meta_chunk );
  FD_TEST( meta->total_sz==12UL && meta->resolved_slot==ULONG_MAX && !meta->resolved_name[ 0 ] );
  retry_now( ctx );

  /* The server drops a request before caught up: asked again from the
     same offset. */
  serve_one( ctx, server, "Range: bytes=8-\r\n", "" );
  for( int i=0; i<100; i++ ) woken_credit( ctx, &busy );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && !ctx->fast_boot_stream.caught_up && publish_cnt==3UL && ctx->fast_boot_stream.wait!=LONG_MAX );
  ctx->fast_boot_stream.wait = 0L;

  /* A download speed window belongs to one request: an expired one
     left by the last request does not cancel the next. */
  ctx->window_deadline = 1L;
  ctx->bytes_in_window = 0UL;
  woken_credit( ctx, &busy );
  FD_TEST( ctx->window_deadline==LONG_MAX && ctx->fast_boot_stream.wait==LONG_MAX && http->state!=FD_SSHTTP_STATE_INIT );

  /* More bytes.  A stream only needs a byte per window. */
  int conn = serve_one_open( ctx, server, "Range: bytes=8-\r\n", "HTTP/1.1 200 OK\r\nStream-Offset: 8\r\nStream-Size: 12\r\n\r\n" );
  for( int i=0; i<100 && http->state!=FD_SSHTTP_STATE_DL; i++ ) woken_credit( ctx, &busy );
  FD_TEST( http->state==FD_SSHTTP_STATE_DL );
  ctx->window_deadline     = 1L;
  ctx->bytes_in_window     = 1UL;
  ctx->min_bytes_in_window = ULONG_MAX;
  woken_credit( ctx, &busy );
  FD_TEST( ctx->window_deadline!=LONG_MAX && ctx->fast_boot_stream.wait==LONG_MAX );
  FD_TEST( 4L==send( conn, "more", 4UL, 0 ) );
  drive_until( ctx, &ctx->fast_boot_stream.off, 12UL );

  /* All the server had was read: caught up, once. */
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && publish_cnt==5UL );
  FD_TEST( ctx->fast_boot_stream.caught_up && publish_sig==FD_SNAPSHOT_MSG_STREAM_CAUGHT_UP );

  /* The stream grows: the bytes come on the same connection. */
  FD_TEST( 4L==send( conn, "tail", 4UL, 0 ) );
  drive_until( ctx, &ctx->fast_boot_stream.off, 16UL );
  FD_TEST( publish_cnt==6UL && publish_sig==FD_SNAPSHOT_MSG_DATA && ctx->fast_boot_stream.wait==LONG_MAX );

  /* The stream closed: asked again from the offset. */
  FD_TEST( !close( conn ) );
  retry_now( ctx );

  /* The stream ended and nothing follows it yet: asked again later,
     from the same offset. */
  serve_one( ctx, server, "Range: bytes=16-\r\n", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" );
  for( int i=0; i<100000 && ctx->fast_boot_stream.wait==LONG_MAX; i++ ) woken_credit( ctx, &busy );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && ctx->fast_boot_stream.off==16UL && publish_cnt==6UL && ctx->fast_boot_stream.wait!=LONG_MAX );
  ctx->fast_boot_stream.wait = 0L;

  /* The server sends the peer on to the next stream, which is read
     from its start, without a second META. */
  FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "fast-boot-stream-124-%s.tar.zst", hash_b58 ) );
  char redirect[ 256 ];
  FD_TEST( fd_cstr_printf_check( redirect, sizeof(redirect), NULL, "HTTP/1.1 302 Found\r\nLocation: /%s\r\nContent-Length: 0\r\n\r\n", name ) );
  FD_TEST( fd_cstr_printf_check( get, sizeof(get), NULL, "GET /%s HTTP/1.1", name ) );

  static fd_wait_info_box_t box[ 1 ];
  ctx->wait_info = fd_wait_info_box_join( fd_wait_info_box_new( box ) );
  ctx->wait_info->info.reset_slot = 123UL;

  /* Its connection drops after the headers, before any data: the
     stream that ended is asked again, so the redirect is checked
     again. */
  serve_one( ctx, server, "Range: bytes=16-\r\n", redirect );
  serve_one( ctx, server, get, "HTTP/1.1 200 OK\r\nStream-Offset: 0\r\nStream-Size: 4\r\n\r\n" );
  for( int i=0; i<100000 && ctx->fast_boot_stream.wait==LONG_MAX; i++ ) woken_credit( ctx, &busy );
  FD_TEST( ctx->fast_boot_stream.slot==123UL && ctx->fast_boot_stream.off==16UL );
  FD_TEST( ctx->fast_boot_stream.next_stream_slot==ULONG_MAX && publish_cnt==6UL && http->state==FD_SSHTTP_STATE_INIT );
  ctx->fast_boot_stream.wait = 0L;

  /* Replay is still below the next stream's start: not followed,
     asked again later. */
  serve_one( ctx, server, "Range: bytes=16-\r\n", redirect );
  serve_one( ctx, server, get, "HTTP/1.1 200 OK\r\nStream-Offset: 0\r\nStream-Size: 4\r\n\r\nnext" );
  drive_until( ctx, &ctx->fast_boot_stream.next_stream_slot, 124UL );
  FD_TEST( ctx->fast_boot_stream.slot==123UL && ctx->fast_boot_stream.off==16UL );
  FD_TEST( publish_cnt==6UL && ctx->fast_boot_stream.wait!=LONG_MAX && http->state==FD_SSHTTP_STATE_INIT );

  /* Not even asked for until replay gets there. */
  ctx->fast_boot_stream.wait = 0L;
  for( int i=0; i<100; i++ ) woken_credit( ctx, &busy );
  FD_TEST( http->state==FD_SSHTTP_STATE_INIT && ctx->fast_boot_stream.wait!=LONG_MAX );
  ctx->wait_info->info.reset_slot = 124UL;
  ctx->fast_boot_stream.wait = 0L;

  serve_one( ctx, server, "Range: bytes=16-\r\n", redirect );
  serve_one( ctx, server, get, "HTTP/1.1 200 OK\r\nStream-Offset: 0\r\nStream-Size: 4\r\n\r\nnext" );
  drive_until( ctx, &ctx->fast_boot_stream.off, 4UL );
  FD_TEST( init_cnt==1UL && ctx->fast_boot_stream.slot==124UL && ctx->fast_boot_stream.next_stream_slot==ULONG_MAX );
  FD_TEST( !strcmp( ctx->fast_boot_stream.path+1, name ) && ctx->fast_boot_stream.path_len==strlen( name )+1UL );
  FD_TEST( publish_cnt==7UL && publish_sig==FD_SNAPSHOT_MSG_DATA );
  retry_now( ctx );

  /* A dropped request on the new stream is asked again on it, from
     its offset. */
  serve_one( ctx, server, get, "" );
  for( int i=0; i<100000 && ctx->fast_boot_stream.wait==LONG_MAX; i++ ) woken_credit( ctx, &busy );
  FD_TEST( ctx->fast_boot_stream.slot==124UL && ctx->fast_boot_stream.off==4UL && publish_cnt==7UL );
  ctx->fast_boot_stream.wait = 0L;

  /* Sent on to a stream that is not after the one that ended:
     malformed. */
  char name123[ 128 ];
  char redirect123[ 256 ];
  char get123[ 160 ];
  FD_TEST( fd_cstr_printf_check( name123, sizeof(name123), NULL, "fast-boot-stream-123-%s.tar.zst", hash_b58 ) );
  FD_TEST( fd_cstr_printf_check( redirect123, sizeof(redirect123), NULL, "HTTP/1.1 302 Found\r\nLocation: /%s\r\nContent-Length: 0\r\n\r\n", name123 ) );
  FD_TEST( fd_cstr_printf_check( get123, sizeof(get123), NULL, "GET /%s HTTP/1.1", name123 ) );
  serve_one( ctx, server, "Range: bytes=4-\r\n", redirect123 );
  serve_one( ctx, server, get123, "HTTP/1.1 200 OK\r\nStream-Offset: 0\r\nStream-Size: 4\r\n\r\nnext" );
  drive_until( ctx, &publish_cnt, 8UL );
  FD_TEST( publish_sig==FD_SNAPSHOT_MSG_CTRL_ERROR && ctx->state==FD_SNAPSHOT_STATE_ERROR && http->state==FD_SSHTTP_STATE_INIT );

  /* After FAIL the stream is asked for afresh.  A SHUTDOWN in the
     middle of a request cancels it. */
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
  init_stream_download( ctx, input, &sa, 124UL, name );
  FD_TEST( init_cnt==2UL && http->state!=FD_SSHTTP_STATE_INIT && http->sockfd!=-1 );

  /* The server had 12 bytes and the stream is gone after 8: the
     peer never caught up on it, so the load fails. */
  serve_one( ctx, server, get, "HTTP/1.1 200 OK\r\nStream-Offset: 0\r\nStream-Size: 12\r\n\r\nsnapshot" );
  drive_until( ctx, &ctx->fast_boot_stream.off, 8UL );
  ulong published = publish_cnt;
  retry_now( ctx );
  serve_one( ctx, server, "Range: bytes=8-\r\n", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" );
  drive_until( ctx, &publish_cnt, published+1UL );
  FD_TEST( publish_sig==FD_SNAPSHOT_MSG_CTRL_ERROR && ctx->state==FD_SNAPSHOT_STATE_ERROR && !ctx->fast_boot_stream.caught_up );

  /* The same when the server sends the peer on to the next stream. */
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
  init_stream_download( ctx, input, &sa, 124UL, name );
  serve_one( ctx, server, get, "HTTP/1.1 200 OK\r\nStream-Offset: 0\r\nStream-Size: 12\r\n\r\nsnapshot" );
  drive_until( ctx, &ctx->fast_boot_stream.off, 8UL );
  published = publish_cnt;
  retry_now( ctx );
  char name125[ 128 ];
  char redirect125[ 256 ];
  char get125[ 160 ];
  FD_TEST( fd_cstr_printf_check( name125, sizeof(name125), NULL, "fast-boot-stream-125-%s.tar.zst", hash_b58 ) );
  FD_TEST( fd_cstr_printf_check( redirect125, sizeof(redirect125), NULL, "HTTP/1.1 302 Found\r\nLocation: /%s\r\nContent-Length: 0\r\n\r\n", name125 ) );
  FD_TEST( fd_cstr_printf_check( get125, sizeof(get125), NULL, "GET /%s HTTP/1.1", name125 ) );
  serve_one( ctx, server, "Range: bytes=8-\r\n", redirect125 );
  serve_one( ctx, server, get125, "HTTP/1.1 200 OK\r\nStream-Offset: 0\r\nStream-Size: 4\r\n\r\nnext" );
  drive_until( ctx, &publish_cnt, published+1UL );
  FD_TEST( publish_sig==FD_SNAPSHOT_MSG_CTRL_ERROR && ctx->state==FD_SNAPSHOT_STATE_ERROR && !ctx->fast_boot_stream.caught_up );
  FD_TEST( ctx->fast_boot_stream.slot==124UL && http->state==FD_SSHTTP_STATE_INIT );

  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
  init_stream_download( ctx, input, &sa, 124UL, name );
  FD_TEST( http->state!=FD_SSHTTP_STATE_INIT && http->sockfd!=-1 );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN && publish_sig==FD_SNAPSHOT_MSG_CTRL_SHUTDOWN );
  FD_TEST( http->state==FD_SSHTTP_STATE_INIT && http->sockfd==-1 );

  fd_sshttp_cancel( http );
  FD_TEST( !close( server ) );
}

/* A FAIL for a fast boot stream before the server answered resets the
   load and is acked.  Once the stream answered the FAIL is late: the
   stream is kept, with its request in flight, and nothing is acked. */
static void
test_stream_fail( void ) {
  static fd_sshttp_t http[1];
  static uchar      input[ sizeof(fd_ssctrl_start_t) ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  static ulong waker_fseq[ FD_FSEQ_FOOTPRINT/sizeof(ulong) ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  fd_snapld_tile_t ctx[1] = {0};
  int busy = 0;
  ctx->sshttp        = fd_sshttp_join( fd_sshttp_new( http, test_epoll_fd ) );
  ctx->waker_fseq    = fd_fseq_join( fd_fseq_new( waker_fseq, 0UL ) );
  ctx->waker_client_idx = 7UL;
  fd_clock_tile_init( ctx->clock );
  ctx->in_rd.base    = input;
  ctx->out_dc.mem    = (fd_wksp_t *)output;
  ctx->out_dc.mtu    = FD_SNAPSHOT_DATA_MTU;
  ctx->out_dc.wmark  = 2UL*FD_SNAPSHOT_DATA_MTU/FD_CHUNK_SZ;
  ctx->local_full_fd = -1;

  int server = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  FD_TEST( server>=0 );
  struct sockaddr_in sa = {
    .sin_family = AF_INET,
    .sin_addr   = { .s_addr = htonl( INADDR_LOOPBACK ) }
  };
  FD_TEST( !bind( server, fd_type_pun( &sa ), sizeof(sa) ) );
  socklen_t sa_sz = sizeof(sa);
  FD_TEST( !getsockname( server, fd_type_pun( &sa ), &sa_sz ) );
  FD_TEST( !listen( server, 1 ) );

  fd_ssctrl_init_t *  init  = (fd_ssctrl_init_t *)input;
  fd_ssctrl_start_t * start = (fd_ssctrl_start_t *)input;
  fd_memset( init, 0, sizeof(*init) );
  init->slot             = 123UL;
  init->fast_boot_stream = 1;
  init_slot   = init->slot;
  publish_cnt = init_cnt = 0UL;
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_FULL, 0UL, sizeof(*init), 0UL, 0UL, 0UL, NULL ) );
  fd_memset( start, 0, sizeof(*start) );
  start->addr = (fd_ip4_port_t){ .addr = sa.sin_addr.s_addr, .port = sa.sin_port };
  fd_cstr_ncpy( start->hostname, "localhost", sizeof(start->hostname) );
  fd_cstr_ncpy( start->path, "/fast-boot-stream-123-x.tar.zst", sizeof(start->path) );
  start->path_len = strlen( start->path );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_START, 0UL, sizeof(*start), 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->pipeline_ready && init_cnt==1UL && publish_cnt==1UL );

  /* No answer yet: the FAIL resets the load and goes down the
     pipeline. */
  serve_one( ctx, server, "GET /fast-boot-stream-123-x.tar.zst HTTP/1.1", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" );
  for( int i=0; i<100; i++ ) woken_credit( ctx, &busy );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && !ctx->sent_meta && publish_cnt==1UL );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE && !ctx->pipeline_ready && publish_cnt==2UL && publish_sig==FD_SNAPSHOT_MSG_CTRL_FAIL );
  FD_TEST( http->state==FD_SSHTTP_STATE_INIT && http->sockfd==-1 );

  /* The stream answered: a FAIL is late and ignored. */
  fd_memset( init, 0, sizeof(*init) );
  init->slot             = 123UL;
  init->fast_boot_stream = 1;
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_FULL, 0UL, sizeof(*init), 0UL, 0UL, 0UL, NULL ) );
  fd_memset( start, 0, sizeof(*start) );
  start->addr = (fd_ip4_port_t){ .addr = sa.sin_addr.s_addr, .port = sa.sin_port };
  fd_cstr_ncpy( start->hostname, "localhost", sizeof(start->hostname) );
  fd_cstr_ncpy( start->path, "/fast-boot-stream-123-x.tar.zst", sizeof(start->path) );
  start->path_len = strlen( start->path );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_START, 0UL, sizeof(*start), 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->pipeline_ready && init_cnt==2UL );
  publish_cnt = 0UL;
  serve_one( ctx, server, "GET /fast-boot-stream-123-x.tar.zst HTTP/1.1", "HTTP/1.1 200 OK\r\nStream-Offset: 0\r\nStream-Size: 12\r\n\r\nsnapshot" );
  drive_until( ctx, &ctx->fast_boot_stream.off, 8UL );
  FD_TEST( ctx->sent_meta && publish_cnt==2UL && publish_sig==FD_SNAPSHOT_MSG_DATA );
  retry_now( ctx );
  for( int i=0; i<100 && http->state==FD_SSHTTP_STATE_INIT; i++ ) woken_credit( ctx, &busy );
  FD_TEST( http->state!=FD_SSHTTP_STATE_INIT && http->sockfd!=-1 && ctx->fast_boot_stream.wait==LONG_MAX );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && ctx->pipeline_ready && publish_cnt==2UL );
  FD_TEST( http->state!=FD_SSHTTP_STATE_INIT && http->sockfd!=-1 && ctx->fast_boot_stream.wait==LONG_MAX );

  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_SHUTDOWN, 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN && http->state==FD_SSHTTP_STATE_INIT && http->sockfd==-1 );

  fd_sshttp_cancel( http );
  FD_TEST( !close( server ) );
}

/* A fast boot stream request whose body arrives late.  The read that
   finds the socket empty parks, queued bytes then wait for the waker,
   and a request that is never woken again is asked again from the offset
   passed on so far once a progress window saw no byte. */
static void
test_stream_parked( void ) {
  static fd_sshttp_t http[1];
  static uchar      input[ sizeof(fd_ssctrl_start_t) ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  static ulong waker_fseq[ FD_FSEQ_FOOTPRINT/sizeof(ulong) ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  fd_snapld_tile_t ctx[1] = {0};
  int busy = 0;
  ctx->sshttp        = fd_sshttp_join( fd_sshttp_new( http, test_epoll_fd ) );
  ctx->waker_fseq    = fd_fseq_join( fd_fseq_new( waker_fseq, 0UL ) );
  ctx->waker_client_idx = 7UL;
  fd_clock_tile_init( ctx->clock );
  ctx->in_rd.base    = input;
  ctx->out_dc.mem    = (fd_wksp_t *)output;
  ctx->out_dc.mtu    = FD_SNAPSHOT_DATA_MTU;
  ctx->out_dc.wmark  = 2UL*FD_SNAPSHOT_DATA_MTU/FD_CHUNK_SZ;
  ctx->local_full_fd = -1;

  int server = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  FD_TEST( server>=0 );
  struct sockaddr_in sa = {
    .sin_family = AF_INET,
    .sin_addr   = { .s_addr = htonl( INADDR_LOOPBACK ) }
  };
  FD_TEST( !bind( server, fd_type_pun( &sa ), sizeof(sa) ) );
  socklen_t sa_sz = sizeof(sa);
  FD_TEST( !getsockname( server, fd_type_pun( &sa ), &sa_sz ) );
  FD_TEST( !listen( server, 1 ) );

  uchar hash[ 32 ];
  fd_memset( hash, 0x5a, sizeof(hash) );
  char hash_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( hash, NULL, hash_b58 );
  char name[ 128 ];
  FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "fast-boot-stream-123-%s.tar.zst", hash_b58 ) );
  char get[ 160 ];
  FD_TEST( fd_cstr_printf_check( get, sizeof(get), NULL, "GET /%s HTTP/1.1", name ) );

  publish_cnt = init_cnt = 0UL;
  init_stream_download( ctx, input, &sa, 123UL, name );

  /* Headers and the first body bytes arrive together; the read after
     them finds the socket empty and parks. */
  ulong const chunk_sz = 100UL;
  char  resp[ 256 ];
  ulong resp_len;
  FD_TEST( fd_cstr_printf_check( resp, sizeof(resp)-chunk_sz, &resp_len, "HTTP/1.1 200 OK\r\nStream-Offset: 0\r\nStream-Size: %lu\r\n\r\n", 3UL*chunk_sz ) );
  fd_memset( resp+resp_len, 'a', chunk_sz );
  resp_len += chunk_sz;
  resp[ resp_len ] = '\0';
  int conn = serve_one_open( ctx, server, get, resp );
  rearm_cnt = 0UL;
  wait_queued( http->sockfd, resp_len );
  for( ulong i=0UL; !fd_sshttp_rx_parked( http ); i++ ) {
    FD_TEST( i<16UL );
    after_credit( ctx, test_stem, NULL, &busy );
  }
  FD_TEST( ctx->sent_meta && publish_cnt==3UL && publish_sig==FD_SNAPSHOT_MSG_DATA && !rearm_cnt );
  FD_TEST( ctx->fast_boot_stream.off==chunk_sz );

  /* Parked and not woken: queued bytes are left alone */
  FD_TEST( (long)chunk_sz==send( conn, resp, chunk_sz, 0 ) );
  wait_queued( http->sockfd, chunk_sz );
  for( int i=0; i<3; i++ ) after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( publish_cnt==3UL && ctx->fast_boot_stream.off==chunk_sz && !rearm_cnt && fd_sshttp_rx_parked( http ) );

  /* Woken: one read, the offset follows, one rearm, then parked again */
  fd_fseq_update( ctx->waker_fseq, 1UL );
  after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( publish_cnt==4UL && publish_sig==FD_SNAPSHOT_MSG_DATA && rearm_cnt==1UL );
  FD_TEST( ctx->fast_boot_stream.off==2UL*chunk_sz && !fd_fseq_query( ctx->waker_fseq ) );
  after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( publish_cnt==4UL && rearm_cnt==1UL && fd_sshttp_rx_parked( http ) );

  /* Never woken again.  The window that saw bytes just restarts.  The
     next one sees none: the request is dropped and the load goes on. */
  ctx->window_deadline = fd_clock_tile_now( ctx->clock )-1L;
  after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && http->sockfd!=-1 && fd_sshttp_rx_parked( http ) );
  ctx->window_deadline = fd_clock_tile_now( ctx->clock )-1L;
  after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && http->sockfd==-1 && !fd_sshttp_rx_parked( http ) );
  FD_TEST( ctx->fast_boot_stream.wait!=LONG_MAX && publish_cnt==4UL && ctx->fast_boot_stream.off==2UL*chunk_sz );
  FD_TEST( !close( conn ) );

  /* The stream is asked again from the bytes passed on so far */
  ctx->fast_boot_stream.wait = 0L;
  serve_one( ctx, server, "Range: bytes=200-\r\n", "HTTP/1.1 200 OK\r\nStream-Offset: 200\r\nStream-Size: 200\r\n\r\n" );
  drive_until( ctx, &publish_cnt, 5UL );
  FD_TEST( ctx->fast_boot_stream.caught_up && publish_sig==FD_SNAPSHOT_MSG_STREAM_CAUGHT_UP );

  fd_sshttp_cancel( http );
  FD_TEST( !close( server ) );
}

/* A snapshot request that fails before any of its response arrived
   is sent again, FD_SNAPLD_REQUEST_RETRY_MAX times at most.  Once
   part of the response went downstream a failure ends the load. */
static void
test_request_retry( void ) {
  static fd_sshttp_t http[1];
  static uchar      input[ sizeof(fd_ssctrl_start_t) ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  static ulong waker_fseq[ FD_FSEQ_FOOTPRINT/sizeof(ulong) ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  fd_snapld_tile_t ctx[1] = {0};
  int busy = 0;
  ctx->sshttp        = fd_sshttp_join( fd_sshttp_new( http, test_epoll_fd ) );
  ctx->waker_fseq    = fd_fseq_join( fd_fseq_new( waker_fseq, 0UL ) );
  ctx->waker_client_idx = 7UL;
  fd_clock_tile_init( ctx->clock );
  ctx->in_rd.base    = input;
  ctx->out_dc.mem    = (fd_wksp_t *)output;
  ctx->out_dc.mtu    = FD_SNAPSHOT_DATA_MTU;
  ctx->out_dc.wmark  = 2UL*FD_SNAPSHOT_DATA_MTU/FD_CHUNK_SZ;
  ctx->local_full_fd = -1;

  int server = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  FD_TEST( server>=0 );
  struct sockaddr_in sa = {
    .sin_family = AF_INET,
    .sin_addr   = { .s_addr = htonl( INADDR_LOOPBACK ) }
  };
  FD_TEST( !bind( server, fd_type_pun( &sa ), sizeof(sa) ) );
  socklen_t sa_sz = sizeof(sa);
  FD_TEST( !getsockname( server, fd_type_pun( &sa ), &sa_sz ) );
  FD_TEST( !listen( server, 1 ) );

  init_full_download( ctx, input, &sa );
  publish_cnt = 0UL;

  /* Not a fast boot: a dropped request fails the load, before or
     after part of the response arrived. */
  serve_one( ctx, server, "GET /snapshot.tar.bz2 HTTP/1.1", "" );
  drive_until( ctx, &publish_cnt, 1UL );
  FD_TEST( publish_sig==FD_SNAPSHOT_MSG_CTRL_ERROR && ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( ctx->request_retries==FD_SNAPLD_REQUEST_RETRY_MAX && http->state==FD_SSHTTP_STATE_INIT );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
  init_full_download( ctx, input, &sa );
  publish_cnt = 0UL;
  serve_one( ctx, server, "GET /snapshot.tar.bz2 HTTP/1.1", "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nsnap" );
  drive_until( ctx, &publish_cnt, 3UL );
  FD_TEST( ctx->sent_meta && publish_sig==FD_SNAPSHOT_MSG_CTRL_ERROR && ctx->state==FD_SNAPSHOT_STATE_ERROR );

  /* In a fast boot the server drops the request: sent again after a
     pause. */
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
  ctx->config.fast_boot = 1;
  init_full_download( ctx, input, &sa );
  publish_cnt = 0UL;
  serve_one( ctx, server, "GET /snapshot.tar.bz2 HTTP/1.1", "" );
  for( int i=0; i<100; i++ ) woken_credit( ctx, &busy );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && !publish_cnt && ctx->fast_boot_stream.wait!=LONG_MAX );
  FD_TEST( ctx->request_retries==FD_SNAPLD_REQUEST_RETRY_MAX-1U );
  ctx->fast_boot_stream.wait = 0L;

  /* The headers arrive but no body: the speed window fails the load
     as before, a stall is not a failed request. */
  int conn = serve_one_open( ctx, server, "GET /snapshot.tar.bz2 HTTP/1.1", "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n" );
  for( int i=0; i<100; i++ ) woken_credit( ctx, &busy );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && !publish_cnt && ctx->window_deadline!=LONG_MAX );
  ctx->min_bytes_in_window = 1UL;
  ctx->window_deadline     = 1L;
  drive_until( ctx, &publish_cnt, 1UL );
  FD_TEST( publish_sig==FD_SNAPSHOT_MSG_CTRL_ERROR && ctx->state==FD_SNAPSHOT_STATE_ERROR );
  FD_TEST( ctx->request_retries==FD_SNAPLD_REQUEST_RETRY_MAX-1U && http->state==FD_SSHTTP_STATE_INIT );
  FD_TEST( !close( conn ) );

  /* After FAIL a new load has a fresh budget.  A request dropped
     every time is given up after FD_SNAPLD_REQUEST_RETRY_MAX more
     tries. */
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
  init_full_download( ctx, input, &sa );
  publish_cnt = 0UL;
  for( uint i=0U; i<=FD_SNAPLD_REQUEST_RETRY_MAX; i++ ) {
    serve_one( ctx, server, "GET /snapshot.tar.bz2 HTTP/1.1", "" );
    for( int j=0; j<100; j++ ) woken_credit( ctx, &busy );
    if( i<FD_SNAPLD_REQUEST_RETRY_MAX ) {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && !publish_cnt && ctx->request_retries==FD_SNAPLD_REQUEST_RETRY_MAX-1U-i );
      ctx->fast_boot_stream.wait = 0L;
    }
  }
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_ERROR && publish_cnt==1UL && publish_sig==FD_SNAPSHOT_MSG_CTRL_ERROR && http->state==FD_SSHTTP_STATE_INIT );

  /* A download that drops after part of the file asks for the rest
     and finishes. */
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_FAIL, 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
  init_full_download( ctx, input, &sa );
  publish_cnt = 0UL;
  serve_one( ctx, server, "GET /snapshot.tar.bz2 HTTP/1.1", "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nsnap" );
  for( int i=0; i<100; i++ ) woken_credit( ctx, &busy );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && ctx->sent_meta && ctx->fast_boot_stream.off==4UL );
  FD_TEST( ctx->request_retries==FD_SNAPLD_REQUEST_RETRY_MAX-1U && ctx->fast_boot_stream.wait!=LONG_MAX );
  ctx->fast_boot_stream.wait = 0L;

  /* The time spent reconnecting does not count as download time. */
  ctx->start_batch    = 1L;
  ctx->bytes_in_batch = 4UL;
  woken_credit( ctx, &busy );
  FD_TEST( ctx->fast_boot_stream.wait==LONG_MAX && ctx->start_batch>1L && !ctx->bytes_in_batch );
  serve_one( ctx, server, "Range: bytes=4-\r\n", "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 4-7/8\r\nContent-Length: 4\r\n\r\nshot" );
  for( int i=0; i<100000 && ctx->state==FD_SNAPSHOT_STATE_PROCESSING; i++ ) woken_credit( ctx, &busy );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING && publish_sig==FD_SNAPSHOT_MSG_LOAD_COMPLETE && ctx->fast_boot_stream.off==8UL );

  /* A fast boot stream request that never got an answer is given up
     the same way.  Once the stream answered it is asked again
     without end. */
  ctx->fast_boot_stream.active = 1;
  ctx->sent_meta               = 0;
  ctx->request_retries         = 1U;
  FD_TEST( handle_connection_failure( ctx, 0L ) && !ctx->request_retries );
  FD_TEST( !handle_connection_failure( ctx, 0L ) );
  ctx->sent_meta = 1;
  FD_TEST( handle_connection_failure( ctx, 0L ) && handle_connection_failure( ctx, 0L ) );

  fd_sshttp_cancel( http );
  FD_TEST( !close( server ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_epoll_fd = epoll_create1( 0 );
  FD_TEST( test_epoll_fd!=-1 );
  test_start( 0, 0 );
  test_start( 0, 1 );
  test_start( 1, 0 );
  test_parked();
  test_stream();
  test_stream_fail();
  test_stream_parked();
  test_request_retry();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
