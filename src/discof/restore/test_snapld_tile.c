#define _GNU_SOURCE
#include "../../disco/stem/fd_stem.h"
#include "utils/fd_sshttp_private.h"
#include "utils/fd_ssctrl.h"
#include "../../util/io/fd_io.h"

#include <netinet/in.h>
#include <sys/epoll.h>
#include <errno.h>
#include "../../ballet/base58/fd_base58.h"

static ulong publish_cnt;
static ulong publish_sig;
static ulong init_cnt;
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
                  ulong         range_start ) {
  init_cnt++;
  return fd_sshttp_init( http, addr, hostname, is_https, path, path_len, hops, now, range_start );
}

#define fd_stem_publish test_stem_publish
#define fd_sshttp_init  test_sshttp_init
#include "fd_snapld_tile.c"

static int test_epoll_fd = -1;
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
  /* Spend longer than the request deadline waiting for START. */
  fd_log_sleep( FD_SSHTTP_DEADLINE_NANOS+1000000L );
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

/* serve_one accepts the tile's next connection, drives the tile until
   its request has arrived, checks the request holds expect, answers
   with resp and closes. */
static void
serve_one( fd_snapld_tile_t * ctx,
           int                server,
           char const *       expect,
           char const *       resp ) {
  int   busy    = 0;
  int   conn    = -1;
  char  req[ 4096 ];
  ulong req_len = 0UL;
  for( ulong i=0UL; i<100000UL; i++ ) {
    after_credit( ctx, test_stem, NULL, &busy );
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
  FD_TEST( !close( conn ) );
}

/* drive_until runs the tile until *var equals val. */
static void
drive_until( fd_snapld_tile_t * ctx,
             ulong *            var,
             ulong              val ) {
  int busy = 0;
  for( ulong i=0UL; i<100000UL && *var!=val; i++ ) after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( *var==val );
}

/* A fast boot stream: the redirect names the stream, the first
   response holds what the server has, a 416 means nothing new yet
   (reported once as caught up), a 206 adds bytes and a 404 ends it. */
static void
test_stream( void ) {
  static fd_sshttp_t http[1];
  static uchar      input[ sizeof(fd_ssctrl_start_t) ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  static ulong waker_fseq[ FD_FSEQ_FOOTPRINT/sizeof(ulong) ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  fd_snapld_tile_t ctx[1] = {0};
  int busy = 0;
  ctx->sshttp        = fd_sshttp_join( fd_sshttp_new( http, test_epoll_fd ) );
  ctx->waker_fseq    = fd_fseq_join( fd_fseq_new( waker_fseq, 0UL ) );
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

  fd_ssctrl_init_t * init = (fd_ssctrl_init_t *)input;
  fd_memset( init, 0, sizeof(*init) );
  init->slot        = 0UL; /* nothing is known about the stream yet */
  init->is_redirect = 1;
  init->stream      = 1;
  init_slot   = init->slot;
  publish_cnt = init_cnt = 0UL;
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_INIT_FULL, 0UL, sizeof(*init), 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->stream.active && ctx->stream.wait==LONG_MAX );
  ulong meta_chunk = ctx->out_dc.chunk; /* META goes out next */

  fd_ssctrl_start_t * start = (fd_ssctrl_start_t *)input;
  fd_memset( start, 0, sizeof(*start) );
  start->addr = (fd_ip4_port_t){ .addr = sa.sin_addr.s_addr, .port = sa.sin_port };
  fd_cstr_ncpy( start->hostname, "localhost", sizeof(start->hostname) );
  fd_cstr_ncpy( start->path, "/fast-boot-stream.tar.zst", sizeof(start->path) );
  start->path_len = strlen( start->path );
  FD_TEST( !returnable_frag( ctx, 0UL, 0UL, FD_SNAPSHOT_MSG_CTRL_START, 0UL, sizeof(*start), 0UL, 0UL, 0UL, NULL ) );
  FD_TEST( ctx->pipeline_ready && init_cnt==1UL );

  uchar hash[ 32 ];
  fd_memset( hash, 0x5a, sizeof(hash) );
  char hash_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( hash, NULL, hash_b58 );
  char name[ 128 ];
  FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "fast-boot-stream-123-%s.tar.zst", hash_b58 ) );
  char redirect[ 256 ];
  FD_TEST( fd_cstr_printf_check( redirect, sizeof(redirect), NULL, "HTTP/1.1 302 Found\r\nLocation: /%s\r\nContent-Length: 0\r\n\r\n", name ) );
  char get[ 160 ];
  FD_TEST( fd_cstr_printf_check( get, sizeof(get), NULL, "GET /%s HTTP/1.1", name ) );

  /* No stream at the server yet: ask again later. */
  serve_one( ctx, server, "GET /fast-boot-stream.tar.zst HTTP/1.1", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" );
  drive_until( ctx, &init_cnt, 1UL );
  for( int i=0; i<100; i++ ) after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && ctx->stream.wait!=LONG_MAX && publish_cnt==1UL );
  ctx->stream.wait = 0L;

  serve_one( ctx, server, "GET /fast-boot-stream.tar.zst HTTP/1.1", redirect );
  serve_one( ctx, server, get, "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nsnapshot" );
  drive_until( ctx, &ctx->stream.off, 8UL );
  FD_TEST( ctx->sent_meta && publish_cnt==3UL && publish_sig==FD_SNAPSHOT_MSG_DATA );
  FD_TEST( http->location[ 0 ]=='/' && !strcmp( http->location+1, name ) );
  fd_ssctrl_meta_t const * meta = fd_chunk_to_laddr_const( output, meta_chunk );
  FD_TEST( meta->resolved_slot==123UL && !memcmp( meta->resolved_hash, hash, 32UL ) && !strcmp( meta->resolved_name, name ) );

  /* Nothing new yet: caught up, once. */
  serve_one( ctx, server, "Range: bytes=8-\r\n", "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n" );
  drive_until( ctx, &publish_cnt, 4UL );
  FD_TEST( ctx->stream.caught_up && publish_sig==FD_SNAPSHOT_MSG_STREAM_CAUGHT_UP );
  FD_TEST( ctx->stream.wait!=LONG_MAX );
  ctx->stream.wait = 0L;
  serve_one( ctx, server, "Range: bytes=8-\r\n", "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n" );
  for( int i=0; i<100; i++ ) after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( publish_cnt==4UL && ctx->stream.wait!=LONG_MAX );
  ctx->stream.wait = 0L;

  /* More bytes. */
  serve_one( ctx, server, "Range: bytes=8-\r\n", "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 8-11/12\r\nContent-Length: 4\r\n\r\nmore" );
  drive_until( ctx, &ctx->stream.off, 12UL );
  FD_TEST( publish_cnt==5UL && publish_sig==FD_SNAPSHOT_MSG_DATA );

  /* The stream ended. */
  serve_one( ctx, server, "Range: bytes=12-\r\n", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" );
  drive_until( ctx, &publish_cnt, 6UL );
  FD_TEST( publish_sig==FD_SNAPSHOT_MSG_LOAD_COMPLETE && ctx->state==FD_SNAPSHOT_STATE_FINISHING );

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
  test_stream();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
