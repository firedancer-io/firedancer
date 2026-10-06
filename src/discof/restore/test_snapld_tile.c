#define _GNU_SOURCE
#include "../../disco/stem/fd_stem.h"
#include "utils/fd_sshttp_private.h"
#include "utils/fd_ssctrl.h"
#include "../../util/io/fd_io.h"
#include "../../ballet/base58/fd_base58.h"

#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/wait.h>

static ulong publish_cnt;
static ulong publish_sig;
static ulong init_cnt;
static ulong init_range;
static ulong expect_init_slot = 123UL;
static ulong init_full_cnt;
static ulong meta_cnt;
static ulong meta_total_sz;
static ulong meta_slot;
static uchar meta_hash[ FD_HASH_FOOTPRINT ];
static ulong data_sz_total;
static uchar init_hash[ FD_HASH_FOOTPRINT ];
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
    FD_TEST( init->slot==expect_init_slot );
    fd_memcpy( init_hash, init->snapshot_hash, FD_HASH_FOOTPRINT );
    init_full_cnt++;
  } else if( sig==FD_SNAPSHOT_MSG_META ) {
    FD_TEST( sz==sizeof(fd_ssctrl_meta_t) );
    fd_ssctrl_meta_t const * meta = fd_chunk_to_laddr_const( output, chunk );
    meta_total_sz = meta->total_sz;
    meta_slot     = meta->resolved_slot;
    fd_memcpy( meta_hash, meta->resolved_hash, FD_HASH_FOOTPRINT );
    meta_cnt++;
  } else if( sig==FD_SNAPSHOT_MSG_DATA ) {
    data_sz_total += sz;
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
  init_range = range_start;
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

/* stream_listen opens a loopback server for the stream downloader to
   talk to and returns its listening socket. */

static int
stream_listen( fd_ip4_port_t * addr ) {
  int listen_fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  FD_TEST( listen_fd>=0 );
  struct sockaddr_in sa = {
    .sin_family = AF_INET,
    .sin_addr   = { .s_addr = htonl( INADDR_LOOPBACK ) }
  };
  FD_TEST( !bind( listen_fd, fd_type_pun( &sa ), sizeof(sa) ) );
  socklen_t sa_sz = sizeof(sa);
  FD_TEST( !getsockname( listen_fd, fd_type_pun( &sa ), &sa_sz ) );
  FD_TEST( !listen( listen_fd, 4 ) );
  addr->addr = sa.sin_addr.s_addr;
  addr->port = sa.sin_port;
  return listen_fd;
}

/* stream_exchange drives the tile until it has opened a connection and
   sent a request, answers it with resp, and then drives the tile
   another drive times so it can consume the answer.  The request text
   is left in req. */

static void
stream_exchange( fd_snapld_tile_t * ctx,
                 int                listen_fd,
                 char *             req,
                 ulong              req_max,
                 char const *       resp,
                 ulong              resp_len,
                 ulong              drive ) {
  int   busy    = 0;
  int   conn    = -1;
  ulong req_len = 0UL;
  ulong sent    = 0UL;
  ulong i;
  for( i=0UL; i<1000000UL; i++ ) {
    after_credit( ctx, test_stem, NULL, &busy );
    if( conn<0 ) {
      conn = accept4( listen_fd, NULL, NULL, SOCK_NONBLOCK );
      continue;
    }
    if( !strstr( req, "\r\n\r\n" ) ) {
      long n = recv( conn, req+req_len, req_max-1UL-req_len, 0 );
      if( n>0L ) {
        req_len += (ulong)n;
        req[ req_len ] = '\0';
      }
      continue;
    }
    if( sent<resp_len ) {
      long n = send( conn, resp+sent, resp_len-sent, MSG_NOSIGNAL );
      if( n>0L ) sent += (ulong)n;
      continue;
    }
    break;
  }
  if( FD_UNLIKELY( i==1000000UL ) ) FD_LOG_ERR(( "stream tile never completed the exchange" ));
  for( i=0UL; i<drive; i++ ) after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( !close( conn ) );
}

static void
test_stream( void ) {
  static fd_sshttp_t http[1];
  static ulong waker_fseq[ FD_FSEQ_FOOTPRINT/sizeof(ulong) ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  static ulong done_fseq[ FD_FSEQ_FOOTPRINT/sizeof(ulong) ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  static ulong pick_fseq[ FD_FSEQ_FOOTPRINT/sizeof(ulong) ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  fd_snapld_tile_t ctx[1] = {0};
  ctx->sshttp          = fd_sshttp_join( fd_sshttp_new( http, test_epoll_fd ) );
  ctx->waker_fseq      = fd_fseq_join( fd_fseq_new( waker_fseq, 0UL ) );
  ctx->done_fseq       = fd_fseq_join( fd_fseq_new( done_fseq, 0UL ) );
  ctx->pick_fseq       = fd_fseq_join( fd_fseq_new( pick_fseq, ULONG_MAX ) );
  fd_clock_tile_init( ctx->clock );
  ctx->out_dc.mem      = (fd_wksp_t *)output;
  ctx->out_dc.mtu      = FD_SNAPSHOT_DATA_MTU;
  ctx->out_dc.wmark    = 2UL*FD_SNAPSHOT_DATA_MTU/FD_CHUNK_SZ;
  ctx->local_full_fd   = -1;
  ctx->local_incr_fd   = -1;
  ctx->state           = FD_SNAPSHOT_STATE_PROCESSING;
  ctx->pipeline_ready  = 1;
  ctx->load_full       = 1;
  ctx->stream          = 1;
  ctx->stream_retry_at = 0L; /* the index request is due right away */
  ctx->stream_slot     = ULONG_MAX;
  ctx->stream_index_deadline = LONG_MAX;
  ctx->window_deadline = LONG_MAX;

  fd_ip4_port_t addr;
  int listen_fd = stream_listen( &addr );
  FD_TEST( fd_cstr_printf_check( ctx->config.stream_server, sizeof(ctx->config.stream_server), NULL,
                                 FD_IP4_ADDR_FMT ":%hu", FD_IP4_ADDR_FMT_ARGS( addr.addr ), fd_ushort_bswap( addr.port ) ) );
  fd_ssboot_server_parse( ctx->config.stream_server, ctx->stream_hostname, &ctx->stream_addr );

  uchar hash[ FD_HASH_FOOTPRINT ];
  for( ulong i=0UL; i<FD_HASH_FOOTPRINT; i++ ) hash[ i ] = (uchar)(i+1UL);
  char hash_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( hash, NULL, hash_b58 );

  /* The newest stream in the index expires too soon to be worth
     joining, so the tile takes the one below it. */
  long  now_unix = fd_clock_tile_now( ctx->clock )/(long)1e9;
  char  index[ 256 ];
  ulong index_len;
  FD_TEST( fd_cstr_printf_check( index, sizeof(index), &index_len, "888 %s %ld\n777 %s %ld\n",
                                 hash_b58, now_unix+60L, hash_b58, now_unix+600L ) );
  char  index_resp[ 512 ];
  ulong index_resp_len;
  FD_TEST( fd_cstr_printf_check( index_resp, sizeof(index_resp), &index_resp_len,
                                 "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n%s", index_len, index ) );

  /* A serving validator with no stream open answers 404, which is
     "not yet", not a reason to die. */
  char const * absent_resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
  char req0[ 1024 ] = {0};
  stream_exchange( ctx, listen_fd, req0, sizeof(req0), absent_resp, strlen( absent_resp ), 8UL );
  FD_TEST( strstr( req0, "GET /boot/index HTTP/1.1" ) );
  FD_TEST( !ctx->stream_index_done && ctx->stream_slot==ULONG_MAX );
  FD_TEST( fd_fseq_query( ctx->pick_fseq )==ULONG_MAX );
  FD_TEST( ctx->stream_retry_at!=LONG_MAX && ctx->stream_index_deadline!=LONG_MAX );

  /* An index whose only stream closes too soon to be worth joining is
     the same answer. */
  char  stale[ 128 ];
  ulong stale_len;
  FD_TEST( fd_cstr_printf_check( stale, sizeof(stale), &stale_len, "888 %s %ld\n", hash_b58, now_unix+60L ) );
  char  stale_resp[ 256 ];
  ulong stale_resp_len;
  FD_TEST( fd_cstr_printf_check( stale_resp, sizeof(stale_resp), &stale_resp_len,
                                 "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n%s", stale_len, stale ) );
  ctx->stream_retry_at = 0L; /* skip the two second wait */
  char req1[ 1024 ] = {0};
  stream_exchange( ctx, listen_fd, req1, sizeof(req1), stale_resp, stale_resp_len, 8UL );
  FD_TEST( strstr( req1, "GET /boot/index HTTP/1.1" ) );
  FD_TEST( !ctx->stream_index_done && !ctx->stream_index_len );
  FD_TEST( fd_fseq_query( ctx->pick_fseq )==ULONG_MAX );
  FD_TEST( ctx->stream_retry_at!=LONG_MAX );

  publish_cnt = init_cnt = init_full_cnt = meta_cnt = data_sz_total = 0UL;
  expect_init_slot = 777UL;
  ctx->stream_retry_at = 0L; /* skip the two second wait */

  char req[ 1024 ] = {0};
  stream_exchange( ctx, listen_fd, req, sizeof(req), index_resp, index_resp_len, 64UL );
  FD_TEST( strstr( req, "GET /boot/index HTTP/1.1" ) );
  FD_TEST( !strstr( req, "Range:" ) );
  FD_TEST( init_full_cnt==1UL && publish_cnt==1UL && !data_sz_total );
  FD_TEST( !memcmp( init_hash, hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( ctx->stream_slot==777UL );
  FD_TEST( fd_fseq_query( ctx->pick_fseq )==777UL );
  FD_TEST( init_cnt==2UL && !init_range );

  /* The archive request streams META once and then the body. */
  char  arch_resp[ 4096 ];
  ulong arch_hdr_len;
  FD_TEST( fd_cstr_printf_check( arch_resp, sizeof(arch_resp), &arch_hdr_len,
                                 "HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n" ) );
  fd_memset( arch_resp+arch_hdr_len, 0x5a, 2000UL );

  char req2[ 1024 ] = {0};
  stream_exchange( ctx, listen_fd, req2, sizeof(req2), arch_resp, arch_hdr_len+2000UL, 64UL );
  FD_TEST( strstr( req2, "GET /boot/777.tar.zst HTTP/1.1" ) );
  FD_TEST( !strstr( req2, "Range:" ) );
  /* INIT carried the slot and hash of the index line this tile picked,
     so META has nothing to resolve. */
  FD_TEST( meta_cnt==1UL && meta_total_sz==2000UL && meta_slot==ULONG_MAX );
  uchar zero_hash[ FD_HASH_FOOTPRINT ] = {0};
  FD_TEST( !memcmp( meta_hash, zero_hash, FD_HASH_FOOTPRINT ) );
  FD_TEST( data_sz_total==2000UL );
  FD_TEST( ctx->stream_received==2000UL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && init_cnt==2UL );

  /* The tail is requested again with a range once the delay passes,
     and the body it answers with continues where the last one
     stopped. */
  char  tail_resp[ 1024 ];
  ulong tail_hdr_len;
  FD_TEST( fd_cstr_printf_check( tail_resp, sizeof(tail_resp), &tail_hdr_len,
                                 "HTTP/1.1 206 Partial Content\r\n"
                                 "Content-Range: bytes 2000-2499/2500\r\n"
                                 "Content-Length: 500\r\n\r\n" ) );
  fd_memset( tail_resp+tail_hdr_len, 0xa5, 500UL );

  fd_log_sleep( FD_SNAPLD_STREAM_RETRY_NANOS+(long)1e6 );
  char req3[ 1024 ] = {0};
  stream_exchange( ctx, listen_fd, req3, sizeof(req3), tail_resp, tail_hdr_len+500UL, 64UL );
  FD_TEST( strstr( req3, "GET /boot/777.tar.zst HTTP/1.1" ) );
  FD_TEST( strstr( req3, "Range: bytes=2000-\r\n" ) );
  FD_TEST( init_cnt==3UL && init_range==2000UL );
  FD_TEST( meta_cnt==1UL && data_sz_total==2500UL );
  FD_TEST( ctx->stream_received==2500UL );

  /* Nothing new to read yet leaves the tile where it was. */
  char const * empty_resp = "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n";
  fd_log_sleep( FD_SNAPLD_STREAM_RETRY_NANOS+(long)1e6 );
  char req4[ 1024 ] = {0};
  stream_exchange( ctx, listen_fd, req4, sizeof(req4), empty_resp, strlen( empty_resp ), 64UL );
  FD_TEST( strstr( req4, "Range: bytes=2500-\r\n" ) );
  FD_TEST( init_cnt==4UL && init_range==2500UL );
  FD_TEST( meta_cnt==1UL && data_sz_total==2500UL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );

  /* A broken answer during the tail is retried, not fatal. */
  char const * broken_resp = "HTTP/1.1 500 Oops\r\nContent-Length: 3\r\n\r\nbad";
  fd_log_sleep( FD_SNAPLD_STREAM_RETRY_NANOS+(long)1e6 );
  char req5[ 1024 ] = {0};
  stream_exchange( ctx, listen_fd, req5, sizeof(req5), broken_resp, strlen( broken_resp ), 64UL );
  FD_TEST( init_cnt==5UL && init_range==2500UL );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING && ctx->stream_retry_at!=LONG_MAX );
  FD_TEST( meta_cnt==1UL && data_sz_total==2500UL );

  /* The tile leaves as soon as the background snapshot load is done,
     without asking for more of the stream, and tells the decompressor
     downstream to stop as well: nothing else in the stream pipeline
     ends it. */
  fd_fseq_update( ctx->done_fseq, 1UL );
  publish_cnt = 0UL;
  int busy = 0;
  after_credit( ctx, test_stem, NULL, &busy );
  FD_TEST( init_cnt==5UL );
  FD_TEST( publish_cnt==1UL && publish_sig==FD_SNAPSHOT_MSG_CTRL_SHUTDOWN );
  FD_TEST( should_shutdown( ctx ) );

  /* A request already in flight when the load finished fails without
     killing the process: the tile just stops asking. */
  ctx->state           = FD_SNAPSHOT_STATE_PROCESSING;
  ctx->stream_retry_at = 0L;
  stream_retry( ctx, "in flight when the load finished" );
  FD_TEST( ctx->stream_retry_at==LONG_MAX );
  FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING );

  /* A server that never offers a stream is fatal once the wait is
     over. */
  fd_fseq_update( ctx->done_fseq, 0UL );
  ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    fd_log_level_logfile_set( 6 );
    fd_log_level_stderr_set( 6 );
    ctx->stream_index_deadline = fd_clock_tile_now( ctx->clock )-1L;
    stream_index_retry( ctx );
    _exit( 0 );
  }
  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) );
  FD_TEST( WEXITSTATUS( status )==1 );

  FD_TEST( !close( listen_fd ) );
}

/* A malformed boot index line is rejected rather than used. */

static void
test_stream_bad_index( void ) {
  uchar hash[ FD_HASH_FOOTPRINT ];
  ulong slot;
  long  expires;
  char  line[ 64 ];

  /* The hash is not base58. */
  fd_cstr_ncpy( line, "777 0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl 99", sizeof(line) );
  FD_TEST( -1==stream_parse_line( line, &slot, hash, &expires ) );

  /* The hash is too short for 32 bytes. */
  fd_cstr_ncpy( line, "777 abc 99", sizeof(line) );
  FD_TEST( -1==stream_parse_line( line, &slot, hash, &expires ) );

  /* No slot. */
  fd_cstr_ncpy( line, "x 11111111111111111111111111111111 99", sizeof(line) );
  FD_TEST( -1==stream_parse_line( line, &slot, hash, &expires ) );

  /* No expiry. */
  fd_cstr_ncpy( line, "777 11111111111111111111111111111111", sizeof(line) );
  FD_TEST( -1==stream_parse_line( line, &slot, hash, &expires ) );

  /* A whole line still parses. */
  fd_cstr_ncpy( line, "777 11111111111111111111111111111111 99", sizeof(line) );
  FD_TEST( !stream_parse_line( line, &slot, hash, &expires ) );
  FD_TEST( slot==777UL && expires==99L );
  uchar zero[ FD_HASH_FOOTPRINT ] = {0};
  FD_TEST( !memcmp( hash, zero, FD_HASH_FOOTPRINT ) );
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
  test_stream_bad_index();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
