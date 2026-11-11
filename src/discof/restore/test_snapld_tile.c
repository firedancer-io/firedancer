#define _GNU_SOURCE
#include "../../disco/stem/fd_stem.h"
#include "utils/fd_sshttp_private.h"
#include "utils/fd_ssctrl.h"
#include "../../util/io/fd_io.h"

#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>

static ulong publish_cnt;
static ulong publish_sig;
static ulong init_cnt;
static ulong rearm_cnt;
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
    FD_TEST( init->slot==123UL );
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
                  long          now ) {
  init_cnt++;
  return fd_sshttp_init( http, addr, hostname, is_https, path, path_len, hops, now );
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
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
