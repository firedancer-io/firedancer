#define _GNU_SOURCE
#include "fd_ipecho_server.h"
#include "fd_ipecho_server_port_check.h"
#include "../../tango/tempo/fd_tempo.h"

#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_CONN_CNT  (16UL)
#define LOOPBACK      (FD_IP4_ADDR(127,0,0,1))
#define SHRED_VERSION (42)

#define PORT_CHECK_MAX_PER_IP (4UL)
#define PORT_CHECK_TIMEOUT_NS ((long)4e9)

struct request {
  ushort tcp_ports[ 4 ];
  ushort udp_ports[ 4 ];
};
typedef struct request request_t;

struct reply {
  uint   magic;
  uint   ip_variant;
  uint   address;
  uchar  shred_version_option;
  ushort shred_version;
};
typedef struct reply reply_t;

struct test_ctx {
  fd_ipecho_server_t *                          server;
  fd_ipecho_server_port_check_metrics_t const * metrics;
  int                                           epoll_fd;
  ushort                                        server_port;
  long                                          now;
  long                                          timeout_ticks;
  void *                                        mem;
};
typedef struct test_ctx test_ctx_t;

static void
advance_server( test_ctx_t * ctx ) {
  int busy = 0;
  fd_ipecho_server_epoll_poll( ctx->server, ctx->now, &busy );
  fd_ipecho_server_port_check_prune( fd_ipecho_server_port_check( ctx->server ), ctx->now );
}

static void
wait_until_readable( test_ctx_t * ctx,
                     int          fd ) {
  for(;;) {
    struct pollfd pfds[ 2 ] = { { .fd = ctx->epoll_fd, .events = POLLIN }, { .fd = fd, .events = POLLIN } };
    FD_TEST( poll( pfds, 2, -1 )>=0 );
    FD_TEST( !( pfds[ 0 ].revents & (POLLERR|POLLNVAL) ) );
    FD_TEST( !( pfds[ 1 ].revents & (POLLERR|POLLNVAL) ) );
    if( pfds[ 1 ].revents & (POLLIN|POLLHUP) ) return;
    advance_server( ctx );
  }
}

static int
bind_ephemeral_port( uint     ip,
                     int      type,
                     int      backlog,
                     ushort * port ) {
  int fd = socket( AF_INET, type|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  FD_TEST( -1!=fd );
  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = ip };
  FD_TEST( -1!=bind( fd, fd_type_pun( &addr ), sizeof(addr) ) );
  if( type==SOCK_STREAM ) FD_TEST( -1!=listen( fd, backlog ) );
  socklen_t len = sizeof(addr);
  FD_TEST( -1!=getsockname( fd, fd_type_pun( &addr ), &len ) );
  *port = fd_ushort_bswap( addr.sin_port );
  return fd;
}

static int
connect_from( uint   src_ip,
              ushort port ) {
  int fd = socket( AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0 );
  FD_TEST( -1!=fd );
  struct sockaddr_in src = { .sin_family = AF_INET, .sin_addr.s_addr = src_ip };
  FD_TEST( -1!=bind( fd, fd_type_pun( &src ), sizeof(src) ) );
  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = fd_ushort_bswap( port ), .sin_addr.s_addr = LOOPBACK };
  FD_TEST( -1!=connect( fd, fd_type_pun( &addr ), sizeof(addr) ) );
  FD_TEST( -1!=fcntl( fd, F_SETFL, fcntl( fd, F_GETFL )|O_NONBLOCK ) );
  return fd;
}

static int
listen_blackhole( ushort * port ) {
  int lfd = bind_ephemeral_port( 0U, SOCK_STREAM, 16, port );
  /* Setting an IP_MINTTL of 255 means that the kernel will discard SYNs
     with an IP TTL < 255. Loopback traffic has a default TTL of 64 so
     this has the effect of blackholing TCP connection attempts without
     requiring any capabilities. */
  int min_ttl = 255;
  FD_TEST( -1!=setsockopt( lfd, IPPROTO_IP, IP_MINTTL, &min_ttl, sizeof(min_ttl) ) );
  return lfd;
}

static int
send_request( test_ctx_t *      ctx,
              uint              src_ip,
              request_t const * request ) {
  uchar msg[ 21UL ] = { 0 };
  for( ulong i=0UL; i<4UL; i++ ) FD_STORE( ushort, msg+4UL+2UL*i,  request->tcp_ports[ i ] );
  for( ulong i=0UL; i<4UL; i++ ) FD_STORE( ushort, msg+12UL+2UL*i, request->udp_ports[ i ] );
  msg[ 20UL ] = '\n';

  int fd = connect_from( src_ip, ctx->server_port );
  FD_TEST( (long)sizeof(msg)==send( fd, msg, sizeof(msg), MSG_NOSIGNAL ) );
  return fd;
}

static void
read_n( test_ctx_t * ctx,
        int          fd,
        uchar *      buf,
        ulong        n ) {
  ulong got = 0UL;
  while( got<n ) {
    wait_until_readable( ctx, fd );
    long sz = read( fd, buf+got, n-got );
    if( -1L==sz ) { FD_TEST( errno==EAGAIN ); continue; }
    FD_TEST( sz>0L );
    got += (ulong)sz;
  }
}

static void
expect_reply( test_ctx_t *    ctx,
              int             fd,
              reply_t const * expected ) {
  uchar msg[ 27UL ];
  read_n( ctx, fd, msg, sizeof(msg) );

  reply_t reply = {
    .magic                = FD_LOAD( uint,   msg      ),
    .ip_variant           = FD_LOAD( uint,   msg+4UL  ),
    .address              = FD_LOAD( uint,   msg+8UL  ),
    .shred_version_option = msg[ 12UL ],
    .shred_version        = FD_LOAD( ushort, msg+13UL ),
  };
  FD_TEST( reply.magic               ==expected->magic                );
  FD_TEST( reply.ip_variant          ==expected->ip_variant           );
  FD_TEST( reply.address             ==expected->address              );
  FD_TEST( reply.shred_version_option==expected->shred_version_option );
  FD_TEST( reply.shred_version       ==expected->shred_version        );
  for( ulong i=15UL; i<sizeof(msg); i++ ) FD_TEST( 0==msg[ i ] );

  wait_until_readable( ctx, fd );
  uchar tmp;
  FD_TEST( 0L==read( fd, &tmp, 1UL ) );
  FD_TEST( -1!=close( fd ) );
}

static void
setup_context( test_ctx_t * ctx,
               fd_wksp_t *  wksp ) {
  memset( ctx, 0, sizeof(*ctx) );
  ctx->now           = fd_tickcount();
  ctx->timeout_ticks = (long)( (double)PORT_CHECK_TIMEOUT_NS*fd_tempo_tick_per_ns( NULL ) );

  ctx->mem = fd_wksp_alloc_laddr( wksp, fd_ipecho_server_align(), fd_ipecho_server_footprint( MAX_CONN_CNT ), 1UL );
  FD_TEST( ctx->mem );
  ctx->server = fd_ipecho_server_join( fd_ipecho_server_new( ctx->mem, MAX_CONN_CNT ) );
  FD_TEST( ctx->server );
  ctx->metrics = fd_ipecho_server_port_check_metrics( fd_ipecho_server_port_check( ctx->server ) );

  ctx->epoll_fd = epoll_create1( EPOLL_CLOEXEC );
  FD_TEST( -1!=ctx->epoll_fd );
  fd_ipecho_server_init( ctx->server, ctx->epoll_fd, LOOPBACK, 0, SHRED_VERSION );

  struct sockaddr_in bound; socklen_t bound_len = sizeof(bound);
  FD_TEST( -1!=getsockname( fd_ipecho_server_sockfd( ctx->server ), fd_type_pun( &bound ), &bound_len ) );
  ctx->server_port = fd_ushort_bswap( bound.sin_port );
}

static void
teardown_context( test_ctx_t * ctx ) {
  fd_ipecho_server_fini( ctx->server );
  FD_TEST( -1!=close( ctx->epoll_fd ) );
  fd_wksp_free_laddr( ctx->mem );
}

/* Test normal request/response with no port check requested. */
static void
test_no_port_check( fd_wksp_t * wksp ) {
  test_ctx_t ctx[ 1 ];
  setup_context( ctx, wksp );
  reply_t expected_reply = { .magic = 0U, .ip_variant = 0U, .address = LOOPBACK, .shred_version_option = 1, .shred_version = SHRED_VERSION };

  request_t request = { 0 };
  expect_reply( ctx, send_request( ctx, LOOPBACK, &request ), &expected_reply );

  teardown_context( ctx );
  FD_LOG_NOTICE(( "test_no_port_check: pass" ));
}

/* Test a port check on 4 UDP ports and 2 TCP ports, which successfully
   completes. */
static void
test_port_check_success( fd_wksp_t * wksp ) {
  test_ctx_t ctx[ 1 ];
  setup_context( ctx, wksp );
  reply_t expected_reply = { .magic = 0U, .ip_variant = 0U, .address = LOOPBACK, .shred_version_option = 1, .shred_version = SHRED_VERSION };

  request_t request = { 0 };
  int udp_fd[ 4 ]; for( ulong i=0UL; i<4UL; i++ ) udp_fd[ i ] = bind_ephemeral_port( LOOPBACK, SOCK_DGRAM,  0,  &request.udp_ports[ i ] );
  int tcp_fd[ 2 ]; for( ulong i=0UL; i<2UL; i++ ) tcp_fd[ i ] = bind_ephemeral_port( LOOPBACK, SOCK_STREAM, 16, &request.tcp_ports[ i ] );

  expect_reply( ctx, send_request( ctx, LOOPBACK, &request ), &expected_reply );

  for( ulong i=0UL; i<4UL; i++ ) {
    wait_until_readable( ctx, udp_fd[ i ] );
    uchar buf[ 8 ];
    struct sockaddr_in from; socklen_t from_len = sizeof(from);
    FD_TEST( 1L==recvfrom( udp_fd[ i ], buf, sizeof(buf), 0, fd_type_pun( &from ), &from_len ) );
    FD_TEST( from.sin_addr.s_addr==LOOPBACK );
    FD_TEST( -1!=close( udp_fd[ i ] ) );
  }

  for( ulong i=0UL; i<2UL; i++ ) {
    wait_until_readable( ctx, tcp_fd[ i ] );
    struct sockaddr_in from; socklen_t from_len = sizeof(from);
    int cfd = accept4( tcp_fd[ i ], fd_type_pun( &from ), &from_len, SOCK_NONBLOCK|SOCK_CLOEXEC );
    FD_TEST( -1!=cfd );
    FD_TEST( from.sin_addr.s_addr==LOOPBACK );

    wait_until_readable( ctx, cfd );
    uchar tmp;
    FD_TEST( 0L==read( cfd, &tmp, 1UL ) );
    FD_TEST( -1!=close( cfd ) );
    FD_TEST( -1!=close( tcp_fd[ i ] ) );
  }

  FD_TEST( ctx->metrics->tcp[ FD_IPECHO_SERVER_PORT_CHECK_TCP_CONNECTED ]==2UL );
  FD_TEST( ctx->metrics->udp_sent==4UL );
  FD_TEST( ctx->metrics->active==0UL );

  teardown_context( ctx );
  FD_LOG_NOTICE(( "test_port_check_success: pass" ));
}

/* Test port check where the TCP handshake times out. */
static void
test_port_check_timeout( fd_wksp_t * wksp ) {
  test_ctx_t ctx[ 1 ];
  setup_context( ctx, wksp );
  reply_t expected_reply = { .magic = 0U, .ip_variant = 0U, .address = LOOPBACK, .shred_version_option = 1, .shred_version = SHRED_VERSION };

  request_t request = { 0 };
  int lfd = listen_blackhole( &request.tcp_ports[ 0 ] );

  /* The reply is sent even if the port check is unsuccessful */
  expect_reply( ctx, send_request( ctx, LOOPBACK, &request ), &expected_reply );
  FD_TEST( ctx->metrics->active==1UL );

  /* Just before the timeout, check that the amount of timeout events
     is 0. */
  ctx->now += ctx->timeout_ticks-1L;
  advance_server( ctx );
  FD_TEST( ctx->metrics->tcp[ FD_IPECHO_SERVER_PORT_CHECK_TCP_TIMEOUT ]==0UL );
  FD_TEST( ctx->metrics->active==1UL );

  /* After the timeout, we should have a timeout event. */
  ctx->now += 1L;
  advance_server( ctx );
  FD_TEST( ctx->metrics->tcp[ FD_IPECHO_SERVER_PORT_CHECK_TCP_TIMEOUT ]==1UL );
  FD_TEST( ctx->metrics->active==0UL );
  FD_TEST( -1!=close( lfd ) );

  teardown_context( ctx );
  FD_LOG_NOTICE(( "test_port_check_timeout: pass" ));
}

/* Test port check where we exceed the maximum number of handshake
   attempts from the same IP (by blackholing the connections). */
static void
test_port_check_limit( fd_wksp_t * wksp ) {
  test_ctx_t ctx[ 1 ];
  setup_context( ctx, wksp );
  reply_t expected_reply = { .magic = 0U, .ip_variant = 0U, .address = LOOPBACK, .shred_version_option = 1, .shred_version = SHRED_VERSION };

  ushort port; int lfd = listen_blackhole( &port );
  request_t four = { .tcp_ports = { port, port, port, port } };
  request_t one  = { .tcp_ports = { port } };

  expect_reply( ctx, send_request( ctx, LOOPBACK, &four ), &expected_reply );
  FD_TEST( ctx->metrics->active==PORT_CHECK_MAX_PER_IP );

  expect_reply( ctx, send_request( ctx, LOOPBACK, &one ), &expected_reply );
  FD_TEST( ctx->metrics->active==PORT_CHECK_MAX_PER_IP );
  FD_TEST( ctx->metrics->tcp[ FD_IPECHO_SERVER_PORT_CHECK_TCP_REJECTED_PER_IP ]==1UL );

  uint other_ip = FD_IP4_ADDR(127,0,0,2);
  expected_reply.address = other_ip;
  expect_reply( ctx, send_request( ctx, other_ip, &one ), &expected_reply );
  FD_TEST( ctx->metrics->active==PORT_CHECK_MAX_PER_IP+1UL );
  FD_TEST( ctx->metrics->tcp[ FD_IPECHO_SERVER_PORT_CHECK_TCP_REJECTED_PER_IP ]==1UL );

  fd_ipecho_server_port_check_close_all( fd_ipecho_server_port_check( ctx->server ) );
  FD_TEST( ctx->metrics->active==0UL );
  FD_TEST( -1!=close( lfd ) );

  teardown_context( ctx );
  FD_LOG_NOTICE(( "test_port_check_limit: pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_tempo_set_tick_per_ns( 1UL, 0UL );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "normal"                                );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 256UL                                   );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( fd_log_cpu_id() ) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_no_port_check( wksp );
  test_port_check_success( wksp );
  test_port_check_timeout( wksp );
  test_port_check_limit( wksp );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
