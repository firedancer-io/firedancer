#include "fd_sshttp_private.h"

#include "../../../util/fd_util.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

extern _Bool fd_sshttp_fuzz;

static int test_epoll_fd = -1;

/* connect_pair wires an fd_sshttp_t up to one end of a socketpair, as
   if the request had just been written out, and returns the other end
   for the test to play the server on. */

static fd_sshttp_t test_http[1];

static int
connect_pair( fd_sshttp_t * http ) {
  int sv[ 2 ];
  FD_TEST( 0==socketpair( AF_UNIX, SOCK_STREAM, 0, sv ) );
  FD_TEST( -1!=fcntl( sv[ 0 ], F_SETFL, fcntl( sv[ 0 ], F_GETFL, 0 )|O_NONBLOCK ) );

  fd_cstr_ncpy( http->hostname, "localhost", sizeof(http->hostname) );
  http->is_https     = 0;
  http->hops         = 4UL;
  http->response_len = 0UL;
  http->content_len  = 0UL;
  http->content_read = 0UL;
  http->addr         = (fd_ip4_port_t){ .addr = FD_IP4_ADDR( 127, 0, 0, 1 ), .port = fd_ushort_bswap( 80 ) };
  http->sockfd       = sv[ 0 ];
  http->epoll_events = EPOLLIN|EPOLLOUT;
  struct epoll_event ev = { .events = http->epoll_events, .data.fd = sv[ 0 ] };
  FD_TEST( !epoll_ctl( http->epoll_fd, EPOLL_CTL_ADD, sv[ 0 ], &ev ) );
  http->state        = FD_SSHTTP_STATE_RESP;
  http->deadline     = LONG_MAX;

  return sv[ 1 ];
}

/* advance_until_terminal spins fd_sshttp_advance until it stops
   returning ADVANCE_AGAIN.  Deadlines are disabled, so a result other
   than ERROR or DONE within the iteration budget means the state
   machine has no way out. */

static int
advance_until_terminal( fd_sshttp_t * http ) {
  uchar buf[ 4096 ];
  struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
  for( ulong i=0UL; i<1024UL; i++ ) {
    ulong data_len   = 0UL;
    int   downloading = 0;
    int   res = fd_sshttp_advance( http, &iov, 1UL, &data_len, &downloading, 0L );
    if( FD_LIKELY( res!=FD_SSHTTP_ADVANCE_AGAIN && res!=FD_SSHTTP_ADVANCE_DATA ) ) return res;
  }
  FD_LOG_ERR(( "fd_sshttp_advance never terminated" ));
}

/* A server that closes after a complete header, without ever sending
   the body it promised, must fail the download rather than spin on the
   readable EOF socket. */

static void
test_eof_during_body( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int server = connect_pair( http );
  char const * resp = "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nhello";
  FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );
  FD_TEST( 0==shutdown( server, SHUT_WR ) );

  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==advance_until_terminal( http ) );

  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
}

/* Same, but the peer closes partway through the response headers. */

static void
test_eof_during_headers( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int server = connect_pair( http );
  char const * resp = "HTTP/1.1 200 OK\r\nContent-Len";
  FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );
  FD_TEST( 0==shutdown( server, SHUT_WR ) );

  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==advance_until_terminal( http ) );

  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
}

/* A peer that immediately closes without writing anything at all. */

static void
test_eof_immediate( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int server = connect_pair( http );
  FD_TEST( 0==shutdown( server, SHUT_WR ) );

  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==advance_until_terminal( http ) );

  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
}

/* Headers that never terminate must be rejected once they fill the
   response buffer, instead of looping on a zero sized recv. */

static void
test_headers_too_large( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int server = connect_pair( http );
  FD_TEST( -1!=fcntl( server, F_SETFL, fcntl( server, F_GETFL, 0 )|O_NONBLOCK ) );

  static uchar junk[ 65536UL ];
  memset( junk, 'a', sizeof(junk) );
  fd_memcpy( junk, "HTTP/1.1 200 OK\r\nX-Pad: ", 24UL );

  uchar buf[ 4096 ];
  struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
  ulong sent = 0UL;
  int   res  = FD_SSHTTP_ADVANCE_AGAIN;
  for( ulong i=0UL; i<4096UL; i++ ) {
    if( FD_LIKELY( sent<sizeof(junk) ) ) {
      long n = send( server, junk+sent, sizeof(junk)-sent, MSG_NOSIGNAL );
      if( FD_LIKELY( n>0L ) ) sent += (ulong)n;
      else if( FD_UNLIKELY( n<0L && errno!=EAGAIN && errno!=EINTR ) ) FD_LOG_ERR(( "send() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }

    ulong data_len    = 0UL;
    int   downloading = 0;
    res = fd_sshttp_advance( http, &iov, 1UL, &data_len, &downloading, 0L );
    if( FD_UNLIKELY( res!=FD_SSHTTP_ADVANCE_AGAIN ) ) break;
  }
  FD_TEST( res==FD_SSHTTP_ADVANCE_ERROR );

  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
}

static void
test_plaintext_host( char const * hostname,
                     char const * host_header_fmt ) {
  int listener = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( listener!=-1 );
  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_addr = { .s_addr = fd_uint_bswap( INADDR_LOOPBACK ) },
  };
  FD_TEST( !bind( listener, fd_type_pun_const( &addr ), sizeof(addr) ) );
  FD_TEST( !listen( listener, 1 ) );
  socklen_t addr_sz = sizeof(addr);
  FD_TEST( !getsockname( listener, fd_type_pun( &addr ), &addr_sz ) );

  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  fd_ip4_port_t peer = { .addr = addr.sin_addr.s_addr, .port = addr.sin_port };
  FD_TEST( !fd_sshttp_init( http, peer, hostname, 0, "/snapshot.tar.bz2", 17UL, 4UL, 0L ) );
  int server = accept( listener, NULL, NULL );
  FD_TEST( server!=-1 );
  FD_TEST( !fcntl( server, F_SETFL, fcntl( server, F_GETFL, 0 )|O_NONBLOCK ) );

  char request[4096];
  ulong request_len = 0UL;
  for( ulong i=0UL; i<1024UL; i++ ) {
    uchar buf[1];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    ulong buf_sz = 0UL;
    int downloading = 0;
    FD_TEST( FD_SSHTTP_ADVANCE_AGAIN==fd_sshttp_advance( http, &iov, 1UL, &buf_sz, &downloading, 0L ) );
    long n = recv( server, request+request_len, sizeof(request)-1UL-request_len, 0 );
    if( n>0L ) request_len += (ulong)n;
    else FD_TEST( n<0L && (errno==EAGAIN || errno==EINTR) );
    request[request_len] = '\0';
    if( strstr( request, "\r\n\r\n" ) ) break;
  }
  FD_TEST( strstr( request, "GET /snapshot.tar.bz2 HTTP/1.1\r\n" )==request );
  char host_header[ 128 ];
  FD_TEST( fd_cstr_printf_check( host_header, sizeof(host_header), NULL, host_header_fmt, fd_ushort_bswap( addr.sin_port ) ) );
  FD_TEST( strstr( request, host_header ) );
  FD_TEST( strstr( request, "\r\n\r\n" ) );
  fd_sshttp_cancel( http );
  FD_TEST( !close( server ) );
  FD_TEST( !close( listener ) );
}

/* Plays a redirect to the given Location from the server side and
   returns the advance result.  In fuzz mode the client does not
   reconnect, so the new port and the rebuilt request can be read back
   from the struct. */

static int
redirect_to( fd_sshttp_t * http,
             char const *  location ) {
  int server = connect_pair( http );
  char resp[ 1024 ];
  FD_TEST( fd_cstr_printf_check( resp, sizeof(resp), NULL, "HTTP/1.1 302 Found\r\nLocation: %s\r\n\r\n", location ) );
  FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );

  uchar buf[ 4096 ];
  struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
  ulong data_len    = 0UL;
  int   downloading = 0;
  int   res = fd_sshttp_advance( http, &iov, 1UL, &data_len, &downloading, 0L );
  FD_TEST( 0==close( server ) );
  return res;
}

static void
test_redirect_location( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );
  char const * file = "snapshot-100-11111111111111111111111111111112.tar.zst";
  char location[ 256 ];
  char request [ 256 ];
  FD_TEST( fd_cstr_printf_check( request, sizeof(request), NULL, "GET /%s HTTP/1.1\r\n", file ) );

  /* Path only: same address, new path. */
  FD_TEST( fd_cstr_printf_check( location, sizeof(location), NULL, "/%s", file ) );
  FD_TEST( FD_SSHTTP_ADVANCE_AGAIN==redirect_to( http, location ) );
  FD_TEST( http->addr.addr==FD_IP4_ADDR( 127, 0, 0, 1 ) && http->addr.port==fd_ushort_bswap( 80 ) );
  FD_TEST( strstr( http->request, request )==http->request );
  FD_TEST( !strcmp( http->snapshot_name, file ) );
  fd_sshttp_cancel( http );

  /* Full URL to the same IP on another port. */
  FD_TEST( fd_cstr_printf_check( location, sizeof(location), NULL, "http://127.0.0.1:8902/%s", file ) );
  FD_TEST( FD_SSHTTP_ADVANCE_AGAIN==redirect_to( http, location ) );
  FD_TEST( http->addr.addr==FD_IP4_ADDR( 127, 0, 0, 1 ) && http->addr.port==fd_ushort_bswap( 8902 ) );
  FD_TEST( strstr( http->request, request )==http->request );
  fd_sshttp_cancel( http );

  /* Full URL naming the host we connected to, default port.  Names
     compare without case and IPs as numbers. */
  FD_TEST( fd_cstr_printf_check( location, sizeof(location), NULL, "http://LocalHost/%s", file ) );
  FD_TEST( FD_SSHTTP_ADVANCE_AGAIN==redirect_to( http, location ) );
  FD_TEST( http->addr.addr==FD_IP4_ADDR( 127, 0, 0, 1 ) && http->addr.port==fd_ushort_bswap( 80 ) );
  fd_sshttp_cancel( http );
  FD_TEST( fd_cstr_printf_check( location, sizeof(location), NULL, "http://127.000.000.001:8902/%s", file ) );
  FD_TEST( FD_SSHTTP_ADVANCE_AGAIN==redirect_to( http, location ) );
  FD_TEST( http->addr.port==fd_ushort_bswap( 8902 ) );
  fd_sshttp_cancel( http );

  /* The rpc tile sends the generic path to the snapshot server, which
     then names the file.  That hop is followed without resolving. */
  FD_TEST( FD_SSHTTP_ADVANCE_AGAIN==redirect_to( http, "http://127.0.0.1:8902/snapshot.tar.bz2" ) );
  FD_TEST( http->addr.port==fd_ushort_bswap( 8902 ) );
  FD_TEST( strstr( http->request, "GET /snapshot.tar.bz2 HTTP/1.1\r\n" )==http->request );
  FD_TEST( !strcmp( http->snapshot_name, file ) );
  fd_sshttp_cancel( http );
  FD_TEST( FD_SSHTTP_ADVANCE_AGAIN==redirect_to( http, "/incremental-snapshot.tar.bz2" ) );
  FD_TEST( !strcmp( http->snapshot_name, file ) );
  fd_sshttp_cancel( http );

  /* Another host or a scheme change is refused. */
  FD_TEST( fd_cstr_printf_check( location, sizeof(location), NULL, "http://1.2.3.4:8902/%s", file ) );
  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==redirect_to( http, location ) );
  FD_TEST( fd_cstr_printf_check( location, sizeof(location), NULL, "http://snapshots.example.com/%s", file ) );
  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==redirect_to( http, location ) );
  FD_TEST( fd_cstr_printf_check( location, sizeof(location), NULL, "https://127.0.0.1:8902/%s", file ) );
  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==redirect_to( http, location ) );

  /* Malformed URLs are refused. */
  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==redirect_to( http, "http://127.0.0.1:8902" ) );
  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==redirect_to( http, "http://127.0.0.1:abc/snapshot-100-11111111111111111111111111111112.tar.zst" ) );
  FD_TEST( fd_cstr_printf_check( location, sizeof(location), NULL, "ftp://127.0.0.1/%s", file ) );
  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==redirect_to( http, location ) );
  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==redirect_to( http, file ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_sshttp_fuzz = 1;
  test_epoll_fd = epoll_create1( 0 );
  FD_TEST( test_epoll_fd!=-1 );

  test_plaintext_host( "snapshots.example.com", "\r\nHost: snapshots.example.com:%u\r\n\r\n" );
  test_plaintext_host( "", "\r\nHost: 127.0.0.1:%u\r\n\r\n" );
  test_eof_during_body();
  test_eof_during_headers();
  test_eof_immediate();
  test_headers_too_large();
  test_redirect_location();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
