#include "fd_sshttp_private.h"

#include "../../../util/fd_util.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/epoll.h>
#include <netinet/in.h>
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
  http->range_start  = 0UL;
  http->addr         = (fd_ip4_port_t){ .addr = 0x7F000001U, .port = fd_ushort_bswap( 80 ) };
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
  for( ulong i=0UL; i<1024UL; i++ ) {
    ulong data_len   = sizeof(buf);
    int   downloading = 0;
    int   res = fd_sshttp_advance( http, &data_len, buf, &downloading, 0L );
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
  ulong sent = 0UL;
  int   res  = FD_SSHTTP_ADVANCE_AGAIN;
  for( ulong i=0UL; i<4096UL; i++ ) {
    if( FD_LIKELY( sent<sizeof(junk) ) ) {
      long n = send( server, junk+sent, sizeof(junk)-sent, MSG_NOSIGNAL );
      if( FD_LIKELY( n>0L ) ) sent += (ulong)n;
      else if( FD_UNLIKELY( n<0L && errno!=EAGAIN && errno!=EINTR ) ) FD_LOG_ERR(( "send() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }

    ulong data_len    = sizeof(buf);
    int   downloading = 0;
    res = fd_sshttp_advance( http, &data_len, buf, &downloading, 0L );
    if( FD_UNLIKELY( res!=FD_SSHTTP_ADVANCE_AGAIN ) ) break;
  }
  FD_TEST( res==FD_SSHTTP_ADVANCE_ERROR );

  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
}

/* run_request drives the state machine to a terminal result, copying
   any body bytes into body.  Returns the terminal result and leaves
   the last reported data length in *last_len. */

static int
run_request( fd_sshttp_t * http,
             uchar *       body,
             ulong         body_max,
             ulong *       body_len,
             ulong *       last_len ) {
  uchar buf[ 4096 ];
  *body_len = 0UL;
  for( ulong i=0UL; i<1024UL; i++ ) {
    ulong data_len    = sizeof(buf);
    int   downloading = 0;
    int   res = fd_sshttp_advance( http, &data_len, buf, &downloading, 0L );
    *last_len = data_len;
    if( FD_LIKELY( res==FD_SSHTTP_ADVANCE_DATA ) ) {
      FD_TEST( *body_len+data_len<=body_max );
      fd_memcpy( body+*body_len, buf, data_len );
      *body_len += data_len;
      continue;
    }
    if( FD_LIKELY( res==FD_SSHTTP_ADVANCE_AGAIN ) ) continue;
    return res;
  }
  FD_LOG_ERR(( "fd_sshttp_advance never terminated" ));
}

/* A ranged request answered with 206 delivers the partial body. */

static void
test_range_partial( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int server = connect_pair( http );
  http->range_start = 10UL;
  char const * resp = "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 10-14/15\r\nContent-Length: 5\r\n\r\nhello";
  FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );

  uchar body[ 16 ];
  ulong body_len, last_len;
  FD_TEST( FD_SSHTTP_ADVANCE_DONE==run_request( http, body, sizeof(body), &body_len, &last_len ) );
  FD_TEST( body_len==5UL && !memcmp( body, "hello", 5UL ) );

  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
}

/* A 200 to a ranged request means the server ignored the range and is
   about to resend the whole file. */

static void
test_range_ignored( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int server = connect_pair( http );
  http->range_start = 10UL;
  char const * resp = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
  FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );

  uchar body[ 16 ];
  ulong body_len, last_len;
  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==run_request( http, body, sizeof(body), &body_len, &last_len ) );

  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
}

/* A 206 to an unranged request is equally wrong. */

static void
test_partial_unranged( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int server = connect_pair( http );
  char const * resp = "HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\n\r\nhello";
  FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );

  uchar body[ 16 ];
  ulong body_len, last_len;
  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==run_request( http, body, sizeof(body), &body_len, &last_len ) );

  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
}

/* 416 means the tail the caller asked for does not exist yet, so the
   request finishes with no bytes and the caller can ask again. */

static void
test_range_not_satisfiable( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int server = connect_pair( http );
  http->range_start = 10UL;
  char const * resp = "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n";
  FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );

  uchar body[ 16 ];
  ulong body_len, last_len;
  FD_TEST( FD_SSHTTP_ADVANCE_DONE==run_request( http, body, sizeof(body), &body_len, &last_len ) );
  FD_TEST( !body_len && !last_len );
  FD_TEST( http->state==FD_SSHTTP_STATE_INIT );

  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
}

/* fd_sshttp_init puts the range in the request only when asked. */

static void
test_range_request( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int listen_fd = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( listen_fd>=0 );
  struct sockaddr_in sa = {
    .sin_family = AF_INET,
    .sin_addr   = { .s_addr = htonl( INADDR_LOOPBACK ) }
  };
  FD_TEST( !bind( listen_fd, fd_type_pun( &sa ), sizeof(sa) ) );
  socklen_t sa_sz = sizeof(sa);
  FD_TEST( !getsockname( listen_fd, fd_type_pun( &sa ), &sa_sz ) );
  FD_TEST( !listen( listen_fd, 1 ) );
  fd_ip4_port_t addr = { .addr = sa.sin_addr.s_addr, .port = sa.sin_port };

  FD_TEST( !fd_sshttp_init( http, addr, "localhost", 0, "/boot/7.tar.zst", 15UL, 4UL, 0L, 0UL ) );
  FD_TEST( strstr( http->request, "GET /boot/7.tar.zst HTTP/1.1" ) );
  FD_TEST( !strstr( http->request, "Range:" ) );
  fd_sshttp_cancel( http );

  FD_TEST( !fd_sshttp_init( http, addr, "localhost", 0, "/boot/7.tar.zst", 15UL, 4UL, 0L, 4096UL ) );
  FD_TEST( strstr( http->request, "Range: bytes=4096-\r\n" ) );
  fd_sshttp_cancel( http );

  FD_TEST( !close( listen_fd ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_sshttp_fuzz = 1;
  test_epoll_fd = epoll_create1( 0 );
  FD_TEST( test_epoll_fd!=-1 );

  test_eof_during_body();
  test_eof_during_headers();
  test_eof_immediate();
  test_headers_too_large();
  test_range_partial();
  test_range_ignored();
  test_partial_unranged();
  test_range_not_satisfiable();
  test_range_request();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
