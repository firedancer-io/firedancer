#include "fd_sshttp_private.h"

#include "../../../util/fd_util.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

extern _Bool fd_sshttp_fuzz;

/* connect_pair wires an fd_sshttp_t up to one end of a socketpair, as
   if the request had just been written out, and returns the other end
   for the test to play the server on. */

static int
connect_pair( fd_sshttp_t * http ) {
  int sv[ 2 ];
  FD_TEST( 0==socketpair( AF_UNIX, SOCK_STREAM, 0, sv ) );
  FD_TEST( -1!=fcntl( sv[ 0 ], F_SETFL, fcntl( sv[ 0 ], F_GETFL, 0 )|O_NONBLOCK ) );

  http->hostname     = "localhost";
  http->is_https     = 0;
  http->hops         = 4UL;
  http->response_len = 0UL;
  http->content_len  = 0UL;
  http->content_read = 0UL;
  http->empty_recvs  = 0UL;
  http->addr         = (fd_ip4_port_t){ .addr = 0x7F000001U, .port = fd_ushort_bswap( 80 ) };
  http->sockfd       = sv[ 0 ];
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
  fd_sshttp_t _http[1];
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( _http ) );
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
  fd_sshttp_t _http[1];
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( _http ) );
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
  fd_sshttp_t _http[1];
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( _http ) );
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
  fd_sshttp_t _http[1];
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( _http ) );
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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_sshttp_fuzz = 1;

  test_eof_during_body();
  test_eof_during_headers();
  test_eof_immediate();
  test_headers_too_large();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
