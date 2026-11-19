#include "fd_sshttp_private.h"
#include "../../../ballet/base58/fd_base58.h"

#include "../../../util/fd_util.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/sockios.h>

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
run_request( fd_sshttp_t * http,
             uchar *       body,
             ulong         body_max,
             ulong *       body_len,
             ulong *       last_len );

static int
advance_until_terminal( fd_sshttp_t * http ) {
  static uchar body[ 1UL<<16 ];
  ulong body_len, last_len;
  return run_request( http, body, sizeof(body), &body_len, &last_len );
}

/* A 200 with an empty body has nothing to load: an error, which is
   what keeps the loader's "response complete" from ever running before
   its first data. */

static void
test_empty_body( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int server = connect_pair( http );
  char const * resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
  FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );
  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==advance_until_terminal( http ) );

  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
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
  FD_TEST( !fd_sshttp_init( http, peer, hostname, 0, "/snapshot.tar.bz2", 17UL, 4UL, 0L, 0UL, 0 ) );
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

static int
sock_opt( int fd,
          int opt ) {
  int       val    = 0;
  socklen_t val_sz = sizeof(int);
  FD_TEST( !getsockopt( fd, SOL_SOCKET, opt, &val, &val_sz ) );
  return val;
}

/* A plaintext body socket turns readable only once
   FD_SSHTTP_SO_RCVLOWAT body bytes are queued.  The mark must drop to
   what is left of the body, or a tail shorter than it never wakes the
   caller and the download stalls on a connection the server keeps
   open. */

static void
test_body_tail_wakes( void ) {
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

  /* A private epoll set, so that only this socket can be ready */
  int epoll_fd = epoll_create1( 0 );
  FD_TEST( epoll_fd!=-1 );
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, epoll_fd ) );
  fd_ip4_port_t peer = { .addr = addr.sin_addr.s_addr, .port = addr.sin_port };
  FD_TEST( !fd_sshttp_init( http, peer, "", 0, "/snapshot.tar.zst", 17UL, 4UL, 0L, 0UL, 0 ) );
  int server = accept( listener, NULL, NULL );
  FD_TEST( server!=-1 );
  FD_TEST( !fcntl( server, F_SETFL, fcntl( server, F_GETFL, 0 )|O_NONBLOCK ) );

  static uchar buf[ 1UL<<16 ];
  struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
  ulong data_len    = 0UL;
  int   downloading = 0;

  char  request[ 4096 ] = {0};
  ulong request_len = 0UL;
  for( ulong i=0UL; !strstr( request, "\r\n\r\n" ); i++ ) {
    FD_TEST( i<1024UL );
    FD_TEST( FD_SSHTTP_ADVANCE_AGAIN==fd_sshttp_advance( http, &iov, 1UL, &data_len, &downloading, 0L ) );
    long n = recv( server, request+request_len, sizeof(request)-1UL-request_len, 0 );
    if( n>0L ) request_len += (ulong)n;
    else FD_TEST( n<0L && (errno==EAGAIN || errno==EINTR) );
    request[ request_len ] = '\0';
  }

  ulong const tail_sz = 1000UL;
  ulong const body_sz = FD_SSHTTP_SO_RCVLOWAT+tail_sz;
  static uchar body[ 2UL*FD_SSHTTP_SO_RCVLOWAT ];
  FD_TEST( body_sz<=sizeof(body) );
  char hdr[ 128 ];
  ulong hdr_len;
  FD_TEST( fd_cstr_printf_check( hdr, sizeof(hdr), &hdr_len, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n", body_sz ) );
  FD_TEST( (long)hdr_len==send( server, hdr, hdr_len, 0 ) );

  /* The headers set the full low-water mark, which the kernel caps at
     half the receive buffer */
  for( ulong i=0UL; http->state!=FD_SSHTTP_STATE_DL; i++ ) {
    FD_TEST( i<1000000UL );
    FD_TEST( FD_SSHTTP_ADVANCE_AGAIN==fd_sshttp_advance( http, &iov, 1UL, &data_len, &downloading, 0L ) );
  }
  ulong rcvbuf = (ulong)sock_opt( http->sockfd, SO_RCVBUF );
  FD_TEST( (ulong)sock_opt( http->sockfd, SO_RCVLOWAT )==fd_ulong_min( FD_SSHTTP_SO_RCVLOWAT, rcvbuf/2UL ) );

  /* Everything but the tail, then drain until the socket is empty */
  ulong sent = 0UL;
  ulong got  = 0UL;
  for( ulong i=0UL; got<body_sz-tail_sz; i++ ) {
    FD_TEST( i<1000000UL );
    if( sent<body_sz-tail_sz ) {
      long n = send( server, body+sent, body_sz-tail_sz-sent, 0 );
      if( n>0L ) sent += (ulong)n;
      else FD_TEST( n<0L && errno==EAGAIN );
    }
    int res = fd_sshttp_advance( http, &iov, 1UL, &data_len, &downloading, 0L );
    FD_TEST( res==FD_SSHTTP_ADVANCE_AGAIN || res==FD_SSHTTP_ADVANCE_DATA );
    if( res==FD_SSHTTP_ADVANCE_DATA ) got += data_len;
  }
  FD_TEST( FD_SSHTTP_ADVANCE_AGAIN==fd_sshttp_advance( http, &iov, 1UL, &data_len, &downloading, 0L ) );
  FD_TEST( fd_sshttp_rx_parked( http ) );
  FD_TEST( (ulong)sock_opt( http->sockfd, SO_RCVLOWAT )==tail_sz );

  /* Short of the tail, the socket stays unreadable even with the bytes
     queued */
  FD_TEST( (long)(tail_sz-1UL)==send( server, body+sent, tail_sz-1UL, 0 ) );
  for( ulong i=0UL;; i++ ) {
    int queued = 0;
    FD_TEST( !ioctl( http->sockfd, SIOCINQ, &queued ) );
    if( (ulong)queued==tail_sz-1UL ) break;
    FD_TEST( i<5000UL );
    fd_log_sleep( (long)1e6 );
  }
  struct epoll_event ev;
  FD_TEST( 0==epoll_wait( epoll_fd, &ev, 1, 0 ) );

  /* The tail is shorter than FD_SSHTTP_SO_RCVLOWAT and must still wake */
  FD_TEST( 1L==send( server, body+sent+tail_sz-1UL, 1UL, 0 ) );
  FD_TEST( 1==epoll_wait( epoll_fd, &ev, 1, 5000 ) );
  FD_TEST( ev.data.fd==http->sockfd && (ev.events & EPOLLIN) );

  int res;
  for( ulong i=0UL; (res=fd_sshttp_advance( http, &iov, 1UL, &data_len, &downloading, 0L ))!=FD_SSHTTP_ADVANCE_DONE; i++ ) {
    FD_TEST( i<1024UL && res==FD_SSHTTP_ADVANCE_DATA );
    got += data_len;
  }
  FD_TEST( got==body_sz );

  FD_TEST( !close( server ) );
  FD_TEST( !close( listener ) );
  FD_TEST( !close( epoll_fd ) );
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
  struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
  *body_len = 0UL;
  for( ulong i=0UL; i<1024UL; i++ ) {
    ulong data_len    = 0UL;
    int   downloading = 0;
    int   res = fd_sshttp_advance( http, &iov, 1UL, &data_len, &downloading, 0L );
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

/* A ranged request answered with 206 delivers the partial body and
   ends the request: DONE for a file, STREAM_CHUNK for a stream. */

static void
test_range_partial( void ) {
  for( int stream=0; stream<=1; stream++ ) {
    fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
    FD_TEST( http );

    int server = connect_pair( http );
    http->range_start = 10UL;
    http->is_stream   = stream;
    char const * resp = "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 10-14/15\r\nContent-Length: 5\r\n\r\nhello";
    FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );

    uchar body[ 16 ];
    ulong body_len, last_len;
    int   res = run_request( http, body, sizeof(body), &body_len, &last_len );
    FD_TEST( res==( stream ? FD_SSHTTP_ADVANCE_STREAM_CHUNK : FD_SSHTTP_ADVANCE_DONE ) );
    FD_TEST( body_len==5UL && !memcmp( body, "hello", 5UL ) );

    FD_TEST( 0==close( server ) );
    fd_sshttp_cancel( http );
  }
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

/* A 206 that resumes somewhere other than where the request asked is
   not usable. */

static void
test_range_mismatch( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int server = connect_pair( http );
  http->range_start = 10UL;
  char const * resp = "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-14/15\r\nContent-Length: 5\r\n\r\nhello";
  FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );

  uchar body[ 16 ];
  ulong body_len, last_len;
  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==run_request( http, body, sizeof(body), &body_len, &last_len ) );

  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
}

/* A 206 with no Content-Range at all is equally unusable. */

static void
test_range_missing( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int server = connect_pair( http );
  http->range_start = 10UL;
  char const * resp = "HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\n\r\nhello";
  FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );

  uchar body[ 16 ];
  ulong body_len, last_len;
  FD_TEST( FD_SSHTTP_ADVANCE_ERROR==run_request( http, body, sizeof(body), &body_len, &last_len ) );

  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
}

/* 416 to a stream poll means the tail does not exist yet: the poll
   finishes idle, with no bytes, and the caller asks again.  A file
   request never asks for a tail that may not exist, so a 416 is an
   error there. */

static void
test_range_not_satisfiable( void ) {
  for( int stream=0; stream<=1; stream++ ) {
    fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
    FD_TEST( http );

    int server = connect_pair( http );
    http->range_start = 10UL;
    http->is_stream   = stream;
    char const * resp = "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n";
    FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );

    uchar body[ 16 ];
    ulong body_len, last_len;
    int   res = run_request( http, body, sizeof(body), &body_len, &last_len );
    FD_TEST( res==( stream ? FD_SSHTTP_ADVANCE_STREAM_IDLE : FD_SSHTTP_ADVANCE_ERROR ) );
    FD_TEST( !body_len );
    if( stream ) FD_TEST( !last_len );
    FD_TEST( http->state==FD_SSHTTP_STATE_INIT );

    FD_TEST( 0==close( server ) );
    fd_sshttp_cancel( http );
  }
}

/* A redirect to a fast boot stream name resolves its slot and hash.
   Another file is read from its start whatever the offset asked for,
   the same file goes on from it. */

static void
test_redirect_stream_name( void ) {
  fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
  FD_TEST( http );

  int server = connect_pair( http );
  http->range_start = 4096UL;

  uchar hash[ 32 ];
  for( ulong i=0UL; i<32UL; i++ ) hash[ i ] = (uchar)(i+1UL);
  char hash_b58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( hash, NULL, hash_b58 );
  char redirect[ 256 ];
  FD_TEST( fd_cstr_printf_check( redirect, sizeof(redirect), NULL,
           "HTTP/1.1 302 Found\r\nLocation: /fast-boot-stream-123-%s.tar.zst\r\nContent-Length: 0\r\n\r\n", hash_b58 ) );
  FD_TEST( (long)strlen( redirect )==send( server, redirect, strlen( redirect ), 0 ) );

  /* In fuzz mode the redirect is followed on the same connection. */
  ulong data_len = 0UL;
  int   downloading;
  uchar buf[ 16 ];
  struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
  for( ulong i=0UL; i<1024UL && http->hops==4UL; i++ ) {
    data_len = 0UL;
    FD_TEST( FD_SSHTTP_ADVANCE_AGAIN==fd_sshttp_advance( http, &iov, 1UL, &data_len, &downloading, 0L ) );
  }
  FD_TEST( http->hops==3UL && http->range_start==0UL );
  char name[ 128 ];
  FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "fast-boot-stream-123-%s.tar.zst", hash_b58 ) );
  FD_TEST( http->resolved_slot==123UL && !memcmp( http->resolved_hash, hash, 32UL ) && !strcmp( http->snapshot_name, name ) );

  char const * resp = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
  FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );
  uchar body[ 16 ];
  ulong body_len, last_len;
  FD_TEST( FD_SSHTTP_ADVANCE_DONE==run_request( http, body, sizeof(body), &body_len, &last_len ) );
  FD_TEST( body_len==5UL && !memcmp( body, "hello", 5UL ) );
  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );

  server = connect_pair( http );
  http->range_start = 4096UL;
  FD_TEST( fd_cstr_printf_check( http->location, sizeof(http->location), &http->location_len, "/%s", name ) );
  FD_TEST( (long)strlen( redirect )==send( server, redirect, strlen( redirect ), 0 ) );
  for( ulong i=0UL; i<1024UL && http->hops==4UL; i++ ) {
    data_len = 0UL;
    FD_TEST( FD_SSHTTP_ADVANCE_AGAIN==fd_sshttp_advance( http, &iov, 1UL, &data_len, &downloading, 0L ) );
  }
  FD_TEST( http->hops==3UL && http->range_start==4096UL );
  FD_TEST( 0==close( server ) );
  fd_sshttp_cancel( http );
}

/* A 404 means there is no such file, ranged or not.  For a stream it
   means the stream is not served when the request had no offset, and
   that the stream being read ended with nothing after it yet when it
   had one. */

static void
test_not_found( void ) {
  struct { int stream; ulong range_start; int expect; } cases[] = {
    { 0, 0UL,  FD_SSHTTP_ADVANCE_NOT_FOUND     },
    { 0, 10UL, FD_SSHTTP_ADVANCE_NOT_FOUND     },
    { 1, 0UL,  FD_SSHTTP_ADVANCE_STREAM_ABSENT },
    { 1, 10UL, FD_SSHTTP_ADVANCE_STREAM_ENDED  },
  };
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    fd_sshttp_t * http = fd_sshttp_join( fd_sshttp_new( test_http, test_epoll_fd ) );
    FD_TEST( http );

    int server = connect_pair( http );
    http->range_start = cases[ i ].range_start;
    http->is_stream   = cases[ i ].stream;
    char const * resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    FD_TEST( (long)strlen( resp )==send( server, resp, strlen( resp ), 0 ) );

    uchar body[ 16 ];
    ulong body_len, last_len;
    FD_TEST( cases[ i ].expect==run_request( http, body, sizeof(body), &body_len, &last_len ) );
    FD_TEST( !body_len && !last_len );
    FD_TEST( http->state==FD_SSHTTP_STATE_INIT );

    FD_TEST( 0==close( server ) );
    fd_sshttp_cancel( http );
  }
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

  FD_TEST( !fd_sshttp_init( http, addr, "localhost", 0, "/boot/7.tar.zst", 15UL, 4UL, 0L, 0UL, 0 ) );
  FD_TEST( strstr( http->request, "GET /boot/7.tar.zst HTTP/1.1" ) );
  FD_TEST( !strstr( http->request, "Range:" ) );
  fd_sshttp_cancel( http );

  FD_TEST( !fd_sshttp_init( http, addr, "localhost", 0, "/boot/7.tar.zst", 15UL, 4UL, 0L, 4096UL, 0 ) );
  FD_TEST( strstr( http->request, "Range: bytes=4096-\r\n" ) );
  fd_sshttp_cancel( http );

  /* A resume asks for the same file from the new offset. */
  FD_TEST( !fd_sshttp_resume( http, 0L, 8192UL ) );
  FD_TEST( strstr( http->request, "GET /boot/7.tar.zst HTTP/1.1" ) );
  FD_TEST( strstr( http->request, "Range: bytes=8192-\r\n" ) );
  fd_sshttp_cancel( http );

  /* A resume keeps the request kind. */
  FD_TEST( !fd_sshttp_init( http, addr, "localhost", 0, "/boot/7.tar.zst", 15UL, 4UL, 0L, 0UL, 1 ) );
  fd_sshttp_cancel( http );
  FD_TEST( !fd_sshttp_resume( http, 0L, 8192UL ) && http->is_stream );
  fd_sshttp_cancel( http );

  /* After a redirect a resume stays on the new name, except from the
     start, which goes back to the requested path. */
  FD_TEST( fd_cstr_printf_check( http->location, sizeof(http->location), &http->location_len, "/boot/8.tar.zst" ) );
  FD_TEST( !fd_sshttp_resume( http, 0L, 4096UL ) );
  FD_TEST( strstr( http->request, "GET /boot/8.tar.zst HTTP/1.1" ) );
  fd_sshttp_cancel( http );
  FD_TEST( !fd_sshttp_resume( http, 0L, 0UL ) );
  FD_TEST( strstr( http->request, "GET /boot/7.tar.zst HTTP/1.1" ) );
  FD_TEST( !strstr( http->request, "Range:" ) );
  fd_sshttp_cancel( http );

  /* A request asks the same server for another path from the start,
     which later resumes from the start go back to. */
  FD_TEST( !fd_sshttp_request( http, 0L, "/boot/9.tar.zst", 15UL, 0UL ) );
  FD_TEST( strstr( http->request, "GET /boot/9.tar.zst HTTP/1.1" ) && strstr( http->request, "Host: localhost" ) );
  FD_TEST( !strstr( http->request, "Range:" ) && http->is_stream );
  fd_sshttp_cancel( http );
  FD_TEST( !fd_sshttp_resume( http, 0L, 0UL ) );
  FD_TEST( strstr( http->request, "GET /boot/9.tar.zst HTTP/1.1" ) );
  fd_sshttp_cancel( http );

  /* A request from an offset is the last request too. */
  FD_TEST( !fd_sshttp_request( http, 0L, "/boot/10.tar.zst", 16UL, 4096UL ) );
  FD_TEST( strstr( http->request, "GET /boot/10.tar.zst HTTP/1.1" ) && strstr( http->request, "Range: bytes=4096-\r\n" ) && http->is_stream );
  fd_sshttp_cancel( http );
  FD_TEST( !fd_sshttp_resume( http, 0L, 0UL ) );
  FD_TEST( strstr( http->request, "GET /boot/10.tar.zst HTTP/1.1" ) && !strstr( http->request, "Range:" ) );
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

  test_plaintext_host( "snapshots.example.com", "\r\nHost: snapshots.example.com:%u\r\n\r\n" );
  test_plaintext_host( "", "\r\nHost: 127.0.0.1:%u\r\n\r\n" );
  test_empty_body();
  test_eof_during_body();
  test_eof_during_headers();
  test_eof_immediate();
  test_headers_too_large();
  test_redirect_location();
  test_body_tail_wakes();
  test_range_partial();
  test_range_ignored();
  test_partial_unranged();
  test_range_mismatch();
  test_range_missing();
  test_range_not_satisfiable();
  test_redirect_stream_name();
  test_not_found();
  test_range_request();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
