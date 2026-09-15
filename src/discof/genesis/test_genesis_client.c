/* Regression test for the incremental HTTP header parse in
   fd_genesis_client.  read_conn used to pass last_len==0 to
   phr_parse_response on every recvfrom, and to call it even after the
   header block had parsed, so a drip fed peer forced a full re-parse of
   the accumulated response per datagram. */

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "fd_genesis_client_private.h"
#include "../../util/fd_util.h"
#include "../../third_party/picohttpparser/picohttpparser.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define PEER_MAX FD_TOPO_GOSSIP_ENTRYPOINTS_MAX

struct parse_state {
  char const * buf;
  ulong        calls;
  ulong        prev_len;
  int          prev_ret;
  ulong        bytes;    /* bytes the parser had not already seen */
};

static struct parse_state parse_state[ PEER_MAX ];

/* Keyed by response buffer, so interleaved peers each get their own
   chain. */

static struct parse_state *
parse_find( char const * buf ) {
  for( ulong i=0UL; i<PEER_MAX; i++ ) {
    if( parse_state[ i ].buf==buf ) return &parse_state[ i ];
    if( !parse_state[ i ].buf ) {
      parse_state[ i ].buf = buf;
      return &parse_state[ i ];
    }
  }
  FD_LOG_ERR(( "out of parse state" ));
}

static int
test_phr_parse_response( char const *        buf,
                         ulong               len,
                         int *               minor_version,
                         int *               status,
                         char const **       msg,
                         ulong *             msg_len,
                         struct phr_header * headers,
                         ulong *             num_headers,
                         ulong               last_len );

#define phr_parse_response test_phr_parse_response
#include "fd_genesis_client.c"
#undef phr_parse_response

static int
test_phr_parse_response( char const *        buf,
                         ulong               len,
                         int *               minor_version,
                         int *               status,
                         char const **       msg,
                         ulong *             msg_len,
                         struct phr_header * headers,
                         ulong *             num_headers,
                         ulong               last_len ) {
  struct parse_state * st = parse_find( buf );

  /* Resume where the last call stopped, and never parse again once the
     headers are done. */
  FD_TEST( last_len==fd_ulong_if( !!st->calls, st->prev_len, 0UL ) );
  FD_TEST( !st->calls || -2==st->prev_ret );

  int ret = phr_parse_response( buf, len, minor_version, status, msg, msg_len, headers, num_headers, last_len );

  st->bytes   += len-last_len;
  st->prev_len = len;
  st->prev_ret = ret;
  st->calls++;

  return ret;
}

static fd_genesis_client_t * client;

/* Attach peer_cnt peers to socketpairs, returning the test's ends in
   fds.  Peer i is 127.0.0.(i+1). */

static void
client_init( int * fds,
             ulong peer_cnt ) {
  FD_TEST( client==fd_genesis_client_join( fd_genesis_client_new( client ) ) );

  fd_memset( parse_state, 0, sizeof(parse_state) );

  for( ulong i=0UL; i<peer_cnt; i++ ) {
    int sockfds[ 2 ];
    FD_TEST( 0==socketpair( AF_UNIX, SOCK_STREAM, 0, sockfds ) );
    for( ulong j=0UL; j<2UL; j++ ) {
      int flags = fcntl( sockfds[ j ], F_GETFL, 0 );
      FD_TEST( -1!=flags );
      FD_TEST( -1!=fcntl( sockfds[ j ], F_SETFL, flags|O_NONBLOCK ) );
    }

    client->pollfds[ i ] = (struct pollfd){ .fd = sockfds[ 0 ], .events = POLLIN|POLLOUT, .revents = 0 };
    client->peers[ i ].addr.addr           = FD_IP4_ADDR( 127, 0, 0, 1 )+(uint)(i<<24);
    client->peers[ i ].addr.port           = fd_ushort_bswap( (ushort)8899 );
    client->peers[ i ].writing             = 1;
    client->peers[ i ].request_bytes_sent  = 0UL;
    client->peers[ i ].response_bytes_read = 0UL;
    fds[ i ] = sockfds[ 1 ];
  }
  for( ulong i=peer_cnt; i<PEER_MAX; i++ ) client->pollfds[ i ].fd = -1;

  client->start_time_nanos   = fd_log_wallclock();
  client->peer_cnt           = peer_cnt;
  client->remaining_peer_cnt = peer_cnt;
}

static void
client_fini( int * fds,
             ulong peer_cnt ) {
  for( ulong i=0UL; i<peer_cnt; i++ ) {
    if( -1!=client->pollfds[ i ].fd ) FD_TEST( !close( client->pollfds[ i ].fd ) );
    FD_TEST( !close( fds[ i ] ) );
  }
}

static void
drain( int fd ) {
  uchar discard[ 4096 ];
  while( recv( fd, discard, sizeof(discard), MSG_DONTWAIT|MSG_NOSIGNAL )>0L ) {}
}

static void
send_all( int           fd,
          uchar const * buf,
          ulong         sz ) {
  for( ulong off=0UL; off<sz; ) {
    long sent = send( fd, buf+off, sz-off, MSG_NOSIGNAL );
    FD_TEST( sent>0L );
    off += (ulong)sent;
  }
}

static int
poll_once( fd_ip4_port_t * peer,
           uchar **        buffer,
           ulong *         buffer_sz ) {
  int charge_busy = 0;
  *buffer    = NULL;
  *buffer_sz = 0UL;
  return fd_genesis_client_poll( client, peer, buffer, buffer_sz, &charge_busy );
}

/* Feed one peer a response in chunk_sz sized datagrams, polling between
   each so no two chunks coalesce into one recvfrom. */

static void
test_drip( uchar const * response,
           ulong         response_sz,
           ulong         header_sz,
           ulong         body_sz,
           ulong         chunk_sz ) {
  int fds[ 1 ];
  client_init( fds, 1UL );

  int done = 0;
  for( ulong off=0UL; off<response_sz; ) {
    ulong chunk = fd_ulong_min( chunk_sz, response_sz-off );
    send_all( fds[ 0 ], response+off, chunk );
    off += chunk;

    uchar *       buffer;
    ulong         buffer_sz;
    fd_ip4_port_t peer = {0};
    int           err  = poll_once( &peer, &buffer, &buffer_sz );
    FD_TEST( err>=0 );
    drain( fds[ 0 ] );

    if( !err ) {
      FD_TEST( off>=header_sz+body_sz );
      FD_TEST( buffer_sz==body_sz );
      FD_TEST( !memcmp( buffer, response+header_sz, body_sz ) );
      FD_TEST( peer.addr==FD_IP4_ADDR( 127, 0, 0, 1 ) );
      FD_TEST( -1==client->pollfds[ 0 ].fd ); /* success closes every peer */
      done = 1;
      break;
    }
  }
  FD_TEST( done );

  struct parse_state * st = parse_find( (char const *)client->peers[ 0 ].response );
  FD_TEST( st->calls );
  FD_TEST( (ulong)st->prev_ret==header_sz );
  FD_TEST( st->bytes<=header_sz+chunk_sz ); /* not quadratic in datagram count */

  client_fini( fds, 1UL );
}

/* Same, but split in two at an arbitrary offset. */

static void
test_split( uchar const * response,
            ulong         response_sz,
            ulong         header_sz,
            ulong         body_sz,
            ulong         prefix_sz ) {
  int fds[ 1 ];
  client_init( fds, 1UL );

  uchar *       buffer;
  ulong         buffer_sz;
  fd_ip4_port_t peer = {0};

  send_all( fds[ 0 ], response, prefix_sz );
  int err = poll_once( &peer, &buffer, &buffer_sz );
  FD_TEST( err>=0 );
  FD_TEST( !!err || prefix_sz>=header_sz+body_sz );
  drain( fds[ 0 ] );

  if( err ) {
    send_all( fds[ 0 ], response+prefix_sz, response_sz-prefix_sz );
    err = poll_once( &peer, &buffer, &buffer_sz );
  }

  FD_TEST( !err );
  FD_TEST( buffer_sz==body_sz );
  FD_TEST( !memcmp( buffer, response+header_sz, body_sz ) );

  client_fini( fds, 1UL );
}

/* Responses the client must refuse, dropping the peer. */

static void
test_reject( char const * response,
             ulong        chunk_sz ) {
  int fds[ 1 ];
  client_init( fds, 1UL );

  ulong response_sz = strlen( response );
  for( ulong off=0UL; off<response_sz; ) {
    ulong chunk = fd_ulong_min( chunk_sz, response_sz-off );
    send_all( fds[ 0 ], (uchar const *)response+off, chunk );
    off += chunk;

    uchar *       buffer;
    ulong         buffer_sz;
    fd_ip4_port_t peer = {0};
    FD_TEST( poll_once( &peer, &buffer, &buffer_sz ) );
    drain( fds[ 0 ] );
    if( -1==client->pollfds[ 0 ].fd ) break;
  }

  FD_TEST( -1==client->pollfds[ 0 ].fd );
  FD_TEST( !client->remaining_peer_cnt );

  uchar *       buffer;
  ulong         buffer_sz;
  fd_ip4_port_t peer = {0};
  FD_TEST( -1==poll_once( &peer, &buffer, &buffer_sz ) ); /* no peers left */

  client_fini( fds, 1UL );
}

static void
test_request( void ) {
  int fds[ 1 ];
  client_init( fds, 1UL );

  uchar *       buffer;
  ulong         buffer_sz;
  fd_ip4_port_t peer = {0};
  FD_TEST( poll_once( &peer, &buffer, &buffer_sz ) );
  FD_TEST( !client->peers[ 0 ].writing );

  char request[ 1024 ];
  long sz = recv( fds[ 0 ], request, sizeof(request)-1UL, MSG_DONTWAIT|MSG_NOSIGNAL );
  FD_TEST( sz>0L );
  request[ sz ] = '\0';
  FD_TEST( (ulong)sz==client->peers[ 0 ].request_bytes_sent );
  FD_TEST( !strncmp( request, "GET /genesis.tar.bz2 HTTP/1.1\r\n", 31UL ) );
  FD_TEST( strstr( request, "\r\nHost: 127.0.0.1:8899\r\n" ) );
  FD_TEST( !strcmp( request+sz-4, "\r\n\r\n" ) );

  client_fini( fds, 1UL );
}

/* A dead peer is dropped without disturbing the others, and the first
   peer to answer wins. */

static void
test_peers( uchar const * response,
            ulong         response_sz,
            ulong         header_sz,
            ulong         body_sz ) {
  int fds[ 3 ];
  client_init( fds, 3UL );

  uchar *       buffer;
  ulong         buffer_sz;
  fd_ip4_port_t peer = {0};

  FD_TEST( poll_once( &peer, &buffer, &buffer_sz ) );

  FD_TEST( !close( fds[ 0 ] ) );
  FD_TEST( poll_once( &peer, &buffer, &buffer_sz ) );
  FD_TEST( -1==client->pollfds[ 0 ].fd );
  FD_TEST(  2UL==client->remaining_peer_cnt );

  send_all( fds[ 2 ], response, header_sz );
  FD_TEST( poll_once( &peer, &buffer, &buffer_sz ) );
  send_all( fds[ 2 ], response+header_sz, response_sz-header_sz );
  FD_TEST( !poll_once( &peer, &buffer, &buffer_sz ) );

  FD_TEST( buffer_sz==body_sz );
  FD_TEST( !memcmp( buffer, response+header_sz, body_sz ) );
  FD_TEST( peer.addr==client->peers[ 2 ].addr.addr );
  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( -1==client->pollfds[ i ].fd );

  FD_TEST( !close( fds[ 1 ] ) );
  FD_TEST( !close( fds[ 2 ] ) );
}

static void
test_timeout( void ) {
  int fds[ 2 ];
  client_init( fds, 2UL );
  client->start_time_nanos = fd_log_wallclock()-21L*1000L*1000L*1000L;

  uchar *       buffer;
  ulong         buffer_sz;
  fd_ip4_port_t peer = {0};
  FD_TEST( -1==poll_once( &peer, &buffer, &buffer_sz ) );
  for( ulong i=0UL; i<2UL; i++ ) FD_TEST( -1==client->pollfds[ i ].fd );

  client_fini( fds, 2UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  client = aligned_alloc( fd_genesis_client_align(), fd_genesis_client_footprint() );
  FD_TEST( client );

  static uchar response[ 64UL*1024UL ];
  ulong body_sz = 32UL*1024UL;
  ulong header_sz;
  FD_TEST( fd_cstr_printf_check( (char *)response, sizeof(response), &header_sz,
                                 "HTTP/1.1 200 OK\r\n"
                                 "Server: test\r\n"
                                 "Content-Type: application/octet-stream\r\n"
                                 "Content-Length: %lu\r\n"
                                 "\r\n", body_sz ) );
  for( ulong i=0UL; i<body_sz; i++ ) response[ header_sz+i ] = (uchar)(i*7UL+1UL);
  ulong response_sz = header_sz+body_sz;

  test_drip( response, response_sz, header_sz, body_sz, 1UL );
  test_drip( response, response_sz, header_sz, body_sz, 17UL );
  test_drip( response, response_sz, header_sz, body_sz, 1024UL );
  test_drip( response, response_sz, header_sz, body_sz, response_sz );

  /* Bytes past Content-Length are ignored. */
  test_drip( response, response_sz+16UL, header_sz, body_sz, 4096UL );

  test_peers( response, response_sz, header_sz, body_sz );

  /* Every two way split, including one that lands inside the CRLFCRLF
     that ends the header block. */
  static uchar small[ 1024 ];
  ulong small_body_sz = 64UL;
  ulong small_hdr_sz;
  FD_TEST( fd_cstr_printf_check( (char *)small, sizeof(small), &small_hdr_sz,
                                 "HTTP/1.1 200 OK\r\n"
                                 "content-length: %lu\r\n" /* header names are case insensitive */
                                 "\r\n", small_body_sz ) );
  for( ulong i=0UL; i<small_body_sz; i++ ) small[ small_hdr_sz+i ] = (uchar)i;
  ulong small_sz = small_hdr_sz+small_body_sz;
  for( ulong prefix=1UL; prefix<small_sz; prefix++ ) {
    test_split( small, small_sz, small_hdr_sz, small_body_sz, prefix );
  }

  test_request();
  test_timeout();

  test_reject( "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 1UL );
  test_reject( "HTTP/1.1 200 OK\r\nServer: test\r\n\r\n",             1UL ); /* no Content-Length */
  test_reject( "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n",      1UL );
  test_reject( "HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n", 4UL );
  test_reject( "HTTP/1.1 200 OK\r\nContent-Length: 10485761\r\n\r\n",  4UL ); /* larger than the response buffer */
  test_reject( "not a http response at all\r\n\r\n",                  1UL );
  test_reject( "HTTP/1.1 600 Nonsense\r\n\r\n",                       1UL );

  free( client );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
