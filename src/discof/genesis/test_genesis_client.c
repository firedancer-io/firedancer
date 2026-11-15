#include "fd_genesis_client_private.h"
#include "../../util/fd_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

/* Connects client to one end of a socketpair, as if fd_genesis_client_init
   had connected to a peer, and returns the other end. */

static int
connect_pair( fd_genesis_client_t * client,
              int                   epoll_fd ) {
  int fds[2];
  FD_TEST( !socketpair( AF_UNIX, SOCK_STREAM, 0, fds ) );
  FD_TEST( -1!=fcntl( fds[0], F_SETFL, O_NONBLOCK ) );

  struct epoll_event ev = { .events = EPOLLIN|EPOLLOUT, .data.fd = fds[0] };
  FD_TEST( !epoll_ctl( epoll_fd, EPOLL_CTL_ADD, fds[0], &ev ) );

  client->start_time_nanos   = LONG_MAX;
  client->peer_cnt           = 1UL;
  client->remaining_peer_cnt = 1UL;
  client->epoll_fd           = epoll_fd;
  client->pollfds[0] = (struct pollfd){ .fd = fds[0], .events = POLLIN|POLLOUT };
  for( ulong i=1UL; i<FD_TOPO_GOSSIP_ENTRYPOINTS_MAX; i++ ) client->pollfds[i].fd = -1;

  client->peers[0].addr.addr          = FD_IP4_ADDR( 127, 0, 0, 1 );
  client->peers[0].addr.port          = fd_ushort_bswap( 8899 );
  client->peers[0].writing            = 1;
  client->peers[0].request_bytes_sent = 0UL;
  client->peers[0].response_bytes_read = 0UL;
  client->peers[0].header_len         = 0UL;
  return fds[1];
}

/* Sends response to the client chunk_sz bytes at a time, polling the
   client after each chunk.  Returns the result of the last poll. */

static int
serve( fd_genesis_client_t * client,
       int                   server_fd,
       char const *          response,
       ulong                 response_sz,
       ulong                 chunk_sz,
       uchar **              buffer,
       ulong *               buffer_sz ) {
  fd_ip4_port_t peer;
  int           charge_busy;

  /* Let the client send its request, and discard it. */
  while( client->peers[0].writing ) {
    FD_TEST( 1==fd_genesis_client_poll( client, fd_log_wallclock(), &peer, buffer, buffer_sz, &charge_busy ) );
  }
  char request[ 1024 ];
  FD_TEST( recv( server_fd, request, sizeof(request), 0 )>0L );

  int result = 1;
  for( ulong off=0UL; off<response_sz && result==1; off+=chunk_sz ) {
    ulong sz = fd_ulong_min( chunk_sz, response_sz-off );
    FD_TEST( send( server_fd, response+off, sz, MSG_NOSIGNAL )==(long)sz );
    result = fd_genesis_client_poll( client, fd_log_wallclock(), &peer, buffer, buffer_sz, &charge_busy );
  }
  return result;
}

static char const body[] = "body\r with a lone CR and \n LF, but no blank line";

static void
test_response( fd_genesis_client_t * client,
               int                   epoll_fd,
               ulong                 chunk_sz ) {
  char  response[ 512 ];
  ulong response_sz;
  FD_TEST( fd_cstr_printf_check( response, sizeof(response), &response_sz,
                                 "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %lu\r\n\r\n%s",
                                 sizeof(body)-1UL, body ) );

  int     server_fd = connect_pair( client, epoll_fd );
  uchar * buffer    = NULL;
  ulong   buffer_sz = 0UL;
  FD_TEST( !serve( client, server_fd, response, response_sz, chunk_sz, &buffer, &buffer_sz ) );
  FD_TEST( buffer_sz==sizeof(body)-1UL );
  FD_TEST( !memcmp( buffer, body, buffer_sz ) );
  FD_TEST( !close( server_fd ) );
}

static void
test_bad_status( fd_genesis_client_t * client,
                 int                   epoll_fd,
                 ulong                 chunk_sz ) {
  static char const response[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

  int     server_fd = connect_pair( client, epoll_fd );
  uchar * buffer    = NULL;
  ulong   buffer_sz = 0UL;
  FD_TEST( 1==serve( client, server_fd, response, sizeof(response)-1UL, chunk_sz, &buffer, &buffer_sz ) );
  FD_TEST( !client->remaining_peer_cnt );
  FD_TEST( !close( server_fd ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_genesis_client_t * client = aligned_alloc( fd_genesis_client_align(), fd_genesis_client_footprint() );
  FD_TEST( client );
  FD_TEST( fd_genesis_client_join( fd_genesis_client_new( client ) ) );

  int epoll_fd = epoll_create1( 0 );
  FD_TEST( epoll_fd>=0 );

  /* One byte at a time, a few bytes at a time and all at once. */
  ulong const chunk_szs[] = { 1UL, 7UL, 4096UL };
  for( ulong i=0UL; i<sizeof(chunk_szs)/sizeof(ulong); i++ ) {
    test_response  ( client, epoll_fd, chunk_szs[ i ] );
    test_bad_status( client, epoll_fd, chunk_szs[ i ] );
  }

  FD_TEST( !close( epoll_fd ) );
  free( client );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
