#include "fd_genesis_client.h"

#include "../../waltz/http/picohttpparser.h"
#include "../../disco/topo/fd_topo.h"
#include "../../util/fd_util.h"
#include "../../ballet/sha256/fd_sha256.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/poll.h>
#include <stdlib.h>

struct fd_genesis_client_peer {
  fd_ip4_port_t addr;

  int writing;
  ulong request_bytes_sent;
  ulong response_bytes_read;
  uchar response[ 10UL*1024UL*1024UL ]; /* 10 MiB max response */
};

typedef struct fd_genesis_client_peer fd_genesis_client_peer_t;

struct fd_genesis_client_private {
  long start_time_nanos;
  ulong peer_cnt;
  ulong remaining_peer_cnt;

  struct pollfd pollfds[ FD_TOPO_GOSSIP_ENTRYPOINTS_MAX ];
  fd_genesis_client_peer_t peers[ FD_TOPO_GOSSIP_ENTRYPOINTS_MAX ];

  ulong magic;
};

FD_FN_CONST ulong
fd_genesis_client_align( void ) {
  return alignof(fd_genesis_client_t);
}

FD_FN_CONST ulong
fd_genesis_client_footprint( void ) {
  return sizeof(fd_genesis_client_t);
}

void *
fd_genesis_client_new( void * shmem ) {
  fd_genesis_client_t * gen = (fd_genesis_client_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_genesis_client_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( gen->magic ) = FD_GENESIS_CLIENT_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)gen;
}

fd_genesis_client_t *
fd_genesis_client_join( void * shgen ) {
  if( FD_UNLIKELY( !shgen ) ) {
    FD_LOG_WARNING(( "NULL shgen" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shgen, fd_genesis_client_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shgen" ));
    return NULL;
  }

  fd_genesis_client_t * gen = (fd_genesis_client_t *)shgen;

  if( FD_UNLIKELY( gen->magic!=FD_GENESIS_CLIENT_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return gen;
}

void
fd_genesis_client_init( fd_genesis_client_t * client,
                        fd_ip4_port_t const * servers,
                        ulong                 servers_len ) {
  FD_TEST( servers_len<=FD_TOPO_GOSSIP_ENTRYPOINTS_MAX );
  ulong peer_cnt = 0UL;

  for( ulong i=0UL; i<servers_len; i++ ) {
    fd_ip4_port_t server = servers[ i ];
    server.port = 8899;  // TODO: SPECIFY IN CONFIG

    int sockfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
    if( FD_UNLIKELY( -1==sockfd ) ) FD_LOG_ERR(( "socket() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port   = fd_ushort_bswap( server.port ),
      .sin_addr   = { .s_addr = server.addr }
    };

    if( FD_UNLIKELY( -1==connect( sockfd, fd_type_pun( &addr ), sizeof(addr) ) && errno!=EINPROGRESS ) ) {
      if( FD_UNLIKELY( -1==close( sockfd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      continue;
    }

    client->pollfds[ peer_cnt ] = (struct pollfd){
      .fd = sockfd,
      .events = POLLIN | POLLOUT,
      .revents = 0
    };
    client->peers[ peer_cnt ].addr = server;
    client->peers[ peer_cnt ].writing = 1;
    client->peers[ peer_cnt ].request_bytes_sent = 0UL;
    client->peers[ peer_cnt ].response_bytes_read = 0UL;
    peer_cnt++;
  }

  for( ulong i=peer_cnt; i<FD_TOPO_GOSSIP_ENTRYPOINTS_MAX; i++ ) client->pollfds[ i ].fd = -1;

  client->peer_cnt = peer_cnt;
  client->remaining_peer_cnt = peer_cnt;
  client->start_time_nanos = fd_log_wallclock();
}

static void
close_one( fd_genesis_client_t * client,
           ulong                 idx ) {
  if( FD_UNLIKELY( -1==close( client->pollfds[ idx ].fd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  client->pollfds[ idx ].fd = -1;
  client->remaining_peer_cnt--;
}

static void
close_all( fd_genesis_client_t * client ) {
  for( ulong i=0UL; i<client->peer_cnt; i++ ) {
    if( FD_UNLIKELY( -1==client->pollfds[ i ].fd ) ) continue;
    close_one( client, i );
  }
}

static void
write_conn( fd_genesis_client_t * client,
            ulong                 conn_idx ) {
  fd_genesis_client_peer_t * peer = &client->peers[ conn_idx ];

  if( FD_LIKELY( !peer->writing ) ) return;

  char request[ 1024UL ];
  FD_TEST( fd_cstr_printf_check( request, sizeof(request), NULL, "GET /genesis.tar.bz2 HTTP/1.1\r\n"
                                                                 "Cache-Control: no-cache\r\n"
                                                                 "Connection: keep-alive\r\n"
                                                                 "Pragma: no-cache\r\n"
                                                                 "User-Agent: Firedancer\r\n"
                                                                 "Host: " FD_IP4_ADDR_FMT ":%hu\r\n\r\n",
                                                                 FD_IP4_ADDR_FMT_ARGS( peer->addr.addr ), fd_ushort_bswap( peer->addr.port ) ) );

  long written = sendto( client->pollfds[ conn_idx ].fd,
                         request+peer->request_bytes_sent,
                         sizeof(request)-peer->request_bytes_sent,
                         MSG_NOSIGNAL,
                         NULL,
                         0 );
  if( FD_UNLIKELY( -1==written && errno==EAGAIN ) ) return; /* No data was written, continue. */
  else if( FD_UNLIKELY( -1==written ) ) {
    close_one( client, conn_idx );
    return;
  }

  peer->request_bytes_sent += (ulong)written;
  if( FD_UNLIKELY( peer->request_bytes_sent==sizeof(request) ) ) {
    peer->writing = 0;
    peer->response_bytes_read = 0UL;
  }
}

static ulong
rpc_phr_content_length( struct phr_header * headers,
                        ulong               num_headers ) {
  for( ulong i=0UL; i<num_headers; i++ ) {
    if( FD_LIKELY( headers[i].name_len!=14UL ) ) continue;
    if( FD_LIKELY( strncasecmp( headers[i].name, "Content-Length", 14UL ) ) ) continue;
    char * end;
    ulong content_length = strtoul( headers[i].value, &end, 10 );
    if( FD_UNLIKELY( end==headers[i].value ) ) return ULONG_MAX;
    return content_length;
  }
  return ULONG_MAX;
}

static int
read_conn( fd_genesis_client_t * client,
           ulong                 conn_idx,
           uchar **              buffer,
           ulong *               buffer_sz ) {
  fd_genesis_client_peer_t * peer = &client->peers[ conn_idx ];

  if( FD_UNLIKELY( peer->writing ) ) return 1;
  long read = recvfrom( client->pollfds[ conn_idx ].fd,
                        peer->response+peer->response_bytes_read,
                        sizeof(peer->response)-peer->response_bytes_read,
                        0,
                        NULL,
                        NULL );
  if( FD_UNLIKELY( -1==read && (errno==EAGAIN || errno==EINTR) ) ) return 1;
  else if( FD_UNLIKELY( -1==read ) ) {
    close_one( client, conn_idx );
    return 1;
  }

  peer->response_bytes_read += (ulong)read;

  int minor_version;
  int status;
  const char * message;
  ulong message_len;
  struct phr_header headers[ 32 ];
  ulong num_headers = 32UL;
  int len = phr_parse_response( (char*)peer->response, peer->response_bytes_read,
                                &minor_version, &status, &message, &message_len,
                                headers, &num_headers, 0L );
  if( FD_UNLIKELY( -1==len ) ) {
    close_one( client, conn_idx );
    return 1;
  } else if( FD_UNLIKELY( -2==len ) ) {
    return 1;
  }

  if( FD_UNLIKELY( status!=200 ) ) {
    close_one( client, conn_idx );
    return 1;
  }

  ulong content_length = rpc_phr_content_length( headers, num_headers );
  if( FD_UNLIKELY( content_length==ULONG_MAX ) ) {
    close_one( client, conn_idx );
    return 1;
  }
  if( FD_UNLIKELY( content_length+(ulong)len>sizeof(peer->response) ) ) {
    close_one( client, conn_idx );
    return 1;
  }
  if( FD_LIKELY( content_length+(ulong)len>peer->response_bytes_read ) ) {
    return 1;
  }

  *buffer_sz = content_length;
  *buffer    = peer->response + (ulong)len;

  uchar hash[ 32UL ] = {0};
  fd_sha256_hash( *buffer, *buffer_sz, hash );

  return 0;
}

int
fd_genesis_client_poll( fd_genesis_client_t * client,
                        fd_ip4_port_t *       peer,
                        uchar **              buffer,
                        ulong *               buffer_sz,
                        int *                 charge_busy ) {
  if( FD_UNLIKELY( !client->remaining_peer_cnt ) ) return -1;
  if( FD_UNLIKELY( fd_log_wallclock()-client->start_time_nanos>20L*1000L*1000*1000L ) ) {
    close_all( client );
    return -1;
  }

  int nfds = fd_syscall_poll( client->pollfds, (uint)client->peer_cnt, 0 );
  if( FD_UNLIKELY( 0==nfds ) ) return 1;
  else if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) return 1;
  else if( FD_UNLIKELY( -1==nfds ) ) FD_LOG_ERR(( "poll() failed (%i-%s)", errno, strerror( errno ) ));

  *charge_busy = 1;

  for( ulong i=0UL; i<FD_TOPO_GOSSIP_ENTRYPOINTS_MAX; i++ ) {
    if( FD_UNLIKELY( -1==client->pollfds[ i ].fd ) ) continue;

    if( FD_LIKELY( client->pollfds[ i ].revents & POLLOUT ) ) write_conn( client, i );
    if( FD_UNLIKELY( -1==client->pollfds[ i ].fd ) ) continue;
    if( FD_LIKELY( client->pollfds[ i ].revents & POLLIN ) ) {
      if( FD_LIKELY( !read_conn( client, i, buffer, buffer_sz ) ) ) {
        close_all( client );
        *peer = client->peers[ i ].addr;
        return 0;
      }
    }
  }

  return 1;
}

struct pollfd const *
fd_genesis_client_get_pollfds( fd_genesis_client_t * client ) {
  return client->pollfds;
}
