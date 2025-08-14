#include "fd_ipecho_client.h"
#include "fd_ipecho_client_private.h"

#include "../../util/fd_util.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

FD_FN_CONST ulong
fd_ipecho_client_align( void ) {
  return alignof(fd_ipecho_client_t);
}

FD_FN_CONST ulong
fd_ipecho_client_footprint( void ) {
  return sizeof(fd_ipecho_client_t);
}

void *
fd_ipecho_client_new( void * shmem ) {
  fd_ipecho_client_t * ipe = (fd_ipecho_client_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ipecho_client_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( ipe->magic ) = FD_IPECHO_CLIENT_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)ipe;
}

fd_ipecho_client_t *
fd_ipecho_client_join( void * shipe ) {
  if( FD_UNLIKELY( !shipe ) ) {
    FD_LOG_WARNING(( "NULL shipe" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shipe, fd_ipecho_client_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shipe" ));
    return NULL;
  }

  fd_ipecho_client_t * ipe = (fd_ipecho_client_t *)shipe;

  if( FD_UNLIKELY( ipe->magic!=FD_IPECHO_CLIENT_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ipe;
}

void
fd_ipecho_client_init( fd_ipecho_client_t *  client,
                       fd_ip4_port_t const * servers,
                       ulong                 servers_len ) {
  ulong peer_cnt = 0UL;

  for( ulong i=0UL; i<servers_len; i++ ) {
    fd_ip4_port_t const * server = &servers[ i ];

    int sockfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
    if( FD_UNLIKELY( -1==sockfd ) ) FD_LOG_ERR(( "socket() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port   = fd_ushort_bswap( server->port ),
      .sin_addr   = { .s_addr = server->addr }
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
    client->peers[ peer_cnt ].writing = 1;
    client->peers[ peer_cnt ].request_bytes_sent = 0UL;
    client->peers[ peer_cnt ].response_bytes_read = 0UL;
    peer_cnt++;
  }

  client->peer_cnt = peer_cnt;
  client->start_time_nanos = fd_log_wallclock();
}

static void
close_one( fd_ipecho_client_t * client,
           ulong                idx ) {
  if( FD_UNLIKELY( -1==close( client->pollfds[ idx ].fd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  client->pollfds[ idx ].fd = -1;
  client->peer_cnt--;
}

static void
close_all( fd_ipecho_client_t * client ) {
  for( ulong i=0UL; i<client->peer_cnt; i++ ) {
    if( FD_UNLIKELY( -1==client->pollfds[ i ].fd ) ) continue;
    close_one( client, i );
  }
}

int
fd_ipecho_client_parse_response( uchar const * response,
                                 ulong         response_len,
                                 ushort *      _shred_version ) {
  if( FD_UNLIKELY( response_len<8UL ) ) return FD_IPECHO_PARSE_ERR;
  if( FD_UNLIKELY( memcmp( response, "\0\0\0\0", 4UL ) ) ) return FD_IPECHO_PARSE_ERR;

  uint ip_variant = fd_uint_load_4_fast( response+4UL );
  if( FD_UNLIKELY( ip_variant>1U ) ) return FD_IPECHO_PARSE_ERR;

  ulong offset = 8UL;
  if( FD_LIKELY( !ip_variant ) ) offset+=4UL;
  else                           offset+=16UL;

  if( FD_UNLIKELY( response_len<offset+3UL ) ) return FD_IPECHO_PARSE_ERR;

  if( FD_UNLIKELY( response[ offset ]!=1 ) ) return FD_IPECHO_PARSE_ERR;

  ushort shred_version = fd_ushort_load_2_fast( response+offset+1UL );
  if( FD_UNLIKELY( !shred_version ) ) return FD_IPECHO_PARSE_ERR;

  *_shred_version = shred_version;
  return FD_IPECHO_PARSE_OK;
}

static void
write_conn( fd_ipecho_client_t * client,
            ulong                conn_idx ) {
  fd_ipecho_client_peer_t * peer = &client->peers[ conn_idx ];

  if( FD_LIKELY( !peer->writing ) ) return;

  uchar request[ 21UL ] = {
    0, 0, 0, 0,             /* Magic */
    0, 0, 0, 0, 0, 0, 0, 0, /* TCP ports */
    0, 0, 0, 0, 0, 0, 0, 0, /* UDP ports */
    '\n',                   /* End of request */
  };

  long written = send( client->pollfds[ conn_idx ].fd,
                       request+peer->request_bytes_sent,
                       sizeof(request)-peer->request_bytes_sent,
                       MSG_NOSIGNAL );
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

static int
read_conn( fd_ipecho_client_t * client,
           ulong                conn_idx,
           ushort *             shred_version ) {
  fd_ipecho_client_peer_t * peer = &client->peers[ conn_idx ];

  if( FD_UNLIKELY( peer->writing ) ) return 1;

  long read = recv( client->pollfds[ conn_idx ].fd,
                    peer->response+peer->response_bytes_read,
                    sizeof(peer->response)-peer->response_bytes_read,
                    0 );

  if( FD_UNLIKELY( -1==read && (errno==EAGAIN || errno==EINTR) ) ) return 1;
  else if( FD_UNLIKELY( -1==read ) ) {
    close_one( client, conn_idx );
    return 1;
  }

  peer->response_bytes_read += (ulong)read;
  if( FD_UNLIKELY( read ) ) return 1;

  int response = fd_ipecho_client_parse_response( peer->response,
                                                  peer->response_bytes_read,
                                                  shred_version );
  if( FD_LIKELY( response==FD_IPECHO_PARSE_OK ) ) return 0;
  else {
    close_one( client, conn_idx );
    return 1;
  }
}

int
fd_ipecho_client_poll( fd_ipecho_client_t * client,
                       ushort *             shred_version,
                       int *                charge_busy ) {
  if( FD_UNLIKELY( !client->peer_cnt ) ) return -1;
  if( FD_UNLIKELY( fd_log_wallclock()-client->start_time_nanos>2L*1000L*1000*1000L ) ) {
    close_all( client );
    return -1;
  }

  int nfds = fd_syscall_poll( client->pollfds, 16U, 0 );
  if( FD_UNLIKELY( 0==nfds ) ) return 1;
  else if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) return 1;
  else if( FD_UNLIKELY( -1==nfds ) ) FD_LOG_ERR(( "poll() failed (%i-%s)", errno, strerror( errno ) ));

  *charge_busy = 1;

  for( ulong i=0UL; i<16U; i++ ) {
    if( FD_UNLIKELY( -1==client->pollfds[ i ].fd ) ) continue;

    if( FD_LIKELY( client->pollfds[ i ].revents & POLLOUT ) ) write_conn( client, i );
    if( FD_UNLIKELY( -1==client->pollfds[ i ].fd ) ) continue;
    if( FD_LIKELY( client->pollfds[ i ].revents & POLLIN ) ) {
      if( FD_LIKELY( !read_conn( client, i, shred_version ) ) ) {
        close_all( client );
        return 0;
      }
    }
  }

  return 1;
}
