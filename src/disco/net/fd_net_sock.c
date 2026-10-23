#include "fd_net_sock.h"

#include <errno.h>

static fd_net_sock_ops_t const fd_net_sock_ops_libc = {
  .socket = socket,
  .sendto = sendto
};

fd_net_sock_t *
fd_net_sock_init( fd_net_sock_t * net_sock ) {
  return fd_net_sock_init_ops( net_sock, &fd_net_sock_ops_libc );
}

fd_net_sock_t *
fd_net_sock_init_ops( fd_net_sock_t *           net_sock,
                      fd_net_sock_ops_t const * ops ) {
  if( FD_UNLIKELY( !net_sock ) ) {
    FD_LOG_WARNING(( "NULL net_sock" ));
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( !ops ) ) {
    FD_LOG_WARNING(( "NULL ops" ));
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( !ops->socket ) ) {
    FD_LOG_WARNING(( "NULL ops->socket" ));
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( !ops->sendto ) ) {
    FD_LOG_WARNING(( "NULL ops->sendto" ));
    errno = EINVAL;
    return NULL;
  }
  int const sock = ops->socket( AF_INET, SOCK_RAW|SOCK_CLOEXEC, IPPROTO_RAW );
  if( FD_UNLIKELY( sock<0 ) ) {
    int const err = errno;
    FD_LOG_WARNING(( "socket(AF_INET,SOCK_RAW,IPPROTO_RAW) failed (%i-%s)", err, fd_io_strerror( err ) ));
    errno = err;
    return NULL;
  }
  net_sock->ops  = ops;
  net_sock->sock = sock;
  return net_sock;
}

int
fd_net_sock_send( fd_net_sock_t *      net_sock,
                  fd_ip4_hdr_t const * ip4,
                  ulong                ip4_sz ) {
  struct sockaddr_in sa = {
    .sin_family      = AF_INET,
    .sin_addr.s_addr = ip4->daddr,
    .sin_port        = 0 /* ignored */
  };
  long const sent_sz = net_sock->ops->sendto( net_sock->sock, ip4, ip4_sz, 0, fd_type_pun_const( &sa ), sizeof(struct sockaddr_in) );
  return sent_sz==(long)ip4_sz;
}
