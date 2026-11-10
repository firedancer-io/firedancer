#ifndef HEADER_fd_src_disco_net_fd_net_sock_h
#define HEADER_fd_src_disco_net_fd_net_sock_h

#include "../fd_disco_base.h"
#include "../../util/net/fd_ip4.h"

#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* fd_net_sock_ops_t is the syscall interface used by fd_net_sock.
   Signatures and semantics match libc.  Tests substitute mocks. */
struct fd_net_sock_ops {
  int  (*socket)( int domain, int type, int protocol );
  long (*sendto)( int sock, void const * buf, ulong len, int flags, struct sockaddr const * addr, socklen_t addr_len );
};
typedef struct fd_net_sock_ops fd_net_sock_ops_t;

struct fd_net_sock {
  fd_net_sock_ops_t const * ops;
  int                       sock;
};
typedef struct fd_net_sock fd_net_sock_t;

FD_PROTOTYPES_BEGIN

/* fd_net_sock_init_ops is the same as fd_net_sock_init but uses the
   given ops instead of libc.  ops and each of its members must be
   non-NULL. */
static fd_net_sock_t *
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
  int const sock = ops->socket( AF_INET, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_RAW );
  if( FD_UNLIKELY( sock<0 ) ) {
    int const err = errno;
    FD_LOG_WARNING(( "socket(AF_INET,SOCK_RAW|SOCK_NONBLOCK,IPPROTO_RAW) failed (%i-%s)", err, fd_io_strerror( err ) ));
    errno = err;
    return NULL;
  }
  net_sock->ops  = ops;
  net_sock->sock = sock;
  return net_sock;
}

/* fd_net_sock_init initializes net_sock and opens a non-blocking
   send-only IPPROTO_RAW socket.  It is not bound to an interface and
   relies on the kernel to route packets.  Returns net_sock on success
   and NULL on error with errno set. */
static fd_net_sock_t *
fd_net_sock_init( fd_net_sock_t * net_sock ) {
  static fd_net_sock_ops_t const ops = {
    .socket = socket,
    .sendto = sendto
  };
  return fd_net_sock_init_ops( net_sock, &ops );
}

/* fd_net_sock_send sends one packet on net_sock with a single
   non-blocking sendto.  ip4 points to the beginning of an IPv4 header.
   ip4_sz is the size of the IP header and payload.  The L2 header will
   be constructed by the kernel.  The destination is ip4->daddr.
   Returns 1 if the whole packet was sent and 0 if the packet was
   not (the send would block, failed, or was short).  Failed packets
   are not retried. */
FD_FN_UNUSED static int
fd_net_sock_send( fd_net_sock_t *      net_sock,
                  fd_ip4_hdr_t const * ip4,
                  ulong                ip4_sz ) {
  struct sockaddr_in sa = {
    .sin_family      = AF_INET,
    .sin_addr.s_addr = ip4->daddr,
    .sin_port        = 0 /* ignored */
  };
  /* Single non-blocking attempt.  If the send would block, fails, or
     is short, the packet is dropped. */
  long const sent_sz = net_sock->ops->sendto( net_sock->sock, ip4, ip4_sz, MSG_DONTWAIT, fd_type_pun_const( &sa ), sizeof(struct sockaddr_in) );
  return sent_sz==(long)ip4_sz;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_net_fd_net_sock_h */
