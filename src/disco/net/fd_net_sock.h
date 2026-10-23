#ifndef HEADER_fd_src_disco_net_fd_net_sock_h
#define HEADER_fd_src_disco_net_fd_net_sock_h

#include "../fd_disco_base.h"
#include "../../util/net/fd_ip4.h"

#include <sys/socket.h>
#include <netinet/in.h>

/* fd_net_sock_ops_t is the syscall interface used by fd_net_sock.
   Signatures and semantics match libc. Tests substitute mocks. */
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

/* fd_net_sock_init initializes net_sock and opens a blocking
   send-only IPPROTO_RAW socket. It is not bound to an interface and
   relies on the kernel to route packets. Returns net_sock on success
   and NULL on error with errno set. */
fd_net_sock_t *
fd_net_sock_init( fd_net_sock_t * net_sock );

/* Same as fd_net_sock_init but includes specifically configured ops.
   ops and each of its members must be non-NULL. */
fd_net_sock_t *
fd_net_sock_init_ops( fd_net_sock_t *           net_sock,
                      fd_net_sock_ops_t const * ops );

/* fd_net_sock_send sends one packet on net_sock with a blocking
   sendto. ip4 points to the beginning of an IPv4 header. ip4_sz is
   the size of the IP header and payload. The L2 header will be
   constructed by the kernel. The destination is ip4->daddr. Returns
   1 if the whole packet was sent and 0 otherwise (error or short
   write). */
int
fd_net_sock_send( fd_net_sock_t *      net_sock,
                  fd_ip4_hdr_t const * ip4,
                  ulong                ip4_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_net_fd_net_sock_h */
