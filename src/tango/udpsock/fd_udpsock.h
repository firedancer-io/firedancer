#ifndef HEADER_fd_src_tango_udpsock_fd_udpsock_h
#define HEADER_fd_src_tango_udpsock_fd_udpsock_h

#include "../fd_tango_base.h"
#include "../aio/fd_aio.h"

/* fd_udpsock is an unprivileged sockets-based driver for UDP apps.
   Internally uses AF_INET SOCK_DGRAM UDP sockets in O_NONBLOCK mode.

   Implements the fd_aio abstraction and mocks Ethernet & IP headers to
   permit operation over localhost.

   Very hacky, low performance, and unsuitable for production use.
   Convenient for debugging as they are compatible with the lo interface.
   Only supports single-threaded operation for now. */

#define FD_UDPSOCK_ALIGN (64UL)

struct fd_udpsock;
typedef struct fd_udpsock fd_udpsock_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_udpsock_align( void );

FD_FN_CONST ulong
fd_udpsock_footprint( ulong mtu,
                      ulong rx_pkt_cnt,
                      ulong tx_pkt_cnt );

/* fd_udpsock_new prepares a new memory region with matching alignment
   and footprint for storing an fd_udpsock_t object.  Returns shmem on
   success and NULL on failure.  The caller is not joined on return. */

void *
fd_udpsock_new( void * shmem,
                ulong  mtu,
                ulong  rx_pkt_cnt,
                ulong  tx_pkt_cnt );

/* fd_udpsock_join joins the caller to the given initialized memory
   region using the given UDP socket file descriptor. */

fd_udpsock_t *
fd_udpsock_join( void * shsock,
                 int    fd );

/* fd_udpsock_leave undoes a local join to the fd_udpsock_t object. */

void *
fd_udpsock_leave( fd_udpsock_t * sock );

/* fd_udpsock_delete releases ownership a memory region back to the
   caller. */

void *
fd_udpsock_delete( void * shsock );

void
fd_udpsock_set_rx( fd_udpsock_t *   sock,
                   fd_aio_t const * aio );

FD_FN_CONST fd_aio_t const *
fd_udpsock_get_tx( fd_udpsock_t * sock );

/* fd_udpsock_service services aio callbacks for incoming packets and
   handles completions for tx requests. */

void
fd_udpsock_service( fd_udpsock_t * sock );

FD_FN_PURE uint
fd_udpsock_get_ip4_address( fd_udpsock_t const * sock );

FD_FN_PURE uint
fd_udpsock_get_listen_port( fd_udpsock_t const * sock );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_udpsock_fd_udpsock_h */
