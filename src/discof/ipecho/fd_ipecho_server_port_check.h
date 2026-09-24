#ifndef HEADER_fd_src_discof_ipecho_fd_ipecho_server_port_check_h
#define HEADER_fd_src_discof_ipecho_fd_ipecho_server_port_check_h

/* Agave joiner nodes have a "port check" option, which is on by
   default. When this is enabled, the joiner node expects the
   entrypoint to send a UDP packet to every UDP port listed in the
   IpEchoServerMessage and complete a TCP handshake with every listed
   TCP port.

   fd_ipecho_server_port_check_t is a data structure for managing
   this on the server side. */

#include "../../util/fd_util_base.h"

#define FD_IPECHO_SERVER_PORT_CHECK_MAGIC (0xF17EDA2CE5190C4EUL) /* FIREDANCER IPECHO SERVER PORT CHECK V0 */

struct fd_ipecho_server_port_check;
typedef struct fd_ipecho_server_port_check fd_ipecho_server_port_check_t;

/* Result of an attempt to complete a port check TCP port handshake */
#define FD_IPECHO_SERVER_PORT_CHECK_TCP_CONNECTED       (0)
#define FD_IPECHO_SERVER_PORT_CHECK_TCP_FAILED          (1)
#define FD_IPECHO_SERVER_PORT_CHECK_TCP_TIMEOUT         (2)
#define FD_IPECHO_SERVER_PORT_CHECK_TCP_DROPPED         (3)
#define FD_IPECHO_SERVER_PORT_CHECK_TCP_REJECTED_PER_IP (4)
#define FD_IPECHO_SERVER_PORT_CHECK_TCP_EVICTED         (5)
#define FD_IPECHO_SERVER_PORT_CHECK_TCP_CNT             (6)

/* Total number of outgoing TCP connections the port checker can have
   in flight at any one time. This number is arbitrary. 2048 is what
   Agave uses. */

#define FD_IPECHO_SERVER_PORT_CHECK_CONN_MAX (2048UL)

struct fd_ipecho_server_port_check_metrics {
  ulong udp_sent;
  ulong tcp[ FD_IPECHO_SERVER_PORT_CHECK_TCP_CNT ];
  ulong active;
};

typedef struct fd_ipecho_server_port_check_metrics fd_ipecho_server_port_check_metrics_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_ipecho_server_port_check_align( void );

FD_FN_CONST ulong
fd_ipecho_server_port_check_footprint( void );

void *
fd_ipecho_server_port_check_new( void * shmem );

fd_ipecho_server_port_check_t *
fd_ipecho_server_port_check_join( void * shpc );

void
fd_ipecho_server_port_check_init( fd_ipecho_server_port_check_t * pc,
                                  uint                            address );

void
fd_ipecho_server_port_check_fini( fd_ipecho_server_port_check_t * pc );

/* fd_ipecho_server_port_check_close_all closes all TCP connections. */

void
fd_ipecho_server_port_check_close_all( fd_ipecho_server_port_check_t * pc );

/* fd_ipecho_server_port_check_udp sends a UDP packet to the given
   address:port, synchronously. We don't need any response from this
   packet, we just send it best-effort. Joiners that are expecting
   this packet will join this entrypoint once they have received a
   UDP packet for each UDP port they specify in the
   IpEchoServerMessage. If they do not receive the packet from us,
   the joining will fail and they will try again. */

void
fd_ipecho_server_port_check_udp( fd_ipecho_server_port_check_t * pc,
                                 uint                            ipv4,
                                 ushort                          port );

/* fd_ipecho_server_port_check_tcp begins a TCP connection to the given
   address:port, asynchronously. This function will return once the
   connection has started, but before the handshake has successfully
   completed. Once the handshake has successfully completed, or failed,
   the caller needs to call fd_ipecho_server_port_check_handle_event.

   This function returns an id identifying the connection (it fits in
   32 bits), which should be stored in the epoll data and passed back to
   fd_ipecho_server_port_check_conn_fd and
   fd_ipecho_server_port_check_handle_event. ULONG_MAX is returned if we
   didn't manage to start the connection successfully. */

ulong
fd_ipecho_server_port_check_tcp( fd_ipecho_server_port_check_t * pc,
                                 uint                            ipv4,
                                 ushort                          port,
                                 long                            now );

int
fd_ipecho_server_port_check_conn_fd( fd_ipecho_server_port_check_t * pc,
                                     ulong                           id );

/* fd_ipecho_server_port_check_handle_event handles an epoll event for
   the connection identified by id.  An event for a connection that
   has since finished, or whose slot has since been reused, is ignored. */

void
fd_ipecho_server_port_check_handle_event( fd_ipecho_server_port_check_t * pc,
                                          ulong                           id );

/* fd_ipecho_server_port_check_prune closes TCP connections that are
   taking too long to complete the handshake
   (FD_IPECHO_SERVER_PORT_CHECK_TIMEOUT_NS). */

void
fd_ipecho_server_port_check_prune( fd_ipecho_server_port_check_t * pc,
                                   long                            now );

fd_ipecho_server_port_check_metrics_t *
fd_ipecho_server_port_check_metrics( fd_ipecho_server_port_check_t * pc );

int
fd_ipecho_server_port_check_udp_sockfd( fd_ipecho_server_port_check_t * pc );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_ipecho_fd_ipecho_server_port_check_h */
