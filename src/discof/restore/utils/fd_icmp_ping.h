#ifndef HEADER_fd_src_discof_restore_utils_fd_icmp_h
#define HEADER_fd_src_discof_restore_utils_fd_icmp_h

#include "../../../util/net/fd_net_headers.h"

/* Helper functions to send and receive icmp pings */

/* fd_icmp_send_ping connects an open socket file descriptor to the
   given dest address and sends an icmp echo packet, blocking if needed.
   Takes a pointer to an unused socket file descriptor and a pointer to
   a destination address. Returns 0 on success and -1 on failure.  Upon
   success, ping_send_time_nanos is set to the software timestamp right
   before send is called. */
int
fd_icmp_send_ping( int                   sockfd,
                   fd_ip4_port_t const * dest,
                   ushort                sequence,
                   long *                ping_send_time_nanos );

/* fd_icmp_recv_ping receives an icmp echo reply packet from the socket
   file descriptor in a non-blocking manner.  Assumes that
   fd_icmp_send_ping was previously called for the given socket file
   descriptor and dest address. The socket file descriptor must be a
   valid socket.  Returns 0 on success and -1 on failure. Upon success,
   ping_recv_time_nanos is set to the software timestamp right after
   recv is called. */
int
fd_icmp_recv_ping_resp( int                   sockfd,
                        fd_ip4_port_t const * dest,
                        ushort                sequence,
                        long *                ping_recv_time_nanos );

#endif /* HEADER_fd_src_discof_restore_utils_fd_icmp_h */
