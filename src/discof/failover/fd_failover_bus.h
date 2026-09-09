#ifndef HEADER_fd_src_discof_failover_fd_failover_bus_h
#define HEADER_fd_src_discof_failover_fd_failover_bus_h

/* The command bus between the admin tile and the failover tile is two
   tango links, admin_failov for requests and failov_admin for responses.
   The admin tile stays the only adminctl poller.  It forwards the
   failover commands here and parks the adminctl slot until the response
   frame arrives or its deadline passes, as it already does for snapshot
   creation on the replay tile.  Every frame holds one adminctl payload,
   so the payload structs in fd_adminctl.h are the wire format.  The
   admin tile consumes responses unreliably, so a stalled identity switch
   cannot backpressure the failover tile. */

#include "../admin/fd_adminctl.h"
#include "fd_failover_channel.h" /* fd_failover_clock */

#define FD_FAILOVER_BUS_STATUS_REQ  (1UL) /* admin to failov, fd_adminctl_failover_status_req_t */
#define FD_FAILOVER_BUS_STATUS_RESP (2UL) /* failov to admin, fd_adminctl_failover_status_resp_t */

struct fd_failover_bus_msg {
  ulong nonce;                              /* per request, echoed on the response */
  ulong result;                             /* FD_ADMINCTL_RESULT_* on responses */
  uchar payload[ FD_ADMINCTL_PAYLOAD_MAX ];
};

typedef struct fd_failover_bus_msg fd_failover_bus_msg_t;

#define FD_FAILOVER_BUS_MTU (sizeof(fd_failover_bus_msg_t))
FD_STATIC_ASSERT( sizeof(fd_failover_bus_msg_t)==272UL, bus_layout );

/* How long the admin tile waits for a response before answering the
   operator itself.  Measured on the monotonic clock, so an operator or
   NTP step cannot fake a timeout or hide one. */
#define FD_FAILOVER_BUS_DEADLINE_NANOS (2000000000L)

#endif /* HEADER_fd_src_discof_failover_fd_failover_bus_h */
