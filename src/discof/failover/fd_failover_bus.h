#ifndef HEADER_fd_src_discof_failover_fd_failover_bus_h
#define HEADER_fd_src_discof_failover_fd_failover_bus_h

/* The admin and failover tiles talk over two links, admin_failov and
   failov_admin.  The admin tile stays the only adminctl poller.  It
   forwards failover commands with a nonce and parks the adminctl slot
   until the answer comes back or the deadline passes.  The failover
   tile asks for identity switches the same way.  Every frame is one
   fd_failover_bus_msg_t.  The admin tile reads failov_admin unreliably,
   so a stalled identity switch cannot backpressure the failover tile. */

#include "../admin/fd_adminctl.h"

#define FD_FAILOVER_BUS_SWITCH_REQ   (1UL) /* failov to admin, fd_failover_switch_req_t */
#define FD_FAILOVER_BUS_SWITCH_RESP  (2UL) /* admin to failov, fd_failover_switch_resp_t */
#define FD_FAILOVER_BUS_CONTROL_REQ  (3UL) /* admin to failov, fd_adminctl_failover_control_t */
#define FD_FAILOVER_BUS_CONTROL_RESP (4UL) /* failov to admin, fd_adminctl_failover_control_resp_t */
#define FD_FAILOVER_BUS_STATUS_REQ   (5UL) /* admin to failov, fd_adminctl_failover_status_req_t */
#define FD_FAILOVER_BUS_STATUS_RESP  (6UL) /* failov to admin, fd_adminctl_failover_status_resp_t */

/* Only the public key goes over the bus.  The sign tile only accepts
   a keypair it loaded at boot. */
struct fd_failover_switch_req {
  uchar identity[ 32 ]; /* public key of the identity to install */
};

typedef struct fd_failover_switch_req fd_failover_switch_req_t;

#define FD_FAILOVER_SWITCH_OK           (0UL)
#define FD_FAILOVER_SWITCH_ERR_DISABLED (1UL) /* failover is off here */

/* Sent once every tile has switched. */
struct fd_failover_switch_resp {
  ulong result;          /* FD_FAILOVER_SWITCH_* */
  ulong tower_watermark; /* the tower keyswitch result, its output sequence at the halt */
  uchar identity[ 32 ];  /* the identity now installed */
};

typedef struct fd_failover_switch_resp fd_failover_switch_resp_t;

FD_STATIC_ASSERT( sizeof(fd_failover_switch_req_t )<=FD_ADMINCTL_PAYLOAD_MAX, switch_req_fits  );
FD_STATIC_ASSERT( sizeof(fd_failover_switch_resp_t)<=FD_ADMINCTL_PAYLOAD_MAX, switch_resp_fits );

struct fd_failover_bus_msg {
  ulong nonce;                              /* per request, echoed on the answer */
  ulong result;                             /* on answers, FD_FAILOVER_SWITCH_* or an adminctl result */
  uchar payload[ FD_ADMINCTL_PAYLOAD_MAX ];
};

typedef struct fd_failover_bus_msg fd_failover_bus_msg_t;

#define FD_FAILOVER_BUS_MTU (sizeof(fd_failover_bus_msg_t))
FD_STATIC_ASSERT( sizeof(fd_failover_bus_msg_t)==272UL, bus_layout );

/* How long the admin tile waits for the failover tile to answer a
   command before it answers the operator itself. */
#define FD_FAILOVER_BUS_DEADLINE_NANOS (2000000000L)

#endif /* HEADER_fd_src_discof_failover_fd_failover_bus_h */
