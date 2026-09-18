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

#define FD_FAILOVER_BUS_STATUS_REQ   (1UL) /* admin to failov, fd_adminctl_failover_status_req_t */
#define FD_FAILOVER_BUS_STATUS_RESP  (2UL) /* failov to admin, fd_adminctl_failover_status_resp_t */
#define FD_FAILOVER_BUS_CONTROL_REQ  (5UL) /* admin to failov, fd_adminctl_failover_control_t */
#define FD_FAILOVER_BUS_CONTROL_RESP (6UL) /* failov to admin, fd_adminctl_failover_control_resp_t */
#define FD_FAILOVER_BUS_SWITCH_REQ   (3UL) /* failov to admin, fd_failover_switch_req_t */
#define FD_FAILOVER_BUS_SWITCH_RESP  (4UL) /* admin to failov, fd_failover_switch_resp_t */

/* Which of the two keypairs the admin tile should switch to.  Only an
   id goes over the link, never the key itself, so the failover tile never
   sees the staked private key. */
#define FD_FAILOVER_SWITCH_KEY_JUNK   (0UL)
#define FD_FAILOVER_SWITCH_KEY_STAKED (1UL)
#define FD_FAILOVER_SWITCH_KEY_CNT    (2UL)

struct fd_failover_switch_req {
  ulong key; /* FD_FAILOVER_SWITCH_KEY_* */
};

typedef struct fd_failover_switch_req fd_failover_switch_req_t;

/* Sent when the switch is finished.  On success the old key is gone from
   every tile, and only then may the failover tile confirm the demotion to
   its peer. */
#define FD_FAILOVER_SWITCH_OK            (0UL)
#define FD_FAILOVER_SWITCH_ERR_KEY       (1UL) /* unknown key */
#define FD_FAILOVER_SWITCH_ERR_DISABLED  (2UL) /* failover is not enabled here */
#define FD_FAILOVER_SWITCH_ERR_CNT       (3UL)

struct fd_failover_switch_resp {
  ulong result;          /* FD_FAILOVER_SWITCH_* */
  ulong tower_watermark; /* the tower tile's output sequence at halt */
  uchar identity[ 32 ];  /* the identity now installed */
};

typedef struct fd_failover_switch_resp fd_failover_switch_resp_t;

FD_STATIC_ASSERT( sizeof(fd_failover_switch_req_t )<=FD_ADMINCTL_PAYLOAD_MAX, switch_req_fits  );
FD_STATIC_ASSERT( sizeof(fd_failover_switch_resp_t)<=FD_ADMINCTL_PAYLOAD_MAX, switch_resp_fits );

struct fd_failover_bus_msg {
  ulong nonce;                              /* per request, echoed on the response */
  ulong result;                             /* FD_ADMINCTL_RESULT_* on responses */
  uchar payload[ FD_ADMINCTL_PAYLOAD_MAX ];
};

typedef struct fd_failover_bus_msg fd_failover_bus_msg_t;

#define FD_FAILOVER_BUS_MTU (sizeof(fd_failover_bus_msg_t))
FD_STATIC_ASSERT( sizeof(fd_failover_bus_msg_t)==272UL, bus_layout );

/* How long the admin tile waits for a response before answering the
   operator itself.  Measured on the monotonic clock so a wall clock step
   cannot shorten or extend it. */
#define FD_FAILOVER_BUS_DEADLINE_NANOS (2000000000L)

#endif /* HEADER_fd_src_discof_failover_fd_failover_bus_h */
