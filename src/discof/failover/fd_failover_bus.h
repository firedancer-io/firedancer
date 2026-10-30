#ifndef HEADER_fd_src_discof_failover_fd_failover_bus_h
#define HEADER_fd_src_discof_failover_fd_failover_bus_h

/* The admin and failover tiles talk over the admin_failov and
   failov_admin links.  The admin tile is the only adminctl poller.  It
   forwards failover commands with a nonce and parks the adminctl slot
   until the response comes back, which for a handoff or promotion is
   when its outcome is known.  The failover tile asks for identity
   switches the same way.  Every frame is one fd_failover_bus_msg_t.
   Both links are reliable, so no frame is lost behind a busy tile. */

#include "../admin/fd_adminctl.h"

#define FD_FAILOVER_BUS_PAYLOAD_MAX (256UL)

/* bus message types */

#define FD_FAILOVER_BUS_SWITCH_REQ      (1UL) /* failov to admin: fd_failover_switch_req_t */
#define FD_FAILOVER_BUS_SWITCH_RESP     (2UL) /* admin to failov: fd_failover_switch_resp_t */
#define FD_FAILOVER_BUS_REQUEST         (3UL) /* admin to failov: fd_adminctl_failover_req_t */
#define FD_FAILOVER_BUS_RESPONSE        (4UL) /* failov to admin: the result of the command with the corresponding nonce and payload */
#define FD_FAILOVER_BUS_OPERATOR_ACTION (5UL) /* admin to failov: fd_failover_operator_t, set-identity ran */
#define FD_FAILOVER_BUS_STEP            (6UL) /* failov to admin: a step of the command with that nonce, a cstr payload */

#define FD_FAILOVER_BUS_STEP_MAX (FD_ADMINCTL_STEP_MAX)

/* result codes */

#define FD_FAILOVER_SWITCH_OK                   (0UL)
#define FD_FAILOVER_SWITCH_ERR_DISABLED         (1UL)
#define FD_FAILOVER_SWITCH_ERR_STALE            (2UL)
#define FD_FAILOVER_SWITCH_ERR_AUTHORIZED_VOTER (3UL) /* the target is an authorized voter, nothing switched */

/* bus message structs */

struct fd_failover_operator {
  ulong epoch;
  uchar identity[ 32 ];
  uchar failover_identity[ 32 ];
};
typedef struct fd_failover_operator fd_failover_operator_t;
FD_STATIC_ASSERT( sizeof(fd_failover_operator_t)<=FD_FAILOVER_BUS_PAYLOAD_MAX, operator_fits );

struct fd_failover_switch_req {
  uchar identity[ 32 ]; /* public key of the identity to install */
  ulong epoch;
};
typedef struct fd_failover_switch_req fd_failover_switch_req_t;
FD_STATIC_ASSERT( sizeof(fd_failover_switch_req_t)<=FD_FAILOVER_BUS_PAYLOAD_MAX, switch_req_fits );

struct fd_failover_switch_resp {
  ulong                  result;
  ulong                  history_watermark;
  fd_failover_operator_t operator;
};
typedef struct fd_failover_switch_resp fd_failover_switch_resp_t;
FD_STATIC_ASSERT( sizeof(fd_failover_switch_resp_t)<=FD_FAILOVER_BUS_PAYLOAD_MAX, switch_resp_fits );

/* bus message framing */

struct fd_failover_bus_msg {
  ulong nonce;  /* per request, echoed on the response */
  ulong result; /* the adminctl result for command responses */
  uchar payload[ FD_FAILOVER_BUS_PAYLOAD_MAX ];
};
typedef struct fd_failover_bus_msg fd_failover_bus_msg_t;

#define FD_FAILOVER_BUS_MTU (sizeof(fd_failover_bus_msg_t))
FD_STATIC_ASSERT( sizeof(fd_failover_bus_msg_t)==272UL, bus_layout );

FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_req_t)<=FD_FAILOVER_BUS_PAYLOAD_MAX, command_fits );
FD_STATIC_ASSERT( FD_FAILOVER_BUS_STEP_MAX<=FD_FAILOVER_BUS_PAYLOAD_MAX, step_fits );

#endif /* HEADER_fd_src_discof_failover_fd_failover_bus_h */
