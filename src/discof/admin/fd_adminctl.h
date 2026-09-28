#ifndef HEADER_fd_src_discof_admin_fd_adminctl_h
#define HEADER_fd_src_discof_admin_fd_adminctl_h

#include "../../util/fd_util_base.h"

/* fd_adminctl_t provides APIs for out-of-band command-and-control
   signals to the firedancer process via the admin tile.  It provides a
   ring of shared-memory command slots between command processes and the
   admin tile.

   Each slot is owned by one CAS word that packs state, process pid,
   request sequence number, and reservation timestamp.  Command
   processes send commands to the main app process via a reserve and
   publish scheme.  A call to fd_adminctl_reserve claims a command slot;
   the command process then has exclusive write access to writing the
   command payload.  The fd_adminctl_publish publishes the command to
   the app process and effectively transfers ownership of the slot to
   the app process.  The app process will poll for a command via
   fd_adminctl_poll, process the command, and send back a result via
   fd_adminctl_complete.  The command process receives the result via
   fd_adminctl_wait which blocks on the result.  At this point, the slot
   is free again and is free to be claimed by another command process.

   If a command process dies while it has ownership of a slot (after
   a reservation has been made, but before a publish OR while a command
   result is available but not consumed), then other command processes
   are free to claim the slot.  If for some reason the command process
   is hung, the caller will be responsible for cleaning up and killing
   the process.

   All input into fd_adminctl_t must be trusted.  If the adminctl memory
   layout changes, adminctl magic must be updated. */

#define FD_ADMINCTL_CMD_IDLE                   (0UL)
#define FD_ADMINCTL_CMD_ADD_AUTH_VOTER         (1UL)
#define FD_ADMINCTL_CMD_SET_IDENTITY           (2UL)
#define FD_ADMINCTL_CMD_GET_IDENTITY           (3UL)
#define FD_ADMINCTL_CMD_REMOVE_ALL_AUTH_VOTERS (4UL)
#define FD_ADMINCTL_CMD_SNAP_CREATE            (5UL)
#define FD_ADMINCTL_CMD_FAILOVER               (6UL)

#define FD_ADMINCTL_ALIGN       (8UL)
#define FD_ADMINCTL_PAYLOAD_MAX (256UL)
#define FD_ADMINCTL_SLOT_CNT    (4UL)

/* Shared command result codes. */
#define FD_ADMINCTL_RESULT_SUCCESS              (0UL)
#define FD_ADMINCTL_RESULT_UNKNOWN_COMMAND      (1UL)
#define FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH (2UL)
#define FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH    (3UL)
#define FD_ADMINCTL_RESULT_UNSUPPORTED          (4UL)

/* App-specific command result codes.
   NOTE: It is important these codes start at least 5UL. */

#define FD_ADD_AUTHORIZED_VOTER_RESULT_KEYPAIR_MISMATCH     (0x1001UL)
#define FD_ADD_AUTHORIZED_VOTER_RESULT_MAX_AUTH_VOTERS      (0x1002UL)
#define FD_ADD_AUTHORIZED_VOTER_RESULT_DUPLICATE_AUTH_VOTER (0x1003UL)

#define FD_SNAPSHOT_CREATE_RESULT_BUSY                      (0x2001UL)
#define FD_SNAPSHOT_CREATE_RESULT_NOT_READY                 (0x2003UL)
#define FD_SNAPSHOT_CREATE_RESULT_SLOT_IN_PAST              (0x2004UL)

#define FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH             (0x3001UL)

#define FD_FAILOVER_CONTROL_RESULT_BUSY              (0x4001UL) /* another failover command is waiting on the failover tile */
#define FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE      (0x4002UL) /* the failover tile did not respond in time */
#define FD_FAILOVER_CONTROL_RESULT_BAD_ROLE          (0x4003UL) /* promote on the active, demote on a standby */
#define FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS       (0x4004UL) /* a transition or key switch is running */
#define FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY      (0x4006UL) /* the bound peer cannot complete this handoff */
#define FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE       (0x4007UL) /* the authenticated peer holds the identity */
#define FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING   (0x4008UL) /* the peer has not responded to our handoff */
#define FD_FAILOVER_CONTROL_RESULT_TAKEN             (0x4009UL) /* the peer took our handoff, only a new local tenure clears this */
#define FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN       (0x400AUL) /* gossip has a fresh contact info for the staked identity from another host */
#define FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER    (0x400CUL) /* active has no eligible final vote state, see its local voting diagnostics */
#define FD_FAILOVER_CONTROL_RESULT_NO_ACTIVE_ADDRESS (0x400EUL) /* gossip has no address for the active */
#define FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED   (0x400FUL) /* unilateral promote cannot verify the peer, explicit fencing required */

struct fd_adminctl_add_auth_voter_v1 {
  ulong version; /* ==FD_ADMINCTL_ADD_AUTH_VOTER_PAYLOAD_VERSION */
  uchar keypair[ 64UL ];
};
typedef struct fd_adminctl_add_auth_voter_v1 fd_adminctl_add_auth_voter_t;
#define FD_ADMINCTL_ADD_AUTH_VOTER_PAYLOAD_VERSION (1UL)

struct fd_adminctl_snap_create_v1 {
  ulong version; /* ==FD_ADMINCTL_SNAP_CREATE_PAYLOAD_VERSION */
  ulong slot;    /* 0 to create a snapshot of the published root
                    immediately, else stop rooting at the first rooted
                    slot >= this slot and snapshot it */
};
typedef struct fd_adminctl_snap_create_v1 fd_adminctl_snap_create_t;
#define FD_ADMINCTL_SNAP_CREATE_PAYLOAD_VERSION (1UL)

struct fd_adminctl_set_identity_v1 {
  ulong version; /* ==FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION */
  uchar keypair[ 64UL ];
};
typedef struct fd_adminctl_set_identity_v1 fd_adminctl_set_identity_t;
#define FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION (1UL)

struct fd_adminctl_get_identity_req_v1 {
  ulong version; /* ==FD_ADMINCTL_GET_IDENTITY_PAYLOAD_VERSION */
};
typedef struct fd_adminctl_get_identity_req_v1 fd_adminctl_get_identity_req_t;

struct fd_adminctl_get_identity_resp_v1 {
  ulong version; /* ==FD_ADMINCTL_GET_IDENTITY_PAYLOAD_VERSION */
  uchar identity_pubkey[ 32UL ];
};
typedef struct fd_adminctl_get_identity_resp_v1 fd_adminctl_get_identity_resp_t;
#define FD_ADMINCTL_GET_IDENTITY_PAYLOAD_VERSION (1UL)

struct fd_adminctl_remove_all_auth_voters_v1 {
  ulong version; /* ==FD_ADMINCTL_REMOVE_ALL_AUTH_VOTERS_PAYLOAD_VERSION */
};
typedef struct fd_adminctl_remove_all_auth_voters_v1 fd_adminctl_remove_all_auth_voters_t;
#define FD_ADMINCTL_REMOVE_ALL_AUTH_VOTERS_PAYLOAD_VERSION (1UL)

/* Failover commands, forwarded to the failover tile. */
#define FD_ADMINCTL_FAILOVER_CMD_HANDOFF (0UL)
#define FD_ADMINCTL_FAILOVER_CMD_DEMOTE  (1UL)
#define FD_ADMINCTL_FAILOVER_CMD_PROMOTE (2UL)
#define FD_ADMINCTL_FAILOVER_CMD_STATUS  (3UL)
#define FD_ADMINCTL_FAILOVER_CMD_CNT     (4UL)

static inline char const *
fd_adminctl_failover_cmd_name( ulong cmd ) {
  switch( cmd ) {
    case FD_ADMINCTL_FAILOVER_CMD_HANDOFF: return "handoff";
    case FD_ADMINCTL_FAILOVER_CMD_DEMOTE:  return "demote";
    case FD_ADMINCTL_FAILOVER_CMD_PROMOTE: return "promote";
    case FD_ADMINCTL_FAILOVER_CMD_STATUS:  return "status";
    default:                               return "unknown";
  }
}

/* The command as the operator types it, `failover promote` sends
   HANDOFF and `failover promote --force` sends PROMOTE. */
static inline char const *
fd_adminctl_failover_cmd_typed( ulong cmd ) {
  return cmd==FD_ADMINCTL_FAILOVER_CMD_HANDOFF ? "promote" : fd_adminctl_failover_cmd_name( cmd );
}

#define FD_ADMINCTL_FAILOVER_FLAG_YES   (1UL) /* confirmation only, does not authorize peer or history overrides */
#define FD_ADMINCTL_FAILOVER_FLAG_FORCE (2UL) /* --force, bypass peer guards and accept incomplete or empty vote history */

struct fd_adminctl_failover_req_v1 {
  ulong  version; /* ==FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION */
  ulong  cmd;     /* FD_ADMINCTL_FAILOVER_CMD_* */
  ulong  flags;   /* FD_ADMINCTL_FAILOVER_FLAG_* */
  uint   addr;    /* HANDOFF only, the active to dial in network byte order, 0 to find it in gossip */
  ushort port;    /* HANDOFF only, the port to dial it on in host byte order, 0 for our own listen port */
  uchar  reserved[ 2 ];
};
typedef struct fd_adminctl_failover_req_v1 fd_adminctl_failover_req_t;

struct fd_adminctl_failover_control_resp_v1 {
  ulong version;    /* ==FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION */
  uchar role;       /* FD_FAILOVER_ROLE_* after the command */
  uchar action;     /* controller action after the command */
  uchar reserved[ 6 ];
  ulong handoff_id; /* the handoff an accepted promote or demote opened or resumed, 0 none */
};
typedef struct fd_adminctl_failover_control_resp_v1 fd_adminctl_failover_control_resp_t;
#define FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION (1UL)

FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_req_t         )==32UL, failover_req_v1_layout          );
FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_control_resp_t)==24UL, failover_control_resp_v1_layout );

/* What the failover controller is doing right now.  It lives only in
   memory, a restart boots a standby with nothing in flight. */
#define FD_FAILOVER_ACTION_IDLE                (0UL) /* no local transition is running */
#define FD_FAILOVER_ACTION_DEMOTE_SWITCH       (1UL) /* waiting for the junk key to be installed */
#define FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK     (2UL) /* DEMOTED sent, waiting for the peer */
#define FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY (3UL) /* waiting for replay to reach the tower tip */
#define FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT  (4UL) /* waiting for the tower tile to adopt */
#define FD_FAILOVER_ACTION_PROMOTE_SWITCH      (5UL) /* waiting for the staked key to be installed */
#define FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER   (6UL) /* requesting the active's final tower */
#define FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT (7UL) /* waiting for the old active to record our response */
#define FD_FAILOVER_ACTION_DEMOTE_DRAIN        (8UL) /* junk key installed, waiting for the tower to drain */
#define FD_FAILOVER_ACTION_CNT                 (9UL) /* number of controller states */

/* Where a promotion takes its tower from, best first */
#define FD_FAILOVER_SOURCE_PEER         (0UL) /* the tower the peer's DEMOTED gave us */
#define FD_FAILOVER_SOURCE_VOTE_ACCOUNT (1UL) /* automatic fallback to the vote account, or forced empty history */
#define FD_FAILOVER_SOURCE_CNT          (2UL)

/* How our last handoff ended, the one we requested or the one we gave */
#define FD_FAILOVER_HANDOFF_NONE       (0UL) /* nothing requested or sent */
#define FD_FAILOVER_HANDOFF_PENDING    (1UL) /* requested or sent, no answer yet */
#define FD_FAILOVER_HANDOFF_TAKEN      (2UL) /* the peer acked it */
#define FD_FAILOVER_HANDOFF_DECLINED   (3UL) /* the peer refused it */
#define FD_FAILOVER_HANDOFF_RESTARTED  (4UL) /* the peer came back with a new boot_id */
#define FD_FAILOVER_HANDOFF_CANCELLED  (5UL) /* `failover promote --force` stopped waiting for the peer */
#define FD_FAILOVER_HANDOFF_NOT_ACTIVE (6UL) /* the machine we dialed was a standby */
#define FD_FAILOVER_HANDOFF_CNT        (7UL) /* number of handoff outcomes */

/* `failover status`, provided by the failover tile.  Only what the
   failover controller knows, nothing RPC, gossip, metrics or the logs
   already show. */
struct fd_adminctl_failover_status_resp_v1 {
  ulong  version;         /* ==FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION */
  uchar  enabled;         /* 0 when failover is off, nothing else is set then */
  uchar  role;            /* FD_FAILOVER_ROLE_* */
  uchar  action;          /* FD_FAILOVER_ACTION_* */
  uchar  stuck;           /* a transition failed or is overdue */
  uchar  link_state;      /* FD_FAILOVER_SESSION_* */
  uchar  peer_role_valid; /* the open handoff authenticated a peer */
  uchar  peer_role;       /* FD_FAILOVER_ROLE_* from HELLO or the handoff result */
  uchar  handoff_result;  /* FD_FAILOVER_HANDOFF_* of our last handoff */
  ulong  peer_boot_id;    /* boot_id of the last peer we paired with, 0 none */
  uint   peer_addr;       /* the address we dial, from `failover promote --address` or the active's from gossip, 0 none */
  ushort peer_port;       /* the failover port we dial it on, in host byte order */
  uchar  promote_source;  /* FD_FAILOVER_SOURCE_* a promote would adopt now */
  uchar  peer_addr_cmd;   /* peer_addr is from `failover promote --address`, else it came from gossip */
  ulong  handoff_id;      /* id of our last handoff, 0 none */
  ulong  promote_floor;   /* coverage floor a promote has to reach, ULONG_MAX none */
  ulong  promote_result;  /* the refusal a promote without --force would get now */
  uchar  mode;            /* FD_FAILOVER_MODE_* the validator runs */
  uchar  request_paused;  /* our handoff request stopped at its deadline, `failover promote` resumes it */
  uchar  reserved[ 6 ];
};
typedef struct fd_adminctl_failover_status_resp_v1 fd_adminctl_failover_status_resp_t;

FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_status_resp_t)==64UL, failover_status_resp_v1_layout );
FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_status_resp_t)<=FD_ADMINCTL_PAYLOAD_MAX, failover_status_resp_fits );

/* fd_adminctl_failover_status_resp_init stamps the version and every
   unknown field.  The admin tile, for a validator with failover off,
   and the failover tile, before it fills the live values, both start
   here. */

static inline void
fd_adminctl_failover_status_resp_init( fd_adminctl_failover_status_resp_t * resp ) {
  fd_memset( resp, 0, sizeof(*resp) );
  resp->version       = FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION;
  resp->promote_floor = ULONG_MAX;
}

typedef struct fd_adminctl_private fd_adminctl_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_adminctl_align( void );

FD_FN_CONST ulong
fd_adminctl_footprint( void );

void *
fd_adminctl_new( void * shmem );

fd_adminctl_t *
fd_adminctl_join( void * shadminctl );

/* fd_adminctl_reserve claims a command slot and returns an identifier
   for the command reservation (index into the command buffer).  Returns
   ULONG_MAX if every slot is busy or reserved.  If a reservation is
   successful, payload_out receives a pointer into shared memory valid
   until publish completes or the reservation is abandoned by process
   death. */

ulong
fd_adminctl_reserve( fd_adminctl_t * adminctl,
                     void **         payload_out,
                     ulong *         payload_max_out );

/* fd_adminctl_publish validates the reservation and publishes the
   command to the admin tile.  This should only be called by a command
   process after a successful reservation.  After this function is
   called, the ownership of the slot is transferred to the app process.
   If a publish is made after a reservation, it will always succeed. */

void
fd_adminctl_publish( fd_adminctl_t * adminctl,
                     ulong           slot_id,
                     ulong           cmd_id,
                     ulong           payload_sz );

/* fd_adminctl_wait waits for the command identified by slot_id to
   complete and returns the command result.  This command should only be
   called by a command process after a successful publish.  After the
   function returns, the command slot will be reclaimed.  The command
   process result is returned. */

ulong
fd_adminctl_wait( fd_adminctl_t * adminctl,
                  ulong           slot_id );

/* fd_adminctl_wait_response is fd_adminctl_wait for commands that also
   return a response payload.  Before the slot is reclaimed, up to
   resp_max bytes of the response payload are copied into resp and the
   response payload size is stored in resp_sz_out. */

ulong
fd_adminctl_wait_response( fd_adminctl_t * adminctl,
                           ulong           slot_id,
                           void *          resp,
                           ulong           resp_max,
                           ulong *         resp_sz_out );

/* fd_adminctl_poll checks a command slot at a time and returns the
   command id and payload if a command is available.  The command is now
   ready to be processed by the app process.  If no command is
   available, the function returns FD_ADMINCTL_CMD_IDLE.  Under the
   hood, it checks one slot at a time and advances the poll cursor.
   This function should be called repeatedly by only the main app
   process. */

ulong
fd_adminctl_poll( fd_adminctl_t * adminctl,
                  ulong *         slot_id_out,
                  void **         payload_out,
                  ulong *         payload_sz_out );

/* fd_adminctl_complete publishes the result for the command that has
   finished being processed.  It should only be called by the app
   process after the command has been processed. */

void
fd_adminctl_complete( fd_adminctl_t * adminctl,
                      ulong           slot_id,
                      ulong           result );

/* fd_adminctl_complete_response is fd_adminctl_complete for commands
   that also return a response payload.  The request payload is zeroed
   and replaced with the resp_sz bytes at resp before the result is
   published. */

void
fd_adminctl_complete_response( fd_adminctl_t * adminctl,
                               ulong           slot_id,
                               ulong           result,
                               void const *    resp,
                               ulong           resp_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_admin_fd_adminctl_h */
