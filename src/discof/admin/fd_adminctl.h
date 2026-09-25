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
#define FD_ADMINCTL_CMD_FAILOVER_STATUS        (6UL)
#define FD_ADMINCTL_CMD_FAILOVER_CONTROL       (7UL)

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

struct fd_adminctl_failover_status_req_v1 {
  ulong version;  /* ==FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION */
  ulong peer_idx; /* which pool peer to report, in member list order without this machine */
};
typedef struct fd_adminctl_failover_status_req_v1 fd_adminctl_failover_status_req_t;

struct fd_adminctl_failover_status_resp_v1 {
  ulong version; /* ==FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION */
  uchar enabled;
  uchar role;
  uchar link_state;           /* FD_FAILOVER_SESSION_* of the reported peer */
  uchar peer_role;
  uchar peer_status_valid;
  uchar pool_healthy;        /* 1 when readiness_reason is POOL_HEALTHY */
  uchar readiness_reason;    /* FD_FAILOVER_READINESS_* */
  uchar member_cnt;          /* pool size including this machine */
  ulong term;
  ulong peer_term;
  uint  status;
  uint  peer_status;
  uchar flags;
  uchar peer_flags;
  uchar self_idx;            /* this machine's place in the member list */
  uchar peer_idx;            /* the reported peer, in member list order without this machine */
  uchar peers_paired;        /* peers with an authenticated session right now */
  uchar reserved[ 3 ];
  ulong peer_status_age_nanos;
  ulong replication_lag_slots; /* ULONG_MAX until measured */
  ulong rtt_nanos;             /* 0 until measured */
  ulong replay_slot;           /* ULONG_MAX until observed */
  ulong root_slot;
  ulong turbine_slot;
  ulong next_leader_slot;
  ulong last_vote_slot;
  ulong peer_replay_slot;
  ulong peer_root_slot;
  ulong peer_turbine_slot;
  ulong peer_next_leader_slot;
  ulong peer_last_vote_slot;
  ulong frames_sent;
  ulong frames_received;
  ulong tls_failures;
  ulong wire_failures;
  ulong hello_rejections;
  ulong connection_attempts;
  ulong sessions_paired;
  ulong pending_handshakes;
  ulong admission_drops;
  ulong handshake_timeouts;
};
typedef struct fd_adminctl_failover_status_resp_v1 fd_adminctl_failover_status_resp_t;
#define FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION (1UL)

#define FD_FAILOVER_READINESS_POOL_HEALTHY      (0U)
#define FD_FAILOVER_READINESS_LINK_DOWN         (1U)
#define FD_FAILOVER_READINESS_STATUS_STALE      (2U)
#define FD_FAILOVER_READINESS_ROLE_CONFLICT     (3U)
#define FD_FAILOVER_READINESS_ACTIVE_UNHEALTHY  (4U)
#define FD_FAILOVER_READINESS_STANDBY_UNHEALTHY (5U)
#define FD_FAILOVER_READINESS_STANDBY_BEHIND    (6U)
#define FD_FAILOVER_READINESS_CNT               (8U)

#define FD_FAILOVER_READINESS_DISABLED          (7U)

/* handoff and drill talk to the peer, demote and promote are local, pause
   and resume block and unblock transitions, clear lowers the stuck flag
   once the installed identity is proved to match the record, reclaim asks
   the peer to stand down so a holder that restarted may take the identity
   back. */
#define FD_ADMINCTL_FAILOVER_CMD_HANDOFF (0UL)
#define FD_ADMINCTL_FAILOVER_CMD_DRILL   (1UL)
#define FD_ADMINCTL_FAILOVER_CMD_DEMOTE  (2UL)
#define FD_ADMINCTL_FAILOVER_CMD_PROMOTE (3UL)
#define FD_ADMINCTL_FAILOVER_CMD_PAUSE   (4UL)
#define FD_ADMINCTL_FAILOVER_CMD_RESUME  (5UL)
#define FD_ADMINCTL_FAILOVER_CMD_CLEAR   (6UL) /* clear stuck once the installed identity is proved to match the record */
#define FD_ADMINCTL_FAILOVER_CMD_RECLAIM (7UL) /* ask the peer to stand down so a holder that restarted may take the identity back */
#define FD_ADMINCTL_FAILOVER_CMD_CNT     (8UL)

struct fd_adminctl_failover_control_v1 {
  ulong version; /* ==FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION */
  ulong cmd;     /* FD_ADMINCTL_FAILOVER_CMD_* */
  uchar force;   /* promote even if the peer is unreachable, still needs its
                    demotion confirmation */
  uchar reserved[ 7 ];
  uchar staked_pubkey[ 32 ]; /* required with force, as a safety check */
};

typedef struct fd_adminctl_failover_control_v1 fd_adminctl_failover_control_t;

struct fd_adminctl_failover_control_resp_v1 {
  ulong version;
  ulong term;
  uchar state; /* FD_FAILOVER_STATE_* after the command was applied */
  uchar role;  /* FD_FAILOVER_ROLE_* */
  uchar paused;
  uchar reserved[ 5 ];
};

typedef struct fd_adminctl_failover_control_resp_v1 fd_adminctl_failover_control_resp_t;
#define FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION (1UL)

/* failover-control result codes, they say why a command was refused. */
#define FD_FAILOVER_CONTROL_RESULT_DISABLED      (0x5001UL)
#define FD_FAILOVER_CONTROL_RESULT_BAD_ROLE      (0x5002UL)
#define FD_FAILOVER_CONTROL_RESULT_NOT_PAIRED    (0x5003UL)
#define FD_FAILOVER_CONTROL_RESULT_BUSY          (0x5004UL)
#define FD_FAILOVER_CONTROL_RESULT_PAUSED        (0x5005UL)
#define FD_FAILOVER_CONTROL_RESULT_NO_EVIDENCE   (0x5006UL)
#define FD_FAILOVER_CONTROL_RESULT_BAD_IDENTITY  (0x5007UL)
#define FD_FAILOVER_CONTROL_RESULT_UNSUPPORTED   (0x5008UL)
#define FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY  (0x5009UL) /* the spare's last status says it cannot take the identity */
#define FD_FAILOVER_CONTROL_RESULT_IDENTITY_MISMATCH (0x500AUL) /* the installed identity disagrees with the recorded role */
#define FD_FAILOVER_CONTROL_RESULT_TOWER_ROLLBACK (0x500BUL) /* the confirmation's final tower is older than the one the peer streamed */
#define FD_FAILOVER_CONTROL_RESULT_PRECONDITION  (0x500DUL) /* a handoff pre-check failed, the status names the reason */

FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_control_t     )<=FD_ADMINCTL_PAYLOAD_MAX, failover_control_req_fits  );
FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_control_resp_t)<=FD_ADMINCTL_PAYLOAD_MAX, failover_control_resp_fits );
FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_control_t     )==56UL, failover_control_req_v1_layout  );
FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_control_resp_t)==24UL, failover_control_resp_v1_layout );

#define FD_FAILOVER_STATUS_RESULT_BUSY          (0x4001UL)
#define FD_FAILOVER_STATUS_RESULT_UNRESPONSIVE  (0x4002UL)
#define FD_FAILOVER_STATUS_RESULT_NO_SUCH_PEER  (0x4003UL)

/* fd_adminctl_failover_status_resp_init stamps the version and every
   unknown field.  Both the admin tile, for a validator with failover
   off, and the failover tile, before it fills the live values, start
   here. */

static inline void
fd_adminctl_failover_status_resp_init( fd_adminctl_failover_status_resp_t * resp ) {
  fd_memset( resp, 0, sizeof(*resp) );
  resp->version               = FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION;
  resp->readiness_reason      = (uchar)FD_FAILOVER_READINESS_DISABLED;
  resp->peer_status_age_nanos = ULONG_MAX;
  resp->replication_lag_slots = ULONG_MAX;
  resp->replay_slot           = ULONG_MAX;
  resp->root_slot             = ULONG_MAX;
  resp->turbine_slot          = ULONG_MAX;
  resp->next_leader_slot      = ULONG_MAX;
  resp->last_vote_slot        = ULONG_MAX;
  resp->peer_replay_slot      = ULONG_MAX;
  resp->peer_root_slot        = ULONG_MAX;
  resp->peer_turbine_slot     = ULONG_MAX;
  resp->peer_next_leader_slot = ULONG_MAX;
  resp->peer_last_vote_slot   = ULONG_MAX;
}

FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_status_req_t )<=FD_ADMINCTL_PAYLOAD_MAX, failover_status_req_fits );
FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_status_resp_t)<=FD_ADMINCTL_PAYLOAD_MAX, failover_status_resp_fits );
FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_status_req_t )==16UL, failover_status_req_v1_layout );
FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_status_resp_t)==232UL, failover_status_resp_v1_layout );

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
