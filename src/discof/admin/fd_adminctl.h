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
#define FD_ADMINCTL_CMD_FAILOVER_PROMOTE       (6UL)

#define FD_ADMINCTL_ALIGN       (8UL)
#define FD_ADMINCTL_PAYLOAD_MAX (32768UL)
#define FD_ADMINCTL_SLOT_CNT    (4UL)
#define FD_ADMINCTL_STEP_MAX    (256UL) /* a step line, with its NUL */
#define FD_ADMINCTL_STEP_CNT    (16UL)  /* step lines a slot keeps for its command process */

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
#define FD_SET_IDENTITY_RESULT_INVALID_VOTE_HISTORY         (0x3002UL)
#define FD_SET_IDENTITY_RESULT_SAME_IDENTITY                (0x3003UL)
#define FD_SET_IDENTITY_RESULT_AUTHORIZED_VOTER             (0x3004UL)

#define FD_FAILOVER_CONTROL_RESULT_BUSY              (0x4001UL)
#define FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER      (0x4002UL)
#define FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS       (0x4003UL)
#define FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY      (0x4004UL)
#define FD_FAILOVER_CONTROL_RESULT_PEER_HOLDS        (0x4005UL)
#define FD_FAILOVER_CONTROL_RESULT_NO_FINAL_HISTORY  (0x4006UL)
#define FD_FAILOVER_CONTROL_RESULT_NO_HOLDER_ADDRESS (0x4007UL)
#define FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND     (0x4008UL)
#define FD_FAILOVER_CONTROL_RESULT_TIMEOUT           (0x4009UL)
#define FD_FAILOVER_CONTROL_RESULT_PEER_RESTARTED    (0x400AUL)
#define FD_FAILOVER_CONTROL_RESULT_ADOPTION_FAILED   (0x400BUL)
#define FD_FAILOVER_CONTROL_RESULT_SWITCH_FAILED     (0x400CUL)
#define FD_FAILOVER_CONTROL_RESULT_HOLDS_OTHER       (0x400DUL)
#define FD_FAILOVER_CONTROL_RESULT_IDENTITY_CHANGED  (0x400EUL)

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

struct fd_adminctl_set_identity_v4 {
  ulong version;           /* ==FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION */
  uchar keypair[ 64UL ];
  ulong vote_history_slot; /* scanned by the command from the vote history file, 0 if none was provided */
};
typedef struct fd_adminctl_set_identity_v4 fd_adminctl_set_identity_t;
FD_STATIC_ASSERT( sizeof(fd_adminctl_set_identity_t)<=FD_ADMINCTL_PAYLOAD_MAX, set_identity );
#define FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION (4UL)

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
#define FD_ADMINCTL_FAILOVER_CMD_HANDOFF   (0UL)
#define FD_ADMINCTL_FAILOVER_CMD_PROMOTE   (1UL)
#define FD_ADMINCTL_FAILOVER_CMD_PREFLIGHT (2UL)
#define FD_ADMINCTL_FAILOVER_CMD_CNT       (3UL)

/* The command as the operator typed it. */
static inline char const *
fd_adminctl_failover_cmd_typed( ulong cmd ) {
  return cmd<FD_ADMINCTL_FAILOVER_CMD_CNT ? "failover promote" : "unknown";
}

#define FD_ADMINCTL_FAILOVER_FLAG_YES   (1UL) /* confirmation only, does not authorize peer or history overrides */
#define FD_ADMINCTL_FAILOVER_FLAG_FORCE (2UL) /* --force, bypass peer guards and accept incomplete or empty vote history */

static inline char const *
fd_adminctl_failover_result_cstr( ulong result ) {
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS:                   return "success";
    case FD_ADMINCTL_RESULT_UNKNOWN_COMMAND:           return "the failover tile does not know this command";
    case FD_ADMINCTL_RESULT_UNSUPPORTED:               return "the failover tile does not support this command";
    case FD_FAILOVER_CONTROL_RESULT_BUSY:              return "another failover command is running on this validator, wait for it";
    case FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER:      return "this machine already runs the identity, or the machine it asked does not";
    case FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS:       return "a transition or key switch is running, wait for it";
    case FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY:      return "the other machine could not finish this handoff and may have given up the identity";
    case FD_FAILOVER_CONTROL_RESULT_PEER_HOLDS:        return "another machine runs the identity";
    case FD_FAILOVER_CONTROL_RESULT_NO_FINAL_HISTORY:  return "the machine running the identity has no eligible final vote state to hand over, its log says why";
    case FD_FAILOVER_CONTROL_RESULT_NO_HOLDER_ADDRESS: return "gossip has no address for the machine running the identity, wait or pass --address";
    case FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND:     return "this machine's replay is too far behind the last vote of the machine running the identity, retry once caught up";
    case FD_FAILOVER_CONTROL_RESULT_TIMEOUT:           return "the machine running the identity did not answer within 64 seconds";
    case FD_FAILOVER_CONTROL_RESULT_PEER_RESTARTED:    return "the machine running the identity restarted before it answered";
    case FD_FAILOVER_CONTROL_RESULT_ADOPTION_FAILED:   return "this machine did not adopt the vote history";
    case FD_FAILOVER_CONTROL_RESULT_SWITCH_FAILED:     return "the identity switch failed";
    case FD_FAILOVER_CONTROL_RESULT_HOLDS_OTHER:       return "this machine votes as the identity failover manages, hand that identity off first";
    case FD_FAILOVER_CONTROL_RESULT_IDENTITY_CHANGED:  return "set-identity changed the identity while the command ran";
    case FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH:      return "the public key in the keypair file does not match its private key";
    case FD_SET_IDENTITY_RESULT_AUTHORIZED_VOTER:      return "the keypair is an authorized voter on this validator";
    default:                                           return "unknown result";
  }
}

struct fd_adminctl_failover_req_v1 {
  ulong  version;      /* ==FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION */
  ulong  cmd;          /* FD_ADMINCTL_FAILOVER_CMD_* */
  ulong  flags;        /* FD_ADMINCTL_FAILOVER_FLAG_* */
  uint   addr;         /* HANDOFF only, the machine running the identity to dial in network byte order, 0 to find it in gossip */
  ushort port;         /* HANDOFF only, the port to dial it on in host byte order, 0 for the default port */
  uchar  target[ 32 ]; /* PREFLIGHT only, the identity the keypair names */
};
typedef struct fd_adminctl_failover_req_v1 fd_adminctl_failover_req_t;

/* Optional promote payload.  Admin consumes and wipes the keypair.
   Only req may be forwarded to the failover tile. */
struct fd_adminctl_failover_prepare_v1 {
  fd_adminctl_failover_req_t req;
  uchar                      keypair[ 64 ];
};
typedef struct fd_adminctl_failover_prepare_v1 fd_adminctl_failover_prepare_t;

struct fd_adminctl_failover_resp_v1 {
  ulong version; /* ==FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION */
  uchar identity[ 32 ];
  ulong slot;    /* on success the last vote cast before hand-over, ULONG_MAX for none */
};
typedef struct fd_adminctl_failover_resp_v1 fd_adminctl_failover_resp_t;
#define FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION (1UL)

FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_req_t )==64UL, failover_req_v1_layout  );
FD_STATIC_ASSERT( sizeof(fd_adminctl_failover_resp_t)==48UL, failover_resp_v1_layout );

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

/* fd_adminctl_wait_steps is fd_adminctl_wait_response that also calls
   step_fn with each step line the admin tile adds while the command
   runs, in order.  A command process that falls more than
   FD_ADMINCTL_STEP_CNT-1 lines behind skips the oldest. */

typedef void (* fd_adminctl_step_fn_t)( char const * step );

ulong
fd_adminctl_wait_steps( fd_adminctl_t *       adminctl,
                        ulong                 slot_id,
                        void *                resp,
                        ulong                 resp_max,
                        ulong *               resp_sz_out,
                        fd_adminctl_step_fn_t step_fn );

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

/* fd_adminctl_step adds a step line to the command being processed in
   slot_id, for its command process to show.  Only the app process
   calls it, between poll and complete.  The line is truncated to
   FD_ADMINCTL_STEP_MAX-1 bytes. */

void
fd_adminctl_step( fd_adminctl_t * adminctl,
                  ulong           slot_id,
                  char const *    step );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_admin_fd_adminctl_h */
