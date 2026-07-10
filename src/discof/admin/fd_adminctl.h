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

#define FD_ADMINCTL_CMD_IDLE           (0UL)
#define FD_ADMINCTL_CMD_ADD_AUTH_VOTER (1UL)
#define FD_ADMINCTL_CMD_SET_IDENTITY   (2UL)
#define FD_ADMINCTL_CMD_GET_IDENTITY   (3UL)

#define FD_ADMINCTL_ALIGN       (8UL)
#define FD_ADMINCTL_PAYLOAD_MAX (256UL)
#define FD_ADMINCTL_SLOT_CNT    (4UL)

/* Shared command result codes. */
#define FD_ADMINCTL_RESULT_SUCCESS         (0UL)
#define FD_ADMINCTL_RESULT_UNKNOWN_COMMAND (1UL)

/* App-specific command result codes.
   NOTE: It is important these codes start at 2UL. */

struct fd_adminctl_add_auth_voter_v1 {
  ulong version; /* ==FD_ADMINCTL_ADD_AUTH_VOTER_PAYLOAD_VERSION */
  uchar keypair[ 64UL ];
};
typedef struct fd_adminctl_add_auth_voter_v1 fd_adminctl_add_auth_voter_t;
#define FD_ADMINCTL_ADD_AUTH_VOTER_PAYLOAD_VERSION (1UL)

#define FD_ADD_AUTHORIZED_VOTER_RESULT_PAYLOAD_TOO_SMALL           (2UL)
#define FD_ADD_AUTHORIZED_VOTER_RESULT_UNSUPPORTED_PAYLOAD_VERSION (3UL)
#define FD_ADD_AUTHORIZED_VOTER_RESULT_UNEXPECTED_PAYLOAD_SIZE     (4UL)
#define FD_ADD_AUTHORIZED_VOTER_RESULT_KEYPAIR_MISMATCH            (5UL)
#define FD_ADD_AUTHORIZED_VOTER_RESULT_MAX_AUTH_VOTERS             (6UL)
#define FD_ADD_AUTHORIZED_VOTER_RESULT_DUPLICATE_AUTH_VOTER        (7UL)

struct fd_adminctl_set_identity_v1 {
  ulong version; /* ==FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION */
  uchar keypair[ 64UL ];
};
typedef struct fd_adminctl_set_identity_v1 fd_adminctl_set_identity_t;
#define FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION (1UL)

#define FD_SET_IDENTITY_RESULT_PAYLOAD_TOO_SMALL           (2UL)
#define FD_SET_IDENTITY_RESULT_UNSUPPORTED_PAYLOAD_VERSION (3UL)
#define FD_SET_IDENTITY_RESULT_UNEXPECTED_PAYLOAD_SIZE     (4UL)
#define FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH            (5UL)

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

#define FD_GET_IDENTITY_RESULT_PAYLOAD_TOO_SMALL           (2UL)
#define FD_GET_IDENTITY_RESULT_UNSUPPORTED_PAYLOAD_VERSION (3UL)
#define FD_GET_IDENTITY_RESULT_UNEXPECTED_PAYLOAD_SIZE     (4UL)

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
