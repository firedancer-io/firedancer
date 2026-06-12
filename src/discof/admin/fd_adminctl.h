#ifndef HEADER_fd_src_discof_admin_fd_adminctl_h
#define HEADER_fd_src_discof_admin_fd_adminctl_h

#include "../../util/fd_util_base.h"

/* fd_adminctl_t provides APIs for out-of-band command-and-control
   signals to the firedancer process via the admin tile.  It provides a
   simple shared-memory command channel between the main application and
   users with an explicit shared-memory header.  The main process' run
   loop should periodically poll the fd_adminctl_t object to see if
   there is outstanding work dispatched from a user command process.
   A key principle is that a user command thread should not be able to
   put the adminctl object and the main process into a bad state.

   fd_adminctl_t is meant to provide a narrow, stable API surface that
   is mostly forward/backwards compatible.  As long as the fd_adminctl_t
   memory layout and command payloads are kept stable, a command process
   can be run on newer/older binaries compared to the main process.
   Important Note: If the adminctl memory layout is being changed,
   adminctl magic must be updated.

   The user command thread should publish a command with a caller-owned
   payload.  Publishing copies the payload into shared memory,
   dispatches the work to the admin tile, and returns the command
   request id.  The user process may then block on retrieving the result
   for that request id.  This ensures that commands are atomically sent
   to the main app process to be processed, but there is no guarantee
   about results being ingested by a command process.  Under the hood
   it combines a compare-and-swap state machine with a checksum and TTL
   to process new commands.

   All input into fd_adminctl_t must be trusted.  fd_adminctl_t is not a
   validation boundary for untrusted commands or payloads.  The object
   is designed to be robust to multiple calling commands that can either
   crash or pause while delivering the command.  This object assumes
   that the main process is always running and will be available to
   consume the command and produce a result.

   The command process is expected to call:

   fd_adminctl_publish() to send over commands to the main app process
   AND
   fd_adminctl_wait() to wait for the result of the command.

   The main app process is expected to call:

   fd_adminctl_poll() to poll for new commands from the command process
   AND
   fd_adminctl_complete() to send a notification to the command process
   and produce a result. */

#define FD_ADMINCTL_CMD_IDLE           (0UL)
#define FD_ADMINCTL_CMD_ADD_AUTH_VOTER (1UL)

#define FD_ADMINCTL_ALIGN       (8UL)
#define FD_ADMINCTL_PAYLOAD_MAX (256UL)

/* fd_adminctl_t will send a result back to the command process.  There
   is no guarantee that the command process will be able to consume the
   result (e.g. in the case of a racing command). */

#define FD_ADMINCTL_RESULT_SUCCESS (0UL)
#define FD_ADMINCTL_RESULT_FAILED  (1UL)
#define FD_ADMINCTL_RESULT_UNKNOWN (2UL)

/* The state of the adminctl object.  The state machine is as follows:
   - FREE: The adminctl object is not being used and is free to be used.
   - RESERVED: The adminctl object has been claimed by a command
     process, but the command process has not yet published.
   - PUBLISHED: The main process can now read the published command from
     the adminctl object
   - DONE: The adminctl object has been completed and there is a result
     ready to consume. */

#define FD_ADMINCTL_STATE_FREE      (0UL)
#define FD_ADMINCTL_STATE_RESERVED  (1UL)
#define FD_ADMINCTL_STATE_PUBLISHED (2UL)
#define FD_ADMINCTL_STATE_DONE      (3UL)

#define FD_ADMINCTL_ADD_AUTH_VOTER_PAYLOAD_VERSION (1UL)

struct fd_adminctl_add_auth_voter_v1 {
  ulong version; /* ==FD_ADMINCTL_ADD_AUTH_VOTER_PAYLOAD_VERSION */
  uchar keypair[ 64UL ];
};
typedef struct fd_adminctl_add_auth_voter_v1 fd_adminctl_add_auth_voter_t;

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

/* fd_adminctl_publish copies payload into the adminctl payload region
   and publishes the command to the main process.  A call to this
   function will block and spin until its command can be processed.  It
   will only block in the case of a racing/pending command.  Returns the
   request id assigned to the published command.  This functions should
   only be called by the command process. */

ulong
fd_adminctl_publish( fd_adminctl_t * adminctl,
                     ulong           cmd,
                     void const *    payload,
                     ulong           payload_sz );

/* fd_adminctl_wait waits for a published command request id to complete
   and returns the command result.  In the standard case, the command
   result is returned.  FD_ADMINCTL_RESULT_UNKNOWN is returned if the
   result for request_id has already been overwritten by a later command
   or if the internal state of the adminctl isn't
   FD_ADMINCTL_STATE_DONE.  This would only happen as a result of
   multiple commands racing with each other.  If RESULT_UNKNOWN is
   returned, it's possible that the command was completed successfully
   (but not guaranteed), and the caller should check the validator logs
   for more details.  RESULT_UNKNOWN should only ever be returned in
   degenerate cases and never in normal validator operation.  This
   function should only be called by the command process. */

ulong
fd_adminctl_wait( fd_adminctl_t * adminctl,
                  ulong           request_id );


/* fd_adminctl_poll polls the adminctl object for the next command
   to be processed.  Returns the command if one is pending and otherwise
   FD_ADMINCTL_CMD_IDLE.  data must point to a caller-owned buffer of
   data_max bytes, and data_sz must point to a caller-owned size output.
   If a command is pending, copies the validated payload into data.  If
   a reserved command is pending and has violated its TTL, reset the
   state of the adminctl object to allow future commands to be
   published.  If the payload checksum doesn't match, the command raced
   with another and the command is dropped; also return
   FD_ADMINCTL_CMD_IDLE.  This function should be called by the main app
   process. */

ulong
fd_adminctl_poll( fd_adminctl_t * adminctl,
                  void *          data,
                  ulong           data_max,
                  ulong *         data_sz );

/* fd_adminctl_complete is called from the main app process and
   publishes a command result to the command process.  This is for use
   by the admin tile after it has finished processing the payload.  The
   result is tied to the latest published request id.  There is no
   guarantee that the command process will be able to consume the result
   (e.g. in the case of a racing command).  This function should only be
   called by the main app process. */

void
fd_adminctl_complete( fd_adminctl_t * adminctl,
                      ulong           result );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_admin_fd_adminctl_h */
