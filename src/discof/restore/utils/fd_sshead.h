#ifndef HEADER_fd_src_discof_restore_utils_fd_sshead_h
#define HEADER_fd_src_discof_restore_utils_fd_sshead_h

/* fd_sshead is a higher-level wrapper around fd_ssresolve that manages
   the full lifecycle of a single non-blocking HTTP HEAD pre-resolve
   against a plain-HTTP peer.  It handles socket creation, non-blocking
   connect, polling, timeout, and cleanup.

   Typical usage:

    fd_sshead_start( head, addr, 0, now, FD_SSHEAD_DEFAULT_TIMEOUT );
    ...
    // in the event loop:
      fd_ssresolve_result_t result;
      int rc = fd_sshead_advance( head, &result, now );
      if( rc==FD_SSHEAD_ADVANCE_DONE ) { ... use result ... }
*/

#include "fd_ssresolve.h"

#include <poll.h>

#define FD_SSHEAD_DEFAULT_TIMEOUT  (2L*1000L*1000L*1000L) /* 2 seconds */

#define FD_SSHEAD_ADVANCE_DONE    ( 2) /* resolve completed, result is valid */
#define FD_SSHEAD_ADVANCE_AGAIN   ( 1) /* in progress, call again */
#define FD_SSHEAD_ADVANCE_IDLE    ( 0) /* no resolve in flight */
#define FD_SSHEAD_ADVANCE_ERROR   (-1) /* resolve failed */
#define FD_SSHEAD_ADVANCE_TIMEOUT (-2) /* resolve timed out */

struct fd_sshead_private;
typedef struct fd_sshead_private fd_sshead_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_sshead_align( void );

FD_FN_CONST ulong
fd_sshead_footprint( void );

void *
fd_sshead_new( void * shmem );

fd_sshead_t *
fd_sshead_join( void * shhead );

/* fd_sshead_start begins a HEAD pre-resolve against the peer at the
   given addr.  It creates a non-blocking TCP socket, connects, and
   initializes the internal fd_ssresolve_t for an HTTP HEAD request.
   full: 1 for full snapshot, 0 for incremental.
   now: current time in nanoseconds (fd_log_wallclock).
   timeout_nanos: how long before the attempt is considered timed out.

   Returns 0 on success, -1 on socket/connect failure, -2 if a session
   was already active. */
int
fd_sshead_start( fd_sshead_t * head,
                 fd_ip4_port_t addr,
                 int           full,
                 long          now,
                 long          timeout_nanos );

/* fd_sshead_advance drives the HEAD resolve forward.  This should be
   called periodically from the event loop.

   On FD_SSHEAD_ADVANCE_DONE, the result struct is populated with the
   resolved slot, base_slot, and hash.  The socket is closed.

   On FD_SSHEAD_ADVANCE_ERROR or FD_SSHEAD_ADVANCE_TIMEOUT, the socket
   is closed internally.

   On FD_SSHEAD_ADVANCE_AGAIN, the resolve is still in progress.

   On FD_SSHEAD_ADVANCE_IDLE, no resolve is in flight. */
int
fd_sshead_advance( fd_sshead_t *           head,
                   fd_ssresolve_result_t * result,
                   long                    now );

/* fd_sshead_cancel cancels any in-flight HEAD resolve and closes the
   socket.  Safe to call even if no resolve is active. */
void
fd_sshead_cancel( fd_sshead_t * head );

/* fd_sshead_active returns 1 if a HEAD resolve is currently in
   flight, 0 otherwise. */
int
fd_sshead_active( fd_sshead_t const * head );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_sshead_h */
