#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_batch_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_batch_h

/* fd_accdb_batch.h provides streaming APIs for bulk account accesses.
   These amortize I/O wait time if paired with an asynchronous database
   I/O engine (e.g. vinyl_io_ur).  Mostly useful for reads of accounts
   that are not in memory cache. */

#include "fd_accdb_base.h"
#include "fd_accdb_ref.h"
#include "fd_accdb_user.h"

/* fd_accdb_ro_pipe_t is an API for pipelining account read requests.

   This API flexibly adapts to the style of underlying I/O API (batch or
   true async) and queue depths without requiring the caller to know
   database config specifics.

   General usage as follows:

     pipe = fd_accdb_ro_pipe_init( ... );
     for each (i, address) in request_list {

       // enqueue another request
       fd_accdb_ro_pipe_enqueue( pipe, address );

       if( i==len(request_list)-1 ) {
         // ensure that all results are read on the last iteration
         fd_accdb_ro_pipe_flush( pipe );
       }

       // handle completions (may be delivered in subsequent iterations)
       while( ro = fd_accdb_ro_pipe_poll( pipe ) ) {
         ... process an account result ...
       }

     }
     fd_accdb_ro_pipe_fini( ... );

   The pattern above enqueues read requests and asynchronously processes
   results as they become available.  The loop blocks as appropriate
   when backpressured. */

struct __attribute__((aligned(16))) fd_accdb_ro_pipe {
  fd_accdb_user_t * user;
  uchar             impl[ 120 ];
};

FD_PROTOTYPES_BEGIN

static inline fd_accdb_ro_pipe_t *
fd_accdb_ro_pipe_init( fd_accdb_ro_pipe_t *      pipe,
                       fd_accdb_user_t *         accdb,
                       fd_funk_txn_xid_t const * xid ) {
  return accdb->base.vt->ro_pipe_init( pipe, accdb, xid );
}

static inline void
fd_accdb_ro_pipe_fini( fd_accdb_ro_pipe_t * pipe,
                       fd_accdb_user_t *    accdb ) {
  accdb->base.vt->ro_pipe_fini( pipe );
}

/* fd_accdb_ro_pipe_enqueue asynchronously enqueues a read request.
   May block internally if queues are full.  The user must drain all
   completions (fd_accdb_ro_pipe_poll) before calling enqueue. */

static inline void
fd_accdb_ro_pipe_enqueue( fd_accdb_ro_pipe_t * pipe,
                          void const *         address ) {
  pipe->user->base.vt->ro_pipe_enqueue( pipe, address );
}

/* fd_accdb_ro_pipe_flush dispatches all enqueued read requests and
   blocks until all results become available.  (All calls made to poll
   after the flush are guaranteed to return non-NULL for requests
   enqueued before the flush.) */

static inline void
fd_accdb_ro_pipe_flush( fd_accdb_ro_pipe_t * pipe ) {
  pipe->user->base.vt->ro_pipe_flush( pipe );
}

/* fd_accdb_ro_pipe_poll polls for the next read completion.  Returns an
   ro handle if a request completed.  Returns NULL if no completion is
   ready.  This may happen because the ro_pipe is waiting for the DB to
   respond, or if ro_pipe is internally buffering up a request batch
   (use ro_pipe_flush to explicitly dispatch a batch), or if there are
   no enqueued requests.

   The lifetime of the returned ro ends when the next call to
   ro_pipe_{enqueue,flush,poll} is made on this pipe object, or when the
   pipe object is destroyed.

   Results are delivered in arbitrary order (not necessarily same as
   enqueued).

   NOTE: If an account was not found, returns a non-NULL ro (to a dummy
   account with zero lamports), which differs from fd_accdb_open_ro. */

static inline fd_accdb_ro_t *
fd_accdb_ro_pipe_poll( fd_accdb_ro_pipe_t * pipe ) {
  return pipe->user->base.vt->ro_pipe_poll( pipe );
}

/* fd_accdb_ro_pipe1 is a fallback implementation of fd_accdb_ro_pipe
   that is based on fd_accdb_open_ro. */

fd_accdb_ro_pipe_t * fd_accdb_ro_pipe1_init   ( fd_accdb_ro_pipe_t *, fd_accdb_user_t *, fd_funk_txn_xid_t const * );
void                 fd_accdb_ro_pipe1_fini   ( fd_accdb_ro_pipe_t * );
void                 fd_accdb_ro_pipe1_enqueue( fd_accdb_ro_pipe_t *, void const * );
void                 fd_accdb_ro_pipe1_flush  ( fd_accdb_ro_pipe_t * );
fd_accdb_ro_t *      fd_accdb_ro_pipe1_poll   ( fd_accdb_ro_pipe_t * );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_batch_h */
