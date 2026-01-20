#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_pipe_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_pipe_h

/* fd_accdb_pipe.h provides APIs for fast bulk account access. */

#include "fd_accdb_base.h"
#include "fd_accdb_ref.h"
#include "fd_accdb_user.h"

/* fd_accdb_ro_pipe_t is an API for pipelining account read requests.

   This API flexibly adapts to the style of underlying I/O backend and
   queue depths without requiring the caller to know database config
   specifics.

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

#define FD_ACCDB_RO_PIPE_MAX (1024UL)

struct fd_accdb_ro_pipe {
  fd_accdb_user_t * accdb;
  fd_funk_txn_xid_t xid;

  ulong batch_idx;  /* index of req batch */
  uint  req_max;
  uint  req_cnt;    /* batch element count */
  uint  req_comp;   /* index of next completion */
  uint  state;

  fd_accdb_ro_t ro_nx[1]; /* ro describing a not-found record */

  uchar         addr[ FD_ACCDB_RO_PIPE_MAX ][ 32 ];
  fd_accdb_ro_t ro  [ FD_ACCDB_RO_PIPE_MAX ];
};

typedef struct fd_accdb_ro_pipe fd_accdb_ro_pipe_t;

FD_PROTOTYPES_BEGIN

/* fd_accdb_ro_pipe_init creates a new ro_pipe.  */

fd_accdb_ro_pipe_t *
fd_accdb_ro_pipe_init( fd_accdb_ro_pipe_t *      pipe,
                       fd_accdb_user_t *         accdb,
                       fd_funk_txn_xid_t const * xid );

void
fd_accdb_ro_pipe_fini( fd_accdb_ro_pipe_t * pipe );

/* fd_accdb_ro_pipe_enqueue asynchronously enqueues a read request.
   May block internally if queues are full.  The user must drain all
   completions (fd_accdb_ro_pipe_poll) before calling enqueue. */

void
fd_accdb_ro_pipe_enqueue( fd_accdb_ro_pipe_t * pipe,
                          void const *         address );

/* fd_accdb_ro_pipe_flush dispatches all enqueued read requests and
   blocks until all results become available.  (All calls made to poll
   after the flush are guaranteed to return non-NULL for requests
   enqueued before the flush.) */

void
fd_accdb_ro_pipe_flush( fd_accdb_ro_pipe_t * pipe );

/* fd_accdb_ro_pipe_poll polls for the next read completion.  Returns an
   ro handle if a request completed.  Returns NULL if no completion is
   ready.  This may happen because the ro_pipe is waiting for the DB to
   respond, or if ro_pipe is internally buffering up a request batch
   (use ro_pipe_flush to explicitly dispatch a batch), or if there are
   no enqueued requests.

   The lifetime of the returned ro ends when the next call to
   ro_pipe_{enqueue,flush,poll} is made on this pipe object, or when the
   pipe object is destroyed.

   Results are delivered in enqueued order.

   NOTE: If an account was not found, returns a non-NULL ro (to a dummy
   account with zero lamports), which differs from fd_accdb_open_ro. */

fd_accdb_ro_t *
fd_accdb_ro_pipe_poll( fd_accdb_ro_pipe_t * pipe );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_pipe_h */
