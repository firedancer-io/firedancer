#include "fd_accdb_pipe.h"
#include "fd_accdb_ref.h"
#include "fd_accdb_sync.h"

/* ro_pipe state machine

   BATCH: generating request batch
   DRAIN: waiting for user to poll responses

   On creation, ro_pipe is in BATCH state.
   BATCH->DRAIN transitioned when flush is requested (open_ro_multi)
   DRAIN->BATCH transitioned when user processed all completions (close_ro_multi) */

#define RO_PIPE_STATE_BATCH 0
#define RO_PIPE_STATE_DRAIN 1

fd_accdb_ro_pipe_t *
fd_accdb_ro_pipe_init( fd_accdb_ro_pipe_t *      pipe,
                       fd_accdb_user_t *         accdb,
                       fd_funk_txn_xid_t const * xid ) {
  if( FD_UNLIKELY( !pipe  ) ) FD_LOG_CRIT(( "NULL pipe"  ));
  if( FD_UNLIKELY( !accdb ) ) FD_LOG_CRIT(( "NULL accdb" ));
  if( FD_UNLIKELY( !xid   ) ) FD_LOG_CRIT(( "NULL xid"   ));

  /* Partial init style because pipe is large O(~64KB) */
  pipe->accdb     = accdb;
  pipe->xid       = *xid;
  pipe->batch_idx = 0UL;
  pipe->req_max   = (uint)fd_ulong_min( fd_accdb_batch_max( accdb ), FD_ACCDB_RO_PIPE_MAX );
  pipe->req_cnt   = 0U;
  pipe->req_comp  = 0U;
  pipe->state     = RO_PIPE_STATE_BATCH;

  return pipe;
}

void
fd_accdb_ro_pipe_fini( fd_accdb_ro_pipe_t * pipe ) {
  fd_accdb_ro_pipe_flush( pipe );
  while( fd_accdb_ro_pipe_poll( pipe ) ) {}
}

void
fd_accdb_ro_pipe_enqueue( fd_accdb_ro_pipe_t * pipe,
                          void const *         address ) {
  if( FD_UNLIKELY( pipe->state!=RO_PIPE_STATE_BATCH ||
                   pipe->req_cnt>=FD_ACCDB_RO_PIPE_MAX ) ) {
    FD_LOG_CRIT(( "ro_pipe_enqueue failed: not ready for new requests (poll() required for next request)" ));
  }
  if( FD_UNLIKELY( pipe->req_max==0UL ) ) {
    FD_LOG_CRIT(( "ro_pipe_enqueue failed: req_max is zero" ));
  }

  memcpy( pipe->addr[ pipe->req_cnt ], address, 32UL );
  pipe->req_cnt++;
  FD_CRIT( pipe->req_max<=FD_ACCDB_RO_PIPE_MAX, "req_max corrupt" );
  if( pipe->req_cnt>=pipe->req_max ) {
    fd_accdb_ro_pipe_flush( pipe );
  }
}

void
fd_accdb_ro_pipe_flush( fd_accdb_ro_pipe_t * pipe ) {
  fd_accdb_open_ro_multi( pipe->accdb, pipe->ro, &pipe->xid, pipe->addr, pipe->req_cnt );
  pipe->state    = RO_PIPE_STATE_DRAIN;
  pipe->req_comp = 0U;
}

fd_accdb_ro_t *
fd_accdb_ro_pipe_poll( fd_accdb_ro_pipe_t * pipe ) {
  if( pipe->state!=RO_PIPE_STATE_DRAIN ) return NULL;
  if( pipe->req_comp==pipe->req_cnt ) {
    fd_accdb_close_ro_multi( pipe->accdb, pipe->ro, pipe->req_cnt );
    pipe->state    = RO_PIPE_STATE_BATCH;
    pipe->req_cnt  = 0U;
    pipe->req_comp = 0U;
    return NULL;
  }

  ulong idx = pipe->req_comp++;
  fd_accdb_ro_t * ro = &pipe->ro[ idx ];
  if( FD_UNLIKELY( !ro->meta || !ro->meta->lamports ) ) {
    ro = pipe->ro_nx;
    return fd_accdb_ro_init_empty( ro, pipe->addr[ idx ] );
  }
  return ro;
}
