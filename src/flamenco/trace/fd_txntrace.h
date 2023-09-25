#ifndef HEADER_fd_src_flamenco_trace_fd_txntrace_h
#define HEADER_fd_src_flamenco_trace_fd_txntrace_h

/* fd_txntrace contains APIs for tracing transactions.  Txn tracing
   captures all inputs required to deterministically execute a txn,
   such that it can be replayed independently without  */

#include "../fd_flamenco_base.h"
#include "fd_trace.pb.h"

/* FD_TXNTRACE_SCRATCH_SPACE is the recommended amount of scratch memory
   available for txn execution captures and replays. */

#define FD_TXNTRACE_SCRATCH_SPACE (1<<30UL)  /* 1 GiB */

FD_PROTOTYPES_BEGIN

/* fd_txntrace_capture_pre records all inputs passed to a transaction
   execution such that it can be replayed later.  global is the executor
   context immediately before transaction execution.  txn is the
   descriptor for the txn payload at txn_data.

   fd_txntrace_capture_post records the state changes resulting from a
   prior transaction execution.  global is the executor context
   immediately after transaction execution.  pre points to the struct
   filled by fd_txntrace_capture_pre.

   out is the struct to be filled with captured data.  Lifetime of
   pointers in out is that of current scratch frame.  On success,
   returns out.  On failure, returns NULL.  Reasons for failure include
   scratch alloc failure.

   Caller must be attached to an fd_scratch with sufficient space to
   temporarily buffer all execution inputs.  A conservative estimate is
   FD_TXNTRACE_SCRATCH_SPACE.  Example usage as follows:

     // Capture pre state
     fd_scratch_push();
     fd_soltrace_TxnInput input;
     int ok = !!fd_txntrace_capture_pre( &input, global, txn, txn_data );
     if( ok ) dump_input( &input );  // use generated capture

     // Actual execution
     fd_execute_txn( ... );

     // Capture post state
     fd_soltrace_TxnDiff diff;
     int ok = !!fd_txntrace_capture_post( &diff, global, &input );
     if( ok ) dump_diff( &diff );
     fd_scratch_pop(); */

fd_soltrace_TxnInput *
fd_txntrace_capture_pre( fd_soltrace_TxnInput * out,
                         fd_global_ctx_t *      global,
                         fd_txn_t const *       txn,
                         uchar const *          txn_data );

fd_soltrace_TxnDiff *
fd_txntrace_capture_post( fd_soltrace_TxnDiff *        out,
                          fd_global_ctx_t *            global,
                          fd_soltrace_TxnInput const * pre );

/* fd_txntrace_replay replays a single transaction in a reconstructed
   txn execution context.  out is the struct to be filled with captured
   replay data.  Lifetime of pointers in out is that of current scratch
   frame.  input points to a previously captured execution input (such
   as returned by fd_txntrace_capture_pre).  wksp is a local join to a
   workspace.

   Example usage:

     fd_scratch_push();
     fd_soltrace_TxnDiff diff;
     int ok = !!fd_txntrace_replay( &diff, &input, wksp );
     if( ok ) dump_diff( diff );
     fd_scratch_pop();

   Always frees any allocations made to the wksp.  However, allocs made
   to fd_scratch must be freed by called (e.g. via fd_scratch_pop()).

   On failure, returns NULL.  Reasons for failure include alloc fail or
   fatal runtime error.  (Transaction exec fail is not a failure
   condition, error will be gracefully recorded in trace.)  Writes
   reason for failure to log. */

fd_soltrace_TxnDiff *
fd_txntrace_replay( fd_soltrace_TxnDiff *        out,
                    fd_soltrace_TxnInput const * input,
                    fd_wksp_t *                  wksp );

/* fd_txntrace_diff compares two transaction diff results.  Returns 1
   if identical, 0 otherwise. */

int
fd_txntrace_diff( fd_soltrace_TxnDiff const * left,
                  fd_soltrace_TxnDiff const * right );

char const *
fd_txntrace_diff_cstr( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_trace_fd_txntrace_h */

