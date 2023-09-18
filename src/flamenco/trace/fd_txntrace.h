#ifndef HEADER_fd_src_flamenco_trace_fd_txntrace_h
#define HEADER_fd_src_flamenco_trace_fd_txntrace_h

#include "../fd_flamenco_base.h"
#include "fd_trace.pb.h"

/* FD_TXNTRACE_SCRATCH_{...} specifies the scratch memory region used
   while tracing transactions. */

#define FD_TXNTRACE_SCRATCH_ALIGN     (4096UL)
#define FD_TXNTRACE_SCRATCH_FOOTPRINT (1<<30UL)  /* 1 GiB */

/* FD_TXNTRACE_{SUCCESS,ERR_{...}} are return codes for
   fd_txntrace_replay. */

#define FD_TXNTRACE_SUCCESS         (0)
#define FD_TXNTRACE_ERR_INVAL_INPUT (1)
#define FD_TXNTRACE_ERR_OUT_UNDERSZ (2)

FD_PROTOTYPES_BEGIN

/* fd_txntrace_replay replays a single transaction in a reconstructed
   txn execution context.  scratch points to a memory region matching
   FD_TXNTRACE_SCRATCH_{ALIGN,FOOTPRINT}.  Caller must not be attached
   to fd_scratch.  Return code is FD_TXNTRACE_SUCCESS on success, or
   otherwise one of FD_TXNTRACE_ERR_{...}. */

int
fd_txntrace_replay( void *                           out,
                    ulong                            out_sz ,
                    fd_soltrace_TxnExecInput const * in,
                    uchar *                          scratch );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_trace_fd_txntrace_h */

