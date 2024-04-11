#ifndef HEADER_fd_src_flamenco_runtime_program_fd_compute_budget_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_compute_budget_program_h

#include "../../fd_flamenco_base.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"

/* FIXME: put these elsewhere */
#define FD_MIN_HEAP_FRAME_BYTES (32 * 1024)     /* Min heap size */
#define FD_MAX_HEAP_FRAME_BYTES (256 * 1024)    /* Max heap size */
#define FD_HEAP_FRAME_BYTES_GRANULARITY (1024)  /* Heap frame requests must be a multiple of this number */
#define FD_MAX_COMPUTE_UNIT_LIMIT (1400000)     /* Max compute unit limit */

#define FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_COMPUTE_UNIT_PRICE (0)
#define FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED         (1)

FD_PROTOTYPES_BEGIN

/* Entry-point for the Solana Compute Budget Program */
int fd_executor_compute_budget_program_execute_instructions( fd_exec_txn_ctx_t * ctx, fd_rawtxn_b_t const * txn_raw );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_compute_budget_program_h */
