#ifndef HEADER_fd_src_flamenco_runtime_program_fd_compute_budget_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_compute_budget_program_h

#include "../../fd_flamenco_base.h"

/* FIXME: put these elsewhere */
#define FD_MIN_HEAP_FRAME_BYTES (32 * 1024)     /* Min heap size */
#define FD_MAX_HEAP_FRAME_BYTES (256 * 1024)    /* Max heap size */
#define FD_HEAP_FRAME_BYTES_GRANULARITY (1024)  /* Heap frame requests must be a multiple of this number */
#define FD_MAX_COMPUTE_UNIT_LIMIT (1400000)     /* Max compute unit limit */

/* SIMD-170 defines new default compute units for builtin, non-builtin, and migrated programs:
   - Any non-migrated builtins have a conservative default CU limit of 3,000 CUs.
   - Any migrated and non-builtins have a default CU limit of 200,000 CUs.

   https://github.com/anza-xyz/agave/blob/v2.1.13/runtime-transaction/src/builtin_programs_filter.rs#L9-L19 */
#define FD_PROGRAM_KIND_NOT_BUILTIN       (0)
#define FD_PROGRAM_KIND_BUILTIN           (1)
#define FD_PROGRAM_KIND_MIGRATING_BUILTIN (2)

FD_PROTOTYPES_BEGIN

/* Validates the requested compute budget limits. Returns an error if
   the requested heap size is invalid, or if the loaded accounts data
   size limit is 0. Also bounds the compute unit and loaded
   accounts data size limits to a specified min / max value.

   https://github.com/anza-xyz/agave/blob/v2.3.1/compute-budget-instruction/src/compute_budget_instruction_details.rs#L101-L153 */
int
fd_sanitize_compute_unit_limits( fd_exec_txn_ctx_t * ctx );

int
fd_executor_compute_budget_program_execute_instructions( fd_exec_txn_ctx_t * ctx );

int
fd_compute_budget_program_execute( fd_exec_instr_ctx_t * ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_compute_budget_program_h */
