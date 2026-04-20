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

/* Borsh-encoded ComputeBudgetInstruction discriminants.
   https://github.com/anza-xyz/agave/blob/v4.0.0-beta.7/sdk/src/compute_budget.rs */

#define FD_COMPUTE_BUDGET_INSTR_DISC_REQUEST_UNITS_DEPRECATED            (0U)
#define FD_COMPUTE_BUDGET_INSTR_DISC_REQUEST_HEAP_FRAME                  (1U)
#define FD_COMPUTE_BUDGET_INSTR_DISC_SET_COMPUTE_UNIT_LIMIT              (2U)
#define FD_COMPUTE_BUDGET_INSTR_DISC_SET_COMPUTE_UNIT_PRICE              (3U)
#define FD_COMPUTE_BUDGET_INSTR_DISC_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT (4U)

/* fd_compute_budget_instr_t is the in-memory representation of a
   decoded ComputeBudgetInstruction.  Agave uses borsh with a 1-byte
   u8 discriminant.  Trailing bytes are allowed (try_from_slice_unchecked). */

struct fd_compute_budget_instr {
  uchar discriminant;
  union {
    uint  request_heap_frame;
    uint  set_compute_unit_limit;
    ulong set_compute_unit_price;
    uint  set_loaded_accounts_data_size_limit;
  };
};
typedef struct fd_compute_budget_instr fd_compute_budget_instr_t;

/* fd_compute_budget_instr_decode decodes a borsh-serialized
   ComputeBudgetInstruction from [data, data+data_sz).
   Returns 0 on success, -1 on decode failure. */

static inline int
fd_compute_budget_instr_decode( uchar const *               data,
                                ulong                       data_sz,
                                fd_compute_budget_instr_t * out ) {
  if( FD_UNLIKELY( data_sz<1UL ) ) return -1;
  out->discriminant = data[0];
  uchar const * p   = data + 1;
  ulong         rem = data_sz - 1;
  switch( out->discriminant ) {
    case FD_COMPUTE_BUDGET_INSTR_DISC_REQUEST_UNITS_DEPRECATED:
      if( FD_UNLIKELY( rem<8UL ) ) return -1;
      return 0;
    case FD_COMPUTE_BUDGET_INSTR_DISC_REQUEST_HEAP_FRAME:
      if( FD_UNLIKELY( rem<4UL ) ) return -1;
      out->request_heap_frame = FD_LOAD( uint, p );
      return 0;
    case FD_COMPUTE_BUDGET_INSTR_DISC_SET_COMPUTE_UNIT_LIMIT:
      if( FD_UNLIKELY( rem<4UL ) ) return -1;
      out->set_compute_unit_limit = FD_LOAD( uint, p );
      return 0;
    case FD_COMPUTE_BUDGET_INSTR_DISC_SET_COMPUTE_UNIT_PRICE:
      if( FD_UNLIKELY( rem<8UL ) ) return -1;
      out->set_compute_unit_price = FD_LOAD( ulong, p );
      return 0;
    case FD_COMPUTE_BUDGET_INSTR_DISC_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT:
      if( FD_UNLIKELY( rem<4UL ) ) return -1;
      out->set_loaded_accounts_data_size_limit = FD_LOAD( uint, p );
      return 0;
    default:
      return -1;
  }
}

FD_PROTOTYPES_BEGIN

/* Validates the requested compute budget limits. Returns an error if
   the requested heap size is invalid, or if the loaded accounts data
   size limit is 0. Also bounds the compute unit and loaded
   accounts data size limits to a specified min / max value.

   https://github.com/anza-xyz/agave/blob/v2.3.1/compute-budget-instruction/src/compute_budget_instruction_details.rs#L101-L153 */
int
fd_sanitize_compute_unit_limits( fd_txn_out_t * txn_out );

int
fd_executor_compute_budget_program_execute_instructions( fd_bank_t const *   bank,
                                                         fd_txn_in_t const * txn_in,
                                                         fd_txn_out_t *      txn_out );

int
fd_compute_budget_program_execute( fd_exec_instr_ctx_t * ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_compute_budget_program_h */
