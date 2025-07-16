#ifndef HEADER_fd_src_flamenco_runtime_fd_compute_budget_details_h
#define HEADER_fd_src_flamenco_runtime_fd_compute_budget_details_h

#include "../fd_flamenco_base.h"

FD_PROTOTYPES_BEGIN

/* Defines any compute budget details that may or may not be updated
   by compute budget instructions.
   https://github.com/anza-xyz/agave/blob/v2.3.1/compute-budget-instruction/src/compute_budget_instruction_details.rs#L39-L51 */
struct fd_compute_budget_details {
  uchar has_compute_units_limit_update;
  uchar has_compute_units_price_update;
  uchar has_requested_heap_size;
  uchar has_loaded_accounts_data_size_limit_update;

  ulong compute_unit_limit;              /* Compute unit limit for this transaction. */
  ulong compute_unit_price;              /* Compute unit price for this transaction. */
  ulong compute_meter;                   /* Remaining compute units */
  ulong heap_size;                       /* Heap size for VMs for this transaction. */
  ulong loaded_accounts_data_size_limit; /* Loaded accounts data size limit for this transaction. */

  /* SIMD-170 introduces a conservative CU limit of 3,000 CUs per
     non-migrated native program, and 200,000 CUs for all other programs
     (including migrated builtins). The below two fields keep track of
     the number of builtin and non-builtin instructions in the transaction
     to calculate default compute unit limits. */
  ulong num_builtin_instrs;              /* Number of builtin instructions in this transaction. */
  ulong num_non_builtin_instrs;          /* Number of non-builtin instructions in this transaction. */

  ushort requested_heap_size_instr_index; /* Index of the instruction that requested a heap size. */
};
typedef struct fd_compute_budget_details fd_compute_budget_details_t;

void
fd_compute_budget_details_new( fd_compute_budget_details_t * details );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_compute_budget_details_h */
