#ifndef HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h
#define HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h

#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"
#include "../fd_txn_account.h"

/* While the maximum number of instruction accounts allowed for instruction
   execution is 256, it is entirely possible to have a transaction with more
   than 256 instruction accounts that passes transaction loading checks and enters
   `fd_execute_instr` (See mainnet transaction
   3eDdfZE6HswPxFKrtnQPsEmTkyL1iP57gRPEXwaqNGAqF1paGXCYYMwh7z4uQDUMgFor742sikVSQZW1gFRDhPNh
   for an example). An instruction that goes into the VM with more than 256 instruction accounts
   will fail, but you could also theoretically invoke a native program with over 256 random
   unreferenced instruction accounts that will execute successfully. The true bound for the
   maximum number of instruction accounts you can pass in is slighly lower than the maximum
   possible size for a serialized transaction (1232).

   HOWEVER... to keep our memory footprint low, we cap the `acct_cnt` at 256 during setup since
   any extra accounts should (ideally) have literally 0 impact on program execution, whether
   or not they are present in the instr info. This keeps the transaction context size from
   blowing up to around 3MB in size. */
#define FD_INSTR_ACCT_MAX               (256)
#define FD_INSTR_ACCT_FLAGS_IS_SIGNER   (0x01U)
#define FD_INSTR_ACCT_FLAGS_IS_WRITABLE (0x02U)

struct fd_instruction_account {
  ushort index_in_transaction;
  ushort index_in_caller;
  ushort index_in_callee;
  uchar is_writable;
  uchar is_signer;
};

typedef struct fd_instruction_account fd_instruction_account_t;

struct fd_instr_info {
  uchar                    program_id;
  ushort                   data_sz;
  ushort                   acct_cnt;

  uchar *                  data;

  fd_instruction_account_t accounts[ FD_INSTR_ACCT_MAX ];
  uchar                    is_duplicate[ FD_INSTR_ACCT_MAX ];

  /* TODO: convert to fd_uwide_t representation of uint_128 */
  ulong                    starting_lamports_h;
  ulong                    starting_lamports_l;
};

typedef struct fd_instr_info fd_instr_info_t;

FD_PROTOTYPES_BEGIN

static inline fd_instruction_account_t
fd_instruction_account_init( ushort idx_in_txn,
                             ushort idx_in_caller,
                             ushort idx_in_callee,
                             uchar  is_writable,
                             uchar  is_signer ) {
  fd_instruction_account_t acc = {
    .index_in_transaction = idx_in_txn,
    .index_in_caller      = idx_in_caller,
    .index_in_callee      = idx_in_callee,
    .is_writable          = is_writable,
    .is_signer            = is_signer,
  };
  return acc;
}

static inline void
fd_instr_info_setup_instr_account( fd_instr_info_t * instr,
                                   uchar             acc_idx_seen[ FD_INSTR_ACCT_MAX ],
                                   ushort            idx_in_txn,
                                   ushort            idx_in_caller,
                                   ushort            idx_in_callee,
                                   uchar             is_writable,
                                   uchar             is_signer ) {
  instr->is_duplicate[ idx_in_callee ] = acc_idx_seen[ idx_in_txn ];
  if( FD_LIKELY( !acc_idx_seen[ idx_in_txn ] ) ) {
    /* This is the first time seeing this account */
    acc_idx_seen[ idx_in_txn ] = 1;
  }

  instr->accounts[ idx_in_callee ] = fd_instruction_account_init( idx_in_txn,
                                                                  idx_in_caller,
                                                                  idx_in_callee,
                                                                  is_writable,
                                                                  is_signer );
}

/* fd_instr_info_accumulate_starting_lamports accumulates the starting lamports fields
   when setting up an fd_instr_info_t object.
   Note that the caller must zero out the starting lamports fields in fd_instr_info_t
   beforehand. */

void
fd_instr_info_accumulate_starting_lamports( fd_instr_info_t *         instr,
                                            fd_exec_txn_ctx_t const * txn_ctx,
                                            ushort                    idx_in_callee,
                                            ushort                    idx_in_txn );

void
fd_instr_info_init_from_txn_instr( fd_instr_info_t *      instr,
                                   fd_exec_txn_ctx_t *    txn_ctx,
                                   fd_txn_instr_t const * txn_instr );

FD_FN_PURE static inline int
fd_instr_acc_is_writable_idx( fd_instr_info_t const * instr,
                              ushort                  idx ) {
  if( FD_UNLIKELY( idx>=instr->acct_cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  return !!(instr->accounts[idx].is_writable);
}

FD_FN_PURE static inline int
fd_instr_acc_is_signer_idx( fd_instr_info_t const * instr,
                            ushort                  idx ) {
  if( FD_UNLIKELY( idx>=instr->acct_cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }

  return !!(instr->accounts[idx].is_signer);
}

/* fd_instr_info_sum_account_lamports returns the sum of lamport account
   balances of all instruction accounts in the context.

   Aborts on integer overflow. */

int
fd_instr_info_sum_account_lamports( fd_instr_info_t const * instr,
                                    fd_exec_txn_ctx_t *     txn_ctx,
                                    ulong *                 total_lamports_h,
                                    ulong *                 total_lamports_l );

static inline uchar
fd_instr_get_acc_flags( fd_instr_info_t const * instr,
                        ushort                  idx ) {
  if( FD_UNLIKELY( idx>=instr->acct_cnt ) ) {
    return 0;
  }

  uchar flags = 0;
  if( instr->accounts[idx].is_signer )   flags |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
  if( instr->accounts[idx].is_writable ) flags |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;

  return flags;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h */
