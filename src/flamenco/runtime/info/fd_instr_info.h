#ifndef HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h
#define HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h

#include "../fd_txn_account.h"
#include "../fd_executor_err.h"
#include "../fd_runtime_const.h"
#include "../../../ballet/txn/fd_txn.h"

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
#define FD_INSTR_ACCT_FLAGS_IS_SIGNER   (0x01U)
#define FD_INSTR_ACCT_FLAGS_IS_WRITABLE (0x02U)

/* The maximum possible size for the instruction data for any
   instruction, which is bounded by FD_RUNTIME_CPI_MAX_INSTR_DATA_LEN
   (which is 10KB). */
#define FD_INSTR_DATA_MAX FD_RUNTIME_CPI_MAX_INSTR_DATA_LEN

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
  ushort                   acct_cnt;

  uchar                    data[ FD_INSTR_DATA_MAX ];
  ushort                   data_sz;

  fd_instruction_account_t accounts[ FD_INSTR_ACCT_MAX ];
  uchar                    is_duplicate[ FD_INSTR_ACCT_MAX ];

  /* Stack height when this instruction was pushed onto the stack (including itself) */
  uchar stack_height;

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
  if( FD_LIKELY( idx_in_txn!=USHORT_MAX ) ) {
    instr->is_duplicate[ idx_in_callee ] = acc_idx_seen[ idx_in_txn ];

    if( FD_LIKELY( !acc_idx_seen[ idx_in_txn ] ) ) {
      /* This is the first time seeing this account */
      acc_idx_seen[ idx_in_txn ] = 1;
    }
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
fd_instr_info_accumulate_starting_lamports( fd_instr_info_t * instr,
                                            fd_txn_out_t *    txn_out,
                                            ushort            idx_in_callee,
                                            ushort            idx_in_txn );

void
fd_instr_info_init_from_txn_instr( fd_instr_info_t *      instr,
                                   fd_bank_t *            bank,
                                   fd_txn_in_t const *    txn_in,
                                   fd_txn_out_t *         txn_out,
                                   fd_txn_instr_t const * txn_instr );

/* https://github.com/anza-xyz/solana-sdk/blob/589e6237f203c2719c300dc044f4e00f48e66a8f/message/src/versions/v0/loaded.rs#L152-L157 */
FD_FN_PURE static inline int
fd_instr_acc_is_writable_idx( fd_instr_info_t const * instr,
                              ushort                  idx ) {
  if( FD_UNLIKELY( idx>=instr->acct_cnt ) ) {
    return 0;
  }

  return !!(instr->accounts[idx].is_writable);
}

/* fd_instr_acc_is_signer_idx returns:
    - 1 if account is signer
    - 0 (with *out_opt_err==0) if account is not signer
  If an error occurs during query, returns 0 and writes the
  error code to *out_opt_err. Possible values for out_opt_err:
    - FD_EXECUTOR_INSTR_ERR_MISSING_ACC occurs when the instr account
      index provided is invalid (out of bounds).
    - 0 if the query was successful. Check the return value to see
      if the account is a signer.

  https://github.com/anza-xyz/agave/blob/v3.0.3/transaction-context/src/lib.rs#L782-L791    */
FD_FN_PURE static inline int
fd_instr_acc_is_signer_idx( fd_instr_info_t const * instr,
                            ushort                  idx,
                            int *                   out_opt_err ) {
  if( FD_UNLIKELY( idx>=instr->acct_cnt ) ) {
    if( out_opt_err ) *out_opt_err = FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    return 0;
  }

  if( out_opt_err ) *out_opt_err = 0;
  return !!(instr->accounts[idx].is_signer);
}

/* fd_instr_info_sum_account_lamports returns the sum of lamport account
   balances of all instruction accounts in the context.

   Aborts on integer overflow. */

int
fd_instr_info_sum_account_lamports( fd_instr_info_t const * instr,
                                    fd_txn_out_t *          txn_out,
                                    ulong *                 total_lamports_h,
                                    ulong *                 total_lamports_l );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_info_fd_instr_info_h */
