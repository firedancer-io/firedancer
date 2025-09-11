#include "fd_instr_info.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../../../util/bits/fd_uwide.h"

void
fd_instr_info_accumulate_starting_lamports( fd_instr_info_t *         instr,
                                            fd_exec_txn_ctx_t const * txn_ctx,
                                            ushort                    idx_in_callee,
                                            ushort                    idx_in_txn ) {
  if( FD_LIKELY( !instr->is_duplicate[ idx_in_callee ] ) ) {
    fd_txn_account_t const * account = &txn_ctx->accounts[ idx_in_txn ];
    if( fd_txn_account_get_meta( account ) ) {
      fd_uwide_inc(
        &instr->starting_lamports_h, &instr->starting_lamports_l,
        instr->starting_lamports_h, instr->starting_lamports_l,
        fd_txn_account_get_lamports( account ) );
    }
  }
}

void
fd_instr_info_init_from_txn_instr( fd_instr_info_t *      instr,
                                   fd_exec_txn_ctx_t *    txn_ctx,
                                   fd_txn_instr_t const * txn_instr ) {

  fd_txn_t const *      txn_descriptor = TXN( &txn_ctx->txn );
  uchar *               instr_acc_idxs = (uchar *)txn_ctx->txn.payload + txn_instr->acct_off;

  instr->program_id = txn_instr->program_id;

  /* See note in fd_instr_info.h. TLDR capping this value at 256 should have
     literally 0 effect on program execution, down to the error codes. This
     is purely for the sake of not increasing the overall memory footprint of the
     transaction context. If this change causes issues, we may need to increase
     the array sizes in the instr info. */
  instr->acct_cnt = fd_ushort_min( txn_instr->acct_cnt, FD_INSTR_ACCT_MAX );
  instr->data_sz  = txn_instr->data_sz;
  instr->data     = (uchar *)txn_ctx->txn.payload + txn_instr->data_off;

  uchar acc_idx_seen[ FD_INSTR_ACCT_MAX ];
  memset(acc_idx_seen, 0, FD_INSTR_ACCT_MAX);

  for( ushort i=0; i<instr->acct_cnt; i++ ) {
    ushort acc_idx = instr_acc_idxs[i];

    fd_instr_info_setup_instr_account( instr,
                                       acc_idx_seen,
                                       acc_idx,
                                       acc_idx,
                                       i,
                                       (uchar)fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, instr_acc_idxs[i] ),
                                       (uchar)fd_txn_is_signer( txn_descriptor, instr_acc_idxs[i] ) );

  }
}

int
fd_instr_info_sum_account_lamports( fd_instr_info_t const * instr,
                                    fd_exec_txn_ctx_t *     txn_ctx,
                                    ulong *                 total_lamports_h,
                                    ulong *                 total_lamports_l ) {
  *total_lamports_h = 0UL;
  *total_lamports_l = 0UL;
  for( ulong i=0UL; i<instr->acct_cnt; ++i ) {
    ushort idx_in_txn = instr->accounts[i].index_in_transaction;
    fd_txn_account_t const * account = &txn_ctx->accounts[ idx_in_txn ];

    if( !fd_txn_account_get_meta( account ) ||
        instr->is_duplicate[i] ) {
      continue;
    }

    /* Perform a checked add on a fd_uwide */
    ulong tmp_total_lamports_h = 0UL;
    ulong tmp_total_lamports_l = 0UL;

    fd_uwide_inc( &tmp_total_lamports_h, &tmp_total_lamports_l, *total_lamports_h, *total_lamports_l,
                  fd_txn_account_get_lamports( account ) );

    if( tmp_total_lamports_h < *total_lamports_h ) {
      return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
    }

    *total_lamports_h = tmp_total_lamports_h;
    *total_lamports_l = tmp_total_lamports_l;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
