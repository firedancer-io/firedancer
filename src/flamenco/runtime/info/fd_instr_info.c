#include "fd_instr_info.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../../../util/bits/fd_uwide.h"

void
fd_convert_txn_instr_to_instr( fd_exec_txn_ctx_t *    txn_ctx,
                               fd_txn_instr_t const * txn_instr,
                               fd_instr_info_t *      instr ) {

  fd_txn_t const *      txn_descriptor = txn_ctx->txn_descriptor;
  fd_rawtxn_b_t const * txn_raw = txn_ctx->_txn_raw;
  const fd_pubkey_t *   account_keys = txn_ctx->account_keys;

  instr->program_id        = txn_instr->program_id;
  instr->program_id_pubkey = account_keys[txn_instr->program_id];

  /* See note in fd_instr_info.h. TLDR capping this value at 256 should have
     literally 0 effect on program execution, down to the error codes. This
     is purely for the sake of not increasing the overall memory footprint of the
     transaction context. If this change causes issues, we may need to increase
     the array sizes in the instr info. */
  instr->acct_cnt          = fd_ushort_min( txn_instr->acct_cnt, FD_INSTR_ACCT_MAX );
  instr->data_sz           = txn_instr->data_sz;
  instr->data              = (uchar *)txn_raw->raw + txn_instr->data_off;

  uchar acc_idx_seen[256];
  memset(acc_idx_seen, 0, 256);
  uchar * instr_acc_idxs = (uchar *)txn_raw->raw + txn_instr->acct_off;
  for( ulong i = 0; i < instr->acct_cnt; i++ ) {
    uchar acc_idx = instr_acc_idxs[i];

    instr->is_duplicate[i] = acc_idx_seen[acc_idx];
    if( FD_LIKELY( !acc_idx_seen[acc_idx] ) ) {
      /* This is the first time seeing this account */
      acc_idx_seen[acc_idx] = 1;
    }

    instr->accts[i].index_in_transaction = acc_idx;
    instr->accts[i].index_in_caller      = acc_idx;
    instr->accts[i].index_in_callee      = (ushort)i;
    if( fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, (int)instr_acc_idxs[i]) ) {
        instr->accts[i].is_writable = 1;
    }
    if( fd_txn_is_signer( txn_descriptor, instr_acc_idxs[i] ) ) {
      instr->accts[i].is_signer = 1;
    }
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
    ushort idx_in_txn = instr->accts[i].index_in_transaction;

    if( txn_ctx->accounts[ idx_in_txn ].const_meta == NULL ||
        instr->is_duplicate[i] ) {
      continue;
    }

    /* Perform a checked add on a fd_uwide */
    ulong tmp_total_lamports_h = 0UL;
    ulong tmp_total_lamports_l = 0UL;

    fd_uwide_inc( &tmp_total_lamports_h, &tmp_total_lamports_l, *total_lamports_h, *total_lamports_l,
                  txn_ctx->accounts[ idx_in_txn ].const_meta->info.lamports );

    if( tmp_total_lamports_h < *total_lamports_h ) {
      return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
    }

    *total_lamports_h = tmp_total_lamports_h;
    *total_lamports_l = tmp_total_lamports_l;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
