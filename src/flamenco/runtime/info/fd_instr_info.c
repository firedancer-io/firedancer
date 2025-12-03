#include "fd_instr_info.h"
#include "../fd_runtime.h"
#include "../../../util/bits/fd_uwide.h"

void
fd_instr_info_accumulate_starting_lamports( fd_instr_info_t * instr,
                                            fd_txn_out_t *    txn_out,
                                            ushort            idx_in_callee,
                                            ushort            idx_in_txn ) {
  if( FD_LIKELY( !instr->is_duplicate[ idx_in_callee ] ) ) {

    fd_account_meta_t const * meta = txn_out->accounts.metas[ idx_in_txn ];
    if( meta ) {
      fd_uwide_inc(
        &instr->starting_lamports_h, &instr->starting_lamports_l,
        instr->starting_lamports_h, instr->starting_lamports_l,
        meta->lamports );
    }
  }
}

void
fd_instr_info_init_from_txn_instr( fd_instr_info_t *      instr,
                                   fd_bank_t *            bank,
                                   fd_txn_in_t const *    txn_in,
                                   fd_txn_out_t *         txn_out,
                                   fd_txn_instr_t const * txn_instr ) {

  fd_txn_t const * txn_descriptor = TXN( txn_in->txn );
  uchar *          instr_acc_idxs = (uchar *)txn_in->txn->payload + txn_instr->acct_off;

  /* Set the stack height to 1 (since this is a top-level instruction) */
  instr->stack_height = 1;

  /* Set the program id */
  instr->program_id = txn_instr->program_id;

  /* See note in fd_instr_info.h.  TLDR: capping this value at 256
     should have literally 0 effect on program execution, down to the
     error codes.  This is purely for the sake of not increasing the
     overall memory footprint of the transaction context.  If this
     change causes issues, we may need to increase the array sizes in
     the instr info. */
  instr->acct_cnt = fd_ushort_min( txn_instr->acct_cnt, FD_INSTR_ACCT_MAX );
  instr->data_sz  = txn_instr->data_sz;
  memcpy( instr->data, txn_in->txn->payload+txn_instr->data_off, instr->data_sz );

  uchar acc_idx_seen[ FD_INSTR_ACCT_MAX ] = {0};

  for( ushort i=0; i<instr->acct_cnt; i++ ) {
    ushort acc_idx = instr_acc_idxs[i];

    fd_instr_info_setup_instr_account( instr,
                                       acc_idx_seen,
                                       acc_idx,
                                       acc_idx,
                                       i,
                                       (uchar)fd_runtime_account_is_writable_idx( txn_in, txn_out, bank, instr_acc_idxs[i] ),
                                       (uchar)fd_txn_is_signer( txn_descriptor, instr_acc_idxs[i] ) );

  }
}

int
fd_instr_info_sum_account_lamports( fd_instr_info_t const * instr,
                                    fd_txn_out_t *          txn_out,
                                    ulong *                 total_lamports_h,
                                    ulong *                 total_lamports_l ) {
  *total_lamports_h = 0UL;
  *total_lamports_l = 0UL;
  for( ulong i=0UL; i<instr->acct_cnt; ++i ) {
    ushort idx_in_txn = instr->accounts[i].index_in_transaction;
    fd_account_meta_t const * meta = txn_out->accounts.metas[ idx_in_txn ];

    if( !meta ||
        instr->is_duplicate[i] ) {
      continue;
    }

    /* Perform a checked add on a fd_uwide */
    ulong tmp_total_lamports_h = 0UL;
    ulong tmp_total_lamports_l = 0UL;

    fd_uwide_inc( &tmp_total_lamports_h, &tmp_total_lamports_l, *total_lamports_h, *total_lamports_l, meta->lamports );

    if( tmp_total_lamports_h < *total_lamports_h ) {
      return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
    }

    *total_lamports_h = tmp_total_lamports_h;
    *total_lamports_l = tmp_total_lamports_l;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
