#include "fd_instr_info.h"

#include "fd_account.h"

void
fd_convert_txn_instr_to_instr( fd_txn_t const *                 txn_descriptor,
                               fd_rawtxn_b_t const *            txn_raw,
                               fd_txn_instr_t const *           txn_instr,
                               fd_pubkey_t const *              accounts,
                               fd_borrowed_account_t *          borrowed_accounts,
                               fd_instr_info_t *                instr ) {
  instr->program_id = txn_instr->program_id;
  instr->program_id_pubkey = accounts[txn_instr->program_id];
  instr->acct_cnt = txn_instr->acct_cnt;
  instr->data_sz = txn_instr->data_sz;
  instr->data =  (uchar *)txn_raw->raw + txn_instr->data_off;

  uchar * instr_acc_idxs = (uchar *)txn_raw->raw + txn_instr->acct_off;
  for( ulong i = 0; i < instr->acct_cnt; i++ ) {
    instr->acct_txn_idxs[i] = instr_acc_idxs[i];
    instr->acct_pubkeys[i] = accounts[instr_acc_idxs[i]];
    instr->borrowed_accounts[i] = &borrowed_accounts[instr_acc_idxs[i]];

    instr->acct_flags[i] = 0;
    if( fd_account_is_writable_idx( txn_descriptor, txn_instr->program_id, instr_acc_idxs[i] ) ) {
      instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;
    }
    if( fd_txn_is_signer( txn_descriptor, instr_acc_idxs[i] ) ) {
      instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
    }
  }
}
