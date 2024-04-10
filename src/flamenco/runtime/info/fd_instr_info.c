#include "fd_instr_info.h"
#include "../fd_account.h"

void
fd_convert_txn_instr_to_instr( fd_txn_t const *          txn_descriptor,
                               fd_rawtxn_b_t const *     txn_raw,
                               fd_txn_instr_t const *    txn_instr,
                               fd_pubkey_t const *       accounts,
                               fd_borrowed_account_t *   borrowed_accounts,
                               fd_instr_info_t *         instr ) {
  ulong starting_lamports = 0;
  instr->program_id = txn_instr->program_id;
  instr->program_id_pubkey = accounts[txn_instr->program_id];
  instr->acct_cnt = txn_instr->acct_cnt;
  instr->data_sz = txn_instr->data_sz;
  instr->data =  (uchar *)txn_raw->raw + txn_instr->data_off;

  uchar acc_idx_seen[256];
  memset(acc_idx_seen, 0, 256);
  uchar * instr_acc_idxs = (uchar *)txn_raw->raw + txn_instr->acct_off;
  for( ulong i = 0; i < instr->acct_cnt; i++ ) {
    if( borrowed_accounts != NULL ) {
      instr->borrowed_accounts[i] = &borrowed_accounts[instr_acc_idxs[i]];
    } else {
      instr->borrowed_accounts[i] = NULL;
    }

    uchar acc_idx = instr_acc_idxs[i];

    instr->is_duplicate[i] = acc_idx_seen[acc_idx];
    if( FD_LIKELY( !acc_idx_seen[acc_idx] ) ) {
      /* This is the first time seeing this account */
      acc_idx_seen[acc_idx] = 1;
      if( instr->borrowed_accounts[i] != NULL && instr->borrowed_accounts[i]->const_meta != NULL ) {
        starting_lamports += instr->borrowed_accounts[i]->const_meta->info.lamports;
      }
    }

    instr->acct_txn_idxs[i] = acc_idx;
    instr->acct_pubkeys[i] = accounts[instr_acc_idxs[i]];
    instr->acct_flags[i] = 0;
    if( instr_acc_idxs[i] != txn_instr->program_id &&
        fd_txn_account_is_writable_idx( txn_descriptor, accounts, instr_acc_idxs[i] ) ) {
      instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;
    }
    if( fd_txn_is_signer( txn_descriptor, instr_acc_idxs[i] ) ) {
      instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
    }
  }

  instr->starting_lamports = starting_lamports;
}

FD_FN_PURE int
fd_instr_any_signed( fd_instr_info_t const * info,
                     fd_pubkey_t const *     pubkey ) {
  int is_signer = 0;
  for( ulong j=0UL; j < info->acct_cnt; j++ )
    is_signer |=
      ( ( !!fd_instr_acc_is_signer_idx( info, j ) ) &
        ( 0==memcmp( pubkey->key, info->acct_pubkeys[j].key, sizeof(fd_pubkey_t) ) ) );
  return is_signer;
}

FD_FN_PURE ulong
fd_instr_info_sum_account_lamports( fd_instr_info_t const * instr ) {

  ulong total_lamports = 0;

  for( ulong i = 0; i < instr->acct_cnt; i++ ) {

    if( instr->borrowed_accounts[i] == NULL )
      continue;

    if( ( instr->is_duplicate[i]                          ) |
        ( instr->borrowed_accounts[i]->const_meta == NULL ) )
      continue;

    ulong acct_lamports = instr->borrowed_accounts[i]->const_meta->info.lamports;

    if( FD_UNLIKELY( __builtin_uaddl_overflow( total_lamports, acct_lamports, &total_lamports ) ) )
      FD_LOG_ERR(( "integer overflow" ));

  }

  return total_lamports;
}
