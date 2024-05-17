#include "fd_instr_info.h"

#include "../fd_account.h"
#include "../../../util/bits/fd_uwide.h"

/* demote_program_id() in https://github.com/solana-labs/solana/blob/061bed0a8ca80afb97f4438155e8a6b47bbf7f6d/sdk/program/src/message/versions/v0/loaded.rs#L150 */
int
fd_txn_account_is_demotion( fd_exec_txn_ctx_t * txn_ctx, int idx )
{
  uint is_program = 0;
  for ( ulong j = 0; j < txn_ctx->txn_descriptor->instr_cnt; j++ ) {
    if ( txn_ctx->txn_descriptor->instr[j].program_id == idx ) {
      is_program = 1;
      break;
    }
  }

  uint bpf_upgradeable_in_txn = 0;
  for( ulong j = 0; j < txn_ctx->accounts_cnt; j++ ) {
    const fd_pubkey_t * acc = &txn_ctx->accounts[j];
    if ( memcmp( acc->uc, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) {
      bpf_upgradeable_in_txn = 1;
      break;
    }
  }
  return (is_program && !bpf_upgradeable_in_txn);
}

void
fd_convert_txn_instr_to_instr( fd_exec_txn_ctx_t *     txn_ctx,
                               fd_txn_instr_t const *  txn_instr,
                               fd_borrowed_account_t * borrowed_accounts,
                               fd_instr_info_t *       instr ) {

  fd_txn_t const *      txn_descriptor = txn_ctx->txn_descriptor;
  fd_rawtxn_b_t const * txn_raw = txn_ctx->_txn_raw;
  const fd_pubkey_t *   accounts = txn_ctx->accounts;

  /* TODO: Lamport check may be redundant */
  ulong starting_lamports_h = 0;
  ulong starting_lamports_l = 0;

  instr->program_id        = txn_instr->program_id;
  instr->program_id_pubkey = accounts[txn_instr->program_id];
  instr->acct_cnt          = txn_instr->acct_cnt;
  instr->data_sz           = txn_instr->data_sz;
  instr->data              = (uchar *)txn_raw->raw + txn_instr->data_off;

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
      if( instr->borrowed_accounts[i] != NULL && instr->borrowed_accounts[i]->const_meta != NULL ) {
        fd_uwide_inc( &starting_lamports_h, &starting_lamports_l, 
                      starting_lamports_h, starting_lamports_l,
                      instr->borrowed_accounts[i]->const_meta->info.lamports );
      }
      acc_idx_seen[acc_idx] = 1;
    }

    instr->acct_txn_idxs[i] = acc_idx;
    instr->acct_pubkeys[i] = accounts[instr_acc_idxs[i]];
    instr->acct_flags[i] = 0;

    if( fd_account_is_writable_idx( txn_descriptor, accounts, txn_instr->program_id, instr_acc_idxs[i] ) &&
        !fd_txn_account_is_demotion( txn_ctx, instr_acc_idxs[i] ) ) {
        instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;
    }
    if( fd_txn_is_signer( txn_descriptor, instr_acc_idxs[i] ) ) {
      instr->acct_flags[i] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
    }
  }

  instr->starting_lamports_h = starting_lamports_h;
  instr->starting_lamports_l = starting_lamports_l;

}

int
fd_instr_any_signed( fd_instr_info_t const * info,
                     fd_pubkey_t const *     pubkey ) {
  int is_signer = 0;
  for( ulong j=0UL; j < info->acct_cnt; j++ )
    is_signer |=
      ( ( !!fd_instr_acc_is_signer_idx( info, j ) ) &
        ( 0==memcmp( pubkey->key, info->acct_pubkeys[j].key, sizeof(fd_pubkey_t) ) ) );
  return is_signer;
}

/* https://github.com/anza-xyz/agave/blob/9706a6464665f7ebd6ead47f0d12f853ccacbab9/sdk/src/transaction_context.rs#L40 */
int
fd_instr_info_sum_account_lamports( fd_instr_info_t const * instr, 
                                    ulong *                 total_lamports_h, 
                                    ulong *                 total_lamports_l ) {
  *total_lamports_h = 0UL;
  *total_lamports_l = 0UL;
  for( ulong i=0UL; i<instr->acct_cnt; ++i ) {
    if( instr->borrowed_accounts[i] == NULL || 
        instr->is_duplicate[i]              || 
        instr->borrowed_accounts[i]->const_meta == NULL ) {
      continue;
    }

    /* Perform a checked add on a fd_uwide */
    ulong tmp_total_lamports_h = 0UL;
    ulong tmp_total_lamports_l = 0UL;

    fd_uwide_inc( &tmp_total_lamports_h, &tmp_total_lamports_l, *total_lamports_h, *total_lamports_l,
                  instr->borrowed_accounts[i]->const_meta->info.lamports );
    
    if( tmp_total_lamports_h < *total_lamports_h ) {
      return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
    }

    *total_lamports_h = tmp_total_lamports_h;
    *total_lamports_l = tmp_total_lamports_l;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
