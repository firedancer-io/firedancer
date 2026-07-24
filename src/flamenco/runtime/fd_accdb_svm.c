#include "fd_accdb_svm.h"
#include "fd_hashes.h"
#include "fd_bank.h"
#include "../capture/fd_capture_ctx.h"
#include "../events/fd_event_runtime.h"

static void
log_account_change( fd_bank_t const *  bank,
                    fd_acc_t * ro,
                    fd_capture_ctx_t * capture_ctx ) {
  if( FD_UNLIKELY( capture_ctx &&
                   capture_ctx->capture_solcap &&
                  bank->f.slot>=capture_ctx->solcap_start_slot ) ) {
    fd_solana_account_meta_t solana_meta[1];
    fd_solana_account_meta_init( solana_meta, ro->lamports, ro->owner, ro->executable );
    fd_capture_link_write_account_update(
        capture_ctx,
        capture_ctx->current_txn_idx,
        (fd_pubkey_t const *)ro->pubkey,
        solana_meta,
        bank->f.slot,
        ro->data,
        ro->data_len );
  }
}

fd_acc_t
fd_accdb_svm_open_rw( fd_bank_t *             bank,
                      fd_accdb_t *            accdb,
                      fd_accdb_svm_update_t * update,
                      fd_pubkey_t const *     pubkey,
                      int                     create ) {
  fd_acc_t acc = fd_accdb_write_one( accdb, bank->accdb_fork_id, pubkey->uc );
  if( FD_UNLIKELY( !acc.lamports && !create ) ) {
    fd_accdb_unwrite_one( accdb, &acc );
    return acc;
  }

  update->lamports_before = acc.lamports;
  update->data_len_before = acc.data_len;
  fd_memcpy( update->owner_before, acc.owner, 32UL );

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash_simple( acc.pubkey, acc.owner, acc.lamports, acc.executable, acc.data, acc.data_len, hash );

  fd_lthash_value_t * bank_lthash = fd_bank_lthash_locking_modify( bank );
  fd_lthash_sub( bank_lthash, hash );
  fd_bank_lthash_end_locking_modify( bank );

  return acc;
}

void
fd_accdb_svm_close_rw( fd_bank_t *             bank,
                       fd_accdb_t *            accdb,
                       fd_capture_ctx_t *      capture_ctx,
                       fd_acc_t *              acc,
                       fd_accdb_svm_update_t * update ) {
  if( FD_UNLIKELY( acc->lamports>update->lamports_before ) ) {
    ulong delta = acc->lamports-update->lamports_before;
    FD_TEST( !__builtin_uaddl_overflow( bank->f.capitalization, delta, &bank->f.capitalization ) );
  } else if( FD_UNLIKELY( acc->lamports<update->lamports_before ) ) {
    ulong delta = update->lamports_before-acc->lamports;
    FD_TEST( !__builtin_usubl_overflow( bank->f.capitalization, delta, &bank->f.capitalization ) );
  }

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash_simple( acc->pubkey, acc->owner, acc->lamports, acc->executable, acc->data, acc->data_len, hash );

  fd_lthash_value_t * bank_lthash = fd_bank_lthash_locking_modify( bank );
  fd_lthash_add( bank_lthash, hash );
  fd_bank_lthash_end_locking_modify( bank );

  log_account_change( bank, acc, capture_ctx );
  if( FD_UNLIKELY( fd_bank_report_runtime_diffs( bank ) ) ) fd_event_runtime_block_account( bank, acc->pubkey, update->owner_before, acc->owner, update->lamports_before, acc->lamports, update->data_len_before, acc->data_len, acc->executable );
  acc->commit = 1;
  fd_accdb_unwrite_one( accdb, acc );
}

void
fd_accdb_svm_credit( fd_bank_t *         bank,
                     fd_accdb_t *        accdb,
                     fd_capture_ctx_t *  capture_ctx,
                     fd_pubkey_t const * pubkey,
                     ulong               lamports_add ) {
  if( FD_UNLIKELY( !lamports_add ) ) return;

  fd_acc_t acc = fd_accdb_write_one( accdb, bank->accdb_fork_id, pubkey->uc );

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash_simple( acc.pubkey, acc.owner, acc.lamports, acc.executable, acc.data, acc.data_len, hash );
  ulong lamports_pre = acc.lamports;
  FD_TEST( !__builtin_uaddl_overflow( acc.lamports, lamports_add, &acc.lamports ) );
  FD_TEST( !__builtin_uaddl_overflow( bank->f.capitalization, lamports_add, &bank->f.capitalization ) );

  fd_lthash_value_t post[1];
  fd_hashes_update_simple( post, hash, pubkey->uc, acc.owner, acc.lamports, acc.executable, acc.data, acc.data_len, bank, capture_ctx );
  if( FD_UNLIKELY( fd_bank_report_runtime_diffs( bank ) ) ) fd_event_runtime_block_account( bank, acc.pubkey, acc.owner, acc.owner, lamports_pre, acc.lamports, acc.data_len, acc.data_len, acc.executable );
  acc.commit = 1;
  fd_accdb_unwrite_one( accdb, &acc );
}

void
fd_accdb_svm_write( fd_bank_t *         bank,
                    fd_accdb_t *        accdb,
                    fd_capture_ctx_t *  capture_ctx,
                    fd_pubkey_t const * pubkey,
                    fd_pubkey_t const * owner,
                    void const *        data,
                    ulong               sz,
                    ulong               lamports_min,
                    int                 exec_bit ) {
  fd_acc_t acc = fd_accdb_write_one( accdb, bank->accdb_fork_id, pubkey->uc );
  ulong lamports_pre = acc.lamports;
  ulong data_len_pre = acc.data_len;
  uchar owner_pre[ 32 ]; fd_memcpy( owner_pre, acc.owner, 32UL );

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash_simple( acc.pubkey, acc.owner, acc.lamports, acc.executable, acc.data, acc.data_len, hash );

  if( FD_UNLIKELY( acc.lamports<lamports_min ) ) {
    ulong delta = lamports_min - acc.lamports;
    acc.lamports = lamports_min;
    FD_TEST( !__builtin_uaddl_overflow( bank->f.capitalization, delta, &bank->f.capitalization ) );
  }

  fd_memcpy( acc.owner, owner, 32UL );
  acc.executable = !!exec_bit;

  fd_memcpy( acc.data, data, sz );
  acc.data_len = sz;

  fd_lthash_value_t post[1];
  fd_hashes_update_simple( post, hash, pubkey->uc, acc.owner, acc.lamports, acc.executable, acc.data, acc.data_len, bank, capture_ctx );
  if( FD_UNLIKELY( fd_bank_report_runtime_diffs( bank ) ) ) fd_event_runtime_block_account( bank, acc.pubkey, owner_pre, acc.owner, lamports_pre, acc.lamports, data_len_pre, acc.data_len, acc.executable );
  acc.commit = 1;
  fd_accdb_unwrite_one( accdb, &acc );
}

ulong
fd_accdb_svm_remove( fd_bank_t *         bank,
                     fd_accdb_t *        accdb,
                     fd_capture_ctx_t *  capture_ctx,
                     fd_pubkey_t const * pubkey ) {
  fd_acc_t acc = fd_accdb_write_one( accdb, bank->accdb_fork_id, pubkey->uc );
  if( FD_UNLIKELY( !acc.lamports ) ) {
    fd_accdb_unwrite_one( accdb, &acc );
    return 0UL;
  }

  ulong burned = acc.lamports;

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash_simple( acc.pubkey, acc.owner, acc.lamports, acc.executable, acc.data, acc.data_len, hash );

  bank->f.capitalization -= burned;
  acc.lamports = 0UL;

  fd_lthash_value_t post[1];
  fd_hashes_update_simple( post, hash, pubkey->uc, acc.owner, acc.lamports, acc.executable, acc.data, acc.data_len, bank, capture_ctx );
  if( FD_UNLIKELY( fd_bank_report_runtime_diffs( bank ) ) ) fd_event_runtime_block_account( bank, acc.pubkey, acc.owner, acc.owner, burned, acc.lamports, acc.data_len, acc.data_len, acc.executable );
  acc.commit = 1;
  fd_accdb_unwrite_one( accdb, &acc );
  return burned;
}
