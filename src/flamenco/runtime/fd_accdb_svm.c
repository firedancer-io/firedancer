#include "fd_accdb_svm.h"
#include "fd_hashes.h"
#include "fd_bank.h"
#include "../capture/fd_capture_ctx.h"

static void
log_account_change( fd_bank_t const *  bank,
                    fd_accdb_entry_t * ro,
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

fd_accdb_entry_t
fd_accdb_svm_open_rw( fd_bank_t *             bank,
                      fd_accdb_t *            accdb,
                      fd_accdb_svm_update_t * update,
                      fd_pubkey_t const *     pubkey,
                      int                     create ) {
  fd_accdb_entry_t entry = fd_accdb_write_one( accdb, bank->accdb_fork_id, pubkey->uc, create, 0 );
  if( FD_UNLIKELY( !entry.lamports ) ) return entry;

  update->lamports_before = entry.lamports;

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash_simple( entry.pubkey, entry.owner, entry.lamports, entry.executable, entry.data, entry.data_len, hash );

  fd_lthash_value_t * bank_lthash = fd_bank_lthash_locking_modify( bank );
  fd_lthash_sub( bank_lthash, hash );
  fd_bank_lthash_end_locking_modify( bank );

  return entry;
}

void
fd_accdb_svm_close_rw( fd_bank_t *             bank,
                       fd_accdb_t *            accdb,
                       fd_capture_ctx_t *      capture_ctx,
                       fd_accdb_entry_t *      entry,
                       fd_accdb_svm_update_t * update ) {
  if( FD_UNLIKELY( entry->lamports>update->lamports_before ) ) {
    ulong delta = entry->lamports-update->lamports_before;
    FD_TEST( !__builtin_uaddl_overflow( bank->f.capitalization, delta, &bank->f.capitalization ) );
  } else if( FD_UNLIKELY( entry->lamports<update->lamports_before ) ) {
    ulong delta = update->lamports_before-entry->lamports;
    FD_TEST( !__builtin_usubl_overflow( bank->f.capitalization, delta, &bank->f.capitalization ) );
  }

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash_simple( entry->pubkey, entry->owner, entry->lamports, entry->executable, entry->data, entry->data_len, hash );

  fd_lthash_value_t * bank_lthash = fd_bank_lthash_locking_modify( bank );
  fd_lthash_add( bank_lthash, hash );
  fd_bank_lthash_end_locking_modify( bank );

  log_account_change( bank, entry, capture_ctx );
  fd_accdb_unwrite_one( accdb, entry );
}

void
fd_accdb_svm_credit( fd_bank_t *         bank,
                     fd_accdb_t *        accdb,
                     fd_capture_ctx_t *  capture_ctx,
                     fd_pubkey_t const * pubkey,
                     ulong               lamports_add ) {
  if( FD_UNLIKELY( !lamports_add ) ) return;

  fd_accdb_entry_t entry = fd_accdb_write_one( accdb, bank->accdb_fork_id, pubkey->uc, 1, 0 );

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash_simple( entry.pubkey, entry.owner, entry.lamports, entry.executable, entry.data, entry.data_len, hash );
  FD_TEST( !__builtin_uaddl_overflow( entry.lamports, lamports_add, &entry.lamports ) );
  FD_TEST( !__builtin_uaddl_overflow( bank->f.capitalization, lamports_add, &bank->f.capitalization ) );

  fd_lthash_value_t post[1];
  fd_hashes_update_simple( post, hash, pubkey->uc, entry.owner, entry.lamports, entry.executable, entry.data, entry.data_len, bank, capture_ctx );
  fd_accdb_unwrite_one( accdb, &entry );
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
  fd_accdb_entry_t entry = fd_accdb_write_one( accdb, bank->accdb_fork_id, pubkey->uc, 1, 0 );
  if( FD_UNLIKELY( !entry.lamports ) ) return;

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash_simple( entry.pubkey, entry.owner, entry.lamports, entry.executable, entry.data, entry.data_len, hash );

  if( FD_UNLIKELY( entry.lamports<lamports_min ) ) {
    entry.lamports = lamports_min;
    FD_TEST( !__builtin_uaddl_overflow( bank->f.capitalization, lamports_min-entry.lamports, &bank->f.capitalization ) );
  }

  fd_memcpy( entry.owner, owner, 32UL );
  entry.executable = !!exec_bit;

  fd_memcpy( entry.data, data, sz );
  if( FD_UNLIKELY( entry.data_len<sz ) ) {
    entry.data_len = sz;
    fd_memset( entry.data+entry.data_len, 0, sz-entry.data_len );
  }

  fd_lthash_value_t post[1];
  fd_hashes_update_simple( post, hash, pubkey->uc, entry.owner, entry.lamports, entry.executable, entry.data, entry.data_len, bank, capture_ctx );
  fd_accdb_unwrite_one( accdb, &entry );
}

ulong
fd_accdb_svm_remove( fd_bank_t *         bank,
                     fd_accdb_t *        accdb,
                     fd_capture_ctx_t *  capture_ctx,
                     fd_pubkey_t const * pubkey ) {
  fd_accdb_entry_t entry = fd_accdb_write_one( accdb, bank->accdb_fork_id, pubkey->uc, 0, 0 );
  if( FD_UNLIKELY( !entry.lamports ) ) return 0UL;

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash_simple( entry.pubkey, entry.owner, entry.lamports, entry.executable, entry.data, entry.data_len, hash );

  FD_TEST( !__builtin_usubl_overflow( bank->f.capitalization, entry.lamports, &bank->f.capitalization ) );
  entry.lamports = 0UL;
  
  fd_lthash_value_t post[1];
  fd_hashes_update_simple( post, hash, pubkey->uc, entry.owner, entry.lamports, entry.executable, entry.data, entry.data_len, bank, capture_ctx );
  fd_accdb_unwrite_one( accdb, &entry );
  return entry.lamports;
}
