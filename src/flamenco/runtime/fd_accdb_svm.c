#include "fd_accdb_svm.h"
#include "fd_hashes.h"
#include "fd_bank.h"
#include "../accdb/fd_accdb_sync.h"
#include "../capture/fd_capture_ctx.h"

static void
log_account_change( fd_capture_ctx_t * capture_ctx,
                    fd_bank_t const *  bank,
                    fd_accdb_ro_t *    ro ) {
  if( capture_ctx && capture_ctx->capture_solcap &&
      bank->f.slot>=capture_ctx->solcap_start_slot ) {
    fd_solana_account_meta_t solana_meta[1];
    fd_solana_account_meta_init(
        solana_meta,
        fd_accdb_ref_lamports  ( ro ),
        fd_accdb_ref_owner     ( ro ),
        !!fd_accdb_ref_exec_bit( ro )
    );
    fd_capture_link_write_account_update(
        capture_ctx,
        capture_ctx->current_txn_idx,
        fd_accdb_ref_address( ro ),
        solana_meta,
        bank->f.slot,
        fd_accdb_ref_data_const( ro ),
        fd_accdb_ref_data_sz   ( ro )
    );
  }
}

fd_accdb_rw_t *
fd_accdb_svm_open_rw( fd_accdb_user_t *         accdb,
                      fd_bank_t *               bank,
                      fd_funk_txn_xid_t const * xid,
                      fd_accdb_rw_t *           rw,
                      fd_accdb_svm_update_t *   update,
                      fd_pubkey_t const *       pubkey,
                      ulong                     data_max,
                      int                       flags ) {
  if( FD_UNLIKELY( !fd_accdb_open_rw( accdb, rw, xid, pubkey, data_max, flags&~FD_ACCDB_FLAG_TRUNCATE ) ) ) {
    return NULL;
  }

  update->lamports_before = fd_accdb_ref_lamports( rw->ro );

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash( pubkey, rw->meta, fd_accdb_ref_data_const( rw->ro ), hash );
  fd_lthash_value_t * bank_lthash = fd_type_pun( fd_bank_lthash_locking_modify( bank ) );
  fd_lthash_sub( bank_lthash, hash );
  fd_bank_lthash_end_locking_modify( bank );

  return rw;
}

void
fd_accdb_svm_close_rw( fd_accdb_user_t *       accdb,
                       fd_bank_t *             bank,
                       fd_capture_ctx_t *      capture_ctx,
                       fd_accdb_rw_t *         rw,
                       fd_accdb_svm_update_t * update ) {

  ulong * cap      = &bank->f.capitalization;
  ulong   lamports = fd_accdb_ref_lamports( rw->ro );
  if( lamports > update->lamports_before ) {
    ulong delta      = lamports - update->lamports_before;
    ulong cap_before = *cap;
    if( FD_UNLIKELY( __builtin_uaddl_overflow( cap_before, delta, cap ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( fd_accdb_ref_address( rw->ro ), addr_b58 );
      FD_LOG_EMERG(( "bank capitalization overflow detected (slot=%lu addr=%s delta=%lu cap_before=%lu)",
                     bank->f.slot, addr_b58, delta, cap_before ));
    }
  } else if( lamports < update->lamports_before ) {
    ulong delta      = update->lamports_before - lamports;
    ulong cap_before = *cap;
    if( FD_UNLIKELY( __builtin_usubl_overflow( cap_before, delta, cap ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( fd_accdb_ref_address( rw->ro ), addr_b58 );
      FD_LOG_EMERG(( "bank capitalization underflow detected (slot=%lu addr=%s delta=%lu cap_before=%lu)",
                     bank->f.slot, addr_b58, delta, cap_before ));
    }
  }

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash( fd_accdb_ref_address( rw->ro ), rw->meta, fd_accdb_ref_data_const( rw->ro ), hash );
  fd_lthash_value_t * bank_lthash = fd_type_pun( fd_bank_lthash_locking_modify( bank ) );
  fd_lthash_add( bank_lthash, hash );
  fd_bank_lthash_end_locking_modify( bank );

  log_account_change( capture_ctx, bank, rw->ro );

  fd_accdb_close_rw( accdb, rw );
}

void
fd_accdb_svm_credit( fd_accdb_user_t *         accdb,
                     fd_bank_t *               bank,
                     fd_funk_txn_xid_t const * xid,
                     fd_capture_ctx_t *        capture_ctx,
                     fd_pubkey_t const *       pubkey,
                     ulong                     lamports_add ) {
  if( FD_UNLIKELY( !lamports_add ) ) return;

  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( accdb, rw, xid, pubkey, 0UL, FD_ACCDB_FLAG_CREATE ) );
  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash( pubkey, rw->meta, fd_accdb_ref_data_const( rw->ro ), hash );

  ulong lamports = fd_accdb_ref_lamports( rw->ro );
  if( FD_UNLIKELY( __builtin_uaddl_overflow( lamports, lamports_add, &lamports ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( pubkey->key, addr_b58 );
    FD_LOG_EMERG(( "integer overflow while crediting %lu lamports to %s (previous balance %lu)",
                    lamports_add, addr_b58, fd_accdb_ref_lamports( rw->ro ) ));
  }
  fd_accdb_ref_lamports_set( rw, lamports );

  ulong * cap = &bank->f.capitalization;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( *cap, lamports_add, cap ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( pubkey->key, addr_b58 );
    FD_LOG_EMERG(( "bank capitalization overflow detected (slot=%lu addr=%s delta=%lu cap_before=%lu)",
                   bank->f.slot, addr_b58, lamports_add, *cap - lamports_add ));
  }

  fd_hashes_update_lthash( pubkey, rw->meta, hash, bank, capture_ctx );
  fd_accdb_close_rw( accdb, rw );
}

void
fd_accdb_svm_write( fd_accdb_user_t *         accdb,
                    fd_bank_t *               bank,
                    fd_funk_txn_xid_t const * xid,
                    fd_capture_ctx_t *        capture_ctx,
                    fd_pubkey_t const *       pubkey,
                    fd_pubkey_t const *       owner,
                    void const *              data,
                    ulong                     sz,
                    ulong                     lamports_min,
                    int                       exec_bit,
                    int                       flags ) {
  fd_accdb_rw_t rw[1];
  if( !fd_accdb_open_rw( accdb, rw, xid, pubkey, sz, flags&FD_ACCDB_FLAG_CREATE ) ) {
    return;
  }

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash( pubkey, rw->meta, fd_accdb_ref_data_const( rw->ro ), hash );

  ulong lamports = fd_accdb_ref_lamports( rw->ro );
  if( FD_UNLIKELY( lamports < lamports_min ) ) {
    ulong delta = lamports_min - lamports;
    fd_accdb_ref_lamports_set( rw, lamports_min );

    ulong * cap = &bank->f.capitalization;
    if( FD_UNLIKELY( __builtin_uaddl_overflow( *cap, delta, cap ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( pubkey->key, addr_b58 );
      FD_LOG_EMERG(( "bank capitalization overflow detected (slot=%lu addr=%s delta=%lu cap_before=%lu)",
                     bank->f.slot, addr_b58, delta, *cap - delta ));
    }
  }

  fd_accdb_ref_owner_set   ( rw, owner      );
  fd_accdb_ref_exec_bit_set( rw, !!exec_bit );
  if( !!( flags & FD_ACCDB_FLAG_TRUNCATE ) ||
      fd_accdb_ref_data_sz( rw->ro ) < sz ) {
    fd_accdb_ref_data_sz_set( accdb, rw, sz, 0 );
  }
  fd_memcpy( fd_accdb_ref_data( rw ), data, sz );

  fd_hashes_update_lthash( pubkey, rw->meta, hash, bank, capture_ctx );
  fd_accdb_close_rw( accdb, rw );
}

ulong
fd_accdb_svm_remove( fd_accdb_user_t *         accdb,
                     fd_bank_t *               bank,
                     fd_funk_txn_xid_t const * xid,
                     fd_capture_ctx_t *        capture_ctx,
                     fd_pubkey_t const *       pubkey ) {
  fd_accdb_rw_t rw[1];
  if( !fd_accdb_open_rw( accdb, rw, xid, pubkey, 0UL, 0 ) ) return 0UL;

  fd_lthash_value_t hash[1];
  fd_hashes_account_lthash( pubkey, rw->meta, fd_accdb_ref_data_const( rw->ro ), hash );

  ulong lamports = fd_accdb_ref_lamports( rw->ro );
  ulong * cap = &bank->f.capitalization;
  if( FD_UNLIKELY( __builtin_usubl_overflow( *cap, lamports, cap ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( pubkey->key, addr_b58 );
    FD_LOG_EMERG(( "bank capitalization underflow detected (slot=%lu addr=%s delta=%lu cap_before=%lu)",
                   bank->f.slot, addr_b58, lamports, *cap + lamports ));
  }
  fd_accdb_ref_lamports_set( rw, 0UL );

  fd_hashes_update_lthash( pubkey, rw->meta, hash, bank, capture_ctx );
  fd_accdb_close_rw( accdb, rw );
  return lamports;
}
