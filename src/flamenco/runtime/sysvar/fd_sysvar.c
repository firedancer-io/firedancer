#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_acc_mgr.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_instr_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../fd_hashes.h"
#include "../fd_runtime.h"

#include "fd_sysvar_rent.h"

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1813 */
void
fd_sysvar_account_update( fd_exec_slot_ctx_t * slot_ctx,
                          fd_pubkey_t const *  address,
                          void const *         data,
                          ulong                sz ) {
  fd_rent_t const * rent    = fd_bank_rent_query( slot_ctx->bank );
  ulong     const   min_bal = fd_rent_exempt_minimum_balance( rent, sz );

  FD_TXN_ACCOUNT_DECL( rec );
  fd_funk_rec_prepare_t prepare = {0};
  fd_txn_account_init_from_funk_mutable( rec, address, slot_ctx->funk, slot_ctx->funk_txn, 1, sz, &prepare );
  fd_lthash_value_t prev_hash[1];
  fd_hashes_account_lthash( address, fd_txn_account_get_meta( rec ), fd_txn_account_get_data( rec ), prev_hash );

  ulong const slot            = fd_bank_slot_get( slot_ctx->bank );
  ulong const lamports_before = fd_txn_account_get_lamports( rec );
  ulong const lamports_after  = fd_ulong_max( lamports_before, min_bal );
  fd_txn_account_set_lamports( rec, lamports_after      );
  fd_txn_account_set_owner   ( rec, &fd_sysvar_owner_id );
  fd_txn_account_set_slot    ( rec, slot                );
  fd_txn_account_set_data    ( rec, data, sz );

  ulong lamports_minted;
  if( FD_UNLIKELY( __builtin_usubl_overflow( lamports_after, lamports_before, &lamports_minted ) ) ) {
    char name[ FD_BASE58_ENCODED_32_SZ ]; fd_base58_encode_32( address->uc, NULL, name );
    FD_LOG_CRIT(( "fd_sysvar_account_update: lamports overflowed: address=%s lamports_before=%lu lamports_after=%lu",
                  name, lamports_before, lamports_after ));
  }

  if( lamports_minted ) {
    ulong cap = fd_bank_capitalization_get( slot_ctx->bank );
    fd_bank_capitalization_set( slot_ctx->bank, cap+lamports_minted );
  } else if( lamports_before==lamports_after ) {
    /* no balance change */
  } else {
    __builtin_unreachable();
  }

  fd_hashes_update_lthash( rec, prev_hash, slot_ctx->bank, slot_ctx->capture_ctx );
  fd_txn_account_mutable_fini( rec, slot_ctx->funk, slot_ctx->funk_txn, &prepare );

  FD_LOG_DEBUG(( "Updated sysvar: address=%s data_sz=%lu slot=%lu lamports=%lu lamports_minted=%lu",
                 FD_BASE58_ENC_32_ALLOCA( address ), sz, slot, lamports_after, lamports_minted ));
}

int
fd_sysvar_instr_acct_check( fd_exec_instr_ctx_t const * ctx,
                            ulong                       idx,
                            fd_pubkey_t const *         addr_want ) {

  if( FD_UNLIKELY( idx >= ctx->instr->acct_cnt ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  ushort idx_in_txn = ctx->instr->accounts[idx].index_in_transaction;
  fd_pubkey_t const * addr_have = &ctx->txn_ctx->account_keys[ idx_in_txn ];
  if( FD_UNLIKELY( 0!=memcmp( addr_have, addr_want, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
