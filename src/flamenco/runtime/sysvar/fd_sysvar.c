#include "fd_sysvar.h"
#include "../fd_acc_mgr.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_instr_ctx.h"
#include "../context/fd_exec_txn_ctx.h"

#include "fd_sysvar_rent.h"

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1813 */
int
fd_sysvar_set( fd_bank_t *          bank,
               fd_funk_t *          funk,
               fd_funk_txn_t *      funk_txn,
               fd_pubkey_t const *  owner,
               fd_pubkey_t const *  pubkey,
               void const *         data,
               ulong                sz,
               ulong                slot ) {

  FD_TXN_ACCOUNT_DECL( rec );

  int err = fd_txn_account_init_from_funk_mutable( rec, pubkey, funk, funk_txn, 1, sz );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  fd_memcpy(rec->vt->get_data_mut( rec ), data, sz);

  /* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1825 */
  fd_acc_lamports_t lamports_before = rec->vt->get_lamports( rec );
  /* https://github.com/anza-xyz/agave/blob/ae18213c19ea5335dfc75e6b6116def0f0910aff/runtime/src/bank.rs#L6184
     The account passed in via the updater is always the current sysvar account, so we take the max of the
     current account lamports and the minimum rent exempt balance needed. */
  fd_rent_t const * rent           = fd_bank_rent_query( bank );
  fd_acc_lamports_t lamports_after = fd_ulong_max( lamports_before, fd_rent_exempt_minimum_balance( rent, sz ) );
  rec->vt->set_lamports( rec, lamports_after );

  /* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1826 */
  if( lamports_after > lamports_before ) {
    fd_bank_capitalization_set( bank, fd_bank_capitalization_get( bank ) + (lamports_after - lamports_before) );
  } else if( lamports_after < lamports_before ) {
    fd_bank_capitalization_set( bank, fd_bank_capitalization_get( bank ) - (lamports_before - lamports_after) );
  }

  rec->vt->set_data_len( rec, sz );
  rec->vt->set_owner( rec, owner );
  rec->vt->set_slot( rec, slot );

  fd_txn_account_mutable_fini( rec, funk, funk_txn );
  return 0;
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
