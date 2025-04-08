#include "fd_sysvar.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "fd_sysvar_rent.h"

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1813 */
int
fd_sysvar_set( fd_exec_slot_ctx_t * slot_ctx,
               fd_pubkey_t const *  owner,
               fd_pubkey_t const *  pubkey,
               void const *         data,
               ulong                sz,
               ulong                slot ) {

  fd_funk_t *     funk     = slot_ctx->funk;
  fd_funk_txn_t * funk_txn = slot_ctx->funk_txn;

  FD_TXN_ACCOUNT_DECL( rec );

  int err = fd_txn_account_init_from_funk_mutable( rec, pubkey, funk, funk_txn, 1, sz );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  fd_memcpy(rec->vt->get_data_mut( rec ), data, sz);

  /* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1825 */
  fd_acc_lamports_t lamports_before = rec->vt->get_lamports( rec );
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  /* https://github.com/anza-xyz/agave/blob/ae18213c19ea5335dfc75e6b6116def0f0910aff/runtime/src/bank.rs#L6184
     The account passed in via the updater is always the current sysvar account, so we take the max of the
     current account lamports and the minimum rent exempt balance needed. */
  fd_acc_lamports_t lamports_after = fd_ulong_max( lamports_before, fd_rent_exempt_minimum_balance( &epoch_bank->rent, sz ) );
  rec->vt->set_lamports( rec, lamports_after );

  /* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1826 */
  if       ( lamports_after > lamports_before ) {
    slot_ctx->slot_bank.capitalization += ( lamports_after - lamports_before );
  } else if( lamports_after < lamports_before ) {
    slot_ctx->slot_bank.capitalization -= ( lamports_before - lamports_after );
  }

  rec->vt->set_data_len( rec, sz );
  rec->vt->set_owner( rec, owner );
  rec->vt->set_slot( rec, slot );

  fd_txn_account_mutable_fini( rec, funk, funk_txn );
  return 0;
}
