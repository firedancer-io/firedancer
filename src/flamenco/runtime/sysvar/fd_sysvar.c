#include "fd_sysvar.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "fd_sysvar_rent.h"

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1813 */
int
fd_sysvar_set( fd_exec_slot_ctx_t * slot_ctx,
               uchar const *        owner,
               fd_pubkey_t const *  pubkey,
               uchar *              data,
               ulong                sz,
               ulong                slot,
               ulong                lamports ) {

  fd_acc_mgr_t *  acc_mgr  = slot_ctx->acc_mgr;
  fd_funk_txn_t * funk_txn = slot_ctx->funk_txn;

  FD_BORROWED_ACCOUNT_DECL(rec);

  int err = fd_acc_mgr_modify( acc_mgr, funk_txn, pubkey, 1, sz, rec );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  fd_memcpy(rec->data, data, sz);
  
  /* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1825 */
  fd_acc_lamports_t lamports_before = rec->meta->info.lamports;
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_acc_lamports_t lamports_after = fd_ulong_max( lamports, fd_rent_exempt_minimum_balance2( &epoch_bank->rent, sz ) );
  rec->meta->info.lamports = lamports_after;

  /* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1826 */
  if ( lamports_after > lamports_before ) {
    slot_ctx->slot_bank.capitalization += ( lamports_after - lamports_before );
  } else if ( lamports_before < lamports_after ) {
    slot_ctx->slot_bank.capitalization -= ( lamports_before - lamports_after );
  }

  rec->meta->dlen = sz;
  fd_memcpy(rec->meta->info.owner, owner, 32);
  rec->meta->slot = slot;
  return 0;
}
