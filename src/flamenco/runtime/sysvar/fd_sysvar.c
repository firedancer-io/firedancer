#include "fd_sysvar.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "fd_sysvar_rent.h"

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1813 */
int
fd_sysvar_set( fd_exec_slot_ctx_t * slot_ctx,
               uchar const *        owner,
               fd_pubkey_t const *  pubkey,
               void const *         data,
               ulong                sz,
               ulong                slot ) {

  fd_funkier_txn_t * funk_txn = slot_ctx->funk_txn;
  fd_funkier_t * funk = slot_ctx->acc_mgr->funk;

  int funk_err = FD_FUNKIER_SUCCESS;
  fd_funkier_rec_prepare_t prepare[1];
  fd_funkier_rec_key_t id = fd_acc_funk_key( pubkey );
  fd_funkier_rec_t * rec = fd_funkier_rec_clone( funk, funk_txn, &id, prepare, NULL );
  if( rec == NULL || funk_err != FD_FUNKIER_SUCCESS )
    return FD_ACC_MGR_ERR_READ_FAILED;

  fd_wksp_t * wksp = fd_funkier_wksp( funk );
  fd_account_meta_t meta_before = *(fd_account_meta_t *)fd_funkier_val( rec, wksp );

  uchar * val = fd_funkier_val_truncate( rec, sizeof(fd_account_meta_t)+sz, fd_funkier_alloc( funk, wksp ), wksp, NULL );;
  fd_memcpy(val + sizeof(fd_account_meta_t), data, sz);
  fd_account_meta_t * meta = (fd_account_meta_t *)val;
  *meta = meta_before;
  meta->dlen = sz;
  fd_memcpy(meta->info.owner, owner, 32);
  meta->slot = slot;

  /* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1825 */
  fd_acc_lamports_t lamports_before = meta->info.lamports;
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  /* https://github.com/anza-xyz/agave/blob/ae18213c19ea5335dfc75e6b6116def0f0910aff/runtime/src/bank.rs#L6184
     The account passed in via the updater is always the current sysvar account, so we take the max of the
     current account lamports and the minimum rent exempt balance needed. */
  fd_acc_lamports_t lamports_after = fd_ulong_max( lamports_before, fd_rent_exempt_minimum_balance( &epoch_bank->rent, sz ) );
  meta->info.lamports = lamports_after;

  fd_funkier_rec_publish( prepare );

  /* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L1826 */
  if       ( lamports_after > lamports_before ) {
    slot_ctx->slot_bank.capitalization += ( lamports_after - lamports_before );
  } else if( lamports_after < lamports_before ) {
    slot_ctx->slot_bank.capitalization -= ( lamports_before - lamports_after );
  }

  return 0;
}
