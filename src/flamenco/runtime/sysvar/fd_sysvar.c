#include "fd_sysvar.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "fd_sysvar_rent.h"

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
  // What is the correct behavior here?  Where is this code in the
  // solana code base?  Do I only adjust the lamports if the data
  // increases but not decreases?  I am inventing money here...
  fd_acc_lamports_t lamports_before = rec->meta->info.lamports;
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  rec->meta->info.lamports = (lamports == 0UL) ? fd_rent_exempt_minimum_balance2( &epoch_bank->rent, sz ) : lamports;
  slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub(
      fd_ulong_sat_add(
        slot_ctx->slot_bank.capitalization,
        rec->meta->info.lamports),
      lamports_before);
  // FD_LOG_DEBUG(("fd_sysvar_set: capitalization={%lu} increased by lamports: %lu for pubkey %32J", slot_ctx->slot_bank.capitalization, (rec->meta->info.lamports - lamports_before), pubkey));


  rec->meta->dlen = sz;
  fd_memcpy(rec->meta->info.owner, owner, 32);
  rec->meta->slot = slot;
  return 0;
}
