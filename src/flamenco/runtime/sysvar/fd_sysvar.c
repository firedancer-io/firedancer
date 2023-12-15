#include "../fd_banks_solana.h"
#include "../fd_acc_mgr.h"
#include "../fd_account.h"
#include "../fd_hashes.h"
#include "../fd_runtime.h"
#include "fd_sysvar.h"

int
fd_sysvar_set( fd_exec_slot_ctx_t *   slot_ctx,
               uchar const *       owner,
               fd_pubkey_t const * pubkey,
               uchar *             data,
               ulong               sz,
               ulong               slot,
               fd_acc_lamports_t const * lamports ) {

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
  rec->meta->info.lamports = (lamports == NULL) ? fd_rent_exempt_minimum_balance2(&slot_ctx->epoch_ctx->epoch_bank.rent, sz) : *lamports;
  slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub(
      fd_ulong_sat_add(
        slot_ctx->slot_bank.capitalization,
        rec->meta->info.lamports),
      lamports_before);
  FD_LOG_DEBUG(("fd_sysvar_set: capitalization={%lu} increased by lamports: %lu for pubkey %32J", slot_ctx->slot_bank.capitalization, (rec->meta->info.lamports - lamports_before), pubkey));


  rec->meta->dlen = sz;
  fd_memcpy(rec->meta->info.owner, owner, 32);
  rec->meta->slot = slot;
  return 0; 
  //fd_acc_mgr_commit( slot_ctx->acc_mgr, rec, slot_ctx );
}
