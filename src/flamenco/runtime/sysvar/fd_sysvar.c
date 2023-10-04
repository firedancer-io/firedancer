#include "../fd_banks_solana.h"
#include "../fd_acc_mgr.h"
#include "../fd_account.h"
#include "../fd_hashes.h"
#include "../fd_runtime.h"
#include "fd_sysvar.h"

int
fd_sysvar_set( fd_global_ctx_t *   global,
               uchar const *       owner,
               fd_pubkey_t const * pubkey,
               uchar *             data,
               ulong               sz,
               ulong               slot,
               fd_acc_lamports_t const * lamports ) {

  fd_acc_mgr_t *  acc_mgr  = global->acc_mgr;
  fd_funk_txn_t * funk_txn = global->funk_txn;

  FD_BORROWED_ACCOUNT_DECL(rec);

  int err = fd_acc_mgr_modify( acc_mgr, funk_txn, pubkey, 1, sz, rec );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  fd_memcpy(rec->data, data, sz);
  // What is the correct behavior here?  Where is this code in the
  // solana code base?  Do I only adjust the lamports if the data
  // increases but not decreases?  I am inventing money here...
  fd_acc_lamports_t lamports_before = rec->meta->info.lamports;
  rec->meta->info.lamports = (lamports == NULL) ? fd_rent_exempt_minimum_balance2(&global->bank.rent, sz) : *lamports;
  global->bank.capitalization = fd_ulong_sat_sub(
      fd_ulong_sat_add(
        global->bank.capitalization,
        rec->meta->info.lamports),
      lamports_before);
  FD_LOG_DEBUG(("fd_sysvar_set: capitalization={%lu} increased by lamports: %lu for pubkey %32J", global->bank.capitalization, (rec->meta->info.lamports - lamports_before), pubkey));


  rec->meta->dlen = sz;
  fd_memcpy(rec->meta->info.owner, owner, 32);
  return fd_acc_mgr_commit( global->acc_mgr, rec, slot );
}
