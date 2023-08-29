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
               fd_acc_lamports_t * lamports ) {

  fd_acc_mgr_t *  acc_mgr  = global->acc_mgr;
  fd_funk_txn_t * funk_txn = global->funk_txn;

  fd_funk_rec_t * acc_data_rec = NULL;
  int modify_err;

  void * raw_acc_data = fd_acc_mgr_modify_raw( acc_mgr, funk_txn, pubkey, 1, sz, NULL, &acc_data_rec, &modify_err );
  if( FD_UNLIKELY( !raw_acc_data ) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  fd_account_meta_t * metadata = (fd_account_meta_t *)raw_acc_data;

  if( FD_UNLIKELY( metadata->magic != FD_ACCOUNT_META_MAGIC ) )
    return FD_ACC_MGR_ERR_WRONG_MAGIC;

  uchar * acc_data = fd_account_get_data( metadata );

  fd_memcpy(acc_data, data, sz);
  // What is the correct behavior here?  Where is this code in the
  // solana code base?  Do I only adjust the lamports if the data
  // increases but not decreases?  I am inventing money here...
  fd_acc_lamports_t lamports_before = metadata->info.lamports;
  metadata->info.lamports = (lamports == NULL) ? fd_rent_exempt_minimum_balance2(&global->bank.rent, sz) : *lamports;
  global->bank.capitalization = fd_ulong_sat_sub(
      fd_ulong_sat_add(
        global->bank.capitalization,
        metadata->info.lamports),
      lamports_before);
  FD_LOG_NOTICE(("fd_sysvar_set: capitalization={%lu} increased by lamports: %lu for pubkey %32J", global->bank.capitalization, (metadata->info.lamports - lamports_before), pubkey));


  metadata->dlen = sz;
  fd_memcpy(metadata->info.owner, owner, 32);
  return fd_acc_mgr_commit_raw( global->acc_mgr, acc_data_rec, pubkey, raw_acc_data, slot, 0 );
}

int
fd_sysvar_set_override( fd_global_ctx_t *   global,
                        uchar const *       owner,
                        fd_pubkey_t const * pubkey,
                        uchar *             data,
                        ulong               data_sz,
                        ulong               slot ) {

  fd_funk_rec_t * acc_data_rec = NULL;
  int modify_err;

  void * raw_acc_data = fd_acc_mgr_modify_raw(global->acc_mgr, global->funk_txn, pubkey, 1, data_sz, NULL, &acc_data_rec, &modify_err);
  if( FD_UNLIKELY( !raw_acc_data ) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  fd_account_meta_t * metadata = (fd_account_meta_t *)raw_acc_data;

  if ( FD_UNLIKELY( metadata->magic != FD_ACCOUNT_META_MAGIC ) )
    return FD_ACC_MGR_ERR_WRONG_MAGIC;

  uchar * acc_data = fd_account_get_data( metadata );

  fd_memcpy(acc_data, data, data_sz);

  metadata->dlen = data_sz;
  fd_memcpy(metadata->info.owner, owner, 32);

  return fd_acc_mgr_commit_raw( global->acc_mgr, acc_data_rec, pubkey, raw_acc_data, slot, 0 );
}
