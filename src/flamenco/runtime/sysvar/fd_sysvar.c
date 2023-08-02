#include "../fd_banks_solana.h"
#include "../fd_acc_mgr.h"
#include "../fd_account.h"
#include "../fd_hashes.h"
#include "../fd_runtime.h"
#include "fd_sysvar.h"

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

int fd_sysvar_set(fd_global_ctx_t *global, const unsigned char *owner, const fd_pubkey_t *pubkey, unsigned char *data, unsigned long sz, ulong slot) {
  fd_funk_rec_t * acc_data_rec = NULL;
  int modify_err;

  ulong acc_sz = sizeof(fd_account_meta_t) + sz;

  void * raw_acc_data = fd_acc_mgr_modify_data(global->acc_mgr, global->funk_txn, pubkey, 1, &acc_sz, NULL, &acc_data_rec, &modify_err);
  if ( FD_UNLIKELY (NULL == raw_acc_data) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  fd_account_meta_t * metadata = (fd_account_meta_t *)raw_acc_data;

  if ( FD_UNLIKELY( metadata->magic != FD_ACCOUNT_META_MAGIC ) )
    return FD_ACC_MGR_ERR_WRONG_MAGIC;

  uchar * acc_data = fd_account_get_data( metadata );

  fd_memcpy(acc_data, data, sz);
  // What is the correct behavior here?  Where is this code in the
  // solana code base?  Do I only adjust the lamports if the data
  // increases but not decreases?  I am inventing money here...
  metadata->info.lamports = (sz + 128) * ((ulong) ((double)global->bank.rent.lamports_per_uint8_year * global->bank.rent.exemption_threshold));

  metadata->dlen = sz;
  fd_memcpy(metadata->info.owner, owner, 32);

  return fd_acc_mgr_commit_data(global->acc_mgr, acc_data_rec, pubkey, raw_acc_data, slot, 0);
}

int fd_sysvar_set_override(fd_global_ctx_t *global, const unsigned char *owner, const fd_pubkey_t *pubkey, unsigned char *data, unsigned long sz, ulong slot) {
  fd_funk_rec_t * acc_data_rec = NULL;
  int modify_err;

  ulong acc_sz = sizeof(fd_account_meta_t) + sz;

  void * raw_acc_data = fd_acc_mgr_modify_data(global->acc_mgr, global->funk_txn, pubkey, 1, &acc_sz, NULL, &acc_data_rec, &modify_err);
  if ( FD_UNLIKELY (NULL == raw_acc_data) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  fd_account_meta_t * metadata = (fd_account_meta_t *)raw_acc_data;

  if ( FD_UNLIKELY( metadata->magic != FD_ACCOUNT_META_MAGIC ) )
    return FD_ACC_MGR_ERR_WRONG_MAGIC;

  uchar * acc_data = fd_account_get_data( metadata );

  fd_memcpy(acc_data, data, sz);
 
  metadata->dlen = sz;
  fd_memcpy(metadata->info.owner, owner, 32);

  return fd_acc_mgr_commit_data(global->acc_mgr, acc_data_rec, pubkey, raw_acc_data, slot, 0);
}
