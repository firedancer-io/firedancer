#include "fd_acc_mgr.h"
#include "fd_runtime.h"
#include "../../ballet/base58/fd_base58.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "fd_rent_lists.h"
#include "fd_rocksdb.h"
#include "sysvar/fd_sysvar_rent.h"
#include "fd_system_ids.h"
#include <assert.h>

fd_account_meta_t const *
fd_funk_acc_mgr_get_acc_meta_readonly( fd_funk_t *            funk,
                                       fd_funk_txn_t const *  txn,
                                       fd_pubkey_t const *    pubkey,
                                       fd_funk_rec_t const ** orec,
                                       int *                  opt_err,
                                       fd_funk_txn_t const ** txn_out  ) {

  fd_funk_rec_key_t     id  = fd_funk_acc_key( pubkey );
  fd_funk_rec_t const * rec = fd_funk_rec_query_global( funk, txn, &id, txn_out );

  if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) )  {
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
    return NULL;
  }
  if( NULL != orec )
    *orec = rec;

  void const * raw = fd_funk_val( rec, fd_funk_wksp(funk) );
  // TODO/FIXME: this check causes issues with some metadata writes

  fd_account_meta_t const * metadata = fd_type_pun_const( raw );
  if( FD_UNLIKELY( metadata->magic != FD_ACCOUNT_META_MAGIC ) ) {
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ACC_MGR_ERR_WRONG_MAGIC );
    return NULL;
  }

  return metadata;
}

fd_account_meta_t *
fd_funk_acc_mgr_get_acc_meta_mutable( fd_funk_t *           funk,
                                      fd_funk_txn_t *       txn,
                                      fd_pubkey_t const *   pubkey,
                                      int                   do_create,
                                      ulong                 min_data_sz,
                                      fd_funk_rec_t const * opt_con_rec,
                                      fd_funk_rec_t **      opt_out_rec,
                                      int *                 opt_err ) {
  fd_funk_rec_key_t id = fd_funk_acc_key( pubkey );

//#ifdef VLOG
//  ulong rec_cnt = 0;
//  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, txn );
//       NULL != rec;
//       rec = fd_funk_txn_next_rec( funk, rec ) ) {
//
//    if( !fd_funk_key_is_acc( rec->pair.key  ) ) continue;
//
//    FD_LOG_DEBUG(( "fd_acc_mgr_modify_raw: %s create: %s  rec_cnt: %d", FD_BASE58_ENC_32_ALLOCA( rec->pair.key->uc ), do_create ? "true" : "false", rec_cnt));
//
//    rec_cnt++;
//  }
//
//  FD_LOG_DEBUG(( "fd_acc_mgr_modify_raw: %s create: %s", FD_BASE58_ENC_32_ALLOCA( pubkey->uc ), do_create ? "true" : "false"));
//#endif

  int funk_err = FD_FUNK_SUCCESS;
  fd_funk_rec_t * rec = fd_funk_rec_write_prepare( funk, txn, &id, sizeof(fd_account_meta_t)+min_data_sz, do_create, opt_con_rec, &funk_err );

  if( FD_UNLIKELY( !rec ) )  {
    if( FD_LIKELY( funk_err==FD_FUNK_ERR_KEY ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
      return NULL;
    }
    /* Irrecoverable funky internal error [[noreturn]] */
    FD_LOG_ERR(( "fd_funk_rec_write_prepare(%s) failed (%i-%s)", FD_BASE58_ENC_32_ALLOCA( pubkey->key ), funk_err, fd_funk_strerror( funk_err ) ));
  }

  if (NULL != opt_out_rec)
    *opt_out_rec = rec;

  fd_account_meta_t * ret = fd_funk_val( rec, fd_funk_wksp( funk ) );

  if( do_create && ret->magic==0UL ) {
    fd_account_meta_init( ret );
  }

  if( ret->magic != FD_ACCOUNT_META_MAGIC ) {
    fd_int_store_if( !!opt_err, opt_err, FD_FUNK_ACC_MGR_ERR_WRONG_MAGIC );
    return NULL;
  }

  return ret;
}

FD_FN_CONST char const *
fd_funk_acc_mgr_strerror( int err ) {
  switch( err ) {
  case FD_FUNK_ACC_MGR_SUCCESS:
    return "success";
  case FD_FUNK_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    return "unknown account";
  case FD_FUNK_ACC_MGR_ERR_WRITE_FAILED:
    return "write failed";
  case FD_FUNK_ACC_MGR_ERR_READ_FAILED:
    return "read failed";
  case FD_FUNK_ACC_MGR_ERR_WRONG_MAGIC:
    return "wrong magic";
  default:
    return "unknown";
  }
}

int
fd_funk_acc_mgr_save_non_tpool( fd_funk_t *        funk,
                                fd_funk_txn_t *    txn,
                                fd_txn_account_t * account,
                                fd_wksp_t *        acc_data_wksp ) {

  account->meta = fd_wksp_laddr( acc_data_wksp, account->meta_gaddr );
  account->data = fd_wksp_laddr( acc_data_wksp, account->data_gaddr );
  account->const_meta = account->meta;
  account->const_data = account->data;

  fd_funk_start_write( funk );
  fd_funk_rec_key_t key = fd_funk_acc_key( account->pubkey );
  fd_funk_rec_t * rec = (fd_funk_rec_t *)fd_funk_rec_query( funk, txn, &key );
  if( rec == NULL ) {
    int err;
    rec = (fd_funk_rec_t *)fd_funk_rec_insert( funk, txn, &key, &err );
    if( rec == NULL ) FD_LOG_ERR(( "unable to insert a new record, error %d", err ));
  }
  account->rec = rec;
  ulong reclen = sizeof(fd_account_meta_t)+account->const_meta->dlen;
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  int err;
  if( fd_funk_val_truncate( account->rec, reclen, fd_funk_alloc( funk, wksp ), wksp, &err ) == NULL ) {
    FD_LOG_ERR(( "unable to allocate account value, err %d", err ));
  }
  err = fd_txn_account_save( funk, account );
  fd_funk_end_write( funk );
  return err;
}