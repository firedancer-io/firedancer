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

fd_acc_mgr_t *
fd_acc_mgr_new( void *      mem,
                fd_funk_t * funk ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_ACC_MGR_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_memset( mem, 0, FD_ACC_MGR_FOOTPRINT );

  fd_acc_mgr_t * acc_mgr = fd_type_pun( mem );
  acc_mgr->funk = funk;
  return acc_mgr;

}

void *
fd_acc_mgr_delete( fd_acc_mgr_t * acc_mgr ) {

  if( FD_UNLIKELY( !acc_mgr ) ) return NULL;

  memset( acc_mgr, 0, FD_ACC_MGR_FOOTPRINT );
  return acc_mgr;
}

void
fd_acc_mgr_set_slots_per_epoch( fd_exec_slot_ctx_t * slot_ctx,
                                ulong                slots_per_epoch ) {
  fd_acc_mgr_t * acc_mgr   = slot_ctx->acc_mgr;
  acc_mgr->slots_per_epoch = slots_per_epoch;
  acc_mgr->part_width      = fd_rent_partition_width( slots_per_epoch );
}

fd_account_meta_t const *
fd_acc_mgr_view_raw( fd_acc_mgr_t *         acc_mgr,
                     fd_funk_txn_t const *  txn,
                     fd_pubkey_t const *    pubkey,
                     fd_funk_rec_t const ** orec,
                     int *                  opt_err,
                     fd_funk_txn_t const ** txn_out  ) {

  fd_funk_rec_key_t id   = fd_acc_funk_key( pubkey );
  fd_funk_t *       funk = acc_mgr->funk;

  /* When we access this pointer later on in the execution pipeline, we assume that
     nothing else will change that account. If the account is writable in the solana txn,
     then we copy the data. If the account is read-only, we do not. This is safe because of
     the read-write locks that the solana transaction holds on the account. */
  for ( ; ; ) {

    fd_funk_rec_query_t query[1];
    fd_funk_txn_t const * dummy_txn_out[1];
    if( !txn_out ) txn_out    = dummy_txn_out;
    fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, txn, &id, txn_out, query );

    if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) )  {
      fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
      return NULL;
    }
    if( NULL != orec )
      *orec = rec;

    void const * raw = fd_funk_val( rec, fd_funk_wksp(funk) );

    fd_account_meta_t const * metadata = fd_type_pun_const( raw );
    if( FD_UNLIKELY( metadata->magic != FD_ACCOUNT_META_MAGIC ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_WRONG_MAGIC );
      return NULL;
    }

    if( FD_LIKELY( fd_funk_rec_query_test( query ) == FD_FUNK_SUCCESS ) ) {
      return metadata;
    }

  }

  /* unreachable */
  return NULL;
}

int
fd_acc_mgr_view( fd_acc_mgr_t *        acc_mgr,
                 fd_funk_txn_t const * txn,
                 fd_pubkey_t const *   pubkey,
                 fd_txn_account_t *    account ) {
  /* TODO: re-add this check after consulting on why this builtin program check.
     Is it the case that the  */
  // if( fd_pubkey_is_builtin_program( pubkey )
  //     || memcmp(pubkey->uc, fd_solana_compute_budget_program_id.uc, sizeof(fd_pubkey_t))==0 ) {
  //   txn = NULL;
  // }
  int err = FD_ACC_MGR_SUCCESS;
  fd_account_meta_t const * meta = fd_acc_mgr_view_raw( acc_mgr, txn, pubkey, &account->const_rec, &err, NULL );
  if( FD_UNLIKELY( !fd_acc_exists( meta ) ) ) {
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      return err;
    }
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  if( FD_UNLIKELY( FD_TXN_ACCOUNT_MAGIC != account->magic ) ) {
    FD_LOG_ERR(( "bad magic for borrowed account - acc: %s, expected: %016lx, got: %016lx", FD_BASE58_ENC_32_ALLOCA( pubkey->uc ), FD_TXN_ACCOUNT_MAGIC, account->magic ));
  }

  fd_memcpy(account->pubkey, pubkey, sizeof(fd_pubkey_t));

  account->const_meta = meta;
  account->const_data = (uchar const *)meta + meta->hlen;

  fd_wksp_t * funk_wksp = fd_funk_wksp( acc_mgr->funk );
  account->meta_gaddr   = fd_wksp_gaddr( funk_wksp, account->const_meta );
  account->data_gaddr   = fd_wksp_gaddr( funk_wksp, account->const_data );


  if( ULONG_MAX == account->starting_dlen )
    account->starting_dlen = meta->dlen;

  if( ULONG_MAX == account->starting_lamports )
    account->starting_lamports = meta->info.lamports;

  return FD_ACC_MGR_SUCCESS;
}

int
fd_acc_mgr_modify( fd_acc_mgr_t *      acc_mgr,
                   fd_funk_txn_t *  txn,
                   fd_pubkey_t const * pubkey,
                   int                 do_create,
                   ulong               min_data_sz,
                   fd_txn_account_t *  account ) {
  fd_funk_t *       funk = acc_mgr->funk;
  fd_wksp_t *          wksp = fd_funk_wksp(funk);
  fd_funk_rec_key_t id   = fd_acc_funk_key( pubkey );

  fd_funk_rec_query_t query[1];
  fd_funk_rec_t * rec = (fd_funk_rec_t *)fd_funk_rec_query_try( funk, txn, &id, query );

  int do_publish = 0;
  fd_funk_rec_prepare_t prepare[1] = {0};
  int funk_err = 0;
  if( !rec ) {
    rec = fd_funk_rec_clone( funk, txn, &id, prepare, &funk_err );
    do_publish = 1;

    if( rec == NULL ) {
      if( FD_LIKELY( funk_err==FD_FUNK_ERR_KEY ) ) {
        if( do_create ) {
          rec = fd_funk_rec_prepare( funk, txn, &id, prepare, &funk_err );
          if( rec == NULL ) {
            /* Irrecoverable funky internal error [[noreturn]] */
            FD_LOG_ERR(( "fd_funk_rec_write_prepare(%s) failed (%i-%s)", FD_BASE58_ENC_32_ALLOCA( pubkey->key ), funk_err, fd_funk_strerror( funk_err ) ));
          }
        } else {
          return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
        }
      } else {
        /* Irrecoverable funky internal error [[noreturn]] */
        FD_LOG_ERR(( "fd_funk_rec_write_prepare(%s) failed (%i-%s)", FD_BASE58_ENC_32_ALLOCA( pubkey->key ), funk_err, fd_funk_strerror( funk_err ) ));
      }
    }
  }

  ulong sz = sizeof(fd_account_meta_t)+min_data_sz;
  void * val;
  if( fd_funk_val_sz( rec ) < sz )
    val = fd_funk_val_truncate( rec, sz, fd_funk_alloc( funk, wksp ), wksp, &funk_err );
  else
    val = fd_funk_val( rec, wksp );

  fd_account_meta_t * meta = val;
  if( do_create && meta->magic==0UL ) {
    fd_account_meta_init( meta );
  }
  if( meta->magic != FD_ACCOUNT_META_MAGIC ) {
    return FD_ACC_MGR_ERR_WRONG_MAGIC;
  }

  /* This is the WRONG place to publish, but fixing it requires
     changes to the acc_mgr api which are out of scope atm. */
  if( do_publish ) {
    fd_funk_rec_publish( prepare );
  }

  assert( account->magic == FD_TXN_ACCOUNT_MAGIC );

  fd_memcpy(account->pubkey, pubkey, sizeof(fd_pubkey_t));

  if( FD_UNLIKELY( meta->magic != FD_ACCOUNT_META_MAGIC ) ) {
    FD_LOG_WARNING(( "WRONG MAGIC" ));
    return FD_ACC_MGR_ERR_WRONG_MAGIC;
  }

#ifdef VLOG
  FD_LOG_DEBUG(( "fd_acc_mgr_modify: %s create: %s  lamports: %ld  owner: %s  executable: %s,  rent_epoch: %ld, data_len: %ld",
                 FD_BASE58_ENC_32_ALLOCA( pubkey->uc ),
                 do_create ? "true" : "false",
                 meta->info.lamports,
                 FD_BASE58_ENC_32_ALLOCA( meta->info.owner ),
                 meta->info.executable ? "true" : "false",
                 meta->info.rent_epoch, meta->dlen ));
#endif

  account->const_rec  = account->rec;
  account->const_meta = account->meta = meta;
  account->const_data = account->data = (uchar *)meta + meta->hlen;

  if( ULONG_MAX == account->starting_dlen )
    account->starting_dlen = meta->dlen;

  if( ULONG_MAX == account->starting_lamports )
    account->starting_lamports = meta->info.lamports;

  return FD_ACC_MGR_SUCCESS;
}

FD_FN_CONST char const *
fd_acc_mgr_strerror( int err ) {
  switch( err ) {
  case FD_ACC_MGR_SUCCESS:
    return "success";
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    return "unknown account";
  case FD_ACC_MGR_ERR_WRITE_FAILED:
    return "write failed";
  case FD_ACC_MGR_ERR_READ_FAILED:
    return "read failed";
  case FD_ACC_MGR_ERR_WRONG_MAGIC:
    return "wrong magic";
  default:
    return "unknown";
  }
}

int
fd_acc_mgr_save( fd_acc_mgr_t *     acc_mgr,
                 fd_txn_account_t * account ) {
  if( account->meta == NULL || account->rec == NULL ) {
    // The meta is NULL so the account is not writable.
    FD_LOG_DEBUG(( "fd_acc_mgr_save: account is not writable: %s", FD_BASE58_ENC_32_ALLOCA( account->pubkey ) ));
    return FD_ACC_MGR_SUCCESS;
  }

  fd_wksp_t * wksp = fd_funk_wksp( acc_mgr->funk );
  ulong reclen = sizeof(fd_account_meta_t)+account->const_meta->dlen;
  uchar * raw = fd_funk_val( account->rec, wksp );
  fd_memcpy( raw, account->meta, reclen );

  return FD_ACC_MGR_SUCCESS;
}

int
fd_acc_mgr_save_non_tpool( fd_acc_mgr_t *     acc_mgr,
                           fd_funk_txn_t *    txn,
                           fd_txn_account_t * account,
                           fd_wksp_t *        acc_data_wksp ) {

  account->meta = fd_wksp_laddr( acc_data_wksp, account->meta_gaddr );
  account->data = fd_wksp_laddr( acc_data_wksp, account->data_gaddr );
  account->const_meta = account->meta;
  account->const_data = account->data;

  fd_funk_rec_key_t key = fd_acc_funk_key( account->pubkey );

  /* Remove previous incarnation of the account's record from the transaction, so that we don't hash it twice */
  fd_funk_rec_hard_remove( acc_mgr->funk, txn, &key );

  int err;
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_t * rec = fd_funk_rec_prepare( acc_mgr->funk, txn, &key, prepare, &err );
  if( rec == NULL ) FD_LOG_ERR(( "unable to insert a new record, error %d", err ));

  account->rec = rec;
  ulong reclen = sizeof(fd_account_meta_t)+account->const_meta->dlen;
  fd_wksp_t * wksp = fd_funk_wksp( acc_mgr->funk );
  if( fd_funk_val_truncate( rec, reclen, fd_funk_alloc( acc_mgr->funk, wksp ), wksp, &err ) == NULL ) {
    FD_LOG_ERR(( "unable to allocate account value, err %d", err ));
  }
  err = fd_acc_mgr_save( acc_mgr, account );

  fd_funk_rec_publish( prepare );

  return err;
}

void
fd_acc_mgr_lock( fd_acc_mgr_t * acc_mgr ) {
  FD_TEST( !acc_mgr->is_locked );
  acc_mgr->is_locked = 1;
}

void
fd_acc_mgr_unlock( fd_acc_mgr_t * acc_mgr ) {
  FD_TEST( acc_mgr->is_locked );
  acc_mgr->is_locked = 0;
}
