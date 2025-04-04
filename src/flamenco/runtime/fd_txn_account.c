#include "fd_txn_account.h"
#include "fd_acc_mgr.h"
#include "fd_runtime.h"

fd_txn_account_t *
fd_txn_account_init( void * ptr ) {
  if( FD_UNLIKELY( !ptr ) ) {
    FD_LOG_WARNING(( "NULL ptr" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ptr, alignof(fd_txn_account_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned ptr" ));
    return NULL;
  }

  memset( ptr, 0, FD_TXN_ACCOUNT_FOOTPRINT );

  fd_txn_account_t * ret = (fd_txn_account_t *)ptr;
  ret->const_data        = NULL;
  ret->const_meta        = NULL;
  ret->meta              = NULL;
  ret->data              = NULL;
  ret->meta_gaddr        = 0UL;
  ret->data_gaddr        = 0UL;
  ret->starting_dlen     = ULONG_MAX;
  ret->starting_lamports = ULONG_MAX;
  ret->vt                = &fd_txn_account_readonly_vtable;

  FD_COMPILER_MFENCE();
  ret->magic = FD_TXN_ACCOUNT_MAGIC;
  FD_COMPILER_MFENCE();

  return ret;
}

/* A common setup helper function that sets
   default values for the txn account */
void
fd_txn_account_setup_common( fd_txn_account_t * acct ) {
  fd_account_meta_t const * meta = acct->const_meta ?
                                   acct->const_meta : acct->meta;

  if( ULONG_MAX == acct->starting_dlen ) {
    acct->starting_dlen = meta->dlen;
  }

  if( ULONG_MAX == acct->starting_lamports ) {
    acct->starting_lamports = meta->info.lamports;
  }
}

void
fd_txn_account_init_from_meta_and_data_mutable( fd_txn_account_t *  acct,
                                                fd_account_meta_t * meta,
                                                uchar *             data ) {
  fd_txn_account_init( acct );
  acct->const_data = data;
  acct->const_meta = meta;
  acct->data = data;
  acct->meta = meta;
}

void
fd_txn_account_init_from_meta_and_data_readonly( fd_txn_account_t *        acct,
                                                 fd_account_meta_t const * meta,
                                                 uchar const *             data ) {
  fd_txn_account_init( &acct );
  acct->const_data = data;
  acct->const_meta = meta;
}

void
fd_txn_account_setup_sentinel_meta_readonly( fd_txn_account_t * acct,
                                             fd_spad_t *        spad,
                                             fd_wksp_t *        spad_wksp ) {
  fd_account_meta_t * sentinel = fd_spad_alloc( spad, FD_ACCOUNT_REC_ALIGN, sizeof(fd_account_meta_t) );
  fd_memset( sentinel, 0, sizeof(fd_account_meta_t) );
  sentinel->magic           = FD_ACCOUNT_META_MAGIC;
  sentinel->info.rent_epoch = ULONG_MAX;
  acct->const_meta          = sentinel;
  acct->starting_lamports   = 0UL;
  acct->starting_dlen       = 0UL;
  acct->meta_gaddr          = fd_wksp_gaddr( spad_wksp, sentinel );
}

void
fd_txn_account_setup_meta_mutable( fd_txn_account_t * acct,
                                   fd_spad_t *        spad,
                                   ulong              sz ) {
  fd_account_meta_t * meta = fd_spad_alloc( spad, alignof(fd_account_meta_t), sizeof(fd_account_meta_t) + sz );
  void * data = (uchar *)meta + sizeof(fd_account_meta_t);

  acct->const_meta = acct->meta = meta;
  acct->const_data = acct->data = data;
  acct->vt         = &fd_txn_account_writable_vtable;
}

void
fd_txn_account_setup_readonly( fd_txn_account_t *        acct,
                               fd_pubkey_t const *       pubkey,
                               fd_account_meta_t const * meta ) {
  fd_memcpy(acct->pubkey, pubkey, sizeof(fd_pubkey_t));

  /* We don't copy the metadata into a buffer here, because we assume
     that we are holding read locks on the account, because we are inside
     a transaction. */
  acct->const_meta = meta;
  acct->const_data = (uchar const *)meta + meta->hlen;
  acct->vt         = &fd_txn_account_readonly_vtable;

  fd_txn_account_setup_common( acct );
}

void
fd_txn_account_setup_mutable( fd_txn_account_t *        acct,
                              fd_pubkey_t const *       pubkey,
                              fd_account_meta_t *       meta ) {
  fd_memcpy(acct->pubkey, pubkey, sizeof(fd_pubkey_t));

  acct->const_rec  = acct->rec;
  acct->const_meta = acct->meta = meta;
  acct->const_data = acct->data = (uchar *)meta + meta->hlen;
  acct->vt         = &fd_txn_account_writable_vtable;

  fd_txn_account_setup_common( acct );
}

/* Operators impl */

/* Internal helper to initialize account data */
uchar *
fd_txn_account_init_data( fd_txn_account_t * acct, void * buf ) {
  /* Assumes that buf is pointing to account data */
  uchar * new_raw_data = (uchar *)buf;
  ulong   dlen         = ( acct->const_meta != NULL ) ? acct->const_meta->dlen : 0;

  if( acct->const_meta != NULL ) {
    fd_memcpy( new_raw_data, (uchar *)acct->const_meta, sizeof(fd_account_meta_t)+dlen );
  } else {
    /* Account did not exist, set up metadata */
    fd_account_meta_init( (fd_account_meta_t *)new_raw_data );
  }

  return new_raw_data;
}

fd_txn_account_t *
fd_txn_account_make_mutable( fd_txn_account_t * acct,
                             void *             buf,
                             fd_wksp_t *        wksp ) {
  if( FD_UNLIKELY( acct->data != NULL ) ) {
    FD_LOG_ERR(( "borrowed account is already mutable" ));
  }

  ulong   dlen         = ( acct->const_meta != NULL ) ? acct->const_meta->dlen : 0UL;
  uchar * new_raw_data = fd_txn_account_init_data( acct, buf );

  acct->const_meta = acct->meta = (fd_account_meta_t *)new_raw_data;
  acct->const_data = acct->data = new_raw_data + sizeof(fd_account_meta_t);
  acct->meta->dlen = dlen;

  /* update global addresses of meta and data after copying into buffer */
  acct->meta_gaddr = fd_wksp_gaddr( wksp, acct->meta );
  acct->data_gaddr = fd_wksp_gaddr( wksp, acct->data );

  acct->vt         = &fd_txn_account_writable_vtable;

  return acct;
}

/* Factory constructors from funk */

int
fd_txn_account_init_from_funk_readonly( fd_txn_account_t *    acct,
                                        fd_pubkey_t const *   pubkey,
                                        fd_funk_t *           funk,
                                        fd_funk_txn_t const * funk_txn ) {
  fd_txn_account_init( acct );

  int err = FD_ACC_MGR_SUCCESS;
  fd_account_meta_t const * meta = fd_funk_get_acc_meta_readonly( funk,
                                                                  funk_txn,
                                                                  pubkey,
                                                                  &acct->const_rec,
                                                                  &err,
                                                                  NULL );

  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return err;
  }

  if( FD_UNLIKELY( !fd_account_meta_exists( meta ) ) ) {
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  if( FD_UNLIKELY( acct->magic!=FD_TXN_ACCOUNT_MAGIC ) ) {
    return FD_ACC_MGR_ERR_WRONG_MAGIC;
  }

  /* setup global addresses of meta and data for exec and replay tile sharing */
  fd_wksp_t * funk_wksp = fd_funk_wksp( funk );
  acct->meta_gaddr = fd_wksp_gaddr( funk_wksp, acct->const_meta );
  acct->data_gaddr = fd_wksp_gaddr( funk_wksp, acct->const_data );

  fd_txn_account_setup_readonly( acct, pubkey, meta );

  return FD_ACC_MGR_SUCCESS;
}

int
fd_txn_account_init_from_funk_mutable( fd_txn_account_t *  acct,
                                       fd_pubkey_t const * pubkey,
                                       fd_funk_t *         funk,
                                       fd_funk_txn_t *     funk_txn,
                                       int                 do_create,
                                       ulong               min_data_sz ) {
  fd_txn_account_init( acct );

  fd_funk_rec_prepare_t prepare = {0};
  int err = FD_ACC_MGR_SUCCESS;
  fd_account_meta_t * meta = fd_funk_get_acc_meta_mutable( funk,
                                                           funk_txn,
                                                           pubkey,
                                                           do_create,
                                                           min_data_sz,
                                                           &acct->rec,
                                                           &prepare,
                                                           &err );

  if( FD_UNLIKELY( !meta ) ) {
    return err;
  }

  if( FD_UNLIKELY( meta->magic!=FD_ACCOUNT_META_MAGIC ) ) {
    return FD_ACC_MGR_ERR_WRONG_MAGIC;
  }

  /* exec tile should never call this function, so the global addresses of
     meta and data should never be used. Instead, populate the prepared_rec
     field so that any created records can be published with fd_txn_account_mutable_fini. */
  acct->prepared_rec = prepare;
  fd_txn_account_setup_mutable( acct, pubkey, meta );

  /* trigger a segfault if the exec tile calls this function,
     as funk will be mapped read-only */
  acct->data[0] = acct->data[0];

  return FD_ACC_MGR_SUCCESS;
}

/* Funk save function impl */

int
fd_txn_account_save_internal( fd_txn_account_t * acct,
                              fd_funk_t *        funk ) {
  if( acct->rec == NULL ) {
    return FD_ACC_MGR_ERR_WRITE_FAILED;
  }

  fd_wksp_t * wksp = fd_funk_wksp( funk );
  ulong reclen = sizeof(fd_account_meta_t)+acct->const_meta->dlen;
  uchar * raw = fd_funk_val( acct->rec, wksp );
  fd_memcpy( raw, acct->meta, reclen );

  return FD_ACC_MGR_SUCCESS;
}

int
fd_txn_account_save( fd_txn_account_t * acct,
                     fd_funk_t *        funk,
                     fd_funk_txn_t *    txn,
                     fd_wksp_t *        acc_data_wksp ) {
  acct->meta = fd_wksp_laddr( acc_data_wksp, acct->meta_gaddr );
  acct->data = fd_wksp_laddr( acc_data_wksp, acct->data_gaddr );

  if( acct->meta == NULL ) {
    /* The meta is NULL so the account is not writable. */
    FD_LOG_DEBUG(( "fd_txn_account_save: account is not writable: %s", FD_BASE58_ENC_32_ALLOCA( acct->pubkey ) ));
    return FD_ACC_MGR_ERR_WRITE_FAILED;
  }

  acct->const_meta = acct->meta;
  acct->const_data = acct->data;

  fd_funk_rec_key_t key = fd_funk_acc_key( acct->pubkey );

  /* Remove previous incarnation of the account's record from the transaction, so that we don't hash it twice */
  fd_funk_rec_hard_remove( funk, txn, &key );

  int err;
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, txn, &key, prepare, &err );
  if( rec == NULL ) FD_LOG_ERR(( "unable to insert a new record, error %d", err ));

  acct->rec = rec;
  ulong reclen = sizeof(fd_account_meta_t)+acct->const_meta->dlen;
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  if( fd_funk_val_truncate( rec, reclen, fd_funk_alloc( funk, wksp ), wksp, &err ) == NULL ) {
    FD_LOG_ERR(( "unable to allocate account value, err %d", err ));
  }
  err = fd_txn_account_save_internal( acct, funk );

  fd_funk_rec_publish( prepare );

  return err;
}

void
fd_txn_account_mutable_fini( fd_txn_account_t * acct,
                             fd_funk_t *        funk,
                             fd_funk_txn_t *    txn ) {
  fd_funk_rec_query_t query[1];

  fd_funk_rec_key_t key = fd_funk_acc_key( acct->pubkey );
  fd_funk_rec_t *   rec = (fd_funk_rec_t *)fd_funk_rec_query_try( funk, txn, &key, query );

  /* Check that the prepared record is still valid -
     if these invariants are broken something is very wrong. */
  if( acct->prepared_rec.rec ) {
    /* Check that the prepared record is not the Funk null value */
    if( !acct->prepared_rec.rec->val_gaddr ) {
      FD_LOG_ERR(( "invalid prepared record for %s: unexpected NULL funk record value. the record might have been modified by another thread",
                   FD_BASE58_ENC_32_ALLOCA( acct->pubkey ) ));
    }

    /* Ensure that the prepared record key still matches our key. */
    if( FD_UNLIKELY( memcmp( acct->prepared_rec.rec->pair.key, &key, sizeof(fd_funk_rec_key_t) )!=0 ) ) {
      FD_LOG_ERR(( "invalid prepared record for %s: the record might have been modified by another thread",
                  FD_BASE58_ENC_32_ALLOCA( acct->pubkey ) ));
    }
  }

  /* We have a prepared record, but a record already exists funk */
  if( rec!=NULL && acct->prepared_rec.rec!=NULL ) {
    FD_LOG_ERR(( "invalid prepared record for %s: trying to publish new record that is already present",
                   FD_BASE58_ENC_32_ALLOCA( acct->pubkey ) ));
  }

  /* Publish the record if the record is not in the current funk transaction
     and there exists a record in preparation in the fd_txn_account_t object */
  if( rec==NULL && acct->prepared_rec.rec!=NULL ) {
    fd_funk_rec_publish( &acct->prepared_rec );
  }
}
