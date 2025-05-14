#include "fd_txn_account.h"
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
  ret->private_state.meta_gaddr = 0UL;
  ret->private_state.data_gaddr = 0UL;
  ret->starting_dlen            = ULONG_MAX;
  ret->starting_lamports        = ULONG_MAX;

  ret->private_state.const_data = NULL;
  ret->private_state.const_meta = NULL;
  ret->private_state.meta       = NULL;
  ret->private_state.data       = NULL;

  /* Defaults to writable vtable */
  ret->vt                       = &fd_txn_account_writable_vtable;

  FD_COMPILER_MFENCE();
  ret->magic = FD_TXN_ACCOUNT_MAGIC;
  FD_COMPILER_MFENCE();

  return ret;
}

/* A common setup helper function that sets
   default values for the txn account */
void
fd_txn_account_setup_common( fd_txn_account_t * acct ) {
  fd_account_meta_t const * meta = acct->private_state.const_meta ?
                                   acct->private_state.const_meta : acct->private_state.meta;

  /* TODO: Why ULONG_MAX check here? */
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
  acct->private_state.const_data = data;
  acct->private_state.const_meta = meta;
  acct->private_state.data       = data;
  acct->private_state.meta       = meta;
  acct->vt                       = &fd_txn_account_writable_vtable;
}

void
fd_txn_account_init_from_meta_and_data_readonly( fd_txn_account_t *        acct,
                                                 fd_account_meta_t const * meta,
                                                 uchar const *             data ) {

  acct->private_state.const_data = data;
  acct->private_state.const_meta = meta;
  acct->vt                       = &fd_txn_account_readonly_vtable;
}

void
fd_txn_account_setup_sentinel_meta_readonly( fd_txn_account_t * acct,
                                             fd_spad_t *        spad,
                                             fd_wksp_t *        spad_wksp ) {

  fd_account_meta_t * sentinel = fd_spad_alloc( spad, FD_ACCOUNT_REC_ALIGN, sizeof(fd_account_meta_t) );
  fd_memset( sentinel, 0, sizeof(fd_account_meta_t) );

  sentinel->magic                = FD_ACCOUNT_META_MAGIC;
  sentinel->info.rent_epoch      = ULONG_MAX;
  acct->private_state.const_meta = sentinel;
  acct->starting_lamports        = 0UL;
  acct->starting_dlen            = 0UL;
  acct->private_state.meta_gaddr = fd_wksp_gaddr( spad_wksp, sentinel );
}

void
fd_txn_account_setup_meta_mutable( fd_txn_account_t * acct,
                                   fd_spad_t *        spad,
                                   ulong              sz ) {
  fd_account_meta_t * meta = fd_spad_alloc( spad, alignof(fd_account_meta_t), sizeof(fd_account_meta_t) + sz );
  void * data = (uchar *)meta + sizeof(fd_account_meta_t);

  acct->private_state.const_meta = acct->private_state.meta = meta;
  acct->private_state.const_data = acct->private_state.data = data;
  acct->vt                       = &fd_txn_account_writable_vtable;
}

void
fd_txn_account_setup_readonly( fd_txn_account_t *        acct,
                               fd_pubkey_t const *       pubkey,
                               fd_account_meta_t const * meta ) {
  fd_memcpy(acct->pubkey, pubkey, sizeof(fd_pubkey_t));

  /* We don't copy the metadata into a buffer here, because we assume
     that we are holding read locks on the account, because we are inside
     a transaction. */
  acct->private_state.const_meta = meta;
  acct->private_state.const_data = (uchar const *)meta + meta->hlen;
  acct->vt                       = &fd_txn_account_readonly_vtable;

  fd_txn_account_setup_common( acct );
}

void
fd_txn_account_setup_mutable( fd_txn_account_t *        acct,
                              fd_pubkey_t const *       pubkey,
                              fd_account_meta_t *       meta ) {
  fd_memcpy(acct->pubkey, pubkey, sizeof(fd_pubkey_t));

  acct->private_state.const_rec  = acct->private_state.rec;
  acct->private_state.const_meta = acct->private_state.meta = meta;
  acct->private_state.const_data = acct->private_state.data = (uchar *)meta + meta->hlen;
  acct->vt                       = &fd_txn_account_writable_vtable;

  fd_txn_account_setup_common( acct );
}

/* Operators impl */

/* Internal helper to initialize account data */
uchar *
fd_txn_account_init_data( fd_txn_account_t * acct, void * buf ) {
  /* Assumes that buf is pointing to account data */
  uchar * new_raw_data = (uchar *)buf;
  ulong   dlen         = ( acct->private_state.const_meta != NULL ) ? acct->private_state.const_meta->dlen : 0;

  if( acct->private_state.const_meta != NULL ) {
    fd_memcpy( new_raw_data, (uchar *)acct->private_state.const_meta, sizeof(fd_account_meta_t)+dlen );
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
  if( FD_UNLIKELY( acct->private_state.data != NULL ) ) {
    FD_LOG_ERR(( "borrowed account is already mutable" ));
  }

  ulong   dlen         = ( acct->private_state.const_meta != NULL ) ? acct->private_state.const_meta->dlen : 0UL;
  uchar * new_raw_data = fd_txn_account_init_data( acct, buf );

  acct->private_state.const_meta = acct->private_state.meta = (fd_account_meta_t *)new_raw_data;
  acct->private_state.const_data = acct->private_state.data = new_raw_data + sizeof(fd_account_meta_t);
  acct->private_state.meta->dlen = dlen;

  /* update global addresses of meta and data after copying into buffer */
  acct->private_state.meta_gaddr = fd_wksp_gaddr( wksp, acct->private_state.meta );
  acct->private_state.data_gaddr = fd_wksp_gaddr( wksp, acct->private_state.data );
  acct->vt                       = &fd_txn_account_writable_vtable;

  return acct;
}

/* Factory constructors from funk */

int
fd_txn_account_init_from_funk_readonly( fd_txn_account_t *    acct,
                                        fd_pubkey_t const *   pubkey,
                                        fd_funk_t const *     funk,
                                        fd_funk_txn_t const * funk_txn ) {
  fd_txn_account_init( acct );

  int err = FD_ACC_MGR_SUCCESS;
  fd_account_meta_t const * meta = fd_funk_get_acc_meta_readonly( funk,
                                                                  funk_txn,
                                                                  pubkey,
                                                                  &acct->private_state.const_rec,
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
  fd_wksp_t * funk_wksp          = fd_funk_wksp( funk );
  acct->private_state.meta_gaddr = fd_wksp_gaddr( funk_wksp, acct->private_state.const_meta );
  acct->private_state.data_gaddr = fd_wksp_gaddr( funk_wksp, acct->private_state.const_data );

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
                                                           &acct->private_state.rec,
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
  acct->private_state.data[0] = acct->private_state.data[0];

  return FD_ACC_MGR_SUCCESS;
}

/* Funk save function impl */

int
fd_txn_account_save_internal( fd_txn_account_t * acct,
                              fd_funk_t *        funk ) {
  if( acct->private_state.rec == NULL ) {
    return FD_ACC_MGR_ERR_WRITE_FAILED;
  }

  fd_wksp_t * wksp = fd_funk_wksp( funk );
  ulong reclen = sizeof(fd_account_meta_t)+acct->private_state.const_meta->dlen;
  uchar * raw = fd_funk_val( acct->private_state.rec, wksp );
  fd_memcpy( raw, acct->private_state.meta, reclen );

  return FD_ACC_MGR_SUCCESS;
}

int
fd_txn_account_save( fd_txn_account_t * acct,
                     fd_funk_t *        funk,
                     fd_funk_txn_t *    txn,
                     fd_wksp_t *        acc_data_wksp ) {
  acct->private_state.meta = fd_wksp_laddr( acc_data_wksp, acct->private_state.meta_gaddr );
  acct->private_state.data = fd_wksp_laddr( acc_data_wksp, acct->private_state.data_gaddr );

  if( acct->private_state.meta == NULL ) {
    /* The meta is NULL so the account is not writable. */
    FD_LOG_DEBUG(( "fd_txn_account_save: account is not writable: %s", FD_BASE58_ENC_32_ALLOCA( acct->pubkey ) ));
    return FD_ACC_MGR_ERR_WRITE_FAILED;
  }

  acct->private_state.const_meta = acct->private_state.meta;
  acct->private_state.const_data = acct->private_state.data;

  fd_funk_rec_key_t key = fd_funk_acc_key( acct->pubkey );

  /* Remove previous incarnation of the account's record from the transaction, so that we don't hash it twice */
  fd_funk_rec_hard_remove( funk, txn, &key );

  int err;
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, txn, &key, prepare, &err );
  if( rec == NULL ) FD_LOG_ERR(( "unable to insert a new record, error %d", err ));

  acct->private_state.rec = rec;
  ulong       reclen = sizeof(fd_account_meta_t)+acct->private_state.const_meta->dlen;
  fd_wksp_t * wksp   = fd_funk_wksp( funk );
  if( fd_funk_val_truncate(
      rec,
      fd_funk_alloc( funk ),
      wksp,
      0UL,
      reclen,
      &err ) == NULL ) {
    FD_LOG_ERR(( "fd_funk_val_truncate(sz=%lu) for account failed (%i-%s)", reclen, err, fd_funk_strerror( err ) ));
  }
  err = fd_txn_account_save_internal( acct, funk );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "fd_txn_account_save_internal() failed (%i-%s)", err, fd_funk_strerror( err ) ));
  }

  fd_funk_rec_publish( funk, prepare );

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
    fd_funk_rec_publish( funk, &acct->prepared_rec );
  }
}

/* read/write mutual exclusion */

FD_FN_PURE int
fd_txn_account_acquire_write_is_safe( fd_txn_account_t const * acct ) {
  return (!acct->private_state.refcnt_excl);
}

/* fd_txn_account_acquire_write acquires write/exclusive access.
   Causes all other write or read acquire attempts will fail.  Returns 1
   on success, 0 on failure.

   Mirrors a try_borrow_mut() call in Agave. */
int
fd_txn_account_acquire_write( fd_txn_account_t * acct ) {
  if( FD_UNLIKELY( !fd_txn_account_acquire_write_is_safe( acct ) ) ) {
    return 0;
  }
  acct->private_state.refcnt_excl = (ushort)1;
  return 1;
}

/* fd_txn_account_release_write{_private} releases a write/exclusive
   access handle. The private version should only be used by fd_borrowed_account_drop
   and fd_borrowed_account_destroy. */
void
fd_txn_account_release_write( fd_txn_account_t * acct ) {
  FD_TEST( acct->private_state.refcnt_excl==1U );
  acct->private_state.refcnt_excl = (ushort)0;
}

void
fd_txn_account_release_write_private( fd_txn_account_t * acct ) {
  /* Only release if it is not yet released */
  if( !fd_txn_account_acquire_write_is_safe( acct ) ) {
    fd_txn_account_release_write( acct );
  }
}

/* Vtable API Impls */

fd_account_meta_t const *
fd_txn_account_get_acc_meta( fd_txn_account_t const * acct ) {
  return acct->private_state.const_meta;
}

uchar const *
fd_txn_account_get_acc_data( fd_txn_account_t const * acct ) {
  return acct->private_state.const_data;
}

fd_funk_rec_t const *
fd_txn_account_get_acc_rec( fd_txn_account_t const * acct ) {
  return acct->private_state.const_rec;
}

uchar *
fd_txn_account_get_acc_data_mut_writable( fd_txn_account_t const * acct ) {
  return acct->private_state.data;
}

void
fd_txn_account_set_meta_readonly( fd_txn_account_t *        acct,
                                  fd_account_meta_t const * meta ) {
  acct->private_state.const_meta = meta;
}

void
fd_txn_account_set_meta_mutable_writable( fd_txn_account_t *  acct,
                                 fd_account_meta_t * meta ) {
  acct->private_state.const_meta = acct->private_state.meta = meta;
}

ulong
fd_txn_account_get_data_len( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->private_state.const_meta ) ) FD_LOG_ERR(("account is not setup" ));
  return acct->private_state.const_meta->dlen;
}

int
fd_txn_account_is_executable( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->private_state.const_meta ) ) FD_LOG_ERR(("account is not setup" ));
  return !!acct->private_state.const_meta->info.executable;
}

fd_pubkey_t const *
fd_txn_account_get_owner( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->private_state.const_meta ) ) FD_LOG_ERR(("account is not setup" ));
  return (fd_pubkey_t const *)acct->private_state.const_meta->info.owner;
}

ulong
fd_txn_account_get_lamports( fd_txn_account_t const * acct ) {
  /* (!const_meta_) considered an internal error */
  if( FD_UNLIKELY( !acct->private_state.const_meta ) ) return 0UL;
  return acct->private_state.const_meta->info.lamports;
}

ulong
fd_txn_account_get_rent_epoch( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->private_state.const_meta ) ) FD_LOG_ERR(("account is not setup" ));
  return acct->private_state.const_meta->info.rent_epoch;
}

fd_hash_t const *
fd_txn_account_get_hash( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->private_state.const_meta ) ) FD_LOG_ERR(("account is not setup" ));
  return (fd_hash_t const *)acct->private_state.const_meta->hash;
}

fd_solana_account_meta_t const *
fd_txn_account_get_info( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->private_state.const_meta ) ) FD_LOG_ERR(("account is not setup" ));
  return &acct->private_state.const_meta->info;
}

void
fd_txn_account_set_executable_writable( fd_txn_account_t * acct, int is_executable ) {
  if( FD_UNLIKELY( !acct->private_state.meta ) ) FD_LOG_ERR(("account is not mutable" ));
  acct->private_state.meta->info.executable = !!is_executable;
}

void
fd_txn_account_set_owner_writable( fd_txn_account_t * acct, fd_pubkey_t const * owner ) {
  if( FD_UNLIKELY( !acct->private_state.meta ) ) FD_LOG_ERR(("account is not mutable" ));
  fd_memcpy( acct->private_state.meta->info.owner, owner, sizeof(fd_pubkey_t) );
}

void
fd_txn_account_set_lamports_writable( fd_txn_account_t * acct, ulong lamports ) {
  if( FD_UNLIKELY( !acct->private_state.meta ) ) FD_LOG_ERR(("account is not mutable" ));
  acct->private_state.meta->info.lamports = lamports;
}

int
fd_txn_account_checked_add_lamports_writable( fd_txn_account_t * acct, ulong lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_add( acct->vt->get_lamports( acct ), lamports, &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  acct->vt->set_lamports( acct, balance_post );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_txn_account_checked_sub_lamports_writable( fd_txn_account_t * acct, ulong lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_sub( acct->vt->get_lamports( acct ),
                                  lamports,
                                  &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  acct->vt->set_lamports( acct, balance_post );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

void
fd_txn_account_set_rent_epoch_writable( fd_txn_account_t * acct, ulong rent_epoch ) {
  if( FD_UNLIKELY( !acct->private_state.meta ) ) FD_LOG_ERR(("account is not mutable" ));
  acct->private_state.meta->info.rent_epoch = rent_epoch;
}

void
fd_txn_account_set_data_writable( fd_txn_account_t * acct,
                                  void const *       data,
                                  ulong              data_sz) {
  if( FD_UNLIKELY( !acct->private_state.meta ) ) FD_LOG_ERR(("account is not mutable" ));
  acct->private_state.meta->dlen = data_sz;
  fd_memcpy( acct->private_state.data, data, data_sz );
}

void
fd_txn_account_set_data_len_writable( fd_txn_account_t * acct,
                                      ulong              data_len ) {
  if( FD_UNLIKELY( !acct->private_state.meta ) ) FD_LOG_ERR(("account is not mutable" ));
  acct->private_state.meta->dlen = data_len;
}

void
fd_txn_account_set_slot_writable( fd_txn_account_t * acct,
                         ulong              slot ) {
  if( FD_UNLIKELY( !acct->private_state.meta ) ) FD_LOG_ERR(("account is not mutable" ));
  acct->private_state.meta->slot = slot;
}

void
fd_txn_account_set_hash_writable( fd_txn_account_t * acct,
                                  fd_hash_t const *  hash ) {
  if( FD_UNLIKELY( !acct->private_state.meta ) ) FD_LOG_ERR(("account is not mutable" ));
  memcpy( acct->private_state.meta->hash, hash->hash, sizeof(fd_hash_t) );
}

void
fd_txn_account_clear_owner_writable( fd_txn_account_t * acct ) {
  if( FD_UNLIKELY( !acct->private_state.meta ) ) FD_LOG_ERR(("account is not mutable" ));
  fd_memset( acct->private_state.meta->info.owner, 0, sizeof(fd_pubkey_t) );
}

void
fd_txn_account_set_meta_info_writable( fd_txn_account_t *               acct,
                                       fd_solana_account_meta_t const * info ) {
  if( FD_UNLIKELY( !acct->private_state.meta ) ) FD_LOG_ERR(("account is not mutable" ));
  acct->private_state.meta->info = *info;
}

void
fd_txn_account_resize_writable( fd_txn_account_t * acct,
                                ulong              dlen ) {
  if( FD_UNLIKELY( !acct->private_state.meta ) ) FD_LOG_ERR(("account is not mutable" ));
  /* Because the memory for an account is preallocated for the transaction
     up to the max account size, we only need to zero out bytes (for the case
     where the account grew) and update the account dlen. */
  ulong old_sz    = acct->private_state.meta->dlen;
  ulong new_sz    = dlen;
  ulong memset_sz = fd_ulong_sat_sub( new_sz, old_sz );
  fd_memset( acct->private_state.data+old_sz, 0, memset_sz );

  acct->private_state.meta->dlen = dlen;
}

uchar *
fd_txn_account_get_acc_data_mut_readonly( fd_txn_account_t const * acct FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "account is not mutable" ));
  return NULL;
}

void
fd_txn_account_set_meta_mutable_readonly( fd_txn_account_t *  acct FD_PARAM_UNUSED,
                                          fd_account_meta_t * meta FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot set meta as mutable in a readonly account!" ));
}

void
fd_txn_account_set_executable_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                        int                is_executable FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot set executable in a readonly account!" ));
}

void
fd_txn_account_set_owner_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                   fd_pubkey_t const * owner FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot set owner in a readonly account!" ));
}

void
fd_txn_account_set_lamports_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                      ulong lamports FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot set lamports in a readonly account!" ));
}

int
fd_txn_account_checked_add_lamports_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                              ulong              lamports FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot do a checked add to lamports in a readonly account!" ));
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_txn_account_checked_sub_lamports_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                              ulong              lamports FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot do a checked sub to lamports in a readonly account!" ));
  return FD_EXECUTOR_INSTR_SUCCESS;
}

void
fd_txn_account_set_rent_epoch_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                        ulong              rent_epoch FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot set rent epoch in a readonly account!" ));
}

void
fd_txn_account_set_data_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                  void const *       data FD_PARAM_UNUSED,
                                  ulong              data_sz FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot set data in a readonly account!" ));
}

void
fd_txn_account_set_data_len_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                      ulong              data_len FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot set data_len in a readonly account!" ));
}

void
fd_txn_account_set_slot_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                  ulong              slot FD_PARAM_UNUSED ) {
  FD_LOG_ERR(("cannot set slot in a readonly account!"));
}

void
fd_txn_account_set_hash_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                  fd_hash_t const *  hash FD_PARAM_UNUSED ) {
  FD_LOG_ERR(("cannot set hash in a readonly account!"));
}

void
fd_txn_account_clear_owner_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED ) {
  FD_LOG_ERR(("cannot clear owner in a readonly account!"));
}

void
fd_txn_account_set_meta_info_readonly( fd_txn_account_t *               acct FD_PARAM_UNUSED,
                                       fd_solana_account_meta_t const * info FD_PARAM_UNUSED ) {
  FD_LOG_ERR(("cannot set meta info in a readonly account!"));
}

void
fd_txn_account_resize_readonly( fd_txn_account_t * acct FD_PARAM_UNUSED,
                                ulong              dlen FD_PARAM_UNUSED ) {
  FD_LOG_ERR(( "cannot resize a readonly account!" ));
}

ushort
fd_txn_account_is_borrowed( fd_txn_account_t const * acct ) {
  return !!acct->private_state.refcnt_excl;
}

int
fd_txn_account_is_mutable( fd_txn_account_t const * acct ) {
  /* A txn account is mutable if meta is non NULL */
  return acct->private_state.meta != NULL;
}

int
fd_txn_account_is_readonly( fd_txn_account_t const * acct ) {
  /* A txn account is readonly if only the const_meta_ field is non NULL */
  return acct->private_state.const_meta!=NULL && acct->private_state.meta==NULL;
}

int
fd_txn_account_try_borrow_mut( fd_txn_account_t * acct ) {
  return fd_txn_account_acquire_write( acct );
}

void
fd_txn_account_drop( fd_txn_account_t * acct ) {
  fd_txn_account_release_write_private( acct );
}

void
fd_txn_account_set_readonly( fd_txn_account_t * acct ) {
  acct->private_state.meta = NULL;
  acct->private_state.data = NULL;
  acct->private_state.rec  = NULL;
  acct->vt                 = &fd_txn_account_readonly_vtable;
}

void
fd_txn_account_set_mutable( fd_txn_account_t * acct ) {
  acct->private_state.meta = (void *)acct->private_state.const_meta;
  acct->private_state.data = (void *)acct->private_state.const_data;
  acct->private_state.rec  = (void *)acct->private_state.const_rec;
  acct->vt                 = &fd_txn_account_writable_vtable;
}

/* vtable definitions */

#define FD_TXN_ACCOUNT_VTABLE_DEF( type )                             \
const fd_txn_account_vtable_t                                         \
fd_txn_account_##type##_vtable = {                                    \
  .get_meta             = fd_txn_account_get_acc_meta,                \
  .get_data             = fd_txn_account_get_acc_data,                \
  .get_rec              = fd_txn_account_get_acc_rec,                 \
                                                                      \
  .get_data_mut         = fd_txn_account_get_acc_data_mut_##type,     \
                                                                      \
  .set_meta_readonly    = fd_txn_account_set_meta_readonly,           \
  .set_meta_mutable     = fd_txn_account_set_meta_mutable_##type,     \
                                                                      \
  .get_data_len         = fd_txn_account_get_data_len,                \
  .is_executable        = fd_txn_account_is_executable,               \
  .get_owner            = fd_txn_account_get_owner,                   \
  .get_lamports         = fd_txn_account_get_lamports,                \
  .get_rent_epoch       = fd_txn_account_get_rent_epoch,              \
  .get_hash             = fd_txn_account_get_hash,                    \
  .get_info             = fd_txn_account_get_info,                    \
                                                                      \
  .set_executable       = fd_txn_account_set_executable_##type,       \
  .set_owner            = fd_txn_account_set_owner_##type,            \
  .set_lamports         = fd_txn_account_set_lamports_##type,         \
  .checked_add_lamports = fd_txn_account_checked_add_lamports_##type, \
  .checked_sub_lamports = fd_txn_account_checked_sub_lamports_##type, \
  .set_rent_epoch       = fd_txn_account_set_rent_epoch_##type,       \
  .set_data             = fd_txn_account_set_data_##type,             \
  .set_data_len         = fd_txn_account_set_data_len_##type,         \
  .set_slot             = fd_txn_account_set_slot_##type,             \
  .set_hash             = fd_txn_account_set_hash_##type,             \
  .clear_owner          = fd_txn_account_clear_owner_##type,          \
  .set_info             = fd_txn_account_set_meta_info_##type,        \
  .resize               = fd_txn_account_resize_##type,               \
                                                                      \
  .is_borrowed          = fd_txn_account_is_borrowed,                 \
  .is_mutable           = fd_txn_account_is_mutable,                  \
  .is_readonly          = fd_txn_account_is_readonly,                 \
                                                                      \
  .try_borrow_mut       = fd_txn_account_try_borrow_mut,              \
  .drop                 = fd_txn_account_drop,                        \
                                                                      \
  .set_readonly         = fd_txn_account_set_readonly,                \
  .set_mutable          = fd_txn_account_set_mutable                  \
}

FD_TXN_ACCOUNT_VTABLE_DEF( readonly );
FD_TXN_ACCOUNT_VTABLE_DEF( writable );

#undef FD_TXN_ACCOUNT_VTABLE_DEF
