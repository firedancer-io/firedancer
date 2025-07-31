#include "fd_txn_account.h"
#include "fd_runtime.h"

void *
fd_txn_account_new( void *              mem,
                    fd_pubkey_t const * pubkey,
                    fd_account_meta_t * meta,
                    uchar *             data,
                    int                 is_mutable ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_txn_account_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
  }

  fd_txn_account_t * txn_account = (fd_txn_account_t *)mem;

  fd_memcpy( txn_account->pubkey, pubkey, sizeof(fd_pubkey_t) );

  fd_wksp_t * wksp = fd_wksp_containing( meta );

  txn_account->magic             = FD_TXN_ACCOUNT_MAGIC;

  txn_account->starting_dlen     = meta->dlen;
  txn_account->starting_lamports = meta->info.lamports;

  txn_account->meta_gaddr        = fd_wksp_gaddr( wksp, meta );
  txn_account->data_gaddr        = fd_wksp_gaddr( wksp, data );
  txn_account->meta              = meta;
  txn_account->data              = data;
  txn_account->is_mutable        = is_mutable;

  return mem;
}

fd_txn_account_t *
fd_txn_account_join( void * mem, fd_wksp_t * data_wksp ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_txn_account_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_txn_account_t * txn_account = (fd_txn_account_t *)mem;

  if( FD_UNLIKELY( txn_account->magic != FD_TXN_ACCOUNT_MAGIC ) ) {
    FD_LOG_WARNING(( "wrong magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( txn_account->meta_gaddr == 0UL ) ) {
    FD_LOG_WARNING(( "`meta gaddr is 0" ));
    return NULL;
  }

  txn_account->meta = fd_wksp_laddr( data_wksp, txn_account->meta_gaddr );
  if( FD_UNLIKELY( !txn_account->meta ) ) {
    FD_LOG_WARNING(( "meta is NULL" ));
    return NULL;
  }

  txn_account->data = fd_wksp_laddr( data_wksp, txn_account->data_gaddr );
  if( FD_UNLIKELY( !txn_account->data && txn_account->meta->dlen ) ) {
    FD_LOG_WARNING(( "data is NULL" ));
    return NULL;
  }

  return txn_account;
}

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
  ret->meta_gaddr = 0UL;
  ret->data_gaddr = 0UL;
  ret->starting_dlen            = ULONG_MAX;
  ret->starting_lamports        = ULONG_MAX;

  ret->meta       = NULL;
  ret->data       = NULL;

  ret->is_mutable = 0;

  FD_COMPILER_MFENCE();
  ret->magic = FD_TXN_ACCOUNT_MAGIC;
  FD_COMPILER_MFENCE();

  return ret;
}

/* A common setup helper function that sets
   default values for the txn account */
void
fd_txn_account_setup_common( fd_txn_account_t * acct ) {
  fd_account_meta_t const * meta = acct->meta;

  /* TODO: Why ULONG_MAX check here? */
  if( ULONG_MAX == acct->starting_dlen ) {
    acct->starting_dlen = meta->dlen;
  }

  if( ULONG_MAX == acct->starting_lamports ) {
    acct->starting_lamports = meta->info.lamports;
  }
}

void
fd_txn_account_setup( fd_txn_account_t *        acct,
                      fd_pubkey_t const *       pubkey,
                      fd_account_meta_t const * meta,
                      int                       is_mutable ) {
  fd_memcpy( acct->pubkey, pubkey, sizeof(fd_pubkey_t) );

  /* We don't copy the metadata into a buffer here, because we assume
     that we are holding read locks on the account, because we are inside
     a transaction. */
  acct->meta       = (fd_account_meta_t *)meta;
  acct->data       = (uchar *)meta + meta->hlen;
  acct->is_mutable = is_mutable;

  fd_txn_account_setup_common( acct );
}

/* Operators impl */

/* Internal helper to initialize account data */
uchar *
fd_txn_account_init_data( fd_txn_account_t * acct, void * buf ) {
  /* Assumes that buf is pointing to account data */
  uchar * new_raw_data = (uchar *)buf;
  ulong   dlen         = ( acct->meta != NULL ) ? acct->meta->dlen : 0;

  if( acct->meta != NULL ) {
    fd_memcpy( new_raw_data, (uchar *)acct->meta, sizeof(fd_account_meta_t)+dlen );
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
  if( FD_UNLIKELY( acct->is_mutable ) ) {
    FD_LOG_ERR(( "borrowed account is already mutable" ));
  }

  ulong   dlen         = !!acct->meta ? acct->meta->dlen : 0UL;
  uchar * new_raw_data = fd_txn_account_init_data( acct, buf );

  acct->meta = (fd_account_meta_t *)new_raw_data;
  acct->data = new_raw_data + sizeof(fd_account_meta_t);
  acct->meta->dlen = dlen;

  /* update global addresses of meta and data after copying into buffer */
  acct->meta_gaddr = fd_wksp_gaddr( wksp, acct->meta );
  acct->data_gaddr = fd_wksp_gaddr( wksp, acct->data );
  acct->is_mutable = 1;

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
                                                                  (fd_funk_rec_t const **)&acct->rec,
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
  acct->meta_gaddr = fd_wksp_gaddr( funk_wksp, acct->meta );
  acct->data_gaddr = fd_wksp_gaddr( funk_wksp, acct->data );

  fd_txn_account_setup( acct, pubkey, meta, 0 );

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
  fd_txn_account_setup( acct, pubkey, meta, 1 );

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
  ulong reclen = sizeof(fd_account_meta_t)+acct->meta->dlen;
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

  fd_funk_rec_key_t key = fd_funk_acc_key( acct->pubkey );

  /* Remove previous incarnation of the account's record from the transaction, so that we don't hash it twice */
  fd_funk_rec_hard_remove( funk, txn, &key );

  int err;
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, txn, &key, prepare, &err );
  if( rec == NULL ) FD_LOG_ERR(( "unable to insert a new record, error %d", err ));

  acct->rec = rec;
  ulong       reclen = sizeof(fd_account_meta_t)+acct->meta->dlen;
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
  return (!acct->refcnt_excl);
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
  acct->refcnt_excl = (ushort)1;
  return 1;
}

/* fd_txn_account_release_write{_private} releases a write/exclusive
   access handle. The private version should only be used by fd_borrowed_account_drop
   and fd_borrowed_account_destroy. */
void
fd_txn_account_release_write( fd_txn_account_t * acct ) {
  FD_TEST( acct->refcnt_excl==1U );
  acct->refcnt_excl = (ushort)0;
}

void
fd_txn_account_release_write_private( fd_txn_account_t * acct ) {
  /* Only release if it is not yet released */
  if( !fd_txn_account_acquire_write_is_safe( acct ) ) {
    fd_txn_account_release_write( acct );
  }
}

fd_pubkey_t const *
fd_txn_account_get_owner( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  return (fd_pubkey_t const *)acct->meta->info.owner;
}

fd_account_meta_t const *
fd_txn_account_get_acc_meta( fd_txn_account_t const * acct ) {
  return acct->meta;
}

uchar const *
fd_txn_account_get_acc_data( fd_txn_account_t const * acct ) {
  return acct->data;
}

fd_funk_rec_t const *
fd_txn_account_get_acc_rec( fd_txn_account_t const * acct ) {
  return acct->rec;
}

uchar *
fd_txn_account_get_acc_data_mut( fd_txn_account_t const * acct ) {
  return acct->data;
}

ulong
fd_txn_account_get_data_len( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) FD_LOG_ERR(("account is not setup" ));
  return acct->meta->dlen;
}

int
fd_txn_account_is_executable( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) FD_LOG_ERR(("account is not setup" ));
  return !!acct->meta->info.executable;
}

ulong
fd_txn_account_get_lamports( fd_txn_account_t const * acct ) {
  /* (!meta_) considered an internal error */
  if( FD_UNLIKELY( !acct->meta ) ) return 0UL;
  return acct->meta->info.lamports;
}

ulong
fd_txn_account_get_rent_epoch( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) FD_LOG_ERR(("account is not setup" ));
  return acct->meta->info.rent_epoch;
}

fd_hash_t const *
fd_txn_account_get_hash( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) FD_LOG_ERR(("account is not setup" ));
  return (fd_hash_t const *)acct->meta->hash;
}

fd_solana_account_meta_t const *
fd_txn_account_get_info( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) FD_LOG_ERR(("account is not setup" ));
  return &acct->meta->info;
}

void
fd_txn_account_set_meta( fd_txn_account_t * acct, fd_account_meta_t * meta ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta = meta;
}

void
fd_txn_account_set_executable( fd_txn_account_t * acct, int is_executable ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->info.executable = !!is_executable;
}

void
fd_txn_account_set_owner( fd_txn_account_t * acct, fd_pubkey_t const * owner ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  fd_memcpy( acct->meta->info.owner, owner, sizeof(fd_pubkey_t) );
}

void
fd_txn_account_set_lamports( fd_txn_account_t * acct, ulong lamports ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->info.lamports = lamports;
}

int
fd_txn_account_checked_add_lamports( fd_txn_account_t * acct, ulong lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_add( fd_txn_account_get_lamports( acct ), lamports, &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  fd_txn_account_set_lamports( acct, balance_post );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_txn_account_checked_sub_lamports( fd_txn_account_t * acct, ulong lamports ) {
  ulong balance_post = 0UL;
  int err = fd_ulong_checked_sub( fd_txn_account_get_lamports( acct ),
                                  lamports,
                                  &balance_post );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  fd_txn_account_set_lamports( acct, balance_post );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

void
fd_txn_account_set_rent_epoch( fd_txn_account_t * acct, ulong rent_epoch ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->info.rent_epoch = rent_epoch;
}

void
fd_txn_account_set_data( fd_txn_account_t * acct,
                         void const *       data,
                         ulong              data_sz ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->dlen = data_sz;
  fd_memcpy( acct->data, data, data_sz );
}

void
fd_txn_account_set_data_len( fd_txn_account_t * acct, ulong data_len ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->dlen = data_len;
}

void
fd_txn_account_set_slot( fd_txn_account_t * acct, ulong slot ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->slot = slot;
}

void
fd_txn_account_set_hash( fd_txn_account_t * acct, fd_hash_t const *  hash ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  memcpy( acct->meta->hash, hash->hash, sizeof(fd_hash_t) );
}

void
fd_txn_account_clear_owner( fd_txn_account_t * acct ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  fd_memset( acct->meta->info.owner, 0, sizeof(fd_pubkey_t) );
}

void
fd_txn_account_set_meta_info( fd_txn_account_t * acct, fd_solana_account_meta_t const * info ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->info = *info;
}

void
fd_txn_account_resize( fd_txn_account_t * acct,
                       ulong              dlen ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  /* Because the memory for an account is preallocated for the transaction
     up to the max account size, we only need to zero out bytes (for the case
     where the account grew) and update the account dlen. */
  ulong old_sz    = acct->meta->dlen;
  ulong new_sz    = dlen;
  ulong memset_sz = fd_ulong_sat_sub( new_sz, old_sz );
  fd_memset( acct->data+old_sz, 0, memset_sz );

  acct->meta->dlen = dlen;
}

ushort
fd_txn_account_is_borrowed( fd_txn_account_t const * acct ) {
  return !!acct->refcnt_excl;
}

int
fd_txn_account_is_mutable( fd_txn_account_t const * acct ) {
  /* A txn account is mutable if meta is non NULL */
  return acct->is_mutable;
}

int
fd_txn_account_is_readonly( fd_txn_account_t const * acct ) {
  /* A txn account is readonly if only the meta_ field is non NULL */
  return !acct->is_mutable;
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
  acct->is_mutable = 0;
}

void
fd_txn_account_set_mutable( fd_txn_account_t * acct ) {
  acct->is_mutable = 1;
}
