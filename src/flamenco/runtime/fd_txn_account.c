#include "fd_txn_account.h"
#include "fd_runtime.h"

void *
fd_txn_account_new( void *              mem,
                    fd_pubkey_t const * pubkey,
                    fd_account_meta_t * meta,
                    int                 is_mutable ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_txn_account_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !pubkey ) ) {
    FD_LOG_WARNING(( "NULL pubkey" ));
    return NULL;
  }

  if( FD_UNLIKELY( !meta ) ) {
    FD_LOG_WARNING(( "NULL meta" ));
    return NULL;
  }

  fd_txn_account_t * txn_account = (fd_txn_account_t *)mem;

  fd_memcpy( txn_account->pubkey, pubkey, sizeof(fd_pubkey_t) );

  fd_wksp_t * wksp = fd_wksp_containing( meta );

  txn_account->magic             = FD_TXN_ACCOUNT_MAGIC;

  txn_account->starting_dlen     = meta->dlen;
  txn_account->starting_lamports = meta->info.lamports;

  uchar * data = (uchar *)meta + sizeof(fd_account_meta_t);

  txn_account->meta_gaddr = fd_wksp_gaddr( wksp, meta );
  if( FD_UNLIKELY( !txn_account->meta_gaddr ) ) {
    FD_LOG_WARNING(( "meta_gaddr is 0" ));
    return NULL;
  }

  txn_account->data_gaddr = fd_wksp_gaddr( wksp, data );
  if( FD_UNLIKELY( !txn_account->data_gaddr ) ) {
    FD_LOG_WARNING(( "data_gaddr is 0" ));
    return NULL;
  }

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

  if( FD_UNLIKELY( !data_wksp ) ) {
    FD_LOG_WARNING(( "NULL data_wksp" ));
    return NULL;
  }

  fd_txn_account_t * txn_account = (fd_txn_account_t *)mem;

  if( FD_UNLIKELY( txn_account->magic != FD_TXN_ACCOUNT_MAGIC ) ) {
    FD_LOG_WARNING(( "wrong magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( txn_account->meta_gaddr==0UL ) ) {
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

void *
fd_txn_account_leave( fd_txn_account_t * acct ) {

  if( FD_UNLIKELY( !acct ) ) {
    FD_LOG_WARNING(( "NULL acct" ));
    return NULL;
  }

  if( FD_UNLIKELY( acct->magic != FD_TXN_ACCOUNT_MAGIC ) ) {
    FD_LOG_WARNING(( "wrong magic" ));
    return NULL;
  }

  acct->meta = NULL;
  acct->data = NULL;

  return acct;
}

void *
fd_txn_account_delete( void * mem ) {
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

  txn_account->magic = 0UL;

  return mem;
}

/* Factory constructors from funk */

int
fd_txn_account_init_from_funk_readonly( fd_txn_account_t *    acct,
                                        fd_pubkey_t const *   pubkey,
                                        fd_funk_t const *     funk,
                                        fd_funk_txn_t const * funk_txn ) {

  int err = FD_ACC_MGR_SUCCESS;
  fd_account_meta_t const * meta = fd_funk_get_acc_meta_readonly(
      funk,
      funk_txn,
      pubkey,
      NULL,
      &err,
      NULL );

  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return err;
  }

  if( FD_UNLIKELY( !fd_txn_account_join( fd_txn_account_new(
        acct,
        pubkey,
        (fd_account_meta_t *)meta,
        0 ), fd_funk_wksp( funk ) ) ) ) {
    FD_LOG_CRIT(( "Failed to join txn account" ));
  }

  return FD_ACC_MGR_SUCCESS;
}

int
fd_txn_account_init_from_funk_mutable( fd_txn_account_t *      acct,
                                       fd_pubkey_t const *     pubkey,
                                       fd_funk_t *             funk,
                                       fd_funk_txn_t *         funk_txn,
                                       int                     do_create,
                                       ulong                   min_data_sz,
                                       fd_funk_rec_prepare_t * prepare_out ) {
  memset( prepare_out, 0, sizeof(fd_funk_rec_prepare_t) );
  int err = FD_ACC_MGR_SUCCESS;
  fd_account_meta_t * meta = fd_funk_get_acc_meta_mutable(
      funk,
      funk_txn,
      pubkey,
      do_create,
      min_data_sz,
      NULL,
      prepare_out,
      &err );

  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return err;
  }

  /* exec tile should never call this function, so the global addresses
     of meta and data should never be used. Instead, populate the
     prepared_rec field so that any created records can be published
     with fd_txn_account_mutable_fini. */

  if( FD_UNLIKELY( !fd_txn_account_join( fd_txn_account_new(
        acct,
        pubkey,
        (fd_account_meta_t *)meta,
        1 ), fd_funk_wksp( funk ) ) ) ) {
    FD_LOG_CRIT(( "Failed to join txn account" ));
  }

  return FD_ACC_MGR_SUCCESS;
}

void
fd_txn_account_mutable_fini( fd_txn_account_t *      acct,
                             fd_funk_t *             funk,
                             fd_funk_txn_t *         txn,
                             fd_funk_rec_prepare_t * prepare ) {
  fd_funk_rec_query_t query[1];

  fd_funk_rec_key_t key = fd_funk_acc_key( acct->pubkey );
  fd_funk_rec_t *   rec = (fd_funk_rec_t *)fd_funk_rec_query_try( funk, txn, &key, query );

  /* Check that the prepared record is still valid -
     if these invariants are broken something is very wrong. */
  if( prepare->rec ) {
    /* Check that the prepared record is not the Funk null value */
    if( !prepare->rec->val_gaddr ) {
      FD_LOG_CRIT(( "invalid prepared record for %s: unexpected NULL funk record value. the record might have been modified by another thread",
                   FD_BASE58_ENC_32_ALLOCA( acct->pubkey ) ));
    }

    /* Ensure that the prepared record key still matches our key. */
    if( FD_UNLIKELY( memcmp( prepare->rec->pair.key, &key, sizeof(fd_funk_rec_key_t) )!=0 ) ) {
      FD_LOG_CRIT(( "invalid prepared record for %s: the record might have been modified by another thread",
                  FD_BASE58_ENC_32_ALLOCA( acct->pubkey ) ));
    }
  }

  /* We have a prepared record, but a record already exists funk */
  if( rec!=NULL && prepare->rec!=NULL ) {
    FD_LOG_CRIT(( "invalid prepared record for %s: trying to publish new record that is already present",
                   FD_BASE58_ENC_32_ALLOCA( acct->pubkey ) ));
  }

  /* Publish the record if the record is not in the current funk transaction
     and there exists a record in preparation in the fd_txn_account_t object */
  if( rec==NULL && prepare->rec!=NULL ) {
    fd_funk_rec_publish( funk, prepare );
  }
}

/* read/write mutual exclusion */

FD_FN_PURE int
fd_txn_account_acquire_write_is_safe( fd_txn_account_t const * acct ) {
  return !acct->refcnt_excl;
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
  if( FD_UNLIKELY( acct->refcnt_excl!=1 ) ) {
    FD_LOG_CRIT(( "refcnt_excl is %d, expected 1", acct->refcnt_excl ));
  }
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
fd_txn_account_get_meta( fd_txn_account_t const * acct ) {
  return acct->meta;
}

uchar const *
fd_txn_account_get_data( fd_txn_account_t const * acct ) {
  return acct->data;
}

uchar *
fd_txn_account_get_data_mut( fd_txn_account_t const * acct ) {
  return acct->data;
}

ulong
fd_txn_account_get_data_len( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  return acct->meta->dlen;
}

int
fd_txn_account_is_executable( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  return !!acct->meta->info.executable;
}

ulong
fd_txn_account_get_lamports( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  return acct->meta->info.lamports;
}

ulong
fd_txn_account_get_rent_epoch( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  return acct->meta->info.rent_epoch;
}

fd_hash_t const *
fd_txn_account_get_hash( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  return (fd_hash_t const *)acct->meta->hash;
}

fd_solana_account_meta_t const *
fd_txn_account_get_info( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
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
