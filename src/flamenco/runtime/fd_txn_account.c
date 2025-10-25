#include "fd_txn_account.h"
#include "fd_runtime.h"
#include "../accdb/fd_accdb_sync.h"
#include "program/fd_program_util.h"

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

  txn_account->magic             = FD_TXN_ACCOUNT_MAGIC;

  txn_account->starting_dlen     = meta->dlen;
  txn_account->starting_lamports = meta->lamports;

  uchar * data = (uchar *)meta + sizeof(fd_account_meta_t);

  txn_account->meta_soff = (long)( (ulong)meta - (ulong)mem );

  txn_account->meta       = meta;
  txn_account->data       = data;
  txn_account->is_mutable = is_mutable;

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

  if( FD_UNLIKELY( txn_account->meta_soff==0UL ) ) {
    FD_LOG_CRIT(( "invalid meta_soff" ));
  }

  txn_account->meta = (void *)( (ulong)mem + (ulong)txn_account->meta_soff );
  txn_account->data = (void *)( (ulong)txn_account->meta + sizeof(fd_account_meta_t) );

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
fd_txn_account_init_from_funk_readonly( fd_txn_account_t *        acct,
                                        fd_pubkey_t const *       pubkey,
                                        fd_funk_t const *         funk,
                                        fd_funk_txn_xid_t const * xid ) {

  int err = FD_ACC_MGR_SUCCESS;
  fd_account_meta_t const * meta = fd_funk_get_acc_meta_readonly(
      funk,
      xid,
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

fd_account_meta_t *
fd_txn_account_init_from_funk_mutable( fd_txn_account_t *        acct,
                                       fd_pubkey_t const *       pubkey,
                                       fd_accdb_user_t *         accdb,
                                       fd_funk_txn_xid_t const * xid,
                                       int                       do_create,
                                       ulong                     min_data_sz,
                                       fd_funk_rec_prepare_t *   prepare_out ) {
  memset( prepare_out, 0, sizeof(fd_funk_rec_prepare_t) );

  fd_accdb_rw_t rw[1];
  if( FD_UNLIKELY( !fd_accdb_modify_prepare( accdb, rw, xid, pubkey->uc, min_data_sz, do_create ) ) ) {
    return NULL;
  }

  if( FD_UNLIKELY( !fd_txn_account_join( fd_txn_account_new(
        acct,
        pubkey,
        rw->meta,
        1 ), fd_funk_wksp( accdb->funk ) ) ) ) {
    FD_LOG_CRIT(( "Failed to join txn account" ));
  }

  /* HACKY: Convert accdb_rw writable reference into txn_account.
     In the future, use fd_accdb_modify_publish instead */
  accdb->rw_active--;
  fd_funk_txn_t * txn = accdb->funk->txn_pool->ele + accdb->tip_txn_idx;
  if( FD_UNLIKELY( !fd_funk_txn_xid_eq( &txn->xid, xid ) ) ) FD_LOG_CRIT(( "accdb_user corrupt: not joined to the expected transaction" ));
  if( !rw->published ) {
    *prepare_out = (fd_funk_rec_prepare_t) {
      .rec          = rw->rec,
      .rec_head_idx = &txn->rec_head_idx,
      .rec_tail_idx = &txn->rec_tail_idx
    };
  } else {
    memset( prepare_out, 0, sizeof(fd_funk_rec_prepare_t) );
  }

  return rw->meta;
}

void
fd_txn_account_mutable_fini( fd_txn_account_t *      acct,
                             fd_accdb_user_t *       accdb,
                             fd_funk_rec_prepare_t * prepare ) {
  fd_funk_rec_key_t key = fd_funk_acc_key( acct->pubkey );

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

    /* Crashes the app if this key already exists in funk (conflicting
       write) */
    fd_funk_rec_publish( accdb->funk, prepare );
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
  return (fd_pubkey_t const *)acct->meta->owner;
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
  return !!acct->meta->executable;
}

ulong
fd_txn_account_get_lamports( fd_txn_account_t const * acct ) {
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  return acct->meta->lamports;
}

ulong
fd_txn_account_get_rent_epoch( fd_txn_account_t const * acct ) {
  (void)acct;
  return ULONG_MAX;
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
  acct->meta->executable = !!is_executable;
}

void
fd_txn_account_set_owner( fd_txn_account_t * acct, fd_pubkey_t const * owner ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  fd_memcpy( acct->meta->owner, owner, sizeof(fd_pubkey_t) );
}

void
fd_txn_account_set_lamports( fd_txn_account_t * acct, ulong lamports ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->lamports = lamports;
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
fd_txn_account_set_data( fd_txn_account_t * acct,
                         void const *       data,
                         ulong              data_sz ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  acct->meta->dlen = (uint)data_sz;
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
  acct->meta->dlen = (uint)data_len;
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
fd_txn_account_clear_owner( fd_txn_account_t * acct ) {
  if( FD_UNLIKELY( !acct->is_mutable ) ) {
    FD_LOG_CRIT(( "account is not mutable" ));
  }
  if( FD_UNLIKELY( !acct->meta ) ) {
    FD_LOG_CRIT(( "account is not setup" ));
  }
  fd_memset( acct->meta->owner, 0, sizeof(fd_pubkey_t) );
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

  acct->meta->dlen = (uint)dlen;
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

fd_solana_account_meta_t
fd_txn_account_get_solana_meta( fd_txn_account_t const * acct ) {
  fd_solana_account_meta_t meta = {
    .lamports   = acct->meta->lamports,
    .rent_epoch = ULONG_MAX,
    .executable = acct->meta->executable,
  };
  memcpy( meta.owner, acct->meta->owner, sizeof(fd_pubkey_t) );
  return meta;
}
