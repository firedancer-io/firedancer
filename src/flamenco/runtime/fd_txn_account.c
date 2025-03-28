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
fd_txn_account_setup_sentinel_meta( fd_txn_account_t * acct,
                                    fd_spad_t *        spad,
                                    fd_wksp_t *        spad_wksp ) {
  fd_account_meta_t const * meta = acct->const_meta ? acct->const_meta : acct->meta;
  if( meta==NULL ) {
    fd_account_meta_t * sentinel = fd_spad_alloc( spad, FD_ACCOUNT_REC_ALIGN, sizeof(fd_account_meta_t) );
    fd_memset( sentinel, 0, sizeof(fd_account_meta_t) );
    sentinel->magic                = FD_ACCOUNT_META_MAGIC;
    sentinel->info.rent_epoch      = ULONG_MAX;
    acct->const_meta        = sentinel;
    acct->starting_lamports = 0UL;
    acct->starting_dlen     = 0UL;
    acct->meta_gaddr        = fd_wksp_gaddr( spad_wksp, sentinel );
  }
}


void
fd_txn_account_setup_readonly( fd_txn_account_t *        acct,
                               fd_pubkey_t const *       pubkey,
                               fd_account_meta_t const * meta ) {
  fd_memcpy(acct->pubkey, pubkey, sizeof(fd_pubkey_t));

  acct->const_meta = meta;
  acct->const_data = (uchar const *)meta + meta->hlen;

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

  fd_txn_account_setup_common( acct );
}

/* Operators impl */

void
fd_txn_account_resize( fd_txn_account_t * acct,
                       ulong              dlen ) {
  /* Because the memory for an account is preallocated for the transaction
     up to the max account size, we only need to zero out bytes (for the case
     where the account grew) and update the account dlen. */
  ulong old_sz    = acct->meta->dlen;
  ulong new_sz    = dlen;
  ulong memset_sz = fd_ulong_sat_sub( new_sz, old_sz );
  fd_memset( acct->data+old_sz, 0, memset_sz );

  acct->meta->dlen = dlen;
}

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

  acct->meta_gaddr = fd_wksp_gaddr( wksp, acct->meta );
  acct->data_gaddr = fd_wksp_gaddr( wksp, acct->data );

  return acct;
}

/* Factory constructors from funk */

int
fd_txn_account_init_from_funk_readonly( fd_txn_account_t *    acct,
                                        fd_pubkey_t const *   pubkey,
                                        fd_funk_t *           funk,
                                        fd_funk_txn_t const * funk_txn ) {
  fd_txn_account_init( acct );

  int err = FD_FUNK_ACC_MGR_SUCCESS;
  fd_account_meta_t const * meta = fd_funk_acc_mgr_get_acc_meta_readonly( funk,
                                                                          funk_txn,
                                                                          pubkey,
                                                                          &acct->const_rec,
                                                                          &err,
                                                                          NULL );

  if( FD_UNLIKELY( err!=FD_FUNK_ACC_MGR_SUCCESS ) ) {
    return err;
  }

  if( FD_UNLIKELY( !fd_account_meta_exists( meta ) ) ) {
    return FD_FUNK_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  if( FD_UNLIKELY( acct->magic!=FD_TXN_ACCOUNT_MAGIC ) ) {
    return FD_FUNK_ACC_MGR_ERR_WRONG_MAGIC;
  }

  fd_wksp_t * funk_wksp = fd_funk_wksp( funk );
  acct->meta_gaddr   = fd_wksp_gaddr( funk_wksp, acct->const_meta );
  acct->data_gaddr   = fd_wksp_gaddr( funk_wksp, acct->const_data );

  fd_txn_account_setup_readonly( acct, pubkey, meta );

  return FD_FUNK_ACC_MGR_SUCCESS;
}

int
fd_txn_account_init_from_funk_mutable( fd_txn_account_t *  acct,
                                       fd_pubkey_t const * pubkey,
                                       fd_funk_t *         funk,
                                       fd_funk_txn_t *     funk_txn,
                                       int                 do_create,
                                       ulong               min_data_sz ) {
  /* TODO: prevent executor tile from calling this function gracefully */

  fd_txn_account_init( acct );

  int err = FD_FUNK_ACC_MGR_SUCCESS;
  fd_account_meta_t * meta = fd_funk_acc_mgr_get_acc_meta_mutable( funk,
                                                                   funk_txn,
                                                                   pubkey,
                                                                   do_create,
                                                                   min_data_sz,
                                                                   acct->const_rec,
                                                                   &acct->rec,
                                                                   &err );
  
  if( FD_UNLIKELY( !meta ) ) {
    return err;
  }

  if( FD_UNLIKELY( meta->magic!=FD_ACCOUNT_META_MAGIC ) ) {
    return FD_FUNK_ACC_MGR_ERR_WRONG_MAGIC;
  }

  fd_txn_account_setup_mutable( acct, pubkey, meta );

  return FD_FUNK_ACC_MGR_SUCCESS;
}

/* Funk save function impl */

int
fd_txn_account_save( fd_funk_t *        funk,
                     fd_txn_account_t * acct ) {
  if( acct->meta == NULL || acct->rec == NULL ) {
    /* The meta is NULL so the account is not writable. */
    return FD_FUNK_ACC_MGR_ERR_WRITE_FAILED;
  }

  fd_wksp_t * wksp = fd_funk_wksp( funk );
  ulong reclen = sizeof(fd_account_meta_t)+acct->const_meta->dlen;
  uchar * raw = fd_funk_val( acct->rec, wksp );
  fd_memcpy( raw, acct->meta, reclen );

  return FD_FUNK_ACC_MGR_SUCCESS;
}
