#include "fd_txn_account.h"
#include "fd_acc_mgr.h"

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
  ret->starting_dlen     = ULONG_MAX;
  ret->starting_lamports = ULONG_MAX;

  FD_COMPILER_MFENCE();
  ret->magic = FD_TXN_ACCOUNT_MAGIC;
  FD_COMPILER_MFENCE();

  return ret;
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
fd_txn_account_make_readonly( fd_txn_account_t * acct, void * buf ) {
  ulong dlen           = ( acct->const_meta != NULL ) ? acct->const_meta->dlen : 0;
  uchar * new_raw_data = fd_txn_account_init_data( acct, buf );

  acct->orig_meta = acct->const_meta = (fd_account_meta_t *)new_raw_data;
  acct->orig_data = acct->const_data = new_raw_data + sizeof(fd_account_meta_t);
  ((fd_account_meta_t *)new_raw_data)->dlen = dlen;

  return acct;
}

fd_txn_account_t *
fd_txn_account_make_mutable( fd_txn_account_t * acct, void * buf ) {
  if( FD_UNLIKELY( acct->data != NULL ) ) FD_LOG_ERR(( "borrowed account is already mutable" ));

  ulong   dlen         = ( acct->const_meta != NULL ) ? acct->const_meta->dlen : 0;
  uchar * new_raw_data = fd_txn_account_init_data( acct, buf );

  acct->const_meta = acct->meta = (fd_account_meta_t *)new_raw_data;
  acct->const_data = acct->data = new_raw_data + sizeof(fd_account_meta_t);
  acct->meta->dlen = dlen;

  return acct;
}

void *
fd_txn_account_restore( fd_txn_account_t * acct ) {
  fd_account_meta_t * meta       = acct->meta;
  uint                is_changed = meta != acct->orig_meta;

  acct->const_meta = acct->orig_meta;
  acct->const_data = acct->orig_data;
  acct->const_rec  = acct->orig_rec;

  if( is_changed ) {
    return meta;
  }

  return NULL;
}

/* Factory constructor impl */
int
fd_txn_account_create_from_funk( fd_txn_account_t *  acct_ptr,
                                 fd_pubkey_t const * acc_pubkey,
                                 fd_acc_mgr_t *      acc_mgr,
                                 fd_funk_txn_t *     funk_txn ) {
  fd_txn_account_init( acct_ptr );

  return fd_acc_mgr_view( acc_mgr, funk_txn, acc_pubkey, acct_ptr );
}
