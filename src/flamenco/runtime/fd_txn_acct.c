#include "fd_txn_acct.h"
#include "fd_acc_mgr.h"

fd_txn_acct_t *
fd_txn_acct_init( void * ptr ) {
  if( FD_UNLIKELY( !ptr ) ) {
    FD_LOG_WARNING(( "NULL ptr" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ptr, alignof(fd_txn_acct_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned ptr" ));
    return NULL;
  }

  memset(ptr, 0, FD_TXN_ACCT_FOOTPRINT);

  fd_txn_acct_t * ret = (fd_txn_acct_t *)ptr;
  ret->starting_dlen     = ULONG_MAX;
  ret->starting_lamports = ULONG_MAX;
  ret->account_found     = 1;

  FD_COMPILER_MFENCE();
  ret->magic = FD_TXN_ACCT_MAGIC;
  FD_COMPILER_MFENCE();

  return ret;
}

/* Operators impl */
uchar *
fd_txn_acct_init_data( fd_txn_acct_t * acct, void * buf ) {
  /* Assumes that buf is pointing to account data */
  uchar * new_raw_data = (uchar *)buf;
  ulong dlen = ( acct->const_meta != NULL ) ? acct->const_meta->dlen : 0;

  if( acct->const_meta != NULL ) {
    fd_memcpy( new_raw_data, (uchar *)acct->const_meta, sizeof(fd_txn_acct_meta_t)+dlen );
  } else {
    /* Account did not exist, set up metadata */
    fd_account_meta_init( (fd_account_meta_t *)new_raw_data );
  }

  return new_raw_data;
}

fd_txn_acct_t *
fd_txn_acct_make_read_only( fd_txn_acct_t * acct, void * buf ) {
  ulong dlen           = ( acct->const_meta != NULL ) ? acct->const_meta->dlen : 0;
  uchar * new_raw_data = fd_txn_acct_init_data( acct, buf );

  acct->orig_meta = acct->const_meta = (fd_account_meta_t *)new_raw_data;
  acct->orig_data = acct->const_data = new_raw_data + sizeof(fd_account_meta_t);
  ((fd_account_meta_t *)new_raw_data)->dlen = dlen;

  return acct;
}

fd_txn_acct_t *
fd_txn_acct_make_mutable( fd_txn_acct_t * acct, void * buf ) {
  FD_TEST_CUSTOM( acct->data == NULL, "borrowed account is already modifiable" );

  ulong dlen           = ( acct->const_meta != NULL ) ? acct->const_meta->dlen : 0;
  uchar * new_raw_data = fd_txn_acct_init_data( acct, buf );

  acct->const_meta = acct->meta = (fd_account_meta_t *)new_raw_data;
  acct->const_data = acct->data = new_raw_data + sizeof(fd_account_meta_t);
  acct->meta->dlen = dlen;

  return acct;
}

void *
fd_txn_acct_restore( fd_txn_acct_t * acct ) {
  fd_account_meta_t * meta = acct->meta;
  uint is_changed = meta != acct->orig_meta;

  acct->const_meta = acct->orig_meta;
  acct->const_data = acct->orig_data;
  acct->const_rec = acct->orig_rec;

  if( is_changed ) {
    return meta;
  }

  return NULL;
}

void *
fd_txn_acct_destroy( fd_txn_acct_t * acct ) {
  return acct->meta;
}

/* Factory constructor impl */
fd_txn_acct_t *
fd_create_txn_acct( fd_txn_acct_t * acct_ptr, fd_pubkey_t * acc_pubkey, fd_exec_txn_ctx_t * txn_ctx ) {
  fd_txn_acct_init( acct_ptr );

  int err                  = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, acc_pubkey, acct_ptr );
  uchar is_unknown_account = err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;

  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS && !is_unknown_account ) ) {
    FD_LOG_ERR(( "fd_acc_mgr_view err=%d", err ));
  }

  memcpy( acct_ptr->pubkey->key, acc_pubkey, sizeof(fd_pubkey_t) );
  return acct_ptr;
}

fd_txn_acct_t
fd_create_txn_acct_decl( fd_pubkey_t * acc_pubkey, fd_exec_txn_ctx_t * txn_ctx ) {
  fd_txn_acct_t acct;
  fd_txn_acct_init( &acct );

  int err                  = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, acc_pubkey, &acct );
  uchar is_unknown_account = err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;

  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS && !is_unknown_account ) ) {
    FD_LOG_ERR(( "fd_acc_mgr_view err=%d", err ));
  }

  memcpy( acct.pubkey->key, acc_pubkey, sizeof(fd_pubkey_t) );
  return acct;
}
