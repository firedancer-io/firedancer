#include "fd_acc_mgr.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../funk/fd_funk.h"

fd_account_meta_t const *
fd_funk_get_acc_meta_readonly( fd_funk_t const *         funk,
                               fd_funk_txn_xid_t const * xid,
                               fd_pubkey_t const *       pubkey,
                               fd_funk_rec_t const **    orec,
                               int *                     opt_err,
                               fd_funk_txn_t const **    txn_out ) {
  fd_funk_rec_key_t id = fd_funk_acc_key( pubkey );

  /* When we access this pointer later on in the execution pipeline, we assume that
     nothing else will change that account. If the account is writable in the solana txn,
     then we copy the data. If the account is read-only, we do not. This is safe because of
     the read-write locks that the solana transaction holds on the account. */
  for( ; ; ) {

    fd_funk_rec_query_t   query[1];
    fd_funk_txn_t const * dummy_txn_out[1];
    if( !txn_out ) txn_out    = dummy_txn_out;
    fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, xid, &id, txn_out, query );

    if( FD_UNLIKELY( !rec || rec->erase ) )  {
      fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
      return NULL;
    }
    if( NULL != orec )
      *orec = rec;

    void const * raw = fd_funk_val( rec, fd_funk_wksp(funk) );

    fd_account_meta_t const * metadata = fd_type_pun_const( raw );
    if( FD_LIKELY( fd_funk_rec_query_test( query ) == FD_FUNK_SUCCESS ) ) {
      return metadata;
    }

  }

  /* unreachable */
  return NULL;
}

fd_account_meta_t *
fd_funk_get_acc_meta_mutable( fd_funk_t *               funk,
                              fd_funk_txn_xid_t const * xid,
                              fd_pubkey_t const *       pubkey,
                              int                       do_create,
                              ulong                     min_data_sz,
                              fd_funk_rec_t **          opt_out_rec,
                              fd_funk_rec_prepare_t *   out_prepare,
                              int *                     opt_err ) {
  fd_wksp_t *       wksp = fd_funk_wksp(funk);
  fd_funk_rec_key_t id   = fd_funk_acc_key( pubkey );

  fd_funk_rec_query_t query[1];
  fd_funk_rec_t * rec = (fd_funk_rec_t *)fd_funk_rec_query_try( funk, xid, &id, query );

  int funk_err = 0;

  /* the record does not exist in the current funk transaction */
  if( !rec ) {
    /* clones a record from an ancestor transaction */
    rec = fd_funk_rec_clone( funk, xid, &id, out_prepare, &funk_err );

    if( rec == NULL ) {
      /* the record does not exist at all */
      if( FD_LIKELY( funk_err==FD_FUNK_ERR_KEY ) ) {
        /* create a new record */
        if( do_create ) {
          rec = fd_funk_rec_prepare( funk, xid, &id, out_prepare, &funk_err );
          if( rec == NULL ) {
            /* Irrecoverable funky internal error [[noreturn]] */
            FD_LOG_ERR(( "fd_funk_rec_write_prepare(%s) failed (%i-%s)", FD_BASE58_ENC_32_ALLOCA( pubkey->key ), funk_err, fd_funk_strerror( funk_err ) ));
          }
        } else {
          fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
          return NULL;
        }
      } else {
        /* Irrecoverable funky internal error [[noreturn]] */
        FD_LOG_ERR(( "fd_funk_rec_write_prepare(%s) failed (%i-%s)", FD_BASE58_ENC_32_ALLOCA( pubkey->key ), funk_err, fd_funk_strerror( funk_err ) ));
      }
    }
  }

  ulong sz = sizeof(fd_account_meta_t)+min_data_sz;
  void * val;
  if( fd_funk_val_sz( rec ) < sz ) {
    val = fd_funk_val_truncate(
        rec,
        fd_funk_alloc( funk ),
        wksp,
        0UL,
        sz,
        &funk_err );
    if( FD_UNLIKELY( !val ) ) FD_LOG_CRIT(( "fd_funk_val_truncate(sz=%lu) failed (%i-%s)", sz, funk_err, fd_funk_strerror( funk_err ) ));
  } else {
    val = fd_funk_val( rec, wksp );
  }

  if (NULL != opt_out_rec) {
    *opt_out_rec = rec;
  }

  fd_account_meta_t * meta = val;
  if( do_create && meta->lamports==0UL ) {
    fd_account_meta_init( meta );
  }

  return meta;
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
  default:
    return "unknown";
  }
}
