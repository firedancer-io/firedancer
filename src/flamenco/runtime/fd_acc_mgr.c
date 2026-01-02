#include "fd_acc_mgr.h"
#include "../../funk/fd_funk.h"

fd_account_meta_t const *
fd_funk_get_acc_meta_readonly( fd_funk_t const *         funk,
                               fd_funk_txn_xid_t const * xid,
                               fd_pubkey_t const *       pubkey,
                               fd_funk_rec_t const **    orec,
                               int *                     opt_err,
                               fd_funk_txn_xid_t *       out_xid ) {
  fd_funk_rec_key_t id = fd_funk_acc_key( pubkey );

  /* When we access this pointer later on in the execution pipeline, we assume that
     nothing else will change that account. If the account is writable in the solana txn,
     then we copy the data. If the account is read-only, we do not. This is safe because of
     the read-write locks that the solana transaction holds on the account. */
  for( ; ; ) {

    fd_funk_rec_query_t   query[1];
    fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, xid, &id, out_xid, query );

    if( FD_UNLIKELY( !rec ) )  {
      fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
      return NULL;
    }
    if( NULL != orec )
      *orec = rec;

    void const * raw = fd_funk_val( rec, fd_funk_wksp( funk ) );

    fd_account_meta_t const * metadata = fd_type_pun_const( raw );
    fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_SUCCESS );
    return metadata;

  }

  /* unreachable */
  return NULL;
}

FD_FN_CONST char const *
fd_acc_mgr_strerror( int err ) {
  switch( err ) {
  case FD_ACC_MGR_SUCCESS:
    return "success";
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    return "unknown account";
  default:
    return "unknown";
  }
}
