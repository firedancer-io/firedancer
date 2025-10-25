#include "fd_acc_mgr.h"

fd_funk_rec_t const *
fd_funk_get_acc_meta_readonly( fd_funk_t const *         funk,
                               fd_funk_txn_xid_t const * xid,
                               fd_pubkey_t const *       pubkey,
                               int *                     opt_err,
                               fd_funk_txn_xid_t *       out_xid ) {
  fd_funk_rec_key_t id = fd_funk_acc_key( pubkey );

  fd_funk_rec_query_t   query[1];
  fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, xid, &id, out_xid, query );

  if( FD_UNLIKELY( !rec ) )  {
    fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
    return NULL;
  }

  fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_SUCCESS );
  return rec;
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
