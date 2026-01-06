#include "fd_acc_mgr.h"
#include "../../funk/fd_funk.h"

fd_account_meta_t const *
fd_funk_get_acc_meta_readonly( fd_funk_t const *         funk,
                               fd_funk_txn_xid_t const * xid,
                               fd_pubkey_t const *       pubkey,
                               fd_funk_txn_xid_t *       out_xid ) {
  fd_funk_rec_key_t id = fd_funk_acc_key( pubkey );

  /* When we access this pointer later on in the execution pipeline, we assume that
     nothing else will change that account. If the account is writable in the solana txn,
     then we copy the data. If the account is read-only, we do not. This is safe because of
     the read-write locks that the solana transaction holds on the account. */

  for(;;) {

    /* Locate the account record */

    fd_funk_rec_query_t   query[1];
    fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, xid, &id, out_xid, query );
    if( FD_UNLIKELY( !rec ) )  {
      return NULL;
    }

    /* Read account balance */

    void const *              raw      = fd_funk_val( rec, fd_funk_wksp( funk ) );
    fd_account_meta_t const * metadata = fd_type_pun_const( raw );
    ulong const               lamports = metadata->lamports;
    if( FD_UNLIKELY( !lamports ) ) {
      /* This account is awaiting deletion */
      return NULL;
    }

    /* Recover from overruns (e.g. account rooted) */

    if( FD_LIKELY( fd_funk_rec_map_query_test( query )==FD_MAP_SUCCESS ) ) {
      return metadata;
    }

  }
}
