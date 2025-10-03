/* fd_sysvar_cache_db.c contains database interactions between the
   sysvar cache and the account database. */

#include "fd_sysvar.h"
#include "fd_sysvar_cache.h"
#include "fd_sysvar_cache_private.h"
#include "../fd_txn_account.h"
#include "../fd_acc_mgr.h"
#include <errno.h>

static int
sysvar_data_fill( fd_sysvar_cache_t *       cache,
                  fd_funk_t *               funk,
                  fd_funk_txn_xid_t const * xid,
                  ulong                     idx,
                  int                       log_fails ) {
  fd_sysvar_pos_t const * pos  = &fd_sysvar_pos_tbl[ idx ];
  fd_pubkey_t const *     key  = &fd_sysvar_key_tbl[ idx ];
  fd_sysvar_desc_t *      desc = &cache->desc      [ idx ];

  /* Read account from database */
  FD_TXN_ACCOUNT_DECL( rec );
  int err = fd_txn_account_init_from_funk_readonly( rec, key, funk, xid );
  if( err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
    if( log_fails ) FD_LOG_DEBUG(( "Sysvar %s not found", pos->name ));
    return 0;
  } else if( err!=FD_ACC_MGR_SUCCESS ) {
    FD_LOG_ERR(( "fd_txn_account_init_from_funk_readonly failed: %i", err ));
    return EIO;
  }

  /* Work around instruction fuzzer quirk */
  if( FD_UNLIKELY( fd_txn_account_get_lamports( rec )==0 ) ) {
    if( log_fails ) FD_LOG_WARNING(( "Skipping sysvar %s: zero balance", pos->name ));
    return 0;
  }

  /* Fill data cache entry */
  ulong data_sz = fd_txn_account_get_data_len( rec );
  data_sz = fd_ulong_min( data_sz, pos->data_max );
  uchar * data = (uchar *)cache+pos->data_off;
  fd_memcpy( data, fd_txn_account_get_data( rec ), data_sz );
  desc->data_sz = (uint)data_sz;

  /* Recover object cache entry from data cache entry */
  return fd_sysvar_obj_restore( cache, desc, pos );
}

static int
fd_sysvar_cache_restore1( fd_bank_t *               bank,
                          fd_funk_t *               funk,
                          fd_funk_txn_xid_t const * xid,
                          int                       log_fails ) {
  fd_sysvar_cache_t * cache = fd_sysvar_cache_join( fd_sysvar_cache_new(
      fd_bank_sysvar_cache_modify( bank ) ) );

  int saw_err = 0;
  for( ulong i=0UL; i<FD_SYSVAR_CACHE_ENTRY_CNT; i++ ) {
    int err = sysvar_data_fill( cache, funk, xid, i, log_fails );
    if( err ) saw_err = 1;
  }

  fd_sysvar_cache_leave( cache );

  return !saw_err;
}

int
fd_sysvar_cache_restore( fd_bank_t *               bank,
                         fd_funk_t *               funk,
                         fd_funk_txn_xid_t const * xid ) {
  return fd_sysvar_cache_restore1( bank, funk, xid, 1 );
}

void
fd_sysvar_cache_restore_fuzz( fd_bank_t *               bank,
                              fd_funk_t *               funk,
                              fd_funk_txn_xid_t const * xid ) {
  (void)fd_sysvar_cache_restore1( bank, funk, xid, 0 );
}
