/* fd_sysvar_cache_db.c contains database interactions between the
   sysvar cache and the account database. */

#include "fd_sysvar.h"
#include "fd_sysvar_cache.h"
#include "fd_sysvar_cache_private.h"

static int
sysvar_data_fill( fd_sysvar_cache_t *       cache,
                  fd_accdb_user_t *         accdb,
                  fd_funk_txn_xid_t const * xid,
                  ulong                     idx,
                  int                       log_fails ) {
  fd_sysvar_pos_t const * pos  = &fd_sysvar_pos_tbl[ idx ];
  fd_pubkey_t const *     key  = &fd_sysvar_key_tbl[ idx ];
  fd_sysvar_desc_t *      desc = &cache->desc      [ idx ];

  /* Read account from database */
  fd_accdb_ro_t ro[1];
  if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, ro, xid, key ) ) ) {
    if( log_fails ) FD_LOG_DEBUG(( "Sysvar %s not found", pos->name ));
    return 0;
  }

  /* Work around instruction fuzzer quirk */
  if( FD_UNLIKELY( fd_accdb_ref_lamports( ro )==0 ) ) {
    if( log_fails ) FD_LOG_WARNING(( "Skipping sysvar %s: zero balance", pos->name ));
    return 0;
  }

  /* Fill data cache entry */
  ulong data_sz = fd_accdb_ref_data_sz( ro );
  /* */ data_sz = fd_ulong_min( data_sz, pos->data_max );
  uchar * data = (uchar *)cache+pos->data_off;
  fd_memcpy( data, fd_accdb_ref_data_const( ro ), data_sz );
  desc->data_sz = (uint)data_sz;

  /* Recover object cache entry from data cache entry */
  return fd_sysvar_obj_restore( cache, desc, pos );
}

static int
sysvar_data_fill_from_metas( fd_sysvar_cache_t *         cache,
                             fd_pubkey_t const *         pubkeys,
                             fd_account_meta_t * const * metas,
                             ulong                       acc_cnt,
                             ulong                       idx ) {
  fd_sysvar_pos_t const * pos  = &fd_sysvar_pos_tbl[ idx ];
  fd_pubkey_t const *     key  = &fd_sysvar_key_tbl[ idx ];
  fd_sysvar_desc_t *      desc = &cache->desc      [ idx ];

  for( ulong i=0UL; i<acc_cnt; i++ ) {
    if( !memcmp( &pubkeys[i], key, sizeof(fd_pubkey_t) ) ) {
      if( metas[i]->lamports==0UL ) return 0;
      ulong data_sz = metas[i]->dlen;
      data_sz = fd_ulong_min( data_sz, pos->data_max );
      uchar * data = (uchar *)cache+pos->data_off;
      fd_memcpy( data, fd_account_data( metas[i] ), data_sz );
      desc->data_sz = (uint)data_sz;

      /* Recover object cache entry from data cache entry */
      return fd_sysvar_obj_restore( cache, desc, pos );
    }
  }
  return 0;
}

static int
fd_sysvar_cache_restore1( fd_bank_t *               bank,
                          fd_accdb_user_t *         accdb,
                          fd_funk_txn_xid_t const * xid,
                          int                       log_fails ) {
  fd_sysvar_cache_t * cache = fd_sysvar_cache_join( fd_sysvar_cache_new(
      fd_bank_sysvar_cache_modify( bank ) ) );

  int saw_err = 0;
  for( ulong i=0UL; i<FD_SYSVAR_CACHE_ENTRY_CNT; i++ ) {
    int err = sysvar_data_fill( cache, accdb, xid, i, log_fails );
    if( err ) saw_err = 1;
  }

  fd_sysvar_cache_leave( cache );

  return !saw_err;
}

int
fd_sysvar_cache_restore( fd_bank_t *               bank,
                         fd_accdb_user_t *         accdb,
                         fd_funk_txn_xid_t const * xid ) {
  return fd_sysvar_cache_restore1( bank, accdb, xid, 1 );
}

void
fd_sysvar_cache_restore_fuzz( fd_bank_t *               bank,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid ) {
  (void)fd_sysvar_cache_restore1( bank, accdb, xid, 0 );
}

void
fd_sysvar_cache_restore_from_metas( fd_bank_t *                 bank,
                                    fd_pubkey_t const *         pubkeys,
                                    fd_account_meta_t * const * metas,
                                    ulong                       acc_cnt ) {
  fd_sysvar_cache_t * cache = fd_sysvar_cache_join( fd_sysvar_cache_new(
    fd_bank_sysvar_cache_modify( bank ) ) );

  for( ulong i=0UL; i<FD_SYSVAR_CACHE_ENTRY_CNT; i++ ) {
    sysvar_data_fill_from_metas( cache, pubkeys, metas, acc_cnt, i );
  }

  fd_sysvar_cache_leave( cache );
}
