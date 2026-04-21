/* fd_sysvar_cache_db.c contains database interactions between the
   sysvar cache and the account database. */

#include "../fd_bank.h"
#include "fd_sysvar_cache_private.h"

static int
sysvar_data_fill( fd_sysvar_cache_t *       cache,
                  fd_accdb_t *              accdb,
                  fd_accdb_fork_id_t        fork,
                  ulong                     idx,
                  int                       log_fails ) {
  fd_sysvar_pos_t const * pos  = &fd_sysvar_pos_tbl[ idx ];
  fd_pubkey_t const *     key  = &fd_sysvar_key_tbl[ idx ];
  fd_sysvar_desc_t *      desc = &cache->desc      [ idx ];

  /* Read account from database */
  fd_accdb_entry_t entry = fd_accdb_read_one( accdb, fork, key->uc );
  if( FD_UNLIKELY( !entry.lamports ) ) {
    if( log_fails ) FD_LOG_DEBUG(( "Sysvar %s not found", pos->name ));
    return 0;
  }

  /* Fill data cache entry */
  ulong data_sz = fd_ulong_min( entry.data_len, pos->data_max );
  uchar * data = (uchar *)cache+pos->data_off;
  fd_memcpy( data, entry.data, data_sz );
  desc->data_sz = (uint)data_sz;
  fd_accdb_unread_one( accdb, &entry );

  /* Recover object cache entry from data cache entry */
  return fd_sysvar_obj_restore( cache, desc, pos );
}

static int
fd_sysvar_cache_restore1( fd_bank_t *  bank,
                          fd_accdb_t * accdb,
                          int          log_fails ) {
  fd_sysvar_cache_t * cache = fd_sysvar_cache_join( fd_sysvar_cache_new(
      &bank->f.sysvar_cache ) );

  int saw_err = 0;
  for( ulong i=0UL; i<FD_SYSVAR_CACHE_ENTRY_CNT; i++ ) {
    int err = sysvar_data_fill( cache, accdb, bank->accdb_fork_id, i, log_fails );
    if( err ) saw_err = 1;
  }

  fd_sysvar_cache_leave( cache );

  return !saw_err;
}

int
fd_sysvar_cache_restore( fd_bank_t *  bank,
                         fd_accdb_t * accdb ) {
  return fd_sysvar_cache_restore1( bank, accdb, 1 );
}

void
fd_sysvar_cache_restore_fuzz( fd_bank_t *  bank,
                              fd_accdb_t * accdb ) {
  (void)fd_sysvar_cache_restore1( bank, accdb, 0 );
}

void
fd_sysvar_cache_restore_from_ref( fd_sysvar_cache_t *      cache,
                                  fd_accdb_entry_t const * entry ) {
  ulong idx;
  for( idx=0UL; idx<FD_SYSVAR_CACHE_ENTRY_CNT; idx++ ) {
    if( 0==memcmp( entry->pubkey, fd_sysvar_key_tbl[ idx ].uc, sizeof(fd_pubkey_t) ) ) break;
  }
  if( FD_UNLIKELY( idx==FD_SYSVAR_CACHE_ENTRY_CNT ) ) return;
  if( FD_UNLIKELY( !entry->lamports ) ) return;

  fd_sysvar_pos_t const * pos  = &fd_sysvar_pos_tbl[ idx ];
  fd_sysvar_desc_t *      desc = &cache->desc      [ idx ];

  ulong data_sz = fd_ulong_min( entry->data_len, pos->data_max );
  uchar * data    = (uchar *)cache+pos->data_off;
  fd_memcpy( data, entry->data, data_sz );
  desc->data_sz = (uint)data_sz;

  /* Recover object cache entry from data cache entry */
  fd_sysvar_obj_restore( cache, desc, pos );
}
