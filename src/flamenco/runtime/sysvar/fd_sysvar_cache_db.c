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
  fd_acc_t acc = fd_accdb_read_one( accdb, fork, key->uc );
  if( FD_UNLIKELY( !acc.lamports ) ) {
    if( log_fails ) FD_LOG_DEBUG(( "Sysvar %s not found", pos->name ));
    fd_accdb_unread_one( accdb, &acc );
    return 0;
  }

  /* Fill data cache acc */
  ulong data_sz = fd_ulong_min( acc.data_len, pos->data_max );
  uchar * data = (uchar *)cache+pos->data_off;
  fd_memcpy( data, acc.data, data_sz );
  desc->data_sz = (uint)data_sz;
  fd_accdb_unread_one( accdb, &acc );

  /* Recover object cache acc from data cache acc */
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
fd_sysvar_cache_restore_one( fd_sysvar_cache_t * cache,
                             fd_pubkey_t const * pubkey,
                             ulong               lamports,
                             uchar const *       acc_data,
                             ulong               acc_data_len ) {
  ulong idx;
  for( idx=0UL; idx<FD_SYSVAR_CACHE_ENTRY_CNT; idx++ ) {
    if( 0==memcmp( pubkey, fd_sysvar_key_tbl[ idx ].uc, sizeof(fd_pubkey_t) ) ) break;
  }
  if( FD_UNLIKELY( idx==FD_SYSVAR_CACHE_ENTRY_CNT ) ) return;
  if( FD_UNLIKELY( !lamports ) ) return;

  fd_sysvar_pos_t const * pos  = &fd_sysvar_pos_tbl[ idx ];
  fd_sysvar_desc_t *      desc = &cache->desc      [ idx ];

  ulong data_sz = fd_ulong_min( acc_data_len, pos->data_max );
  uchar * data    = (uchar *)cache+pos->data_off;
  fd_memcpy( data, acc_data, data_sz );
  desc->data_sz = (uint)data_sz;

  /* Recover object cache acc from data cache acc */
  fd_sysvar_obj_restore( cache, desc, pos );
}
