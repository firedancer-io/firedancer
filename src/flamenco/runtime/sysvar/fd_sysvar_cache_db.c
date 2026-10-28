/* fd_sysvar_cache_db.c contains database interactions between the
   sysvar cache and the account database. */

#include "fd_sysvar_cache_private.h"

static int
sysvar_data_fill( fd_sysvar_cache_t * cache,
                  ulong               idx,
                  ulong               lamports,
                  uchar const *       acc_data,
                  ulong               acc_data_len,
                  int                 log_fails ) {
  fd_sysvar_pos_t const * pos  = &fd_sysvar_pos_tbl[ idx ];
  fd_sysvar_desc_t *      desc = &cache->desc      [ idx ];

  if( FD_UNLIKELY( !lamports ) ) {
    if( log_fails ) FD_LOG_DEBUG(( "Sysvar %s not found", pos->name ));
    return 0;
  }

  /* Fill data cache acc */
  ulong data_sz = fd_ulong_min( acc_data_len, pos->data_max );
  uchar * data = (uchar *)cache+pos->data_off;
  fd_memcpy( data, acc_data, data_sz );
  desc->data_sz = (uint)data_sz;

  /* Recover object cache acc from data cache acc */
  return fd_sysvar_obj_restore( cache, desc, pos );
}

static int
fd_sysvar_cache_restore1( fd_sysvar_cache_t * mem,
                          fd_accdb_t *        accdb,
                          fd_accdb_fork_id_t  fork_id,
                          uchar *             nocache_buf,
                          int                 log_fails ) {
  fd_sysvar_cache_t * cache = fd_sysvar_cache_join( fd_sysvar_cache_new( mem ) );

  int saw_err = 0;
  for( ulong i=0UL; i<FD_SYSVAR_CACHE_ENTRY_CNT; i++ ) {
    uchar const * key = fd_sysvar_key_tbl[ i ].uc;
    int err;
    if( nocache_buf ) {
      ulong lamports;
      int   executable;
      uchar owner[ 32UL ];
      ulong data_len;
      fd_accdb_read_one_nocache( accdb, fork_id, key, &lamports, &executable, owner, nocache_buf, &data_len );
      err = sysvar_data_fill( cache, i, lamports, nocache_buf, lamports ? data_len : 0UL, log_fails );
    } else {
      fd_acc_t acc = fd_accdb_read_one( accdb, fork_id, key );
      err = sysvar_data_fill( cache, i, acc.lamports, acc.data, acc.data_len, log_fails );
      fd_accdb_unread_one( accdb, &acc );
    }
    if( err ) saw_err = 1;
  }

  fd_sysvar_cache_leave( cache );

  return !saw_err;
}

int
fd_sysvar_cache_restore( fd_sysvar_cache_t * cache,
                         fd_accdb_t *        accdb,
                         fd_accdb_fork_id_t  fork_id ) {
  return fd_sysvar_cache_restore1( cache, accdb, fork_id, NULL, 1 );
}

int
fd_sysvar_cache_restore_nocache( fd_sysvar_cache_t * cache,
                                 fd_accdb_t *        accdb,
                                 fd_accdb_fork_id_t  fork_id,
                                 uchar *             buf ) {
  return fd_sysvar_cache_restore1( cache, accdb, fork_id, buf, 1 );
}

void
fd_sysvar_cache_restore_fuzz( fd_sysvar_cache_t * cache,
                              fd_accdb_t *        accdb,
                              fd_accdb_fork_id_t  fork_id ) {
  (void)fd_sysvar_cache_restore1( cache, accdb, fork_id, NULL, 0 );
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
  (void)sysvar_data_fill( cache, idx, lamports, acc_data, acc_data_len, 0 );
}
