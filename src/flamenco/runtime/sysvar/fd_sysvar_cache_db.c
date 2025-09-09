/* fd_sysvar_cache_db.c contains database interactions between the
   sysvar cache and the account database. */

#include "fd_sysvar.h"
#include "fd_sysvar_cache.h"
#include "fd_sysvar_cache_private.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../fd_txn_account.h"
#include "../../accdb/fd_accdb_sync.h"
#include <errno.h>

static int
sysvar_data_fill( fd_sysvar_cache_t *  cache,
                  fd_exec_slot_ctx_t * slot_ctx,
                  ulong                idx,
                  int                  log_fails ) {
  fd_sysvar_pos_t const * pos  = &fd_sysvar_pos_tbl[ idx ];
  fd_pubkey_t const *     key  = &fd_sysvar_key_tbl[ idx ];
  fd_sysvar_desc_t *      desc = &cache->desc      [ idx ];

  /* Read account from database */
  int db_err = FD_ACCDB_READ_BEGIN( slot_ctx->accdb, key, rec ) {

    /* Work around instruction fuzzer quirk */
    if( FD_UNLIKELY( fd_accdb_ref_lamports( rec )==0 ) ) {
      if( log_fails ) FD_LOG_WARNING(( "Skipping sysvar %s: zero balance", pos->name ));
      return 0;
    }

    /* Fill data cache entry */
    ulong data_sz = fd_accdb_ref_data_sz( rec );
    data_sz = fd_ulong_min( data_sz, pos->data_max );
    uchar * data = (uchar *)cache+pos->data_off;
    fd_memcpy( data, fd_accdb_ref_data_const( rec ), data_sz );
    desc->data_sz = (uint)data_sz;

  }
  FD_ACCDB_READ_END;
  if( db_err==FD_ACCDB_ERR_KEY ) {
    if( log_fails ) FD_LOG_DEBUG(( "Sysvar %s not found", pos->name ));
    return 0;
  } else if( FD_UNLIKELY( db_err!=FD_ACCDB_SUCCESS ) ) {
    FD_LOG_ERR(( "fd_txn_account_init_from_funk_readonly failed: %i", db_err ));
    return EIO;
  }

  /* Recover object cache entry from data cache entry */
  return fd_sysvar_obj_restore( cache, desc, pos, log_fails );
}

static int
fd_sysvar_cache_restore1( fd_exec_slot_ctx_t * slot_ctx,
                          int                  log_fails ) {
  fd_sysvar_cache_t * cache = fd_sysvar_cache_join( fd_sysvar_cache_new(
      fd_bank_sysvar_cache_modify( slot_ctx->bank ) ) );

  int saw_err = 0;
  for( ulong i=0UL; i<FD_SYSVAR_CACHE_ENTRY_CNT; i++ ) {
    int err = sysvar_data_fill( cache, slot_ctx, i, log_fails );
    if( err ) saw_err = 1;
  }

  fd_sysvar_cache_leave( cache );

  return !saw_err;
}

int
fd_sysvar_cache_restore( fd_exec_slot_ctx_t * slot_ctx ) {
  return fd_sysvar_cache_restore1( slot_ctx, 1 );
}

void
fd_sysvar_cache_restore_fuzz( fd_exec_slot_ctx_t * slot_ctx ) {
  (void)fd_sysvar_cache_restore1( slot_ctx, 0 );
}
