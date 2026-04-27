#include "fd_sysvar_stake_history.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_accdb_svm.h"

void
fd_sysvar_stake_history_init( fd_bank_t *               bank,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid,
                              fd_capture_ctx_t *        capture_ctx ) {
  uchar data[ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ];
  fd_memset( data, 0, sizeof(data) );
  fd_sysvar_account_update( bank, accdb, xid, capture_ctx, &fd_sysvar_stake_history_id, data, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
}

void
fd_sysvar_stake_history_update( fd_bank_t *                      bank,
                                fd_accdb_user_t *                accdb,
                                fd_funk_txn_xid_t const *        xid,
                                fd_capture_ctx_t *               capture_ctx,
                                fd_stake_history_entry_t const * entry ) {

  fd_accdb_rw_t rw[1];
  fd_accdb_svm_update_t update[1];
  if( FD_UNLIKELY( !fd_accdb_svm_open_rw( accdb, bank, xid, rw, update, &fd_sysvar_stake_history_id, 0UL, 0 ) ) ) {
    FD_LOG_ERR(( "state is missing stake history sysvar" ));
  }
  if( FD_UNLIKELY( 0!=memcmp( fd_accdb_ref_owner( rw->ro ), &fd_sysvar_owner_id, sizeof(fd_pubkey_t) ) ) ) {
    FD_LOG_ERR(( "stake history sysvar not owned by sysvar owner" ));
  }
  uchar * data    = fd_accdb_ref_data   ( rw );
  ulong   data_sz = fd_accdb_ref_data_sz( rw->ro );
  if( FD_UNLIKELY( data_sz < 8UL ) ) {
    FD_LOG_ERR(( "invalid stake history sysvar" ));
  }

  ulong len = FD_LOAD( ulong, data );
  if( FD_UNLIKELY( len > FD_SYSVAR_STAKE_HISTORY_CAP ) ) {
    FD_LOG_ERR(( "invalid stake history sysvar: len too large (%lu)", len ));
  }
  ulong min_sz = 8UL + len * 32UL;
  if( FD_UNLIKELY( data_sz < min_sz ) ) {
    FD_LOG_ERR(( "invalid stake history sysvar: data_sz too small (%lu, required %lu)", data_sz, min_sz ));
  }

  ulong new_len = fd_ulong_min( len + 1UL, FD_SYSVAR_STAKE_HISTORY_CAP );
  ulong shift   = fd_ulong_min( len, FD_SYSVAR_STAKE_HISTORY_CAP - 1UL );

  if( shift ) {
    memmove( data + 8UL + 32UL, data + 8UL, shift * 32UL );
  }

  uchar * p = data + 8UL;
  FD_STORE( ulong, p,      entry->epoch );
  FD_STORE( ulong, p+ 8UL, entry->effective );
  FD_STORE( ulong, p+16UL, entry->activating );
  FD_STORE( ulong, p+24UL, entry->deactivating );

  FD_STORE( ulong, data, new_len );

  fd_accdb_svm_close_rw( accdb, bank, capture_ctx, rw, update );
}

int
fd_sysvar_stake_history_validate( uchar const * data,
                                  ulong         sz ) {
  if( FD_UNLIKELY( sz < 8UL ) ) return 0;
  ulong len = FD_LOAD( ulong, data );
  if( FD_UNLIKELY( len > FD_SYSVAR_STAKE_HISTORY_CAP ) ) return 0;
  ulong min_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( len, 32UL, &min_sz ) ) ) return 0;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( min_sz, 8UL, &min_sz ) ) ) return 0;
  if( FD_UNLIKELY( sz < min_sz ) ) return 0;
  return 1;
}

fd_stake_history_t *
fd_sysvar_stake_history_view( fd_stake_history_t * view,
                              uchar const *        data,
                              ulong                sz ) {
  if( FD_UNLIKELY( !fd_sysvar_stake_history_validate( data, sz ) ) ) return NULL;
  view->len     = FD_LOAD( ulong, data );
  view->entries = fd_type_pun_const( data + 8UL );
  return view;
}

fd_stake_history_entry_t const *
fd_sysvar_stake_history_query( fd_stake_history_t const * view,
                               ulong                      epoch ) {
  if( FD_UNLIKELY( !view || !view->len ) ) return NULL;
  if( epoch > view->entries[0].epoch ) return NULL;

  ulong off = view->entries[0].epoch - epoch;
  if( off < view->len && view->entries[off].epoch == epoch ) {
    return &view->entries[off];
  }

  ulong lo = 0UL;
  ulong hi = view->len - 1UL;
  while( lo <= hi ) {
    ulong mid = lo + ( hi - lo ) / 2UL;
    if( view->entries[mid].epoch == epoch ) {
      return &view->entries[mid];
    } else if( view->entries[mid].epoch > epoch ) {
      lo = mid + 1UL;
    } else {
      if( mid == 0UL ) return NULL;
      hi = mid - 1UL;
    }
  }
  return NULL;
}
