#include "fd_sysvar_stake_history.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_accdb_svm.h"
#include "fd_sysvar_rent.h"

void
fd_sysvar_stake_history_init( fd_bank_t *        bank,
                              fd_accdb_t *       accdb,
                              fd_capture_ctx_t * capture_ctx ) {
  uchar data[ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ];
  fd_memset( data, 0, sizeof(data) );
  fd_sysvar_account_update( bank, accdb, capture_ctx, &fd_sysvar_stake_history_id, data, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
}

/* https://github.com/anza-xyz/agave/blob/v4.0.0-rc.1/runtime/src/bank.rs#L2452-L2463 */

void
fd_sysvar_stake_history_update( fd_bank_t *                      bank,
                                fd_accdb_t *                     accdb,
                                fd_capture_ctx_t *               capture_ctx,
                                fd_stake_history_entry_t const * entry ) {
  fd_accdb_svm_update_t update[1];
  fd_acc_t rw = fd_accdb_svm_open_rw( bank, accdb, update, &fd_sysvar_stake_history_id, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );

  if( FD_UNLIKELY( !rw.lamports ) ) {
    /* Initialize account if it did not exist */
    fd_memcpy( rw.owner, fd_sysvar_owner_id.key, sizeof(fd_pubkey_t) );
    rw.lamports = fd_rent_exempt_minimum_balance( &bank->f.rent, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
    rw.data_len = FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ;
    fd_memset( rw.data, 0, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
    /* Now a valid StakeHistory sysvar with zero entries */
  } else {
    /* Sanity check existing state */
    if( FD_UNLIKELY( 0!=memcmp( rw.owner, &fd_sysvar_owner_id, sizeof(fd_pubkey_t) ) ) ) {
      FD_LOG_ERR(( "stake history sysvar not owned by sysvar owner" ));
    }
  }

  if( FD_UNLIKELY( rw.data_len<8UL ) ) FD_LOG_ERR(( "invalid stake history sysvar" ));

  ulong len = FD_LOAD( ulong, rw.data );
  len = fd_ulong_min( len, FD_SYSVAR_STAKE_HISTORY_CAP );
  ulong min_sz = 8UL + len * sizeof(fd_stake_history_entry_t);
  if( FD_UNLIKELY( rw.data_len<min_sz ) ) {
    FD_LOG_ERR(( "invalid stake history sysvar: data_len too small (%lu, required %lu)", rw.data_len, min_sz ));
  }

  /* https://github.com/anza-xyz/solana-sdk/blob/account%40v4.3.0/account/src/lib.rs#L618 */
  if( FD_UNLIKELY( rw.data_len!=FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ) ) rw.data_len = FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ;

  fd_stake_history_entry_t * entries = fd_type_pun( rw.data+8UL );

  /* https://github.com/solana-program/stake/blob/interface%40v4.0.0/interface/src/stake_history.rs#L83 */
  ulong idx   = 0UL;
  int   found = 0;
  {
    ulong lo = 0UL;
    ulong hi = len;
    while( lo < hi ) {
      ulong mid         = lo + (hi - lo) / 2UL;
      ulong probe_epoch = entries[mid].epoch;
      if( entry->epoch == probe_epoch ) {
        idx   = mid;
        found = 1;
        break;
      } else if( entry->epoch > probe_epoch ) {
        hi = mid;
      } else {
        lo = mid + 1UL;
      }
    }
    if( !found ) idx = lo;
  }

  /* Ensure account is rent exempt
     https://github.com/anza-xyz/agave/blob/v4.0.0-rc.1/runtime/src/bank.rs#L5849-L5854 */
  ulong rent_min = fd_rent_exempt_minimum_balance( &bank->f.rent, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
  if( FD_UNLIKELY( rent_min>rw.lamports ) ) rw.lamports = rent_min;

  /* Insert new element */
  ulong new_len = fd_ulong_if( found, len, fd_ulong_min( len+1UL, FD_SYSVAR_STAKE_HISTORY_CAP ) );
  ulong used_sz = 8UL + new_len * sizeof(fd_stake_history_entry_t);

  if( found ) {
    /* https://github.com/solana-program/stake/blob/interface%40v4.0.0/interface/src/stake_history.rs#L84 */
    entries[ idx ] = *entry;
  } else if( idx < FD_SYSVAR_STAKE_HISTORY_CAP ) {
    /* https://github.com/solana-program/stake/blob/interface%40v4.0.0/interface/src/stake_history.rs#L85
       https://github.com/solana-program/stake/blob/interface%40v4.0.0/interface/src/stake_history.rs#L87 */
    ulong shift_count = fd_ulong_min( len, FD_SYSVAR_STAKE_HISTORY_CAP-1UL ) - idx;
    memmove( &entries[ idx+1UL ], &entries[ idx ], shift_count * sizeof(fd_stake_history_entry_t) );
    entries[ idx ] = *entry;
    new_len = fd_ulong_min( len+1UL, FD_SYSVAR_STAKE_HISTORY_CAP );
  }
  /* else: idx == cap and not found - new entry would be truncated, drop */

  /* Zero trailing bytes (technically a no-op) */
  FD_TEST( used_sz <= FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
  fd_memset( rw.data+used_sz, 0, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ-used_sz );

  FD_STORE( ulong, rw.data, new_len );
  fd_accdb_svm_close_rw( bank, accdb, capture_ctx, &rw, update );
}

int
fd_sysvar_stake_history_validate( uchar const * data,
                                  ulong         sz ) {
  if( FD_UNLIKELY( sz < 8UL ) ) return 0;
  ulong len = FD_LOAD( ulong, data );
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
  if( FD_UNLIKELY( !view || !view->len || epoch>view->entries[0].epoch ) ) return NULL;
  ulong index = view->entries[0].epoch - epoch;
  if( FD_UNLIKELY( index>=view->len ) ) return NULL;
  return &view->entries[index];
}
