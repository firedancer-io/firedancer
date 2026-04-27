#include "fd_sysvar_slot_hashes.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_accdb_svm.h"
#include "../../accdb/fd_accdb_sync.h"

void
fd_sysvar_slot_hashes_init( fd_bank_t *               bank,
                            fd_accdb_user_t *         accdb,
                            fd_funk_txn_xid_t const * xid,
                            fd_capture_ctx_t *        capture_ctx ) {
  uchar data[ FD_SYSVAR_SLOT_HASHES_BINCODE_SZ ];
  uchar * p = data;

  /* count */
  FD_STORE( ulong, p, 0UL );
  p += sizeof(ulong);

  FD_TEST( (ulong)(p - data) == sizeof(ulong) );

  fd_sysvar_account_update( bank, accdb, xid, capture_ctx, &fd_sysvar_slot_hashes_id, data, sizeof(ulong) );
}

void
fd_sysvar_slot_hashes_update( fd_bank_t *               bank,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid,
                              fd_capture_ctx_t *        capture_ctx ) {

  fd_accdb_rw_t rw[1];
  fd_accdb_svm_update_t update[1];
  if( FD_UNLIKELY( !fd_accdb_svm_open_rw( accdb, bank, xid, rw, update, &fd_sysvar_slot_hashes_id, 0UL, 0 ) ) ) {
    /* Agave initializes a new empty slot_hashes if it doesn't exist */
    fd_sysvar_slot_hashes_init( bank, accdb, xid, capture_ctx );
    if( FD_UNLIKELY( !fd_accdb_svm_open_rw( accdb, bank, xid, rw, update, &fd_sysvar_slot_hashes_id, 0UL, 0 ) ) ) {
      FD_LOG_ERR(( "state is missing slot hashes sysvar" ));
    }
  }
  if( FD_UNLIKELY( 0!=memcmp( fd_accdb_ref_owner( rw->ro ), &fd_sysvar_owner_id, sizeof(fd_pubkey_t) ) ) ) {
    FD_LOG_ERR(( "slot hashes sysvar not owned by sysvar owner" ));
  }
  uchar * data    = fd_accdb_ref_data   ( rw );
  ulong   data_sz = fd_accdb_ref_data_sz( rw->ro );
  if( FD_UNLIKELY( data_sz < sizeof(ulong) ) ) {
    FD_LOG_HEXDUMP_ERR(( "invalid slot hashes sysvar", data, data_sz ));
  }

  ulong cnt = FD_LOAD( ulong, data );

  /* Search for existing entry with parent_slot */
  fd_slot_hash_t * entries = (fd_slot_hash_t *)(data + sizeof(ulong));
  int found = 0;
  for( ulong i=0UL; i<cnt; i++ ) {
    if( entries[i].slot == bank->f.parent_slot ) {
      fd_memcpy( &entries[i].hash, &bank->f.bank_hash, sizeof(fd_hash_t) );
      found = 1;
      break;
    }
  }

  if( !found ) {
    /* Evict oldest if full */
    if( cnt >= FD_SYSVAR_SLOT_HASHES_CAP ) {
      cnt = FD_SYSVAR_SLOT_HASHES_CAP - 1UL;
    }

    /* We need more space — resize the account data.
       New size: 8 + (cnt+1)*40 */
    ulong new_cnt = cnt + 1UL;
    ulong new_sz  = sizeof(ulong) + new_cnt * sizeof(fd_slot_hash_t);

    /* The account might need to grow. Close and rewrite. */
    fd_accdb_svm_close_rw( accdb, bank, capture_ctx, rw, update );

    /* Build the new data: prepend the new entry, then copy the old ones */
    uchar new_data[ FD_SYSVAR_SLOT_HASHES_BINCODE_SZ ];
    FD_STORE( ulong, new_data, new_cnt );

    fd_slot_hash_t * new_entries = (fd_slot_hash_t *)(new_data + sizeof(ulong));
    new_entries[0].slot = bank->f.parent_slot;
    fd_memcpy( &new_entries[0].hash, &bank->f.bank_hash, sizeof(fd_hash_t) );

    /* Re-read the old data to copy existing entries */
    fd_accdb_ro_t ro[1];
    if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, ro, xid, &fd_sysvar_slot_hashes_id ) ) ) {
      FD_LOG_ERR(( "slot hashes sysvar disappeared" ));
    }
    uchar const * old_data    = fd_accdb_ref_data_const( ro );
    ulong         old_data_sz = fd_accdb_ref_data_sz( ro );
    ulong         old_cnt     = FD_LOAD( ulong, old_data );
    ulong         copy_cnt    = fd_ulong_min( old_cnt, cnt );
    if( copy_cnt > 0UL && old_data_sz >= sizeof(ulong) + copy_cnt * sizeof(fd_slot_hash_t) ) {
      fd_memcpy( &new_entries[1], old_data + sizeof(ulong), copy_cnt * sizeof(fd_slot_hash_t) );
    }
    fd_accdb_close_ro( accdb, ro );

    fd_sysvar_account_update( bank, accdb, xid, capture_ctx, &fd_sysvar_slot_hashes_id, new_data, new_sz );
    return;
  }

  fd_accdb_svm_close_rw( accdb, bank, capture_ctx, rw, update );
}

int
fd_sysvar_slot_hashes_validate( uchar const * data,
                                ulong         sz ) {
  if( FD_UNLIKELY( sz < sizeof(ulong) ) ) return 0;
  ulong cnt = FD_LOAD( ulong, data );
  ulong min_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( cnt, sizeof(fd_slot_hash_t), &min_sz ) ) ) return 0;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( min_sz, sizeof(ulong), &min_sz ) ) ) return 0;
  if( FD_UNLIKELY( sz < min_sz ) ) return 0;
  return 1;
}

fd_slot_hashes_view_t *
fd_sysvar_slot_hashes_view( fd_slot_hashes_view_t * view,
                            uchar const *           data,
                            ulong                   sz ) {
  if( FD_UNLIKELY( !fd_sysvar_slot_hashes_validate( data, sz ) ) ) return NULL;
  ulong cnt   = FD_LOAD( ulong, data );
  view->elems = (fd_slot_hash_t const *)( data + sizeof(ulong) );
  view->cnt   = cnt;
  return view;
}
