#include "fd_sysvar_slot_hashes.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_accdb_svm.h"

void
fd_sysvar_slot_hashes_init( fd_bank_t *        bank,
                            fd_accdb_t *       accdb,
                            fd_capture_ctx_t * capture_ctx ) {
  uchar data[ FD_SYSVAR_SLOT_HASHES_BINCODE_SZ ] = {0};
  fd_sysvar_account_update( bank, accdb, capture_ctx, &fd_sysvar_slot_hashes_id, data, FD_SYSVAR_SLOT_HASHES_BINCODE_SZ );
}

void
fd_sysvar_slot_hashes_update( fd_bank_t *        bank,
                              fd_accdb_t *       accdb,
                              fd_capture_ctx_t * capture_ctx ) {
  fd_accdb_svm_update_t update[1];
  fd_acc_t acc = fd_accdb_svm_open_rw( bank, accdb, update, &fd_sysvar_slot_hashes_id, 0 );
  if( FD_UNLIKELY( !acc.lamports ) ) {
    /* Agave initializes a new empty slot_hashes if it doesn't exist */
    fd_sysvar_slot_hashes_init( bank, accdb, capture_ctx );
    acc = fd_accdb_svm_open_rw( bank, accdb, update, &fd_sysvar_slot_hashes_id, 0 );
    if( FD_UNLIKELY( !acc.lamports ) ) {
      FD_LOG_ERR(( "state is missing slot hashes sysvar" ));
    }
  }
  if( FD_UNLIKELY( 0!=memcmp( acc.owner, &fd_sysvar_owner_id, sizeof(fd_pubkey_t) ) ) ) {
    FD_LOG_ERR(( "slot hashes sysvar not owned by sysvar owner" ));
  }
  uchar * data    = acc.data;
  ulong   data_sz = acc.data_len;
  if( FD_UNLIKELY( data_sz < FD_SYSVAR_SLOT_HASHES_BINCODE_SZ ) ) {
    FD_LOG_HEXDUMP_ERR(( "invalid slot hashes sysvar", data, data_sz ));
  }

  ulong cnt = FD_LOAD( ulong, data );
  if( FD_UNLIKELY( cnt > FD_SYSVAR_SLOT_HASHES_CAP ) ) {
    FD_LOG_HEXDUMP_ERR(( "corrupt slot hashes sysvar", data, data_sz ));
  }

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
    ulong keep = fd_ulong_min( cnt, FD_SYSVAR_SLOT_HASHES_CAP - 1UL );
    memmove( &entries[1], &entries[0], keep * sizeof(fd_slot_hash_t) );
    entries[0].slot = bank->f.parent_slot;
    fd_memcpy( &entries[0].hash, &bank->f.bank_hash, sizeof(fd_hash_t) );
    FD_STORE( ulong, data, keep + 1UL );
  }

  fd_accdb_svm_close_rw( bank, accdb, capture_ctx, &acc, update );
}

int
fd_sysvar_slot_hashes_validate( uchar const * data,
                                ulong         sz ) {
  if( FD_UNLIKELY( sz < sizeof(ulong) ) ) return 0;
  ulong cnt = FD_LOAD( ulong, data );
  if( FD_UNLIKELY( cnt > FD_SYSVAR_SLOT_HASHES_CAP ) ) return 0;
  if( FD_UNLIKELY( sz < sizeof(ulong) + cnt*sizeof(fd_slot_hash_t) ) ) return 0;
  return 1;
}

fd_slot_hashes_t *
fd_sysvar_slot_hashes_view( fd_slot_hashes_t * view,
                            uchar const *      data,
                            ulong              sz ) {
  if( FD_UNLIKELY( !fd_sysvar_slot_hashes_validate( data, sz ) ) ) return NULL;
  ulong cnt   = FD_LOAD( ulong, data );
  view->elems = (fd_slot_hash_t const *)( data + sizeof(ulong) );
  view->cnt   = cnt;
  return view;
}
