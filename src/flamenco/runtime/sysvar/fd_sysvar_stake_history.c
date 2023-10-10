#include "fd_sysvar_stake_history.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

void write_stake_history( fd_exec_slot_ctx_t * slot_ctx, fd_stake_history_t* stake_history ) {
  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/sysvar/stake_history.rs#L12 */
  ulong min_size = 16392;

  ulong          sz = fd_ulong_max( min_size, fd_stake_history_size( stake_history ) );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_stake_history_encode( stake_history, &ctx ) )
    FD_LOG_ERR(("fd_stake_history_encode failed"));

  fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_stake_history_id, enc, sz, slot_ctx->bank.slot, NULL );
}

int fd_sysvar_stake_history_read( fd_exec_slot_ctx_t * slot_ctx, fd_stake_history_t* result ) {

  FD_BORROWED_ACCOUNT_DECL(stake_rec);
  int          err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_stake_history_id, stake_rec);
  if (FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS))
    return err;

  fd_bincode_decode_ctx_t ctx = {
    .data = stake_rec->const_data,
    .dataend = (char *) stake_rec->const_data + stake_rec->const_meta->dlen,
    .valloc  = slot_ctx->valloc
  };

  if ( fd_stake_history_decode( result, &ctx ) )
    FD_LOG_ERR(("fd_stake_history_decode failed"));

  return 0;
}

void fd_sysvar_stake_history_init( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_stake_history_t stake_history = {
    .pool = fd_stake_history_pool_alloc( slot_ctx->valloc ),
    .treap = fd_stake_history_treap_alloc( slot_ctx->valloc )
  };
  write_stake_history( slot_ctx, &stake_history );
}

void fd_sysvar_stake_history_update( fd_exec_slot_ctx_t * global, fd_stake_history_entry_t * entry) {
  // Need to make this maybe zero copies of map...
  fd_stake_history_t stake_history;
  fd_sysvar_stake_history_read( global, &stake_history);
  ulong idx = fd_stake_history_pool_idx_acquire( stake_history.pool );

  stake_history.pool[ idx ].epoch = entry->epoch;
  fd_memcpy(&stake_history.pool[ idx ], entry, sizeof(fd_stake_history_entry_t));
  fd_stake_history_treap_idx_insert( stake_history.treap, idx, stake_history.pool );
  write_stake_history( global, &stake_history);
}
