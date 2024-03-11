#include "fd_sysvar_stake_history.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

void write_stake_history( fd_exec_slot_ctx_t * slot_ctx, fd_stake_history_t* stake_history ) {
  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/sysvar/stake_history.rs#L12 */
  ulong max_size = 16392;
  ulong curr_size = stake_history->treap->ele_cnt * 32 + 8;
  ulong          sz = fd_ulong_max( max_size, curr_size );

  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_stake_history_encode( stake_history, &ctx ) )
    FD_LOG_ERR(("fd_stake_history_encode failed"));

  fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_stake_history_id, enc, sz, slot_ctx->slot_bank.slot, NULL );

}

fd_stake_history_t *
fd_sysvar_stake_history_read( fd_stake_history_t * result,
                              fd_exec_slot_ctx_t * slot_ctx,
                              fd_valloc_t *valloc) {

  FD_BORROWED_ACCOUNT_DECL(stake_rec);
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_stake_history_id, stake_rec);
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) )
    return NULL;

  fd_bincode_decode_ctx_t ctx = {
    .data = stake_rec->const_data,
    .dataend = (char *) stake_rec->const_data + stake_rec->const_meta->dlen,
    .valloc  = *valloc
  };

  if( FD_UNLIKELY( fd_stake_history_decode( result, &ctx )!=FD_BINCODE_SUCCESS ) )
    return NULL;
  return result;
}

void
fd_sysvar_stake_history_destroy( fd_stake_history_t * result,
                                 fd_exec_slot_ctx_t * slot_ctx ) {
  fd_bincode_destroy_ctx_t ctx = {
    .valloc  = slot_ctx->valloc
  };
  fd_stake_history_destroy( result, &ctx );
}

void fd_sysvar_stake_history_init( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_stake_history_t stake_history = {
    .pool = fd_stake_history_pool_alloc( slot_ctx->valloc ),
    .treap = fd_stake_history_treap_alloc( slot_ctx->valloc )
  };
  write_stake_history( slot_ctx, &stake_history );
}

void fd_sysvar_stake_history_update( fd_exec_slot_ctx_t * slot_ctx, fd_stake_history_entry_t * entry) {
  // Need to make this maybe zero copies of map...
  fd_stake_history_t stake_history;
  fd_sysvar_stake_history_read( &stake_history, slot_ctx, &slot_ctx->valloc );

  if (fd_stake_history_treap_ele_cnt( stake_history.treap ) == fd_stake_history_treap_ele_max( stake_history.treap )) {
    fd_stake_history_treap_fwd_iter_t iter = fd_stake_history_treap_fwd_iter_init( stake_history.treap, stake_history.pool );
    fd_stake_history_entry_t * ele = fd_stake_history_treap_fwd_iter_ele( iter, stake_history.pool );
    stake_history.treap = fd_stake_history_treap_ele_remove( stake_history.treap, ele, stake_history.pool );
    fd_stake_history_pool_ele_release( stake_history.pool, ele );
  }

  ulong idx = fd_stake_history_pool_idx_acquire( stake_history.pool );

  stake_history.pool[ idx ].epoch = entry->epoch;
  stake_history.pool[ idx ].activating = entry->activating;
  stake_history.pool[ idx ].effective = entry->effective;
  stake_history.pool[ idx ].deactivating = entry->deactivating;
  stake_history.treap = fd_stake_history_treap_idx_insert( stake_history.treap, idx, stake_history.pool );


  write_stake_history( slot_ctx, &stake_history);
  fd_bincode_destroy_ctx_t destroy = { .valloc = slot_ctx->valloc };
  fd_stake_history_destroy( &stake_history, &destroy );
}
