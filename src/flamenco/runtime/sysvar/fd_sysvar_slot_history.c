#include "fd_sysvar_slot_history.h"
#include "fd_sysvar.h"
#include "fd_sysvar_rent.h"
#include "../fd_executor_err.h"
#include "../fd_system_ids.h"

/* FIXME These constants should be header defines */

static const ulong slot_history_min_account_size = 131097;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L37 */
static const ulong slot_history_max_entries = 1024 * 1024;

/* TODO: move into seperate bitvec library */
static const ulong bits_per_block = 8 * sizeof(ulong);

void
fd_sysvar_slot_history_set( fd_slot_history_t * history,
                            ulong               i ) {
  if( FD_UNLIKELY( i > history->next_slot && i - history->next_slot >= slot_history_max_entries ) ) {
    FD_LOG_WARNING(( "Ignoring out of bounds (i=%lu next_slot=%lu)", i, history->next_slot ));
    return;
  }

  // Skipped slots, delete them from history
  for( ulong j = history->next_slot; j < i; j++ ) {
    ulong block_idx = (j / bits_per_block) % (history->bits.bits->blocks_len);
    history->bits.bits->blocks[ block_idx ] &= ~( 1UL << ( j % bits_per_block ) );
  }
  ulong block_idx = (i / bits_per_block) % (history->bits.bits->blocks_len);
  history->bits.bits->blocks[ block_idx ] |= ( 1UL << ( i % bits_per_block ) );
}

static const ulong blocks_len = slot_history_max_entries / bits_per_block;

int fd_sysvar_slot_history_write_history( fd_exec_slot_ctx_t * slot_ctx,
                                          fd_slot_history_t * history ) {
  ulong sz = fd_slot_history_size( history );
  if (sz < slot_history_min_account_size)
    sz = slot_history_min_account_size;
  uchar enc[ sz ];
  fd_memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  int err = fd_slot_history_encode( history, &ctx );
  if (0 != err)
    return err;
  return fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_slot_history_id, enc, sz, slot_ctx->slot_bank.slot );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L16 */
void
fd_sysvar_slot_history_init( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
  /* Create a new slot history instance */
  fd_slot_history_t         history = {0};
  fd_slot_history_inner_t * inner   = fd_spad_alloc( runtime_spad, alignof(fd_slot_history_inner_t), sizeof(fd_slot_history_inner_t) );
  inner->blocks = fd_spad_alloc( runtime_spad, alignof(ulong), sizeof(ulong) * blocks_len );
  memset( inner->blocks, 0, sizeof(ulong) * blocks_len );
  inner->blocks_len = blocks_len;
  history.bits.bits = inner;
  history.bits.len  = slot_history_max_entries;

  /* TODO: handle slot != 0 init case */
  fd_sysvar_slot_history_set( &history, slot_ctx->slot_bank.slot );
  history.next_slot = slot_ctx->slot_bank.slot + 1;

  fd_sysvar_slot_history_write_history( slot_ctx, &history );
  fd_slot_history_destroy( &history );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2345 */
int
fd_sysvar_slot_history_update( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
  /* Set current_slot, and update next_slot */

  fd_pubkey_t const * key = &fd_sysvar_slot_history_id;

  FD_TXN_ACCOUNT_DECL( rec );
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, key, rec);
  if (err)
    FD_LOG_CRIT(( "fd_acc_mgr_view(slot_history) failed: %d", err ));

  fd_bincode_decode_ctx_t ctx = {
    .data    = rec->const_data,
    .dataend = rec->const_data + rec->const_meta->dlen
  };

  ulong total_sz = 0UL;
  err = fd_slot_history_decode_footprint( &ctx, &total_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "fd_slot_history_decode_footprint failed" ));
  }

  uchar * mem = fd_spad_alloc( runtime_spad, fd_slot_history_align(), total_sz );
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "Unable to allocate memory for slot history" ));
  }


  fd_slot_history_t * history = fd_slot_history_decode( mem, &ctx );

  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L48 */
  fd_sysvar_slot_history_set( history, slot_ctx->slot_bank.slot );
  history->next_slot = slot_ctx->slot_bank.slot + 1;

  ulong sz = fd_slot_history_size( history );
  if( sz < slot_history_min_account_size )
    sz = slot_history_min_account_size;

  err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, key, 1, sz, rec );
  if (err)
    FD_LOG_CRIT(( "fd_acc_mgr_modify(slot_history) failed: %d", err ));

  fd_bincode_encode_ctx_t e_ctx = {
    .data    = rec->data,
    .dataend = rec->data+sz
  };
  if( fd_slot_history_encode( history, &e_ctx ) )
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  rec->meta->info.lamports = fd_rent_exempt_minimum_balance( &epoch_bank->rent, sz );

  rec->meta->dlen = sz;
  fd_memcpy( rec->meta->info.owner, fd_sysvar_owner_id.key, sizeof(fd_pubkey_t) );

  fd_slot_history_destroy( history );

  return 0;
}

fd_slot_history_t *
fd_sysvar_slot_history_read( fd_acc_mgr_t *  acc_mgr,
                             fd_funk_txn_t * funk_txn,
                             fd_spad_t *     spad ) {
  /* Set current_slot, and update next_slot */

  fd_pubkey_t const * key = &fd_sysvar_slot_history_id;

  FD_TXN_ACCOUNT_DECL( rec );
  int err = fd_acc_mgr_view( acc_mgr, funk_txn, key, rec );
  if( err ) {
    FD_LOG_CRIT(( "fd_acc_mgr_view(slot_history) failed: %d", err ));
  }

  fd_bincode_decode_ctx_t ctx = {
    .data    = rec->const_data,
    .dataend = rec->const_data + rec->const_meta->dlen
  };

  ulong total_sz = 0UL;
  err = fd_slot_history_decode_footprint( &ctx, &total_sz );
  if( err ) {
    FD_LOG_ERR(( "fd_slot_history_decode_footprint failed" ));
  }

  uchar * mem = fd_spad_alloc( spad, fd_slot_history_align(), total_sz );
  if( !mem ) {
    FD_LOG_ERR(( "Unable to allocate memory for slot history" ));
  }

  return fd_slot_history_decode( mem, &ctx );
}

int
fd_sysvar_slot_history_find_slot( fd_slot_history_t const * history,
                                  ulong                     slot ) {
  if( slot > history->next_slot - 1UL ) {
    return FD_SLOT_HISTORY_SLOT_FUTURE;
  } else if ( slot < fd_ulong_sat_sub( history->next_slot, slot_history_max_entries ) ) {
    return FD_SLOT_HISTORY_SLOT_TOO_OLD;
  } else {
    ulong block_idx = (slot / bits_per_block) % (history->bits.bits->blocks_len);
    if( history->bits.bits->blocks[ block_idx ] & ( 1UL << ( slot % bits_per_block ) ) ) {
      return FD_SLOT_HISTORY_SLOT_FOUND;
    } else {
      return FD_SLOT_HISTORY_SLOT_NOT_FOUND;
    }
  }
}
