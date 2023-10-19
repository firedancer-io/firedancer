#include "fd_sysvar_slot_history.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"
#include "fd_sysvar_rent.h"
#include "../fd_system_ids.h"

const ulong slot_history_min_account_size = 131097;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L37 */
const ulong slot_history_max_entries = 1024 * 1024;

/* TODO: move into seperate bitvec library */
const ulong bits_per_block = 8 * sizeof(ulong);
void fd_sysvar_slot_history_set( fd_slot_history_t* history, ulong i ) {
  // Corrupt history, zero everything out
  if ( i > history->next_slot && i - history->next_slot >= slot_history_max_entries ) {
    for ( ulong j = 0; j < history->bits.bits->blocks_len; j++) {
      history->bits.bits->blocks[ j ] = 0;
    }
  } else {
    // Skipped slots, delete them from history
    for (ulong j = history->next_slot; j < i; j++) {
      ulong block_idx = (j / bits_per_block) % (history->bits.bits->blocks_len);
      history->bits.bits->blocks[ block_idx ] &= ~( 1UL << ( j % bits_per_block ) );
    }
  }
  ulong block_idx = (i / bits_per_block) % (history->bits.bits->blocks_len);
  history->bits.bits->blocks[ block_idx ] |= ( 1UL << ( i % bits_per_block ) );
}

const ulong blocks_len = slot_history_max_entries / bits_per_block;

int fd_sysvar_slot_history_write_history( fd_exec_slot_ctx_t * slot_ctx,
                                          fd_slot_history_t * history ) {
  ulong sz = fd_slot_history_size( history );
  if (sz < slot_history_min_account_size)
    sz = slot_history_min_account_size;
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  int err = fd_slot_history_encode( history, &ctx );
  if (0 != err)
    return err;
  return fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_slot_history_id, enc, sz, slot_ctx->bank.slot, NULL );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L16 */
void fd_sysvar_slot_history_init( fd_exec_slot_ctx_t * slot_ctx ) {
  /* Create a new slot history instance */
  fd_slot_history_t history;
  fd_slot_history_inner_t *inner = fd_valloc_malloc( slot_ctx->valloc, 8UL, sizeof(fd_slot_history_inner_t) );
  inner->blocks = fd_valloc_malloc( slot_ctx->valloc, 8UL, sizeof(ulong) * blocks_len );
  memset( inner->blocks, 0, sizeof(ulong) * blocks_len );
  inner->blocks_len = blocks_len;
  history.bits.bits = inner;
  history.bits.len = slot_history_max_entries;

  /* TODO: handle slot != 0 init case */
  fd_sysvar_slot_history_set( &history, slot_ctx->bank.slot );
  history.next_slot = slot_ctx->bank.slot + 1;

  fd_sysvar_slot_history_write_history( slot_ctx, &history );
  fd_bincode_destroy_ctx_t ctx = { .valloc = slot_ctx->valloc };
  fd_slot_history_destroy( &history, &ctx );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2345 */
int
fd_sysvar_slot_history_update( fd_exec_slot_ctx_t * slot_ctx ) {
  /* Set current_slot, and update next_slot */

  fd_pubkey_t const * key = &fd_sysvar_slot_history_id;

  FD_BORROWED_ACCOUNT_DECL(rec);
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, key, rec);
  if (err)
    FD_LOG_CRIT(( "fd_acc_mgr_view(slot_history) failed: %d", err ));

  fd_bincode_decode_ctx_t ctx;
  ctx.data    = rec->const_data;
  ctx.dataend = rec->const_data + rec->const_meta->dlen;
  ctx.valloc  = slot_ctx->valloc;
  fd_slot_history_t history[1];
  if( fd_slot_history_decode( history, &ctx ) )
    FD_LOG_ERR(("fd_slot_history_decode failed"));

  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L48 */
  fd_sysvar_slot_history_set( history, slot_ctx->bank.slot );
  history->next_slot = slot_ctx->bank.slot + 1;

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

  rec->meta->info.lamports = fd_rent_exempt_minimum_balance2( &slot_ctx->bank.rent, sz );

  rec->meta->dlen = sz;
  fd_memcpy( rec->meta->info.owner, fd_sysvar_owner_id.key, sizeof(fd_pubkey_t) );

  fd_bincode_destroy_ctx_t ctx_d = { .valloc = slot_ctx->valloc };
  fd_slot_history_destroy( history, &ctx_d );

  return fd_acc_mgr_commit(slot_ctx->acc_mgr, rec, slot_ctx);
}
