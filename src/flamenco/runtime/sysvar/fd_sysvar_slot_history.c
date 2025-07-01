#include "fd_sysvar_slot_history.h"
#include "fd_sysvar.h"
#include "fd_sysvar_rent.h"
#include "../fd_executor_err.h"
#include "../fd_system_ids.h"

/* FIXME These constants should be header defines */

static const ulong slot_history_min_account_size = 131097;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L37 */
static const ulong slot_history_max_entries = 1024 * 1024;

/* TODO: move into separate bitvec library */
static const ulong bits_per_block = 8 * sizeof(ulong);

void
fd_sysvar_slot_history_set( fd_slot_history_global_t * history,
                            ulong                      i ) {
  if( FD_UNLIKELY( i > history->next_slot && i - history->next_slot >= slot_history_max_entries ) ) {
    FD_LOG_WARNING(( "Ignoring out of bounds (i=%lu next_slot=%lu)", i, history->next_slot ));
    return;
  }

  ulong * blocks     = (ulong *)((uchar*)history + history->bits_bitvec_offset);
  ulong   blocks_len = history->bits_bitvec_len;

  // Skipped slots, delete them from history
  if( FD_UNLIKELY( blocks_len == 0 ) ) return;
  for( ulong j = history->next_slot; j < i; j++ ) {
    ulong block_idx = (j / bits_per_block) % (blocks_len);
    blocks[ block_idx ] &= ~( 1UL << ( j % bits_per_block ) );
  }
  ulong block_idx = (i / bits_per_block) % (blocks_len);
  blocks[ block_idx ] |= ( 1UL << ( i % bits_per_block ) );
}

FD_FN_UNUSED static const ulong blocks_len = slot_history_max_entries / bits_per_block;

int
fd_sysvar_slot_history_write_history( fd_exec_slot_ctx_t *       slot_ctx,
                                      fd_slot_history_global_t * history ) {
  ulong sz = slot_history_min_account_size;
  uchar enc[ sz ];
  fd_memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data    = enc;
  ctx.dataend = enc + sz;
  int err = fd_slot_history_encode_global( history, &ctx );
  if (0 != err)
    return err;
  return fd_sysvar_set( slot_ctx->bank, slot_ctx->funk, slot_ctx->funk_txn, &fd_sysvar_owner_id, &fd_sysvar_slot_history_id, enc, sz, slot_ctx->slot );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L16 */

void
fd_sysvar_slot_history_init( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {
  /* Create a new slot history instance */

  /* We need to construct the gaddr-aware slot history object */
  ulong total_sz = sizeof(fd_slot_history_global_t) + alignof(fd_slot_history_global_t) +
                   (sizeof(ulong) + alignof(ulong)) * blocks_len;

  uchar * mem = fd_spad_alloc( runtime_spad, alignof(fd_slot_history_global_t), total_sz );
  fd_slot_history_global_t * history = (fd_slot_history_global_t *)mem;
  ulong *                    blocks  = (ulong *)fd_ulong_align_up( (ulong)((uchar*)history + sizeof(fd_slot_history_global_t)), alignof(ulong) );

  history->next_slot          = slot_ctx->slot + 1UL;
  history->bits_bitvec_offset = (ulong)((uchar*)blocks - (uchar*)history);
  history->bits_len           = slot_history_max_entries;
  history->bits_bitvec_len    = blocks_len;
  history->has_bits           = 1;
  memset( blocks, 0, sizeof(ulong) * blocks_len );

  /* TODO: handle slot != 0 init case */
  fd_sysvar_slot_history_set( history, slot_ctx->slot );
  fd_sysvar_slot_history_write_history( slot_ctx, history );
  } FD_SPAD_FRAME_END;
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2345 */
int
fd_sysvar_slot_history_update( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
  /* Set current_slot, and update next_slot */

  fd_pubkey_t const * key = &fd_sysvar_slot_history_id;

  FD_TXN_ACCOUNT_DECL( rec );
  int err = fd_txn_account_init_from_funk_readonly( rec, key, slot_ctx->funk, slot_ctx->funk_txn );
  if (err)
    FD_LOG_CRIT(( "fd_txn_account_init_from_funk_readonly(slot_history) failed: %d", err ));

  fd_bincode_decode_ctx_t ctx = {
    .data    = rec->vt->get_data( rec ),
    .dataend = rec->vt->get_data( rec ) + rec->vt->get_data_len( rec )
  };

  ulong total_sz = 0UL;
  err = fd_slot_history_decode_footprint( &ctx, &total_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_CRIT(( "fd_slot_history_decode_footprint failed %d", err ));
  }

  uchar * mem = fd_spad_alloc( runtime_spad, fd_slot_history_align(), total_sz );
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_CRIT(( "Unable to allocate memory for slot history" ));
  }

  fd_slot_history_global_t * history = fd_slot_history_decode_global( mem, &ctx );

  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L48 */
  fd_sysvar_slot_history_set( history, slot_ctx->slot );
  history->next_slot = slot_ctx->slot + 1;

  ulong sz = slot_history_min_account_size;

  err = fd_txn_account_init_from_funk_mutable( rec, key, slot_ctx->funk, slot_ctx->funk_txn, 1, sz );
  if (err)
    FD_LOG_CRIT(( "fd_txn_account_init_from_funk_mutable(slot_history) failed: %d", err ));

  fd_bincode_encode_ctx_t e_ctx = {
    .data    = rec->vt->get_data_mut( rec ),
    .dataend = rec->vt->get_data_mut( rec )+sz,
  };

  if( FD_UNLIKELY( fd_slot_history_encode_global( history, &e_ctx ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_rent_t const * rent = fd_bank_rent_query( slot_ctx->bank );
  rec->vt->set_lamports( rec, fd_rent_exempt_minimum_balance( rent, sz ) );

  rec->vt->set_data_len( rec, sz );
  rec->vt->set_owner( rec, &fd_sysvar_owner_id );

  fd_txn_account_mutable_fini( rec, slot_ctx->funk, slot_ctx->funk_txn );

  return 0;
}

fd_slot_history_global_t *
fd_sysvar_slot_history_read( fd_funk_t *     funk,
                             fd_funk_txn_t * funk_txn,
                             fd_spad_t *     spad ) {

  /* Set current_slot, and update next_slot */

  fd_pubkey_t const * key = &fd_sysvar_slot_history_id;

  FD_TXN_ACCOUNT_DECL( rec );
  int err = fd_txn_account_init_from_funk_readonly( rec, key, funk, funk_txn );
  if( err ) {
    FD_LOG_CRIT(( "fd_txn_account_init_from_funk_readonly(slot_history) failed: %d", err ));
  }

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( rec->vt->get_lamports( rec ) == 0UL ) ) {
    return NULL;
  }

  fd_bincode_decode_ctx_t ctx = {
    .data    = rec->vt->get_data( rec ),
    .dataend = rec->vt->get_data( rec ) + rec->vt->get_data_len( rec )
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

  return fd_slot_history_decode_global( mem, &ctx );
}

int
fd_sysvar_slot_history_find_slot( fd_slot_history_global_t const * history,
                                  ulong                            slot,
                                  fd_wksp_t *                      wksp ) {
  (void)wksp;
  ulong * blocks = (ulong *)((uchar*)history + history->bits_bitvec_offset);
  if( FD_UNLIKELY( !blocks ) ) {
    FD_LOG_ERR(( "Unable to find slot history blocks" ));
  }
  ulong blocks_len = history->bits_bitvec_len;


  if( slot > history->next_slot - 1UL ) {
    return FD_SLOT_HISTORY_SLOT_FUTURE;
  } else if ( slot < fd_ulong_sat_sub( history->next_slot, slot_history_max_entries ) ) {
    return FD_SLOT_HISTORY_SLOT_TOO_OLD;
  } else {
    ulong block_idx = (slot / bits_per_block) % blocks_len;
    if( blocks[ block_idx ] & ( 1UL << ( slot % bits_per_block ) ) ) {
      return FD_SLOT_HISTORY_SLOT_FOUND;
    } else {
      return FD_SLOT_HISTORY_SLOT_NOT_FOUND;
    }
  }
}
