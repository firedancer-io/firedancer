#include "../fd_flamenco.h"
#include "fd_account.h"
#include "fd_replay.h"

int
fd_replay( fd_runtime_ctx_t * state, fd_runtime_args_t *args )
{
  ulong r = fd_funk_txn_cancel_all(state->slot_ctx->acc_mgr->funk, 1);
  FD_LOG_INFO(( "Cancelled old transactions %lu", r ));

  fd_features_restore( state->slot_ctx );

  if (state->slot_ctx->acc_mgr->blockstore->max < args->end_slot)
    args->end_slot = state->slot_ctx->acc_mgr->blockstore->max;
  // FD_LOG_WARNING(("Failing here"))
  fd_runtime_update_leaders(state->slot_ctx, state->slot_ctx->slot_bank.slot);

  fd_calculate_epoch_accounts_hash_values( state->slot_ctx );

  long replay_time = -fd_log_wallclock();
  ulong txn_cnt = 0;
  ulong slot_cnt = 0;
  fd_blockstore_t * blockstore = state->slot_ctx->acc_mgr->blockstore;

  ulong prev_slot = state->slot_ctx->slot_bank.slot;
  for ( ulong slot = state->slot_ctx->slot_bank.slot+1; slot < args->end_slot; ++slot ) {
    state->slot_ctx->slot_bank.prev_slot = prev_slot;
    state->slot_ctx->slot_bank.slot      = slot;

    FD_LOG_DEBUG(("reading slot %ld", slot));

    fd_blockstore_start_read(blockstore);
    fd_blockstore_block_t * blk = fd_blockstore_block_query(blockstore, slot);
    if (blk == NULL) {
      FD_LOG_WARNING(("failed to read slot %ld", slot));
      fd_blockstore_end_read(blockstore);
      continue;
    }
    uchar * val = fd_blockstore_block_data_laddr(blockstore, blk);
    ulong sz = blk->sz;
    fd_blockstore_end_read(blockstore);

    ulong blk_txn_cnt = 0;
    FD_TEST( fd_runtime_block_eval_tpool( state->slot_ctx, state->capture_ctx, val, sz, state->tpool, state->max_workers, &blk_txn_cnt ) == FD_RUNTIME_EXECUTE_SUCCESS );
    txn_cnt += blk_txn_cnt;
    slot_cnt++;

    fd_blockstore_start_read(blockstore);
    uchar const * expected = fd_blockstore_block_query_hash( blockstore, slot );
    if ( FD_UNLIKELY( !expected ) )
      FD_LOG_ERR(("slot %lu is missing its hash", slot));
    else if( FD_UNLIKELY( 0!=memcmp( state->slot_ctx->slot_bank.poh.hash, expected, 32UL ) ) ) {
      FD_LOG_WARNING(( "PoH hash mismatch! slot=%lu expected=%32J, got=%32J",
          slot,
          expected,
          state->slot_ctx->slot_bank.poh.hash ));
      if( state->abort_on_mismatch ) {
        __asm__( "int $3" );
        fd_blockstore_end_read(blockstore);
        return 1;
      }
    }

    expected = fd_blockstore_block_query_bank_hash( blockstore, slot );
    if ( FD_UNLIKELY( !expected ) ) {
      FD_LOG_ERR(("slot %lu is missing its bank hash", slot));
    } else if( FD_UNLIKELY( 0!=memcmp( state->slot_ctx->slot_bank.banks_hash.hash, expected, 32UL ) ) ) {
      FD_LOG_WARNING(( "Bank hash mismatch! slot=%lu expected=%32J, got=%32J",
          slot,
          expected,
          state->slot_ctx->slot_bank.banks_hash.hash ));
      if( state->abort_on_mismatch ) {
        __asm__( "int $3" );
        fd_blockstore_end_read(blockstore);
        return 1;
      }
    }
    fd_blockstore_end_read(blockstore);

#if 0
    if (NULL != args->capitalization_file) {
      slot_capitalization_t *c = capitalization_map_query(state->map, slot, NULL);
      if (NULL != c) {
        if (state->slot_ctx->slot_bank.capitalization != c->capitalization)
          FD_LOG_ERR(( "capitalization missmatch!  slot=%lu got=%ld != expected=%ld  (%ld)", slot, state->slot_ctx->slot_bank.capitalization, c->capitalization,  state->slot_ctx->slot_bank.capitalization - c->capitalization  ));
      }
    }
#endif
    if (0==memcmp( state->slot_ctx->slot_bank.banks_hash.hash, expected, 32UL )) {
      ulong publish_err = fd_funk_txn_publish(state->slot_ctx->acc_mgr->funk, state->slot_ctx->funk_txn, 1);
      if (publish_err == 0)
        {
          FD_LOG_ERR(("publish err - %lu", publish_err));
          return -1;
        }
      state->slot_ctx->funk_txn = NULL;
    }

    prev_slot = slot;
  }

  replay_time += fd_log_wallclock();
  double replay_time_s = (double)replay_time * 1e-9;
  double tps = (double)txn_cnt / replay_time_s;
  double sec_per_slot = replay_time_s/(double)slot_cnt;
  FD_LOG_NOTICE(( "replay completed - slots: %lu, elapsed: %6.6f s, txns: %lu, tps: %6.6f, sec/slot: %6.6f", slot_cnt, replay_time_s, txn_cnt, tps, sec_per_slot ));

  // fd_funk_txn_publish( state->slot_ctx->acc_mgr->funk, state->slot_ctx->acc_mgr->funk_txn, 1);

  return 0;
}


ulong
fd_runtime_ctx_align( void ) {
  return alignof(fd_runtime_ctx_t);
}

ulong
fd_runtime_ctx_footprint( void ) {
  return sizeof(fd_runtime_ctx_t);
}

void *
fd_runtime_ctx_new( void * shmem ) {
  fd_runtime_ctx_t * replay_state = (fd_runtime_ctx_t *)shmem;

  if( FD_UNLIKELY( !replay_state ) ) {
    FD_LOG_WARNING(( "NULL replay_state" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)replay_state, fd_runtime_ctx_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned replay_state" ));
    return NULL;
  }

  return (void *) replay_state;
}

/* fd_runtime_ctx_join returns the local join to the wksp backing the funk.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes funk is a current local join. */

fd_runtime_ctx_t *
fd_runtime_ctx_join( void * state ) {
  return (fd_runtime_ctx_t *) state;
}

/* fd_runtime_ctx_leave leaves an existing join.  Returns the underlying
   shfunk on success and NULL on failure.  (logs details). */

void *
fd_runtime_ctx_leave( fd_runtime_ctx_t * state ) {
  return state;
}

/* fd_runtime_ctx_delete unformats a wksp allocation used as a replay_state */
void *
fd_runtime_ctx_delete( void * state ) {
  return state;
}
