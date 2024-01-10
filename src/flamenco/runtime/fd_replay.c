#include "../fd_flamenco.h"
#include "fd_account.h"
#include "fd_replay.h"

int
fd_replay( fd_replay_state_t * state )
{
  /* Create scratch allocator */

  ulong  smax = 256 /*MiB*/ << 20;
  void * smem = fd_wksp_alloc_laddr( state->local_wksp, fd_scratch_smem_align(), smax, 1UL );
  if( FD_UNLIKELY( !smem ) ) FD_LOG_ERR(( "Failed to alloc scratch mem" ));
  ulong  scratch_depth = 128UL;
  void * fmem = fd_wksp_alloc_laddr( state->local_wksp, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( scratch_depth ), 2UL );
  if( FD_UNLIKELY( !fmem ) ) FD_LOG_ERR(( "Failed to alloc scratch frames" ));

  fd_scratch_attach( smem, fmem, smax, scratch_depth );

  fd_features_restore( state->slot_ctx );

  if (state->slot_ctx->acc_mgr->blockstore->max < state->end_slot)
    state->end_slot = state->slot_ctx->acc_mgr->blockstore->max;
  // FD_LOG_WARNING(("Failing here"))
  fd_runtime_update_leaders(state->slot_ctx, state->slot_ctx->slot_bank.slot);

  fd_calculate_epoch_accounts_hash_values( state->slot_ctx );

  long replay_time = -fd_log_wallclock();
  ulong txn_cnt = 0;
  ulong slot_cnt = 0;
  fd_blockstore_t * blockstore = state->slot_ctx->acc_mgr->blockstore;

  ulong prev_slot = state->slot_ctx->slot_bank.slot;
  for ( ulong slot = state->slot_ctx->slot_bank.slot+1; slot < state->end_slot; ++slot ) {
    state->slot_ctx->slot_bank.prev_slot = prev_slot;
    state->slot_ctx->slot_bank.slot      = slot;

    FD_LOG_DEBUG(("reading slot %ld", slot));

    fd_blockstore_block_t * blk = fd_blockstore_block_query(blockstore, slot);
    if (blk == NULL) {
      FD_LOG_WARNING(("failed to read slot %ld", slot));
      continue;
    }
    uchar * val = fd_blockstore_block_data_laddr(blockstore, blk);
    ulong sz = blk->sz;

    ulong blk_txn_cnt = 0;
    FD_TEST( fd_runtime_block_eval_tpool( state->slot_ctx, state->capture_ctx, val, sz, state->tpool, state->max_workers, &blk_txn_cnt ) == FD_RUNTIME_EXECUTE_SUCCESS );
    txn_cnt += blk_txn_cnt;
    slot_cnt++;

    uchar const * expected = fd_blockstore_block_query_hash( state->slot_ctx->acc_mgr->blockstore, slot );
    if ( FD_UNLIKELY( !expected ) )
      FD_LOG_ERR(("slot %lu is missing its hash", slot));
    else if( FD_UNLIKELY( 0!=memcmp( state->slot_ctx->slot_bank.poh.hash, expected, 32UL ) ) ) {
      FD_LOG_WARNING(( "PoH hash mismatch! slot=%lu expected=%32J, got=%32J",
          slot,
          expected,
          state->slot_ctx->slot_bank.poh.hash ));
      if( state->abort_on_mismatch ) {
        __asm__( "int $3" );
        return 1;
      }
    }

    expected = fd_blockstore_block_query_bank_hash( state->slot_ctx->acc_mgr->blockstore, slot );
    if ( FD_UNLIKELY( !expected ) ) {
      FD_LOG_ERR(("slot %lu is missing its bank hash", slot));
    } else if( FD_UNLIKELY( 0!=memcmp( state->slot_ctx->slot_bank.banks_hash.hash, expected, 32UL ) ) ) {
      FD_LOG_WARNING(( "Bank hash mismatch! slot=%lu expected=%32J, got=%32J",
          slot,
          expected,
          state->slot_ctx->slot_bank.banks_hash.hash ));
      if( state->abort_on_mismatch ) {
        __asm__( "int $3" );
        return 1;
      }
    }

    if (NULL != state->capitalization_file) {
      slot_capitalization_t *c = capitalization_map_query(state->map, slot, NULL);
      if (NULL != c) {
        if (state->slot_ctx->slot_bank.capitalization != c->capitalization)
          FD_LOG_ERR(( "capitalization missmatch!  slot=%lu got=%ld != expected=%ld  (%ld)", slot, state->slot_ctx->slot_bank.capitalization, c->capitalization,  state->slot_ctx->slot_bank.capitalization - c->capitalization  ));
      }
    }
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

  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_wksp_free_laddr( fd_scratch_detach( NULL ) );
  fd_wksp_free_laddr( fmem                      );
  return 0;
}


ulong
fd_replay_state_align( void ) {
  return alignof(fd_replay_state_t);
}

ulong
fd_replay_state_footprint( void ) {
  return sizeof(fd_replay_state_t);
}

void *
fd_replay_state_new( void * shmem ) {
  fd_replay_state_t * replay_state = (fd_replay_state_t *)shmem;

  if( FD_UNLIKELY( !replay_state ) ) {
    FD_LOG_WARNING(( "NULL replay_state" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)replay_state, fd_replay_state_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned replay_state" ));
    return NULL;
  }

  return (void *) replay_state;
}

/* fd_replay_state_join returns the local join to the wksp backing the funk.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes funk is a current local join. */

fd_replay_state_t *
fd_replay_state_join( void * state ) {
  return (fd_replay_state_t *) state;
}

/* fd_replay_state_leave leaves an existing join.  Returns the underlying
   shfunk on success and NULL on failure.  (logs details). */

void *
fd_replay_state_leave( fd_replay_state_t * state ) {
  return state;
}

/* fd_replay_state_delete unformats a wksp allocation used as a replay_state */
void *
fd_replay_state_delete( void * state ) {
  return state;
}
