#include "fd_replay.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"
#include "../shred/fd_shred_cap.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

void *
fd_replay_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_replay_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_replay_footprint();
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING( ( "bad footprint" ) );
    return NULL;
  }

  fd_memset( mem, 0, footprint );
  ulong laddr                = (ulong)mem;
  laddr                      = fd_ulong_align_up( laddr, alignof( fd_replay_t ) );
  fd_replay_t * replay       = (void *)laddr;
  replay->smr                = FD_SLOT_NULL;
  replay->snapshot_slot      = FD_SLOT_NULL;
  replay->first_turbine_slot = FD_SLOT_NULL;
  replay->curr_turbine_slot  = 0;

  laddr += sizeof( fd_replay_t );

  laddr              = fd_ulong_align_up( laddr, fd_replay_commitment_align() );
  replay->commitment = fd_replay_commitment_new( (void *)laddr );
  laddr += fd_replay_commitment_footprint();

  laddr           = fd_ulong_align_up( laddr, alignof( long ) );
  replay->pending = (long *)laddr;
  laddr += sizeof( long ) * FD_REPLAY_PENDING_MAX;
  replay->pending_start = 0;
  replay->pending_end   = 0;
  replay->pending_lock  = 0;

  laddr = fd_ulong_align_up( laddr, alignof( fd_replay_t ) );

  FD_TEST( laddr == (ulong)mem + footprint );

  return mem;
}

/* TODO only safe for local joins */
fd_replay_t *
fd_replay_join( void * replay ) {

  if( FD_UNLIKELY( !replay ) ) {
    FD_LOG_WARNING( ( "NULL replay" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)replay, fd_replay_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned replay" ) );
    return NULL;
  }

  fd_replay_t * replay_ = (fd_replay_t *)replay;
  replay_->commitment   = fd_replay_commitment_join( replay_->commitment );

  return replay_;
}

void *
fd_replay_leave( fd_replay_t const * replay ) {

  if( FD_UNLIKELY( !replay ) ) {
    FD_LOG_WARNING( ( "NULL replay" ) );
    return NULL;
  }

  return (void *)replay;
}

void *
fd_replay_delete( void * replay ) {

  if( FD_UNLIKELY( !replay ) ) {
    FD_LOG_WARNING( ( "NULL replay" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)replay, fd_replay_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned replay" ) );
    return NULL;
  }

  return replay;
}

static void
fd_replay_pending_lock( fd_replay_t * replay ) {
  for( ;; ) {
    if( FD_LIKELY( !FD_ATOMIC_CAS( &replay->pending_lock, 0UL, 1UL ) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
}

static void
fd_replay_pending_unlock( fd_replay_t * replay ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( replay->pending_lock ) = 0UL;
}

void
fd_replay_add_pending( fd_replay_t * replay, ulong slot, long delay ) {
  fd_replay_pending_lock( replay );

  long   when    = replay->now + delay;
  long * pending = replay->pending;
  if( replay->pending_start == replay->pending_end ) {
    /* Queue is empty */
    replay->pending_start                  = slot;
    replay->pending_end                    = slot + 1U;
    pending[slot & FD_REPLAY_PENDING_MASK] = when;

  } else if( slot < replay->pending_start ) {
    /* Grow down */
    if( replay->pending_end - slot > FD_REPLAY_PENDING_MAX )
      FD_LOG_ERR( ( "pending queue overrun: start=%lu, end=%lu, new slot=%lu",
                    replay->pending_start,
                    replay->pending_end,
                    slot ) );
    pending[slot & FD_REPLAY_PENDING_MASK] = when;
    for( ulong i = slot + 1; i < replay->pending_start; ++i ) {
      /* Zero fill */
      pending[i & FD_REPLAY_PENDING_MASK] = 0;
    }
    replay->pending_start = slot;

  } else if( slot >= replay->pending_end ) {
    /* Grow up */
    if( slot - replay->pending_start > FD_REPLAY_PENDING_MAX )
      FD_LOG_ERR( ( "pending queue overrun: start=%lu, end=%lu, new slot=%lu",
                    replay->pending_start,
                    replay->pending_end,
                    slot ) );
    pending[slot & FD_REPLAY_PENDING_MASK] = when;
    for( ulong i = replay->pending_end; i < slot; ++i ) {
      /* Zero fill */
      pending[i & FD_REPLAY_PENDING_MASK] = 0;
    }
    replay->pending_end = slot + 1U;

  } else {
    /* Update in place */
    long * p = &pending[slot & FD_REPLAY_PENDING_MASK];
    if( 0 == *p || *p > when ) *p = when;
  }

  fd_replay_pending_unlock( replay );
}

ulong
fd_replay_pending_iter_init( fd_replay_t * replay ) {
  return replay->pending_start;
}

ulong
fd_replay_pending_iter_next( fd_replay_t * replay, long now, ulong i ) {
  fd_replay_pending_lock( replay );
  ulong end = replay->pending_end;
  for( i = fd_ulong_max( i, replay->pending_start ); 1; ++i ) {
    if( i >= end ) {
      /* End sentinel */
      i = ULONG_MAX;
      break;
    }
    long * ele = &replay->pending[i & FD_REPLAY_PENDING_MASK];
    if( i <= replay->smr || *ele == 0 ) {
      /* Empty or useless slot */
      if( replay->pending_start == i ) replay->pending_start = i + 1U; /* Pop it */
    } else if( *ele <= now ) {
      /* Do this slot */
      long when = *ele;
      *ele      = 0;
      if( replay->pending_start == i ) replay->pending_start = i + 1U; /* Pop it */
      FD_LOG_DEBUG(
          ( "preparing slot %lu when=%ld now=%ld latency=%ld", i, when, now, now - when ) );
      break;
    }
  }
  fd_replay_pending_unlock( replay );
  return i;
}

fd_fork_t *
fd_replay_slot_prepare( fd_replay_t * replay, ulong slot ) {

  fd_blockstore_start_read( replay->blockstore );

  ulong re_adds[2];
  uint  re_adds_cnt = 0;

  fd_block_t * block = fd_blockstore_block_query( replay->blockstore, slot );

  /* We already executed this block */

  if( FD_UNLIKELY( block && fd_uchar_extract_bit( block->flags, FD_BLOCK_FLAG_PROCESSED ) ) ) {
    goto end;
  }

  fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( replay->blockstore, slot );
  if( FD_UNLIKELY( !slot_meta ) ) {
    fd_replay_slot_repair( replay, slot );
    re_adds[re_adds_cnt++] = slot;
    goto end;
  }

  ulong            parent_slot = slot_meta->parent_slot;

  fd_slot_meta_t * parent_slot_meta =
      fd_blockstore_slot_meta_query( replay->blockstore, parent_slot );

  /* If the parent slot meta is missing, this block is an orphan and the ancestry needs to be
     repaired before we can replay it. */

  if( FD_UNLIKELY( !parent_slot_meta ) ) {
    fd_repair_need_orphan( replay->repair, slot );
    re_adds[re_adds_cnt++] = slot;
    re_adds[re_adds_cnt++] = parent_slot;
    goto end;
  }

  /* Check if we have a complete parent block. */

  fd_block_t * parent_block = fd_blockstore_block_query( replay->blockstore, parent_slot );

  /* We have a parent slot meta, and therefore have at least one shred of the parent block, so we
     have the ancestry and need to repair that block directly (as opposed to calling repair orphan).
  */

  if( FD_UNLIKELY( !parent_block ) ) {
    fd_replay_slot_repair( replay, parent_slot );
    re_adds[re_adds_cnt++] = slot;
    re_adds[re_adds_cnt++] = parent_slot;
    goto end;
  }

  /* Check if the parent is processed (executed) yet. */

  if( FD_UNLIKELY( !fd_uchar_extract_bit( parent_block->flags, FD_BLOCK_FLAG_PROCESSED ) ) ) {
    re_adds[re_adds_cnt++] = slot;
    re_adds[re_adds_cnt++] = parent_slot;
    goto end;
  }

  /* Check if the block is still incomplete. Ask for the remaining shreds. */

  if( FD_UNLIKELY( !block ) ) {
    fd_replay_slot_repair( replay, slot );
    re_adds[re_adds_cnt++] = slot;
    goto end;
  }

  /* Query for the fork to execute the block on in the frontier */

  fd_fork_t * fork = fd_fork_frontier_ele_query(
      replay->forks->frontier, &parent_slot, NULL, replay->forks->pool );

  /* If the parent block is both present and executed (see earlier conditionals), but isn't in the
     frontier, that means this block is starting a new fork and needs to be added to the
     frontier. This requires rolling back to that txn in funk. */

  if( FD_UNLIKELY( !fork ) ) {

    /* Alloc a new slot_ctx */

    fork       = fd_fork_pool_ele_acquire( replay->forks->pool );
    fork->slot = parent_slot;

    /* Format and join the slot_ctx */

    fd_exec_slot_ctx_t * slot_ctx =
        fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &fork->slot_ctx, replay->valloc ) );
    if( FD_UNLIKELY( !slot_ctx ) ) { FD_LOG_ERR( ( "failed to new and join slot_ctx" ) ); }

    /* Restore and decode w/ funk */

    fd_replay_slot_ctx_restore( replay, fork->slot, slot_ctx );

    /* Add to frontier */

    fd_fork_frontier_ele_insert( replay->forks->frontier, fork, replay->forks->pool );
  }

  /* Prepare the replay_slot struct. */

  fork->head = block;

  /* Mark the block as prepared, and thus unsafe to remove. */

  block->flags = fd_uchar_set_bit( block->flags, FD_BLOCK_FLAG_PREPARED );

  /* Block data ptr remains valid outside of the rw lock for the lifetime of the block alloc. */

  fd_blockstore_end_read( replay->blockstore );

  /* Add slots to pending. */

  for( uint i = 0; i < re_adds_cnt; ++i ) {
    fd_replay_add_pending( replay, re_adds[i], FD_REPAIR_BACKOFF_TIME );
  }

  /* Return the fork, to proceed with execution of the fork head. */

  return fork;

/* Not ready to execute, so cleanup. */

end:
  fd_blockstore_end_read( replay->blockstore );

  for( uint i = 0; i < re_adds_cnt; ++i )
    fd_replay_add_pending( replay, re_adds[i], FD_REPAIR_BACKOFF_TIME );

  return NULL;
}

void
fd_replay_slot_execute( fd_replay_t *      replay,
                        ulong              slot,
                        fd_fork_t *        fork,
                        fd_capture_ctx_t * capture_ctx ) {
  fd_shred_cap_mark_stable( replay, slot );

  ulong txn_cnt                        = 0;
  fork->slot_ctx.slot_bank.prev_slot = fork->slot_ctx.slot_bank.slot;
  fork->slot_ctx.slot_bank.slot      = slot;
  FD_TEST(
      fd_runtime_block_eval_tpool( &fork->slot_ctx,
                                   capture_ctx,
                                   fd_blockstore_block_data_laddr( replay->blockstore, fork->head ),
                                   fork->head->data_sz,
                                   replay->tpool,
                                   replay->max_workers,
                                   1,
                                   &txn_cnt ) == FD_RUNTIME_EXECUTE_SUCCESS );
  (void)txn_cnt;

  fd_blockstore_start_write( replay->blockstore );

  fd_block_t * block_ = fd_blockstore_block_query( replay->blockstore, slot );
  if( FD_LIKELY( block_ ) ) {
    block_->flags = fd_uchar_set_bit( block_->flags, FD_BLOCK_FLAG_PROCESSED );
    memcpy( &block_->bank_hash, &fork->slot_ctx.slot_bank.banks_hash, sizeof( fd_hash_t ) );
  }

  fd_blockstore_end_write( replay->blockstore );

  /* Re-key the replay_slot_ctx to be the slot of the block we just executed. */

  fd_fork_t * child = fd_fork_frontier_ele_remove(
      replay->forks->frontier, &fork->slot, NULL, replay->forks->pool );
  child->slot = slot;
  if( FD_UNLIKELY( fd_fork_frontier_ele_query(
          replay->forks->frontier, &slot, NULL, replay->forks->pool ) ) ) {
    FD_LOG_ERR( ( "invariant violation: child slot %lu was already in the frontier", slot ) );
  }
  fd_fork_frontier_ele_insert( replay->forks->frontier, child, replay->forks->pool );

  /* Prepare bank for next execution. */

  child->slot_ctx.slot_bank.slot           = slot;
  child->slot_ctx.slot_bank.collected_fees = 0;
  child->slot_ctx.slot_bank.collected_rent = 0;

  FD_LOG_NOTICE( ( "first turbine: %lu, current received turbine: %lu, behind: %lu current "
                   "executed: %lu, caught up: %d",
                   replay->first_turbine_slot,
                   replay->curr_turbine_slot,
                   replay->curr_turbine_slot - slot,
                   slot,
                   slot > replay->first_turbine_slot ) );

  fd_hash_t const * bank_hash = &child->slot_ctx.slot_bank.banks_hash;
  fork->head->bank_hash       = *bank_hash;
  FD_LOG_NOTICE( ( "bank hash: %32J", bank_hash->hash ) );

  // fd_bank_hash_cmp_t * bank_hash_cmp = fd_exec_epoch_ctx_bank_hash_cmp( child->slot_ctx.epoch_ctx );
  // fd_bank_hash_cmp_lock( bank_hash_cmp );
  // fd_bank_hash_cmp_insert( bank_hash_cmp, slot, bank_hash, 1 );

  // /* Try to move the bank hash comparison window forward */
  // while (1) {
  //   ulong *children, nchildren, parent_slot = bank_hash_cmp->slot;
  //   if ( fd_blockstore_next_slot_query( replay->blockstore, parent_slot, &children, &nchildren ) == FD_BLOCKSTORE_OK ) {
  //     for (ulong i = 0; i < nchildren; i++) {
  //       if( FD_LIKELY( fd_bank_hash_cmp_check( bank_hash_cmp, children[i] ) ) ) {
  //         bank_hash_cmp->slot = children[i];
  //         break;
  //       }
  //     }
  //   } else {
  //     FD_LOG_WARNING( ("failed at getting children of slot %lu", parent_slot) );
  //   }
  //   if(bank_hash_cmp->slot == parent_slot) break;
  // }
  // fd_bank_hash_cmp_unlock( bank_hash_cmp );

  // fd_bft_fork_update( replay->bft, child );
  // fd_bft_fork_choice( replay->bft );
}

void
fd_replay_slot_repair( fd_replay_t * replay, ulong slot ) {
  fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( replay->blockstore, slot );

  if( fd_blockstore_is_slot_ancient( replay->blockstore, slot ) ) {
    FD_LOG_ERR( ( "repair is hopelessly behind by %lu slots, max history is %lu",
                  replay->blockstore->max - slot,
                  replay->blockstore->slot_max ) );
  }

  if( FD_LIKELY( !slot_meta ) ) {

    /* We haven't received any shreds for this slot yet */

    fd_repair_need_highest_window_index( replay->repair, slot, 0 );

  } else {

    /* We've received at least one shred, so fill in what's missing */

    ulong last_index = slot_meta->last_index;

    /* We don't know the last index yet */

    if( FD_UNLIKELY( last_index == ULONG_MAX ) ) {
      last_index = slot_meta->received - 1;
      fd_repair_need_highest_window_index( replay->repair, slot, (uint)last_index );
    }

    /* First make sure we are ready to execute this blook soon. Look for an ancestor that was
       executed. */

    ulong anc_slot = slot;
    int   good     = 0;
    for( uint i = 0; i < 3; ++i ) {
      anc_slot               = fd_blockstore_parent_slot_query( replay->blockstore, anc_slot );
      fd_block_t * anc_block = fd_blockstore_block_query( replay->blockstore, anc_slot );
      if( anc_block && fd_uchar_extract_bit( anc_block->flags, FD_BLOCK_FLAG_PROCESSED ) ) {
        good = 1;
        break;
      }
    }
    if( !good ) return;

    /* Fill in what's missing */

    ulong cnt = 0;
    for( ulong i = slot_meta->consumed + 1; i <= last_index; i++ ) {
      if( fd_blockstore_shred_query( replay->blockstore, slot, (uint)i ) != NULL ) continue;
      if( fd_repair_need_window_index( replay->repair, slot, (uint)i ) > 0 ) ++cnt;
    }
    if( cnt )
      FD_LOG_NOTICE( ( "[repair] need %lu [%lu, %lu], sent %lu requests",
                       slot,
                       slot_meta->consumed + 1,
                       last_index,
                       cnt ) );
  }
}

void
fd_replay_slot_ctx_restore( fd_replay_t * replay, ulong slot, fd_exec_slot_ctx_t * slot_ctx ) {
  fd_funk_txn_t *   txn_map    = fd_funk_txn_map( replay->funk, fd_funk_wksp( replay->funk ) );
  fd_hash_t const * block_hash = fd_blockstore_block_hash_query( replay->blockstore, slot );
  FD_LOG_DEBUG(("Current slot %lu", slot));
  if( !block_hash ) FD_LOG_ERR( ( "missing block hash of slot we're trying to restore" ) );
  fd_funk_txn_xid_t xid;
  fd_memcpy( xid.uc, block_hash, sizeof( fd_funk_txn_xid_t ) );
  xid.ul[0]             = slot;
  fd_funk_rec_key_t id  = fd_runtime_slot_bank_key();
  fd_funk_txn_t *   txn = fd_funk_txn_query( &xid, txn_map );
  if( !txn ) FD_LOG_ERR( ( "missing txn, parent slot %lu", slot ) );
  fd_funk_rec_t const * rec = fd_funk_rec_query_global( replay->funk, txn, &id );
  if( rec == NULL ) FD_LOG_ERR( ( "failed to read banks record" ) );
  void *                  val = fd_funk_val( rec, fd_funk_wksp( replay->funk ) );
  fd_bincode_decode_ctx_t ctx;
  ctx.data    = val;
  ctx.dataend = (uchar *)val + fd_funk_val_sz( rec );
  ctx.valloc  = replay->valloc;

  FD_TEST( slot_ctx->magic == FD_EXEC_SLOT_CTX_MAGIC );

  slot_ctx->epoch_ctx = replay->epoch_ctx;

  slot_ctx->funk_txn   = txn;
  slot_ctx->acc_mgr    = replay->acc_mgr;
  slot_ctx->blockstore = replay->blockstore;
  slot_ctx->valloc     = replay->valloc;

  fd_bincode_destroy_ctx_t destroy_ctx = {
    .valloc = replay->valloc,
  };

  fd_slot_bank_destroy( &slot_ctx->slot_bank, &destroy_ctx );
  FD_TEST( fd_slot_bank_decode( &slot_ctx->slot_bank, &ctx ) == FD_BINCODE_SUCCESS );
  FD_TEST( !fd_runtime_sysvar_cache_load( slot_ctx ) );
  slot_ctx->leader = fd_epoch_leaders_get( fd_exec_epoch_ctx_leaders( slot_ctx->epoch_ctx ), slot );

  // TODO how do i get this info, ignoring rewards for now
  // slot_ctx->epoch_reward_status = ???

  // signature_cnt, account_delta_hash, prev_banks_hash are used for the banks hash calculation and
  // not needed when restoring parent

  FD_LOG_NOTICE( ( "recovered slot_bank for slot=%lu banks_hash=%32J poh_hash %32J",
                   slot_ctx->slot_bank.slot,
                   slot_ctx->slot_bank.banks_hash.hash,
                   slot_ctx->slot_bank.poh.hash ) );

  /* Prepare bank for next slot */
  slot_ctx->slot_bank.slot           = slot;
  slot_ctx->slot_bank.collected_fees = 0;
  slot_ctx->slot_bank.collected_rent = 0;

  /* FIXME epoch boundary stuff when replaying */
  // fd_features_restore( slot_ctx );
  // fd_runtime_update_leaders( slot_ctx, slot_ctx->slot_bank.slot );
  // fd_calculate_epoch_accounts_hash_values( slot_ctx );
}

void
fd_replay_turbine_rx( fd_replay_t * replay, fd_shred_t const * shred, ulong shred_sz ) {
  FD_LOG_DEBUG( ( "[turbine] received shred - type: %x slot: %lu idx: %u",
                  fd_shred_type( shred->variant ) & FD_SHRED_TYPEMASK_DATA,
                  shred->slot,
                  shred->idx ) );
  fd_pubkey_t const * leader = fd_epoch_leaders_get( fd_exec_epoch_ctx_leaders( replay->epoch_ctx ), shred->slot );
  if( FD_UNLIKELY( !leader ) ) {
    FD_LOG_WARNING( ( "unable to get current leader, ignoring turbine packet" ) );
    return;
  }
  fd_fec_set_t const * out_fec_set = NULL;
  fd_shred_t const *   out_shred   = NULL;
  int                  rc          = fd_fec_resolver_add_shred(
      replay->fec_resolver, shred, shred_sz, leader->uc, &out_fec_set, &out_shred );
  if( rc == FD_FEC_RESOLVER_SHRED_COMPLETES ) {
    if( FD_UNLIKELY( replay->first_turbine_slot == FD_SLOT_NULL ) ) {
      replay->first_turbine_slot = shred->slot;
    }
    fd_shred_t * parity_shred = (fd_shred_t *)fd_type_pun( out_fec_set->parity_shreds[0] );
    FD_LOG_DEBUG( ( "slot: %lu. parity: %u. data: %u",
                    parity_shred->slot,
                    parity_shred->code.code_cnt,
                    parity_shred->code.data_cnt ) );

    /* Start repairs in 300ms */
    ulong slot = parity_shred->slot;
    fd_replay_add_pending( replay, slot, (ulong)300e6 );

    fd_blockstore_t * blockstore = replay->blockstore;
    fd_blockstore_start_write( blockstore );

    if( fd_blockstore_block_query( blockstore, slot ) != NULL ) {
      fd_blockstore_end_write( blockstore );
      return;
    }

    for( ulong i = 0; i < parity_shred->code.data_cnt; i++ ) {
      fd_shred_t * data_shred = (fd_shred_t *)fd_type_pun( out_fec_set->data_shreds[i] );
      FD_LOG_DEBUG( ( "[turbine] rx shred - slot: %lu idx: %u", slot, data_shred->idx ) );
      int rc = fd_blockstore_shred_insert( blockstore, data_shred );
      /* TODO @yunzhang: write to shred_cap */
      fd_shred_cap_archive( replay, data_shred, FD_SHRED_CAP_FLAG_MARK_TURBINE( 0 ) );

      if( FD_UNLIKELY( rc == FD_BLOCKSTORE_OK_SLOT_COMPLETE ) ) {
        if( FD_UNLIKELY( replay->first_turbine_slot == FD_SLOT_NULL ) ) {
          replay->first_turbine_slot = slot;
        }
        replay->curr_turbine_slot = fd_ulong_max( slot, replay->curr_turbine_slot );
        FD_LOG_NOTICE( ( "[turbine] slot %lu complete", slot ) );

        fd_blockstore_end_write( blockstore );

        /* Execute immediately */
        fd_replay_add_pending( replay, slot, 0 );
        return;
      }
    }

    fd_blockstore_end_write( blockstore );
  }
}

void
fd_replay_repair_rx( fd_replay_t * replay, fd_shred_t const * shred ) {
  FD_LOG_DEBUG( ( "[repair] rx shred - slot: %lu idx: %u", shred->slot, shred->idx ) );
  fd_blockstore_t * blockstore = replay->blockstore;

  fd_blockstore_start_write( blockstore );
  /* TODO remove this check when we can handle duplicate shreds and blocks */
  if( fd_blockstore_block_query( blockstore, shred->slot ) != NULL ) {
    fd_blockstore_end_write( blockstore );
    return;
    // return FD_BLOCKSTORE_OK;
  }
  int rc = fd_blockstore_shred_insert( blockstore, shred );

  /* TODO @yunzhang: write to shred_cap */
  fd_shred_cap_archive( replay, shred, FD_SHRED_CAP_FLAG_MARK_REPAIR( 0 ) );

  fd_blockstore_end_write( blockstore );

  /* FIXME */
  if( FD_UNLIKELY( rc < FD_BLOCKSTORE_OK ) ) {
    FD_LOG_ERR( ( "failed to insert shred. reason: %d", rc ) );
  } else if( rc == FD_BLOCKSTORE_OK_SLOT_COMPLETE ) {
    fd_replay_add_pending( replay, shred->slot, 0 );
  } else {
    fd_replay_add_pending( replay, shred->slot, FD_REPAIR_BACKOFF_TIME );
  }
  // return rc;
}

fd_fork_t *
fd_replay_prepare_ctx( fd_replay_t * replay,
                       ulong parent_slot ) {

  /* Query for the fork to execute the block on in the frontier */

  fd_fork_t * fork = fd_fork_frontier_ele_query(
      replay->forks->frontier, &parent_slot, NULL, replay->forks->pool );

  /* If the parent block is both present and executed (see earlier conditionals), but isn't in the
     frontier, that means this block is starting a new fork and needs to be added to the
     frontier. This requires rolling back to that txn in funk. */

  if( FD_UNLIKELY( !fork ) ) {

    /* Alloc a new slot_ctx */

    fork       = fd_fork_pool_ele_acquire( replay->forks->pool );
    fork->slot = parent_slot;

    /* Format and join the slot_ctx */

    fd_exec_slot_ctx_t * slot_ctx =
        fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &fork->slot_ctx, replay->valloc ) );
    if( FD_UNLIKELY( !slot_ctx ) ) { FD_LOG_ERR( ( "failed to new and join slot_ctx" ) ); }

    /* Restore and decode w/ funk */

    fd_replay_slot_ctx_restore( replay, fork->slot, slot_ctx );

    /* Add to frontier */

    fd_fork_frontier_ele_insert( replay->forks->frontier, fork, replay->forks->pool );
  }

  return fork;
}
