#include "fd_replay.h"
#include "../fd_flamenco.h"
#include "context/fd_exec_slot_ctx.h"
#include "fd_account.h"
#include "fd_blockstore.h"
#include "fd_borrowed_account.h"
#include "fd_runtime.h"

void *
fd_replay_new( void * mem, ulong slot_max, ulong seed ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_replay_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_replay_footprint( slot_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING( ( "bad slot_max (%lu)", slot_max ) );
    return NULL;
  }

  fd_memset( mem, 0, footprint );

  ulong laddr = (ulong)mem;

  fd_replay_t * replay = (fd_replay_t *)mem;
  laddr                = fd_ulong_align_up( laddr + sizeof( fd_replay_t ), fd_replay_pool_align() );
  replay->pool         = fd_replay_pool_new( (void *)laddr, slot_max );
  laddr =
      fd_ulong_align_up( laddr + fd_replay_pool_footprint( slot_max ), fd_replay_frontier_align() );
  replay->frontier   = fd_replay_frontier_new( (void *)laddr, slot_max, seed );
  laddr              = fd_ulong_align_up( laddr + fd_replay_frontier_footprint( slot_max ),
                             fd_replay_commitment_align() );
  replay->commitment = fd_replay_commitment_new( (void *)laddr );
  fd_memset( (void *)laddr, 0, fd_replay_commitment_footprint() ); /* zero out nested arrays */
  laddr = fd_ulong_align_up( laddr + fd_replay_commitment_footprint(), fd_replay_set_align() );
  replay->pending = fd_replay_set_new( (void *)laddr );
  laddr           = fd_ulong_align_up( laddr + fd_replay_set_footprint(), fd_replay_set_align() );
  replay->missing = fd_replay_set_new( (void *)laddr );
  laddr           = fd_ulong_align_up( laddr + fd_replay_set_footprint(), fd_replay_set_align() );
  replay->dedup   = fd_replay_set_new( (void *)laddr );

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
  replay_->pool         = fd_replay_pool_join( replay_->pool );
  replay_->frontier     = fd_replay_frontier_join( replay_->frontier );
  replay_->commitment   = fd_replay_commitment_join( replay_->commitment );
  replay_->pending      = fd_replay_set_join( replay_->pending );
  replay_->missing      = fd_replay_set_join( replay_->missing );
  replay_->dedup        = fd_replay_set_join( replay_->dedup );

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

void
fd_replay_pending_execute( fd_replay_t * replay ) {
  fd_replay_set_t new_pending[FD_REPLAY_SET_MAX / ( sizeof( size_t ) * 8 )] = { 0 };

  /* we might push items back into the queue, so process at most current queue_cnt items */
  FD_LOG_DEBUG( ( "pending cnt: %lu", fd_replay_set_cnt( replay->pending ) ) );

  for( ulong idx = fd_replay_set_iter_init( replay->pending ); !fd_replay_set_iter_done( idx );
       idx       = fd_replay_set_iter_next( replay->pending, idx ) ) {
    ulong slot = idx + replay->smr;
    fd_blockstore_start_read( replay->blockstore );

    fd_blockstore_block_t * block = fd_blockstore_block_query( replay->blockstore, slot );
    ulong parent_slot             = fd_blockstore_slot_parent_query( replay->blockstore, slot );

    /* This can happen when bootstrapping from snapshot to turbine or the block is evicted. */
    if( block == NULL || parent_slot == FD_SLOT_NULL ) {
      fd_replay_missing_insert( replay, slot );
      fd_replay_set_insert( new_pending, slot - replay->smr );
      fd_blockstore_end_read( replay->blockstore );
      continue;
    }

    /* We've already executed this block. */
    if( FD_UNLIKELY( fd_uint_extract_bit( block->flags, FD_BLOCKSTORE_BLOCK_FLAG_EXECUTED ) ) ) {
      continue;
    }

    fd_blockstore_block_t * parent_block =
        fd_blockstore_block_query( replay->blockstore, parent_slot );

    /* If the parent block is missing, we need to repair before we can replay the child. */
    if( FD_UNLIKELY( !parent_block ) ) {
      fd_replay_missing_insert( replay, parent_slot );
      fd_replay_set_insert( new_pending, slot - replay->smr );
      fd_blockstore_end_read( replay->blockstore );
      continue;
    };

    /* We haven't executed the parent block yet, so add both back to the queue. */
    if( FD_UNLIKELY(
            !fd_uint_extract_bit( parent_block->flags, FD_BLOCKSTORE_BLOCK_FLAG_EXECUTED ) ) ) {
      fd_replay_set_insert( new_pending, parent_slot - replay->smr );
      fd_replay_set_insert( new_pending, slot - replay->smr );
      fd_blockstore_end_read( replay->blockstore );
      continue;
    }

    /* Find the parent in the frontier. */
    fd_replay_slot_t * parent =
        fd_replay_frontier_ele_query( replay->frontier, &parent_slot, NULL, replay->pool );

    /* If the parent isn't in the frontier, that means this is starting a new fork and the parent
     * needs to be added to the frontier. This requires rolling back to that parent in funk, and
     * then saving it into the frontier. */
    if( FD_UNLIKELY( !parent ) ) {

      /* Alloc a new slot_ctx */
      parent       = fd_replay_pool_ele_acquire( replay->pool );
      parent->slot = parent_slot;
      fd_exec_slot_ctx_t * parent_slot_ctx =
          fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &parent->slot_ctx ) );

      /* Restore and decode w/ funk */
      fd_replay_slot_ctx_restore( replay, parent->slot, parent_slot_ctx );

      /* Add to frontier */
      fd_replay_frontier_ele_insert( replay->frontier, parent, replay->pool );
    }

    /* block data ptr remains valid outside of the rw lock for the lifetime of the block alloc */
    uchar const * block_data = fd_blockstore_block_data_laddr( replay->blockstore, block );
    fd_blockstore_end_read( replay->blockstore );

    /* Prepare block for next execution */
    parent->slot_ctx.slot_bank.prev_slot = parent->slot;
    parent->slot_ctx.slot_bank.slot      = slot;

    /* Next execution expects these to be zeroed out*/
    parent->slot_ctx.slot_bank.collected_fees = 0;
    parent->slot_ctx.slot_bank.collected_rent = 0;

    // ulong txn_cnt = 0;
    (void)block_data;
    // FD_TEST( fd_runtime_block_eval_tpool( &parent->slot_ctx,
    //                                       NULL,
    //                                       block_data,
    //                                       block->sz,
    //                                       replay->tpool,
    //                                       replay->max_workers,
    //                                       &txn_cnt ) == FD_RUNTIME_EXECUTE_SUCCESS );
    // (void)txn_cnt;

    // fd_blockstore_start_write( replay->blockstore );
    // block = fd_blockstore_block_query( replay->blockstore, slot );
    // if( block == NULL ) {
    //   FD_LOG_WARNING( ( "block was evicted after execution, before setting flags." ) );
    // } else {
    //   block->flags = fd_uint_set_bit( block->flags, FD_BLOCKSTORE_BLOCK_FLAG_EXECUTED );
    // }
    // fd_blockstore_end_write( replay->blockstore );

    // /* parent->slot_ctx is now child->slot_ctx, so re-insert into the map keyed by child slot */
    // fd_replay_slot_t * child =
    //     fd_replay_frontier_ele_remove( replay->frontier, &parent->slot, NULL, replay->pool );
    // fd_slot_bank_t * bank = &child->slot_ctx.slot_bank;
    // child->slot           = bank->prev_slot; /* this is a hack to fix the fact eval is setting +1 */
    // fd_replay_frontier_ele_insert( replay->frontier, child, replay->pool );

    // FD_LOG_NOTICE( ( "slot: %lu", child->slot ) );
    // FD_LOG_NOTICE( ( "bank hash: %32J", child->slot_ctx.slot_bank.banks_hash.hash ) );

  //   fd_vote_accounts_pair_t_mapnode_t * vote_accounts_pool = bank->epoch_stakes.vote_accounts_pool;
  //   fd_vote_accounts_pair_t_mapnode_t * vote_accounts_root = bank->epoch_stakes.vote_accounts_root;

  //   FD_LOG_NOTICE( ( "iterating vote accounts" ) );
  //   for( fd_vote_accounts_pair_t_mapnode_t * node =
  //            fd_vote_accounts_pair_t_map_minimum( vote_accounts_pool, vote_accounts_root );
  //        node;
  //        node = fd_vote_accounts_pair_t_map_successor( vote_accounts_pool, node ) ) {
  //     fd_solana_account_t * vote_account = &node->elem.value;

  //     fd_bincode_decode_ctx_t decode = {
  //         .data    = vote_account->data,
  //         .dataend = vote_account->data + vote_account->data_len,
  //         .valloc  = child->slot_ctx.valloc,
  //     };
  //     fd_vote_state_versioned_t vote_state[1] = { 0 };

  //     FD_LOG_NOTICE( ( "vote_account_data %lu", vote_account->data_len ) );
  //     if( FD_UNLIKELY( FD_BINCODE_SUCCESS !=
  //                      fd_vote_state_versioned_decode( vote_state, &decode ) ) ) {}
  //     FD_LOG_NOTICE( ( "node account %32J %32J",
  //                      &vote_state->inner.current.node_pubkey,
  //                      &vote_state->inner.current.authorized_withdrawer ) );
  //     fd_option_slot_t root_slot = vote_state->inner.current.root_slot;

  //     FD_LOG_NOTICE( ( "root_slot is some? %d %lu", root_slot.is_some, root_slot.slot ) );
  //     if( FD_LIKELY( root_slot.is_some ) ) {
  //       FD_LOG_NOTICE( ( "found root %lu", root_slot.slot ) );
  //       /* TODO confirm there's no edge case where the root's ancestor is not rooted */
  //       fd_blockstore_start_read( replay->blockstore );
  //       ulong ancestor = root_slot.slot;
  //       while( ancestor != FD_SLOT_NULL ) {
  //         FD_LOG_NOTICE( ( "adding slot: %lu to finalized", ancestor ) );
  //         fd_replay_commitment_t * commitment =
  //             fd_replay_commitment_query( replay->commitment, ancestor, NULL );
  //         if( FD_UNLIKELY( !commitment ) ) {
  //           commitment = fd_replay_commitment_insert( replay->commitment, ancestor );
  //         }
  //         commitment->finalized_stake += vote_account->lamports;
  //         ancestor = fd_blockstore_slot_parent_query( replay->blockstore, ancestor );
  //       }
  //       fd_blockstore_end_read( replay->blockstore );
  //     }

  //     fd_landed_vote_t * votes = vote_state->inner.current.votes;
  //     /* TODO double check with labs people we can use latency field like this */
  //     for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( votes );
  //          !deq_fd_landed_vote_t_iter_done( votes, iter );
  //          iter = deq_fd_landed_vote_t_iter_next( votes, iter ) ) {
  //       fd_landed_vote_t * landed_vote = deq_fd_landed_vote_t_iter_ele( votes, iter );
  //       FD_LOG_NOTICE( ( "landed_vote latency %lu", landed_vote->latency ) );
  //       FD_LOG_NOTICE( ( "landed_vote lockout %lu", landed_vote->lockout.slot ) );
  //       fd_replay_commitment_t * commitment =
  //           fd_replay_commitment_query( replay->commitment, slot - landed_vote->latency, NULL );
  //       if( FD_UNLIKELY( !commitment ) ) {
  //         commitment =
  //             fd_replay_commitment_insert( replay->commitment, slot - landed_vote->latency );
  //       }
  //       FD_TEST( landed_vote->lockout.confirmation_count < 32 ); // FIXME remove
  //       commitment->confirmed_stake[landed_vote->lockout.confirmation_count] +=
  //           vote_account->lamports;
  //     }
  //   }

  //   for( ulong i = 0; i < fd_replay_commitment_slot_cnt(); i++ ) {
  //     fd_replay_commitment_t * commitment =
  //         fd_replay_commitment_query( replay->commitment, i, NULL );
  //     if( FD_UNLIKELY( commitment ) ) {
  //       // FD_LOG_NOTICE( ( "confirmation stake:" ) );
  //       // for( ulong i = 0; i < 32; i++ ) {
  //       //   FD_LOG_NOTICE( ( "%lu: %lu", i, commitment->confirmed_stake[i] ) );
  //       // }
  //       FD_LOG_NOTICE(
  //           ( "slot %lu: %lu finalized", commitment->slot, commitment->finalized_stake ) );
  //     }
  //   }
  }
  fd_replay_set_union( replay->pending, replay->pending, new_pending );
}

void
fd_replay_slot_ctx_restore( fd_replay_t * replay, ulong slot, fd_exec_slot_ctx_t * slot_ctx ) {
  fd_funk_txn_t *   txn_map    = fd_funk_txn_map( replay->funk, fd_funk_wksp( replay->funk ) );
  fd_hash_t const * block_hash = fd_blockstore_block_hash_query( replay->blockstore, slot );
  if( !block_hash ) FD_LOG_ERR( ( "missing block hash of slot we're trying to restore" ) );
  fd_funk_txn_xid_t xid;
  fd_memcpy( xid.uc, block_hash, sizeof( fd_funk_txn_xid_t ) );
  fd_funk_rec_key_t id  = fd_runtime_slot_bank_key();
  fd_funk_txn_t *   txn = fd_funk_txn_query( &xid, txn_map );
  if( !txn ) FD_LOG_ERR( ( "missing txn" ) );
  fd_funk_rec_t const * rec = fd_funk_rec_query_global( replay->funk, txn, &id );
  if( rec == NULL ) FD_LOG_ERR( ( "failed to read banks record" ) );
  void *                  val = fd_funk_val( rec, fd_funk_wksp( replay->funk ) );
  fd_bincode_decode_ctx_t ctx;
  ctx.data    = val;
  ctx.dataend = (uchar *)val + fd_funk_val_sz( rec );
  ctx.valloc  = *replay->valloc;

  FD_TEST( slot_ctx->magic == FD_EXEC_SLOT_CTX_MAGIC );

  slot_ctx->epoch_ctx = replay->epoch_ctx;

  slot_ctx->funk_txn   = txn;
  slot_ctx->acc_mgr    = replay->acc_mgr;
  slot_ctx->blockstore = replay->blockstore;
  slot_ctx->valloc     = *replay->valloc;

  FD_TEST( fd_slot_bank_decode( &slot_ctx->slot_bank, &ctx ) == FD_BINCODE_SUCCESS );
  FD_TEST( fd_runtime_sysvar_cache_load( slot_ctx ) );
  slot_ctx->leader = fd_epoch_leaders_get( slot_ctx->epoch_ctx->leaders, slot );

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
fd_replay_pending_insert( fd_replay_t * replay, ulong slot ) {
  fd_replay_set_insert( replay->pending, slot - replay->smr );
}

void
fd_replay_missing_insert( fd_replay_t * replay, ulong slot ) {
  fd_replay_set_insert( replay->missing, slot - replay->smr );
}
