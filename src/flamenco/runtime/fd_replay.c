#include "fd_replay.h"

static int
upsert_repair_req( fd_replay_t * replay, ulong slot, uint shred_idx );

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

  laddr                 = fd_ulong_align_up( laddr, alignof( fd_replay_t ) );
  fd_replay_t * replay  = (fd_replay_t *)mem;
  replay->smr           = FD_SLOT_NULL;
  replay->turbine_slot  = FD_SLOT_NULL;
  replay->snapshot_slot = FD_SLOT_NULL;
  laddr += sizeof( fd_replay_t );

  laddr        = fd_ulong_align_up( laddr, fd_replay_pool_align() );
  replay->pool = fd_replay_pool_new( (void *)laddr, slot_max );
  laddr += fd_replay_pool_footprint( slot_max );

  laddr            = fd_ulong_align_up( laddr, fd_replay_frontier_align() );
  replay->frontier = fd_replay_frontier_new( (void *)laddr, slot_max, seed );
  laddr += fd_replay_frontier_footprint( slot_max );

  laddr              = fd_ulong_align_up( laddr, fd_replay_commitment_align() );
  replay->commitment = fd_replay_commitment_new( (void *)laddr );
  laddr += fd_replay_commitment_footprint();

  laddr           = fd_ulong_align_up( laddr, fd_replay_pending_align() );
  replay->pending = fd_replay_pending_new( (void *)laddr );
  laddr += fd_replay_pending_footprint();

  //   laddr           = fd_ulong_align_up( laddr, fd_fec_resolver_align() );
  // replay->fec_resolver = fd_fec_resolver_new( (void *)laddr, 1024, 1024, 1024, 1024 );
  // laddr += fd_fec_resolver_footprint( 1024, 1024, 1024, 1024 );

  laddr                = fd_ulong_align_up( laddr, fd_repair_peer_align() );
  replay->repair_peers = fd_repair_peer_new( (void *)laddr );
  laddr += fd_repair_peer_footprint();

  laddr               = fd_ulong_align_up( laddr, fd_repair_req_align() );
  replay->repair_reqs = fd_repair_req_new( (void *)laddr );
  laddr += fd_repair_req_footprint();

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
  replay_->pending      = fd_replay_pending_join( replay_->pending );
  // replay_->fec_resolver = fd_fec_resolver_join( replay_->fec_resolver );
  replay_->repair_peers = fd_repair_peer_join( replay_->repair_peers );
  replay_->repair_reqs  = fd_repair_req_join( replay_->repair_reqs );

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
fd_replay_shred_insert( fd_replay_t * replay, fd_shred_t const * shred ) {
  fd_shred_key_t    key = { .slot = shred->slot, .idx = shred->idx };
  fd_repair_req_t * req = fd_repair_req_query( replay->repair_reqs, key, NULL );
  if( FD_LIKELY( req ) ) { /*  shred came from turbine, req was evicted, etc. */
    fd_repair_req_remove( replay->repair_reqs, req );
  }

  fd_blockstore_t * blockstore = replay->blockstore;

  fd_blockstore_start_read( blockstore );
  /* TODO remove this check when we can handle duplicate shreds */
  if( fd_blockstore_block_query( blockstore, shred->slot ) != NULL ) {
    fd_blockstore_end_read( blockstore );
    return;
  }
  fd_blockstore_end_read( blockstore );

  fd_blockstore_start_write( blockstore );
  int rc = fd_blockstore_shred_insert( blockstore, NULL, shred );
  if( FD_UNLIKELY( rc != FD_BLOCKSTORE_OK ) ) FD_LOG_ERR( ( "failed to insert shred" ) );
  fd_blockstore_end_write( blockstore );
}

fd_replay_slot_ctx_t *
fd_replay_slot_prepare( fd_replay_t *  replay,
                        ulong          slot,
                        uchar const ** block_out,
                        ulong *        block_sz_out ) {
  fd_blockstore_start_read( replay->blockstore );

  fd_blockstore_block_t * block = fd_blockstore_block_query( replay->blockstore, slot );

  /* The caller expects this slot to have a complete block, but it doesn't, so try to repair it.
     This can happen if a slot was removed or we noticed from another data source (eg. gossip votes)
     that we're missing a block. In normal conditions, `fd_replay_slot_prepare` is only called after
     receiving all the shreds for slot. */
  if( FD_LIKELY( !block ) ) {
    fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( replay->blockstore, slot );

    if( FD_LIKELY( !slot_meta ) ) { /* new slot */
      if( FD_LIKELY( upsert_repair_req( replay, slot, FD_SHRED_IDX_NULL ) ) ) {
        fd_repair_peer_t * peer = fd_replay_repair_peer_sample( replay );
        if( NULL != peer ) {
          FD_LOG_DEBUG( ( "requesting highest shred %lu from %32J", slot, &peer->id ) );
          fd_repair_need_highest_window_index( replay->repair, &peer->id, slot, 0 );
        }
      }
    } else { /* existing slot, fill in remaining shreds */
      // FIXME

      fd_repair_peer_t * peer = fd_replay_repair_peer_sample( replay );
      if( NULL == peer ) return NULL;
      for( ulong i = slot_meta->consumed; i <= slot_meta->last_index; i++ ) {
        if( FD_LIKELY( upsert_repair_req( replay, slot, (uint)i ) ) ) {
          FD_LOG_DEBUG( ( "requesting shred %lu %lu", slot, i ) );
          fd_repair_need_window_index( replay->repair, &peer->id, slot, (uint)i );
        }
      }
    }

    fd_replay_pending_push_tail( replay->pending, slot );

    fd_blockstore_end_read( replay->blockstore );
    return NULL;
  }

  if( FD_UNLIKELY( fd_uint_extract_bit( block->flags, FD_BLOCKSTORE_BLOCK_FLAG_EXECUTED ) ) ) {
    fd_blockstore_end_read( replay->blockstore );
    return NULL;
  }

  ulong parent_slot = fd_blockstore_slot_parent_query( replay->blockstore, slot );

  /* If the parent block is missing, this block is an orphan and the ancestry needs to be repaired
   * before we can replay it. */
  if( FD_UNLIKELY( !fd_blockstore_block_query( replay->blockstore, parent_slot ) ) ) {
    fd_repair_peer_t * peer = fd_replay_repair_peer_sample( replay );
    if( FD_LIKELY( NULL != peer && upsert_repair_req( replay, slot, FD_SHRED_IDX_NULL ) ) ) {
      fd_repair_need_orphan( replay->repair, &peer->id, slot );
    }

    fd_replay_pending_push_tail( replay->pending, slot );

    fd_blockstore_end_read( replay->blockstore );
    return NULL;
  }

  fd_replay_slot_ctx_t * parent =
      fd_replay_frontier_ele_query( replay->frontier, &parent_slot, NULL, replay->pool );

  /* If parent isn't in the frontier, that means this block is starting a new fork and the
   * parent needs to be added to the frontier. This requires rolling back to that txn in
   * funk, and then inserting it into the frontier. */

  if( FD_UNLIKELY( !parent ) ) {
    /* Alloc a new slot_ctx */
    parent       = fd_replay_pool_ele_acquire( replay->pool );
    parent->slot = parent_slot;

    /* Format and join the slot_ctx */
    fd_exec_slot_ctx_t * slot_ctx =
        fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &parent->slot_ctx ) );
    if( FD_UNLIKELY( !slot_ctx ) ) { FD_LOG_ERR( ( "failed to new and join slot_ctx" ) ); }

    /* Restore and decode w/ funk */
    fd_replay_slot_ctx_restore( replay, parent->slot, slot_ctx );

    /* Add to frontier */
    fd_replay_frontier_ele_insert( replay->frontier, parent, replay->pool );
  }

  /* Prepare the replay_slot struct. */
  *block_out    = fd_blockstore_block_data_laddr( replay->blockstore, block );
  *block_sz_out = block->sz;

  /* Block data ptr remains valid outside of the rw lock for the lifetime of the block alloc. */
  fd_blockstore_end_read( replay->blockstore );

  /* Mark the block as prepared, and thus unsafe to remove. */
  fd_blockstore_start_write( replay->blockstore );
  block->flags = fd_uint_set_bit( block->flags, FD_BLOCKSTORE_BLOCK_FLAG_PREPARED );
  fd_blockstore_end_write( replay->blockstore );

  return parent;
}

void
fd_replay_slot_execute( fd_replay_t *          replay,
                        ulong                  slot,
                        fd_replay_slot_ctx_t * parent_slot_ctx,
                        uchar const *          block,
                        ulong                  block_sz ) {
  ulong txn_cnt                            = 0;
  parent_slot_ctx->slot_ctx.slot_bank.slot = slot;
  FD_TEST( fd_runtime_block_eval_tpool( &parent_slot_ctx->slot_ctx,
                                        NULL,
                                        block,
                                        block_sz,
                                        replay->tpool,
                                        replay->max_workers,
                                        1,
                                        &txn_cnt ) == FD_RUNTIME_EXECUTE_SUCCESS );
  (void)txn_cnt;

  fd_blockstore_start_write( replay->blockstore );
  fd_blockstore_block_t * block_ = fd_blockstore_block_query( replay->blockstore, slot );
  if( FD_LIKELY( block_ ) ) {
    block_->flags = fd_uint_set_bit( block_->flags, FD_BLOCKSTORE_BLOCK_FLAG_EXECUTED );
  }
  fd_blockstore_end_write( replay->blockstore );

  /* Re-key the replay_slot_ctx to be the slot of the block we just executed. */
  fd_replay_slot_ctx_t * child_slot_ctx =
      fd_replay_frontier_ele_remove( replay->frontier, &parent_slot_ctx->slot, NULL, replay->pool );
  child_slot_ctx->slot = slot;
  if( FD_UNLIKELY( fd_replay_frontier_ele_query( replay->frontier, &slot, NULL, replay->pool ) ) ) {
    FD_LOG_ERR( ( "invariant violation: child slot %lu was already in the frontier", slot ) );
  }
  fd_replay_frontier_ele_insert( replay->frontier, child_slot_ctx, replay->pool );

  /* FIXME remove this hack once we have turbine */
  fd_replay_pending_push_tail( replay->pending, slot + 1 );

  /* Prepare bank for next execution. */
  parent_slot_ctx->slot_ctx.slot_bank.slot           = slot;
  parent_slot_ctx->slot_ctx.slot_bank.collected_fees = 0;
  parent_slot_ctx->slot_ctx.slot_bank.collected_rent = 0;

  FD_LOG_NOTICE( ( "slot: %lu", slot ) );
  FD_LOG_NOTICE( ( "bank hash: %32J", child_slot_ctx->slot_ctx.slot_bank.banks_hash.hash ) );

  //   fd_vote_accounts_pair_t_mapnode_t * vote_accounts_pool =
  //   bank->epoch_stakes.vote_accounts_pool; fd_vote_accounts_pair_t_mapnode_t *
  //   vote_accounts_root = bank->epoch_stakes.vote_accounts_root;

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
  //           fd_replay_commitment_query( replay->commitment, slot - landed_vote->latency, NULL
  //           );
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

void
fd_replay_slot_ctx_restore( fd_replay_t * replay, ulong slot, fd_exec_slot_ctx_t * slot_ctx ) {
  fd_funk_txn_t *   txn_map    = fd_funk_txn_map( replay->funk, fd_funk_wksp( replay->funk ) );
  fd_hash_t const * block_hash = fd_blockstore_block_hash_query( replay->blockstore, slot );
  if( !block_hash ) FD_LOG_ERR( ( "missing block hash of slot we're trying to restore" ) );
  fd_funk_txn_xid_t xid;
  fd_memcpy( xid.uc, block_hash, sizeof( fd_funk_txn_xid_t ) );
  xid.ul[0] = slot;
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
fd_replay_turbine_rx( fd_replay_t * replay, fd_shred_t const * shred ) {
  if( FD_UNLIKELY( replay->turbine_slot == FD_SLOT_NULL ) ) {
    replay->turbine_slot = shred->slot;
    fd_replay_pending_push_tail( replay->pending, shred->slot );
  }
  FD_LOG_NOTICE( ( "inserting" ) );
  fd_replay_shred_insert( replay, shred );
}

void
fd_replay_repair_rx( fd_replay_t * replay, fd_shred_t const * shred ) {
  fd_shred_key_t    key = { .slot = shred->slot, .idx = shred->idx };
  fd_repair_req_t * req = fd_repair_req_query( replay->repair_reqs, key, NULL );
  if( FD_LIKELY( req ) ) fd_repair_req_remove( replay->repair_reqs, req );
  replay->repair_req_cnt--;
  fd_replay_shred_insert( replay, shred );
}

// #define GET_PEER
//   fd_repair_peer_t * peer = peers[repair_ctx->peer_iter % peer_cnt];
//   repair_ctx->peer_iter += 17077
fd_repair_peer_t *
fd_replay_repair_peer_sample( fd_replay_t * replay ) {
  for( ulong i = 0; i < fd_repair_peer_slot_cnt(); i++ ) {
    fd_repair_peer_t * peer = &replay->repair_peers[i];
    if( fd_repair_peer_key_inval( peer->id ) ) continue;
    // if( peer->request_cnt > 100U && peer->reply_cnt * 3U < peer->request_cnt ) {
    //   continue; /* 2/3 fails */
    // }
    return peer;
  }
  return NULL;
}

static int
upsert_repair_req( fd_replay_t * replay, ulong slot, uint shred_idx ) {
  fd_shred_key_t    key = { .slot = slot, .idx = shred_idx };
  fd_repair_req_t * req = fd_repair_req_query( replay->repair_reqs, key, NULL );
  long              now = fd_log_wallclock();
  if( FD_LIKELY( !req ) ) {
    /* TODO use dlist for time-based eviction */
    if( FD_UNLIKELY( replay->repair_req_cnt == fd_repair_req_slot_cnt() ) ) {
      ulong i = fd_rng_ulong( replay->rng );
      fd_repair_req_remove( replay->repair_reqs, &replay->repair_reqs[i] );
      replay->repair_req_cnt--;
    }
    req = fd_repair_req_insert( replay->repair_reqs, key );
    replay->repair_req_cnt++;
    req->ts  = 0;
    req->cnt = 0;
  }
  if( FD_LIKELY( ( now - req->ts ) > (long)100e6 ) ) {
    req->ts = now;
    req->cnt++;
    return 1;
  }
  return 0;
}
