#include "fd_replay.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"

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
  ulong laddr               = (ulong)mem;
  laddr                     = fd_ulong_align_up( laddr, alignof( fd_replay_t ) );
  fd_replay_t * replay      = (void *)laddr;
  replay->smr               = FD_SLOT_NULL;
  replay->snapshot_slot     = FD_SLOT_NULL;
  replay->first_turbine_slot = FD_SLOT_NULL;
  replay->curr_turbine_slot  = 0;

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

  laddr           = fd_ulong_align_up( laddr, alignof( long ) );
  replay->pending = (long *)laddr;
  laddr += sizeof( long )*FD_REPLAY_PENDING_MAX;
  replay->pending_start = 0;
  replay->pending_end = 0;
  replay->pending_lock = 0;

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
  replay_->pool         = fd_replay_pool_join( replay_->pool );
  replay_->frontier     = fd_replay_frontier_join( replay_->frontier );
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
  for(;;) {
    if( FD_LIKELY( !FD_ATOMIC_CAS( &replay->pending_lock, 0UL, 1UL) ) ) break;
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
  
  long when = replay->now + delay;
  long * pending = replay->pending;
  if( replay->pending_start == replay->pending_end ) {
    /* Queue is empty */
    replay->pending_start = slot;
    replay->pending_end = slot+1U;
    pending[slot & FD_REPLAY_PENDING_MASK] = when;
    
  } else if ( slot < replay->pending_start ) {
    /* Grow down */
    if( replay->pending_end - slot > FD_REPLAY_PENDING_MAX )
      FD_LOG_ERR(( "pending queue overrun: start=%lu, end=%lu, new slot=%lu", replay->pending_start, replay->pending_end, slot ));
    pending[slot & FD_REPLAY_PENDING_MASK] = when;
    for( ulong i = slot+1; i < replay->pending_start; ++i ) {
      /* Zero fill */
      pending[i & FD_REPLAY_PENDING_MASK] = 0;
    }
    replay->pending_start = slot;

  } else if ( slot >= replay->pending_end ) {
    /* Grow up */
    if( slot - replay->pending_start > FD_REPLAY_PENDING_MAX )
      FD_LOG_ERR(( "pending queue overrun: start=%lu, end=%lu, new slot=%lu", replay->pending_start, replay->pending_end, slot ));
    pending[slot & FD_REPLAY_PENDING_MASK] = when;
    for( ulong i = replay->pending_end; i < slot; ++i ) {
      /* Zero fill */
      pending[i & FD_REPLAY_PENDING_MASK] = 0;
    }
    replay->pending_end = slot+1U;

  } else {
    /* Update in place */
    long * p = &pending[slot & FD_REPLAY_PENDING_MASK];
    if( 0 == *p || *p > when )
      *p = when;
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
  for( i = fd_ulong_max(i, replay->pending_start); 1; ++i ) {
    if( i >= end ) {
      /* End sentinel */
      i = ULONG_MAX;
      break;
    }
    long * ele = &replay->pending[ i & FD_REPLAY_PENDING_MASK ];
    if( i <= replay->smr || *ele == 0 ) {
      /* Empty or useless slot */
      if( replay->pending_start == i )
        replay->pending_start = i+1U; /* Pop it */
    } else if( *ele <= now ) {
      /* Do this slot */
      long when = *ele;
      *ele = 0;
      if( replay->pending_start == i )
        replay->pending_start = i+1U; /* Pop it */
      FD_LOG_DEBUG(( "preparing slot %lu when=%ld now=%ld latency=%ld",
                     i, when, now, now - when ));
      break;
    }
  }
  fd_replay_pending_unlock( replay );
  return i;
}

#define FD_SHRED_PCAP_OK 0
#define FD_SHRED_PCAP_ERR -1

int
fd_replay_shred_logging( fd_replay_t * replay, fd_shred_t const * shred ) {
  if ( replay->shred_log_fd == NULL ) return 0;
  ulong n = fwrite( shred, fd_shred_sz(shred), 1UL, replay->shred_log_fd);

  if ( FD_UNLIKELY( n != 1UL ) ) {
    FD_LOG_WARNING(( "failed at logging shred idx=%d for slot#%d", shred->idx, shred->slot ));
    return FD_SHRED_PCAP_ERR;
  } else {
    FD_LOG_NOTICE ( ( "logging shred idx=%d for slot#%u", shred->idx, shred->slot ) );
    return FD_SHRED_PCAP_OK;
  }
}

int
fd_replay_shred_insert( fd_replay_t * replay, fd_shred_t const * shred ) {
  fd_blockstore_t * blockstore = replay->blockstore;

  fd_blockstore_start_write( blockstore );
  /* TODO remove this check when we can handle duplicate shreds and blocks */
  if( fd_blockstore_block_query( blockstore, shred->slot ) != NULL ) {
    fd_blockstore_end_write( blockstore );
    return FD_BLOCKSTORE_OK;
  }
  int rc = fd_blockstore_shred_insert( blockstore, shred );

  /* TODO @yunzhang: write to pcap */
  fd_replay_shred_logging(replay, shred);

  fd_blockstore_end_write( blockstore );

  /* FIXME */
  if( FD_UNLIKELY( rc < FD_BLOCKSTORE_OK ) ) {
    FD_LOG_ERR( ( "failed to insert shred. reason: %d", rc ) );
  } else if ( rc == FD_BLOCKSTORE_OK_SLOT_COMPLETE ) {
    fd_replay_add_pending( replay, shred->slot, 0 );
  } else {
    fd_replay_add_pending( replay, shred->slot, FD_REPAIR_BACKOFF_TIME );
  }
  return rc;
}

fd_replay_slot_ctx_t *
fd_replay_slot_prepare( fd_replay_t *  replay,
                        ulong          slot,
                        uchar const ** block_out,
                        ulong *        block_sz_out ) {
  fd_blockstore_start_read( replay->blockstore );

  ulong re_adds[2];
  uint re_adds_cnt = 0;

  fd_block_t * block = fd_blockstore_block_query( replay->blockstore, slot );

  /* We already executed this block */
  if( FD_UNLIKELY( block && fd_uint_extract_bit( block->flags, FD_BLOCK_FLAG_EXECUTED ) ) ) goto end;

  fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( replay->blockstore, slot );

  if( FD_UNLIKELY( !slot_meta ) ) {
    /* I know nothing about this block yet */
    fd_replay_slot_repair( replay, slot );
    re_adds[re_adds_cnt++] = slot;
    goto end;
  }

  ulong            parent_slot  = slot_meta->parent_slot;
  fd_slot_meta_t * parent_slot_meta =
    fd_blockstore_slot_meta_query( replay->blockstore, parent_slot );

  /* If the parent slot meta is missing, this block is an orphan and the ancestry needs to be
   * repaired before we can replay it. */
  if( FD_UNLIKELY( !parent_slot_meta ) ) {
    fd_repair_need_orphan( replay->repair, slot );
    re_adds[re_adds_cnt++] = slot;
    re_adds[re_adds_cnt++] = parent_slot;
    goto end;
  }

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

  /* See if the parent is executed yet */
  if( FD_UNLIKELY( !fd_uint_extract_bit( parent_block->flags, FD_BLOCK_FLAG_EXECUTED ) ) ) {
    re_adds[re_adds_cnt++] = slot;
    re_adds[re_adds_cnt++] = parent_slot;
    goto end;
  }

  /* The parent is executed, but the block is still incomplete. Ask for more shreds. */
  if( FD_UNLIKELY( !block ) ) {
    fd_replay_slot_repair( replay, slot );
    re_adds[re_adds_cnt++] = slot;
    goto end;
  }

  /* Query for the parent in the frontier */
  fd_replay_slot_ctx_t * parent =
      fd_replay_frontier_ele_query( replay->frontier, &parent_slot, NULL, replay->pool );

  /* If the parent block is both present and executed (see earlier conditionals), but isn't in the
     frontier, that means this block is starting a new fork and the parent needs to be added to the
     frontier. This requires rolling back to that txn in funk, and then inserting it into the
     frontier. */

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

  /* Mark the block as prepared, and thus unsafe to remove. */
  block->flags = fd_uint_set_bit( block->flags, FD_BLOCK_FLAG_PREPARED );

  /* Block data ptr remains valid outside of the rw lock for the lifetime of the block alloc. */
  fd_blockstore_end_read( replay->blockstore );

  for (uint i = 0; i < re_adds_cnt; ++i)
    fd_replay_add_pending( replay, re_adds[i], FD_REPAIR_BACKOFF_TIME );

  return parent;

end:
  fd_blockstore_end_read( replay->blockstore );

  for (uint i = 0; i < re_adds_cnt; ++i)
    fd_replay_add_pending( replay, re_adds[i], FD_REPAIR_BACKOFF_TIME );

  return NULL;
}

void
fd_replay_slot_execute( fd_replay_t *          replay,
                        ulong                  slot,
                        fd_replay_slot_ctx_t * parent,
                        uchar const *          block,
                        ulong                  block_sz ) {
  ulong txn_cnt                   = 0;
  parent->slot_ctx.slot_bank.slot = slot;
  FD_TEST( fd_runtime_block_eval_tpool( &parent->slot_ctx,
                                        NULL,
                                        block,
                                        block_sz,
                                        replay->tpool,
                                        replay->max_workers,
                                        1,
                                        &txn_cnt ) == FD_RUNTIME_EXECUTE_SUCCESS );
  (void)txn_cnt;

  fd_blockstore_start_write( replay->blockstore );
  
  fd_block_t * block_ = fd_blockstore_block_query( replay->blockstore, slot );
  if( FD_LIKELY( block_ ) ) {
    block_->flags = fd_uint_set_bit( block_->flags, FD_BLOCK_FLAG_EXECUTED );
    memcpy( &block_->bank_hash, &parent->slot_ctx.slot_bank.banks_hash, sizeof( fd_hash_t ) );
  }

  fd_blockstore_end_write( replay->blockstore );

  /* Re-key the replay_slot_ctx to be the slot of the block we just executed. */
  fd_replay_slot_ctx_t * child =
      fd_replay_frontier_ele_remove( replay->frontier, &parent->slot, NULL, replay->pool );
  child->slot = slot;
  if( FD_UNLIKELY( fd_replay_frontier_ele_query( replay->frontier, &slot, NULL, replay->pool ) ) ) {
    FD_LOG_ERR( ( "invariant violation: child slot %lu was already in the frontier", slot ) );
  }
  fd_replay_frontier_ele_insert( replay->frontier, child, replay->pool );

  /* Prepare bank for next execution. */
  child->slot_ctx.slot_bank.slot           = slot;
  child->slot_ctx.slot_bank.collected_fees = 0;
  child->slot_ctx.slot_bank.collected_rent = 0;

  FD_LOG_NOTICE( ( "slot: %lu", slot ) );
  FD_LOG_NOTICE( ( "first turbine: %lu, curr turbine: %lu, behind: %lu",
                   replay->first_turbine_slot,
                   replay->curr_turbine_slot,
                   replay->curr_turbine_slot - slot ) );
  FD_LOG_NOTICE( ( "bank hash: %32J", child->slot_ctx.slot_bank.banks_hash.hash ) );

  fd_vote_bank_match_check( child->slot_ctx.epoch_ctx->bank_matches, slot, &child->slot_ctx.slot_bank.banks_hash, 1 );
  

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
fd_replay_slot_repair( fd_replay_t * replay, ulong slot ) {
  fd_slot_meta_t * slot_meta = fd_blockstore_slot_meta_query( replay->blockstore, slot );

  if( fd_blockstore_is_slot_ancient( replay->blockstore, slot ) ) {
    FD_LOG_ERR(( "repair is hopelessly behind by %lu slots, max history is %lu",
                 replay->blockstore->max - slot, replay->blockstore->slot_max ));
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

    /* First make sure we are ready to execute this blook soon. Look for an ancestor that was executed. */
    ulong anc_slot = slot;
    int good = 0;
    for( uint i = 0; i < 3; ++i ) {
      anc_slot  = fd_blockstore_slot_parent_query( replay->blockstore, anc_slot );
      fd_block_t * anc_block = fd_blockstore_block_query( replay->blockstore, anc_slot );
      if( anc_block && fd_uint_extract_bit( anc_block->flags, FD_BLOCK_FLAG_EXECUTED ) ) {
        good = 1;
        break;
      }
    }
    if( !good ) return;
    
    /* Fill in what's missing */
    ulong cnt = 0;
    for( ulong i = slot_meta->consumed + 1; i <= last_index; i++ ) {
      if( fd_blockstore_shred_query( replay->blockstore, slot, (uint)i ) != NULL ) continue;
      if( fd_repair_need_window_index( replay->repair, slot, (uint)i ) > 0 )
        ++cnt;
    }
    if( cnt )
      FD_LOG_NOTICE( ( "[repair] need %lu [%lu, %lu], sent %lu requests", slot, slot_meta->consumed + 1, last_index, cnt ) );
  }
}

void
fd_replay_slot_ctx_restore( fd_replay_t * replay, ulong slot, fd_exec_slot_ctx_t * slot_ctx ) {
  fd_funk_txn_t *   txn_map    = fd_funk_txn_map( replay->funk, fd_funk_wksp( replay->funk ) );
  fd_hash_t const * block_hash = fd_blockstore_block_hash_query( replay->blockstore, slot );
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

  FD_TEST( fd_slot_bank_decode( &slot_ctx->slot_bank, &ctx ) == FD_BINCODE_SUCCESS );
  FD_TEST( !fd_runtime_sysvar_cache_load( slot_ctx ) );
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
fd_replay_turbine_rx( fd_replay_t * replay, fd_shred_t const * shred, ulong shred_sz ) {
  FD_LOG_DEBUG( ( "[turbine] received shred - type: %x slot: %lu idx: %u",
                  fd_shred_type( shred->variant ) & FD_SHRED_TYPEMASK_DATA,
                  shred->slot,
                  shred->idx ) );
  fd_pubkey_t const *  leader = fd_epoch_leaders_get( replay->epoch_ctx->leaders, shred->slot );
  fd_fec_set_t const * out_fec_set = NULL;
  fd_shred_t const *   out_shred   = NULL;
  int                  rc          = fd_fec_resolver_add_shred(
      replay->fec_resolver, shred, shred_sz, leader->uc, &out_fec_set, &out_shred );
  if( rc == FD_FEC_RESOLVER_SHRED_COMPLETES ) {
    if( FD_UNLIKELY( replay->first_turbine_slot == FD_SLOT_NULL ) ) {
      replay->first_turbine_slot = shred->slot;
    }
    fd_shred_t * parity_shred = (fd_shred_t *)fd_type_pun( out_fec_set->parity_shreds[0] );
    FD_LOG_DEBUG( ( "slot: %lu. parity: %lu. data: %lu",
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
      FD_LOG_DEBUG(
          ( "[turbine] rx shred - slot: %lu idx: %u", slot, data_shred->idx ) );
      int rc = fd_blockstore_shred_insert( blockstore, data_shred );
      /* TODO @yunzhang: write to pcap */
      fd_replay_shred_logging(replay, data_shred);

      if( FD_UNLIKELY( rc == FD_BLOCKSTORE_OK_SLOT_COMPLETE ) ) {
        if( FD_UNLIKELY( replay->first_turbine_slot == FD_SLOT_NULL ) ) { replay->first_turbine_slot = slot; }
        replay->curr_turbine_slot = fd_ulong_max(slot, replay->curr_turbine_slot);
        FD_LOG_NOTICE(( "[turbine] slot %lu complete", slot ));
        
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
  fd_replay_shred_insert( replay, shred );
}
