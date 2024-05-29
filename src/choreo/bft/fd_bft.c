#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/fd_borrowed_account.h"
#include "../../flamenco/runtime/program/fd_program_util.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"

#include "../fd_choreo_base.h"
#include "../ghost/fd_ghost.h"
#include "../tower/fd_tower.h"
#include "fd_bft.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

void *
fd_bft_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_bft_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_bft_footprint();
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING( ( "bad mem" ) );
    return NULL;
  }

  return shmem;
}

fd_bft_t *
fd_bft_join( void * shbft ) {

  if( FD_UNLIKELY( !shbft ) ) {
    FD_LOG_WARNING( ( "NULL bft" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shbft, fd_bft_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned bft" ) );
    return NULL;
  }

  return (fd_bft_t *)shbft;
}

void *
fd_bft_leave( fd_bft_t const * bft ) {

  if( FD_UNLIKELY( !bft ) ) {
    FD_LOG_WARNING( ( "NULL bft" ) );
    return NULL;
  }

  return (void *)bft;
}

void *
fd_bft_delete( void * bft ) {

  if( FD_UNLIKELY( !bft ) ) {
    FD_LOG_WARNING( ( "NULL bft" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)bft, fd_bft_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned bft" ) );
    return NULL;
  }

  return bft;
}

static ulong
query_pubkey_stake( fd_pubkey_t const * pubkey, fd_vote_accounts_t * vote_accounts ) {
  fd_vote_accounts_pair_t_mapnode_t key         = { 0 };
  key.elem.key                                  = *pubkey;
  fd_vote_accounts_pair_t_mapnode_t * vote_node = fd_vote_accounts_pair_t_map_find(
      vote_accounts->vote_accounts_pool, vote_accounts->vote_accounts_root, &key );
  return vote_node ? vote_node->elem.stake : 0;
}

static void
count_replay_votes( fd_bft_t * bft, fd_fork_t * fork ) {
  FD_PARAM_UNUSED long now = fd_log_wallclock();

  fd_latest_vote_t * latest_votes = fork->slot_ctx.latest_votes;

  // fd_root_vote_t *   root_votes   = bft->root_votes;

  ulong vote_cnt = 0;
  // ulong smr      = bft->smr;

  for( fd_latest_vote_deque_iter_t iter = fd_latest_vote_deque_iter_init( latest_votes );
       !fd_latest_vote_deque_iter_done( latest_votes, iter );
       iter = fd_latest_vote_deque_iter_next( latest_votes, iter ) ) {
    FD_PARAM_UNUSED long tic = fd_log_wallclock();

    // long total_tic = fd_log_wallclock();

    fd_latest_vote_t *  latest_vote = fd_latest_vote_deque_iter_ele( latest_votes, iter );
    fd_pubkey_t const * node_pubkey = &latest_vote->node_pubkey;

    // FD_BORROWED_ACCOUNT_DECL( vote_account );
    // long view_tic = fd_log_wallclock();
    // rc = fd_acc_mgr_view( bft->acc_mgr, fork->slot_ctx.funk_txn, node_pubkey, vote_account );
    // if( rc != FD_ACC_MGR_SUCCESS ) FD_LOG_ERR( ( "failed to view vote account" ) );
    // long view_toc = fd_log_wallclock();
    // if (view_toc - view_tic > 10000) {
    //   FD_LOG_NOTICE( ( "view took: %ld", view_toc - view_tic ) );
    // }

    // long decode_tic = fd_log_wallclock();
    // fd_bincode_decode_ctx_t decode_ctx = { .data    = vote_account->const_data,
    //                                        .dataend = vote_account->const_data +
    //                                                   vote_account->const_meta->dlen,
    //                                        .valloc = bft->valloc };

    // fd_vote_state_versioned_t versioned;
    // rc = fd_vote_state_versioned_decode( &versioned, &decode_ctx );
    // if( FD_UNLIKELY( rc != FD_BINCODE_SUCCESS ) ) FD_LOG_ERR( ( "failed to decode" ) );
    // fd_vote_convert_to_current( &versioned, bft->valloc );
    // fd_vote_state_t * vote_state = &versioned.inner.current;
    // long decode_toc = fd_log_wallclock();
    // if( decode_toc - decode_tic > 10000 ) {
    //   FD_LOG_NOTICE( ( "decode took: %ld", decode_toc - decode_tic ) );
    // }

    // fd_landed_vote_t * vote      = deq_fd_landed_vote_t_peek_tail( vote_state->votes );
    // ulong              vote_slot = vote->lockout.slot;

    ulong vote_slot = latest_vote->slot_hash.slot;

    /* Ignore votes for slots < smr. */

    if( FD_UNLIKELY( vote_slot <= bft->smr ) ) continue;

    /* Look up _our_ bank hash for this vote. Note, because these are replay votes that come from
       the vote program, the bank hashes must match. */

    fd_blockstore_start_read( bft->blockstore );
    fd_hash_t const * bank_hash = fd_blockstore_bank_hash_query( bft->blockstore, vote_slot );
    fd_blockstore_end_read( bft->blockstore );

#if FD_BFT_USE_HANDHOLDING
    /* This indicates a programming error, because if these are replay votes that were successfully
       executed by the vote program that should imply the vote program attempts to look up the bank
       hash the vote is voting on). This invariant is broken if the bank hash is missing. */
    // if( FD_UNLIKELY( !bank_hash ) ) FD_LOG_ERR( ( "missing bank hash %lu", vote_slot ) );
    if( FD_UNLIKELY( !bank_hash ) ) __asm__( "int $3" );
#endif

    /* Look up the stake for this pubkey. */

    ulong stake = query_pubkey_stake( node_pubkey,
                                      &fork->slot_ctx.epoch_ctx->epoch_bank.stakes.vote_accounts );

    // FD_LOG_NOTICE( ( "[1] took %.1lf us", (double)( fd_log_wallclock() - tic ) / 1e3 ) );

    /* Look up the ghost node. */

    fd_slot_hash_t    slot_hash  = { .slot = vote_slot, .hash = *bank_hash };
    fd_ghost_node_t * ghost_node = fd_ghost_node_query( bft->ghost, &slot_hash );

#if FD_BFT_USE_HANDHOLDING
    /* This indicates a programming error, because the slot hash must have been inserted if we are
     * processesing replay votes. */
    if( FD_UNLIKELY( !ghost_node ) ) {
      FD_LOG_ERR( ( "missing ghost key %lu %32J", slot_hash.slot, slot_hash.hash.hash ) );
    };
#endif

    /* Upsert the vote into ghost. */

    fd_ghost_replay_vote_upsert( bft->ghost, &slot_hash, node_pubkey, stake );

    // FD_LOG_NOTICE( ( "[2] took %.1lf us", (double)( fd_log_wallclock() - tic ) / 1e3 ) );

    /* Check this slot's stake pct in ghost, and mark stake threshold accordingly if reached. */

    double pct = (double)ghost_node->stake / (double)bft->epoch_stake;

    if( FD_UNLIKELY( !ghost_node->eqv_safe && pct > FD_BFT_EQV_SAFE ) ) {
      ghost_node->eqv_safe = 1;
#if FD_BFT_USE_HANDHOLDING
      // FD_LOG_NOTICE(
      //     ( "[bft] eqv safe (%lf): (%lu, %32J)", pct, slot_hash.slot, slot_hash.hash.hash ) );
#endif
    }

    if( FD_UNLIKELY( !ghost_node->opt_conf && pct > FD_BFT_OPT_CONF ) ) {
      ghost_node->opt_conf = 1;
#if FD_BFT_USE_HANDHOLDING
      // FD_LOG_NOTICE(
      //     ( "[bft] opt conf (%lf): (%lu, %32J)", pct, slot_hash.slot, slot_hash.hash.hash ) );
#endif
    }

//     /* Only process vote slots higher than our SMR. */

//     if( FD_LIKELY( latest_vote->root > bft->smr ) ) {

//       /* Find the previous root vote by node pubkey. */

//       fd_root_vote_t * prev_root_vote =
//           fd_root_vote_map_query( root_votes, latest_vote->node_pubkey, NULL );

//       if( FD_UNLIKELY( !prev_root_vote ) ) {

//         /* This node pubkey has not yet voted. */

//         prev_root_vote = fd_root_vote_map_insert( root_votes, latest_vote->node_pubkey );
//       } else {

//         /* Subtract the stake from the ancestry beginning from previous vote's root. */

//         ulong ancestor = prev_root_vote->root;
//         while( ancestor > bft->smr ) {
//           // FD_LOG_NOTICE( ( "ancestor: %lu", ancestor ) );
//           fd_slot_commitment_t * ancestor_slot_commitment =
//               fd_slot_commitment_map_query( bft->slot_commitments, ancestor, NULL );
//           if( FD_LIKELY( ancestor_slot_commitment ) )
//             ancestor_slot_commitment->rooted_stake -= stake;
//           ancestor = fd_blockstore_parent_slot_query( bft->blockstore, ancestor );

// #if FD_BFT_USE_HANDHOLDING
//           /* this validator has a different ancestry back to our SMR. */
//           if( FD_UNLIKELY( ancestor == FD_SLOT_NULL ) ) __asm__( "int $3" );
// #endif
//         }
//       }

//       /* Update our bookkeeping of this node pubkey's root. */

//       prev_root_vote->root = latest_vote->root;

//       /* Add this node pubkey's stake to all slots in the ancestry back to the SMR. */

//       ulong ancestor = latest_vote->root;
//       while( ancestor > bft->smr ) {
//         fd_slot_commitment_t * slot_commitment =
//             fd_slot_commitment_map_query( bft->slot_commitments, ancestor, NULL );
//         if( FD_UNLIKELY( !slot_commitment ) ) {
//           slot_commitment = fd_slot_commitment_map_insert( bft->slot_commitments, ancestor );
//         }
//         slot_commitment->rooted_stake += stake;

//         double pct = (double)slot_commitment->rooted_stake / (double)bft->epoch_stake;
//         if( FD_UNLIKELY( pct > FD_BFT_SMR && !slot_commitment->finalized ) ) {
//           FD_LOG_NOTICE( ( "new SMR: %lu (%lf)", ancestor, pct ) );
//           smr                        = fd_ulong_max( ancestor, smr );
//           slot_commitment->finalized = 1;
//         }

//         fd_blockstore_start_read( bft->blockstore );
//         ancestor = fd_blockstore_parent_slot_query( bft->blockstore, ancestor );
//         fd_blockstore_end_read( bft->blockstore );
//       }
//     }

    // FD_LOG_NOTICE( ( "[3] took %.1lf us", (double)( fd_log_wallclock() - tic ) / 1e3 ) );

    vote_cnt++;
    // long total_toc = fd_log_wallclock();
    // FD_LOG_NOTICE(("total took: %ld", total_toc - total_tic));
    // FD_LOG_NOTICE(
    //     ( "[loop iteration] took %.1lf us", (double)( fd_log_wallclock() - tic ) / 1e3 ) );
  }
  FD_LOG_NOTICE( ( "processed %lu votes", vote_cnt ) );
  // FD_LOG_NOTICE(
  //     ( "[count_replay_votes] took %.2lf ms", (double)( fd_log_wallclock() - now ) / 1e6 ) );

  // if( FD_LIKELY( smr > bft->smr ) ) {
  //   // fd_bft_prune( bft, smr );
  //   fd_bft_smr_update( bft, smr );
  // }

  // FD_LOG_NOTICE(
  //     ( "[count_replay_votes] took %.2lf ms", (double)( fd_log_wallclock() - now ) / 1e6 ) );
}

FD_FN_UNUSED static void
count_gossip_votes( fd_bft_t *                    bft,
                    fd_latest_vote_t *            gossip_votes,
                    FD_PARAM_UNUSED fd_stakes_t * epoch_stakes ) {
  for( fd_latest_vote_deque_iter_t iter = fd_latest_vote_deque_iter_init( gossip_votes );
       !fd_latest_vote_deque_iter_done( gossip_votes, iter );
       iter = fd_latest_vote_deque_iter_next( gossip_votes, iter ) ) {

    fd_latest_vote_t * vote      = fd_latest_vote_deque_iter_ele( gossip_votes, iter );
    ulong              vote_slot = vote->slot_hash.slot;

    fd_hash_t const * bank_hash = fd_blockstore_bank_hash_query( bft->blockstore, vote_slot );
    if( FD_UNLIKELY( !bank_hash ) ) {
      /* TODO we need to implement repair logic here */
      FD_LOG_WARNING( ( "couldn't find bank hash for slot %lu", vote_slot ) );
      continue;
    }

    fd_slot_hash_t    slot_hash  = { .slot = vote_slot, .hash = *bank_hash };
    fd_ghost_node_t * ghost_node = fd_ghost_node_query( bft->ghost, &slot_hash );

#if FD_BFT_USE_HANDHOLDING
    /* This indicates a programming error, because the checks above should ensure slot hash is in
       ghost given we are using our own (slot, bank hash) that we just looked up in blockstore. */
    if( FD_UNLIKELY( !ghost_node ) ) {
      FD_LOG_ERR( ( "missing ghost key %lu %32J", slot_hash.slot, slot_hash.hash.hash ) );
    };
#endif

    if( FD_UNLIKELY( 0 != memcmp( bank_hash, &vote->slot_hash, sizeof( fd_hash_t ) ) ) ) {
      ghost_node->eqv = 1;

#if FD_BFT_USE_HANDHOLDING
      FD_LOG_WARNING( ( "eqv on slot: %lu. ours: %32J vs. theirs: %32J",
                        vote_slot,
                        bank_hash,
                        &vote->slot_hash.hash ) );
#endif

      continue;
    }

    // ulong stake = query_pubkey_stake( &vote->node_pubkey, epoch_stakes );
    // fd_ghost_gossip_vote_upsert( bft->ghost, &slot_hash, &vote->node_pubkey, stake );
  }
}

/* Update fork with the votes in the block. */
void
fd_bft_fork_update( fd_bft_t * bft, fd_fork_t * fork ) {
  FD_PARAM_UNUSED long now = fd_log_wallclock();

  fd_slot_bank_t * bank = &fork->slot_ctx.slot_bank;

  /* Update the current fork head's bft key. */

  fd_slot_hash_t curr_key = {
      .slot = fork->slot,
      .hash = bank->banks_hash,
  };

  /* Get the parent key. Every block must have a parent (except genesis or snapshot block). */

  fd_blockstore_start_read( bft->blockstore );
  ulong parent_slot = fd_blockstore_parent_slot_query( bft->blockstore, fork->slot );
  fd_blockstore_end_read( bft->blockstore );

  /* Insert this fork into bft. */

  if( FD_UNLIKELY( parent_slot == FD_SLOT_NULL ) ) {
    fd_ghost_leaf_insert( bft->ghost, &curr_key, NULL );
  } else {
    fd_blockstore_start_read( bft->blockstore );
    fd_hash_t const * parent_bank_hash =
        fd_blockstore_bank_hash_query( bft->blockstore, parent_slot );
    fd_blockstore_end_read( bft->blockstore );
    if( FD_UNLIKELY( !parent_bank_hash ) ) {
      __asm__("int $3");
      FD_LOG_ERR( ( "invariant violation: executed child before having parent bank hash." ) );
    }
    fd_slot_hash_t parent_key = {
        .slot = parent_slot,
        .hash = *parent_bank_hash,
    };
    fd_ghost_leaf_insert( bft->ghost, &curr_key, &parent_key );
  }

  /* Insert this fork into commitment. */

  // fd_slot_commitment_t * slot_commitment = fd_commitment_slot_insert( forks->commitment, slot );

  // fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( fork->slot_ctx.epoch_ctx );

  /* Count replay votes in this fork's block. */

  count_replay_votes( bft, fork );

  /* Count gossip votes received since the last process. */

  // count_gossip_votes( bft, fork->slot_ctx.latest_votes, &epoch_bank->stakes );

  /* Update slot commitment. */

  // fd_slot_commitment_t * slot_commitment = fd_commitment_slot_query( forks->commitment,
  // vote_state->root_slot ); if (FD_UNLIKELY( !slot_commitment )) {
  //   slot_commitment = fd_commitment_slot_insert( forks->commitment, vote_state->root_slot );

  // }
  // slot_commitment->finalized_stake += stake;

  // for( fd_landed_vote_t * landed_vote = deq_fd_landed_vote_t_peek_head( votes ); landed_vote;
  //      landed_vote                    = deq_fd_landed_vote_t_peek_next( votes, landed_vote )
  //      )
  //      {
  //   fd_replay_commitment_t * commitment =
  //       fd_commitment_slot_query( forks->commitment, slot - landed_vote->latency );
  //   if( FD_UNLIKELY( !commitment ) ) {
  //     commitment = fd_commitment_slot_insert( forks->commitment, slot - landed_vote->latency
  //     );
  //   }
  //   FD_TEST( landed_vote->lockout.confirmation_count < 32 ); // FIXME remove
  //   commitment->confirmed_stake[landed_vote->lockout.confirmation_count] += stake;
  // }

  // FD_LOG_NOTICE(
  //     ( "[fd_bft_fork_update] took %.2lf ms", (double)( fd_log_wallclock() - now ) / 1e6 ) );
}

fd_fork_t *
fd_bft_fork_choice( fd_bft_t * bft ) {
  long now = fd_log_wallclock();

  fd_ghost_t * ghost = bft->ghost;

  /* get the fork head. */

  fd_ghost_node_t * head = ghost->root->head;

  /* do not pick forks with equivocating blocks along its ancestry. */

  fd_ghost_node_t * ancestor = head;
  while( ancestor ) {
    if( FD_UNLIKELY( ancestor->eqv && !ancestor->eqv_safe ) ) return NULL;
    ancestor = ancestor->parent;
  }

  /* search for the fork head in the frontier. */

  fd_fork_t * fork = fd_fork_frontier_ele_query(
      bft->forks->frontier, &head->slot_hash.slot, NULL, bft->forks->pool );
#if FD_BFT_USE_HANDHOLDING
  /* the ghost head must exist in the frontier. */
  if( FD_UNLIKELY( !fork ) ) {
    FD_LOG_ERR( ( "missing fork head (%lu, %32J)", head->slot_hash.slot, &head->slot_hash.hash ) );
  }
#endif

  FD_LOG_NOTICE( ( "picked fork head: slot %lu", fork->slot ) );
  FD_LOG_NOTICE( ( "fork selection took %.2lf ms", (double)( fd_log_wallclock() - now ) / 1e6 ) );

  return fork;

  //   fd_slot_hash_t root = ghost->root;

  //   ulong            heaviest_fork_weight = 0;
  //   fd_slot_hash_t * heaviest_fork_key    = NULL;

  //   /* query every fork in the frontier to retrieve the heaviest bank */

  //   fd_fork_frontier_t * frontier = bft->forks->frontier;
  //   fd_fork_t *          pool     = bft->forks->pool;
  //   for( fd_fork_frontier_iter_t iter = fd_fork_frontier_iter_init( frontier, pool );
  //        !fd_fork_frontier_iter_done( iter, frontier, pool );
  //        iter = fd_fork_frontier_iter_next( iter, frontier, pool ) ) {

  //     fd_fork_t * fork = fd_fork_frontier_iter_ele( iter, frontier, pool );

  //     fd_slot_hash_t    key  = { .slot = fork->slot, .hash = fork->slot_ctx.slot_bank.banks_hash
  //     }; fd_ghost_node_t * node = fd_ghost_node_query( ghost, &key );

  //     /* do not pick forks with equivocating blocks. */

  //     if( FD_UNLIKELY( node->eqv && !node->eqv_safe ) ) continue;

  // #if FD_BFT_USE_HANDHOLDING
  //     /* This indicates a programmer error, because node must have been inserted into ghost
  //     earlier in
  //      * fd_bft_fork_update. */
  //     if( !node ) FD_LOG_ERR( ( "missing ghost node %lu", fork->slot ) );
  // #endif

  //     if( FD_LIKELY( !heaviest_fork_key || node->weight > heaviest_fork_weight ) ) {
  //       heaviest_fork_weight = node->weight;
  //       heaviest_fork_key    = &node->slot_hash;
  //     }
  //   }

  //   if( heaviest_fork_key ) {
  //     double pct = (double)heaviest_fork_weight / (double)bft->epoch_stake;
  //     FD_LOG_NOTICE( ( "[bft] voting for heaviest fork %lu %lu (%lf)",
  //                      heaviest_fork_key->slot,
  //                      heaviest_fork_weight,
  //                      pct ) );
  //   }

  //   return heaviest_fork_key; /* lifetime as long as it remains in the frontier */
}

void
fd_bft_commitment_update( FD_FN_UNUSED fd_bft_t * forks, FD_FN_UNUSED fd_fork_t * fork ) {
  //   fd_slot_bank_t * bank = &fork->slot_ctx.slot_bank;

  //   fd_vote_accounts_pair_t_mapnode_t * vote_accounts_pool =
  //   bank->epoch_stakes.vote_accounts_pool; fd_vote_accounts_pair_t_mapnode_t *
  //   vote_accounts_root = bank->epoch_stakes.vote_accounts_root;

  //   for( fd_vote_accounts_pair_t_mapnode_t * node =
  //            fd_vote_accounts_pair_t_map_minimum( vote_accounts_pool, vote_accounts_root );
  //        node;
  //        node = fd_vote_accounts_pair_t_map_successor( vote_accounts_pool, node ) ) {
  //     fd_solana_account_t * vote_account = &node->elem.value;

  //     fd_bincode_decode_ctx_t decode = {
  //         .data    = vote_account->data,
  //         .dataend = vote_account->data + vote_account->data_len,
  //         .valloc  = valloc,
  //     };
  //     fd_vote_state_versioned_t vote_state[1] = { 0 };

  //     FD_LOG_NOTICE( ( "vote_account_data %lu", vote_account->data_len ) );
  //     if( FD_UNLIKELY( FD_BINCODE_SUCCESS !=
  //                      fd_vote_state_versioned_decode( vote_state, &decode ) ) ) {
  //       __asm__( "int $3" );
  //     }
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
  //         commitment = fd_replay_commitment_insert( replay->commitment, slot -
  //         landed_vote->latency );
  //       }
  //       FD_TEST( landed_vote->lockout.confirmation_count < 32 ); // FIXME remove
  //       commitment->confirmed_stake[landed_vote->lockout.confirmation_count] +=
  //           vote_account->lamports;
  //     }
  //   }
}

void
fd_bft_epoch_stake_update( fd_bft_t * bft, fd_exec_epoch_ctx_t * epoch_ctx ) {
  ulong                               epoch_stake = 0;
  fd_epoch_bank_t *                   epoch_bank  = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );
  fd_vote_accounts_pair_t_mapnode_t * pool = epoch_bank->stakes.vote_accounts.vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t * root = epoch_bank->stakes.vote_accounts.vote_accounts_root;
  for( fd_vote_accounts_pair_t_mapnode_t * node = fd_vote_accounts_pair_t_map_minimum( pool, root );
       node;
       node = fd_vote_accounts_pair_t_map_successor( pool, node ) ) {
    epoch_stake += node->elem.stake;
  }
  bft->epoch_stake = epoch_stake;
}

void
fd_bft_prune( fd_bft_t * bft, ulong slot ) {
  FD_PARAM_UNUSED long now = fd_log_wallclock();

  fd_blockstore_t * blockstore = bft->blockstore;
  fd_funk_t *       funk       = bft->funk;

  /* Read the slot's bank hash. */

  fd_blockstore_start_read( blockstore );
  fd_hash_t const * bank_hash = fd_blockstore_bank_hash_query( blockstore, slot );
#if FD_BFT_USE_HANDHOLDING
  /* root must be present in the blockstore with a bank hash. */
  if( FD_UNLIKELY( !bank_hash ) ) __asm__( "int $3" );
#endif
  fd_slot_hash_t slot_hash = { .slot = slot, .hash = *bank_hash };
  fd_blockstore_end_read( blockstore );

  /* Update the super-majority root (SMR), after pruning any forks in the ancestry path to
     the previous SMR across all relevant forking structures (ghost, blockstore, funk). The
     SMR is monotonically increasing, so `smr` must be > blockstore->smr. */

  /* Prune ghost. */

  fd_ghost_node_t const * root =
      fd_ghost_node_query( bft->ghost, &slot_hash ); /* ghost_root must exist */
  fd_ghost_prune( bft->ghost, root );

  /* Prune forks. */

  fd_forks_prune( bft->forks, slot );

  /* If it's the snapshot slot, return early. */

  if( FD_UNLIKELY( slot == bft->snapshot_slot ) ) return;

  /* Remove the slot from the slot commitments. */

  fd_slot_commitment_t * slot_commitment =
      fd_slot_commitment_map_query( bft->slot_commitments, slot, NULL );
  fd_slot_commitment_map_remove( bft->slot_commitments, slot_commitment );

  /* Prune blockstore. */

  fd_blockstore_start_write( blockstore );
  fd_blockstore_prune( blockstore, slot );
  fd_blockstore_end_write( blockstore );

  // FD_LOG_NOTICE(
  //     ( "[fd_bft_prune no funk] took %.2lf ms", (double)( fd_log_wallclock() - now ) / 1e6 ) );

  /* Query the funk txn xid. */

  FD_PARAM_UNUSED long funk_now = fd_log_wallclock();

  fd_blockstore_start_read( blockstore );
  fd_hash_t const * block_hash_ = fd_blockstore_block_hash_query( blockstore, slot );
#if FD_BFT_USE_HANDHOLDING
  if( FD_UNLIKELY( !block_hash_ ) ) {
    __asm__( "int $3" );
    FD_LOG_ERR( ( "missing block hash of slot we're trying to restore" ) );
  }
#endif
  fd_hash_t block_hash = *block_hash_;
  fd_blockstore_end_read( blockstore );

  fd_funk_txn_xid_t xid;
  fd_memcpy( xid.uc, &block_hash, sizeof( fd_funk_txn_xid_t ) );
  xid.ul[0] = slot;

  /* Publish funk. */

  fd_funk_start_write( funk );
  fd_funk_txn_t * funk_txn =
      fd_funk_txn_query( &xid, fd_funk_txn_map( funk, fd_funk_wksp( funk ) ) );
#if FD_BFT_USE_HANDHOLDING
  if( !funk_txn ) {
    __asm__( "int $3" );
    FD_LOG_ERR( ( "missing block hash that should be in funk. slot %lu", slot ) );
  }
#endif
  ulong rc = fd_funk_txn_publish( funk, funk_txn, 1 );
  if( rc == 0 ) FD_LOG_ERR( ( "publish err" ) );
  fd_funk_end_write( funk );

  // FD_LOG_NOTICE(
  //     ( "[fd_bft_prune funk] took %.2lf ms", (double)( fd_log_wallclock() - funk_now ) / 1e6 ) );
  // FD_LOG_NOTICE( ( "[fd_bft_prune] took %.2lf ms", (double)( fd_log_wallclock() - now ) / 1e6 )
  // );
}

void
fd_bft_smr_update( fd_bft_t * bft, ulong smr ) {
  bft->smr = smr;

  /* Update blockstore. */

  bft->blockstore->smr = smr;

  /* Update forks. */

  bft->forks->smr = smr;

  /* Update ghost. */

  fd_blockstore_start_read( bft->blockstore );
  fd_hash_t const * bank_hash = fd_blockstore_bank_hash_query( bft->blockstore, smr );
#if FD_BFT_USE_HANDHOLDING
  /* root must be present in the blockstore with a bank hash. */
  if( FD_UNLIKELY( !bank_hash ) ) __asm__( "int $3" );
#endif
  fd_slot_hash_t slot_hash = { .slot = smr, .hash = *bank_hash };
  fd_blockstore_end_read( bft->blockstore );

  fd_ghost_node_t * root = fd_ghost_node_query( bft->ghost, &slot_hash );
  bft->ghost->root       = root;
}
