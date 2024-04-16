#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/fd_borrowed_account.h"
#include "../../flamenco/runtime/program/fd_program_util.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"

#include "../fd_choreo_base.h"
#include "../ghost/fd_ghost.h"
#include "fd_bft.h"

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

static void
count_votes( fd_bft_t * bft, fd_fork_t * fork ) {
  for( fd_tower_deque_iter_t iter = fd_tower_deque_iter_init( fork->slot_ctx.towers );
       !fd_tower_deque_iter_done( fork->slot_ctx.towers, iter );
       iter = fd_tower_deque_iter_next( fork->slot_ctx.towers, iter ) ) {
    fd_tower_t * tower = fd_tower_deque_iter_ele( fork->slot_ctx.towers, iter );

    ulong vote_slot = tower->slots[tower->cnt - 1];

    /* Ignore votes for slots < snapshot_slot. */

    if( FD_UNLIKELY( vote_slot < bft->snapshot_slot ) ) continue;

    /* Look up _our_ bank hash for this vote slot. */

    fd_hash_t const * vote_hash = fd_blockstore_bank_hash_query( bft->blockstore, vote_slot );
    if( FD_UNLIKELY( !vote_hash ) ) {
      FD_LOG_WARNING( ( "couldn't find bank hash for slot %lu", vote_slot ) );
      continue;
    }
    fd_slot_hash_t vote_key = { .slot = vote_slot, .hash = *vote_hash };

    /* Look up latest vote for this node (pubkey) and stake. */

    fd_pubkey_t * pubkey = &tower->vote_acc_addr;

    fd_vote_accounts_pair_t_mapnode_t * root =
        fork->slot_ctx.epoch_ctx->epoch_bank.stakes.vote_accounts.vote_accounts_root;
    fd_vote_accounts_pair_t_mapnode_t * pool =
        fork->slot_ctx.epoch_ctx->epoch_bank.stakes.vote_accounts.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t key = { 0 };
    key.elem.key                          = *pubkey;
    fd_vote_accounts_pair_t_mapnode_t * vote_node =
        fd_vote_accounts_pair_t_map_find( pool, root, &key );

    /* If it's not in the epoch stakes map, look in the incremental-epoch stakes map.  */

    if( !vote_node ) {
      pool = fork->slot_ctx.slot_bank.vote_account_keys.vote_accounts_pool;
      root = fork->slot_ctx.slot_bank.vote_account_keys.vote_accounts_root;
      fd_vote_accounts_pair_t_mapnode_t * vote_node =
          fd_vote_accounts_pair_t_map_find( pool, root, &key );
      if( !vote_node ) {
        FD_LOG_DEBUG( ( "couldn't find %32J in vote account stakes", pubkey->key ) );
        continue;
      }
    }

    /* Set the stake. */

    ulong             stake      = vote_node->elem.stake;
    fd_ghost_node_t * node = fd_ghost_node_query( bft->ghost, &vote_key );

    /* This slot hash must have been inserted, because ghost only processes replay votes. */

    if( FD_UNLIKELY( !node ) ) {
      FD_LOG_ERR( ( "missing ghost key %lu %32J", vote_key.slot, vote_key.hash.hash ) );
    };

    fd_ghost_latest_vote_upsert( bft->ghost, &vote_key, pubkey, stake );

    double pct = (double)node->stake / (double)bft->epoch_stake;
    if( FD_UNLIKELY( !fork->eqv_safe && pct > FD_BFT_EQV_SAFE ) ) {
      fork->eqv_safe = 1;
#if FD_BFT_USE_HANDHOLDING
      FD_LOG_NOTICE(
          ( "[bft] eqv safe (%lf): (%lu, %32J)", pct, vote_key.slot, vote_key.hash.hash ) );
#endif
    }
    if( FD_UNLIKELY( !fork->opt_conf && pct > FD_BFT_OPT_CONF ) ) {
      fork->opt_conf = 1;
#if FD_BFT_USE_HANDHOLDING
      FD_LOG_NOTICE(
          ( "[bft] opt conf (%lf): (%lu, %32J)", pct, vote_key.slot, vote_key.hash.hash ) );
#endif
    }
  }
}

void
fd_bft_fork_update( fd_bft_t * bft, fd_fork_t * fork ) {
  fd_slot_bank_t * bank = &fork->slot_ctx.slot_bank;

  /* Update the current fork head's bft key. */

  fd_slot_hash_t curr_key = {
      .slot = fork->slot,
      .hash = bank->banks_hash,
  };

  /* Get the parent key. Every block must have a parent (except genesis or snapshot block). */

  ulong parent_slot = fd_blockstore_parent_slot_query(bft->blockstore, fork->slot);

  /* Insert this fork into bft. */

  if( FD_UNLIKELY( parent_slot == FD_SLOT_NULL ) ) {
    fd_ghost_leaf_insert( bft->ghost, &curr_key, NULL );
  } else {
    fd_hash_t const * parent_bank_hash =
        fd_blockstore_bank_hash_query( bft->blockstore, parent_slot );
    if( FD_UNLIKELY( !parent_bank_hash ) ) {
      FD_LOG_ERR( ( "invariant violation: executed child before having parent bank hash." ) );
    }
    fd_slot_hash_t parent_key = {
        .slot = parent_slot,
        .hash = *parent_bank_hash,
    };
    FD_LOG_NOTICE( ( "[ghost] insert slot: %lu hash: %32J parent: %lu parent_hash: %32J",
                     curr_key.slot,
                     curr_key.hash.uc,
                     parent_slot,
                     parent_bank_hash->hash ) );
    fd_ghost_leaf_insert( bft->ghost, &curr_key, &parent_key );
  }

  /* Insert this fork into commitment. */

  // fd_slot_commitment_t * slot_commitment = fd_commitment_slot_insert( forks->commitment, slot );

  /* Count votes in this fork's block. */

  count_votes( bft, fork );

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
}

fd_slot_hash_t *
fd_bft_fork_choice( fd_bft_t * bft ) {
  fd_ghost_t * ghost = bft->ghost;

  ulong            heaviest_fork_weight = 0;
  fd_slot_hash_t * heaviest_fork_key    = NULL;

  /* query every fork in the frontier to retrieve the heaviest bank */

  fd_fork_frontier_t * frontier = bft->forks->frontier;
  fd_fork_t *          pool     = bft->forks->pool;
  for( fd_fork_frontier_iter_t iter = fd_fork_frontier_iter_init( frontier, pool );
       !fd_fork_frontier_iter_done( iter, frontier, pool );
       iter = fd_fork_frontier_iter_next( iter, frontier, pool ) ) {

    fd_fork_t * fork = fd_fork_frontier_iter_ele( iter, frontier, pool );

    fd_slot_hash_t    key  = { .slot = fork->slot, .hash = fork->slot_ctx.slot_bank.banks_hash };
    fd_ghost_node_t * node = fd_ghost_node_query( ghost, &key );

    #if FD_BFT_USE_HANDHOLDING

    /* invariant: node must have been inserted by now */

    if( !node ) FD_LOG_ERR( ( "missing ghost node %lu", fork->slot ) );
#endif

    if( FD_LIKELY( !heaviest_fork_key || node->weight > heaviest_fork_weight ) ) {
      heaviest_fork_weight = node->weight;
      heaviest_fork_key    = &node->key;
    }
  }

  if( heaviest_fork_key ) {
    double pct = (double)heaviest_fork_weight / (double)bft->epoch_stake;
    FD_LOG_NOTICE( ( "[bft] voting for heaviest fork %lu %lu (%lf)", heaviest_fork_key->slot, heaviest_fork_weight, pct ) );
    // fd_ghost_print( ghost );
  }

  return heaviest_fork_key; /* lifetime as long as it remains in forks->bft */
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
  fd_vote_accounts_pair_t_mapnode_t * pool =
      epoch_ctx->epoch_bank.stakes.vote_accounts.vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t * root =
      epoch_ctx->epoch_bank.stakes.vote_accounts.vote_accounts_root;
  for( fd_vote_accounts_pair_t_mapnode_t * node = fd_vote_accounts_pair_t_map_minimum( pool, root );
       node;
       node = fd_vote_accounts_pair_t_map_successor( pool, node ) ) {
    epoch_stake += node->elem.stake;
  }
  bft->epoch_stake = epoch_stake;
}
