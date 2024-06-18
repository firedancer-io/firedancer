#include "fd_tower.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"

#define THRESHOLD_DEPTH         ( 8 )
#define THRESHOLD_PCT           ( 2.0 / 3.0 )
#define SHALLOW_THRESHOLD_DEPTH ( 4 )
#define SHALLOW_THRESHOLD_PCT   ( 0.38 )
#define SWITCH_PCT              ( 0.38 )

void *
fd_tower_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING( ( "NULL mem" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_tower_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned mem" ) );
    return NULL;
  }

  ulong footprint = fd_tower_footprint();
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING( ( "bad mem" ) );
    return NULL;
  }

  return shmem;
}

fd_tower_t *
fd_tower_join( void * shtower ) {

  if( FD_UNLIKELY( !shtower ) ) {
    FD_LOG_WARNING( ( "NULL tower" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtower, fd_tower_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned tower" ) );
    return NULL;
  }

  return (fd_tower_t *)shtower;
}

void *
fd_tower_leave( fd_tower_t const * tower ) {

  if( FD_UNLIKELY( !tower ) ) {
    FD_LOG_WARNING( ( "NULL tower" ) );
    return NULL;
  }

  return (void *)tower;
}

void *
fd_tower_delete( void * tower ) {

  if( FD_UNLIKELY( !tower ) ) {
    FD_LOG_WARNING( ( "NULL tower" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)tower, fd_tower_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned tower" ) );
    return NULL;
  }

  return tower;
}

void
fd_tower_epoch_update( fd_tower_t * tower, fd_exec_epoch_ctx_t * epoch_ctx ) {
  ulong                               total_stake = 0;
  fd_epoch_bank_t *                   epoch_bank  = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );
  fd_vote_accounts_pair_t_mapnode_t * pool        = epoch_bank->stakes.vote_accounts.vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t * root        = epoch_bank->stakes.vote_accounts.vote_accounts_root;
  for( fd_vote_accounts_pair_t_mapnode_t * node = fd_vote_accounts_pair_t_map_minimum( pool, root ); node;
       node                                     = fd_vote_accounts_pair_t_map_successor( pool, node ) ) {
    total_stake += node->elem.stake;
  }
  tower->total_stake = total_stake;
}

void
fd_tower_fork_update( fd_tower_t * tower, fd_fork_t * fork ) {
  int rc;

  fd_blockstore_t * blockstore = tower->blockstore;
  fd_ghost_t *      ghost      = tower->ghost;
  fd_valloc_t       valloc     = tower->valloc;

  /* Get the slot hash of the just-executed slot. */

  fd_slot_hash_t slot_hash = {
      .slot = fork->slot,
      .hash = fork->slot_ctx.slot_bank.banks_hash,
  };

  /* Get the parent key. Every slot except the root must have a parent. */

  fd_blockstore_start_read( blockstore );
  ulong             parent_slot      = fd_blockstore_parent_slot_query( blockstore, fork->slot );
  fd_hash_t const * parent_bank_hash = fd_blockstore_bank_hash_query( blockstore, parent_slot );
#if FD_TOWER_USE_HANDHOLDING
  /* we must have a parent slot and bank hash, given we just executed
     its child. if not, likely a bug in blockstore pruning. */
  if( FD_UNLIKELY( parent_slot == FD_SLOT_NULL ) ) {
    FD_LOG_ERR( ( "missing parent slot for curr slot %lu", fork->slot ) );
  };
  if( FD_UNLIKELY( !parent_bank_hash ) ) {
    FD_LOG_ERR( ( "missing parent bank hash for parent slot %lu", parent_slot ) );
  };
#endif
  fd_slot_hash_t parent_slot_hash = { .slot = parent_slot, .hash = *parent_bank_hash };
  fd_blockstore_end_read( blockstore );

  /* Insert this the fork head into ghost. */

  fork->ghost_node = fd_ghost_node_insert( ghost, &slot_hash, &parent_slot_hash );

  fd_vote_accounts_pair_t_mapnode_t * root = fork->slot_ctx.slot_bank.epoch_stakes.vote_accounts_root;
  fd_vote_accounts_pair_t_mapnode_t * pool = fork->slot_ctx.slot_bank.epoch_stakes.vote_accounts_pool;
  for( fd_vote_accounts_pair_t_mapnode_t * curr = fd_vote_accounts_pair_t_map_minimum( pool, root ); curr;
       curr                                     = fd_vote_accounts_pair_t_map_successor( pool, curr ) ) {
    if( FD_UNLIKELY( curr->elem.stake == 0UL ) ) {
      continue;
    }

    fd_pubkey_t const * vote_account_address = &curr->elem.key;
    FD_BORROWED_ACCOUNT_DECL( vote_account );
    fd_vote_state_versioned_t vote_state_versioned = { 0 };

    rc = fd_acc_mgr_view( tower->acc_mgr, fork->slot_ctx.funk_txn, vote_account_address, vote_account );
    if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING( ( "fd_acc_mgr_view failed on vote account %32J. error: %d", vote_account_address, rc ) );
      __asm__( "int $3" );
    }

    rc = fd_vote_get_state( vote_account, valloc, &vote_state_versioned );
    if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING( ( "fd_vote_get_state failed on vote account %32J. error: %d", vote_account_address, rc ) );
      __asm__( "int $3" );
    }

    fd_vote_convert_to_current( &vote_state_versioned, valloc );
    fd_vote_state_t *  vote_state   = &vote_state_versioned.inner.current;
    fd_landed_vote_t * landed_votes = vote_state->votes;

    if( FD_UNLIKELY( deq_fd_landed_vote_t_empty( landed_votes ) ) ) {
      continue;
    }

    ulong vote_slot = deq_fd_landed_vote_t_peek_tail_const( landed_votes )->lockout.slot;

    /* Ignore votes for slots < root. */

    if( FD_UNLIKELY( vote_slot < tower->root ) ) {
      continue;
    }

    /* Look up _our_ bank hash for this vote. It is invariant that our
       bank hash matches the voter's hash, because this was checked
       earlier by the vote program during slot execution. */

    fd_blockstore_start_read( blockstore );
    fd_hash_t const * vote_hash = fd_blockstore_bank_hash_query( blockstore, vote_slot );
#if FD_TOWER_USE_HANDHOLDING
    /* Somehow we're missing this bank hash. Likely a bug in blockstore
       pruning logic. */
    if( FD_UNLIKELY( !vote_hash ) ) {
      FD_LOG_WARNING( ( "unexpected missing bank hash for slot %lu", vote_slot ) );
      continue;
    };
#endif
    fd_slot_hash_t vote_slot_hash = { .slot = vote_slot, .hash = *vote_hash };
    fd_blockstore_end_read( blockstore );

    /* Look up the ghost node. */

    fd_ghost_node_t * ghost_node = fd_ghost_node_query( ghost, &vote_slot_hash );

#if FD_TOWER_USE_HANDHOLDING
    /* The vote hash must match our bank hash, so we must have inserted
       this slot hash into ghost previously.
       
       FIXME vote for slot # > root but got pruned off different fork before root? */
    if( FD_UNLIKELY( !ghost_node ) ) {
      FD_LOG_ERR( ( "missing ghost key %lu %32J", vote_slot_hash.slot, vote_slot_hash.hash.hash ) );
    };
#endif

    /* Upsert the vote into ghost. */

    fd_ghost_replay_vote_insert( ghost, &vote_slot_hash, &vote_state->node_pubkey, curr->elem.stake );

    /* Check this slot's stake pct in ghost, and mark stake threshold accordingly if reached. */

    double pct = (double)ghost_node->stake / (double)tower->total_stake;

    if( FD_UNLIKELY( !ghost_node->eqv_safe && pct > FD_TOWER_EQV_SAFE ) ) {
      ghost_node->eqv_safe = 1;
      // FD_LOG_NOTICE(( "[tower] eqv safe (%lf): (%lu, %32J)", pct, slot_hash.slot, slot_hash.hash.hash ) );
    }

    if( FD_UNLIKELY( !ghost_node->opt_conf && pct > FD_TOWER_OPT_CONF ) ) {
      ghost_node->opt_conf = 1;
      // FD_LOG_NOTICE( ( "[tower] opt conf (%lf): (%lu, %32J)", pct, slot_hash.slot, slot_hash.hash.hash ) );
    }
  }
}

static int
is_same_fork( fd_tower_t * tower, fd_fork_t * fork ) {
  ulong prev_vote_slot = tower->vote_slots[tower->vote_slot_cnt - 1];

  fd_ghost_node_t * ancestor = fork->ghost_node;

  /* Look for prev_vote_slot in fork's ancestry.

     It is invariant that the prev_vote_slot either appears in the
     ancestry, or ancestor->slot_hash.slot < prev_vote_slot. This is
     because we only root when we reach max lockout in our tower. */

  while( FD_LIKELY( ancestor->slot_hash.slot >= prev_vote_slot ) ) {
    if( FD_LIKELY( ancestor->slot_hash.slot == prev_vote_slot ) ) {
      return 1;
    }

    ancestor = ancestor->parent;
  }

  return 0;
}

fd_fork_t *
fd_tower_best_fork_select( fd_tower_t * tower ) {
  fd_ghost_node_t * head = fd_ghost_head_query( tower->ghost );

  /* search for the fork head in the frontier. */

  fd_fork_t * best = fd_fork_frontier_ele_query( tower->forks->frontier, &head->slot_hash.slot, NULL, tower->forks->pool );

#if FD_TOWER_USE_HANDHOLDING
  /* if the ghost head is not in the frontier, it means we must have pruned it and that means we're in a bad state.  */
  if( FD_UNLIKELY( !best ) ) {
    FD_LOG_ERR( ( "missing ghost head (%lu, %32J) in frontier", head->slot_hash.slot, &head->slot_hash.hash ) );
  }
#endif

  return best;
}

fd_fork_t *
fd_tower_reset_fork_select( fd_tower_t * tower ) {

  /* TODO this is O(n) in # of forks (frontier ele cnt). is that a problem? */

  /* TODO implement equivocation rules */

  fd_fork_frontier_t * frontier = tower->forks->frontier;
  fd_fork_t *          pool     = tower->forks->pool;

  for( fd_fork_frontier_iter_t iter = fd_fork_frontier_iter_init( frontier, pool ); !fd_fork_frontier_iter_done( iter, frontier, pool );
       iter                         = fd_fork_frontier_iter_next( iter, frontier, pool ) ) {
    fd_fork_t * fork = fd_fork_frontier_iter_ele( iter, frontier, pool );
    if( FD_LIKELY( is_same_fork( tower, fork ) ) ) {
      return fork;
    }
  }

  /* TODO This can happen if we throw away an equivocating block
     (unimplemented), but otherwise should never happen. */

  FD_LOG_ERR( ( "Our prev_vote_slot was not compatible with any of the frontier forks. Halting." ) );
}

fd_fork_t *
fd_tower_vote_fork_select( fd_tower_t * tower ) {

  fd_fork_t * best = fd_tower_best_fork_select( tower );

  fd_fork_t * vote_fork = NULL;
  if( FD_LIKELY( is_same_fork( tower, best ) ) ) {

    /* The best fork is the same fork as our last vote, so we can vote
       for the fork's head, if we pass the threshold check. */

    if( FD_LIKELY( fd_tower_threshold_check( tower ) ) ) {

      vote_fork = best;
    }

  } else {

    /* The best fork is on a different fork, so try to switch if we pass
       lockout and switch threshold. */

    if( FD_UNLIKELY( fd_tower_lockout_check( tower, best ) && fd_tower_switch_check( tower, best ) ) ) {
      vote_fork = best;
    }
  }

  return vote_fork; /* Defaults to NULL if we cannot vote. */

  /* Only process vote slots higher than our SMR. */

  // if( FD_LIKELY( latest_vote->root > tower->smr ) ) {

  //   /* Find the previous root vote by node pubkey. */

  //   fd_root_vote_t * prev_root_vote =
  //       fd_root_vote_map_query( root_votes, latest_vote->node_pubkey, NULL );

  //   if( FD_UNLIKELY( !prev_root_vote ) ) {

  //     /* This node pubkey has not yet voted. */

  //     prev_root_vote = fd_root_vote_map_insert( root_votes, latest_vote->node_pubkey );
  //   } else {

  //     fd_root_stake_t * root_stake =
  //         fd_root_stake_map_query( tower->root_stakes, prev_root_vote->root, NULL );
  //     root_stake->stake -= stake;
  //   }

  //   /* Update our bookkeeping of this node pubkey's root. */

  //   prev_root_vote->root = latest_vote->root;

  //   /* Add this node pubkey's stake to all slots in the ancestry back to the SMR. */

  //   fd_root_stake_t * root_stake =
  //       fd_root_stake_map_query( tower->root_stakes, latest_vote->root, NULL );
  //   if( FD_UNLIKELY( !root_stake ) ) {
  //     root_stake = fd_root_stake_map_insert( tower->root_stakes, latest_vote->root );
  //   }
  //   root_stake->stake += stake;
  // }
  // }

  // if( FD_LIKELY( smr > tower->smr ) ) { tower->smr = smr; }
}

int
fd_tower_lockout_check( fd_tower_t * tower, fd_fork_t * fork ) {
  if( FD_UNLIKELY( !tower->vote_slot_cnt ) ) {
    return 1;
  }
  ulong prev_vote_slot          = tower->vote_slots[tower->vote_slot_cnt - 1];
  ulong lockout_expiration_slot = prev_vote_slot + ( 1UL << tower->vote_slot_cnt );
  return fork->slot > lockout_expiration_slot;
}

int
fd_tower_switch_check( fd_tower_t * tower, fd_fork_t * fork ) {
  ulong             switch_stake = 0;
  fd_ghost_node_t * ancestor     = fork->ghost_node;
  while( FD_LIKELY( ancestor ) ) {
    fd_ghost_node_t * curr = ancestor;
    while( FD_LIKELY( curr ) ) {
      if( FD_LIKELY( curr != fork->ghost_node ) ) {
        switch_stake += curr->weight;
      }
      curr = curr->sibling;
    }
  }
  return ( (double)switch_stake / (double)tower->total_stake ) > SWITCH_PCT;
}

int
fd_tower_threshold_check( fd_tower_t * tower ) {
  fd_blockstore_t * blockstore = tower->blockstore;

  if( FD_UNLIKELY( tower->vote_slot_cnt < THRESHOLD_DEPTH ) ) {
    return 1;
  }

  ulong threshold_slot = tower->vote_slots[tower->vote_slot_cnt - THRESHOLD_DEPTH];
  fd_blockstore_start_read( blockstore );
  fd_hash_t const * threshold_bank_hash = fd_blockstore_bank_hash_query( blockstore, threshold_slot );
#if FD_TOWER_USE_HANDHOLDING
  if( FD_UNLIKELY( !threshold_bank_hash ) ) {
    /* the threshold bank hash must be in the blockstore,
       because if it's in our tower we voted on it. */
    /* TODO think about the case where we dump a bank hash */
    FD_LOG_ERR( ( "missing threshold_bank_hash for slot %lu", threshold_slot ) );
  }
#endif
  fd_slot_hash_t threshold_slot_hash = { .slot = threshold_slot, .hash = *threshold_bank_hash };
  fd_blockstore_end_read( blockstore );

  /* FIXME needs to use more complicated voted_stakes logic vs. ghost weight */

  fd_ghost_node_t const * threshold_ghost_node = fd_ghost_node_query( tower->ghost, &threshold_slot_hash );

#if FD_TOWER_USE_HANDHOLDING
  /* the threshold slot hash must be in ghost,
     because we voted on it thus must have inserted it into ghost. */
  if( FD_UNLIKELY( !threshold_ghost_node ) ) {
    FD_LOG_ERR( ( "missing threshold_ghost_node (%lu, %32J) in ghost",
                  threshold_ghost_node->slot_hash.slot,
                  &threshold_ghost_node->slot_hash.hash ) );
  }
#endif

  double pct = (double)threshold_ghost_node->weight / (double)tower->total_stake;
  return pct > THRESHOLD_PCT;
}
