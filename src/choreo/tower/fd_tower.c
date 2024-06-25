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

void
fd_tower_init( fd_tower_t * tower, fd_exec_epoch_ctx_t const * epoch_ctx, ulong root ) {

  if( FD_UNLIKELY( !tower ) ) {
    FD_LOG_WARNING( ( "NULL tower" ) );
    return;
  }

  if( FD_UNLIKELY( root == FD_SLOT_NULL ) ) {
    FD_LOG_WARNING( ( "NULL slot" ) );
    return;
  }

  if( FD_UNLIKELY( tower->root ) ) {
    FD_LOG_WARNING( ( "tower already initialized" ) );
    return;
  }

  fd_tower_epoch_update( tower, epoch_ctx );
  tower->root = root;

  return;
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

static int
vote_state_versioned_get( fd_acc_mgr_t *              acc_mgr,
                          fd_funk_txn_t *             funk_txn,
                          fd_valloc_t                 valloc,
                          fd_pubkey_t const *         vote_acc_addr,
                          fd_vote_state_versioned_t * vote_state_versioned_out ) {
  int rc;

  FD_BORROWED_ACCOUNT_DECL( vote_acc );
  rc = fd_acc_mgr_view( acc_mgr, funk_txn, vote_acc_addr, vote_acc );
  if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(
        ( "fd_acc_mgr_view failed on vote account %32J. error: %d", vote_acc_addr, rc ) );
  }

  rc = fd_vote_get_state( vote_acc, valloc, vote_state_versioned_out );
  if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(
        ( "fd_vote_get_state failed on vote account %32J. error: %d", vote_acc_addr, rc ) );
  }

  fd_vote_convert_to_current( vote_state_versioned_out, valloc );

  return rc;
}

static inline int
lockout_check( ulong const vote_slots[static FD_TOWER_VOTE_SLOTS_MAX],
               ulong       vote_slot_cnt,
               ulong       slot ) {
  ulong prev_vote_slot          = vote_slots[vote_slot_cnt - 1];
  ulong lockout                 = 1UL << vote_slot_cnt;
  ulong lockout_expiration_slot = prev_vote_slot + lockout;
  return slot > lockout_expiration_slot;
}

static inline void
pop_expired( ulong const vote_slots[static FD_TOWER_VOTE_SLOTS_MAX],
             ulong *     vote_slot_cnt,
             ulong       slot ) {
  while( vote_slot_cnt ) {
    if( FD_UNLIKELY( lockout_check( vote_slots, *vote_slot_cnt, slot ) ) ) break;
    *vote_slot_cnt -= 1;
  }
}

int
fd_tower_lockout_check( fd_tower_t const * tower, fd_fork_t const * fork ) {
  return lockout_check( tower->vote_slots, tower->vote_slot_cnt, fork->slot );
}

int
fd_tower_switch_check( fd_tower_t const * tower, fd_fork_t const * fork ) {
  ulong             switch_stake = 0;
  fd_ghost_node_t * ancestor     = fork->ghost_node;
  while( FD_LIKELY( ancestor ) ) {
    fd_ghost_node_t * curr = ancestor;
    while( FD_LIKELY( curr ) ) {
      if( FD_LIKELY( curr != fork->ghost_node ) ) switch_stake += curr->weight;
      curr = curr->sibling;
    }
  }
  return ( (double)switch_stake / (double)tower->total_stake ) > SWITCH_PCT;
}

int
fd_tower_threshold_check( fd_tower_t const * tower,
                          fd_fork_t const *  fork,
                          fd_acc_mgr_t *     acc_mgr ) {
  if( FD_UNLIKELY( tower->vote_slot_cnt < THRESHOLD_DEPTH ) ) return 1;

  /* Simulate a vote on _our_ tower for the fork head (fork->slot),
     popping the expired votes. */

  ulong simulate_vote_slot_cnt = tower->vote_slot_cnt;
  pop_expired( tower->vote_slots, &simulate_vote_slot_cnt, fork->slot );

  /* Get the vote slot from THRESHOLD_DEPTH back (+1 for the simulated
     vote). */

  ulong threshold_slot = tower->vote_slots[tower->vote_slot_cnt + 1 - THRESHOLD_DEPTH];

  /* Track the amount of stake that has vote slot >= threshold_slot. */

  ulong threshold_stake = 0;

  /* Iterate all the vote accounts. */

  for( ulong i = 0; i < tower->vote_acc_cnt; i++ ) {
    FD_SCRATCH_SCOPE_BEGIN {
      fd_valloc_t               valloc               = fd_scratch_virtual();
      fd_vote_state_versioned_t vote_state_versioned = { 0 };

      int rc = vote_state_versioned_get( acc_mgr,
                                         fork->slot_ctx.funk_txn,
                                         valloc,
                                         tower->vote_accs[i].addr,
                                         &vote_state_versioned );
      if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) FD_LOG_ERR( ( "fail" ) );

      fd_vote_state_t *  vote_state   = &vote_state_versioned.inner.current;
      fd_landed_vote_t * landed_votes = vote_state->votes;

      /* If the vote account has an empty tower, continue. */

      if( FD_UNLIKELY( deq_fd_landed_vote_t_empty( landed_votes ) ) ) continue;

      /* Get vote account's latest vote. */

      ulong vote_slot = deq_fd_landed_vote_t_peek_tail_const( landed_votes )->lockout.slot;

      /* Convert the landed_votes into tower's vote_slots interface. */

      ulong vote_slots[FD_TOWER_VOTE_SLOTS_MAX] = { 0 };
      ulong vote_slot_cnt                       = 0;
      while( !deq_fd_landed_vote_t_empty( landed_votes ) ) {
        vote_slots[vote_slot_cnt++] = deq_fd_landed_vote_t_pop_tail( landed_votes ).lockout.slot;
      }

      /* Simulate a vote on _their_ tower for the fork head, popping the
         expired votes. */

      pop_expired( vote_slots, &vote_slot_cnt, fork->slot );

      /* Count the stake towards threshold if top of tower >= our
         threshold slot. Here we are iterating vote accounts on the fork
         that we are threshold checking itself, so these slots are all
         defined to be on the same fork. */

      if( FD_LIKELY( vote_slot >= threshold_slot ) ) threshold_stake += tower->vote_accs[i].stake;
    }
    FD_SCRATCH_SCOPE_END;
  }

  return ( (double)threshold_stake / (double)tower->total_stake ) > THRESHOLD_PCT;
}

static int
is_same_fork( fd_tower_t const * tower, fd_fork_t const * fork ) {
  ulong prev_vote_slot = tower->vote_slots[tower->vote_slot_cnt - 1];

  fd_ghost_node_t * ancestor = fork->ghost_node;

  /* Look for prev_vote_slot in fork's ancestry.

     It is invariant that the prev_vote_slot either appears in the
     ancestry, or ancestor->slot < prev_vote_slot. This is
     because we only root when we reach max lockout in our tower. */

  while( FD_LIKELY( ancestor->slot >= prev_vote_slot ) ) {
    if( FD_LIKELY( ancestor->slot == prev_vote_slot ) ) return 1;

    ancestor = ancestor->parent;
  }

  return 0;
}

fd_fork_t *
fd_tower_best_fork_select( FD_PARAM_UNUSED fd_tower_t const * tower, fd_forks_t * forks, fd_ghost_t * ghost ) {
  fd_ghost_node_t * head = fd_ghost_head_query( ghost );

  /* search for the fork head in the frontier. */

  fd_fork_t * best = fd_fork_frontier_ele_query( forks->frontier, &head->slot, NULL, forks->pool );

#if FD_TOWER_USE_HANDHOLDING
  /* if the ghost head is not in the frontier, so we must have pruned it
     and we're in a bad state. */
  if( FD_UNLIKELY( !best ) ) FD_LOG_ERR( ( "missing ghost head %lu in frontier", head->slot ) );
#endif

  return best;
}

fd_fork_t *
fd_tower_reset_fork_select( fd_tower_t const * tower, fd_forks_t * forks ) {

  /* TODO this is O(n) in # of forks (frontier ele cnt). is that a problem? */

  /* TODO implement equivocation rules */

  fd_fork_frontier_t * frontier = forks->frontier;
  fd_fork_t *          pool     = forks->pool;

  for( fd_fork_frontier_iter_t iter = fd_fork_frontier_iter_init( frontier, pool );
       !fd_fork_frontier_iter_done( iter, frontier, pool );
       iter = fd_fork_frontier_iter_next( iter, frontier, pool ) ) {
    fd_fork_t * fork = fd_fork_frontier_iter_ele( iter, frontier, pool );
    if( FD_LIKELY( is_same_fork( tower, fork ) ) ) return fork;
  }

  /* TODO This can happen if we throw away an equivocating block
     (unimplemented), but otherwise should never happen. */

  FD_LOG_ERR(
      ( "Our prev_vote_slot was not compatible with any of the frontier forks. Halting." ) );
}

fd_fork_t *
fd_tower_vote_fork_select( fd_tower_t *   tower,
                           fd_forks_t *   forks,
                           fd_acc_mgr_t * acc_mgr,
                           fd_ghost_t *   ghost ) {

  fd_fork_t * best = fd_tower_best_fork_select( tower, forks, ghost );

  fd_fork_t * vote_fork = NULL;
  if( FD_LIKELY( is_same_fork( tower, best ) ) ) {

    /* The best fork is the same fork as our last vote, so we can vote
       for the fork's head if we pass the threshold check. */

    if( FD_LIKELY( fd_tower_threshold_check( tower, best, acc_mgr ) ) ) vote_fork = best;

  } else {

    /* The best fork is on a different fork, so try to switch if we pass
       lockout and switch threshold. */

    if( FD_UNLIKELY( fd_tower_lockout_check( tower, best ) &&
                     fd_tower_switch_check( tower, best ) ) ) {
      vote_fork = best;
    }
  }

  if( FD_LIKELY( vote_fork ) ) {

    /* Pop expired votes. */

    pop_expired( tower->vote_slots, &tower->vote_slot_cnt, vote_fork->slot );

    /* Add the new vote slot to the tower. */

    tower->vote_slots[tower->vote_slot_cnt++] = vote_fork->slot;
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

  // if( FD_LIKELY( smr > tower->smr ) ) tower->smr = smr;
}

void
fd_tower_epoch_update( fd_tower_t * tower, fd_exec_epoch_ctx_t const * epoch_ctx ) {
  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank_const( epoch_ctx );

  ulong total_stake = 0;

  for( fd_vote_accounts_pair_t_mapnode_t * curr = fd_vote_accounts_pair_t_map_minimum(
           epoch_bank->stakes.vote_accounts.vote_accounts_pool,
           epoch_bank->stakes.vote_accounts.vote_accounts_root );
       curr;
       curr = fd_vote_accounts_pair_t_map_successor(
           epoch_bank->stakes.vote_accounts.vote_accounts_pool,
           curr ) ) {

#if FD_TOWER_USE_HANDHOLDING
    if( FD_UNLIKELY( tower->vote_acc_cnt == FD_VOTER_MAX ) ) FD_LOG_ERR( ( "voter overflow." ) );
#endif

    if( FD_UNLIKELY( curr->elem.stake > 0UL ) ) {
      tower->vote_accs[tower->vote_acc_cnt++] =
          ( fd_tower_vote_acc_t ){ .addr = &curr->elem.key, .stake = curr->elem.stake };
    }
    total_stake += curr->elem.stake;
  }
  tower->total_stake = total_stake;
}

void
fd_tower_fork_update( fd_tower_t *      tower,
                      fd_fork_t *       fork,
                      fd_acc_mgr_t *    acc_mgr,
                      fd_blockstore_t * blockstore,
                      fd_ghost_t *      ghost ) {
  ulong root = tower->root; /* FIXME fseq */

  /* Get the parent key. Every slot except the root must have a parent. */

  fd_blockstore_start_read( blockstore );
  ulong parent_slot = fd_blockstore_parent_slot_query( blockstore, fork->slot );
#if FD_TOWER_USE_HANDHOLDING
  /* we must have a parent slot and bank hash, given we just executed
     its child. if not, likely a bug in blockstore pruning. */
  if( FD_UNLIKELY( parent_slot == FD_SLOT_NULL ) ) {
    FD_LOG_ERR( ( "missing parent slot for curr slot %lu", fork->slot ) );
  };
#endif
  fd_blockstore_end_read( blockstore );

  /* Insert the new fork head into ghost. */

  fork->ghost_node = fd_ghost_node_insert( ghost, fork->slot, parent_slot );

  for( ulong i = 0; i < tower->vote_acc_cnt; i++ ) {
    fd_pubkey_t const * vote_acc_addr = tower->vote_accs[i].addr;
    FD_SCRATCH_SCOPE_BEGIN {
      fd_valloc_t               valloc               = fd_scratch_virtual();
      fd_vote_state_versioned_t vote_state_versioned = { 0 };

      int rc = vote_state_versioned_get( acc_mgr,
                                         fork->slot_ctx.funk_txn,
                                         valloc,
                                         vote_acc_addr,
                                         &vote_state_versioned );
      if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) FD_LOG_ERR( ( "fail" ) );

      fd_vote_state_t *  vote_state   = &vote_state_versioned.inner.current;
      fd_landed_vote_t * landed_votes = vote_state->votes;

      /* If the vote account has an empty tower, continue. */

      if( FD_UNLIKELY( deq_fd_landed_vote_t_empty( landed_votes ) ) ) continue;

      /* Get the vote account's latest vote. */

      ulong vote_slot = deq_fd_landed_vote_t_peek_tail_const( landed_votes )->lockout.slot;

      /* Ignore votes for slots < root. This guards the ghost invariant
         that the vote slot must be present in the ghost tree. */

      if( FD_UNLIKELY( vote_slot < root ) ) continue;

      /* Upsert the vote into ghost. */

      fd_ghost_replay_vote_upsert( ghost,
                                   vote_slot,
                                   &vote_state->node_pubkey,
                                   tower->vote_accs[i].stake );
    }
    FD_SCRATCH_SCOPE_END;
  }
}
