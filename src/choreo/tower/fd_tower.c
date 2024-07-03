#include "fd_tower.h"
#include "../../flamenco/runtime/program/fd_vote_program.h"

#define THRESHOLD_DEPTH         ( 8 )
#define THRESHOLD_PCT           ( 2.0 / 3.0 )
#define SHALLOW_THRESHOLD_DEPTH ( 4 )
#define SHALLOW_THRESHOLD_PCT   ( 0.38 )
#define SWITCH_PCT              ( 0.38 )
void
print( fd_tower_vote_t * tower_votes ) {
  ulong max_slot = 0;

  /* Determine spacing. */

  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init_rev( tower_votes );
       !fd_tower_votes_iter_done_rev( tower_votes, iter );
       iter = fd_tower_votes_iter_prev( tower_votes, iter ) ) {

    max_slot = fd_ulong_max( max_slot, fd_tower_votes_iter_ele_const( tower_votes, iter )->slot );
  }

  /* Calculate the number of digits in the maximum slot value. */

  int           radix = 0;
  unsigned long rem   = max_slot;
  do {
    rem /= 10;
    ++radix;
  } while( rem > 0 );

  /* Print the table header */

  printf( "%*s | %s\n", radix, "slot", "confirmation count" );

  /* Print the divider line */

  for( int i = 0; i < radix; i++ ) {
    printf( "-" );
  }
  printf( " | " );
  for( ulong i = 0; i < strlen( "confirmation_count" ); i++ ) {
    printf( "-" );
  }
  printf( "\n" );

  /* Print each record in the table */

  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init_rev( tower_votes );
       !fd_tower_votes_iter_done_rev( tower_votes, iter );
       iter = fd_tower_votes_iter_prev( tower_votes, iter ) ) {

    fd_tower_vote_t const * vote = fd_tower_votes_iter_ele_const( tower_votes, iter );
    printf( "%*lu | %lu\n", radix, vote->slot, vote->conf );
    max_slot = fd_ulong_max( max_slot, fd_tower_votes_iter_ele_const( tower_votes, iter )->slot );
  }
  printf( "\n" );
}
/* clang-format off */
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

  fd_memset( shmem, 0, footprint );
  ulong        laddr = (ulong)shmem;
  fd_tower_t * tower = (void *)laddr;
  laddr             += sizeof( fd_tower_t );

  laddr        = fd_ulong_align_up( laddr, fd_tower_votes_align() );
  tower->votes = fd_tower_votes_new( (void *)laddr );
  laddr       += fd_tower_votes_footprint();

  laddr            = fd_ulong_align_up( laddr, fd_tower_vote_accs_align() );
  tower->vote_accs = fd_tower_vote_accs_new( (void *)laddr );
  laddr           += fd_tower_vote_accs_footprint();

  return shmem;
}
/* clang-format on */

/* clang-format off */
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

  ulong        laddr = (ulong)shtower; /* offset from a memory region */
  fd_tower_t * tower = (void *)shtower;
  laddr             += sizeof(fd_tower_t);

  laddr        = fd_ulong_align_up( laddr, fd_tower_votes_align() );
  tower->votes = fd_tower_votes_new( (void *)laddr );
  laddr       += fd_tower_votes_footprint();

  laddr            = fd_ulong_align_up( laddr, fd_tower_vote_accs_align() );
  tower->vote_accs = fd_tower_vote_accs_new( (void *)laddr );
  laddr           += fd_tower_vote_accs_footprint();

  return (fd_tower_t *)shtower;
}
/* clang-format on */

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

  /* Set the root. */

  tower->root = root;

  /* Set total stake and vote accounts. */

  fd_tower_epoch_update( tower, epoch_ctx );

  return;
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
    FD_LOG_WARNING( ( "fd_acc_mgr_view failed on vote account %32J. error: %d",
                      vote_acc_addr,
                      rc ) );
  }

  rc = fd_vote_get_state( vote_acc, valloc, vote_state_versioned_out );
  if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING( ( "fd_vote_get_state failed on vote account %32J. error: %d",
                      vote_acc_addr,
                      rc ) );
  }

  fd_vote_convert_to_current( vote_state_versioned_out, valloc );

  return rc;
}

/* If vote->slot is an ancestor of fork->slot, we know they belong to
   the same fork. */
static inline int
is_same_fork( fd_tower_vote_t const * vote, fd_fork_t const * fork, fd_ghost_t const * ghost ) {
  return fd_ghost_is_ancestor( ghost, vote->slot, fork->slot );
}

static inline ulong
lockout_expiration_slot( fd_tower_vote_t const * vote ) {
  ulong lockout = 1UL << vote->conf;
  return vote->slot + lockout;
}

/* Simulate a vote on the vote tower for the fork head, returning the
   new height (cnt) for all the votes that would have been popped. */

static inline ulong
simulate_vote( fd_tower_vote_t const * votes, ulong slot ) {
  ulong cnt = fd_tower_votes_cnt( votes );
  while( cnt ) {

    /* Return early if we can't pop the top tower vote, even if votes
       below it are expired. */

    if( FD_LIKELY( lockout_expiration_slot( fd_tower_votes_peek_index_const( votes, cnt - 1 ) ) >
                   slot ) ) {
      break;
    }
    cnt--;
  }
  return cnt + 1; /* Add 1 to represent the simulated vote. */
}

int
fd_tower_lockout_check( fd_tower_t const * tower,
                        fd_fork_t const *  fork,
                        fd_ghost_t const * ghost ) {

  /* Simulate a vote for fork->slot, popping off the votes that would
     get expired by voting for fork->slot. */

  ulong cnt = simulate_vote( tower->votes, fork->slot );

  /* Subtract the simulated vote. */

  cnt--;

  /* Check all remaining votes on the tower to make sure they are on the
     same fork. */

  while( 1 ) {
    fd_tower_vote_t const * vote = fd_tower_votes_peek_index_const( tower->votes, cnt-- );

    /* Optimize for same fork. */

    if( FD_UNLIKELY( !is_same_fork( vote, fork, ghost ) ) ) {
      FD_LOG_NOTICE( ( "[fd_tower_lockout_check] can't vote for %lu. locked out by prev vote (slot: "
                       "%lu, conf: %lu)",
                       fork->slot,
                       vote->slot,
                       vote->conf ) );
      return 0;
    }

    if( FD_UNLIKELY( cnt == 0 ) ) break;
  }

  /* All remaining votes in the tower are on the same fork, so we are
     not locked out and OK to vote. */

  return 1;
}

int
fd_tower_switch_check( fd_tower_t const * tower,
                       fd_fork_t const *  fork,
                       fd_ghost_t const * ghost ) {
  ulong switch_stake = 0;

  fd_ghost_node_t const * ancestor = fd_ghost_node_query_const( ghost, fork->slot );

#if FD_GHOST_USE_HANDHOLDING
  if( FD_UNLIKELY( !ancestor ) ) {

    /* It is invariant that the fork head must be in ghost, as it was just inserted during
       fd_tower_fork_update. */

    FD_LOG_ERR( ( "unable to find fork head %lu in ghost", fork->slot ) );
  }
#endif

  while( FD_LIKELY( ancestor->parent ) ) {
    fd_ghost_node_t * child = ancestor->child;

    /* Both conditionals are marked FD_LIKELY because we only try to
       switch if the best fork differs from our latest vote fork. */

    while( FD_LIKELY( child ) ) {

      if( FD_LIKELY( child != ancestor && child->slot ) ) switch_stake += child->weight;
      child = child->sibling;
    }
    ancestor = ancestor->parent;
  }

  double switch_pct = (double)switch_stake / (double)tower->total_stake;
  FD_LOG_NOTICE( ( "[fd_tower_switch_check] switch slot: %lu. stake: %.0lf%%",
                   fork->slot,
                   switch_pct * 100.0 ) );
  return switch_pct > SWITCH_PCT;
}

int
fd_tower_threshold_check( fd_tower_t const * tower,
                          fd_fork_t const *  fork,
                          fd_acc_mgr_t *     acc_mgr ) {
  ulong cnt = simulate_vote( tower->votes, fork->slot );

  /* Return early if our tower is not at least THRESHOLD_DEPTH deep after
     simulating. */

  if( FD_UNLIKELY( cnt < THRESHOLD_DEPTH ) ) return 1;

  /* Get the vote slot from THRESHOLD_DEPTH back. */

  fd_tower_vote_t * our_threshold_vote = fd_tower_votes_peek_index( tower->votes,
                                                                    cnt - THRESHOLD_DEPTH );

  /* Track the amount of stake that has vote slot >= threshold_slot. */

  ulong threshold_stake = 0;

  /* Iterate all the vote accounts. */

  for( fd_tower_vote_accs_iter_t iter = fd_tower_vote_accs_iter_init( tower->vote_accs );
       !fd_tower_vote_accs_iter_done( tower->vote_accs, iter );
       iter = fd_tower_vote_accs_iter_next( tower->vote_accs, iter ) ) {

    FD_SCRATCH_SCOPE_BEGIN {

      fd_valloc_t valloc = fd_scratch_virtual();

      fd_tower_vote_acc_t *     vote_acc = fd_tower_vote_accs_iter_ele( tower->vote_accs, iter );
      fd_vote_state_versioned_t vote_state_versioned = { 0 };

      int rc = vote_state_versioned_get( acc_mgr,
                                         fork->slot_ctx.funk_txn,
                                         valloc,
                                         vote_acc->addr,
                                         &vote_state_versioned );
      if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) FD_LOG_ERR( ( "fail" ) );

      fd_vote_state_t *  vote_state   = &vote_state_versioned.inner.current;
      fd_landed_vote_t * landed_votes = vote_state->votes;

      /* If the vote account has an empty tower, continue. */

      if( FD_UNLIKELY( deq_fd_landed_vote_t_empty( landed_votes ) ) ) continue;

      /* Convert the landed_votes into tower's vote_slots interface. */

      void * mem = fd_scratch_alloc( fd_tower_votes_align(), fd_tower_votes_footprint() );
      fd_tower_vote_t * their_tower_votes = fd_tower_votes_join( fd_tower_votes_new( mem ) );
      while( !deq_fd_landed_vote_t_empty( landed_votes ) ) {
        fd_landed_vote_t landed_vote = deq_fd_landed_vote_t_pop_head( landed_votes );
        fd_tower_votes_push_tail( their_tower_votes,
                                  ( fd_tower_vote_t ){
                                      .slot = landed_vote.lockout.slot,
                                      .conf = landed_vote.lockout.confirmation_count } );
      }

      ulong cnt = simulate_vote( their_tower_votes, fork->slot );

      /* Continue if their tower is not yet THRESHOLD_DEPTH deep after
         simulating. */

      if( FD_UNLIKELY( cnt < THRESHOLD_DEPTH ) ) continue;

      /* Get the vote slot from THRESHOLD_DEPTH back.*/

      fd_tower_vote_t * their_threshold_vote = fd_tower_votes_peek_index( their_tower_votes,
                                                                          cnt - THRESHOLD_DEPTH );

      /* Add their stake if their threshold vote's slot >= our threshold
         vote's slot.

         Because we are iterating vote accounts on the same fork that we
         are threshold checking, we know these slots must occur in a
         common ancestry.

         If their_threshold_vote->slot >= our_threshold_vote->slot, we
         know their threshold vote is either for the same slot or a
         descendant slot of our threshold vote. */

      if( FD_LIKELY( their_threshold_vote->slot >= our_threshold_vote->slot ) ) {
        threshold_stake += vote_acc->stake;
      }
    }
    FD_SCRATCH_SCOPE_END;
  }

  double threshold_pct = (double)threshold_stake / (double)tower->total_stake;
  FD_LOG_NOTICE( ( "[fd_tower_threshold_check] threshold slot: %lu. stake: %.0lf%%",
                   our_threshold_vote->slot,
                   threshold_pct * 100.0 ) );
  return threshold_pct > THRESHOLD_PCT;
}

fd_fork_t const *
fd_tower_best_fork_select( FD_PARAM_UNUSED fd_tower_t const * tower,
                           fd_forks_t const *                 forks,
                           fd_ghost_t const *                 ghost ) {
  fd_ghost_node_t const * head = fd_ghost_head_query_const( ghost );

  /* Search for the fork head in the frontier. */

  fd_fork_t const * best = fd_forks_query_const( forks, head->slot );

#if FD_TOWER_USE_HANDHOLDING
  if( FD_UNLIKELY( !best ) ) {

    /* If the best fork is not in the frontier, then we must have pruned
       it and we're now in a bad state. */

    /* TODO eqvoc */

    FD_LOG_ERR( ( "missing ghost head %lu in frontier", head->slot ) );
  }
#endif

  return best;
}

fd_fork_t const *
fd_tower_reset_fork_select( fd_tower_t const * tower,
                            fd_forks_t const * forks,
                            fd_ghost_t const * ghost ) {

  /* We haven't voted yet, so just reset to the best fork. */

  if( FD_UNLIKELY( fd_tower_votes_empty( tower->votes ) ) ) {
    return fd_tower_best_fork_select( tower, forks, ghost );
  }

  /* TODO this is O(n) in # of forks (frontier ele cnt). is that a
     problem? */

  fd_tower_vote_t const *    latest_vote = fd_tower_votes_peek_tail_const( tower->votes );
  fd_fork_frontier_t const * frontier    = forks->frontier;
  fd_fork_t const *          pool        = forks->pool;

  for( fd_fork_frontier_iter_t iter = fd_fork_frontier_iter_init( frontier, pool );
       !fd_fork_frontier_iter_done( iter, frontier, pool );
       iter = fd_fork_frontier_iter_next( iter, frontier, pool ) ) {

    fd_fork_t const * fork = fd_fork_frontier_iter_ele_const( iter, frontier, pool );
    if( FD_LIKELY( is_same_fork( latest_vote, fork, ghost ) ) ) return fork;
  }

  /* TODO this can happen if somehow prune our last vote fork or we
     discard it due to equivocation. Both these cases are currently
     unhandled. */

  FD_LOG_ERR( ( "None of the frontier forks matched our last vote fork. Halting." ) );
}

fd_fork_t const *
fd_tower_vote_fork_select( fd_tower_t *       tower,
                           fd_forks_t const * forks,
                           fd_acc_mgr_t *     acc_mgr,
                           fd_ghost_t const * ghost ) {

  fd_fork_t const * vote_fork = NULL;

  fd_tower_vote_t const * latest_vote = fd_tower_votes_peek_tail_const( tower->votes );
  fd_fork_t const *       best        = fd_tower_best_fork_select( tower, forks, ghost );

  /* Optimize for when there is just one fork (most of the time). */

  if( FD_LIKELY( !latest_vote || is_same_fork( latest_vote, best, ghost ) ) ) {

    /* The best fork is on the same fork and we can vote for
       best_fork->slot if we pass the threshold check. */

    if( FD_LIKELY( fd_tower_threshold_check( tower, best, acc_mgr ) ) ) vote_fork = best;

  } else {

    /* The best fork is on a different fork, so try to switch if we pass
       lockout and switch threshold. */

    if( FD_UNLIKELY( fd_tower_lockout_check( tower, best, ghost ) &&
                     fd_tower_switch_check( tower, best, ghost ) ) ) {
      fd_tower_vote_t const * vote = fd_tower_votes_peek_tail_const( tower->votes );
      FD_LOG_NOTICE( ( "[fd_tower_vote_fork_select] switching to best fork %lu from last vote "
                       "(slot: %lu conf: %lu)",
                       best->slot,
                       vote->slot,
                       vote->conf ) );
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
       curr = fd_vote_accounts_pair_t_map_successor( epoch_bank->stakes.vote_accounts
                                                         .vote_accounts_pool,
                                                     curr ) ) {

#if FD_TOWER_USE_HANDHOLDING
    if( FD_UNLIKELY( fd_tower_vote_accs_cnt( tower->vote_accs ) ==
                     fd_tower_vote_accs_max( tower->vote_accs ) ) )
      FD_LOG_ERR( ( "fd_tower_vote_accs overflow." ) );
#endif

    if( FD_UNLIKELY( curr->elem.stake > 0UL ) ) {
      fd_tower_vote_accs_push_tail( tower->vote_accs,
                                    ( fd_tower_vote_acc_t ){ .addr  = &curr->elem.key,
                                                             .stake = curr->elem.stake } );
    }
    total_stake += curr->elem.stake;
  }
  tower->total_stake = total_stake;
}

void
fd_tower_fork_update( fd_tower_t const * tower,
                      fd_fork_t const *  fork,
                      fd_acc_mgr_t *     acc_mgr,
                      fd_blockstore_t *  blockstore,
                      fd_ghost_t *       ghost ) {
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

  // if( fork->slot == 279803918 ) {
  //   FD_LOG_NOTICE(("parent_slot: %lu", parent_slot));
  //   FD_PARAM_UNUSED fd_ghost_node_t * ps1 = fd_ghost_node_query( ghost, parent_slot );
  //   FD_PARAM_UNUSED fd_ghost_node_t * ps2 = fd_ghost_node_query( ghost, 279803917 );
  //   __asm__("int $3");
  // }
  fd_ghost_node_t * ghost_node = fd_ghost_node_insert( ghost, fork->slot, parent_slot );

#if FD_TOWER_USE_HANDHOLDING
  if( FD_UNLIKELY( !ghost_node ) ) {
    FD_LOG_ERR( ( "failed to insert ghost node %lu", fork->slot ) );
  }
#endif

  for( fd_tower_vote_accs_iter_t iter = fd_tower_vote_accs_iter_init_rev( tower->vote_accs );
       !fd_tower_vote_accs_iter_done_rev( tower->vote_accs, iter );
       iter = fd_tower_vote_accs_iter_prev( tower->vote_accs, iter ) ) {

    fd_tower_vote_acc_t * vote_acc      = fd_tower_vote_accs_iter_ele( tower->vote_accs, iter );
    fd_pubkey_t const *   vote_acc_addr = vote_acc->addr;

    FD_SCRATCH_SCOPE_BEGIN {
      fd_valloc_t               valloc               = fd_scratch_virtual();
      fd_vote_state_versioned_t vote_state_versioned = { 0 };

      int rc = vote_state_versioned_get( acc_mgr,
                                         fork->slot_ctx.funk_txn,
                                         valloc,
                                         vote_acc_addr,
                                         &vote_state_versioned );
      if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_ERR( ( "[fd_tower_fork_update] failed to get vote account %32J", vote_acc_addr ) );
      }

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

      fd_ghost_replay_vote_upsert( ghost, vote_slot, &vote_state->node_pubkey, vote_acc->stake );
    }
    FD_SCRATCH_SCOPE_END;
  }
}

void
fd_tower_vote( fd_tower_t const * tower, ulong slot ) {
  /* First, simulate a vote for slot. We do this purely for
     implementation convenience and code reuse.

     As the name of this function indicates, we are not just
     simulating and in fact voting for this fork by pushing this a new
     vote onto the tower. */

  ulong cnt = simulate_vote( tower->votes, slot );

  /* Subtract the simulated vote. */

  cnt--;

  /* Pop everything that got expired. */

  while( fd_tower_votes_cnt( tower->votes ) > cnt ) {
    fd_tower_votes_pop_tail( tower->votes );
  }

  /* Increase confirmations (double lockouts) in consecutive votes. */

  ulong prev_conf = 0;
  for( fd_tower_votes_iter_t iter = fd_tower_votes_iter_init_rev( tower->votes );
       !fd_tower_votes_iter_done_rev( tower->votes, iter );
       iter = fd_tower_votes_iter_prev( tower->votes, iter ) ) {
    fd_tower_vote_t * vote = fd_tower_votes_iter_ele( tower->votes, iter );
    if( FD_UNLIKELY( vote->conf != ++prev_conf ) ) {
      break;
    }
    vote->conf++;
  }

  /* Add the new vote to the tower. */

  fd_tower_votes_push_tail( tower->votes, ( fd_tower_vote_t ){ .slot = slot, .conf = 1 } );
}

void
fd_tower_print( fd_tower_t const * tower ) {
  print( tower->votes );
}
