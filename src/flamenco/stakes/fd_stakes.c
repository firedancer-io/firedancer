#include "fd_stakes.h"

/* fd_stakes_accum_by_node converts Stakes (unordered list of (vote acc,
   active stake) tuples) to StakedNodes (rbtree mapping (node identity)
   => (active stake) ordered by node identity).  Returns the tree root. */

static fd_stake_weight_t_mapnode_t *
fd_stakes_accum_by_node( fd_vote_accounts_t const * in,
                         fd_stake_weight_t_mapnode_t *    out_pool ) {

  /* Stakes::staked_nodes(&self: Stakes) -> HashMap<Pubkey, u64> */

  fd_vote_accounts_pair_t_mapnode_t * in_pool = in->vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t * in_root = in->vote_accounts_root;

  /* VoteAccounts::staked_nodes(&self: VoteAccounts) -> HashMap<Pubkey, u64> */

  /* For each active vote account, accumulate (node_identity, stake) by
     summing stake. */

  fd_stake_weight_t_mapnode_t * out_root = NULL;

  for( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum( in_pool, in_root );
                                           n;
                                           n = fd_vote_accounts_pair_t_map_successor( in_pool, n ) ) {

    /* ... filter(|(stake, _)| *stake != 0u64) */
    if( n->elem.stake == 0UL ) continue;

    /* Create scratch allocator for current scope */
    FD_SCRATCH_SCOPED_FRAME;  fd_valloc_t scratch = fd_scratch_virtual();

    /* Decode vote account */
    uchar const * vote_acc_data = n->elem.value.data;
    fd_bincode_decode_ctx_t decode_ctx = {
      .data    = vote_acc_data,
      .dataend = vote_acc_data + n->elem.value.data_len,
      .valloc  = scratch,
    };
    fd_vote_state_versioned_t vote_state_versioned;
    if( FD_UNLIKELY( 0!=fd_vote_state_versioned_decode( &vote_state_versioned, &decode_ctx ) ) ) {
      /* TODO can this occur on a real cluster? */
      FD_LOG_WARNING(( "Failed to deserialize vote account %32J", n->elem.key.key ));
      continue;
    }

    /* Extract node pubkey */
    fd_pubkey_t const * node_pubkey;
    switch( vote_state_versioned.discriminant ) {
    case fd_vote_state_versioned_enum_v0_23_5:
      node_pubkey = &vote_state_versioned.inner.v0_23_5.node_pubkey; break;
    case fd_vote_state_versioned_enum_current:
      node_pubkey = &vote_state_versioned.inner.current.node_pubkey; break;
    default:
      __builtin_unreachable();
    }

    /* Check if node identity was previously visited */
    fd_stake_weight_t_mapnode_t * query = fd_stake_weight_t_map_acquire( out_pool );
    FD_TEST( query );
    query->elem.key = *node_pubkey;
    fd_stake_weight_t_mapnode_t * node = fd_stake_weight_t_map_find( out_pool, out_root, query );

    if( FD_UNLIKELY( node ) ) {
      /* Accumulate to previously created entry */
      fd_stake_weight_t_map_release( out_pool, query );
      node->elem.stake += n->elem.stake;
    } else {
      /* Create new entry */
      node = query;
      node->elem.stake = n->elem.stake;
      fd_stake_weight_t_map_insert( out_pool, &out_root, node );
    }

  }

  return out_root;
}

/* fd_stake_weight_sort sorts the given array of stake weights with
   length stakes_cnt by tuple (stake, pubkey) in descending order. */

FD_FN_CONST static int
fd_stakes_sort_before( fd_stake_weight_t a,
                       fd_stake_weight_t b ) {

  if( a.stake > b.stake ) return 1;
  if( a.stake < b.stake ) return 0;
  if( memcmp( &a.key, &b.key, 32UL )>0 ) return 1;
  return 0;
}

#define SORT_NAME        fd_stakes_sort
#define SORT_KEY_T       fd_stake_weight_t
#define SORT_BEFORE(a,b) fd_stakes_sort_before( (a), (b) )
#include "../../util/tmpl/fd_sort.c"

void
fd_stake_weight_sort( fd_stake_weight_t * stakes,
                      ulong               stakes_cnt ) {
  fd_stakes_sort_inplace( stakes, stakes_cnt );
}

/* fd_stakes_export_sorted converts StakedNodes (rbtree mapping
   (node identity) => (active stake) from fd_stakes_accum_by_node) to
   a list of fd_stake_weights_t. */

static ulong
fd_stakes_export( fd_stake_weight_t_mapnode_t const * const in_pool,
                  fd_stake_weight_t_mapnode_t const * const root,
                  fd_stake_weight_t *           const out ) {

  fd_stake_weight_t * out_end = out;

  for( fd_stake_weight_t_mapnode_t const * ele = fd_stake_weight_t_map_minimum( (fd_stake_weight_t_mapnode_t *)in_pool, (fd_stake_weight_t_mapnode_t *)root ); ele; ele = (fd_stake_weight_t_mapnode_t *)fd_stake_weight_t_map_successor( (fd_stake_weight_t_mapnode_t *)in_pool, (fd_stake_weight_t_mapnode_t *)ele ) ) {
    *out_end++ = ele->elem;
  }

  return (ulong)( out_end - out );
}

ulong
fd_stake_weights_by_node( fd_vote_accounts_t const * accs,
                          fd_stake_weight_t *        weights ) {

  /* Enter scratch frame for duration for function */

  if( FD_UNLIKELY( !fd_scratch_push_is_safe() ) ) {
    FD_LOG_WARNING(( "fd_scratch_push() failed" ));
    return ULONG_MAX;
  }

  FD_SCRATCH_SCOPED_FRAME;

  /* Estimate size required to store temporary data structures */

  /* TODO size is the wrong method name for this */
  ulong vote_acc_cnt = fd_vote_accounts_pair_t_map_size( accs->vote_accounts_pool, accs->vote_accounts_root );

  ulong rb_align     = fd_stake_weight_t_map_align();
  ulong rb_footprint = fd_stake_weight_t_map_footprint( vote_acc_cnt );

  if( FD_UNLIKELY( !fd_scratch_alloc_is_safe( rb_align, rb_footprint ) ) ) {
    FD_LOG_WARNING(( "insufficient scratch space: need %lu align %lu footprint",
                     rb_align, rb_footprint ));
    return ULONG_MAX;
  }

  /* Create rb tree */

  void * pool_mem = fd_scratch_alloc( rb_align, rb_footprint );
         pool_mem = fd_stake_weight_t_map_new( pool_mem, vote_acc_cnt );
  fd_stake_weight_t_mapnode_t * pool = fd_stake_weight_t_map_join( pool_mem );
  if( FD_UNLIKELY( !pool_mem ) ) FD_LOG_CRIT(( "fd_stake_weights_new() failed" ));

  /* Accumulate stakes to rb tree */

  fd_stake_weight_t_mapnode_t const * root = fd_stakes_accum_by_node( accs, pool );

  /* Export to sorted list */

  ulong weights_cnt = fd_stakes_export( pool, root, weights );
  fd_stake_weight_sort( weights, weights_cnt );
  return weights_cnt;
}

double warmup_cooldown_rate( ulong current_epoch, ulong * new_rate_activation_epoch ) {
  ulong unwrapped = new_rate_activation_epoch ? *new_rate_activation_epoch : ULONG_MAX;
  return current_epoch < unwrapped ? 0.25 : 0.09;
}

fd_stake_history_entry_t stake_and_activating( fd_delegation_t const * delegation, ulong target_epoch, fd_stake_history_t * stake_history, ulong * new_rate_activation_epoch ) {
  ulong delegated_stake = delegation->stake;

  fd_stake_history_entry_t * cluster_stake_at_activation_epoch = NULL;

  fd_stake_history_epochentry_pair_t k;
  k.epoch = delegation->activation_epoch;


  if (delegation->activation_epoch == ULONG_MAX) {
    // if is bootstrap
    fd_stake_history_entry_t entry = {
      .effective = delegated_stake,
      .activating = 0
    };

    return entry;
  } else if (delegation->activation_epoch == delegation->deactivation_epoch) {
    fd_stake_history_entry_t entry = {
      .effective = 0,
      .activating = 0
    };

    return entry;
  } else if ( target_epoch == delegation->activation_epoch ) {
    fd_stake_history_entry_t entry = {
      .effective = 0,
      .activating = delegated_stake
    };

    return entry;
  } else if ( target_epoch < delegation->activation_epoch ) {
    fd_stake_history_entry_t entry = {
      .effective = 0,
      .activating = 0
    };
    return entry;
  }
  else if (stake_history != NULL) {
    fd_stake_history_epochentry_pair_t * n = fd_stake_history_entries_treap_ele_query( stake_history->treap, k.epoch, stake_history->pool );

    if (NULL != n)
      cluster_stake_at_activation_epoch = &n->entry;

    if (cluster_stake_at_activation_epoch == NULL) {
      fd_stake_history_entry_t entry = {
        .effective = delegated_stake,
        .activating = 0,
      };

      return entry;
    }

    ulong prev_epoch = delegation->activation_epoch;
    fd_stake_history_entry_t * prev_cluster_stake = cluster_stake_at_activation_epoch;

    ulong current_epoch;
    ulong current_effective_stake = 0;
    for (;;) {
      current_epoch = prev_epoch + 1;
      if (prev_cluster_stake->activating == 0) {
        break;
      }

      ulong remaining_activating_stake = delegated_stake - current_effective_stake;
      double weight = (double)remaining_activating_stake / (double)prev_cluster_stake->activating;

      double newly_effective_cluster_stake = (double)prev_cluster_stake->effective * warmup_cooldown_rate(current_epoch, new_rate_activation_epoch);
      ulong newly_effective_stake = (ulong)(weight * newly_effective_cluster_stake);
      newly_effective_stake = (newly_effective_stake == 0) ? 1 : newly_effective_stake;

      current_effective_stake += newly_effective_stake;
      if (current_effective_stake >= delegated_stake) {
          current_effective_stake = delegated_stake;
          break;
      }

      if (current_epoch >= target_epoch || current_epoch >= delegation->deactivation_epoch) {
        break;
      }

      // Find the current epoch in history
      fd_stake_history_epochentry_pair_t k;
      k.epoch = current_epoch;
      fd_stake_history_epochentry_pair_t * n = fd_stake_history_entries_treap_ele_query( stake_history->treap, k.epoch, stake_history->pool );


      if (NULL != n) {
        prev_epoch = current_epoch;
        prev_cluster_stake = &n->entry;
      } else
        break;
    }

    fd_stake_history_entry_t entry = {
      .effective = current_effective_stake,
      .activating = delegated_stake - current_effective_stake,
    };
    return entry;
  } else {
    // no history or I've dropped out of history, so assume fully effective
    fd_stake_history_entry_t entry = {
      .effective = delegated_stake,
      .activating = 0,
    };

    return entry;
  }
}

fd_stake_history_entry_t stake_activating_and_deactivating( fd_delegation_t const * delegation, ulong target_epoch, fd_stake_history_t * stake_history, ulong * new_rate_activation_epoch ) {

  fd_stake_history_entry_t stake_and_activating_entry = stake_and_activating( delegation, target_epoch, stake_history, new_rate_activation_epoch );

  ulong effective_stake = stake_and_activating_entry.effective;
  ulong activating_stake = stake_and_activating_entry.activating;

  fd_stake_history_entry_t * cluster_stake_at_activation_epoch = NULL;

  fd_stake_history_epochentry_pair_t k;
  k.epoch = delegation->deactivation_epoch;

  if (target_epoch < delegation->deactivation_epoch) {
    // if is bootstrap
    if (activating_stake == 0) {
      fd_stake_history_entry_t entry = {
        .effective = effective_stake,
        .deactivating = 0,
        .activating = 0
      };
      return entry;
    } else {
      fd_stake_history_entry_t entry = {
        .effective = effective_stake,
        .deactivating = 0,
        .activating = activating_stake
      };
      return entry;
    }
  } else if (target_epoch == delegation->deactivation_epoch) {
    fd_stake_history_entry_t entry = {
      .effective = effective_stake,
      .deactivating = effective_stake,
      .activating = 0
    };
    return entry;
  } else if (stake_history != NULL) {
    fd_stake_history_epochentry_pair_t * n = fd_stake_history_entries_treap_ele_query( stake_history->treap, k.epoch, stake_history->pool );


    if (NULL != n) {
      cluster_stake_at_activation_epoch = &n->entry;
    }

    if (cluster_stake_at_activation_epoch == NULL) {
      fd_stake_history_entry_t entry = {
        .effective = 0,
        .activating = 0,
        .deactivating = 0
      };

      return entry;
    }
    ulong prev_epoch = delegation->deactivation_epoch;
    fd_stake_history_entry_t * prev_cluster_stake = cluster_stake_at_activation_epoch;

    ulong current_epoch;
    ulong current_effective_stake = effective_stake;
    for (;;) {
      current_epoch = prev_epoch + 1;
      if (prev_cluster_stake->deactivating == 0) {
        break;
      }

      double weight = (double)current_effective_stake / (double)prev_cluster_stake->deactivating;

      double newly_not_effective_cluster_stake = (double)prev_cluster_stake->effective * warmup_cooldown_rate(current_epoch, new_rate_activation_epoch);
      ulong newly_not_effective_stake = (ulong)(weight * newly_not_effective_cluster_stake);
      newly_not_effective_stake = (newly_not_effective_stake == 0) ? 1 : newly_not_effective_stake;

      current_effective_stake = fd_ulong_sat_sub(current_effective_stake, newly_not_effective_stake);
      if (current_effective_stake == 0) {
          break;
      }

      if (current_epoch >= target_epoch) {
        break;
      }

      // Find the current epoch in history
      fd_stake_history_epochentry_pair_t k;
      k.epoch = current_epoch;
      fd_stake_history_epochentry_pair_t * n = fd_stake_history_entries_treap_ele_query( stake_history->treap, k.epoch, stake_history->pool );
;

      if (NULL != n) {
        prev_epoch = current_epoch;
        prev_cluster_stake = &n->entry;
      } else
        break;
    }

    fd_stake_history_entry_t entry = {
      .effective = current_effective_stake,
      .deactivating = current_effective_stake,
      .activating = 0
    };

    return entry;
  } else {
     fd_stake_history_entry_t entry = {
      .effective = 0,
      .activating = 0,
      .deactivating = 0
    };

    return entry;
  }
}



/* https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L169 */
void
fd_stakes_activate_epoch( fd_global_ctx_t * global,
                          ulong             next_epoch ) {

  fd_stakes_t* stakes = &global->bank.stakes;

  /* Current stake delegations: list of all current delegations in stake_delegations
     https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L180 */
  /* Add a new entry to the Stake History sysvar for the previous epoch
     https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L181-L192 */

  fd_stake_history_t history;
  fd_sysvar_stake_history_read( global,  &history);

  fd_stake_history_entry_t accumulator = {
    .effective = 0,
    .activating = 0,
    .deactivating = 0
  };

  ulong * new_rate_activation_epoch = NULL;
  for ( fd_delegation_pair_t_mapnode_t * n = fd_delegation_pair_t_map_minimum(stakes->stake_delegations_pool, stakes->stake_delegations_root); n; n = fd_delegation_pair_t_map_successor(stakes->stake_delegations_pool, n) ) {
    fd_stake_history_entry_t new_entry = stake_activating_and_deactivating( &n->elem.delegation, stakes->epoch, &history, new_rate_activation_epoch );
    accumulator.effective += new_entry.effective;
    accumulator.activating += new_entry.activating;
    accumulator.deactivating += new_entry.deactivating;
  }

  fd_stake_history_epochentry_pair_t new_elem = {
    .epoch = stakes->epoch,
    .entry = accumulator
  };

  ulong idx = fd_stake_history_entries_pool_idx_acquire( stakes->stake_history.pool );
  stakes->stake_history.pool[ idx ] = new_elem;
  fd_sysvar_stake_history_update( global, &new_elem);

  /* Update the current epoch value */
  stakes->epoch = next_epoch;

  /* Refresh the stake distribution of vote accounts for the next epoch,
     using the updated Stake History.
     https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L194-L216 */
  fd_stake_weight_t_mapnode_t * pool = fd_stake_weight_t_map_alloc(global->valloc, 10000);
  fd_stake_weight_t_mapnode_t * root = NULL;

  fd_sysvar_stake_history_read( global,  &history);
  for ( fd_delegation_pair_t_mapnode_t * n = fd_delegation_pair_t_map_minimum(stakes->stake_delegations_pool, stakes->stake_delegations_root); n; n = fd_delegation_pair_t_map_successor(stakes->stake_delegations_pool, n) ) {
    ulong delegation_stake = stake_activating_and_deactivating( &n->elem.delegation, stakes->epoch, &history, new_rate_activation_epoch ).effective;
    fd_stake_weight_t_mapnode_t temp;
    fd_memcpy(&temp.elem.key, &n->elem.delegation.voter_pubkey, sizeof(fd_pubkey_t));
    fd_stake_weight_t_mapnode_t * entry  = fd_stake_weight_t_map_find(pool, root, &temp);
    if (entry != NULL) {
      entry->elem.stake += delegation_stake;
    } else {
      entry = fd_stake_weight_t_map_acquire( pool );
      fd_memcpy( &entry->elem.key, &n->elem.delegation.voter_pubkey, sizeof(fd_pubkey_t));
      entry->elem.stake = delegation_stake;
      fd_stake_weight_t_map_insert( pool, &root, entry );
    }
  }
  for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(stakes->vote_accounts.vote_accounts_pool, stakes->vote_accounts.vote_accounts_root); n; n = fd_vote_accounts_pair_t_map_successor(stakes->vote_accounts.vote_accounts_pool, n) ) {
    fd_stake_weight_t_mapnode_t temp;
    memcpy(&temp.elem.key, &n->elem.key, sizeof(fd_pubkey_t));
    fd_stake_weight_t_mapnode_t * entry = fd_stake_weight_t_map_find(pool, root, &temp);
    n->elem.stake = (entry == NULL) ? 0 : entry->elem.stake;
  }
}

int
write_stake_state( fd_global_ctx_t *   global,
                   fd_pubkey_t const * stake_acc,
                   fd_stake_state_t *  stake_state,
                   ushort              is_new_account ) {

  ulong encoded_stake_state_size = (is_new_account) ? STAKE_ACCOUNT_SIZE : fd_stake_state_size(stake_state);

  FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);

  int err = fd_acc_mgr_modify( global->acc_mgr, global->funk_txn, stake_acc, !!is_new_account, encoded_stake_state_size, stake_acc_rec );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "write_stake_state failed" ));
    return err;
  }

  if (is_new_account)
    fd_memset( stake_acc_rec->data, 0, encoded_stake_state_size );

  fd_bincode_encode_ctx_t ctx3;
  ctx3.data    = stake_acc_rec->data;
  ctx3.dataend = stake_acc_rec->data + encoded_stake_state_size;
  if( FD_UNLIKELY( fd_stake_state_encode( stake_state, &ctx3 )!=FD_BINCODE_SUCCESS ) )
    FD_LOG_ERR(("fd_stake_state_encode failed"));

  if( is_new_account )
    stake_acc_rec->meta->dlen = STAKE_ACCOUNT_SIZE;
  /* TODO Lamports? */
  stake_acc_rec->meta->info.executable = 0;
  stake_acc_rec->meta->info.rent_epoch = 0UL;
  memcpy( &stake_acc_rec->meta->info.owner, global->solana_stake_program, sizeof(fd_pubkey_t) );

  return FD_EXECUTOR_INSTR_SUCCESS;
}
