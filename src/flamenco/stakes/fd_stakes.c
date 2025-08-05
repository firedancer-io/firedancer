#include "fd_stakes.h"
#include "../runtime/fd_acc_mgr.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../runtime/program/fd_stake_program.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"

ulong
fd_stake_weights_by_node( fd_vote_accounts_global_t const * accs,
                          fd_vote_stake_weight_t *          weights ) {
  fd_vote_accounts_pair_global_t_mapnode_t * pool = fd_vote_accounts_vote_accounts_pool_join( accs );
  fd_vote_accounts_pair_global_t_mapnode_t * root = fd_vote_accounts_vote_accounts_root_join( accs );

  /* For each active vote account, return (vote_key, node_identity, stake), sorted by (stake, vote) */
  ulong weights_cnt = 0;
  for( fd_vote_accounts_pair_global_t_mapnode_t * n = fd_vote_accounts_pair_global_t_map_minimum( pool, root );
                                           n;
                                           n = fd_vote_accounts_pair_global_t_map_successor( pool, n ) ) {

    /* ... filter(|(stake, _)| *stake != 0u64) */
    if( n->elem.stake == 0UL ) continue;

    /* Copy output values */
    memcpy( weights[ weights_cnt ].vote_key.uc, n->elem.key.uc, sizeof(fd_pubkey_t) );
    weights[ weights_cnt ].stake = n->elem.stake;
    uchar * vote_account_data = fd_solana_account_data_join( &n->elem.value );
    /* node_pubkey is at offset 4, no need to fully deserialize the account(s) */
    memcpy( weights[ weights_cnt ].id_key.uc, vote_account_data+4UL, sizeof(fd_pubkey_t) );
    weights_cnt++;
  }

  sort_vote_weights_by_stake_vote_inplace( weights, weights_cnt );
  return weights_cnt;
}

/* Helper function to deserialize a vote account. If successful, populates vote account info in `elem`
   and saves the decoded vote state in `vote_state` */
static fd_vote_state_versioned_t *
deserialize_and_update_vote_account( fd_exec_slot_ctx_t *                       slot_ctx,
                                     fd_vote_accounts_pair_global_t_mapnode_t * elem,
                                     fd_stake_weight_t_mapnode_t *              stake_delegations_root,
                                     fd_stake_weight_t_mapnode_t *              stake_delegations_pool,
                                     fd_pubkey_t const *                        vote_account_pubkey,
                                     fd_spad_t *                                runtime_spad ) {

  FD_TXN_ACCOUNT_DECL( vote_account );
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( vote_account,
                                                           vote_account_pubkey,
                                                           slot_ctx->funk,
                                                           slot_ctx->funk_txn ) ) ) {
    FD_LOG_DEBUG(( "Vote account not found" ));
    return NULL;
  }

  // Deserialize the vote account and ensure its in the correct state
  int err;
  fd_vote_state_versioned_t * res = fd_bincode_decode_spad(
      vote_state_versioned, runtime_spad,
      fd_txn_account_get_data( vote_account ),
      fd_txn_account_get_data_len( vote_account ),
      &err );
  if( FD_UNLIKELY( err ) ) {
    return NULL;
  }

  // Get the stake amount from the stake delegations map
  fd_stake_weight_t_mapnode_t temp;
  temp.elem.key = *vote_account_pubkey;
  fd_stake_weight_t_mapnode_t * entry = fd_stake_weight_t_map_find( stake_delegations_pool, stake_delegations_root, &temp );
  elem->elem.stake = ( entry==NULL ) ? 0UL : entry->elem.stake;

  return res;
}

static void
compute_stake_delegations(
    fd_epoch_info_t *             temp_info,
    ulong const                   epoch,
    fd_stake_history_t const *    history,
    ulong *                       new_rate_activation_epoch,
    fd_stake_weight_t_mapnode_t * delegation_pool,
    fd_stake_weight_t_mapnode_t * delegation_root,
    ulong                         vote_states_pool_sz,
    fd_spad_t *                   spad,
    ulong                         end_idx
) {
  fd_epoch_info_pair_t const * stake_infos = temp_info->stake_infos;

  FD_SPAD_FRAME_BEGIN( spad ) {

  /* Create a temporary <pubkey, stake> map to hold delegations */
  void * mem = fd_spad_alloc( spad, fd_stake_weight_t_map_align(), fd_stake_weight_t_map_footprint( vote_states_pool_sz ) );
  fd_stake_weight_t_mapnode_t * temp_pool = fd_stake_weight_t_map_join( fd_stake_weight_t_map_new( mem, vote_states_pool_sz ) );
  fd_stake_weight_t_mapnode_t * temp_root = NULL;

  fd_stake_weight_t_mapnode_t temp;
  for( ulong i=0UL; i<end_idx; i++ ) {
    fd_delegation_t const * delegation = &stake_infos[i].stake.delegation;
    temp.elem.key = delegation->voter_pubkey;

    // Skip any delegations that are not in the delegation pool
    fd_stake_weight_t_mapnode_t * delegation_entry = fd_stake_weight_t_map_find( delegation_pool, delegation_root, &temp );
    if( FD_UNLIKELY( delegation_entry==NULL ) ) {
      continue;
    }

    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating( delegation, epoch, history, new_rate_activation_epoch );
    delegation_entry = fd_stake_weight_t_map_find( temp_pool, temp_root, &temp );
    if( FD_UNLIKELY( delegation_entry==NULL ) ) {
      delegation_entry = fd_stake_weight_t_map_acquire( temp_pool );
      delegation_entry->elem.key   = delegation->voter_pubkey;
      delegation_entry->elem.stake = new_entry.effective;
      fd_stake_weight_t_map_insert( temp_pool, &temp_root, delegation_entry );
    } else {
      delegation_entry->elem.stake += new_entry.effective;
    }
  }

  // Update the parent delegation pool with the calculated delegation values
  for( fd_stake_weight_t_mapnode_t * elem = fd_stake_weight_t_map_minimum( temp_pool, temp_root );
                                      elem;
                                      elem = fd_stake_weight_t_map_successor( temp_pool, elem ) ) {
    fd_stake_weight_t_mapnode_t * output_delegation_node = fd_stake_weight_t_map_find( delegation_pool, delegation_root, elem );
    output_delegation_node->elem.stake += elem->elem.stake;
  }

  } FD_SPAD_FRAME_END;

}


/* Populates vote accounts with updated delegated stake from the next cached epoch stakes into temp_info */
void
fd_populate_vote_accounts( fd_exec_slot_ctx_t *       slot_ctx,
                           fd_stake_history_t const * history,
                           ulong *                    new_rate_activation_epoch,
                           fd_epoch_info_t *          temp_info,
                           fd_spad_t *                runtime_spad ) {


  /* Initialize a temporary vote states cache */
  fd_account_keys_global_t *         vote_account_keys        = fd_bank_vote_account_keys_locking_modify( slot_ctx->bank );
  fd_account_keys_pair_t_mapnode_t * vote_account_keys_pool   = fd_account_keys_account_keys_pool_join( vote_account_keys );
  fd_account_keys_pair_t_mapnode_t * vote_account_keys_root   = fd_account_keys_account_keys_root_join( vote_account_keys );
  ulong                              vote_account_keys_map_sz = vote_account_keys_pool ? fd_account_keys_pair_t_map_size( vote_account_keys_pool, vote_account_keys_root ) : 0UL;

  fd_vote_accounts_global_t const *          vote_accounts               = fd_bank_curr_epoch_stakes_locking_query( slot_ctx->bank );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_pool          = fd_vote_accounts_vote_accounts_pool_join( vote_accounts );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root          = fd_vote_accounts_vote_accounts_root_join( vote_accounts );
  ulong                                      vote_accounts_stakes_map_sz = vote_accounts_pool ? fd_vote_accounts_pair_global_t_map_size( vote_accounts_pool, vote_accounts_root ) : 0UL;

  ulong vote_states_pool_sz   = vote_accounts_stakes_map_sz + vote_account_keys_map_sz;
  temp_info->vote_states_root = NULL;
  uchar * pool_mem = fd_spad_alloc( runtime_spad, fd_vote_info_pair_t_map_align(), fd_vote_info_pair_t_map_footprint( vote_states_pool_sz ) );
  temp_info->vote_states_pool = fd_vote_info_pair_t_map_join( fd_vote_info_pair_t_map_new( pool_mem, vote_states_pool_sz ) );

  /* Create a map of <pubkey, stake> to store the total stake of each vote account. */
  void * mem = fd_spad_alloc( runtime_spad, fd_stake_weight_t_map_align(), fd_stake_weight_t_map_footprint( vote_states_pool_sz ) );
  fd_stake_weight_t_mapnode_t * pool = fd_stake_weight_t_map_join( fd_stake_weight_t_map_new( mem, vote_states_pool_sz ) );
  fd_stake_weight_t_mapnode_t * root = NULL;

  /* We can optimize this function by only iterating over the vote accounts (since there's much fewer of them) instead of all
     of the stake accounts, and pre-inserting them into the delegations pool. This way, the delegation calculations can be tpooled. */
  for( fd_vote_accounts_pair_global_t_mapnode_t * elem = fd_vote_accounts_pair_global_t_map_minimum( vote_accounts_pool, vote_accounts_root );
        elem;
        elem = fd_vote_accounts_pair_global_t_map_successor( vote_accounts_pool, elem ) ) {
    fd_stake_weight_t_mapnode_t * entry = fd_stake_weight_t_map_acquire( pool );
    entry->elem.key                     = elem->elem.key;
    entry->elem.stake                   = 0UL;
    fd_stake_weight_t_map_insert( pool, &root, entry );
  }

  fd_bank_curr_epoch_stakes_end_locking_query( slot_ctx->bank );

  for( fd_account_keys_pair_t_mapnode_t * n = fd_account_keys_pair_t_map_minimum( vote_account_keys_pool, vote_account_keys_root );
        n;
        n = fd_account_keys_pair_t_map_successor( vote_account_keys_pool, n ) ) {
    fd_stake_weight_t_mapnode_t temp;
    temp.elem.key = n->elem.key;
    fd_stake_weight_t_mapnode_t * entry = fd_stake_weight_t_map_find( pool, root, &temp );
    if( FD_LIKELY( entry==NULL ) ) {
      entry             = fd_stake_weight_t_map_acquire( pool );
      entry->elem.key   = n->elem.key;
      entry->elem.stake = 0UL;
      fd_stake_weight_t_map_insert( pool, &root, entry );
    }
  }

  fd_bank_vote_account_keys_end_locking_modify( slot_ctx->bank );

  compute_stake_delegations(
      temp_info,
      fd_bank_epoch_get( slot_ctx->bank ),
      history,
      new_rate_activation_epoch,
      pool,
      root,
      vote_states_pool_sz,
      runtime_spad,
      temp_info->stake_infos_len
  );

  // Iterate over each vote account in the epoch stakes cache and populate the new vote accounts pool
  /* NOTE: we use epoch_bank->next_epoch_stakes because Agave indexes their epoch stakes cache by leader schedule epoch.
     This means that the epoch stakes for epoch E are indexed by epoch E+1.
     This is just a workaround for now.
     https://github.com/anza-xyz/agave/blob/v2.2.14/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L309 */
  ulong total_epoch_stake = 0UL;

  fd_vote_accounts_global_t const *          next_epoch_stakes      = fd_bank_next_epoch_stakes_locking_query( slot_ctx->bank );
  fd_vote_accounts_pair_global_t_mapnode_t * next_epoch_stakes_pool = fd_vote_accounts_vote_accounts_pool_join( next_epoch_stakes );
  fd_vote_accounts_pair_global_t_mapnode_t * next_epoch_stakes_root = fd_vote_accounts_vote_accounts_root_join( next_epoch_stakes );

  for( fd_vote_accounts_pair_global_t_mapnode_t * elem = fd_vote_accounts_pair_global_t_map_minimum( next_epoch_stakes_pool, next_epoch_stakes_root );
       elem;
       elem = fd_vote_accounts_pair_global_t_map_successor( next_epoch_stakes_pool, elem ) ) {
    fd_pubkey_t const * vote_account_pubkey = &elem->elem.key;
    FD_TXN_ACCOUNT_DECL( acc );
    int rc = fd_txn_account_init_from_funk_readonly( acc, vote_account_pubkey, slot_ctx->funk, slot_ctx->funk_txn );
    FD_TEST( rc == 0 );
    uchar * data     = fd_solana_account_data_join( &elem->elem.value );
    ulong   data_len = elem->elem.value.data_len;

    int err;
    fd_vote_state_versioned_t * vote_state = fd_bincode_decode_spad( vote_state_versioned,
                                                                     runtime_spad,
                                                                     data,
                                                                     data_len,
                                                                     &err );

    if( FD_LIKELY( vote_state ) ) {
      total_epoch_stake += elem->elem.stake;
      // Insert into the temporary vote states cache
      fd_vote_info_pair_t_mapnode_t * new_vote_state_node = fd_vote_info_pair_t_map_acquire( temp_info->vote_states_pool );
      new_vote_state_node->elem.account = *vote_account_pubkey;
      new_vote_state_node->elem.state   = *vote_state;
      fd_vote_info_pair_t_map_insert( temp_info->vote_states_pool, &temp_info->vote_states_root, new_vote_state_node );
    } else {
      FD_LOG_WARNING(( "Failed to deserialize vote account" ));
    }
  }
  fd_bank_next_epoch_stakes_end_locking_query( slot_ctx->bank );

  fd_bank_total_epoch_stake_set( slot_ctx->bank, total_epoch_stake );
}

/*
Refresh vote accounts.

This updates the epoch bank stakes vote_accounts cache - that is, the total amount
of delegated stake each vote account has, using the current delegation values from inside each
stake account. Contrary to the Agave equivalent, it also merges the stakes cache vote accounts with the
new vote account keys from this epoch.

https://github.com/solana-labs/solana/blob/c091fd3da8014c0ef83b626318018f238f506435/runtime/src/stakes.rs#L562 */
void
fd_refresh_vote_accounts( fd_exec_slot_ctx_t *       slot_ctx,
                          fd_stake_history_t const * history,
                          ulong *                    new_rate_activation_epoch,
                          fd_epoch_info_t *          temp_info,
                          fd_spad_t *                runtime_spad ) {

  fd_vote_accounts_global_t *                vote_accounts             = fd_bank_curr_epoch_stakes_locking_modify( slot_ctx->bank );
  fd_vote_accounts_pair_global_t_mapnode_t * stakes_vote_accounts_pool = fd_vote_accounts_vote_accounts_pool_join( vote_accounts );
  fd_vote_accounts_pair_global_t_mapnode_t * stakes_vote_accounts_root = fd_vote_accounts_vote_accounts_root_join( vote_accounts );

  fd_account_keys_global_t *         vote_account_keys      = fd_bank_vote_account_keys_locking_modify( slot_ctx->bank );
  fd_account_keys_pair_t_mapnode_t * vote_account_keys_pool = fd_account_keys_account_keys_pool_join( vote_account_keys );
  fd_account_keys_pair_t_mapnode_t * vote_account_keys_root = fd_account_keys_account_keys_root_join( vote_account_keys );

  ulong vote_account_keys_map_sz    = !!vote_account_keys_pool ? fd_account_keys_pair_t_map_size( vote_account_keys_pool, vote_account_keys_root ) : 0UL;
  ulong vote_accounts_stakes_map_sz = !!stakes_vote_accounts_pool ? fd_vote_accounts_pair_global_t_map_size( stakes_vote_accounts_pool, stakes_vote_accounts_root ) : 0UL;
  ulong vote_states_pool_sz         = vote_accounts_stakes_map_sz + vote_account_keys_map_sz;

  /* Initialize a temporary vote states cache */
  temp_info->vote_states_root = NULL;
  uchar * pool_mem = fd_spad_alloc( runtime_spad, fd_vote_info_pair_t_map_align(), fd_vote_info_pair_t_map_footprint( vote_states_pool_sz ) );
  temp_info->vote_states_pool = fd_vote_info_pair_t_map_join( fd_vote_info_pair_t_map_new( pool_mem, vote_states_pool_sz ) );

  /* Create a map of <pubkey, stake> to store the total stake of each vote account. */
  void * mem = fd_spad_alloc( runtime_spad, fd_stake_weight_t_map_align(), fd_stake_weight_t_map_footprint( vote_states_pool_sz ) );
  fd_stake_weight_t_mapnode_t * pool = fd_stake_weight_t_map_join( fd_stake_weight_t_map_new( mem, vote_states_pool_sz ) );
  fd_stake_weight_t_mapnode_t * root = NULL;

  /* We can optimize this function by only iterating over the vote accounts (since there's much fewer of them) instead of all
     of the stake accounts, and pre-inserting them into the delegations pool. This way, the delegation calculations can be tpooled. */
  for( fd_vote_accounts_pair_global_t_mapnode_t * elem = fd_vote_accounts_pair_global_t_map_minimum( stakes_vote_accounts_pool, stakes_vote_accounts_root );
        elem;
        elem = fd_vote_accounts_pair_global_t_map_successor( stakes_vote_accounts_pool, elem ) ) {
    fd_stake_weight_t_mapnode_t * entry = fd_stake_weight_t_map_acquire( pool );
    entry->elem.key                     = elem->elem.key;
    entry->elem.stake                   = 0UL;
    fd_stake_weight_t_map_insert( pool, &root, entry );
  }

  for( fd_account_keys_pair_t_mapnode_t * n = fd_account_keys_pair_t_map_minimum( vote_account_keys_pool, vote_account_keys_root );
        n;
        n = fd_account_keys_pair_t_map_successor( vote_account_keys_pool, n ) ) {
    fd_stake_weight_t_mapnode_t temp;
    temp.elem.key = n->elem.key;
    fd_stake_weight_t_mapnode_t * entry = fd_stake_weight_t_map_find( pool, root, &temp );
    if( FD_LIKELY( entry==NULL ) ) {
      entry             = fd_stake_weight_t_map_acquire( pool );
      entry->elem.key   = n->elem.key;
      entry->elem.stake = 0UL;
      fd_stake_weight_t_map_insert( pool, &root, entry );
    }
  }

  compute_stake_delegations(
      temp_info,
      fd_bank_epoch_get( slot_ctx->bank ),
      history,
      new_rate_activation_epoch,
      pool,
      root,
      vote_states_pool_sz,
      runtime_spad,
      temp_info->stake_infos_len
  );

  // Iterate over each vote account in the epoch stakes cache and populate the new vote accounts pool
  ulong total_epoch_stake = 0UL;
  for( fd_vote_accounts_pair_global_t_mapnode_t * elem = fd_vote_accounts_pair_global_t_map_minimum( stakes_vote_accounts_pool, stakes_vote_accounts_root );
       elem;
       elem = fd_vote_accounts_pair_global_t_map_successor( stakes_vote_accounts_pool, elem ) ) {

    fd_pubkey_t const *         vote_account_pubkey = &elem->elem.key;
    fd_vote_state_versioned_t * vote_state          = deserialize_and_update_vote_account( slot_ctx,
                                                                                           elem,
                                                                                           root,
                                                                                           pool,
                                                                                           vote_account_pubkey,
                                                                                           runtime_spad );
    if( FD_LIKELY( vote_state ) ) {
      total_epoch_stake += elem->elem.stake;
      // Insert into the temporary vote states cache
      /* FIXME: This copy copies over some local pointers, which means
         that the allocation done when deserializing the vote account
         is not freed until the end of the epoch boundary processing. */
      fd_vote_info_pair_t_mapnode_t * new_vote_state_node = fd_vote_info_pair_t_map_acquire( temp_info->vote_states_pool );
      new_vote_state_node->elem.account = *vote_account_pubkey;
      new_vote_state_node->elem.state   = *vote_state;
      fd_vote_info_pair_t_map_insert( temp_info->vote_states_pool, &temp_info->vote_states_root, new_vote_state_node );
    } else {
      FD_LOG_WARNING(( "Failed to deserialize vote account" ));
    }
  }

  // Update the epoch stakes cache with new vote accounts from the epoch
  for( fd_account_keys_pair_t_mapnode_t * n = fd_account_keys_pair_t_map_minimum( vote_account_keys_pool, vote_account_keys_root );
        n;
        n = fd_account_keys_pair_t_map_successor( vote_account_keys_pool, n ) ) {

    fd_pubkey_t const * vote_account_pubkey = &n->elem.key;
    fd_vote_accounts_pair_global_t_mapnode_t key;
    key.elem.key = *vote_account_pubkey;

    /* No need to process duplicate vote account keys. This is a mostly redundant check
       since upserting vote accounts also checks against the vote stakes, but this is
       there anyways in case that ever changes */
    if( FD_UNLIKELY( fd_vote_accounts_pair_global_t_map_find( stakes_vote_accounts_pool, stakes_vote_accounts_root, &key ) ) ) {
      continue;
    }

    fd_vote_accounts_pair_global_t_mapnode_t * new_vote_node = fd_vote_accounts_pair_global_t_map_acquire( stakes_vote_accounts_pool );
    fd_vote_state_versioned_t *                vote_state    = deserialize_and_update_vote_account( slot_ctx,
                                                                                                    new_vote_node,
                                                                                                    root,
                                                                                                    pool,
                                                                                                    vote_account_pubkey,
                                                                                                    runtime_spad );

    if( FD_UNLIKELY( !vote_state ) ) {
      fd_vote_accounts_pair_global_t_map_release( stakes_vote_accounts_pool, new_vote_node );
      continue;
    }

    // Insert into the epoch stakes cache and temporary vote states cache
    fd_vote_accounts_pair_global_t_map_insert( stakes_vote_accounts_pool, &stakes_vote_accounts_root, new_vote_node );
    total_epoch_stake += new_vote_node->elem.stake;

    fd_vote_info_pair_t_mapnode_t * new_vote_state_node = fd_vote_info_pair_t_map_acquire( temp_info->vote_states_pool );
    new_vote_state_node->elem.account = *vote_account_pubkey;
    new_vote_state_node->elem.state   = *vote_state;
    fd_vote_info_pair_t_map_insert( temp_info->vote_states_pool, &temp_info->vote_states_root, new_vote_state_node );
  }
  fd_vote_accounts_vote_accounts_pool_update( vote_accounts, stakes_vote_accounts_pool );
  fd_vote_accounts_vote_accounts_root_update( vote_accounts, stakes_vote_accounts_root );

  fd_bank_curr_epoch_stakes_end_locking_modify( slot_ctx->bank );

  fd_bank_total_epoch_stake_set( slot_ctx->bank, total_epoch_stake );

  /* At this point, we need to flush the vote account keys cache */
  vote_account_keys_pool = fd_account_keys_account_keys_pool_join( vote_account_keys );
  vote_account_keys_root = fd_account_keys_account_keys_root_join( vote_account_keys );
  fd_account_keys_pair_t_map_release_tree( vote_account_keys_pool, vote_account_keys_root );
  vote_account_keys_root = NULL;
  fd_account_keys_account_keys_pool_update( vote_account_keys, vote_account_keys_pool );
  fd_account_keys_account_keys_root_update( vote_account_keys, vote_account_keys_root );
  fd_bank_vote_account_keys_end_locking_modify( slot_ctx->bank );
}

static void
accumulate_stake_cache_delegations(
    fd_stake_delegations_t *   stake_delegations,
    fd_exec_slot_ctx_t const * slot_ctx,
    fd_stake_history_t const * history,
    ulong *                    new_rate_activation_epoch,
    fd_stake_history_entry_t * accumulator,
    fd_epoch_info_t *          temp_info,
    ulong                      epoch ) {

  fd_stake_delegation_t *     pool = fd_stake_delegations_get_pool( stake_delegations );
  fd_stake_delegation_map_t * map  = fd_stake_delegations_get_map( stake_delegations );

  ulong effective    = 0UL;
  ulong activating   = 0UL;
  ulong deactivating = 0UL;

  for( fd_stake_delegation_map_iter_t iter = fd_stake_delegation_map_iter_init( map, pool );
       !fd_stake_delegation_map_iter_done( iter, map, pool );
       iter = fd_stake_delegation_map_iter_next( iter, map, pool ) ) {
    fd_stake_delegation_t * stake_delegation = fd_stake_delegation_map_iter_ele( iter, map, pool );

    FD_TXN_ACCOUNT_DECL( acc );
    int rc = fd_txn_account_init_from_funk_readonly( acc,
                                                      &stake_delegation->stake_account,
                                                      slot_ctx->funk,
                                                      slot_ctx->funk_txn );
    if( FD_UNLIKELY( rc!=FD_ACC_MGR_SUCCESS || fd_txn_account_get_lamports( acc )==0UL ) ) {
      FD_LOG_WARNING(("Failed to init account"));
      continue;
    }

    fd_stake_state_v2_t stake_state;
    rc = fd_stake_get_state( acc, &stake_state );
    if( FD_UNLIKELY( rc != 0 ) ) {
      FD_LOG_WARNING(("Failed to get stake state"));
      continue;
    }

    if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
      FD_LOG_WARNING(("Not a stake"));
      continue;
    }

    if( FD_UNLIKELY( stake_state.inner.stake.stake.delegation.stake == 0 ) ) {
      continue;
    }

    fd_delegation_t * delegation = &stake_state.inner.stake.stake.delegation;

    ulong delegation_idx = temp_info->stake_infos_len++;
    temp_info->stake_infos[delegation_idx].stake   = stake_state.inner.stake.stake;
    temp_info->stake_infos[delegation_idx].account = stake_delegation->stake_account;

    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating( delegation, epoch, history, new_rate_activation_epoch );
    effective    += new_entry.effective;
    activating   += new_entry.activating;
    deactivating += new_entry.deactivating;
  }

  accumulator->effective    += effective;
  accumulator->activating   += activating;
  accumulator->deactivating += deactivating;

}

/* Accumulates information about epoch stakes into `temp_info`, which is a temporary cache
   used to save intermediate state about stake and vote accounts to avoid them from having to
   be recomputed on every access, especially at the epoch boundary. Also collects stats in `accumulator` */
void
fd_accumulate_stake_infos( fd_exec_slot_ctx_t const * slot_ctx,
                           fd_stake_delegations_t *   stake_delegations,
                           fd_stake_history_t const * history,
                           ulong *                    new_rate_activation_epoch,
                           fd_stake_history_entry_t * accumulator,
                           fd_epoch_info_t *          temp_info,
                           fd_spad_t *                runtime_spad ) {

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  ulong epoch = fd_bank_epoch_get( slot_ctx->bank );

  accumulate_stake_cache_delegations(
      stake_delegations,
      slot_ctx,
      history,
      new_rate_activation_epoch,
      accumulator,
      temp_info,
      epoch
  );

  temp_info->stake_infos_new_keys_start_idx = temp_info->stake_infos_len;

  fd_account_keys_global_t const *   stake_account_keys = fd_bank_stake_account_keys_locking_query( slot_ctx->bank );
  fd_account_keys_pair_t_mapnode_t * account_keys_pool  = fd_account_keys_account_keys_pool_join( stake_account_keys );
  fd_account_keys_pair_t_mapnode_t * account_keys_root  = fd_account_keys_account_keys_root_join( stake_account_keys );

  if( !account_keys_pool ) {
    fd_bank_stake_account_keys_end_locking_query( slot_ctx->bank );
    return;
  }

  /* The number of account keys aggregated across the epoch is usually small, so there aren't much performance gains from tpooling here. */
  for( fd_account_keys_pair_t_mapnode_t * n = fd_account_keys_pair_t_map_minimum( account_keys_pool, account_keys_root );
       n;
       n = fd_account_keys_pair_t_map_successor( account_keys_pool, n ) ) {
    FD_TXN_ACCOUNT_DECL( acc );
    int rc = fd_txn_account_init_from_funk_readonly(acc, &n->elem.key, slot_ctx->funk, slot_ctx->funk_txn );
    if( FD_UNLIKELY( rc!=FD_ACC_MGR_SUCCESS || fd_txn_account_get_lamports( acc )==0UL ) ) {
      continue;
    }

    fd_stake_state_v2_t stake_state;
    rc = fd_stake_get_state( acc, &stake_state );
    if( FD_UNLIKELY( rc != 0 ) ) {
      continue;
    }

    if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
      continue;
    }

    if( FD_UNLIKELY( stake_state.inner.stake.stake.delegation.stake==0UL ) ) {
      continue;
    }

    fd_delegation_t * delegation = &stake_state.inner.stake.stake.delegation;
    temp_info->stake_infos[temp_info->stake_infos_len  ].stake    = stake_state.inner.stake.stake;
    temp_info->stake_infos[temp_info->stake_infos_len++].account  = n->elem.key;
    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating( delegation, epoch, history, new_rate_activation_epoch );
    accumulator->effective    += new_entry.effective;
    accumulator->activating   += new_entry.activating;
    accumulator->deactivating += new_entry.deactivating;
  }

  fd_bank_stake_account_keys_end_locking_query( slot_ctx->bank );

  } FD_SPAD_FRAME_END;
}

/* https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L169 */
void
fd_stakes_activate_epoch( fd_exec_slot_ctx_t *  slot_ctx,
                          ulong *               new_rate_activation_epoch,
                          fd_epoch_info_t *     temp_info,
                          fd_spad_t *           runtime_spad ) {

  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( (void*)fd_bank_stake_delegations_locking_modify( slot_ctx->bank ) );

  fd_account_keys_global_t const * stake_account_keys = fd_bank_stake_account_keys_locking_query( slot_ctx->bank );

  fd_account_keys_pair_t_mapnode_t * account_keys_pool = NULL;
  fd_account_keys_pair_t_mapnode_t * account_keys_root = NULL;

  if( stake_account_keys ) {
    account_keys_pool = fd_account_keys_account_keys_pool_join( stake_account_keys );
    account_keys_root = fd_account_keys_account_keys_root_join( stake_account_keys );
  }

  /* Current stake delegations: list of all current delegations in stake_delegations
     https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L180 */
  /* Add a new entry to the Stake History sysvar for the previous epoch
     https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L181-L192 */

  fd_stake_history_t const * history = fd_sysvar_stake_history_read( slot_ctx->funk, slot_ctx->funk_txn, runtime_spad );
  if( FD_UNLIKELY( !history ) ) FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));

  ulong stake_delegations_size = fd_stake_delegations_cnt( stake_delegations );

  stake_delegations_size += !!account_keys_pool ? fd_account_keys_pair_t_map_size( account_keys_pool, account_keys_root ) : 0UL;

  fd_bank_stake_account_keys_end_locking_query( slot_ctx->bank );

  temp_info->stake_infos_len = 0UL;
  temp_info->stake_infos     = (fd_epoch_info_pair_t *)fd_spad_alloc( runtime_spad, FD_EPOCH_INFO_PAIR_ALIGN, sizeof(fd_epoch_info_pair_t)*stake_delegations_size );
  fd_memset( temp_info->stake_infos, 0, sizeof(fd_epoch_info_pair_t)*stake_delegations_size );

  fd_stake_history_entry_t accumulator = {
    .effective    = 0UL,
    .activating   = 0UL,
    .deactivating = 0UL
  };

  /* Accumulate stats for stake accounts */
  fd_accumulate_stake_infos(
      slot_ctx,
      stake_delegations,
      history,
      new_rate_activation_epoch,
      &accumulator,
      temp_info,
      runtime_spad );

  /* https://github.com/anza-xyz/agave/blob/v2.1.6/runtime/src/stakes.rs#L359 */
  fd_epoch_stake_history_entry_pair_t new_elem = {
    .epoch        = fd_bank_epoch_get( slot_ctx->bank ),
    .entry        = {
      .effective    = accumulator.effective,
      .activating   = accumulator.activating,
      .deactivating = accumulator.deactivating
    }
  };

  fd_sysvar_stake_history_update( slot_ctx, &new_elem, runtime_spad );

  fd_bank_stake_delegations_end_locking_modify( slot_ctx->bank );

}

int
write_stake_state( fd_txn_account_t *    stake_acc_rec,
                   fd_stake_state_v2_t * stake_state ) {

  ulong encoded_stake_state_size = fd_stake_state_v2_size(stake_state);

  fd_bincode_encode_ctx_t ctx = {
    .data    = fd_txn_account_get_data_mut( stake_acc_rec ),
    .dataend = fd_txn_account_get_data_mut( stake_acc_rec ) + encoded_stake_state_size,
  };
  if( FD_UNLIKELY( fd_stake_state_v2_encode( stake_state, &ctx ) != FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "fd_stake_state_encode failed" ));
  }

  return 0;
}
