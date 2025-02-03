#include "fd_stakes.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/context/fd_exec_epoch_ctx.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../runtime/program/fd_stake_program.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"

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

    /* Extract node pubkey */
    fd_pubkey_t const * node_pubkey = &n->elem.value.node_pubkey;

    fd_pubkey_t null_key = {0};
    if( memcmp( node_pubkey, null_key.uc, sizeof(fd_pubkey_t) ) == 0 ) {
      FD_LOG_WARNING(( "vote account %s skipped", FD_BASE58_ENC_32_ALLOCA( n->elem.key.key ) ));
      continue;
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
                          fd_stake_weight_t *        weights,
                          fd_spad_t *                runtime_spad ) {

  /* Estimate size required to store temporary data structures */

  /* TODO size is the wrong method name for this */
  ulong vote_acc_cnt = fd_vote_accounts_pair_t_map_size( accs->vote_accounts_pool, accs->vote_accounts_root );

  ulong rb_align     = fd_stake_weight_t_map_align();
  ulong rb_footprint = fd_stake_weight_t_map_footprint( vote_acc_cnt );

  /* Create rb tree */

  void * pool_mem = fd_spad_alloc( runtime_spad, rb_align, rb_footprint );
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

/* Helper function to deserialize a vote account. If successful, populates vote account info in `elem`
   and saves the decoded vote state in `vote_state` */
static uchar
deserialize_and_update_vote_account( fd_exec_slot_ctx_t *                slot_ctx,
                                     fd_vote_accounts_pair_t_mapnode_t * elem,
                                     fd_stake_weight_t_mapnode_t *       stake_delegations_root,
                                     fd_stake_weight_t_mapnode_t *       stake_delegations_pool,
                                     fd_pubkey_t const *                 vote_account_pubkey,
                                     fd_vote_state_versioned_t *         vote_state,
                                     fd_spad_t *                         runtime_spad ) {

  FD_BORROWED_ACCOUNT_DECL( vote_account );
  if( FD_UNLIKELY( fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, vote_account_pubkey, vote_account ) ) ) {
    FD_LOG_DEBUG(( "Vote account not found" ));
    return 1;
  }

  // Deserialize the vote account and ensure its in the correct state
  fd_bincode_decode_ctx_t decode = {
    .data    = vote_account->const_data,
    .dataend = vote_account->const_data + vote_account->const_meta->dlen,
    .valloc  = fd_spad_virtual( runtime_spad ),
  };

  if( FD_UNLIKELY( fd_vote_state_versioned_decode( vote_state, &decode ) ) ) {
    return 1;
  }

  fd_vote_block_timestamp_t last_timestamp;
  fd_pubkey_t node_pubkey;

  switch( vote_state->discriminant ) {
    case fd_vote_state_versioned_enum_current:
      last_timestamp = vote_state->inner.current.last_timestamp;
      node_pubkey    = vote_state->inner.current.node_pubkey;
      break;
    case fd_vote_state_versioned_enum_v0_23_5:
      last_timestamp = vote_state->inner.v0_23_5.last_timestamp;
      node_pubkey    = vote_state->inner.v0_23_5.node_pubkey;
      break;
    case fd_vote_state_versioned_enum_v1_14_11:
      last_timestamp = vote_state->inner.v1_14_11.last_timestamp;
      node_pubkey    = vote_state->inner.v1_14_11.node_pubkey;
      break;
    default:
      __builtin_unreachable();
  }

  fd_memcpy( &elem->elem.key, vote_account->pubkey, sizeof(fd_pubkey_t));
  elem->elem.value.lamports = vote_account->const_meta->info.lamports;

  fd_memcpy(elem->elem.value.node_pubkey.uc, node_pubkey.uc, sizeof(fd_pubkey_t));
  elem->elem.value.last_timestamp_ts   = last_timestamp.timestamp;
  elem->elem.value.last_timestamp_slot = last_timestamp.slot;

  fd_memcpy( &elem->elem.value.owner, vote_account->const_meta->info.owner, sizeof(fd_pubkey_t) );
  elem->elem.value.executable = (uchar)vote_account->const_meta->info.executable;
  elem->elem.value.rent_epoch = vote_account->const_meta->info.rent_epoch;

  // Get the stake amount from the stake delegations map
  fd_stake_weight_t_mapnode_t temp;
  fd_memcpy( &temp.elem.key, vote_account_pubkey, sizeof(fd_pubkey_t) );
  fd_stake_weight_t_mapnode_t * entry = fd_stake_weight_t_map_find( stake_delegations_pool, stake_delegations_root, &temp );
  elem->elem.stake = ( entry==NULL ) ? 0UL : entry->elem.stake;

  return 0;
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
  fd_slot_bank_t *  slot_bank  = &slot_ctx->slot_bank;
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_stakes_t *     stakes     = &epoch_bank->stakes;

  // Initialize a temporary vote states cache
  ulong vote_states_pool_sz   = fd_vote_accounts_pair_t_map_size( stakes->vote_accounts.vote_accounts_pool, stakes->vote_accounts.vote_accounts_root )
                              + fd_account_keys_pair_t_map_size( slot_bank->vote_account_keys.account_keys_pool, slot_bank->vote_account_keys.account_keys_root );
  temp_info->vote_states_root = NULL;
  temp_info->vote_states_pool = fd_vote_info_pair_t_map_alloc( fd_spad_virtual( runtime_spad ), vote_states_pool_sz ); 

  /* Create a map of <pubkey, stake> to store the total stake of each vote account.
     TODO: I think `maplen` can be bounded by `vote_states_pool_sz`, assuming there aren't any stake delegations
     that point to a voter pubkey that is not in the epoch stakes / new vote account keys cache. */
  static const ulong maplen = 10000;
  void * mem = fd_spad_alloc( runtime_spad, fd_stake_weight_t_map_align(), fd_stake_weight_t_map_footprint(maplen));
  fd_stake_weight_t_mapnode_t * pool = fd_stake_weight_t_map_join(fd_stake_weight_t_map_new(mem, maplen));
  fd_stake_weight_t_mapnode_t * root = NULL;

  // Iterate over each stake delegation and accumulate the stake amount associated with the given vote account.
  for( ulong idx=0UL; idx<temp_info->stake_infos_len; idx++ ) {
      // Fetch the delegation associated with this stake account
      fd_delegation_t * delegation = &temp_info->stake_infos[idx].stake.delegation;
      fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating(
        delegation, stakes->epoch, history, new_rate_activation_epoch );

      // Add this delegation amount to the total stake of the vote account
      ulong delegation_stake = new_entry.effective;
      fd_stake_weight_t_mapnode_t temp;
      fd_memcpy(&temp.elem.key, &delegation->voter_pubkey, sizeof(fd_pubkey_t));
      fd_stake_weight_t_mapnode_t * entry  = fd_stake_weight_t_map_find(pool, root, &temp);
      if (entry != NULL) {
        entry->elem.stake += delegation_stake;
      } else {
        entry = fd_stake_weight_t_map_acquire( pool );
        fd_memcpy( &entry->elem.key, &delegation->voter_pubkey, sizeof(fd_pubkey_t));
        entry->elem.stake = delegation_stake;
        fd_stake_weight_t_map_insert( pool, &root, entry );
      }
  }

  // Iterate over each vote account in the epoch stakes cache and populate the new vote accounts pool
  ulong total_epoch_stake = 0UL;
  for( fd_vote_accounts_pair_t_mapnode_t * elem = fd_vote_accounts_pair_t_map_minimum( stakes->vote_accounts.vote_accounts_pool, stakes->vote_accounts.vote_accounts_root );
        elem;
        elem = fd_vote_accounts_pair_t_map_successor( stakes->vote_accounts.vote_accounts_pool, elem ) ) {
    fd_pubkey_t const * vote_account_pubkey = &elem->elem.key;
    fd_vote_state_versioned_t vote_state[1] = {0};
    if( FD_LIKELY( !deserialize_and_update_vote_account( slot_ctx, elem, root, pool, vote_account_pubkey, vote_state, runtime_spad ) ) ) {
      total_epoch_stake += elem->elem.stake;

      // Insert into the temporary vote states cache
      fd_vote_info_pair_t_mapnode_t * new_vote_state_node = fd_vote_info_pair_t_map_acquire( temp_info->vote_states_pool );
      fd_memcpy( &new_vote_state_node->elem.account, vote_account_pubkey, sizeof(fd_pubkey_t) );
      fd_memcpy( &new_vote_state_node->elem.state, vote_state, sizeof(fd_vote_state_versioned_t) );
      fd_vote_info_pair_t_map_insert( temp_info->vote_states_pool, &temp_info->vote_states_root, new_vote_state_node );
    }
  }

  // Update the epoch stakes cache with new vote accounts from the epoch
  for( fd_account_keys_pair_t_mapnode_t * n = fd_account_keys_pair_t_map_minimum( slot_bank->vote_account_keys.account_keys_pool, slot_bank->vote_account_keys.account_keys_root );
        n;
        n = fd_account_keys_pair_t_map_successor( slot_bank->vote_account_keys.account_keys_pool, n ) ) {

    fd_pubkey_t const * vote_account_pubkey = &n->elem.key;
    fd_vote_state_versioned_t vote_state[1] = {0};
    fd_vote_accounts_pair_t_mapnode_t key;
    fd_memcpy( &key.elem.key, vote_account_pubkey, sizeof(fd_pubkey_t) );
    
    /* No need to process duplicate vote account keys. This is a mostly redundant check
       since upserting vote accounts also checks against the vote stakes, but this is
       there anyways in case that ever changes */ 
    if( FD_UNLIKELY( fd_vote_accounts_pair_t_map_find( stakes->vote_accounts.vote_accounts_pool, stakes->vote_accounts.vote_accounts_root, &key ) ) ) {
      continue;
    }

    fd_vote_accounts_pair_t_mapnode_t * new_vote_node = fd_vote_accounts_pair_t_map_acquire( stakes->vote_accounts.vote_accounts_pool );
    if( FD_UNLIKELY( deserialize_and_update_vote_account( slot_ctx, new_vote_node, root, pool, vote_account_pubkey, vote_state, runtime_spad ) ) ) {
      fd_vote_accounts_pair_t_map_release( stakes->vote_accounts.vote_accounts_pool, new_vote_node );
      continue;
    }

    // Insert into the epoch stakes cache and temporary vote states cache
    fd_vote_accounts_pair_t_map_insert( stakes->vote_accounts.vote_accounts_pool, &stakes->vote_accounts.vote_accounts_root, new_vote_node );
    total_epoch_stake += new_vote_node->elem.stake;

    fd_vote_info_pair_t_mapnode_t * new_vote_state_node = fd_vote_info_pair_t_map_acquire( temp_info->vote_states_pool );
    fd_memcpy( &new_vote_state_node->elem.account, vote_account_pubkey, sizeof(fd_pubkey_t) );
    fd_memcpy( &new_vote_state_node->elem.state, vote_state, sizeof(fd_vote_state_versioned_t) );
    fd_vote_info_pair_t_map_insert( temp_info->vote_states_pool, &temp_info->vote_states_root, new_vote_state_node );
  }

  slot_ctx->epoch_ctx->total_epoch_stake = total_epoch_stake;

  fd_account_keys_pair_t_map_release_tree( slot_bank->vote_account_keys.account_keys_pool, slot_bank->vote_account_keys.account_keys_root );
  slot_bank->vote_account_keys.account_keys_root = NULL;
}

/* Accumulates information about epoch stakes into `temp_info`, which is a temporary cache
   used to save intermediate state about stake and vote accounts to avoid them from having to
   be recomputed on every access, especially at the epoch boundary. Also collects stats in `accumulator` */
void 
fd_accumulate_stake_infos( fd_exec_slot_ctx_t const * slot_ctx,
                           fd_stakes_t const *        stakes,
                           fd_stake_history_t const * history,
                           ulong *                    new_rate_activation_epoch,
                           fd_stake_history_entry_t * accumulator,
                           fd_epoch_info_t *          temp_info,
                           fd_spad_t *                spad ) {
  ulong delegation_idx = 0UL;

  for( fd_delegation_pair_t_mapnode_t * n = fd_delegation_pair_t_map_minimum( stakes->stake_delegations_pool, stakes->stake_delegations_root ); 
                                        n; 
                                        n = fd_delegation_pair_t_map_successor( stakes->stake_delegations_pool, n ) ) {
    FD_BORROWED_ACCOUNT_DECL(acc);
    int rc = fd_acc_mgr_view(slot_ctx->acc_mgr, slot_ctx->funk_txn, &n->elem.account, acc);
    if ( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS || acc->const_meta->info.lamports == 0 ) ) {
      continue;
    }

    fd_stake_state_v2_t stake_state;
    rc = fd_stake_get_state( acc, spad, &stake_state );
    if( FD_UNLIKELY( rc != 0 ) ) {
      continue;
    }

    if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
      continue;
    }

    if( FD_UNLIKELY( stake_state.inner.stake.stake.delegation.stake == 0 ) ) {
      continue;
    }

    fd_delegation_t * delegation = &stake_state.inner.stake.stake.delegation;
    fd_memcpy(&temp_info->stake_infos[delegation_idx  ].stake, &stake_state.inner.stake.stake, sizeof(fd_stake_t));
    fd_memcpy(&temp_info->stake_infos[delegation_idx++].account, &n->elem.account, sizeof(fd_pubkey_t));
    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating( delegation, stakes->epoch, history, new_rate_activation_epoch );
    accumulator->effective    += new_entry.effective;
    accumulator->activating   += new_entry.activating;
    accumulator->deactivating += new_entry.deactivating;
  }

  for( fd_account_keys_pair_t_mapnode_t * n = fd_account_keys_pair_t_map_minimum( slot_ctx->slot_bank.stake_account_keys.account_keys_pool, slot_ctx->slot_bank.stake_account_keys.account_keys_root );
       n;
       n = fd_account_keys_pair_t_map_successor( slot_ctx->slot_bank.stake_account_keys.account_keys_pool, n ) ) {
    FD_BORROWED_ACCOUNT_DECL(acc);
    int rc = fd_acc_mgr_view(slot_ctx->acc_mgr, slot_ctx->funk_txn, &n->elem.key, acc);
    if( FD_UNLIKELY( rc!=FD_ACC_MGR_SUCCESS || acc->const_meta->info.lamports==0UL ) ) {
      continue;
    }

    fd_stake_state_v2_t stake_state;
    rc = fd_stake_get_state( acc, spad, &stake_state );
    if( FD_UNLIKELY( rc != 0) ) {
      continue;
    }

    if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
      continue;
    }

    if( FD_UNLIKELY( stake_state.inner.stake.stake.delegation.stake==0UL ) ) {
      continue;
    }

    fd_delegation_t * delegation = &stake_state.inner.stake.stake.delegation;
    fd_memcpy(&temp_info->stake_infos[delegation_idx  ].stake.delegation, &stake_state.inner.stake.stake, sizeof(fd_stake_t));
    fd_memcpy(&temp_info->stake_infos[delegation_idx++].account, &n->elem.key, sizeof(fd_pubkey_t));
    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating( delegation, stakes->epoch, history, new_rate_activation_epoch );
    accumulator->effective    += new_entry.effective;
    accumulator->activating   += new_entry.activating;
    accumulator->deactivating += new_entry.deactivating;
  }

  temp_info->stake_infos_len = delegation_idx;
}

/* https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L169 */
void
fd_stakes_activate_epoch( fd_exec_slot_ctx_t *  slot_ctx,
                          ulong *               new_rate_activation_epoch,
                          fd_epoch_info_t *     temp_info,
                          fd_spad_t *           runtime_spad ) {

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_stakes_t *     stakes     = &epoch_bank->stakes;

  /* Current stake delegations: list of all current delegations in stake_delegations
     https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L180 */
  /* Add a new entry to the Stake History sysvar for the previous epoch
     https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L181-L192 */

  fd_stake_history_t const * history = fd_sysvar_cache_stake_history( slot_ctx->sysvar_cache );
  if( FD_UNLIKELY( !history ) ) FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));

  ulong stake_delegations_size = fd_delegation_pair_t_map_size(
    stakes->stake_delegations_pool, stakes->stake_delegations_root );
  stake_delegations_size += fd_account_keys_pair_t_map_size(
    slot_ctx->slot_bank.stake_account_keys.account_keys_pool, slot_ctx->slot_bank.stake_account_keys.account_keys_root );
  temp_info->stake_infos_len = stake_delegations_size;
  temp_info->stake_infos     = (fd_epoch_info_pair_t *)fd_spad_alloc( runtime_spad, FD_EPOCH_INFO_PAIR_ALIGN, FD_EPOCH_INFO_PAIR_FOOTPRINT*stake_delegations_size );
  fd_memset( temp_info->stake_infos, 0, FD_EPOCH_INFO_PAIR_FOOTPRINT*stake_delegations_size );

  fd_stake_history_entry_t accumulator = {
    .effective    = 0UL,
    .activating   = 0UL,
    .deactivating = 0UL
  };

  /* Accumulate stats for stake accounts */
  fd_accumulate_stake_infos( slot_ctx, stakes, history, new_rate_activation_epoch, &accumulator, temp_info, runtime_spad );

  /* https://github.com/anza-xyz/agave/blob/v2.1.6/runtime/src/stakes.rs#L359 */
  fd_stake_history_entry_t new_elem = {
    .epoch        = stakes->epoch,
    .effective    = accumulator.effective,
    .activating   = accumulator.activating,
    .deactivating = accumulator.deactivating
  };

  fd_sysvar_stake_history_update( slot_ctx, &new_elem, runtime_spad );

  /* Refresh the sysvar cache stake history entry after updating the sysvar.
      We need to do this here because it is used in subsequent places in the epoch boundary. */
  fd_bincode_destroy_ctx_t sysvar_cache_destroy_ctx = { .valloc = fd_spad_virtual( slot_ctx->sysvar_cache->runtime_spad ) };
  fd_stake_history_destroy( slot_ctx->sysvar_cache->val_stake_history, &sysvar_cache_destroy_ctx );
  fd_sysvar_cache_restore_stake_history( slot_ctx->sysvar_cache, slot_ctx->acc_mgr, slot_ctx->funk_txn );

}

int
write_stake_state( fd_borrowed_account_t *  stake_acc_rec,
                   fd_stake_state_v2_t *    stake_state ) {

  ulong encoded_stake_state_size = fd_stake_state_v2_size(stake_state);

  fd_bincode_encode_ctx_t ctx = {
    .data = stake_acc_rec->data,
    .dataend = stake_acc_rec->data + encoded_stake_state_size,
  };
  if( FD_UNLIKELY( fd_stake_state_v2_encode( stake_state, &ctx ) != FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "fd_stake_state_encode failed" ));
  }

  return 0;
}
