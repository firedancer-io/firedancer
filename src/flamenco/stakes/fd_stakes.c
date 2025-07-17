#include "fd_stakes.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../runtime/program/fd_stake_program.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"

/* fd_stakes_accum_by_node converts Stakes (unordered list of (vote acc,
   active stake) tuples) to StakedNodes (rbtree mapping (node identity)
   => (active stake) ordered by node identity).  Returns the tree root. */

static fd_stake_weight_t_mapnode_t *
fd_stakes_accum_by_node( fd_vote_accounts_global_t const * in,
                         fd_stake_weight_t_mapnode_t *     out_pool,
                         fd_spad_t *                       runtime_spad ) {

  /* Stakes::staked_nodes(&self: Stakes) -> HashMap<Pubkey, u64> */

  fd_vote_accounts_pair_global_t_mapnode_t * in_pool = fd_vote_accounts_vote_accounts_pool_join( in );
  fd_vote_accounts_pair_global_t_mapnode_t * in_root = fd_vote_accounts_vote_accounts_root_join( in );

  /* VoteAccounts::staked_nodes(&self: VoteAccounts) -> HashMap<Pubkey, u64> */

  /* For each active vote account, accumulate (node_identity, stake) by
     summing stake. */

  fd_stake_weight_t_mapnode_t * out_root = NULL;

  for( fd_vote_accounts_pair_global_t_mapnode_t * n = fd_vote_accounts_pair_global_t_map_minimum( in_pool, in_root );
                                           n;
                                           n = fd_vote_accounts_pair_global_t_map_successor( in_pool, n ) ) {

    /* ... filter(|(stake, _)| *stake != 0u64) */
    if( n->elem.stake == 0UL ) continue;

    int err;
    uchar * data     = fd_solana_account_data_join( &n->elem.value );
    ulong   data_len = n->elem.value.data_len;

    fd_vote_state_versioned_t * vsv = fd_bincode_decode_spad(
        vote_state_versioned, runtime_spad,
        data,
        data_len,
        &err );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Failed to decode vote account %s (%d)", FD_BASE58_ENC_32_ALLOCA( n->elem.key.key ), err ));
    }

    fd_pubkey_t node_pubkey;
    switch( vsv->discriminant ) {
      case fd_vote_state_versioned_enum_v0_23_5:
        node_pubkey = vsv->inner.v0_23_5.node_pubkey;
        break;
      case fd_vote_state_versioned_enum_v1_14_11:
        node_pubkey = vsv->inner.v1_14_11.node_pubkey;
        break;
      case fd_vote_state_versioned_enum_current:
        node_pubkey = vsv->inner.current.node_pubkey;
        break;
      default:
        __builtin_unreachable();
    }


    /* Extract node pubkey */

    fd_pubkey_t null_key = {0};
    if( memcmp( &node_pubkey, null_key.uc, sizeof(fd_pubkey_t) ) == 0 ) {
      FD_LOG_WARNING(( "vote account %s skipped", FD_BASE58_ENC_32_ALLOCA( n->elem.key.key ) ));
      continue;
    }
    /* Check if node identity was previously visited */
    fd_stake_weight_t_mapnode_t * query = fd_stake_weight_t_map_acquire( out_pool );
    if( FD_UNLIKELY( !query ) ) {
      FD_LOG_ERR(( "fd_stakes_accum_by_node() failed" ));
    }

    query->elem.key = node_pubkey;

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
fd_stake_weights_by_node( fd_vote_accounts_global_t const * accs,
                          fd_stake_weight_t *               weights,
                          fd_spad_t *                       runtime_spad ) {

  /* Estimate size required to store temporary data structures */

  fd_vote_accounts_pair_global_t_mapnode_t * vote_acc_pool = fd_vote_accounts_vote_accounts_pool_join( accs );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_acc_root = fd_vote_accounts_vote_accounts_root_join( accs );

  ulong vote_acc_cnt = fd_vote_accounts_pair_global_t_map_size( vote_acc_pool, vote_acc_root );

  ulong rb_align     = fd_stake_weight_t_map_align();
  ulong rb_footprint = fd_stake_weight_t_map_footprint( vote_acc_cnt );

  /* Create rb tree */

  void * pool_mem = fd_spad_alloc( runtime_spad, rb_align, rb_footprint );
  pool_mem = fd_stake_weight_t_map_new( pool_mem, vote_acc_cnt );
  fd_stake_weight_t_mapnode_t * pool = fd_stake_weight_t_map_join( pool_mem );
  if( FD_UNLIKELY( !pool_mem ) ) FD_LOG_CRIT(( "fd_stake_weights_new() failed" ));

  /* Accumulate stakes to rb tree */

  fd_stake_weight_t_mapnode_t const * root = fd_stakes_accum_by_node( accs, pool, runtime_spad );

  /* Export to sorted list */

  ulong weights_cnt = fd_stakes_export( pool, root, weights );
  fd_stake_weight_sort( weights, weights_cnt );

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
      vote_account->vt->get_data( vote_account ),
      vote_account->vt->get_data_len( vote_account ),
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
compute_stake_delegations( fd_epoch_info_t *                temp_info,
                           fd_compute_stake_delegations_t * task_args,
                           ulong                            worker_idx,
                           ulong                            start_idx,
                           ulong                            end_idx ) {


  fd_spad_t *                      spad                      = task_args->spads[worker_idx];
  fd_epoch_info_pair_t const *     stake_infos               = temp_info->stake_infos;
  ulong                            epoch                     = task_args->epoch;
  fd_stake_history_t const *       history                   = task_args->stake_history;
  ulong *                          new_rate_activation_epoch = task_args->new_rate_activation_epoch;
  fd_stake_weight_t_mapnode_t *    delegation_pool           = task_args->delegation_pool;
  fd_stake_weight_t_mapnode_t *    delegation_root           = task_args->delegation_root;
  ulong                            vote_states_pool_sz       = task_args->vote_states_pool_sz;

  FD_SPAD_FRAME_BEGIN( spad ) {

  /* Create a temporary <pubkey, stake> map to hold delegations */
  void * mem = fd_spad_alloc( spad, fd_stake_weight_t_map_align(), fd_stake_weight_t_map_footprint( vote_states_pool_sz ) );
  fd_stake_weight_t_mapnode_t * temp_pool = fd_stake_weight_t_map_join( fd_stake_weight_t_map_new( mem, vote_states_pool_sz ) );
  fd_stake_weight_t_mapnode_t * temp_root = NULL;

  fd_stake_weight_t_mapnode_t temp;
  for( ulong i=start_idx; i<end_idx; i++ ) {
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
    FD_ATOMIC_FETCH_AND_ADD( &output_delegation_node->elem.stake, elem->elem.stake );
  }

  } FD_SPAD_FRAME_END;

}


/* Populates vote accounts with updated delegated stake from the next cached epoch stakes into temp_info */
void
fd_populate_vote_accounts( fd_exec_slot_ctx_t *       slot_ctx,
                           fd_stake_history_t const * history,
                           ulong *                    new_rate_activation_epoch,
                           fd_epoch_info_t *          temp_info,
                           fd_spad_t * *              exec_spads,
                           fd_spad_t *                runtime_spad ) {


  /* Initialize a temporary vote states cache */
  fd_account_keys_global_t *         vote_account_keys        = fd_bank_vote_account_keys_locking_modify( slot_ctx->bank );
  fd_account_keys_pair_t_mapnode_t * vote_account_keys_pool   = fd_account_keys_account_keys_pool_join( vote_account_keys );
  fd_account_keys_pair_t_mapnode_t * vote_account_keys_root   = fd_account_keys_account_keys_root_join( vote_account_keys );
  ulong                              vote_account_keys_map_sz = vote_account_keys_pool ? fd_account_keys_pair_t_map_size( vote_account_keys_pool, vote_account_keys_root ) : 0UL;

  fd_stakes_global_t const *                 stakes                      = fd_bank_stakes_locking_query( slot_ctx->bank );
  fd_vote_accounts_global_t const *          vote_accounts               = &stakes->vote_accounts;
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

  fd_bank_stakes_end_locking_query( slot_ctx->bank );

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

  fd_compute_stake_delegations_t task_args  = {
    .epoch                     = stakes->epoch,
    .stake_history             = history,
    .new_rate_activation_epoch = new_rate_activation_epoch,
    .delegation_pool           = pool,
    .delegation_root           = root,
    .vote_states_pool_sz       = vote_states_pool_sz,
    .spads                     = exec_spads,
  };

  compute_stake_delegations( temp_info, &task_args, 0UL, 0UL, temp_info->stake_infos_len );

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
                          fd_spad_t * *              exec_spads,
                          fd_spad_t *                runtime_spad ) {

  fd_stakes_global_t *                       stakes                    = fd_bank_stakes_locking_modify( slot_ctx->bank );
  fd_vote_accounts_global_t *                vote_accounts             = &stakes->vote_accounts;
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

  fd_compute_stake_delegations_t task_args  = {
    .epoch                     = stakes->epoch,
    .stake_history             = history,
    .new_rate_activation_epoch = new_rate_activation_epoch,
    .delegation_pool           = pool,
    .delegation_root           = root,
    .vote_states_pool_sz       = vote_states_pool_sz,
    .spads                     = exec_spads,
  };

  compute_stake_delegations( temp_info, &task_args, 0UL, 0UL, temp_info->stake_infos_len );

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
  fd_vote_accounts_vote_accounts_pool_update( &stakes->vote_accounts, stakes_vote_accounts_pool );
  fd_vote_accounts_vote_accounts_root_update( &stakes->vote_accounts, stakes_vote_accounts_root );

  fd_bank_stakes_end_locking_modify( slot_ctx->bank );

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
accumulate_stake_cache_delegations( fd_delegation_pair_t_mapnode_t * *      delegations_roots,
                                    fd_accumulate_delegations_task_args_t * task_args,
                                    ulong                                   worker_idx,
                                    fd_delegation_pair_t_mapnode_t *        end_node ) {

  fd_exec_slot_ctx_t const *              slot_ctx                  = task_args->slot_ctx;
  fd_stake_history_t const *              history                   = task_args->stake_history;
  ulong *                                 new_rate_activation_epoch = task_args->new_rate_activation_epoch;
  fd_stake_history_entry_t *              accumulator               = task_args->accumulator;
  fd_delegation_pair_t_mapnode_t *        delegations_pool          = task_args->stake_delegations_pool;
  fd_epoch_info_t *                       temp_info                 = task_args->temp_info;
  ulong                                   epoch                     = task_args->epoch;

  ulong effective    = 0UL;
  ulong activating   = 0UL;
  ulong deactivating = 0UL;

  for( fd_delegation_pair_t_mapnode_t * n =  delegations_roots[worker_idx];
                                        n != end_node;
                                        n =  fd_delegation_pair_t_map_successor( delegations_pool, n ) ) {

    FD_TXN_ACCOUNT_DECL( acc );
    int rc = fd_txn_account_init_from_funk_readonly( acc,
                                                      &n->elem.account,
                                                      slot_ctx->funk,
                                                      slot_ctx->funk_txn );
    if( FD_UNLIKELY( rc!=FD_ACC_MGR_SUCCESS || acc->vt->get_lamports( acc )==0UL ) ) {
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

    ulong delegation_idx = FD_ATOMIC_FETCH_AND_ADD( &temp_info->stake_infos_len, 1UL );
    temp_info->stake_infos[delegation_idx].stake   = stake_state.inner.stake.stake;
    temp_info->stake_infos[delegation_idx].account = n->elem.account;

    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating( delegation, epoch, history, new_rate_activation_epoch );
    effective    += new_entry.effective;
    activating   += new_entry.activating;
    deactivating += new_entry.deactivating;
  }

  FD_ATOMIC_FETCH_AND_ADD( &accumulator->effective,    effective );
  FD_ATOMIC_FETCH_AND_ADD( &accumulator->activating,   activating );
  FD_ATOMIC_FETCH_AND_ADD( &accumulator->deactivating, deactivating );

}

static void FD_FN_UNUSED
accumulate_stake_cache_delegations_tpool_task( void  *tpool,
                                               ulong t0 FD_PARAM_UNUSED,      ulong t1 FD_PARAM_UNUSED,
                                               void  *args,
                                               void  *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                                               ulong l0 FD_PARAM_UNUSED,      ulong l1 FD_PARAM_UNUSED,
                                               ulong m0 FD_PARAM_UNUSED,      ulong m1 FD_PARAM_UNUSED,
                                               ulong n0 FD_PARAM_UNUSED,      ulong n1 FD_PARAM_UNUSED ) {
  fd_delegation_pair_t_mapnode_t * *      delegations_roots = (fd_delegation_pair_t_mapnode_t * *)tpool;
  fd_accumulate_delegations_task_args_t * task_args         = (fd_accumulate_delegations_task_args_t *)args;
  ulong                                   worker_idx        = fd_tile_idx();

  accumulate_stake_cache_delegations( delegations_roots,
                                      task_args,
                                      worker_idx,
                                      delegations_roots[ worker_idx+1UL ] );

}

/* Accumulates information about epoch stakes into `temp_info`, which is a temporary cache
   used to save intermediate state about stake and vote accounts to avoid them from having to
   be recomputed on every access, especially at the epoch boundary. Also collects stats in `accumulator` */
void
fd_accumulate_stake_infos( fd_exec_slot_ctx_t const * slot_ctx,
                           fd_stakes_global_t const * stakes,
                           fd_stake_history_t const * history,
                           ulong *                    new_rate_activation_epoch,
                           fd_stake_history_entry_t * accumulator,
                           fd_epoch_info_t *          temp_info,
                           fd_spad_t * *              exec_spads,
                           ulong                      exec_spads_cnt,
                           fd_spad_t *                runtime_spad ) {

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  fd_delegation_pair_t_mapnode_t * stake_delegations_pool = fd_stakes_stake_delegations_pool_join( stakes );
  fd_delegation_pair_t_mapnode_t * stake_delegations_root = fd_stakes_stake_delegations_root_join( stakes );

  ulong stake_delegations_pool_sz = fd_delegation_pair_t_map_size( stake_delegations_pool, stake_delegations_root );
  if( FD_UNLIKELY( stake_delegations_pool_sz==0UL ) ) {
    return;
  }

  /* Batch up the stake info accumulations via tpool. Currently this is only marginally more efficient because we
     do not have access to iterators at a specific index in constant or logarithmic time. */
  ulong worker_cnt                                         = fd_ulong_min( stake_delegations_pool_sz,exec_spads_cnt );

  fd_delegation_pair_t_mapnode_t ** batch_delegation_roots = fd_spad_alloc( runtime_spad, alignof(fd_delegation_pair_t_mapnode_t *),
                                                                                      ( worker_cnt + 1 )*sizeof(fd_delegation_pair_t_mapnode_t *) );

  ulong * idx_starts = fd_spad_alloc( runtime_spad, alignof(ulong), worker_cnt * sizeof(ulong) );

  // Determine the logical index partitioning of the delegations pool so we know where to start iterating from
  for( ulong i=0UL; i<worker_cnt; i++ ) {
    ulong _idx_end;
    FD_TPOOL_PARTITION( 0UL, stake_delegations_pool_sz, 1UL, i, worker_cnt, idx_starts[i], _idx_end );
    (void)_idx_end;
  }

  ulong batch_idx = 0UL;
  ulong iter_idx  = 0UL;
  for( fd_delegation_pair_t_mapnode_t * n = fd_delegation_pair_t_map_minimum( stake_delegations_pool, stake_delegations_root );
      n;
      n = fd_delegation_pair_t_map_successor( stake_delegations_pool, n ) ) {
    if( iter_idx++==idx_starts[batch_idx] ) {
      batch_delegation_roots[batch_idx++] = n;
    }
  }
  batch_delegation_roots[worker_cnt] = NULL;

  fd_accumulate_delegations_task_args_t task_args = {
    .slot_ctx                  = slot_ctx,
    .stake_history             = history,
    .new_rate_activation_epoch = new_rate_activation_epoch,
    .accumulator               = accumulator,
    .temp_info                 = temp_info,
    .spads                     = exec_spads,
    .stake_delegations_pool    = stake_delegations_pool,
    .epoch                     = stakes->epoch,
  };


  accumulate_stake_cache_delegations( batch_delegation_roots,
                                      &task_args,
                                      0UL,
                                      NULL );

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
    if( FD_UNLIKELY( rc!=FD_ACC_MGR_SUCCESS || acc->vt->get_lamports( acc )==0UL ) ) {
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
    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating( delegation, stakes->epoch, history, new_rate_activation_epoch );
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
                          fd_spad_t * *         exec_spads,
                          ulong                 exec_spad_cnt,
                          fd_spad_t *           runtime_spad ) {

  fd_stakes_global_t const *       stakes                 = fd_bank_stakes_locking_query( slot_ctx->bank );
  fd_delegation_pair_t_mapnode_t * stake_delegations_pool = fd_stakes_stake_delegations_pool_join( stakes );
  fd_delegation_pair_t_mapnode_t * stake_delegations_root = fd_stakes_stake_delegations_root_join( stakes );

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

  ulong stake_delegations_size = fd_delegation_pair_t_map_size(
    stake_delegations_pool, stake_delegations_root );

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
  fd_accumulate_stake_infos( slot_ctx,
                             stakes,
                             history,
                             new_rate_activation_epoch,
                             &accumulator,
                             temp_info,
                             exec_spads,
                             exec_spad_cnt,
                             runtime_spad );

  /* https://github.com/anza-xyz/agave/blob/v2.1.6/runtime/src/stakes.rs#L359 */
  fd_epoch_stake_history_entry_pair_t new_elem = {
    .epoch        = stakes->epoch,
    .entry        = {
      .effective    = accumulator.effective,
      .activating   = accumulator.activating,
      .deactivating = accumulator.deactivating
    }
  };

  fd_sysvar_stake_history_update( slot_ctx, &new_elem, runtime_spad );

  fd_bank_stakes_end_locking_query( slot_ctx->bank );

}

int
write_stake_state( fd_txn_account_t *    stake_acc_rec,
                   fd_stake_state_v2_t * stake_state ) {

  ulong encoded_stake_state_size = fd_stake_state_v2_size(stake_state);

  fd_bincode_encode_ctx_t ctx = {
    .data    = stake_acc_rec->vt->get_data_mut( stake_acc_rec ),
    .dataend = stake_acc_rec->vt->get_data_mut( stake_acc_rec ) + encoded_stake_state_size,
  };
  if( FD_UNLIKELY( fd_stake_state_v2_encode( stake_state, &ctx ) != FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "fd_stake_state_encode failed" ));
  }

  return 0;
}
