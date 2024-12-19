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
                          fd_stake_weight_t *        weights ) {

  /* Enter scratch frame for duration for function */

  if( FD_UNLIKELY( !fd_scratch_push_is_safe() ) ) {
    FD_LOG_WARNING(( "fd_scratch_push() failed" ));
    return ULONG_MAX;
  }

  FD_SCRATCH_SCOPE_BEGIN {

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
  } FD_SCRATCH_SCOPE_END;
}

/*
Refresh vote accounts.

This updates the epoch bank stakes vote_accounts cache - that is, the total amount
of delegated stake each vote account has, using the current delegation values from inside each
stake account.

https://github.com/solana-labs/solana/blob/c091fd3da8014c0ef83b626318018f238f506435/runtime/src/stakes.rs#L562 */
void
refresh_vote_accounts( fd_exec_slot_ctx_t *       slot_ctx,
                       fd_stake_history_t const * history,
                       ulong *                    new_rate_activation_epoch,
                       fd_epoch_info_t           *temp_info
 ) {
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_stakes_t * stakes = &epoch_bank->stakes;

  FD_SCRATCH_SCOPE_BEGIN {

    // Create a map of <pubkey, stake> to store the total stake of each vote account.
    static const ulong maplen = 10000;
    void * mem = fd_scratch_alloc( fd_stake_weight_t_map_align(), fd_stake_weight_t_map_footprint(maplen));
    fd_stake_weight_t_mapnode_t * pool = fd_stake_weight_t_map_join(fd_stake_weight_t_map_new(mem, maplen));
    fd_stake_weight_t_mapnode_t * root = NULL;

    // Iterate over each stake delegation and accumulate the stake amount associated with the given vote account.
    for ( ulong idx = 0; idx < temp_info->infos_len; idx++ ) {
        // Fetch the delegation associated with this stake account
        fd_delegation_t * delegation = &temp_info->infos[idx].stake.delegation;
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

    // Copy the delegated stake values calculated above to the epoch bank stakes vote_accounts
    for ( fd_vote_accounts_pair_t_mapnode_t * n =
        fd_vote_accounts_pair_t_map_minimum(
          stakes->vote_accounts.vote_accounts_pool, stakes->vote_accounts.vote_accounts_root);
          n;
          n = fd_vote_accounts_pair_t_map_successor(stakes->vote_accounts.vote_accounts_pool, n) ) {
      fd_stake_weight_t_mapnode_t temp;
      memcpy(&temp.elem.key, &n->elem.key, sizeof(fd_pubkey_t));
      fd_stake_weight_t_mapnode_t * entry = fd_stake_weight_t_map_find(pool, root, &temp);
      n->elem.stake = (entry == NULL) ? 0 : entry->elem.stake;
    }

    // Copy the delegated stake values calculated above to the slot bank stakes vote_accounts
    for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum( slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, slot_ctx->slot_bank.vote_account_keys.vote_accounts_root );
          n;
          n = fd_vote_accounts_pair_t_map_successor( slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, n )) {
      fd_stake_weight_t_mapnode_t temp;
      memcpy(&temp.elem.key, &n->elem.key, sizeof(fd_pubkey_t));
      fd_stake_weight_t_mapnode_t * entry = fd_stake_weight_t_map_find(pool, root, &temp);
      n->elem.stake = (entry == NULL) ? 0 : entry->elem.stake;
    }

  } FD_SCRATCH_SCOPE_END;
}

/* https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L169 */
void
fd_stakes_activate_epoch( fd_exec_slot_ctx_t *  slot_ctx,
                          ulong *               new_rate_activation_epoch,
                          fd_epoch_info_t      *temp_info
 ) {
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_stakes_t * stakes = &epoch_bank->stakes;

  /* Current stake delegations: list of all current delegations in stake_delegations
     https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L180 */
  /* Add a new entry to the Stake History sysvar for the previous epoch
     https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L181-L192 */

  fd_stake_history_t const * history = fd_sysvar_cache_stake_history( slot_ctx->sysvar_cache );
  if( FD_UNLIKELY( !history ) ) FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));

  ulong stake_delegations_size = fd_delegation_pair_t_map_size(
    stakes->stake_delegations_pool, stakes->stake_delegations_root );
  stake_delegations_size += fd_stake_accounts_pair_t_map_size(
    slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root );
  temp_info->infos_len = stake_delegations_size;
  temp_info->infos = (fd_epoch_info_pair_t *)fd_scratch_alloc( FD_EPOCH_INFO_PAIR_ALIGN, FD_EPOCH_INFO_PAIR_FOOTPRINT*stake_delegations_size );
  fd_memset( temp_info->infos, 0, FD_EPOCH_INFO_PAIR_FOOTPRINT*stake_delegations_size );
  ulong delegation_idx = 0;

  fd_stake_history_entry_t accumulator = {
    .effective = 0,
    .activating = 0,
    .deactivating = 0
  };

  fd_stake_weight_t_mapnode_t * pool = fd_stake_weight_t_map_alloc(slot_ctx->valloc, 10000);
  fd_stake_weight_t_mapnode_t * root = NULL;

  for ( fd_delegation_pair_t_mapnode_t * n = fd_delegation_pair_t_map_minimum(stakes->stake_delegations_pool, stakes->stake_delegations_root); n; n = fd_delegation_pair_t_map_successor(stakes->stake_delegations_pool, n) ) {
    FD_BORROWED_ACCOUNT_DECL(acc);
    int rc = fd_acc_mgr_view(slot_ctx->acc_mgr, slot_ctx->funk_txn, &n->elem.account, acc);
    if ( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS || acc->const_meta->info.lamports == 0 ) ) {
      continue;
    }

    fd_stake_state_v2_t stake_state;
    rc = fd_stake_get_state( acc, &slot_ctx->valloc, &stake_state );
    if ( FD_UNLIKELY( rc != 0) ) {
      continue;
    }

    if ( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
      continue;
    }

    if( FD_UNLIKELY( stake_state.inner.stake.stake.delegation.stake == 0 ) ) {
      continue;
    }

    fd_delegation_t * delegation = &stake_state.inner.stake.stake.delegation;
    fd_memcpy(&temp_info->infos[delegation_idx  ].stake, &stake_state.inner.stake.stake, sizeof(fd_stake_t));
    fd_memcpy(&temp_info->infos[delegation_idx++].account, &n->elem.account, sizeof(fd_pubkey_t));
    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating( delegation, stakes->epoch, history, new_rate_activation_epoch );
    accumulator.effective += new_entry.effective;
    accumulator.activating += new_entry.activating;
    accumulator.deactivating += new_entry.deactivating;

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

  for ( fd_stake_accounts_pair_t_mapnode_t * n = fd_stake_accounts_pair_t_map_minimum( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root);
        n;
        n = fd_stake_accounts_pair_t_map_successor( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, n ) ) {
    FD_BORROWED_ACCOUNT_DECL(acc);
    int rc = fd_acc_mgr_view(slot_ctx->acc_mgr, slot_ctx->funk_txn, &n->elem.key, acc);
    if ( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS || acc->const_meta->info.lamports == 0 ) ) {
      continue;
    }

    fd_stake_state_v2_t stake_state;
    rc = fd_stake_get_state( acc, &slot_ctx->valloc, &stake_state );
    if ( FD_UNLIKELY( rc != 0) ) {
      continue;
    }

    if ( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
      continue;
    }

    if( FD_UNLIKELY( stake_state.inner.stake.stake.delegation.stake == 0 ) ) {
      continue;
    }

    fd_delegation_t * delegation = &stake_state.inner.stake.stake.delegation;
    fd_memcpy(&temp_info->infos[delegation_idx  ].stake.delegation, &stake_state.inner.stake.stake, sizeof(fd_stake_t));
    fd_memcpy(&temp_info->infos[delegation_idx++].account, &n->elem.key, sizeof(fd_pubkey_t));
    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating( delegation, stakes->epoch, history, new_rate_activation_epoch );
    accumulator.effective += new_entry.effective;
    accumulator.activating += new_entry.activating;
    accumulator.deactivating += new_entry.deactivating;

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

  temp_info->infos_len = delegation_idx;

  fd_stake_history_entry_t new_elem = {
    .epoch = stakes->epoch,
    .effective = accumulator.effective,
    .activating = accumulator.activating,
    .deactivating = accumulator.deactivating
  };

  fd_sysvar_stake_history_update( slot_ctx, &new_elem);

  fd_valloc_free( slot_ctx->valloc,
    fd_stake_weight_t_map_delete( fd_stake_weight_t_map_leave ( pool ) ) );

  /* Refresh the sysvar cache stake history entry after updating the sysvar.
      We need to do this here because it is used in subsequent places in the epoch boundary. */
  fd_bincode_destroy_ctx_t sysvar_cache_destroy_ctx = { .valloc = slot_ctx->sysvar_cache->valloc };
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
