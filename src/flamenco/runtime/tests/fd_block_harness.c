#include "fd_solfuzz_private.h"
#include "../fd_cost_tracker.h"
#include "fd_txn_harness.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"
#include "../fd_txn_account.h"
#include "../program/fd_stake_program.h"
#include "../program/fd_vote_program.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_recent_hashes.h"
#include "../../rewards/fd_rewards.h"
#include "../../stakes/fd_stakes.h"
#include "../../types/fd_types.h"
#include "../../../disco/pack/fd_pack.h"
#include "generated/block.pb.h"

/* Templatized leader schedule sort helper functions */
typedef struct {
  fd_pubkey_t pk;
  ulong       sched_pos; /* track original position in sched[] */
} pk_with_pos_t;

#define SORT_NAME        sort_pkpos
#define SORT_KEY_T       pk_with_pos_t
#define SORT_BEFORE(a,b) (memcmp(&(a).pk, &(b).pk, sizeof(fd_pubkey_t))<0)
#include "../../../util/tmpl/fd_sort.c"  /* generates templatized sort_pkpos_*() APIs */

/* Fixed leader schedule hash seed (consistent with solfuzz-agave) */
#define LEADER_SCHEDULE_HASH_SEED 0xDEADFACEUL

/* Stripped down version of `fd_refresh_vote_accounts()` that simply refreshes the stake delegation amount
   for each of the vote accounts using the stake delegations cache. */
static void
fd_runtime_fuzz_block_refresh_vote_accounts( fd_vote_states_t *       vote_states,
                                             fd_vote_states_t *       vote_states_prev_prev,
                                             fd_stake_delegations_t * stake_delegations,
                                             ulong                    epoch ) {
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t * node = fd_stake_delegations_iter_ele( iter );

    fd_pubkey_t * voter_pubkey = &node->vote_account;
    ulong         stake        = node->stake;

    /* Find the voter in the vote accounts cache and update their
       delegation amount */
    fd_vote_state_ele_t * vote_state = fd_vote_states_query( vote_states, voter_pubkey );
    if( !vote_state ) continue;

    vote_state->stake     += stake;
    vote_state->stake_t_2 += stake;
  }

  /* We need to set the stake_t_2 for the vote accounts in the vote
     states cache.  An important edge case to handle is if the current
     epoch is less than 2, that means we should use the current stakes
     because the stake_t_2 field is not yet populated. */
  fd_vote_states_iter_t vs_iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( vs_iter_, vote_states_prev_prev );
       !fd_vote_states_iter_done( iter );
       fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t * vote_state = fd_vote_states_iter_ele( iter );
    fd_vote_state_ele_t * vote_state_prev_prev = fd_vote_states_query( vote_states_prev_prev, &vote_state->vote_account );
    ulong t_2_stake = !!vote_state_prev_prev ? vote_state_prev_prev->stake : 0UL;
    vote_state->stake_t_2 = epoch>=2UL ? t_2_stake : vote_state->stake;
    vote_state->stake_t_2 = vote_state->stake;
  }
}

/* Registers a single vote account into the current votes cache. The entry is derived
   from the current present account state. This function also registers a vote timestamp
   for the vote account */
static void
fd_runtime_fuzz_block_register_vote_account( fd_funk_t  *              funk,
                                             fd_funk_txn_xid_t const * xid,
                                             fd_vote_states_t *        vote_states,
                                             fd_pubkey_t *             pubkey,
                                             fd_spad_t *               spad ) {
  fd_txn_account_t acc[1];
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( acc, pubkey, funk, xid ) ) ) {
    return;
  }

  /* Account must be owned by the vote program */
  if( memcmp( fd_txn_account_get_owner( acc ), fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return;
  }

  /* Account must have > 0 lamports */
  if( fd_txn_account_get_lamports( acc )==0UL ) {
    return;
  }

  /* Account must be initialized correctly */
  if( FD_UNLIKELY( !fd_vote_state_versions_is_correct_and_initialized( acc ) ) ) {
    return;
  }

  /* Get the vote state from the account data */
  fd_vote_state_versioned_t * vsv = NULL;
  int err = fd_vote_get_state( acc, spad, &vsv );
  if( FD_UNLIKELY( err ) ) {
    return;
  }

  fd_vote_states_update_from_account(
      vote_states,
      acc->pubkey,
      fd_txn_account_get_data( acc ),
      fd_txn_account_get_data_len( acc ) );
}

/* Stores an entry in the stake delegations cache for the given vote account. Deserializes and uses the present
   account state to derive delegation information. */
static void
fd_runtime_fuzz_block_register_stake_delegation( fd_funk_t *               funk,
                                                 fd_funk_txn_xid_t const * xid,
                                                 fd_stake_delegations_t *  stake_delegations,
                                                 fd_pubkey_t *             pubkey ) {
 fd_txn_account_t acc[1];
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( acc, pubkey, funk, xid ) ) ) {
    return;
  }

  /* Account must be owned by the stake program */
  if( memcmp( fd_txn_account_get_owner( acc ), fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return;
  }

  /* Account must have > 0 lamports */
  if( fd_txn_account_get_lamports( acc )==0UL ) {
    return;
  }

  /* Stake state must exist and be initialized correctly */
  fd_stake_state_v2_t stake_state;
  if( FD_UNLIKELY( fd_stake_get_state( acc, &stake_state ) || !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
    return;
  }

  /* Skip 0-stake accounts */
  if( FD_UNLIKELY( stake_state.inner.stake.stake.delegation.stake==0UL ) ) {
    return;
  }

  /* Nothing to do if the account already exists in the cache */
  fd_stake_delegations_update(
      stake_delegations,
      pubkey,
      &stake_state.inner.stake.stake.delegation.voter_pubkey,
      stake_state.inner.stake.stake.delegation.stake,
      stake_state.inner.stake.stake.delegation.activation_epoch,
      stake_state.inner.stake.stake.delegation.deactivation_epoch,
      stake_state.inner.stake.stake.credits_observed,
      stake_state.inner.stake.stake.delegation.warmup_cooldown_rate );
}

/* Common helper method for populating a previous epoch's vote cache. */
static void
fd_runtime_fuzz_block_update_prev_epoch_votes_cache( fd_vote_states_t *            vote_states,
                                                     fd_exec_test_vote_account_t * vote_accounts,
                                                     pb_size_t                     vote_accounts_cnt,
                                                     fd_spad_t *                   spad ) {
  FD_SPAD_FRAME_BEGIN( spad ) {
    for( uint i=0U; i<vote_accounts_cnt; i++ ) {
      fd_exec_test_acct_state_t * vote_account  = &vote_accounts[i].vote_account;
      ulong                       stake         = vote_accounts[i].stake;
      uchar *                     vote_data     = vote_account->data->bytes;
      ulong                       vote_data_len = vote_account->data->size;
      fd_pubkey_t                 vote_address  = {0};
      fd_memcpy( &vote_address, vote_account->address, sizeof(fd_pubkey_t) );

      /* Try decoding the vote state from the account data. If it isn't
         decodable, don't try inserting it into the cache. */
      fd_vote_state_versioned_t * res = fd_bincode_decode_spad(
          vote_state_versioned, spad,
          vote_data,
          vote_data_len,
          NULL );
      if( res==NULL ) continue;

      fd_vote_states_update_from_account( vote_states, &vote_address, vote_data, vote_data_len );
      fd_vote_state_ele_t * vote_state = fd_vote_states_query( vote_states, &vote_address );
      vote_state->stake     += stake;
      vote_state->stake_t_2 += stake;
    }
  } FD_SPAD_FRAME_END;
}

static void
fd_runtime_fuzz_block_ctx_destroy( fd_solfuzz_runner_t * runner ) {
  fd_accdb_clear( runner->accdb_admin );
  fd_progcache_clear( runner->progcache_admin );
}

/* Sets up block execution context from an input test case to execute against the runtime.
   Returns block_info on success and NULL on failure. */
static fd_txn_p_t *
fd_runtime_fuzz_block_ctx_create( fd_solfuzz_runner_t *                runner,
                                  fd_exec_test_block_context_t const * test_ctx,
                                  ulong *                              out_txn_cnt ) {
  fd_funk_t *  funk  = runner->accdb->funk;
  fd_bank_t *  bank  = runner->bank;
  fd_banks_t * banks = runner->banks;

  fd_banks_clear_bank( banks, bank );

  /* Generate unique ID for funk txn */
  fd_funk_txn_xid_t xid[1] = {{ .ul={ LONG_MAX,LONG_MAX } }};

  /* Create temporary funk transaction and slot / epoch contexts */
  fd_funk_txn_xid_t parent_xid; fd_funk_txn_xid_set_root( &parent_xid );
  fd_accdb_attach_child( runner->accdb_admin, &parent_xid, xid );
  fd_progcache_txn_attach_child( runner->progcache_admin, &parent_xid, xid );

  /* Restore feature flags */
  fd_features_t features = {0};
  if( !fd_runtime_fuzz_restore_features( &features, &test_ctx->epoch_ctx.features ) ) {
    return NULL;
  }
  fd_bank_features_set( bank, features );

  /* Set up slot context */
  ulong slot        = test_ctx->slot_ctx.slot;
  ulong parent_slot = test_ctx->slot_ctx.prev_slot;

  fd_hash_t * bank_hash = fd_bank_bank_hash_modify( bank );
  fd_memcpy( bank_hash, test_ctx->slot_ctx.parent_bank_hash, sizeof(fd_hash_t) );

  /* All bank mgr stuff here. */

  fd_bank_slot_set( bank, slot );

  fd_bank_parent_slot_set( bank, parent_slot );

  fd_bank_block_height_set( bank, test_ctx->slot_ctx.block_height );

  fd_bank_capitalization_set( bank, test_ctx->slot_ctx.prev_epoch_capitalization );

  fd_bank_lamports_per_signature_set( bank, 5000UL );

  fd_bank_prev_lamports_per_signature_set( bank, test_ctx->slot_ctx.prev_lps );

  // self.max_tick_height = (self.slot + 1) * self.ticks_per_slot;
  fd_bank_hashes_per_tick_set( bank, test_ctx->epoch_ctx.hashes_per_tick );

  fd_bank_ticks_per_slot_set( bank, test_ctx->epoch_ctx.ticks_per_slot );

  fd_bank_ns_per_slot_set( bank, 400000000 ); // TODO: restore from input

  fd_bank_genesis_creation_time_set( bank, test_ctx->epoch_ctx.genesis_creation_time );

  fd_bank_slots_per_year_set( bank, test_ctx->epoch_ctx.slots_per_year );

  fd_bank_parent_signature_cnt_set( bank, test_ctx->slot_ctx.parent_signature_count );

  fd_fee_rate_governor_t * fee_rate_governor = fd_bank_fee_rate_governor_modify( bank );
  *fee_rate_governor = (fd_fee_rate_governor_t){
    .target_lamports_per_signature = test_ctx->slot_ctx.fee_rate_governor.target_lamports_per_signature,
    .target_signatures_per_slot    = test_ctx->slot_ctx.fee_rate_governor.target_signatures_per_slot,
    .min_lamports_per_signature    = test_ctx->slot_ctx.fee_rate_governor.min_lamports_per_signature,
    .max_lamports_per_signature    = test_ctx->slot_ctx.fee_rate_governor.max_lamports_per_signature,
    .burn_percent                  = (uchar)test_ctx->slot_ctx.fee_rate_governor.burn_percent
  };

  fd_inflation_t * inflation = fd_bank_inflation_modify( bank );
  *inflation = (fd_inflation_t){
    .initial         = test_ctx->epoch_ctx.inflation.initial,
    .terminal        = test_ctx->epoch_ctx.inflation.terminal,
    .taper           = test_ctx->epoch_ctx.inflation.taper,
    .foundation      = test_ctx->epoch_ctx.inflation.foundation,
    .foundation_term = test_ctx->epoch_ctx.inflation.foundation_term
  };

  fd_bank_block_height_set( bank, test_ctx->slot_ctx.block_height );

  /* Initialize the current running epoch stake and vote accounts */

  fd_vote_states_t * vote_states = fd_bank_vote_states_locking_modify( bank );
  vote_states = fd_vote_states_join( fd_vote_states_new( vote_states, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  fd_bank_vote_states_end_locking_modify( bank );

  fd_vote_states_t * vote_states_prev = fd_bank_vote_states_prev_locking_modify( bank );
  vote_states_prev = fd_vote_states_join( fd_vote_states_new( vote_states_prev, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  fd_bank_vote_states_prev_end_locking_modify( bank );

  fd_vote_states_t * vote_states_prev_prev = fd_bank_vote_states_prev_prev_locking_modify( bank );
  vote_states_prev_prev = fd_vote_states_join( fd_vote_states_new( vote_states_prev_prev, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  fd_bank_vote_states_prev_prev_end_locking_modify( bank );

  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( banks );
  stake_delegations = fd_stake_delegations_join( fd_stake_delegations_new( stake_delegations, FD_RUNTIME_MAX_STAKE_ACCOUNTS, 0 ) );

  /* Load in all accounts with > 0 lamports provided in the context. The input expects unique account pubkeys. */
  vote_states = fd_bank_vote_states_locking_modify( bank );
  for( ushort i=0; i<test_ctx->acct_states_count; i++ ) {
    fd_txn_account_t acc[1];
    fd_runtime_fuzz_load_account( acc, funk, xid, &test_ctx->acct_states[i], 1 );

    /* Update vote accounts cache for epoch T */
    fd_pubkey_t pubkey;
    memcpy( &pubkey, test_ctx->acct_states[i].address, sizeof(fd_pubkey_t) );
    fd_runtime_fuzz_block_register_vote_account(
        funk,
        xid,
        vote_states,
        &pubkey,
        runner->spad );

    /* Update the stake delegations cache for epoch T */
    fd_runtime_fuzz_block_register_stake_delegation( funk,
                                                     xid,
                                                     stake_delegations,
                                                     &pubkey );
  }

  /* Zero out vote stakes to avoid leakage across tests */
  fd_vote_states_reset_stakes( vote_states );

  /* Finish init epoch bank sysvars */
  fd_epoch_schedule_t epoch_schedule_[1];
  fd_epoch_schedule_t * epoch_schedule = fd_sysvar_epoch_schedule_read( funk, xid, epoch_schedule_ );
  FD_TEST( epoch_schedule );
  fd_bank_epoch_schedule_set( bank, *epoch_schedule );

  fd_rent_t const * rent = fd_sysvar_rent_read( funk, xid, runner->spad );
  FD_TEST( rent );
  fd_bank_rent_set( bank, *rent );

  /* Current epoch gets updated in process_new_epoch, so use the epoch
     from the parent slot */
  fd_bank_epoch_set( bank, fd_slot_to_epoch( epoch_schedule, parent_slot, NULL ) );

  /* Update vote cache for epoch T-1 */
  vote_states_prev = fd_bank_vote_states_prev_locking_modify( bank );
  fd_runtime_fuzz_block_update_prev_epoch_votes_cache( vote_states_prev,
                                                       test_ctx->epoch_ctx.vote_accounts_t_1,
                                                       test_ctx->epoch_ctx.vote_accounts_t_1_count,
                                                       runner->spad );
  fd_bank_vote_states_prev_end_locking_modify( bank );

  /* Update vote cache for epoch T-2 */
  vote_states_prev_prev = fd_bank_vote_states_prev_prev_locking_modify( bank );
  fd_runtime_fuzz_block_update_prev_epoch_votes_cache( vote_states_prev_prev,
                                                       test_ctx->epoch_ctx.vote_accounts_t_2,
                                                       test_ctx->epoch_ctx.vote_accounts_t_2_count,
                                                       runner->spad );

  /* Refresh vote accounts to calculate stake delegations */
  fd_runtime_fuzz_block_refresh_vote_accounts( vote_states, vote_states_prev_prev, stake_delegations, fd_bank_epoch_get( bank ) );
  fd_bank_vote_states_end_locking_modify( bank );

  fd_bank_vote_states_prev_prev_end_locking_modify( bank );

  /* Update leader schedule */
  fd_runtime_update_leaders( bank, runner->spad );

  /* Initialize the blockhash queue and recent blockhashes sysvar from the input blockhash queue */
  ulong blockhash_seed; FD_TEST( fd_rng_secure( &blockhash_seed, sizeof(ulong) ) );
  fd_blockhashes_init( fd_bank_block_hash_queue_modify( bank ), blockhash_seed );

  /* TODO: We might need to load this in from the input. We also need to
     size this out for worst case, but this also blows up the memory
     requirement. */
  /* Allocate all the memory for the rent fresh accounts list */

  // Set genesis hash to {0}
  fd_hash_t * genesis_hash = fd_bank_genesis_hash_modify( bank );
  fd_memset( genesis_hash->hash, 0, sizeof(fd_hash_t) );

  // Use the latest lamports per signature
  fd_recent_block_hashes_t const * rbh = fd_sysvar_recent_hashes_read( funk, xid, runner->spad );
  if( rbh && !deq_fd_block_block_hash_entry_t_empty( rbh->hashes ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_head_const( rbh->hashes );
    if( last && last->fee_calculator.lamports_per_signature!=0UL ) {
      fd_bank_lamports_per_signature_set( bank, last->fee_calculator.lamports_per_signature );
      fd_bank_prev_lamports_per_signature_set( bank, last->fee_calculator.lamports_per_signature );
    }
  }

  /* Make a new funk transaction since we're done loading in accounts for context */
  fd_funk_txn_xid_t fork_xid = { .ul = { slot, 0UL } };
  fd_accdb_attach_child        ( runner->accdb_admin,     xid, &fork_xid );
  fd_progcache_txn_attach_child( runner->progcache_admin, xid, &fork_xid );
  xid[0] = fork_xid;

  /* Set the initial lthash from the input since we're in a new Funk txn */
  fd_lthash_value_t * lthash = fd_bank_lthash_locking_modify( bank );
  fd_memcpy( lthash, test_ctx->slot_ctx.parent_lthash, sizeof(fd_lthash_value_t) );
  fd_bank_lthash_end_locking_modify( bank );

  // Populate blockhash queue and recent blockhashes sysvar
  for( ushort i=0; i<test_ctx->blockhash_queue_count; ++i ) {
    fd_hash_t hash;
    memcpy( &hash, test_ctx->blockhash_queue[i]->bytes, sizeof(fd_hash_t) );
    fd_bank_poh_set( bank, hash );
    fd_sysvar_recent_hashes_update( bank, funk, xid, NULL ); /* appends an entry */
  }

  // Set the current poh from the input (we skip POH verification in this fuzzing target)
  fd_hash_t * poh = fd_bank_poh_modify( bank );
  fd_memcpy( poh->hash, test_ctx->slot_ctx.poh, sizeof(fd_hash_t) );

  /* Restore sysvar cache */
  fd_sysvar_cache_restore_fuzz( bank, funk, xid );

  /* Prepare raw transaction pointers and block / microblock infos */
  ulong        txn_cnt  = test_ctx->txns_count;
  fd_txn_p_t * txn_ptrs = fd_spad_alloc( runner->spad, alignof(fd_txn_p_t), txn_cnt * sizeof(fd_txn_p_t) );
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn    = &txn_ptrs[i];
    ulong        msg_sz = fd_runtime_fuzz_serialize_txn( txn->payload, &test_ctx->txns[i] );

    // Reject any transactions over 1232 bytes
    if( FD_UNLIKELY( msg_sz==ULONG_MAX ) ) {
      return NULL;
    }
    txn->payload_sz = msg_sz;

    // Reject any transactions that cannot be parsed
    if( FD_UNLIKELY( !fd_txn_parse( txn->payload, msg_sz, TXN( txn ), NULL ) ) ) {
      return NULL;
    }
  }

  *out_txn_cnt = txn_cnt;
  return txn_ptrs;
}

/* Takes in a list of txn_p_t created from
   fd_runtime_fuzz_block_ctx_create and executes it against the runtime.
   Returns the execution result. */
static int
fd_runtime_fuzz_block_ctx_exec( fd_solfuzz_runner_t *     runner,
                                fd_funk_txn_xid_t const * xid,
                                fd_txn_p_t *              txn_ptrs,
                                ulong                     txn_cnt ) {
  int res = 0;

  // Prepare. Execute. Finalize.
  FD_SPAD_FRAME_BEGIN( runner->spad ) {
    fd_capture_ctx_t * capture_ctx = NULL;
    if( runner->solcap ) {
      void * capture_ctx_mem = fd_spad_alloc( runner->spad, fd_capture_ctx_align(), fd_capture_ctx_footprint() );
      capture_ctx            = fd_capture_ctx_new( capture_ctx_mem );
      if( FD_UNLIKELY( capture_ctx==NULL ) ) {
        FD_LOG_ERR(("capture_ctx_mem is NULL, cannot write solcap"));
      }
      capture_ctx->capture           = runner->solcap;
      capture_ctx->solcap_start_slot = fd_bank_slot_get( runner->bank );
      fd_solcap_writer_set_slot( capture_ctx->capture, fd_bank_slot_get( runner->bank ) );
    }

    /* TODO:FIXME: */
    fd_vote_state_credits_t vote_state_credits;
    fd_rewards_recalculate_partitioned_rewards( runner->banks, runner->bank, runner->accdb->funk, xid, &vote_state_credits, capture_ctx );

    /* Process new epoch may push a new spad frame onto the runtime spad. We should make sure this frame gets
       cleared (if it was allocated) before executing the block. */
    int is_epoch_boundary = 0;
    fd_runtime_block_pre_execute_process_new_epoch( runner->banks, runner->bank, runner->accdb->funk, xid, capture_ctx, runner->spad, &is_epoch_boundary );

    res = fd_runtime_block_execute_prepare( runner->bank, runner->accdb->funk, xid, capture_ctx, runner->spad );
    if( FD_UNLIKELY( res ) ) {
      return res;
    }

    /* Sequential transaction execution */
    for( ulong i=0UL; i<txn_cnt; i++ ) {
      fd_txn_p_t * txn = &txn_ptrs[i];

      /* Execute the transaction against the runtime */
      res = FD_RUNTIME_EXECUTE_SUCCESS;
      fd_exec_txn_ctx_t * txn_ctx = fd_runtime_fuzz_txn_ctx_exec( runner, xid, txn, &res );
      txn_ctx->exec_err           = res;

      if( FD_UNLIKELY( !(txn_ctx->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) ) ) {
        break;
      }

      /* Finalize the transaction */
      fd_runtime_finalize_txn(
          runner->accdb->funk,
          runner->progcache,
          NULL,
          xid,
          txn_ctx,
          runner->bank,
          capture_ctx,
          0 );

      if( FD_UNLIKELY( !(txn_ctx->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) ) ) {
        break;
      }

      res = FD_RUNTIME_EXECUTE_SUCCESS;
    }

    /* Finalize the block */
    fd_runtime_block_execute_finalize( runner->bank, runner->accdb->funk, xid, capture_ctx, 1 );
  } FD_SPAD_FRAME_END;

  return res;
}

/* Canonical (Agave-aligned) schedule hash
   Unique pubkeys referenced by sched, sorted deterministically
   Per-rotation indices mapped into sorted-uniq array */
ulong
fd_hash_epoch_leaders( fd_solfuzz_runner_t *      runner,
                       fd_epoch_leaders_t const * leaders,
                       ulong                      seed,
                       uchar                      out[16] ) {
  /* Single contiguous spad allocation for uniq[] and sched_mapped[] */
  void *buf = fd_spad_alloc(
    runner->spad,
    alignof(pk_with_pos_t),
    leaders->sched_cnt*sizeof(pk_with_pos_t) +
    leaders->sched_cnt*sizeof(uint) );

  pk_with_pos_t * tmp          = (pk_with_pos_t *)buf;
  uint          * sched_mapped = (uint *)( tmp + leaders->sched_cnt );

  /* Gather all pubkeys and original positions from sched[] (skip invalid) */
  ulong gather_cnt = 0UL;
  for( ulong i=0UL; i<leaders->sched_cnt; i++ ) {
    uint idx = leaders->sched[i];
    if( idx>=leaders->pub_cnt ) { /* invalid slot leader */
      sched_mapped[i] = 0U;       /* prefill invalid mapping */
      continue;
    }
    fd_memcpy( &tmp[gather_cnt].pk, &leaders->pub[idx], sizeof(fd_pubkey_t) );
    tmp[gather_cnt].sched_pos = i;
    gather_cnt++;
  }

  if( gather_cnt==0UL ) {
    /* No leaders => hash:=0, count:=0 */
    fd_memset( out, 0, sizeof(ulong)*2 );
    return 0UL;
  }

  /* Sort tmp[] by pubkey, note: comparator relies on first struct member */
  sort_pkpos_inplace( tmp, (ulong)gather_cnt );

  /* Dedupe and assign indices into sched_mapped[] during single pass */
  ulong uniq_cnt = 0UL;
  for( ulong i=0UL; i<gather_cnt; i++ ) {
    if( i==0UL || memcmp( &tmp[i].pk, &tmp[i-1].pk, sizeof(fd_pubkey_t) )!=0 )
      uniq_cnt++;
    /* uniq_cnt-1 is index in uniq set */
    sched_mapped[tmp[i].sched_pos] = (uint)(uniq_cnt-1UL);
  }

  /* Reconstruct contiguous uniq[] for hashing */
  fd_pubkey_t *uniq = fd_spad_alloc( runner->spad,
                                     alignof(fd_pubkey_t),
                                     uniq_cnt*sizeof(fd_pubkey_t) );
  {
    ulong write_pos = 0UL;
    for( ulong i=0UL; i<gather_cnt; i++ ) {
      if( i==0UL || memcmp( &tmp[i].pk, &tmp[i-1].pk, sizeof(fd_pubkey_t) )!=0 )
      fd_memcpy( &uniq[write_pos++], &tmp[i].pk, sizeof(fd_pubkey_t) );
    }
  }

  /* Hash sorted unique pubkeys */
  ulong h1 = fd_hash( seed, uniq, uniq_cnt * sizeof(fd_pubkey_t) );
  fd_memcpy( out, &h1, sizeof(ulong) );

  /* Hash mapped indices */
  ulong h2 = fd_hash( seed, sched_mapped, leaders->sched_cnt * sizeof(uint) );
  fd_memcpy( out + sizeof(ulong), &h2, sizeof(ulong) );

  return uniq_cnt;
}

static void
fd_runtime_fuzz_build_leader_schedule_effects( fd_solfuzz_runner_t *                runner,
                                               fd_funk_txn_xid_t const *            xid,
                                               fd_exec_test_block_effects_t *       effects,
                                               fd_exec_test_block_context_t const * test_ctx ) {
  /* Read epoch schedule sysvar */
  fd_epoch_schedule_t es_;
  fd_epoch_schedule_t *sched = fd_sysvar_epoch_schedule_read( runner->accdb->funk, xid, &es_ );
  FD_TEST( sched!=NULL );

  ulong parent_slot = fd_bank_parent_slot_get( runner->bank );

  /* Epoch we will use for effects (Agave: parent slot's leader schedule epoch) */
  ulong agave_epoch    = fd_slot_to_leader_schedule_epoch( sched, parent_slot );
  ulong agave_slot0    = fd_epoch_slot0( sched, agave_epoch );
  ulong slots_in_epoch = fd_epoch_slot_cnt( sched, agave_epoch );

  /* Temporary vote_states for building stake weights */
  fd_vote_states_t *tmp_vs = fd_vote_states_join(
      fd_vote_states_new(
          fd_spad_alloc( runner->spad,
                         fd_vote_states_align(),
                         fd_vote_states_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS ) ),
          FD_RUNTIME_MAX_VOTE_ACCOUNTS,
          999UL /* stake_delegations_max */ ) );

  /* Select stake source based on the Agave-consistent epoch */
  /* Agave code pointers: see stake source selection in execute_block() at
     solfuzz-agave/src/block.rs (build_*_stake_delegations and epoch_stakes inserts) */
  if ( agave_epoch==fd_slot_to_leader_schedule_epoch( sched, parent_slot ) ) {
    /* Same as parent epoch, so use vote_accounts_t_1 */
    fd_runtime_fuzz_block_update_prev_epoch_votes_cache(
        tmp_vs,
        test_ctx->epoch_ctx.vote_accounts_t_1,
        test_ctx->epoch_ctx.vote_accounts_t_1_count,
        runner->spad );
  } else if ( agave_epoch==fd_slot_to_leader_schedule_epoch( sched, parent_slot )-1UL ) {
    /* One before parent epoch, so use vote_accounts_t_2 */
    fd_runtime_fuzz_block_update_prev_epoch_votes_cache(
        tmp_vs,
        test_ctx->epoch_ctx.vote_accounts_t_2,
        test_ctx->epoch_ctx.vote_accounts_t_2_count,
        runner->spad );
  } else if (agave_epoch==fd_slot_to_leader_schedule_epoch(sched, parent_slot)+1UL) {
    /* One ahead of parent epoch, so use current acct_states */
    for ( ushort i=0; i<test_ctx->acct_states_count; i++ ) {
      fd_txn_account_t acc[1];
      fd_runtime_fuzz_load_account( acc, runner->accdb->funk, xid, &test_ctx->acct_states[i], 1 );
      fd_pubkey_t pubkey;
      memcpy( &pubkey, test_ctx->acct_states[i].address, sizeof(fd_pubkey_t) );
      fd_runtime_fuzz_block_register_vote_account( runner->accdb->funk, xid, tmp_vs, &pubkey, runner->spad );
    }
    fd_stake_delegations_t * stake_delegations =
        fd_stake_delegations_join(
            fd_stake_delegations_new(
                fd_spad_alloc( runner->spad,
                               fd_stake_delegations_align(),
                               fd_stake_delegations_footprint( FD_RUNTIME_MAX_STAKE_ACCOUNTS ) ),
                FD_RUNTIME_MAX_STAKE_ACCOUNTS, 0 ) );
    for ( ushort i=0; i<test_ctx->acct_states_count; i++ ) {
      fd_pubkey_t pubkey;
      memcpy( &pubkey, test_ctx->acct_states[i].address, sizeof(fd_pubkey_t) );
      fd_runtime_fuzz_block_register_stake_delegation( runner->accdb->funk, xid, stake_delegations, &pubkey );
    }
    fd_runtime_fuzz_block_refresh_vote_accounts( tmp_vs, tmp_vs, stake_delegations, fd_bank_epoch_get( runner->bank ) );
  }

  /* Build weights from the selected stake source */
  ulong vote_acc_cnt = fd_vote_states_cnt( tmp_vs );
  fd_vote_stake_weight_t *weights =
      fd_spad_alloc( runner->spad, alignof(fd_vote_stake_weight_t),
                     vote_acc_cnt * sizeof(fd_vote_stake_weight_t) );
  ulong weight_cnt = fd_stake_weights_by_node( tmp_vs, weights );

  /* Build ephemeral leader schedule for the Agave epoch */
  ulong fp = fd_epoch_leaders_footprint( weight_cnt, slots_in_epoch );
  FD_TEST( fp!=0UL );
  void *mem = fd_spad_alloc( runner->spad, fd_epoch_leaders_align(), fp );
  ulong vote_keyed = (ulong)fd_runtime_should_use_vote_keyed_leader_schedule( runner->bank );
  fd_epoch_leaders_t *effects_leaders = fd_epoch_leaders_join(
      fd_epoch_leaders_new( mem,
                            agave_epoch,
                            agave_slot0,
                            slots_in_epoch,
                            weight_cnt,
                            weights,
                            0UL,
                            vote_keyed ) );
  FD_TEST( effects_leaders!=NULL );

  /* Fill out effects struct from the Agave epoch info */
  effects->has_leader_schedule               = 1;
  effects->leader_schedule.leaders_epoch     = agave_epoch;
  effects->leader_schedule.leaders_slot0     = agave_slot0;
  effects->leader_schedule.leaders_slot_cnt  = slots_in_epoch;
  effects->leader_schedule.leaders_sched_cnt = slots_in_epoch;
  effects->leader_schedule.leader_pub_cnt    =
      fd_hash_epoch_leaders( runner, effects_leaders,
                             LEADER_SCHEDULE_HASH_SEED,
                             effects->leader_schedule.leader_schedule_hash );
}

ulong
fd_solfuzz_block_run( fd_solfuzz_runner_t * runner,
                      void const *          input_,
                      void **               output_,
                      void *                output_buf,
                      ulong                 output_bufsz ) {
  fd_exec_test_block_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_block_effects_t **      output = fd_type_pun( output_ );

  FD_SPAD_FRAME_BEGIN( runner->spad ) {
    /* Set up the block execution context */
    ulong txn_cnt;
    fd_txn_p_t * txn_ptrs = fd_runtime_fuzz_block_ctx_create( runner, input, &txn_cnt );
    if( txn_ptrs==NULL ) {
      fd_runtime_fuzz_block_ctx_destroy( runner );
      return 0;
    }

    fd_funk_txn_xid_t xid  = { .ul = { fd_bank_slot_get( runner->bank ), 0UL } };

    /* Execute the constructed block against the runtime. */
    int res = fd_runtime_fuzz_block_ctx_exec( runner, &xid, txn_ptrs, txn_cnt );

    /* Start saving block exec results */
    FD_SCRATCH_ALLOC_INIT( l, output_buf );
    ulong output_end = (ulong)output_buf + output_bufsz;

    fd_exec_test_block_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_block_effects_t),
                                sizeof(fd_exec_test_block_effects_t) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      abort();
    }
    fd_memset( effects, 0, sizeof(fd_exec_test_block_effects_t) );

    /* Capture error status */
    effects->has_error = !!( res );

    /* Capture capitalization */
    effects->slot_capitalization = fd_bank_capitalization_get( runner->bank );

    /* Capture hashes */
    fd_hash_t bank_hash = fd_bank_bank_hash_get( runner->bank );
    fd_memcpy( effects->bank_hash, bank_hash.hash, sizeof(fd_hash_t) );

    /* Capture cost tracker */
    fd_cost_tracker_t const * cost_tracker = fd_bank_cost_tracker_locking_query( runner->bank );
    effects->has_cost_tracker = 1;
    effects->cost_tracker = (fd_exec_test_cost_tracker_t) {
      .block_cost = cost_tracker ? cost_tracker->block_cost : 0UL,
      .vote_cost  = cost_tracker ? cost_tracker->vote_cost  : 0UL,
    };
    fd_bank_cost_tracker_end_locking_query( runner->bank );

    /* Effects: build T-epoch (bank epoch), T-stakes ephemeral leaders and report */
    fd_runtime_fuzz_build_leader_schedule_effects( runner, &xid, effects, input );

    ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
    fd_runtime_fuzz_block_ctx_destroy( runner );

    *output = effects;
    return actual_end - (ulong)output_buf;
  } FD_SPAD_FRAME_END;
}
