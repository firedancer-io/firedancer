#include "fd_solfuzz_private.h"
#include "../fd_cost_tracker.h"
#include "fd_txn_harness.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"
#include "../fd_txn_account.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../info/fd_runtime_block_info.h"
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

/* Stripped down version of `fd_refresh_vote_accounts()` that simply refreshes the stake delegation amount
   for each of the vote accounts using the stake delegations cache. */
static void
fd_runtime_fuzz_block_refresh_vote_accounts( fd_vote_states_t *       vote_states,
                                             fd_stake_delegations_t * stake_delegations ) {
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

    ulong vote_stake = vote_state->stake;
    fd_vote_states_update_stake( vote_states, voter_pubkey, vote_stake + stake );

  }
}

/* Registers a single vote account into the current votes cache. The entry is derived
   from the current present account state. This function also registers a vote timestamp
   for the vote account */
static void
fd_runtime_fuzz_block_register_vote_account( fd_exec_slot_ctx_t * slot_ctx,
                                             fd_vote_states_t *   vote_states,
                                             fd_pubkey_t *        pubkey,
                                             fd_spad_t *          spad ) {
  FD_TXN_ACCOUNT_DECL( acc );
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( acc, pubkey, slot_ctx->funk, slot_ctx->xid ) ) ) {
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
fd_runtime_fuzz_block_register_stake_delegation( fd_exec_slot_ctx_t *     slot_ctx,
                                                 fd_stake_delegations_t * stake_delegations,
                                                 fd_pubkey_t *            pubkey ) {
 FD_TXN_ACCOUNT_DECL( acc );
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( acc, pubkey, slot_ctx->funk, slot_ctx->xid ) ) ) {
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
      fd_vote_states_update_stake( vote_states, &vote_address, stake );
    }
  } FD_SPAD_FRAME_END;
}

static void
fd_runtime_fuzz_block_ctx_destroy( fd_solfuzz_runner_t * runner ) {
  fd_funk_txn_cancel_all( runner->funk );
}

/* Sets up block execution context from an input test case to execute against the runtime.
   Returns block_info on success and NULL on failure. */
static fd_runtime_block_info_t *
fd_runtime_fuzz_block_ctx_create( fd_solfuzz_runner_t *                runner,
                                  fd_exec_slot_ctx_t *                 slot_ctx,
                                  fd_exec_test_block_context_t const * test_ctx ) {
  fd_funk_t * funk = runner->funk;

  slot_ctx->banks = runner->banks;
  slot_ctx->bank  = runner->bank;
  fd_banks_clear_bank( slot_ctx->banks, slot_ctx->bank );

  /* Generate unique ID for funk txn */
  fd_funk_txn_xid_t xid[1] = {0};
  xid[0] = fd_funk_generate_xid();

  /* Create temporary funk transaction and slot / epoch contexts */
  fd_funk_txn_xid_t parent_xid; fd_funk_txn_xid_set_root( &parent_xid );
  fd_funk_txn_prepare( funk, &parent_xid, xid );

  /* Restore feature flags */
  fd_features_t features = {0};
  if( !fd_runtime_fuzz_restore_features( &features, &test_ctx->epoch_ctx.features ) ) {
    return NULL;
  }
  fd_bank_features_set( slot_ctx->bank, features );

  /* Set up slot context */
  ulong slot = test_ctx->slot_ctx.slot;

  slot_ctx->xid[0] = xid[0];
  slot_ctx->funk   = funk;
  slot_ctx->silent = 1;

  fd_hash_t * bank_hash = fd_bank_bank_hash_modify( slot_ctx->bank );
  fd_memcpy( bank_hash, test_ctx->slot_ctx.parent_bank_hash, sizeof(fd_hash_t) );

  /* All bank mgr stuff here. */

  fd_bank_slot_set( slot_ctx->bank, slot );

  fd_bank_parent_slot_set( slot_ctx->bank, test_ctx->slot_ctx.prev_slot );

  fd_bank_block_height_set( slot_ctx->bank, test_ctx->slot_ctx.block_height );

  fd_bank_capitalization_set( slot_ctx->bank, test_ctx->slot_ctx.prev_epoch_capitalization );

  fd_bank_lamports_per_signature_set( slot_ctx->bank, 5000UL );

  fd_bank_prev_lamports_per_signature_set( slot_ctx->bank, test_ctx->slot_ctx.prev_lps );

  // self.max_tick_height = (self.slot + 1) * self.ticks_per_slot;
  fd_bank_hashes_per_tick_set( slot_ctx->bank, test_ctx->epoch_ctx.hashes_per_tick );

  fd_bank_ticks_per_slot_set( slot_ctx->bank, test_ctx->epoch_ctx.ticks_per_slot );

  fd_bank_ns_per_slot_set( slot_ctx->bank, 400000000 ); // TODO: restore from input

  fd_bank_genesis_creation_time_set( slot_ctx->bank, test_ctx->epoch_ctx.genesis_creation_time );

  fd_bank_slots_per_year_set( slot_ctx->bank, test_ctx->epoch_ctx.slots_per_year );

  fd_bank_parent_signature_cnt_set( slot_ctx->bank, test_ctx->slot_ctx.parent_signature_count );

  fd_fee_rate_governor_t * fee_rate_governor = fd_bank_fee_rate_governor_modify( slot_ctx->bank );
  *fee_rate_governor = (fd_fee_rate_governor_t){
    .target_lamports_per_signature = test_ctx->slot_ctx.fee_rate_governor.target_lamports_per_signature,
    .target_signatures_per_slot    = test_ctx->slot_ctx.fee_rate_governor.target_signatures_per_slot,
    .min_lamports_per_signature    = test_ctx->slot_ctx.fee_rate_governor.min_lamports_per_signature,
    .max_lamports_per_signature    = test_ctx->slot_ctx.fee_rate_governor.max_lamports_per_signature,
    .burn_percent                  = (uchar)test_ctx->slot_ctx.fee_rate_governor.burn_percent
  };

  fd_inflation_t * inflation = fd_bank_inflation_modify( slot_ctx->bank );
  *inflation = (fd_inflation_t){
    .initial         = test_ctx->epoch_ctx.inflation.initial,
    .terminal        = test_ctx->epoch_ctx.inflation.terminal,
    .taper           = test_ctx->epoch_ctx.inflation.taper,
    .foundation      = test_ctx->epoch_ctx.inflation.foundation,
    .foundation_term = test_ctx->epoch_ctx.inflation.foundation_term
  };

  fd_bank_block_height_set( slot_ctx->bank, test_ctx->slot_ctx.block_height );

  /* Initialize the current running epoch stake and vote accounts */

  /* SETUP STAKES HERE */
  fd_vote_states_t * vote_states = fd_bank_vote_states_locking_modify( slot_ctx->bank );
  vote_states = fd_vote_states_join( fd_vote_states_new( vote_states, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  fd_bank_vote_states_end_locking_modify( slot_ctx->bank );

  fd_vote_states_t * vote_states_prev = fd_bank_vote_states_prev_locking_modify( slot_ctx->bank );
  vote_states_prev = fd_vote_states_join( fd_vote_states_new( vote_states_prev, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  fd_bank_vote_states_prev_end_locking_modify( slot_ctx->bank );

  fd_vote_states_t * vote_states_prev_prev = fd_bank_vote_states_prev_prev_locking_modify( slot_ctx->bank );
  vote_states_prev_prev = fd_vote_states_join( fd_vote_states_new( vote_states_prev_prev, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  fd_bank_vote_states_prev_prev_end_locking_modify( slot_ctx->bank );

  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( slot_ctx->banks );
  stake_delegations = fd_stake_delegations_join( fd_stake_delegations_new( stake_delegations, FD_RUNTIME_MAX_STAKE_ACCOUNTS, 0 ) );

  /* Load in all accounts with > 0 lamports provided in the context. The input expects unique account pubkeys. */
  vote_states = fd_bank_vote_states_locking_modify( slot_ctx->bank );
  for( ushort i=0; i<test_ctx->acct_states_count; i++ ) {
    FD_TXN_ACCOUNT_DECL(acc);
    fd_runtime_fuzz_load_account( acc, funk, xid, &test_ctx->acct_states[i], 1 );

    /* Update vote accounts cache for epoch T */
    fd_pubkey_t pubkey;
    memcpy( &pubkey, test_ctx->acct_states[i].address, sizeof(fd_pubkey_t) );
    fd_runtime_fuzz_block_register_vote_account(
        slot_ctx,
        vote_states,
        &pubkey,
        runner->spad );

    /* Update the stake delegations cache for epoch T */
    fd_runtime_fuzz_block_register_stake_delegation( slot_ctx,
                                                     stake_delegations,
                                                     &pubkey );
  }

  /* Refresh vote accounts to calculate stake delegations */
  fd_runtime_fuzz_block_refresh_vote_accounts( vote_states, stake_delegations );
  fd_bank_vote_states_end_locking_modify( slot_ctx->bank );

  /* Finish init epoch bank sysvars */
  fd_epoch_schedule_t epoch_schedule_[1];
  fd_epoch_schedule_t * epoch_schedule = fd_sysvar_epoch_schedule_read( funk, xid, epoch_schedule_ );
  FD_TEST( epoch_schedule );
  fd_bank_epoch_schedule_set( slot_ctx->bank, *epoch_schedule );

  fd_rent_t const * rent = fd_sysvar_rent_read( funk, xid, runner->spad );
  FD_TEST( rent );
  fd_bank_rent_set( slot_ctx->bank, *rent );

  fd_bank_epoch_set( slot_ctx->bank, fd_slot_to_epoch( epoch_schedule, slot, NULL ) );


  /* Refresh the program cache */
  fd_runtime_fuzz_refresh_program_cache( slot_ctx, test_ctx->acct_states, test_ctx->acct_states_count, runner->spad );

  /* Update vote cache for epoch T-1 */
  vote_states_prev = fd_bank_vote_states_prev_locking_modify( slot_ctx->bank );
  fd_runtime_fuzz_block_update_prev_epoch_votes_cache( vote_states_prev,
                                                       test_ctx->epoch_ctx.vote_accounts_t_1,
                                                       test_ctx->epoch_ctx.vote_accounts_t_1_count,
                                                       runner->spad );
  fd_bank_vote_states_prev_end_locking_modify( slot_ctx->bank );

  /* Update vote cache for epoch T-2 */
  vote_states_prev_prev = fd_bank_vote_states_prev_prev_locking_modify( slot_ctx->bank );
  fd_runtime_fuzz_block_update_prev_epoch_votes_cache( vote_states_prev_prev,
                                                       test_ctx->epoch_ctx.vote_accounts_t_2,
                                                       test_ctx->epoch_ctx.vote_accounts_t_2_count,
                                                       runner->spad );
  fd_bank_vote_states_prev_prev_end_locking_modify( slot_ctx->bank );

  /* Update leader schedule */
  fd_vote_stake_weight_t * epoch_weights_mem = fd_spad_alloc( runner->spad, alignof(fd_vote_stake_weight_t), FD_RUNTIME_MAX_VOTE_ACCOUNTS * sizeof(fd_vote_stake_weight_t) );
  fd_runtime_update_leaders( slot_ctx->bank, fd_bank_slot_get( slot_ctx->bank ), epoch_weights_mem );

  /* Initialize the blockhash queue and recent blockhashes sysvar from the input blockhash queue */
  ulong blockhash_seed; FD_TEST( fd_rng_secure( &blockhash_seed, sizeof(ulong) ) );
  fd_blockhashes_init( fd_bank_block_hash_queue_modify( slot_ctx->bank ), blockhash_seed );

  /* TODO: We might need to load this in from the input. We also need to
     size this out for worst case, but this also blows up the memory
     requirement. */
  /* Allocate all the memory for the rent fresh accounts list */

  // Set genesis hash to {0}
  fd_hash_t * genesis_hash = fd_bank_genesis_hash_modify( slot_ctx->bank );
  fd_memset( genesis_hash->hash, 0, sizeof(fd_hash_t) );

  // Use the latest lamports per signature
  fd_recent_block_hashes_t const * rbh = fd_sysvar_recent_hashes_read( funk, xid, runner->spad );
  if( rbh && !deq_fd_block_block_hash_entry_t_empty( rbh->hashes ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_head_const( rbh->hashes );
    if( last && last->fee_calculator.lamports_per_signature!=0UL ) {
      fd_bank_lamports_per_signature_set( slot_ctx->bank, last->fee_calculator.lamports_per_signature );
      fd_bank_prev_lamports_per_signature_set( slot_ctx->bank, last->fee_calculator.lamports_per_signature );
    }
  }

  /* Make a new funk transaction since we're done loading in accounts for context */
  fd_funk_txn_xid_t fork_xid = { .ul = { slot, slot } };
  fd_funk_txn_prepare( funk, slot_ctx->xid, &fork_xid );
  slot_ctx->xid[0] = fork_xid;

  /* Reset the lthash to zero, because we are in a new Funk transaction now */
  fd_lthash_value_t lthash = {0};
  fd_bank_lthash_set( slot_ctx->bank, lthash );

  // Populate blockhash queue and recent blockhashes sysvar
  for( ushort i=0; i<test_ctx->blockhash_queue_count; ++i ) {
    fd_hash_t hash;
    memcpy( &hash, test_ctx->blockhash_queue[i]->bytes, sizeof(fd_hash_t) );
    fd_bank_poh_set( slot_ctx->bank, hash );
    fd_sysvar_recent_hashes_update( slot_ctx ); /* appends an entry */
  }

  // Set the current poh from the input (we skip POH verification in this fuzzing target)
  fd_hash_t * poh = fd_bank_poh_modify( slot_ctx->bank );
  fd_memcpy( poh->hash, test_ctx->slot_ctx.poh, sizeof(fd_hash_t) );

  /* Restore sysvar cache */
  fd_sysvar_cache_restore_fuzz( slot_ctx );

  /* Prepare raw transaction pointers and block / microblock infos */
  ulong txn_cnt = test_ctx->txns_count;

  // For fuzzing, we're using a single microblock batch that contains a single microblock containing all transactions
  fd_runtime_block_info_t *    block_info       = fd_spad_alloc( runner->spad, alignof(fd_runtime_block_info_t), sizeof(fd_runtime_block_info_t) );
  fd_microblock_batch_info_t * batch_info       = fd_spad_alloc( runner->spad, alignof(fd_microblock_batch_info_t), sizeof(fd_microblock_batch_info_t) );
  fd_microblock_info_t *       microblock_info  = fd_spad_alloc( runner->spad, alignof(fd_microblock_info_t), sizeof(fd_microblock_info_t) );
  fd_memset( block_info, 0, sizeof(fd_runtime_block_info_t) );
  fd_memset( batch_info, 0, sizeof(fd_microblock_batch_info_t) );
  fd_memset( microblock_info, 0, sizeof(fd_microblock_info_t) );

  block_info->microblock_batch_cnt   = 1UL;
  block_info->microblock_cnt         = 1UL;
  block_info->microblock_batch_infos = batch_info;

  batch_info->microblock_cnt         = 1UL;
  batch_info->microblock_infos       = microblock_info;

  ulong batch_signature_cnt          = 0UL;
  ulong batch_txn_cnt                = 0UL;
  ulong batch_account_cnt            = 0UL;
  ulong signature_cnt                = 0UL;
  ulong account_cnt                  = 0UL;

  fd_microblock_hdr_t * microblock_hdr = fd_spad_alloc( runner->spad, alignof(fd_microblock_hdr_t), sizeof(fd_microblock_hdr_t) );
  fd_memset( microblock_hdr, 0, sizeof(fd_microblock_hdr_t) );

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

    signature_cnt += TXN( txn )->signature_cnt;
    account_cnt   += fd_txn_account_cnt( TXN( txn ), FD_TXN_ACCT_CAT_ALL );
  }

  microblock_hdr->txn_cnt         = txn_cnt;
  microblock_info->microblock.raw = (uchar *)microblock_hdr;

  microblock_info->signature_cnt  = signature_cnt;
  microblock_info->account_cnt    = account_cnt;
  microblock_info->txns           = txn_ptrs;

  batch_signature_cnt            += signature_cnt;
  batch_txn_cnt                  += txn_cnt;
  batch_account_cnt              += account_cnt;

  block_info->signature_cnt = batch_info->signature_cnt = batch_signature_cnt;
  block_info->txn_cnt       = batch_info->txn_cnt       = batch_txn_cnt;
  block_info->account_cnt   = batch_info->account_cnt   = batch_account_cnt;

  return block_info;
}

/* Takes in a block_info created from `fd_runtime_fuzz_block_ctx_create()`
   and executes it against the runtime. Returns the execution result. */
static int
fd_runtime_fuzz_block_ctx_exec( fd_solfuzz_runner_t *      runner,
                                fd_exec_slot_ctx_t *       slot_ctx,
                                fd_runtime_block_info_t *  block_info ) {
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
      capture_ctx->capture   = runner->solcap;
      capture_ctx->solcap_start_slot = fd_bank_slot_get( slot_ctx->bank );
      slot_ctx->capture_ctx = capture_ctx;
      fd_solcap_writer_set_slot( slot_ctx->capture_ctx->capture, fd_bank_slot_get( slot_ctx->bank ) );
    }

    fd_rewards_recalculate_partitioned_rewards( slot_ctx, capture_ctx, runner->spad );

    /* Process new epoch may push a new spad frame onto the runtime spad. We should make sure this frame gets
       cleared (if it was allocated) before executing the block. */
    int is_epoch_boundary = 0;
    fd_vote_stake_weight_t * epoch_weights_mem = fd_spad_alloc( runner->spad, alignof(fd_vote_stake_weight_t), FD_RUNTIME_MAX_VOTE_ACCOUNTS * sizeof(fd_vote_stake_weight_t) );
    fd_runtime_block_pre_execute_process_new_epoch( slot_ctx, capture_ctx, runner->spad, epoch_weights_mem, &is_epoch_boundary );

    res = fd_runtime_block_execute_prepare( slot_ctx, runner->spad );
    if( FD_UNLIKELY( res ) ) {
      return res;
    }

    fd_txn_p_t * txn_ptrs = block_info->microblock_batch_infos[0].microblock_infos[0].txns;
    ulong        txn_cnt  = block_info->microblock_batch_infos[0].txn_cnt;

    /* Sequential transaction execution */
    for( ulong i=0UL; i<txn_cnt; i++ ) {
      fd_txn_p_t * txn = &txn_ptrs[i];

      /* Update the program cache */
      fd_runtime_update_program_cache( slot_ctx, txn, runner->spad );

      /* Execute the transaction against the runtime */
      res = FD_RUNTIME_EXECUTE_SUCCESS;
      fd_exec_txn_ctx_t * txn_ctx = fd_runtime_fuzz_txn_ctx_exec( runner, slot_ctx, txn, &res );
      txn_ctx->exec_err           = res;

      if( FD_UNLIKELY( !(txn_ctx->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) ) ) {
        break;
      }

      /* Finalize the transaction */
      fd_runtime_finalize_txn(
          slot_ctx->funk,
          NULL,
          slot_ctx->xid,
          txn_ctx,
          slot_ctx->bank,
          capture_ctx );

      if( FD_UNLIKELY( !(txn_ctx->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) ) ) {
        break;
      }

      res = FD_RUNTIME_EXECUTE_SUCCESS;
    }

    /* Finalize the block */
    fd_runtime_block_execute_finalize( slot_ctx );
  } FD_SPAD_FRAME_END;

  return res;
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
    /* Initialize memory */
    uchar *               slot_ctx_mem  = fd_spad_alloc( runner->spad, FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT );
    fd_exec_slot_ctx_t *  slot_ctx      = fd_exec_slot_ctx_join ( fd_exec_slot_ctx_new ( slot_ctx_mem ) );

    /* Set up the block execution context */
    fd_runtime_block_info_t * block_info = fd_runtime_fuzz_block_ctx_create( runner, slot_ctx, input );
    if( block_info==NULL ) {
      fd_runtime_fuzz_block_ctx_destroy( runner );
      return 0;
    }

    /* Execute the constructed block against the runtime. */
    int res = fd_runtime_fuzz_block_ctx_exec( runner, slot_ctx, block_info );

    /* Start saving block exec results */
    FD_SCRATCH_ALLOC_INIT( l, output_buf );
    ulong output_end = (ulong)output_buf + output_bufsz;

    fd_exec_test_block_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_block_effects_t),
                                  sizeof (fd_exec_test_block_effects_t) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      abort();
    }
    fd_memset( effects, 0, sizeof(fd_exec_test_block_effects_t) );

    /* Capture error status */
    effects->has_error = !!( res );

    /* Capture capitalization */
    effects->slot_capitalization = fd_bank_capitalization_get( slot_ctx->bank );

    /* Capture hashes */
    fd_hash_t bank_hash = fd_bank_bank_hash_get( slot_ctx->bank );
    fd_memcpy( effects->bank_hash, bank_hash.hash, sizeof(fd_hash_t) );

    /* Capture cost tracker */
    fd_cost_tracker_t * cost_tracker = fd_bank_cost_tracker_locking_query( slot_ctx->bank );
    effects->has_cost_tracker = 1;
    effects->cost_tracker = (fd_exec_test_cost_tracker_t) {
      .block_cost = cost_tracker ? cost_tracker->block_cost : 0UL,
      .vote_cost  = cost_tracker ? cost_tracker->vote_cost : 0UL,
    };
    fd_bank_cost_tracker_end_locking_query( slot_ctx->bank );

    ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
    fd_runtime_fuzz_block_ctx_destroy( runner );

    *output = effects;
    return actual_end - (ulong)output_buf;
  } FD_SPAD_FRAME_END;
}
