#include "fd_block_harness.h"

/* Stripped down version of `fd_refresh_vote_accounts()` that simply refreshes the stake delegation amount
   for each of the vote accounts using the stake delegations cache. */
static void
fd_runtime_fuzz_block_refresh_vote_accounts( fd_vote_accounts_pair_global_t_mapnode_t *  vote_accounts_pool,
                                             fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root,
                                             fd_delegation_pair_t_mapnode_t *  stake_delegations_pool,
                                             fd_delegation_pair_t_mapnode_t * stake_delegations_root ) {
  for( fd_delegation_pair_t_mapnode_t * node = fd_delegation_pair_t_map_minimum( stake_delegations_pool, stake_delegations_root );
       node;
       node = fd_delegation_pair_t_map_successor( stake_delegations_pool, node ) ) {
    fd_pubkey_t * voter_pubkey = &node->elem.delegation.voter_pubkey;
    ulong         stake        = node->elem.delegation.stake;

    /* Find the voter in the vote accounts cache and update their delegation amount */
    fd_vote_accounts_pair_global_t_mapnode_t vode_node[1];
    fd_memcpy( vode_node->elem.key.uc, voter_pubkey, sizeof(fd_pubkey_t) );
    fd_vote_accounts_pair_global_t_mapnode_t * found_node = fd_vote_accounts_pair_global_t_map_find( vote_accounts_pool, vote_accounts_root, vode_node );
    if( FD_LIKELY( found_node ) ) {
      found_node->elem.stake += stake;
    }
  }
}

/* Registers a single vote account into the current votes cache. The entry is derived
   from the current present account state. This function also registers a vote timestamp
   for the vote account */
static void
fd_runtime_fuzz_block_register_vote_account( fd_exec_slot_ctx_t *                        slot_ctx,
                                             fd_vote_accounts_pair_global_t_mapnode_t *  pool,
                                             fd_vote_accounts_pair_global_t_mapnode_t ** root,
                                             fd_pubkey_t *                               pubkey,
                                             fd_spad_t *                                 spad ) {
  FD_TXN_ACCOUNT_DECL( acc );
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( acc, pubkey, slot_ctx->funk, slot_ctx->funk_txn ) ) ) {
    return;
  }

  /* Account must be owned by the vote program */
  if( memcmp( acc->vt->get_owner( acc ), fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return;
  }

  /* Account must have > 0 lamports */
  if( acc->vt->get_lamports( acc )==0UL ) {
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

  /* Nothing to do if the account already exists in the cache */
  fd_vote_accounts_pair_global_t_mapnode_t existing_node[1];
  fd_memcpy( existing_node->elem.key.uc, pubkey, sizeof(fd_pubkey_t) );
  if( fd_vote_accounts_pair_global_t_map_find( pool, *root, existing_node ) ) {
    return;
  }

  /* At this point, the node is new and needs to be inserted into the cache. */
  fd_vote_accounts_pair_global_t_mapnode_t * node_to_insert = fd_vote_accounts_pair_global_t_map_acquire( pool );
  fd_memcpy( node_to_insert->elem.key.uc, pubkey, sizeof(fd_pubkey_t) );

  ulong account_dlen                    = acc->vt->get_data_len( acc );
  node_to_insert->elem.stake            = 0UL; // This will get set later
  node_to_insert->elem.value.executable = !!acc->vt->is_executable( acc );
  node_to_insert->elem.value.lamports   = acc->vt->get_lamports( acc );
  node_to_insert->elem.value.rent_epoch = acc->vt->get_rent_epoch( acc );
  node_to_insert->elem.value.data_len   = account_dlen;

  uchar * data = fd_spad_alloc( spad, alignof(uchar), account_dlen );
  memcpy( data, acc->vt->get_data( acc ), account_dlen );
  fd_solana_account_data_update( &node_to_insert->elem.value, data );

  fd_vote_accounts_pair_global_t_map_insert( pool, root, node_to_insert );

  /* Record a timestamp for the vote account */
  fd_vote_block_timestamp_t const * ts = NULL;
  switch( vsv->discriminant ) {
    case fd_vote_state_versioned_enum_v0_23_5:
      ts = &vsv->inner.v0_23_5.last_timestamp;
      break;
    case fd_vote_state_versioned_enum_v1_14_11:
      ts = &vsv->inner.v1_14_11.last_timestamp;
      break;
    case fd_vote_state_versioned_enum_current:
      ts = &vsv->inner.current.last_timestamp;
      break;
    default:
      __builtin_unreachable();
  }

  fd_vote_record_timestamp_vote_with_slot( pubkey, ts->timestamp, ts->slot, slot_ctx->bank );
}

/* Stores an entry in the stake delegations cache for the given vote account. Deserializes and uses the present
   account state to derive delegation information. */
static void
fd_runtime_fuzz_block_register_stake_delegation( fd_exec_slot_ctx_t *              slot_ctx,
                                                 fd_delegation_pair_t_mapnode_t *  pool,
                                                 fd_delegation_pair_t_mapnode_t ** root,
                                                 fd_pubkey_t *                     pubkey ) {
 FD_TXN_ACCOUNT_DECL( acc );
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( acc, pubkey, slot_ctx->funk, slot_ctx->funk_txn ) ) ) {
    return;
  }

  /* Account must be owned by the stake program */
  if( memcmp( acc->vt->get_owner( acc ), fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return;
  }

  /* Account must have > 0 lamports */
  if( acc->vt->get_lamports( acc )==0UL ) {
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
  fd_delegation_pair_t_mapnode_t existing_node[1];
  fd_memcpy( existing_node->elem.account.uc, pubkey, sizeof(fd_pubkey_t) );
  if( fd_delegation_pair_t_map_find( pool, *root, existing_node ) ) {
    return;
  }

  /* At this point, the node is new and needs to be inserted into the cache. */
  fd_delegation_pair_t_mapnode_t * node_to_insert = fd_delegation_pair_t_map_acquire( pool );
  fd_memcpy( node_to_insert->elem.account.uc, pubkey, sizeof(fd_pubkey_t) );

  node_to_insert->elem.account    = *pubkey;
  node_to_insert->elem.delegation = stake_state.inner.stake.stake.delegation;

  fd_delegation_pair_t_map_insert( pool, root, node_to_insert );
}

/* Common helper method for populating a previous epoch's vote cache. */
static void
fd_runtime_fuzz_block_update_prev_epoch_votes_cache( fd_vote_accounts_pair_global_t_mapnode_t *  pool,
                                                     fd_vote_accounts_pair_global_t_mapnode_t ** root,
                                                     fd_exec_test_vote_account_t *        vote_accounts,
                                                     pb_size_t                            vote_accounts_cnt,
                                                     fd_spad_t *                          spad ) {
  for( uint i=0U; i<vote_accounts_cnt; i++ ) {
    fd_exec_test_acct_state_t * vote_account = &vote_accounts[i].vote_account;
    ulong                       stake        = vote_accounts[i].stake;

    fd_vote_accounts_pair_global_t_mapnode_t * vote_node = fd_vote_accounts_pair_global_t_map_acquire( pool );
    vote_node->elem.stake = stake;
    fd_memcpy( &vote_node->elem.key, vote_account->address, sizeof(fd_pubkey_t) );
    vote_node->elem.value.executable = vote_account->executable;
    vote_node->elem.value.lamports   = vote_account->lamports;
    vote_node->elem.value.rent_epoch = vote_account->rent_epoch;
    vote_node->elem.value.data_len   = vote_account->data->size;
    fd_memcpy( &vote_node->elem.value.owner, vote_account->owner, sizeof(fd_pubkey_t) );

    uchar * data = fd_spad_alloc( spad, alignof(uchar), vote_account->data->size );
    memcpy( data, vote_account->data->bytes, vote_account->data->size );
    fd_solana_account_data_update( &vote_node->elem.value, data );

    fd_vote_accounts_pair_global_t_map_insert( pool, root, vote_node );
  }
}

static void
fd_runtime_fuzz_block_ctx_destroy( fd_runtime_fuzz_runner_t * runner,
                                   fd_wksp_t *                wksp ) {
  fd_funk_txn_cancel_all( runner->funk, 1 );
  fd_wksp_detach( wksp );
}

/* Sets up block execution context from an input test case to execute against the runtime.
   Returns block_info on success and NULL on failure. */
static fd_runtime_block_info_t *
fd_runtime_fuzz_block_ctx_create( fd_runtime_fuzz_runner_t *           runner,
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
  fd_funk_txn_start_write( funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 1 );
  fd_funk_txn_end_write( funk );

  /* Allocate contexts */
  ulong vote_acct_max = fd_ulong_max( 128UL, test_ctx->acct_states_count );

  /* Restore feature flags */
  fd_features_t features = {0};
  if( !fd_runtime_fuzz_restore_features( &features, &test_ctx->epoch_ctx.features ) ) {
    return NULL;
  }
  fd_bank_features_set( slot_ctx->bank, features );

  /* Set up slot context */
  ulong slot = test_ctx->slot_ctx.slot;

  slot_ctx->funk_txn  = funk_txn;
  slot_ctx->funk      = funk;
  runner->bank->slot_ = slot;

  fd_hash_t * bank_hash = fd_bank_bank_hash_modify( slot_ctx->bank );
  fd_memcpy( bank_hash, test_ctx->slot_ctx.parent_bank_hash, sizeof(fd_hash_t) );

  /* All bank mgr stuff here. */

  /* Initialize vote timestamps cache */
  fd_clock_timestamp_votes_global_t * clock_timestamp_votes = fd_bank_clock_timestamp_votes_locking_modify( slot_ctx->bank );
  uchar * pool_mem = (uchar *)fd_ulong_align_up( (ulong)clock_timestamp_votes + sizeof(fd_clock_timestamp_votes_global_t), fd_clock_timestamp_vote_t_map_align() );
  fd_clock_timestamp_vote_t_mapnode_t * clock_pool = fd_clock_timestamp_vote_t_map_join( fd_clock_timestamp_vote_t_map_new( pool_mem, 15000UL ) );
  fd_clock_timestamp_vote_t_mapnode_t * clock_root = NULL;

  fd_clock_timestamp_votes_votes_pool_update( clock_timestamp_votes, clock_pool );
  fd_clock_timestamp_votes_votes_root_update( clock_timestamp_votes, clock_root );
  fd_bank_clock_timestamp_votes_end_locking_modify( slot_ctx->bank );

  slot_ctx->bank->slot_ = slot;

  fd_bank_block_height_set( slot_ctx->bank, test_ctx->slot_ctx.block_height );

  fd_bank_parent_slot_set( slot_ctx->bank, test_ctx->slot_ctx.prev_slot );

  fd_bank_capitalization_set( slot_ctx->bank, test_ctx->slot_ctx.prev_epoch_capitalization );

  fd_bank_lamports_per_signature_set( slot_ctx->bank, 5000UL );

  fd_bank_prev_lamports_per_signature_set( slot_ctx->bank, test_ctx->slot_ctx.prev_lps );

  // self.max_tick_height = (self.slot + 1) * self.ticks_per_slot;
  fd_bank_hashes_per_tick_set( slot_ctx->bank, test_ctx->epoch_ctx.hashes_per_tick );

  fd_bank_ticks_per_slot_set( slot_ctx->bank, test_ctx->epoch_ctx.ticks_per_slot );

  fd_bank_ns_per_slot_set( slot_ctx->bank, 400000000 ); // TODO: restore from input

  fd_bank_genesis_creation_time_set( slot_ctx->bank, test_ctx->epoch_ctx.genesis_creation_time );

  fd_bank_slots_per_year_set( slot_ctx->bank, test_ctx->epoch_ctx.slots_per_year );

  fd_fee_rate_governor_t * fee_rate_governor = fd_bank_fee_rate_governor_modify( slot_ctx->bank );
  fee_rate_governor->target_lamports_per_signature = 10000UL;
  fee_rate_governor->target_signatures_per_slot = 20000UL;
  fee_rate_governor->min_lamports_per_signature = 5000UL;
  fee_rate_governor->max_lamports_per_signature = 100000UL;
  fee_rate_governor->burn_percent = 50;

  fd_inflation_t * inflation = fd_bank_inflation_modify( slot_ctx->bank );
  inflation->initial         = test_ctx->epoch_ctx.inflation.initial;
  inflation->terminal        = test_ctx->epoch_ctx.inflation.terminal;
  inflation->taper           = test_ctx->epoch_ctx.inflation.taper;
  inflation->foundation      = test_ctx->epoch_ctx.inflation.foundation;
  inflation->foundation_term = test_ctx->epoch_ctx.inflation.foundation_term;

  fd_bank_block_height_set( slot_ctx->bank, test_ctx->slot_ctx.block_height );

  // /* Initialize the current running epoch stake and vote accounts */

  /* TODO: should be stake account max */
  fd_account_keys_global_t * stake_account_keys = fd_bank_stake_account_keys_locking_modify( slot_ctx->bank );
  pool_mem = (uchar *)fd_ulong_align_up( (ulong)stake_account_keys + sizeof(fd_account_keys_global_t), fd_account_keys_pair_t_map_align() );
  fd_account_keys_pair_t_mapnode_t * account_keys_pool = fd_account_keys_pair_t_map_join( fd_account_keys_pair_t_map_new( pool_mem, vote_acct_max ) );
  fd_account_keys_pair_t_mapnode_t * account_keys_root = NULL;
  fd_account_keys_account_keys_pool_update( stake_account_keys, account_keys_pool );
  fd_account_keys_account_keys_root_update( stake_account_keys, account_keys_root );
  fd_bank_stake_account_keys_end_locking_modify( slot_ctx->bank );

  fd_account_keys_global_t * vote_account_keys = fd_bank_vote_account_keys_locking_modify( slot_ctx->bank );
  pool_mem = (uchar *)fd_ulong_align_up( (ulong)vote_account_keys + sizeof(fd_account_keys_global_t), fd_account_keys_pair_t_map_align() );
  fd_account_keys_pair_t_mapnode_t * vote_account_keys_pool = fd_account_keys_pair_t_map_join( fd_account_keys_pair_t_map_new( pool_mem, vote_acct_max ) );
  fd_account_keys_pair_t_mapnode_t * vote_account_keys_root = NULL;
  fd_account_keys_account_keys_pool_update( vote_account_keys, vote_account_keys_pool );
  fd_account_keys_account_keys_root_update( vote_account_keys, vote_account_keys_root );
  fd_bank_vote_account_keys_end_locking_modify( slot_ctx->bank );


  /* SETUP STAKES HERE */
  fd_stakes_global_t * stakes = fd_bank_stakes_locking_modify( slot_ctx->bank );
  pool_mem = (uchar *)fd_ulong_align_up( (ulong)stakes + sizeof(fd_stakes_global_t), fd_vote_accounts_pair_t_map_align() );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_pool = fd_vote_accounts_pair_global_t_map_join( fd_vote_accounts_pair_global_t_map_new( pool_mem, vote_acct_max ) );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root = NULL;
  pool_mem = (uchar *)fd_ulong_align_up( (ulong)pool_mem + fd_vote_accounts_pair_global_t_map_footprint( vote_acct_max ), fd_delegation_pair_t_map_align() );
  fd_delegation_pair_t_mapnode_t * stake_delegations_pool = fd_delegation_pair_t_map_join( fd_delegation_pair_t_map_new( pool_mem, vote_acct_max ) );
  fd_delegation_pair_t_mapnode_t * stake_delegations_root = NULL;

  /* Load in all accounts with > 0 lamports provided in the context. The input expects unique account pubkeys. */
  for( ushort i=0; i<test_ctx->acct_states_count; i++ ) {
    FD_TXN_ACCOUNT_DECL(acc);
    fd_runtime_fuzz_load_account( acc, funk, funk_txn, &test_ctx->acct_states[i], 1 );

    /* Update vote accounts cache for epoch T */
    fd_pubkey_t pubkey;
    memcpy( &pubkey, test_ctx->acct_states[i].address, sizeof(fd_pubkey_t) );
    fd_runtime_fuzz_block_register_vote_account( slot_ctx,
                                                 vote_accounts_pool,
                                                 &vote_accounts_root,
                                                 &pubkey,
                                                 runner->spad );

    /* Update the stake delegations cache for epoch T */
    fd_runtime_fuzz_block_register_stake_delegation( slot_ctx,
                                                     stake_delegations_pool,
                                                     &stake_delegations_root,
                                                     &pubkey );
  }

  /* Refresh vote accounts to calculate stake delegations */
  fd_runtime_fuzz_block_refresh_vote_accounts( vote_accounts_pool,
                                               vote_accounts_root,
                                               stake_delegations_pool,
                                               stake_delegations_root );

  fd_vote_accounts_vote_accounts_pool_update( &stakes->vote_accounts, vote_accounts_pool );
  fd_vote_accounts_vote_accounts_root_update( &stakes->vote_accounts, vote_accounts_root );

  fd_stakes_stake_delegations_pool_update( stakes, stake_delegations_pool );
  fd_stakes_stake_delegations_root_update( stakes, stake_delegations_root );

  /* Finish init epoch bank sysvars */
  fd_epoch_schedule_t epoch_schedule_[1];
  fd_epoch_schedule_t * epoch_schedule = fd_sysvar_epoch_schedule_read( funk, funk_txn, epoch_schedule_ );
  fd_bank_epoch_schedule_set( slot_ctx->bank, *epoch_schedule );

  fd_rent_t const * rent = fd_sysvar_rent_read( funk, funk_txn, runner->spad );
  fd_bank_rent_set( slot_ctx->bank, *rent );

  stakes->epoch = fd_slot_to_epoch( epoch_schedule, test_ctx->slot_ctx.prev_slot, NULL );

  fd_bank_stakes_end_locking_modify( slot_ctx->bank );

  /* Add accounts to bpf program cache */
  fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, runner->spad );

  fd_vote_accounts_global_t * vote_accounts = fd_bank_next_epoch_stakes_locking_modify( slot_ctx->bank );
  pool_mem = (uchar *)fd_ulong_align_up( (ulong)vote_accounts + sizeof(fd_vote_accounts_global_t), fd_vote_accounts_pair_global_t_map_align() );
  vote_accounts_pool = fd_vote_accounts_pair_global_t_map_join( fd_vote_accounts_pair_global_t_map_new( pool_mem, vote_acct_max ) );
  vote_accounts_root = NULL;

  /* Update vote cache for epoch T-1 */
  fd_runtime_fuzz_block_update_prev_epoch_votes_cache( vote_accounts_pool,
                                                       &vote_accounts_root,
                                                       test_ctx->epoch_ctx.vote_accounts_t_1,
                                                       test_ctx->epoch_ctx.vote_accounts_t_1_count,
                                                       runner->spad );

  fd_vote_accounts_vote_accounts_pool_update( vote_accounts, vote_accounts_pool );
  fd_vote_accounts_vote_accounts_root_update( vote_accounts, vote_accounts_root );

  fd_bank_next_epoch_stakes_end_locking_modify( slot_ctx->bank );

  /* Update vote cache for epoch T-2 */
  vote_accounts = fd_bank_epoch_stakes_locking_modify( slot_ctx->bank );
  pool_mem = (uchar *)fd_ulong_align_up( (ulong)vote_accounts + sizeof(fd_vote_accounts_global_t), fd_vote_accounts_pair_global_t_map_align() );
  vote_accounts_pool = fd_vote_accounts_pair_global_t_map_join( fd_vote_accounts_pair_global_t_map_new( pool_mem, vote_acct_max ) );
  vote_accounts_root = NULL;

  fd_runtime_fuzz_block_update_prev_epoch_votes_cache( vote_accounts_pool,
                                                       &vote_accounts_root,
                                                       test_ctx->epoch_ctx.vote_accounts_t_2,
                                                       test_ctx->epoch_ctx.vote_accounts_t_2_count,
                                                       runner->spad );

  fd_vote_accounts_vote_accounts_pool_update( vote_accounts, vote_accounts_pool );
  fd_vote_accounts_vote_accounts_root_update( vote_accounts, vote_accounts_root );
  fd_bank_epoch_stakes_end_locking_modify( slot_ctx->bank );

  /* Update leader schedule */
  fd_runtime_update_leaders( slot_ctx->bank, fd_bank_slot_get( slot_ctx->bank ), runner->spad );

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
  fd_recent_block_hashes_t const * rbh = fd_sysvar_recent_hashes_read( funk, funk_txn, runner->spad );
  if( rbh && !deq_fd_block_block_hash_entry_t_empty( rbh->hashes ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_head_const( rbh->hashes );
    if( last && last->fee_calculator.lamports_per_signature!=0UL ) {
      fd_bank_lamports_per_signature_set( slot_ctx->bank, last->fee_calculator.lamports_per_signature );
      fd_bank_prev_lamports_per_signature_set( slot_ctx->bank, last->fee_calculator.lamports_per_signature );
    }
  }

  // Populate blockhash queue and recent blockhashes sysvar
  for( ushort i=0; i<test_ctx->blockhash_queue_count; ++i ) {
    fd_hash_t hash;
    memcpy( &hash, test_ctx->blockhash_queue[i]->bytes, sizeof(fd_hash_t) );
    fd_bank_poh_set( slot_ctx->bank, hash );
    fd_sysvar_recent_hashes_update( slot_ctx, runner->spad ); /* appends an entry */
  }

  // Set the current poh from the input (we skip POH verification in this fuzzing target)
  fd_hash_t * poh = fd_bank_poh_modify( slot_ctx->bank );
  fd_memcpy( poh->hash, test_ctx->slot_ctx.poh, sizeof(fd_hash_t) );

  /* Make a new funk transaction since we're done loading in accounts for context */
  fd_funk_txn_xid_t fork_xid[1] = {0};
  fork_xid[0] = fd_funk_generate_xid();
  fd_funk_txn_start_write( funk );
  slot_ctx->funk_txn = fd_funk_txn_prepare( funk, slot_ctx->funk_txn, fork_xid, 1 );
  fd_funk_txn_end_write( funk );

  /* Calculate epoch account hash values. This sets epoch_bank.eah_{start_slot, stop_slot, interval} */
  fd_calculate_epoch_accounts_hash_values( slot_ctx );

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
    fd_txn_p_t * txn = &txn_ptrs[i];

    ushort _instr_count, _addr_table_cnt;
    ulong msg_sz = fd_runtime_fuzz_serialize_txn( txn->payload, &test_ctx->txns[i], &_instr_count, &_addr_table_cnt );

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
fd_runtime_fuzz_block_ctx_exec( fd_runtime_fuzz_runner_t * runner,
                                fd_exec_slot_ctx_t *       slot_ctx,
                                fd_runtime_block_info_t *  block_info ) {
  int res = 0;

  fd_spad_t * runtime_spad = runner->spad;

  // Prepare. Execute. Finalize.
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {
    fd_rewards_recalculate_partitioned_rewards( slot_ctx, &runtime_spad, 1UL, runtime_spad );

    /* Process new epoch may push a new spad frame onto the runtime spad. We should make sure this frame gets
       cleared (if it was allocated) before executing the block. */
    int   is_epoch_boundary = 0;
    fd_runtime_block_pre_execute_process_new_epoch( slot_ctx, &runtime_spad, 1UL, runtime_spad, &is_epoch_boundary );

    res = fd_runtime_block_execute( slot_ctx, NULL, block_info, runtime_spad );
  } FD_SPAD_FRAME_END;

  return res;
}

ulong
fd_runtime_fuzz_block_run( fd_runtime_fuzz_runner_t * runner,
                           void const *               input_,
                           void **                    output_,
                           void *                     output_buf,
                           ulong                      output_bufsz ) {
  fd_exec_test_block_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_block_effects_t **      output = fd_type_pun( output_ );

  FD_SPAD_FRAME_BEGIN( runner->spad ) {
    /* Initialize memory */
    fd_wksp_t *           wksp          = fd_wksp_attach( "wksp" );
    uchar *               slot_ctx_mem  = fd_spad_alloc( runner->spad, FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT );
    fd_exec_slot_ctx_t *  slot_ctx      = fd_exec_slot_ctx_join ( fd_exec_slot_ctx_new ( slot_ctx_mem ) );

    /* Set up the block execution context */
    fd_runtime_block_info_t * block_info = fd_runtime_fuzz_block_ctx_create( runner, slot_ctx, input );
    if( block_info==NULL ) {
      fd_runtime_fuzz_block_ctx_destroy( runner, wksp );
      return 0;
    }

    /* Execute the constructed block against the runtime. */
    int res = fd_runtime_fuzz_block_ctx_exec( runner, slot_ctx, block_info);

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

    ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
    fd_runtime_fuzz_block_ctx_destroy( runner, wksp );

    *output = effects;
    return actual_end - (ulong)output_buf;
  } FD_SPAD_FRAME_END;
}
