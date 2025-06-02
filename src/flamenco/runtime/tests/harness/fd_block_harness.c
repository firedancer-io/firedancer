#include "fd_block_harness.h"

/* Common helper method for populating each epoch's vote cache. */
static void
fd_runtime_fuzz_block_update_votes_cache( fd_exec_slot_ctx_t *                 slot_ctx,
                                          fd_vote_accounts_pair_t_mapnode_t *  pool,
                                          fd_vote_accounts_pair_t_mapnode_t ** root,
                                          fd_exec_test_vote_account_t *        vote_accounts,
                                          pb_size_t                            vote_accounts_cnt,
                                          fd_spad_t *                          spad,
                                          uchar                                update_vote_timestamp ) {
  for( uint i=0U; i<vote_accounts_cnt; i++ ) {
    fd_exec_test_acct_state_t * vote_account = &vote_accounts[i].vote_account;
    ulong                       stake        = vote_accounts[i].stake;

    fd_vote_accounts_pair_t_mapnode_t * vote_node = fd_vote_accounts_pair_t_map_acquire( pool );
    vote_node->elem.stake = stake;
    fd_memcpy( &vote_node->elem.key, vote_account->address, sizeof(fd_pubkey_t) );
    vote_node->elem.value.executable = vote_account->executable;
    vote_node->elem.value.lamports   = vote_account->lamports;
    vote_node->elem.value.rent_epoch = vote_account->rent_epoch;
    vote_node->elem.value.data_len   = vote_account->data->size;
    vote_node->elem.value.data       = fd_spad_alloc( spad, alignof(uchar), vote_account->data->size );
    fd_memcpy( vote_node->elem.value.data, vote_account->data->bytes, vote_account->data->size );
    fd_memcpy( &vote_node->elem.value.owner, vote_account->owner, sizeof(fd_pubkey_t) );

    fd_vote_accounts_pair_t_map_insert( pool, root, vote_node );

    /* Update the clock vote timestamps map for stakes at epoch T */
    if( update_vote_timestamp ) {
      FD_TXN_ACCOUNT_DECL( acc );
      if( fd_txn_account_init_from_funk_readonly( acc, &vote_node->elem.key, slot_ctx->funk, slot_ctx->funk_txn ) ) {
        return;
      }

      FD_SPAD_FRAME_BEGIN( spad ) {
        /* First need to deserialize the vote state from the account record */
        int err;
        fd_vote_state_versioned_t * vsv = fd_bincode_decode_spad(
          vote_state_versioned, spad,
          acc->vt->get_data( acc ),
          acc->vt->get_data_len( acc ),
          &err );
        if( FD_UNLIKELY( err ) ) {
          return;
        }

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

        fd_vote_record_timestamp_vote_with_slot( slot_ctx, &vote_node->elem.key, ts->timestamp, ts->slot );
      } FD_SPAD_FRAME_END;
    }
  }
}

static void
fd_runtime_fuzz_block_ctx_destroy( fd_runtime_fuzz_runner_t * runner,
                                   fd_exec_slot_ctx_t *       slot_ctx,
                                   fd_wksp_t *                wksp,
                                   fd_alloc_t *               alloc ) {
  if( !slot_ctx ) return; // This shouldn't be false either

  fd_wksp_free_laddr( fd_alloc_delete( fd_alloc_leave( alloc ) ) );
  fd_wksp_detach( wksp );

  fd_funk_txn_cancel_all( runner->funk, 1 );
}

/* Sets up block execution context from an input test case to execute against the runtime.
   Returns block_info on success and NULL on failure. */
static fd_runtime_block_info_t *
fd_runtime_fuzz_block_ctx_create( fd_runtime_fuzz_runner_t *           runner,
                                  fd_exec_slot_ctx_t *                 slot_ctx,
                                  fd_exec_test_block_context_t const * test_ctx ) {
  fd_funk_t * funk = runner->funk;

  /* Generate unique ID for funk txn */
  fd_funk_txn_xid_t xid[1] = {0};
  xid[0] = fd_funk_generate_xid();

  /* Create temporary funk transaction and slot / epoch contexts */
  fd_funk_txn_start_write( funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 1 );
  fd_funk_txn_end_write( funk );

  /* Allocate contexts */
  ulong                 vote_acct_max = fd_ulong_max( 128UL,
                                                      fd_ulong_max( test_ctx->epoch_ctx.stake_accounts_count,
                                                                       fd_ulong_max( test_ctx->epoch_ctx.vote_accounts_t_count,
                                                                                        fd_ulong_max( test_ctx->epoch_ctx.vote_accounts_t_1_count,
                                                                                                         test_ctx->epoch_ctx.vote_accounts_t_2_count ) ) ) );
  uchar *               epoch_ctx_mem = fd_spad_alloc( runner->spad, 128UL, fd_exec_epoch_ctx_footprint( vote_acct_max ) );
  fd_exec_epoch_ctx_t * epoch_ctx     = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, vote_acct_max ) );

  /* Restore feature flags */
  if( !fd_runtime_fuzz_restore_features( epoch_ctx, &test_ctx->epoch_ctx.features ) ) {
    return NULL;
  }

  /* Set up slot context */
  slot_ctx->funk_txn                    = funk_txn;
  slot_ctx->funk                        = funk;
  slot_ctx->enable_exec_recording       = 0;
  slot_ctx->epoch_ctx                   = epoch_ctx;
  slot_ctx->runtime_wksp                = fd_wksp_containing( slot_ctx );
  slot_ctx->prev_lamports_per_signature = test_ctx->slot_ctx.prev_lps;
  fd_memcpy( &slot_ctx->slot_bank.banks_hash, test_ctx->slot_ctx.parent_bank_hash, sizeof( fd_hash_t ) );

  /* Set up slot bank */
  ulong            slot      = test_ctx->slot_ctx.slot;
  fd_slot_bank_t * slot_bank = &slot_ctx->slot_bank;

  /* Initialize vote timestamps cache */
  uchar * pool_mem                      = fd_spad_alloc( runner->spad, fd_clock_timestamp_vote_t_map_align(), fd_clock_timestamp_vote_t_map_footprint( 10000UL ) );
  slot_bank->timestamp_votes.votes_pool = fd_clock_timestamp_vote_t_map_join( fd_clock_timestamp_vote_t_map_new( pool_mem, 10000UL ) );
  slot_bank->timestamp_votes.votes_root = NULL;

  fd_memcpy( slot_bank->lthash.lthash, test_ctx->slot_ctx.parent_lt_hash, FD_LTHASH_LEN_BYTES );
  slot_bank->slot                   = slot;
  slot_bank->block_height           = test_ctx->slot_ctx.block_height;
  slot_bank->prev_slot              = test_ctx->slot_ctx.prev_slot;
  slot_bank->fee_rate_governor      = (fd_fee_rate_governor_t) {
    .target_lamports_per_signature  = 10000UL,
    .target_signatures_per_slot     = 20000UL,
    .min_lamports_per_signature     = 5000UL,
    .max_lamports_per_signature     = 100000UL,
    .burn_percent                   = 50,
  };
  slot_bank->capitalization         = test_ctx->slot_ctx.prev_epoch_capitalization;
  slot_bank->lamports_per_signature = 5000UL;

  /* Set up epoch context and epoch bank */
  /* TODO: Do we need any more of these? */
  fd_epoch_bank_t * epoch_bank    = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );

  // self.max_tick_height = (self.slot + 1) * self.ticks_per_slot;
  epoch_bank->hashes_per_tick       = test_ctx->epoch_ctx.hashes_per_tick;
  epoch_bank->ticks_per_slot        = test_ctx->epoch_ctx.ticks_per_slot;
  epoch_bank->ns_per_slot           = (uint128)400000000; // TODO: restore from input or smth
  epoch_bank->genesis_creation_time = test_ctx->epoch_ctx.genesis_creation_time;
  epoch_bank->slots_per_year        = test_ctx->epoch_ctx.slots_per_year;
  epoch_bank->inflation             = (fd_inflation_t) {
    .initial         = test_ctx->epoch_ctx.inflation.initial,
    .terminal        = test_ctx->epoch_ctx.inflation.terminal,
    .taper           = test_ctx->epoch_ctx.inflation.taper,
    .foundation      = test_ctx->epoch_ctx.inflation.foundation,
    .foundation_term = test_ctx->epoch_ctx.inflation.foundation_term
  };

  /* Load in all accounts with > 0 lamports provided in the context */
  for( ushort i=0; i<test_ctx->acct_states_count; i++ ) {
    FD_TXN_ACCOUNT_DECL(acc);
    fd_runtime_fuzz_load_account( acc, funk, funk_txn, &test_ctx->acct_states[i], 1 );
  }

  /* Restore sysvar cache */
  fd_runtime_sysvar_cache_load( slot_ctx, runner->spad );

  /* Finish init epoch bank sysvars */
  uchar * val_epoch_schedule = fd_wksp_laddr_fast( runner->wksp, slot_ctx->sysvar_cache->gaddr_epoch_schedule );
  fd_memcpy( &epoch_bank->epoch_schedule, val_epoch_schedule, sizeof(fd_epoch_schedule_t) );
  fd_memcpy( &epoch_bank->rent_epoch_schedule, val_epoch_schedule, sizeof(fd_epoch_schedule_t) );
  uchar * val_rent = fd_wksp_laddr_fast( runner->wksp, slot_ctx->sysvar_cache->gaddr_rent );
  fd_memcpy( &epoch_bank->rent, val_rent, sizeof(fd_rent_t) );
  epoch_bank->stakes.epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot_bank->prev_slot, NULL );

  /* Update stake cache for epoch T */
  for( uint i=0U; i<test_ctx->epoch_ctx.stake_accounts_count; i++ ) {
    fd_pubkey_t voter_pubkey;
    fd_memcpy( &voter_pubkey, test_ctx->epoch_ctx.stake_accounts[i].voter_pubkey, sizeof(fd_pubkey_t) );

    fd_pubkey_t stake_account;
    fd_memcpy( &stake_account, test_ctx->epoch_ctx.stake_accounts[i].stake_account_pubkey, sizeof(fd_pubkey_t) );

    ulong  stake                = test_ctx->epoch_ctx.stake_accounts[i].stake;
    ulong  activation_epoch     = test_ctx->epoch_ctx.stake_accounts[i].activation_epoch;
    ulong  deactivation_epoch   = test_ctx->epoch_ctx.stake_accounts[i].deactivation_epoch;
    double warmup_cooldown_rate = test_ctx->epoch_ctx.stake_accounts[i].warmup_cooldown_rate;

    fd_delegation_pair_t_mapnode_t * stake_node = fd_delegation_pair_t_map_acquire( epoch_bank->stakes.stake_delegations_pool );
    fd_memcpy( &stake_node->elem.account, &stake_account, sizeof(fd_pubkey_t) );
    fd_memcpy( &stake_node->elem.delegation.voter_pubkey, &voter_pubkey, sizeof(fd_pubkey_t) );
    stake_node->elem.delegation.stake                = stake;
    stake_node->elem.delegation.activation_epoch     = activation_epoch;
    stake_node->elem.delegation.deactivation_epoch   = deactivation_epoch;
    stake_node->elem.delegation.warmup_cooldown_rate = warmup_cooldown_rate;

    fd_delegation_pair_t_map_insert( epoch_bank->stakes.stake_delegations_pool,
                                     &epoch_bank->stakes.stake_delegations_root,
                                     stake_node );
  }

  /* Update vote cache for epoch T */
  fd_runtime_fuzz_block_update_votes_cache( slot_ctx,
                                            epoch_bank->stakes.vote_accounts.vote_accounts_pool,
                                            &epoch_bank->stakes.vote_accounts.vote_accounts_root,
                                            test_ctx->epoch_ctx.vote_accounts_t,
                                            test_ctx->epoch_ctx.vote_accounts_t_count,
                                            runner->spad,
                                            1 );

  /* Update vote cache for epoch T-1 */
  fd_runtime_fuzz_block_update_votes_cache( slot_ctx,
                                            epoch_bank->next_epoch_stakes.vote_accounts_pool,
                                            &epoch_bank->next_epoch_stakes.vote_accounts_root,
                                            test_ctx->epoch_ctx.vote_accounts_t_1,
                                            test_ctx->epoch_ctx.vote_accounts_t_1_count,
                                            runner->spad,
                                            0 );

  /* Update vote cache for epoch T-2 */
  pool_mem                                   = fd_spad_alloc( runner->spad,
                                                              fd_vote_accounts_pair_t_map_align(),
                                                              fd_vote_accounts_pair_t_map_footprint( vote_acct_max ) );
  slot_bank->epoch_stakes.vote_accounts_pool = fd_vote_accounts_pair_t_map_join( fd_vote_accounts_pair_t_map_new( pool_mem, vote_acct_max ) );
  slot_bank->epoch_stakes.vote_accounts_root = NULL;
  fd_runtime_fuzz_block_update_votes_cache( slot_ctx,
                                            slot_bank->epoch_stakes.vote_accounts_pool,
                                            &slot_bank->epoch_stakes.vote_accounts_root,
                                            test_ctx->epoch_ctx.vote_accounts_t_2,
                                            test_ctx->epoch_ctx.vote_accounts_t_2_count,
                                            runner->spad,
                                            0 );

  /* Initialize the current running epoch stake and vote accounts */
  pool_mem                                        = fd_spad_alloc( runner->spad,
                                                                   fd_account_keys_pair_t_map_align(),
                                                                   fd_account_keys_pair_t_map_footprint( vote_acct_max ) );
  slot_bank->stake_account_keys.account_keys_pool = fd_account_keys_pair_t_map_join( fd_account_keys_pair_t_map_new( pool_mem, vote_acct_max ) );
  slot_bank->stake_account_keys.account_keys_root = NULL;
  for( uint i=0U; i<test_ctx->epoch_ctx.new_stake_accounts_count; i++ ) {
    FD_TXN_ACCOUNT_DECL( acc );

    fd_pubkey_t stake_pubkey;
    fd_memcpy( &stake_pubkey, test_ctx->epoch_ctx.new_stake_accounts[i]->bytes, sizeof(fd_pubkey_t) );

    // Fetch and store the stake account using acc mgr
    if( fd_txn_account_init_from_funk_readonly( acc, &stake_pubkey, slot_ctx->funk, slot_ctx->funk_txn ) ) {
      continue;
    }

    fd_store_stake_delegation( slot_ctx, acc );
  }

  pool_mem                                       = fd_spad_alloc( runner->spad,
                                                                  fd_account_keys_pair_t_map_align(),
                                                                  fd_account_keys_pair_t_map_footprint( vote_acct_max ) );
  slot_bank->vote_account_keys.account_keys_pool = fd_account_keys_pair_t_map_join( fd_account_keys_pair_t_map_new( pool_mem, vote_acct_max ) );
  slot_bank->vote_account_keys.account_keys_root = NULL;
  for( uint i=0U; i<test_ctx->epoch_ctx.new_vote_accounts_count; i++ ) {
    FD_TXN_ACCOUNT_DECL( acc );

    fd_pubkey_t vote_pubkey;
    memcpy( &vote_pubkey, test_ctx->epoch_ctx.new_vote_accounts[i]->bytes, sizeof(fd_pubkey_t) );

    // Fetch and store the vote account from the acc mgr
    if( fd_txn_account_init_from_funk_readonly( acc, &vote_pubkey, slot_ctx->funk, slot_ctx->funk_txn ) ) {
      continue;
    }

    fd_vote_store_account( slot_ctx, acc );
  }

  /* Update leader schedule */
  fd_runtime_update_leaders( slot_ctx, slot_ctx->slot_bank.slot, runner->spad );

  /* Initialize the blockhash queue and recent blockhashes sysvar from the input blockhash queue */
  slot_bank->block_hash_queue.max_age   = FD_BLOCKHASH_QUEUE_MAX_ENTRIES; // Max age is fixed at 300
  slot_bank->block_hash_queue.ages_root = NULL;
  pool_mem = fd_spad_alloc( runner->spad, fd_hash_hash_age_pair_t_map_align(), fd_hash_hash_age_pair_t_map_footprint( FD_BLOCKHASH_QUEUE_MAX_ENTRIES+1UL ) );
  slot_bank->block_hash_queue.ages_pool = fd_hash_hash_age_pair_t_map_join( fd_hash_hash_age_pair_t_map_new( pool_mem, FD_BLOCKHASH_QUEUE_MAX_ENTRIES+1UL ) );
  slot_bank->block_hash_queue.last_hash = fd_valloc_malloc( fd_spad_virtual( runner->spad ), FD_HASH_ALIGN, FD_HASH_FOOTPRINT );

  /* TODO: We might need to load this in from the input. We also need to size this out for worst case, but this also blows up the memory requirement. */
  /* Allocate all the memory for the rent fresh accounts list */
  fd_rent_fresh_accounts_new( &slot_bank->rent_fresh_accounts );
  slot_bank->rent_fresh_accounts.total_count        = 0UL;
  slot_bank->rent_fresh_accounts.fresh_accounts_len = FD_RENT_FRESH_ACCOUNTS_MAX;
  slot_bank->rent_fresh_accounts.fresh_accounts     = fd_spad_alloc(
    runner->spad,
    alignof(fd_rent_fresh_account_t),
    sizeof(fd_rent_fresh_account_t) * FD_RENT_FRESH_ACCOUNTS_MAX );
  fd_memset(  slot_bank->rent_fresh_accounts.fresh_accounts, 0, sizeof(fd_rent_fresh_account_t) * FD_RENT_FRESH_ACCOUNTS_MAX );

  // Set genesis hash to {0}
  fd_memset( &epoch_bank->genesis_hash, 0, sizeof(fd_hash_t) );
  fd_memset( slot_bank->block_hash_queue.last_hash, 0, sizeof(fd_hash_t) );

  // Use the latest lamports per signature
  fd_recent_block_hashes_global_t const * rbh_global = fd_sysvar_cache_recent_block_hashes( slot_ctx->sysvar_cache, runner->wksp );
  fd_recent_block_hashes_t rbh[1];
  if( rbh_global ) {
    rbh->hashes = deq_fd_block_block_hash_entry_t_join( (uchar*)rbh_global + rbh_global->hashes_offset );
  }

  if( rbh_global && !deq_fd_block_block_hash_entry_t_empty( rbh->hashes ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_head_const( rbh->hashes );
    if( last && last->fee_calculator.lamports_per_signature!=0UL ) {
      slot_bank->lamports_per_signature     = last->fee_calculator.lamports_per_signature;
      slot_ctx->prev_lamports_per_signature = last->fee_calculator.lamports_per_signature;
    }
  }

  // Populate blockhash queue and recent blockhashes sysvar
  for( ushort i=0; i<test_ctx->blockhash_queue_count; ++i ) {
    fd_block_block_hash_entry_t blockhash_entry;
    memcpy( &blockhash_entry.blockhash, test_ctx->blockhash_queue[i]->bytes, sizeof(fd_hash_t) );
    slot_bank->poh = blockhash_entry.blockhash;
    fd_sysvar_recent_hashes_update( slot_ctx, runner->spad );
  }

  // Set the current poh from the input (we skip POH verification in this fuzzing target)
  fd_memcpy( slot_ctx->slot_bank.poh.uc, test_ctx->slot_ctx.poh, FD_HASH_FOOTPRINT );

  /* Make a new funk transaction since we're done loading in accounts for context */
  fd_funk_txn_xid_t fork_xid[1] = {0};
  fork_xid[0] = fd_funk_generate_xid();
  fd_funk_txn_start_write( funk );
  slot_ctx->funk_txn = fd_funk_txn_prepare( funk, slot_ctx->funk_txn, fork_xid, 1 );
  fd_funk_txn_end_write( funk );

  /* Calculate epoch account hash values. This sets epoch_bank.eah_{start_slot, stop_slot, interval} */
  fd_calculate_epoch_accounts_hash_values( slot_ctx );

  /* Prepare raw transaction pointers and block / microblock infos */
  ulong microblock_cnt = test_ctx->microblocks_count;

  // For fuzzing, we're using a single microblock batch that contains all microblocks
  fd_runtime_block_info_t *    block_info       = fd_spad_alloc( runner->spad, alignof(fd_runtime_block_info_t), sizeof(fd_runtime_block_info_t) );
  fd_microblock_batch_info_t * batch_info       = fd_spad_alloc( runner->spad, alignof(fd_microblock_batch_info_t), sizeof(fd_microblock_batch_info_t) );
  fd_microblock_info_t *       microblock_infos = fd_spad_alloc( runner->spad, alignof(fd_microblock_info_t), microblock_cnt * sizeof(fd_microblock_info_t) );
  fd_memset( block_info, 0, sizeof(fd_runtime_block_info_t) );
  fd_memset( batch_info, 0, sizeof(fd_microblock_batch_info_t) );
  fd_memset( microblock_infos, 0, microblock_cnt * sizeof(fd_microblock_info_t) );

  block_info->microblock_batch_cnt   = 1UL;
  block_info->microblock_cnt         = microblock_cnt;
  block_info->microblock_batch_infos = batch_info;

  batch_info->microblock_cnt         = microblock_cnt;
  batch_info->microblock_infos       = microblock_infos;

  ulong batch_signature_cnt          = 0UL;
  ulong batch_txn_cnt                = 0UL;
  ulong batch_account_cnt            = 0UL;

  for( ulong i=0UL; i<microblock_cnt; i++ ) {
    fd_exec_test_microblock_t const * input_microblock = &test_ctx->microblocks[i];
    fd_microblock_info_t *            microblock_info  = &microblock_infos[i];
    fd_microblock_hdr_t *             microblock_hdr   = fd_spad_alloc( runner->spad, alignof(fd_microblock_hdr_t), sizeof(fd_microblock_hdr_t) );
    fd_memset( microblock_hdr, 0, sizeof(fd_microblock_hdr_t) );

    ulong txn_cnt       = input_microblock->txns_count;
    ulong signature_cnt = 0UL;
    ulong account_cnt   = 0UL;

    fd_txn_p_t * txn_ptrs = fd_spad_alloc( runner->spad, alignof(fd_txn_p_t), txn_cnt * sizeof(fd_txn_p_t) );

    for( ulong j=0UL; j<txn_cnt; j++ ) {
      fd_txn_p_t * txn = &txn_ptrs[j];

      ushort _instr_count, _addr_table_cnt;
      ulong msg_sz = fd_runtime_fuzz_serialize_txn( txn->payload, &input_microblock->txns[j], &_instr_count, &_addr_table_cnt );

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
  }

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

  /* Initialize tpool and spad(s) */
  ulong        worker_max = FD_BLOCK_HARNESS_TPOOL_WORKER_CNT;
  void *       tpool_mem  = fd_spad_alloc( runner->spad, FD_TPOOL_ALIGN, FD_TPOOL_FOOTPRINT( worker_max ) );
  fd_tpool_t * tpool      = fd_tpool_init( tpool_mem, worker_max, 0UL );
  fd_tpool_worker_push( tpool, 1UL );

  fd_spad_t * runtime_spad = runner->spad;

  /* Format chunks of memory for the exec spads
     TODO: This memory needs a better bound. */
  fd_spad_t * exec_spads[FD_BLOCK_HARNESS_TPOOL_WORKER_CNT] = { 0 };
  ulong       exec_spads_cnt                                = FD_BLOCK_HARNESS_TPOOL_WORKER_CNT;
  for( ulong i=0UL; i<worker_max; i++ ) {
    void *      exec_spad_mem = fd_spad_alloc( runtime_spad, FD_SPAD_ALIGN, FD_SPAD_FOOTPRINT( FD_BLOCK_HARNESS_MEM_PER_SPAD ) );
    fd_spad_t * exec_spad     = fd_spad_join( fd_spad_new( exec_spad_mem, FD_BLOCK_HARNESS_MEM_PER_SPAD ) );
    exec_spads[i] = exec_spad;
  }

  // Prepare. Execute. Finalize.
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {
    fd_rewards_recalculate_partitioned_rewards( slot_ctx, tpool, exec_spads, exec_spads_cnt, runtime_spad );

    /* Process new epoch may push a new spad frame onto the runtime spad. We should make sure this frame gets
       cleared (if it was allocated) before executing the block. */
    ulong spad_frame_ct     = fd_spad_frame_used( runtime_spad );
    int   is_epoch_boundary = 0;
    fd_runtime_block_pre_execute_process_new_epoch( slot_ctx, tpool, exec_spads, exec_spads_cnt, runtime_spad, &is_epoch_boundary );
    while( fd_spad_frame_used( runtime_spad )>spad_frame_ct ) {
      fd_spad_pop( runtime_spad );
    }

    res = fd_runtime_block_execute_tpool( slot_ctx, NULL, block_info, tpool, exec_spads, exec_spads_cnt, runtime_spad );
  } FD_SPAD_FRAME_END;

  fd_tpool_worker_pop( tpool );

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
    fd_alloc_t *          alloc         = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 2 ), 2 ), 0 );
    uchar *               slot_ctx_mem  = fd_spad_alloc( runner->spad, FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT );
    fd_exec_slot_ctx_t *  slot_ctx      = fd_exec_slot_ctx_join ( fd_exec_slot_ctx_new ( slot_ctx_mem, runner->spad ) );

    /* Set up the block execution context */
    fd_runtime_block_info_t * block_info = fd_runtime_fuzz_block_ctx_create( runner, slot_ctx, input );
    if( block_info==NULL ) {
      fd_runtime_fuzz_block_ctx_destroy( runner, slot_ctx, wksp, alloc );
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
    effects->slot_capitalization = slot_ctx->slot_bank.capitalization;

    /* Capture hashes */
    uchar out_lt_hash[32];
    fd_lthash_hash( (fd_lthash_value_t const *)slot_ctx->slot_bank.lthash.lthash, out_lt_hash );
    fd_memcpy( effects->bank_hash, slot_ctx->slot_bank.banks_hash.hash, sizeof(fd_hash_t) );
    fd_memcpy( effects->lt_hash, out_lt_hash, sizeof(fd_hash_t) );
    fd_memcpy( effects->account_delta_hash, slot_ctx->account_delta_hash.hash, sizeof(fd_hash_t) );

    /* Capture accounts. Since the only input accounts list comes from the input transactions, we have to iterate through
       all input transactions, gather the account keys in order, and skip any duplicate accounts. */
    // TODO: implement me

    ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
    fd_runtime_fuzz_block_ctx_destroy( runner, slot_ctx, wksp, alloc );

    *output = effects;
    return actual_end - (ulong)output_buf;
  } FD_SPAD_FRAME_END;
}
