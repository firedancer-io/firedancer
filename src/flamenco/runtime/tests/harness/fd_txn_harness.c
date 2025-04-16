#include "fd_txn_harness.h"
#include "fd_harness_common.h"

static void
fd_runtime_fuzz_txn_ctx_destroy( fd_runtime_fuzz_runner_t * runner,
                                 fd_exec_slot_ctx_t *       slot_ctx ) {
  if( !slot_ctx ) return; // This shouldn't be false either
  fd_funk_txn_t *       funk_txn  = slot_ctx->funk_txn;

  fd_funk_txn_cancel( runner->funk, funk_txn, 1 );
}

/* Creates transaction execution context for a single test case. Returns a
   a parsed txn descriptor on success and NULL on failure. */
static fd_txn_p_t *
fd_runtime_fuzz_txn_ctx_create( fd_runtime_fuzz_runner_t *         runner,
                                fd_exec_slot_ctx_t *               slot_ctx,
                                fd_exec_test_txn_context_t const * test_ctx ) {
  const uchar empty_bytes[64] = { 0 };
  fd_funk_t * funk = runner->funk;

  /* Generate unique ID for funk txn */

  fd_funk_txn_xid_t xid[1] = {0};
  xid[0] = fd_funk_generate_xid();

  /* Create temporary funk transaction and spad contexts */

  fd_funk_txn_start_write( funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 1 );
  fd_funk_txn_end_write( funk );

  ulong vote_acct_max = MAX_TX_ACCOUNT_LOCKS;

  /* Allocate contexts */
  uchar *               epoch_ctx_mem = fd_spad_alloc( runner->spad, fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( vote_acct_max ) );
  fd_exec_epoch_ctx_t * epoch_ctx     = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, vote_acct_max ) );

  assert( epoch_ctx );
  assert( slot_ctx  );

  /* Set up epoch context */
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );

  /* Set up slot context */

  slot_ctx->epoch_ctx = epoch_ctx;
  slot_ctx->funk_txn  = funk_txn;
  slot_ctx->funk      = funk;

  /* Restore feature flags */

  fd_exec_test_feature_set_t const * feature_set = &test_ctx->epoch_ctx.features;
  if( !fd_runtime_fuzz_restore_features( epoch_ctx, feature_set ) ) {
    return NULL;
  }

  /* Restore slot bank */
  fd_slot_bank_new( &slot_ctx->slot_bank );

  /* Initialize builtin accounts */
  fd_builtin_programs_init( slot_ctx );

  /* Load account states into funk (note this is different from the account keys):
    Account state = accounts to populate Funk
    Account keys = account keys that the transaction needs */
  for( ulong i = 0; i < test_ctx->account_shared_data_count; i++ ) {
    /* Load the accounts into the account manager
       Borrowed accounts get reset anyways - we just need to load the account somewhere */
    FD_TXN_ACCOUNT_DECL( acc );
    fd_runtime_fuzz_load_account( acc, funk, funk_txn, &test_ctx->account_shared_data[i], 1 );
  }

  /* Restore sysvar cache */
  fd_sysvar_cache_restore( slot_ctx->sysvar_cache, funk, funk_txn, runner->spad, fd_wksp_containing( slot_ctx ) );

  /* Add accounts to bpf program cache */
  fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, funk_txn, runner->spad );

  /* Default slot */
  ulong slot = test_ctx->slot_ctx.slot ? test_ctx->slot_ctx.slot : 10; // Arbitrary default > 0

  /* Set slot bank variables (defaults obtained from GenesisConfig::default() in Agave) */
  slot_ctx->slot_bank.slot                                            = slot;
  slot_ctx->slot_bank.prev_slot                                       = slot_ctx->slot_bank.slot - 1; // Can underflow, but its fine since it will correctly be ULONG_MAX
  slot_ctx->slot_bank.fee_rate_governor.burn_percent                  = 50;
  slot_ctx->slot_bank.fee_rate_governor.min_lamports_per_signature    = 0;
  slot_ctx->slot_bank.fee_rate_governor.max_lamports_per_signature    = 0;
  slot_ctx->slot_bank.fee_rate_governor.target_lamports_per_signature = 10000;
  slot_ctx->slot_bank.fee_rate_governor.target_signatures_per_slot    = 20000;
  slot_ctx->slot_bank.lamports_per_signature                          = 5000;
  slot_ctx->prev_lamports_per_signature                               = 5000;

  /* Set epoch bank variables if not present (defaults obtained from GenesisConfig::default() in Agave) */
  fd_epoch_schedule_t default_epoch_schedule = {
                                                .slots_per_epoch             = 432000,
                                                .leader_schedule_slot_offset = 432000,
                                                .warmup                      = 1,
                                                .first_normal_epoch          = 14,
                                                .first_normal_slot           = 524256
                                               };
  fd_rent_t           default_rent           = {
                                                .lamports_per_uint8_year     = 3480,
                                                .exemption_threshold         = 2.0,
                                                .burn_percent                = 50
                                               };
  epoch_bank->epoch_schedule      = default_epoch_schedule;
  epoch_bank->rent_epoch_schedule = default_epoch_schedule;
  epoch_bank->rent                = default_rent;
  epoch_bank->ticks_per_slot      = 64;
  epoch_bank->slots_per_year      = SECONDS_PER_YEAR * (1000000000.0 / (double)6250000) / (double)epoch_bank->ticks_per_slot;

  // Override default values if provided
  if( slot_ctx->sysvar_cache->has_epoch_schedule ) {
    epoch_bank->epoch_schedule      = *(fd_epoch_schedule_t *)fd_type_pun_const( slot_ctx->sysvar_cache->val_epoch_schedule );
    epoch_bank->rent_epoch_schedule = *(fd_epoch_schedule_t *)fd_type_pun_const( slot_ctx->sysvar_cache->val_epoch_schedule );
  }

  if( slot_ctx->sysvar_cache->has_rent ) {
    epoch_bank->rent = *(fd_rent_t *)fd_type_pun_const( slot_ctx->sysvar_cache->val_rent );
  }

  /* Provide default slot hashes of size 1 if not provided */
  if( !slot_ctx->sysvar_cache->has_slot_hashes ) {
    uchar * deque_mem = fd_spad_alloc( runner->spad, deq_fd_slot_hash_t_align(), deq_fd_slot_hash_t_footprint( 1 ) );
    fd_slot_hash_t * slot_hashes = deq_fd_slot_hash_t_join( deq_fd_slot_hash_t_new( deque_mem, 1 ) );
    fd_slot_hash_t * dummy_elem = deq_fd_slot_hash_t_push_tail_nocopy( slot_hashes );
    memset( dummy_elem, 0, sizeof(fd_slot_hash_t) );
    fd_slot_hashes_t default_slot_hashes = { .hashes = slot_hashes };
    fd_sysvar_slot_hashes_init( slot_ctx, &default_slot_hashes );
  }

  /* Provide default stake history if not provided */
  if( !slot_ctx->sysvar_cache->has_stake_history ) {
    // Provide a 0-set default entry
    fd_stake_history_entry_t entry = {0};
    fd_sysvar_stake_history_init( slot_ctx );
    fd_sysvar_stake_history_update( slot_ctx, &entry, runner->spad );
  }

  /* Provide default last restart slot sysvar if not provided */
  if( !slot_ctx->sysvar_cache->has_last_restart_slot ) {
    fd_sysvar_last_restart_slot_init( slot_ctx );
  }

  /* Provide a default clock if not present */
  if( !slot_ctx->sysvar_cache->has_clock ) {
    fd_sysvar_clock_init( slot_ctx );
    fd_sysvar_clock_update( slot_ctx, runner->spad );
  }

  /* Epoch schedule and rent get set from the epoch bank */
  fd_sysvar_epoch_schedule_init( slot_ctx );
  fd_sysvar_rent_init( slot_ctx );

  /* Set the epoch rewards sysvar if partition epoch rewards feature is enabled

     TODO: The init parameters are not exactly conformant with Agave's epoch rewards sysvar. We should
     be calling `fd_begin_partitioned_rewards` with the same parameters as Agave. However,
     we just need the `active` field to be conformant due to a single Stake program check.
     THIS MAY CHANGE IN THE FUTURE. If there are other parts of transaction execution that use
     the epoch rewards sysvar, we may need to update this.
  */
  if( (FD_FEATURE_ACTIVE( slot_ctx->slot_bank.slot, slot_ctx->epoch_ctx->features, enable_partitioned_epoch_reward ) ||
       FD_FEATURE_ACTIVE( slot_ctx->slot_bank.slot, slot_ctx->epoch_ctx->features, partitioned_epoch_rewards_superfeature ))
      && !slot_ctx->sysvar_cache->has_epoch_rewards ) {
    fd_point_value_t point_value = {0};
    fd_hash_t const * last_hash = test_ctx->blockhash_queue_count > 0 ? (fd_hash_t const *)test_ctx->blockhash_queue[0]->bytes : (fd_hash_t const *)empty_bytes;
    fd_sysvar_epoch_rewards_init( slot_ctx, 0UL, 0UL, 2UL, 1UL, point_value, last_hash);
  }

  /* Restore sysvar cache (again, since we may need to provide default sysvars) */
  fd_sysvar_cache_restore( slot_ctx->sysvar_cache, funk, funk_txn, runner->spad, fd_wksp_containing( slot_ctx ) );

  /* A NaN rent exemption threshold is U.B. in Solana Labs */
  fd_rent_t const * rent = fd_sysvar_cache_rent( slot_ctx->sysvar_cache );
  if( ( rent->exemption_threshold != 0.0 &&
        !fd_dblbits_is_normal( fd_dblbits( rent->exemption_threshold ) ) ) |
      ( rent->exemption_threshold     <      0.0 ) |
      ( rent->exemption_threshold     >    999.0 ) |
      ( rent->lamports_per_uint8_year > UINT_MAX ) |
      ( rent->burn_percent            >      100 ) ) {
    return NULL;
  }

  /* Blockhash queue is given in txn message. We need to populate the following two fields:
     - slot_ctx->slot_bank.block_hash_queue
     - slot_ctx->slot_bank.recent_block_hashes */
  ulong num_blockhashes = test_ctx->blockhash_queue_count;

  /* Blockhash queue init */
  slot_ctx->slot_bank.block_hash_queue.max_age   = FD_BLOCKHASH_QUEUE_MAX_ENTRIES;
  slot_ctx->slot_bank.block_hash_queue.ages_root = NULL;
  uchar * pool_mem = fd_spad_alloc( runner->spad, fd_hash_hash_age_pair_t_map_align(), fd_hash_hash_age_pair_t_map_footprint( 400 ) );
  slot_ctx->slot_bank.block_hash_queue.ages_pool = fd_hash_hash_age_pair_t_map_join( fd_hash_hash_age_pair_t_map_new( pool_mem, 400 ) );
  slot_ctx->slot_bank.block_hash_queue.last_hash = fd_spad_alloc( runner->spad, FD_HASH_ALIGN, FD_HASH_FOOTPRINT );

  // Save lamports per signature for most recent blockhash, if sysvar cache contains recent block hashes
  fd_recent_block_hashes_global_t const * rbh_global = fd_sysvar_cache_recent_block_hashes( slot_ctx->sysvar_cache );
  fd_recent_block_hashes_t rbh[1];
  if( rbh_global ) {
    rbh->hashes = deq_fd_block_block_hash_entry_t_join( fd_wksp_laddr_fast( fd_wksp_containing( runner->spad ), rbh_global->hashes_gaddr ) );
  }

  if( rbh_global && !deq_fd_block_block_hash_entry_t_empty( rbh->hashes ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_head_const( rbh->hashes );
    if( last && last->fee_calculator.lamports_per_signature!=0UL ) {
      slot_ctx->slot_bank.lamports_per_signature = last->fee_calculator.lamports_per_signature;
      slot_ctx->prev_lamports_per_signature      = last->fee_calculator.lamports_per_signature;
    }
  }

  // Blockhash_queue[end] = last (latest) hash
  // Blockhash_queue[0] = genesis hash
  if( num_blockhashes > 0 ) {
    memcpy( &epoch_bank->genesis_hash, test_ctx->blockhash_queue[0]->bytes, sizeof(fd_hash_t) );

    for( ulong i = 0; i < num_blockhashes; ++i ) {
      // Recent block hashes cap is 150 (actually 151), while blockhash queue capacity is 300 (actually 301)
      fd_block_block_hash_entry_t blockhash_entry;
      memcpy( &blockhash_entry.blockhash, test_ctx->blockhash_queue[i]->bytes, sizeof(fd_hash_t) );
      slot_ctx->slot_bank.poh = blockhash_entry.blockhash;
      fd_sysvar_recent_hashes_update( slot_ctx, runner->spad );
    }
  } else {
    // Add a default empty blockhash and use it as genesis
    num_blockhashes = 1;
    memcpy( &epoch_bank->genesis_hash, empty_bytes, sizeof(fd_hash_t) );
    fd_block_block_hash_entry_t blockhash_entry;
    memcpy( &blockhash_entry.blockhash, empty_bytes, sizeof(fd_hash_t) );
    slot_ctx->slot_bank.poh = blockhash_entry.blockhash;
    fd_sysvar_recent_hashes_update( slot_ctx, runner->spad );
  }
  fd_sysvar_cache_restore_recent_block_hashes( slot_ctx->sysvar_cache, funk, funk_txn, runner->spad, fd_wksp_containing( slot_ctx ) );

  /* Create the raw txn (https://solana.com/docs/core/transactions#transaction-size) */
  uchar * txn_raw_begin = fd_spad_alloc( runner->spad, alignof(uchar), 1232 );
  ushort instr_count, addr_table_cnt;
  ulong msg_sz = fd_runtime_fuzz_serialize_txn( txn_raw_begin, &test_ctx->tx, &instr_count, &addr_table_cnt );
  if( FD_UNLIKELY( msg_sz==ULONG_MAX ) ) {
    return NULL;
  }

  /* Set up txn descriptor from raw data */
  fd_txn_t * txn_descriptor = (fd_txn_t *) fd_spad_alloc( runner->spad, fd_txn_align(), fd_txn_footprint( instr_count, addr_table_cnt ) );
  if( FD_UNLIKELY( !fd_txn_parse( txn_raw_begin, msg_sz, txn_descriptor, NULL ) ) ) {
    return NULL;
  }

  /* Run txn preparation phases and execution
     NOTE: This should be modified accordingly if transaction setup logic changes */
  fd_txn_p_t * txn = fd_spad_alloc( runner->spad, alignof(fd_txn_p_t), sizeof(fd_txn_p_t) );
  memcpy( txn->payload, txn_raw_begin, msg_sz );
  txn->payload_sz = msg_sz;
  txn->flags = FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
  memcpy( txn->_, txn_descriptor, fd_txn_footprint( instr_count, addr_table_cnt ) );

  return txn;
}

/* Takes in a parsed txn descriptor to be executed against the runtime.
   Returns the task info. */
static fd_execute_txn_task_info_t *
fd_runtime_fuzz_txn_ctx_exec( fd_runtime_fuzz_runner_t * runner,
                              fd_exec_slot_ctx_t *       slot_ctx,
                              fd_txn_p_t *               txn ) {
  fd_execute_txn_task_info_t * task_info = fd_spad_alloc( runner->spad, alignof(fd_execute_txn_task_info_t), sizeof(fd_execute_txn_task_info_t) );
  memset( task_info, 0, sizeof(fd_execute_txn_task_info_t) );
  task_info->txn     = txn;
  task_info->txn_ctx = fd_spad_alloc( runner->spad, FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );

  fd_tpool_t tpool[1];
  tpool->worker_cnt = 1;
  tpool->worker_max = 1;

  fd_runtime_prepare_txns_start( slot_ctx, task_info, txn, 1UL, runner->spad );

  /* Setup the spad for account allocation */
  task_info->txn_ctx->spad      = runner->spad;
  task_info->txn_ctx->spad_wksp = fd_wksp_containing( runner->spad );

  fd_runtime_pre_execute_check( task_info, 0 );

  if( task_info->txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) {
      task_info->txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
      task_info->exec_res    = fd_execute_txn( task_info );
  }

  slot_ctx->slot_bank.collected_execution_fees += task_info->txn_ctx->execution_fee;
  slot_ctx->slot_bank.collected_priority_fees  += task_info->txn_ctx->priority_fee;
  slot_ctx->slot_bank.collected_rent           += task_info->txn_ctx->collected_rent;
  return task_info;
}

ulong
fd_runtime_fuzz_serialize_txn( uchar *                                      txn_raw_begin,
                               fd_exec_test_sanitized_transaction_t const * tx,
                               ushort *                                     out_instr_cnt,
                               ushort *                                     out_addr_table_cnt ) {
  const uchar empty_bytes[64] = { 0 };
  uchar * txn_raw_cur_ptr = txn_raw_begin;

  /* Compact array of signatures (https://solana.com/docs/core/transactions#transaction)
     Note that although documentation interchangably refers to the signature cnt as a compact-u16
     and a u8, the max signature cnt is capped at 48 (due to txn size limits), so u8 and compact-u16
     is represented the same way anyways and can be parsed identically. */
  // Note: always create a valid txn with 1+ signatures, add an empty signature if none is provided
  uchar signature_cnt = fd_uchar_max( 1, (uchar) tx->signatures_count );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signature_cnt, sizeof(uchar) );
  for( uchar i = 0; i < signature_cnt; ++i ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, tx->signatures && tx->signatures[i] ? tx->signatures[i]->bytes : empty_bytes, FD_TXN_SIGNATURE_SZ );
  }

  /* Message */
  /* For v0 transactions, the highest bit of the num_required_signatures is set, and an extra byte is used for the version.
     https://solanacookbook.com/guides/versioned-transactions.html#versioned-transactions-transactionv0

     We will always create a transaction with at least 1 signature, and cap the signature count to 127 to avoid
     collisions with the header_b0 tag. */
  uchar num_required_signatures = fd_uchar_max( 1, fd_uchar_min( 127, (uchar) tx->message.header.num_required_signatures ) );
  if( !tx->message.is_legacy ) {
    uchar header_b0 = (uchar) 0x80UL;
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &header_b0, sizeof(uchar) );
  }

  /* Header (3 bytes) (https://solana.com/docs/core/transactions#message-header) */
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_required_signatures, sizeof(uchar) );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &tx->message.header.num_readonly_signed_accounts, sizeof(uchar) );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &tx->message.header.num_readonly_unsigned_accounts, sizeof(uchar) );

  /* Compact array of account addresses (https://solana.com/docs/core/transactions#compact-array-format) */
  // Array length is a compact u16
  ushort num_acct_keys = (ushort) tx->message.account_keys_count;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, num_acct_keys );
  for( ushort i = 0; i < num_acct_keys; ++i ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, tx->message.account_keys[i]->bytes, sizeof(fd_pubkey_t) );
  }

  /* Recent blockhash (32 bytes) (https://solana.com/docs/core/transactions#recent-blockhash) */
  // Note: add an empty blockhash if none is provided
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, tx->message.recent_blockhash ? tx->message.recent_blockhash->bytes : empty_bytes, sizeof(fd_hash_t) );

  /* Compact array of instructions (https://solana.com/docs/core/transactions#array-of-instructions) */
  // Instruction count is a compact u16
  ushort instr_count = (ushort) tx->message.instructions_count;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instr_count );
  for( ushort i = 0; i < instr_count; ++i ) {
    // Program ID index
    uchar program_id_index = (uchar) tx->message.instructions[i].program_id_index;
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &program_id_index, sizeof(uchar) );

    // Compact array of account addresses
    ushort acct_count = (ushort) tx->message.instructions[i].accounts_count;
    FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, acct_count );
    for( ushort j = 0; j < acct_count; ++j ) {
      uchar account_index = (uchar) tx->message.instructions[i].accounts[j];
      FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &account_index, sizeof(uchar) );
    }

    // Compact array of 8-bit data
    pb_bytes_array_t * data = tx->message.instructions[i].data;
    ushort data_len;
    if( data ) {
      data_len = (ushort) data->size;
      FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, data_len );
      FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, data->bytes, data_len );
    } else {
      data_len = 0;
      FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, data_len );
    }
  }

  /* Address table lookups (N/A for legacy transactions) */
  ushort addr_table_cnt = 0;
  if( !tx->message.is_legacy ) {
    /* Compact array of address table lookups (https://solanacookbook.com/guides/versioned-transactions.html#compact-array-of-address-table-lookups) */
    // NOTE: The diagram is slightly wrong - the account key is a 32 byte pubkey, not a u8
    addr_table_cnt = (ushort) tx->message.address_table_lookups_count;
    FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, addr_table_cnt );
    for( ushort i = 0; i < addr_table_cnt; ++i ) {
      // Account key
      FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, tx->message.address_table_lookups[i].account_key, sizeof(fd_pubkey_t) );

      // Compact array of writable indexes
      ushort writable_count = (ushort) tx->message.address_table_lookups[i].writable_indexes_count;
      FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, writable_count );
      for( ushort j = 0; j < writable_count; ++j ) {
        uchar writable_index = (uchar) tx->message.address_table_lookups[i].writable_indexes[j];
        FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &writable_index, sizeof(uchar) );
      }

      // Compact array of readonly indexes
      ushort readonly_count = (ushort) tx->message.address_table_lookups[i].readonly_indexes_count;
      FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, readonly_count );
      for( ushort j = 0; j < readonly_count; ++j ) {
        uchar readonly_index = (uchar) tx->message.address_table_lookups[i].readonly_indexes[j];
        FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &readonly_index, sizeof(uchar) );
      }
    }
  }

  *out_instr_cnt = instr_count;
  *out_addr_table_cnt = addr_table_cnt;
  return (ulong)(txn_raw_cur_ptr - txn_raw_begin);
}

ulong
fd_runtime_fuzz_txn_run( fd_runtime_fuzz_runner_t * runner,
                         void const *               input_,
                         void **                    output_,
                         void *                     output_buf,
                         ulong                      output_bufsz ) {
  fd_exec_test_txn_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_txn_result_t **       output = fd_type_pun( output_ );

  FD_SPAD_FRAME_BEGIN( runner->spad ) {

    /* Initialize memory */
    uchar *               slot_ctx_mem = fd_spad_alloc( runner->spad, FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT  );
    fd_exec_slot_ctx_t *  slot_ctx     = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem, runner->spad ) );

    /* Setup the transaction context */
    fd_txn_p_t * txn = fd_runtime_fuzz_txn_ctx_create( runner, slot_ctx, input );
    if( txn==NULL ) {
      fd_runtime_fuzz_txn_ctx_destroy( runner, slot_ctx );
      return 0;
    }

    /* Execute the transaction against the runtime */
    fd_execute_txn_task_info_t * task_info = fd_runtime_fuzz_txn_ctx_exec( runner, slot_ctx, txn );
    fd_exec_txn_ctx_t *          txn_ctx   = task_info->txn_ctx;

    int exec_res = task_info->exec_res;

    /* Start saving txn exec results */
    FD_SCRATCH_ALLOC_INIT( l, output_buf );
    ulong output_end = (ulong)output_buf + output_bufsz;

    fd_exec_test_txn_result_t * txn_result =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_txn_result_t),
                                  sizeof (fd_exec_test_txn_result_t) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      abort();
    }
    fd_memset( txn_result, 0, sizeof(fd_exec_test_txn_result_t) );

    /* Capture basic results fields */
    txn_result->executed                          = task_info->txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
    txn_result->sanitization_error                = !( task_info->txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS );
    txn_result->has_resulting_state               = false;
    txn_result->resulting_state.acct_states_count = 0;
    txn_result->is_ok                             = !exec_res;
    txn_result->status                            = (uint32_t) -exec_res;
    txn_result->instruction_error                 = 0;
    txn_result->instruction_error_index           = 0;
    txn_result->custom_error                      = 0;
    txn_result->executed_units                    = txn_ctx->compute_unit_limit - txn_ctx->compute_meter;
    txn_result->has_fee_details                   = false;

    if( txn_result->sanitization_error ) {
      if( exec_res==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR ) {
      /* If exec_res was an instruction error and we have a sanitization error, it was a precompile error */
        txn_result->instruction_error       = (uint32_t) -txn_ctx->exec_err;
        txn_result->instruction_error_index = (uint32_t) txn_ctx->instr_err_idx;

        /*
        TODO: precompile error codes are not conformant, so we're ignoring custom error codes for them for now. This should be revisited in the future.
        For now, only precompiles throw custom error codes, so we can ignore all custom error codes thrown in the sanitization phase. If this changes,
        this logic will have to be revisited.

        if( task_info->txn_ctx->exec_err == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
          txn_result->custom_error = txn_ctx->custom_err;
        }
        */
      }

      ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
      fd_runtime_fuzz_txn_ctx_destroy( runner, slot_ctx );

      *output = txn_result;
      return actual_end - (ulong)output_buf;

    } else {
      /* Capture the instruction error code */
      if( exec_res==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR ) {
        int instr_err_idx                   = txn_ctx->instr_err_idx;
        int program_id_idx                  = txn_ctx->instr_infos[instr_err_idx].program_id;

        txn_result->instruction_error       = (uint32_t) -txn_ctx->exec_err;
        txn_result->instruction_error_index = (uint32_t) instr_err_idx;

        /* If the exec err was a custom instr error and came from a precompile instruction, don't capture the custom error code. */
        if( txn_ctx->exec_err==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR &&
            fd_executor_lookup_native_precompile_program( &txn_ctx->accounts[ program_id_idx ] )==NULL ) {
          txn_result->custom_error = txn_ctx->custom_err;
        }
      }
    }

    txn_result->has_fee_details                = true;
    txn_result->fee_details.transaction_fee    = slot_ctx->slot_bank.collected_execution_fees;
    txn_result->fee_details.prioritization_fee = slot_ctx->slot_bank.collected_priority_fees;

    /* Rent is only collected on successfully loaded transactions */
    txn_result->rent                           = txn_ctx->collected_rent;

    if( txn_ctx->return_data.len > 0 ) {
      txn_result->return_data = FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                      PB_BYTES_ARRAY_T_ALLOCSIZE( txn_ctx->return_data.len ) );
      if( FD_UNLIKELY( _l > output_end ) ) {
        abort();
      }

      txn_result->return_data->size = (pb_size_t)txn_ctx->return_data.len;
      fd_memcpy( txn_result->return_data->bytes, txn_ctx->return_data.data, txn_ctx->return_data.len );
    }

    /* Allocate space for captured accounts */
    ulong modified_acct_cnt = txn_ctx->accounts_cnt;

    txn_result->has_resulting_state         = true;
    txn_result->resulting_state.acct_states =
      FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_acct_state_t),
                                  sizeof (fd_exec_test_acct_state_t) * modified_acct_cnt );
    if( FD_UNLIKELY( _l > output_end ) ) {
      abort();
    }

    /* Capture borrowed accounts */
    for( ushort j=0; j < txn_ctx->accounts_cnt; j++ ) {
      fd_txn_account_t * acc = &txn_ctx->accounts[j];

      /* For fees-only transactions, only save the fee payer (and potentially the nonce) only */
      if( task_info->txn->flags & FD_TXN_P_FLAGS_FEES_ONLY ) {
        if( j!=FD_FEE_PAYER_TXN_IDX && j!=task_info->txn_ctx->nonce_account_idx_in_txn ) {
          continue;
        }
      }

      if( !( fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, j ) || j==FD_FEE_PAYER_TXN_IDX ) ) continue;
      assert( acc->vt->is_mutable( acc ) );

      ulong modified_idx = txn_result->resulting_state.acct_states_count;
      assert( modified_idx < modified_acct_cnt );

      fd_exec_test_acct_state_t * out_acct = &txn_result->resulting_state.acct_states[ modified_idx ];
      memset( out_acct, 0, sizeof(fd_exec_test_acct_state_t) );
      /* Copy over account content */

      memcpy( out_acct->address, acc->pubkey, sizeof(fd_pubkey_t) );

      out_acct->lamports = acc->vt->get_lamports( acc );

      if( acc->vt->get_data_len( acc ) > 0 ) {
        out_acct->data =
          FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                      PB_BYTES_ARRAY_T_ALLOCSIZE( acc->vt->get_data_len( acc ) ) );
        if( FD_UNLIKELY( _l > output_end ) ) {
          abort();
        }
        out_acct->data->size = (pb_size_t)acc->vt->get_data_len( acc );
        fd_memcpy( out_acct->data->bytes, acc->vt->get_data( acc ), acc->vt->get_data_len( acc ) );
      }

      out_acct->executable = acc->vt->is_executable( acc );
      out_acct->rent_epoch = acc->vt->get_rent_epoch( acc );
      memcpy( out_acct->owner, acc->vt->get_owner( acc ), sizeof(fd_pubkey_t) );

      txn_result->resulting_state.acct_states_count++;
    }

    ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
    fd_runtime_fuzz_txn_ctx_destroy( runner, slot_ctx );

    *output = txn_result;
    return actual_end - (ulong)output_buf;
  } FD_SPAD_FRAME_END;
}
