#include "fd_solfuzz.h"
#include "fd_solfuzz_private.h"
#include "fd_txn_harness.h"
#include "../fd_runtime.h"
#include "../fd_executor.h"
#include "../fd_txn_account.h"
#include "../fd_cost_tracker.h"
#include "../program/fd_builtin_programs.h"
#include "../sysvar/fd_sysvar_clock.h"
#include "../sysvar/fd_sysvar_epoch_rewards.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../sysvar/fd_sysvar_recent_hashes.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_slot_hashes.h"
#include "../sysvar/fd_sysvar_stake_history.h"
#include "../sysvar/fd_sysvar_last_restart_slot.h"
#include "../../../disco/pack/fd_pack.h"
#include <assert.h>

/* Macros to append data to construct a serialized transaction
   without exceeding bounds */
#define FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _to_add, _sz ) __extension__({ \
   if( FD_UNLIKELY( (*_cur_data)+_sz>_begin+FD_TXN_MTU ) ) return ULONG_MAX;          \
   fd_memcpy( *_cur_data, _to_add, _sz );                                             \
   *_cur_data += _sz;                                                                 \
})

#define FD_CHECKED_ADD_CU16_TO_TXN_DATA( _begin, _cur_data, _to_add ) __extension__({ \
   do {                                                                               \
      uchar _buf[3];                                                                  \
      fd_bincode_encode_ctx_t _encode_ctx = { .data = _buf, .dataend = _buf+3 };      \
      fd_bincode_compact_u16_encode( &_to_add, &_encode_ctx );                        \
      ulong _sz = (ulong) ((uchar *)_encode_ctx.data - _buf );                        \
      FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _buf, _sz );                     \
   } while(0);                                                                        \
})

static void
fd_runtime_fuzz_xid_cancel( fd_solfuzz_runner_t * runner,
                            fd_funk_txn_xid_t *   xid ) {
  if( FD_UNLIKELY( !xid ) ) return; // This shouldn't be false either
  fd_funk_txn_cancel( runner->funk, xid );
  fd_progcache_clear( runner->progcache_admin );
}

/* Creates transaction execution context for a single test case. Returns a
   a parsed txn descriptor on success and NULL on failure. */
static fd_txn_p_t *
fd_runtime_fuzz_txn_ctx_create( fd_solfuzz_runner_t *              runner,
                                fd_exec_test_txn_context_t const * test_ctx ) {
  fd_funk_t * funk = runner->funk;

  /* Default slot */
  ulong slot = test_ctx->slot_ctx.slot ? test_ctx->slot_ctx.slot : 10; // Arbitrary default > 0

  /* Set up the funk transaction */
  fd_funk_txn_xid_t xid = { .ul = { slot, 0UL } };
  fd_funk_txn_xid_t parent_xid; fd_funk_txn_xid_set_root( &parent_xid );
  fd_funk_txn_prepare     ( funk,                    &parent_xid, &xid );
  fd_progcache_txn_prepare( runner->progcache_admin, &parent_xid, &xid );

  /* Set up slot context */
  fd_banks_clear_bank( runner->banks, runner->bank );

  /* Restore feature flags */
  fd_exec_test_feature_set_t const * feature_set = &test_ctx->epoch_ctx.features;
  fd_features_t * features_bm = fd_bank_features_modify( runner->bank );
  if( !fd_runtime_fuzz_restore_features( features_bm, feature_set ) ) {
    return NULL;
  }

  /* Set bank variables (defaults obtained from GenesisConfig::default() in Agave) */

  fd_bank_slot_set( runner->bank, slot );
  fd_bank_parent_slot_set( runner->bank, fd_bank_slot_get( runner->bank ) - 1UL );

  /* Initialize builtin accounts */
  fd_builtin_programs_init( runner->bank, runner->funk, &xid, NULL );

  /* Load account states into funk (note this is different from the account keys):
    Account state = accounts to populate Funk
    Account keys = account keys that the transaction needs */
  for( ulong i = 0; i < test_ctx->account_shared_data_count; i++ ) {
    /* Load the accounts into the account manager
       Borrowed accounts get reset anyways - we just need to load the account somewhere */
    fd_txn_account_t acc[1];
    fd_runtime_fuzz_load_account( acc, funk, &xid, &test_ctx->account_shared_data[i], 1 );
  }

  /* Setup Bank manager */

  fd_bank_lamports_per_signature_set( runner->bank, 5000UL );

  fd_bank_prev_lamports_per_signature_set( runner->bank, 5000UL );

  fd_fee_rate_governor_t * fee_rate_governor = fd_bank_fee_rate_governor_modify( runner->bank );
  fee_rate_governor->burn_percent                  = 50;
  fee_rate_governor->min_lamports_per_signature    = 0;
  fee_rate_governor->max_lamports_per_signature    = 0;
  fee_rate_governor->target_lamports_per_signature = 10000;
  fee_rate_governor->target_signatures_per_slot    = 20000;

  fd_bank_ticks_per_slot_set( runner->bank, 64 );

  fd_bank_slots_per_year_set( runner->bank, SECONDS_PER_YEAR * (1000000000.0 / (double)6250000) / (double)(fd_bank_ticks_per_slot_get( runner->bank )) );

  /* Ensure the presence of */
  fd_epoch_schedule_t epoch_schedule_[1];
  fd_epoch_schedule_t * epoch_schedule = fd_sysvar_epoch_schedule_read( funk, &xid, epoch_schedule_ );
  FD_TEST( epoch_schedule );
  fd_bank_epoch_schedule_set( runner->bank, *epoch_schedule );

  fd_rent_t const * rent = fd_sysvar_rent_read( funk, &xid, runner->spad );
  FD_TEST( rent );
  fd_bank_rent_set( runner->bank, *rent );

  fd_slot_hashes_global_t * slot_hashes = fd_sysvar_slot_hashes_read( funk, &xid, runner->spad );
  FD_TEST( slot_hashes );

  fd_stake_history_t stake_history_[1];
  fd_stake_history_t * stake_history = fd_sysvar_stake_history_read( funk, &xid, stake_history_ );
  FD_TEST( stake_history );

  fd_sol_sysvar_clock_t clock_[1];
  fd_sol_sysvar_clock_t const * clock = fd_sysvar_clock_read( funk, &xid, clock_ );
  FD_TEST( clock );

  /* Setup vote states dummy account */
  fd_vote_states_t * vote_states = fd_vote_states_join( fd_vote_states_new( fd_bank_vote_states_locking_modify( runner->bank ), FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_TRANSACTION, 999UL ) );
  if( FD_UNLIKELY( !vote_states ) ) {
    fd_bank_vote_states_end_locking_modify( runner->bank );
    return NULL;
  }
  fd_bank_vote_states_end_locking_modify( runner->bank );

  /* Setup vote states dummy account */
  fd_vote_states_t * vote_states_prev = fd_vote_states_join( fd_vote_states_new( fd_bank_vote_states_prev_locking_modify( runner->bank ), FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_TRANSACTION, 999UL ) );
  if( FD_UNLIKELY( !vote_states_prev ) ) {
    fd_bank_vote_states_prev_end_locking_modify( runner->bank );
    return NULL;
  }
  fd_bank_vote_states_prev_end_locking_modify( runner->bank );

  /* Setup vote states dummy account */
  fd_vote_states_t * vote_states_prev_prev = fd_vote_states_join( fd_vote_states_new( fd_bank_vote_states_prev_prev_locking_modify( runner->bank ), FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_TRANSACTION, 999UL ) );
  if( FD_UNLIKELY( !vote_states_prev_prev ) ) {
    fd_bank_vote_states_prev_prev_end_locking_modify( runner->bank );
    return NULL;
  }
  fd_bank_vote_states_prev_prev_end_locking_modify( runner->bank );

  /* Epoch schedule and rent get set from the epoch bank */
  fd_sysvar_epoch_schedule_init( runner->bank, runner->funk, &xid, NULL );
  fd_sysvar_rent_init( runner->bank, runner->funk, &xid, NULL );

  /* Blockhash queue is given in txn message. We need to populate the following two fields:
     - block_hash_queue
     - recent_block_hashes */
  ulong num_blockhashes = test_ctx->blockhash_queue_count;

  /* Blockhash queue init */
  ulong blockhash_seed; FD_TEST( fd_rng_secure( &blockhash_seed, sizeof(ulong) ) );
  fd_blockhashes_t * blockhashes = fd_blockhashes_init( fd_bank_block_hash_queue_modify( runner->bank ), blockhash_seed );

  // Save lamports per signature for most recent blockhash, if sysvar cache contains recent block hashes
  fd_recent_block_hashes_t const * rbh_sysvar = fd_sysvar_recent_hashes_read( funk, &xid, runner->spad );
  fd_recent_block_hashes_t rbh[1];
  if( rbh_sysvar ) {
    rbh->hashes = rbh_sysvar->hashes;
  }

  if( rbh_sysvar && !deq_fd_block_block_hash_entry_t_empty( rbh->hashes ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_head_const( rbh->hashes );
    if( last && last->fee_calculator.lamports_per_signature!=0UL ) {
      fd_bank_lamports_per_signature_set( runner->bank, last->fee_calculator.lamports_per_signature );
      fd_bank_prev_lamports_per_signature_set( runner->bank, last->fee_calculator.lamports_per_signature );
    }
  }

  // Blockhash_queue[end] = last (latest) hash
  // Blockhash_queue[0] = genesis hash
  if( num_blockhashes > 0 ) {
    fd_hash_t * genesis_hash = fd_bank_genesis_hash_modify( runner->bank );
    memcpy( genesis_hash->hash, test_ctx->blockhash_queue[0]->bytes, sizeof(fd_hash_t) );

    for( ulong i = 0; i < num_blockhashes; ++i ) {
      fd_hash_t blockhash = FD_LOAD( fd_hash_t, test_ctx->blockhash_queue[i]->bytes );
      /* Drop duplicate blockhashes */
      if( FD_UNLIKELY( fd_blockhash_map_idx_remove( blockhashes->map, &blockhash, ULONG_MAX, blockhashes->d.deque )!=ULONG_MAX ) ) {
        FD_LOG_WARNING(( "Fuzz input has a duplicate blockhash %s at index %lu",
                         FD_BASE58_ENC_32_ALLOCA( blockhash.hash ), i ));
      }
      // Recent block hashes cap is 150 (actually 151), while blockhash queue capacity is 300 (actually 301)
      fd_bank_poh_set( runner->bank, blockhash );
      fd_sysvar_recent_hashes_update( runner->bank, runner->funk, &xid, NULL );
    }
  } else {
    // Add a default empty blockhash and use it as genesis
    num_blockhashes = 1;
    *fd_bank_genesis_hash_modify( runner->bank ) = (fd_hash_t){0};
    fd_bank_poh_set( runner->bank, (fd_hash_t){0} );
    fd_sysvar_recent_hashes_update( runner->bank, runner->funk, &xid, NULL );
  }

  /* Restore sysvars from account context */
  fd_sysvar_cache_restore_fuzz( runner->bank, runner->funk, &xid );

  /* Create the raw txn (https://solana.com/docs/core/transactions#transaction-size) */
  fd_txn_p_t * txn    = fd_spad_alloc( runner->spad, alignof(fd_txn_p_t), sizeof(fd_txn_p_t) );
  ulong        msg_sz = fd_runtime_fuzz_serialize_txn( txn->payload, &test_ctx->tx );
  if( FD_UNLIKELY( msg_sz==ULONG_MAX ) ) {
    return NULL;
  }

  /* Set up txn descriptor from raw data */
  if( FD_UNLIKELY( !fd_txn_parse( txn->payload, msg_sz, TXN( txn ), NULL ) ) ) {
    return NULL;
  }

  txn->payload_sz = msg_sz;

  return txn;
}

ulong
fd_runtime_fuzz_serialize_txn( uchar *                                      txn_raw_begin,
                               fd_exec_test_sanitized_transaction_t const * tx ) {
  uchar * txn_raw_cur_ptr = txn_raw_begin;

  /* Compact array of signatures (https://solana.com/docs/core/transactions#transaction)
     Note that although documentation interchangably refers to the signature cnt as a compact-u16
     and a u8, the max signature cnt is capped at 48 (due to txn size limits), so u8 and compact-u16
     is represented the same way anyways and can be parsed identically. */
  // Note: always create a valid txn with 1+ signatures, add an empty signature if none is provided
  uchar signature_cnt = fd_uchar_max( 1, (uchar) tx->signatures_count );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signature_cnt, sizeof(uchar) );
  for( uchar i = 0; i < signature_cnt; ++i ) {
    fd_signature_t sig = {0};
    if( tx->signatures && tx->signatures[i] ) sig = FD_LOAD( fd_signature_t, tx->signatures[i]->bytes );
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &sig, FD_TXN_SIGNATURE_SZ );
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
  fd_hash_t msg_rbh = {0};
  if( tx->message.recent_blockhash ) msg_rbh = FD_LOAD( fd_hash_t, tx->message.recent_blockhash->bytes );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &msg_rbh, sizeof(fd_hash_t) );

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

  return (ulong)(txn_raw_cur_ptr - txn_raw_begin);
}

fd_exec_txn_ctx_t *
fd_runtime_fuzz_txn_ctx_exec( fd_solfuzz_runner_t *     runner,
                              fd_funk_txn_xid_t const * xid,
                              fd_txn_p_t *              txn,
                              int *                     exec_res ) {

  /* Setup the spad for account allocation */
  uchar *             txn_ctx_mem        = fd_spad_alloc_check( runner->spad, FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
  fd_exec_txn_ctx_t * txn_ctx            = fd_exec_txn_ctx_join( fd_exec_txn_ctx_new( txn_ctx_mem ), runner->spad, fd_wksp_containing( runner->spad ) );
  txn_ctx->flags                         = FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
  if( FD_UNLIKELY( !fd_funk_join( txn_ctx->funk, runner->funk->shmem ) ) ) {
    FD_LOG_CRIT(( "fd_funk_join failed" ));
  }
  uchar * pc_scratch = fd_spad_alloc_check( runner->spad, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT );
  txn_ctx->progcache = fd_progcache_join( txn_ctx->_progcache, runner->progcache->funk->shmem, pc_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT );
  if( FD_UNLIKELY( !txn_ctx->progcache ) ) {
    FD_LOG_CRIT(( "fd_progcache_join failed" ));
  }
  txn_ctx->bank_hash_cmp                 = NULL;
  txn_ctx->fuzz_config.enable_vm_tracing = runner->enable_vm_tracing;
  txn_ctx->xid[0]                        = *xid;

  *exec_res = fd_runtime_prepare_and_execute_txn(
      runner->banks,
      0UL,
      txn_ctx,
      txn,
      NULL );

  return txn_ctx;
}

ulong
fd_solfuzz_txn_run( fd_solfuzz_runner_t * runner,
                    void const *          input_,
                    void **               output_,
                    void *                output_buf,
                    ulong                 output_bufsz ) {
  fd_exec_test_txn_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_txn_result_t **       output = fd_type_pun( output_ );

  FD_SPAD_FRAME_BEGIN( runner->spad ) {

    /* Setup the transaction context */
    fd_txn_p_t * txn = fd_runtime_fuzz_txn_ctx_create( runner, input );

    fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( runner->bank ), 0UL } };
    if( FD_UNLIKELY( txn==NULL ) ) {
      fd_runtime_fuzz_xid_cancel( runner, &xid );
      return 0;
    }

    /* Execute the transaction against the runtime */
    int exec_res = 0;
    fd_exec_txn_ctx_t * txn_ctx = fd_runtime_fuzz_txn_ctx_exec( runner, &xid, txn, &exec_res );

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
    txn_result->executed                          = txn_ctx->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
    txn_result->sanitization_error                = !(txn_ctx->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS);
    txn_result->has_resulting_state               = false;
    txn_result->resulting_state.acct_states_count = 0;
    txn_result->is_ok                             = !exec_res;
    txn_result->status                            = (uint32_t) -exec_res;
    txn_result->instruction_error                 = 0;
    txn_result->instruction_error_index           = 0;
    txn_result->custom_error                      = 0;
    txn_result->has_fee_details                   = false;
    txn_result->loaded_accounts_data_size         = txn_ctx->loaded_accounts_data_size;

    if( txn_result->sanitization_error ) {
      /* Collect fees for transactions that failed to load */
      if( txn_ctx->flags & FD_TXN_P_FLAGS_FEES_ONLY ) {
        txn_result->has_fee_details                = true;
        txn_result->fee_details.prioritization_fee = txn_ctx->priority_fee;
        txn_result->fee_details.transaction_fee    = txn_ctx->execution_fee;
      }

      if( exec_res==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR ) {
        txn_result->instruction_error       = (uint32_t) -txn_ctx->exec_err;
        txn_result->instruction_error_index = (uint32_t) txn_ctx->instr_err_idx;
        if( txn_ctx->exec_err==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
          txn_result->custom_error = txn_ctx->custom_err;
        }
      }

      ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
      fd_runtime_fuzz_xid_cancel( runner, &xid );

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
    txn_result->fee_details.transaction_fee    = txn_ctx->execution_fee;
    txn_result->fee_details.prioritization_fee = txn_ctx->priority_fee;
    txn_result->executed_units                 = txn_ctx->compute_budget_details.compute_unit_limit - txn_ctx->compute_budget_details.compute_meter;


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

    /* If the transaction is a fees-only transaction, we have to create rollback accounts to iterate over and save. */
    fd_txn_account_t * accounts_to_save = txn_ctx->accounts;
    ulong              accounts_cnt     = txn_ctx->accounts_cnt;
    if( txn_ctx->flags & FD_TXN_P_FLAGS_FEES_ONLY ) {
      accounts_to_save = fd_spad_alloc( runner->spad, alignof(fd_txn_account_t), sizeof(fd_txn_account_t) * 2 );
      accounts_cnt     = 0UL;

      if( FD_LIKELY( txn_ctx->nonce_account_idx_in_txn!=FD_FEE_PAYER_TXN_IDX ) ) {
        accounts_to_save[accounts_cnt++] = *txn_ctx->rollback_fee_payer_account;
      }

      if( txn_ctx->nonce_account_idx_in_txn!=ULONG_MAX ) {
        accounts_to_save[accounts_cnt++] = *txn_ctx->rollback_nonce_account;
      }
    }

    /* Capture borrowed accounts */
    for( ulong j=0UL; j<accounts_cnt; j++ ) {
      fd_txn_account_t * acc = &accounts_to_save[j];

      if( !( fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, (ushort)j ) || j==FD_FEE_PAYER_TXN_IDX ) ) continue;
      assert( fd_txn_account_is_mutable( acc ) );

      ulong modified_idx = txn_result->resulting_state.acct_states_count;
      assert( modified_idx < modified_acct_cnt );

      fd_exec_test_acct_state_t * out_acct = &txn_result->resulting_state.acct_states[ modified_idx ];
      memset( out_acct, 0, sizeof(fd_exec_test_acct_state_t) );
      /* Copy over account content */

      memcpy( out_acct->address, acc->pubkey, sizeof(fd_pubkey_t) );

      out_acct->lamports = fd_txn_account_get_lamports( acc );

      if( fd_txn_account_get_data_len( acc )>0UL ) {
        out_acct->data =
          FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                      PB_BYTES_ARRAY_T_ALLOCSIZE( fd_txn_account_get_data_len( acc ) ) );
        if( FD_UNLIKELY( _l > output_end ) ) {
          abort();
        }
        out_acct->data->size = (pb_size_t)fd_txn_account_get_data_len( acc );
        fd_memcpy( out_acct->data->bytes, fd_txn_account_get_data( acc ), fd_txn_account_get_data_len( acc ) );
      }

      out_acct->executable = fd_txn_account_is_executable( acc );
      memcpy( out_acct->owner, fd_txn_account_get_owner( acc ), sizeof(fd_pubkey_t) );

      txn_result->resulting_state.acct_states_count++;
    }

    ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
    fd_runtime_fuzz_xid_cancel( runner, &xid );

    *output = txn_result;
    return actual_end - (ulong)output_buf;
  } FD_SPAD_FRAME_END;
}
