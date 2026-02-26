#include "fd_solfuzz.h"
#include "fd_solfuzz_private.h"
#include "fd_txn_harness.h"
#include "fd_dump_pb.h"
#include "../fd_runtime.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../../accdb/fd_accdb_admin_v1.h"
#include "../../accdb/fd_accdb_impl_v1.h"
#include "../../log_collector/fd_log_collector.h"
#include "../fd_system_ids.h"

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

/* Retrieves the slot number from the clock sysvar account within the
   txn context.  Throws FD_LOG_ERR if the clock sysvar is not found
   or is malformed. */
static ulong
fd_solfuzz_pb_txn_ctx_get_slot( fd_exec_test_txn_context_t const * test_ctx ) {
  for( ulong i=0UL; i<test_ctx->account_shared_data_count; i++ ) {
    if( !memcmp( &test_ctx->account_shared_data[i].address, &fd_sysvar_clock_id, sizeof(fd_pubkey_t) ) ) {
      FD_TEST( test_ctx->account_shared_data[i].data->size==sizeof(fd_sol_sysvar_clock_t) );
      return FD_LOAD( ulong, test_ctx->account_shared_data[i].data->bytes );
    }
  }
  FD_LOG_ERR(( "invariant violation: clock sysvar account not found in txn context" ));
}

static void
fd_solfuzz_txn_ctx_destroy( fd_solfuzz_runner_t * runner ) {
  fd_accdb_v1_clear( runner->accdb_admin );
  fd_progcache_clear( runner->progcache_admin );

  /* In order to check for leaks in the workspace, we need to compact the
     allocators. Without doing this, empty superblocks may be retained
     by the fd_alloc instance, which mean we cannot check for leaks. */
  fd_alloc_compact( fd_accdb_user_v1_funk( runner->accdb )->alloc );
  fd_alloc_compact( runner->progcache_admin->funk->alloc );
}

/* Creates transaction execution context for a single test case.
   Returns a parsed txn descriptor on success and NULL on failure. */
static fd_txn_p_t *
fd_solfuzz_pb_txn_ctx_create( fd_solfuzz_runner_t *              runner,
                              fd_exec_test_txn_context_t const * test_ctx ) {
  fd_accdb_user_t * accdb = runner->accdb;

  /* Set up the funk transaction */
  ulong             slot = fd_solfuzz_pb_txn_ctx_get_slot( test_ctx );
  fd_funk_txn_xid_t xid  = { .ul = { slot, runner->bank->data->idx } };
  fd_funk_txn_xid_t parent_xid; fd_funk_txn_xid_set_root( &parent_xid );
  fd_accdb_attach_child        ( runner->accdb_admin,     &parent_xid, &xid );
  fd_progcache_txn_attach_child( runner->progcache_admin, &parent_xid, &xid );

  /* Initialize bank from input txn bank */
  fd_banks_clear_bank( runner->banks, runner->bank, 64UL );
  FD_TEST( test_ctx->has_bank );
  fd_exec_test_txn_bank_t const * txn_bank = &test_ctx->bank;

  /* Initialize blockhash queue */
  ulong blockhash_seed; FD_TEST( fd_rng_secure( &blockhash_seed, sizeof(ulong) ) );
  fd_blockhashes_t * blockhashes = fd_blockhashes_init( fd_bank_block_hash_queue_modify( runner->bank ), blockhash_seed );
  for( uint i=0UL; i<txn_bank->blockhash_queue_count; i++ ) {
    fd_exec_test_blockhash_queue_entry_t const * entry = &txn_bank->blockhash_queue[i];

    fd_hash_t hash                   = FD_LOAD( fd_hash_t, entry->blockhash );
    ulong     lamports_per_signature = entry->lamports_per_signature;

    fd_blockhash_info_t * blockhash = fd_blockhashes_push_new( blockhashes, &hash );
    blockhash->fee_calculator = (fd_fee_calculator_t){
      .lamports_per_signature = lamports_per_signature
    };
  }

  /* RBH lamports per signature. In the Agave harness this is set inside
     the fee rate governor itself. */
  fd_bank_rbh_lamports_per_sig_set( runner->bank, txn_bank->rbh_lamports_per_signature );

  /* Fee rate governor */
  FD_TEST( txn_bank->has_fee_rate_governor );
  fd_fee_rate_governor_t * fee_rate_governor = fd_bank_fee_rate_governor_modify( runner->bank );
  *fee_rate_governor = (fd_fee_rate_governor_t){
    .target_lamports_per_signature = txn_bank->fee_rate_governor.target_lamports_per_signature,
    .target_signatures_per_slot    = txn_bank->fee_rate_governor.target_signatures_per_slot,
    .min_lamports_per_signature    = txn_bank->fee_rate_governor.min_lamports_per_signature,
    .max_lamports_per_signature    = txn_bank->fee_rate_governor.max_lamports_per_signature,
    .burn_percent                  = (uchar)txn_bank->fee_rate_governor.burn_percent,
  };

  /* Slot and parent slot */
  fd_bank_slot_set( runner->bank, slot );
  fd_bank_parent_slot_set( runner->bank, slot-1UL );

  /* Total epoch stake */
  fd_bank_total_epoch_stake_set( runner->bank, txn_bank->total_epoch_stake );

  /* Epoch schedule */
  FD_TEST( txn_bank->has_epoch_schedule );
  fd_epoch_schedule_t * epoch_schedule = fd_bank_epoch_schedule_modify( runner->bank );
  *epoch_schedule = (fd_epoch_schedule_t){
    .slots_per_epoch             = txn_bank->epoch_schedule.slots_per_epoch,
    .leader_schedule_slot_offset = txn_bank->epoch_schedule.leader_schedule_slot_offset,
    .warmup                      = txn_bank->epoch_schedule.warmup,
    .first_normal_epoch          = txn_bank->epoch_schedule.first_normal_epoch,
    .first_normal_slot           = txn_bank->epoch_schedule.first_normal_slot
  };

  /* Rent */
  FD_TEST( txn_bank->has_rent );
  fd_rent_t * rent = fd_bank_rent_modify( runner->bank );
  *rent = (fd_rent_t){
    .lamports_per_uint8_year = txn_bank->rent.lamports_per_byte_year,
    .exemption_threshold     = txn_bank->rent.exemption_threshold,
    .burn_percent            = (uchar)txn_bank->rent.burn_percent
  };

  /* Features */
  FD_TEST( txn_bank->has_features );
  fd_exec_test_feature_set_t const * feature_set = &txn_bank->features;
  fd_features_t * features_bm = fd_bank_features_modify( runner->bank );
  if( !fd_solfuzz_pb_restore_features( features_bm, feature_set ) ) {
    return NULL;
  }

  /* Epoch */
  ulong epoch = fd_slot_to_epoch( epoch_schedule, slot, NULL );
  fd_bank_epoch_set( runner->bank, epoch );

  /* Load account states into funk (note this is different from the account keys):
    Account state = accounts to populate Funk
    Account keys = account keys that the transaction needs */
  for( ulong i = 0; i < test_ctx->account_shared_data_count; i++ ) {
    /* Load the accounts into the account manager
       Borrowed accounts get reset anyways - we just need to load the account somewhere */
    fd_solfuzz_pb_load_account( runner->runtime, accdb, &xid, &test_ctx->account_shared_data[i], i );
  }


  fd_bank_ticks_per_slot_set( runner->bank, 64 );
  fd_bank_slots_per_year_set( runner->bank, SECONDS_PER_YEAR * (1000000000.0 / (double)6250000) / (double)(fd_bank_ticks_per_slot_get( runner->bank )) );

  /* Restore sysvars from account context */
  fd_sysvar_cache_restore_fuzz( runner->bank, runner->accdb, &xid );

  /* Create the raw txn (https://solana.com/docs/core/transactions#transaction-size) */
  fd_txn_p_t * txn    = fd_spad_alloc( runner->spad, alignof(fd_txn_p_t), sizeof(fd_txn_p_t) );
  ulong        msg_sz = fd_solfuzz_pb_txn_serialize( txn->payload, &test_ctx->tx );
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
fd_solfuzz_pb_txn_serialize( uchar *                                      txn_raw_begin,
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

void
fd_solfuzz_txn_ctx_exec( fd_solfuzz_runner_t * runner,
                         fd_runtime_t *        runtime,
                         fd_txn_in_t const *   txn_in,
                         int *                 exec_res,
                         fd_txn_out_t *        txn_out ) {

  txn_out->err.is_committable = 1;

  runtime->log.enable_vm_tracing = runner->enable_vm_tracing;
  uchar * tracing_mem = NULL;
  if( runner->enable_vm_tracing ) {
    tracing_mem = fd_spad_alloc_check( runner->spad, FD_RUNTIME_VM_TRACE_STATIC_ALIGN, FD_RUNTIME_VM_TRACE_STATIC_FOOTPRINT * FD_MAX_INSTRUCTION_STACK_DEPTH );
  }

  runtime->accdb              = runner->accdb;
  runtime->progcache          = runner->progcache;
  runtime->status_cache       = NULL;
  runtime->log.tracing_mem    = tracing_mem;
  runtime->log.dumping_mem    = NULL;
  runtime->log.capture_ctx    = NULL;
  runtime->log.dump_proto_ctx = NULL;
  runtime->log.txn_dump_ctx   = NULL;

  fd_runtime_prepare_and_execute_txn( runtime, runner->bank, txn_in, txn_out );
  *exec_res = txn_out->err.txn_err;
}

ulong
fd_solfuzz_pb_txn_run( fd_solfuzz_runner_t * runner,
                       void const *          input_,
                       void **               output_,
                       void *                output_buf,
                       ulong                 output_bufsz ) {
  fd_exec_test_txn_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_txn_result_t **       output = fd_type_pun( output_ );

  FD_SPAD_FRAME_BEGIN( runner->spad ) {

    /* Setup the transaction context */
    fd_txn_p_t * txn = fd_solfuzz_pb_txn_ctx_create( runner, input );
    if( FD_UNLIKELY( txn==NULL ) ) {
      fd_solfuzz_txn_ctx_destroy( runner );
      return 0UL;
    }

    /* Execute the transaction against the runtime */
    int exec_res = 0;
    fd_runtime_t *       runtime = runner->runtime;
    fd_txn_in_t *        txn_in  = fd_spad_alloc( runner->spad, alignof(fd_txn_in_t), sizeof(fd_txn_in_t) );
    fd_txn_out_t *       txn_out = fd_spad_alloc( runner->spad, alignof(fd_txn_out_t), sizeof(fd_txn_out_t) );
    fd_log_collector_t * log     = fd_spad_alloc( runner->spad, alignof(fd_log_collector_t), sizeof(fd_log_collector_t) );
    runtime->log.log_collector = log;
    runtime->acc_pool = runner->acc_pool;
    txn_in->txn = txn;
    txn_in->bundle.is_bundle = 0;
    fd_solfuzz_txn_ctx_exec( runner, runtime, txn_in, &exec_res, txn_out );

    /* Build result directly into the caller-owned output_buf */
    fd_exec_test_txn_result_t * txn_result = NULL;
    ulong result_sz = create_txn_result_protobuf_from_txn(
        &txn_result,
        output_buf,
        output_bufsz,
        txn_in,
        txn_out,
        runner->bank,
        exec_res
    );

    txn_out->err.is_committable = 0;
    fd_runtime_cancel_txn( runner->runtime, txn_out );
    fd_solfuzz_txn_ctx_destroy( runner );

    *output = txn_result;
    return result_sz;
  } FD_SPAD_FRAME_END;
}
