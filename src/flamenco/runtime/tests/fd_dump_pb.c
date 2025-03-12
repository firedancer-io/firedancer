#include "fd_dump_pb.h"

#define SORT_NAME        sort_uint64_t
#define SORT_KEY_T       uint64_t
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../../util/tmpl/fd_sort.c"

/***** UTILITY FUNCTIONS *****/

static void
dump_sorted_features( fd_features_t const * features,
                      fd_exec_test_feature_set_t * output_feature_set,
                      fd_spad_t * spad ) {
  /* NOTE: Caller must have a scratch frame prepared */
  uint64_t * unsorted_features = fd_spad_alloc( spad, alignof(uint64_t), FD_FEATURE_ID_CNT * sizeof(uint64_t) );
  ulong num_features = 0;
  for( const fd_feature_id_t * current_feature = fd_feature_iter_init(); !fd_feature_iter_done( current_feature ); current_feature = fd_feature_iter_next( current_feature ) ) {
    if (features->f[current_feature->index] != FD_FEATURE_DISABLED) {
      unsorted_features[num_features++] = (uint64_t) current_feature->id.ul[0];
    }
  }
  // Sort the features
  void * scratch = fd_spad_alloc( spad, sort_uint64_t_stable_scratch_align(), sort_uint64_t_stable_scratch_footprint(num_features) );
  uint64_t * sorted_features = sort_uint64_t_stable_fast( unsorted_features, num_features, scratch );

  // Set feature set in message
  output_feature_set->features_count = (pb_size_t) num_features;
  output_feature_set->features       = sorted_features;
}

static void
dump_account_state( fd_txn_account_t const *    txn_account,
                    fd_exec_test_acct_state_t * output_account,
                    fd_spad_t *                 spad ) {
    // Address
    fd_memcpy(output_account->address, txn_account->pubkey, sizeof(fd_pubkey_t));

    // Lamports
    output_account->lamports = (uint64_t) txn_account->const_meta->info.lamports;

    // Data
    output_account->data = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( txn_account->const_meta->dlen ) );
    output_account->data->size = (pb_size_t) txn_account->const_meta->dlen;
    fd_memcpy(output_account->data->bytes, txn_account->const_data, txn_account->const_meta->dlen);

    // Executable
    output_account->executable = (bool) txn_account->const_meta->info.executable;

    // Rent epoch
    output_account->rent_epoch = (uint64_t) txn_account->const_meta->info.rent_epoch;

    // Owner
    fd_memcpy(output_account->owner, txn_account->const_meta->info.owner, sizeof(fd_pubkey_t));

    // Seed address (not present)
    output_account->has_seed_addr = false;
}

static void
create_txn_context_protobuf_from_txn( fd_exec_test_txn_context_t * txn_context_msg,
                                      fd_exec_txn_ctx_t *          txn_ctx,
                                      fd_spad_t *                  spad ) {
  fd_txn_t const * txn_descriptor = txn_ctx->txn_descriptor;
  uchar const *    txn_payload    = (uchar const *) txn_ctx->_txn_raw->raw;

  /* We don't want to store builtins in account shared data */
  fd_pubkey_t const loaded_builtins[] = {
    fd_solana_system_program_id,
    fd_solana_vote_program_id,
    fd_solana_stake_program_id,
    fd_solana_config_program_id,
    // fd_solana_zk_token_proof_program_id,
    fd_solana_bpf_loader_v4_program_id,
    fd_solana_address_lookup_table_program_id,
    fd_solana_bpf_loader_deprecated_program_id,
    fd_solana_bpf_loader_program_id,
    fd_solana_bpf_loader_upgradeable_program_id,
    fd_solana_compute_budget_program_id,
    fd_solana_keccak_secp_256k_program_id,
    fd_solana_secp256r1_program_id,
    fd_solana_zk_elgamal_proof_program_id,
    fd_solana_ed25519_sig_verify_program_id,
    fd_solana_spl_native_mint_id,
  };
  const ulong num_loaded_builtins = (sizeof(loaded_builtins) / sizeof(fd_pubkey_t));

  /* Prepare sysvar cache accounts */
  fd_pubkey_t const fd_relevant_sysvar_ids[] = {
    fd_sysvar_clock_id,
    fd_sysvar_epoch_schedule_id,
    fd_sysvar_epoch_rewards_id,
    fd_sysvar_fees_id,
    fd_sysvar_rent_id,
    fd_sysvar_slot_hashes_id,
    fd_sysvar_recent_block_hashes_id,
    fd_sysvar_stake_history_id,
    fd_sysvar_last_restart_slot_id,
    fd_sysvar_instructions_id,
  };
  const ulong num_sysvar_entries = (sizeof(fd_relevant_sysvar_ids) / sizeof(fd_pubkey_t));

  /* Transaction Context -> account_shared_data
     Contains:
      - Account data for regular accounts
      - Account data for LUT accounts
      - Account data for executable accounts
      - Account data for (almost) all sysvars
  */
  // Dump regular accounts first
  txn_context_msg->account_shared_data_count = 0;
  txn_context_msg->account_shared_data = fd_spad_alloc( spad,
                                                        alignof(fd_exec_test_acct_state_t),
                                                        (txn_ctx->accounts_cnt * 2 + txn_descriptor->addr_table_lookup_cnt + num_sysvar_entries) * sizeof(fd_exec_test_acct_state_t) );
  for( ulong i = 0; i < txn_ctx->accounts_cnt; ++i ) {
    FD_TXN_ACCOUNT_DECL( txn_account );
    int ret = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, &txn_ctx->account_keys[i], txn_account );
    if( FD_UNLIKELY(ret != FD_ACC_MGR_SUCCESS) ) {
      continue;
    }

    // Make sure account is not a builtin
    bool is_builtin = false;
    for( ulong j = 0; j < num_loaded_builtins; ++j ) {
      if( 0 == memcmp( &txn_ctx->account_keys[i], &loaded_builtins[j], sizeof(fd_pubkey_t) ) ) {
        is_builtin = true;
        break;
      }
    }
    if( !is_builtin ) {
      dump_account_state( txn_account, &txn_context_msg->account_shared_data[txn_context_msg->account_shared_data_count++], spad );
    }
  }

  // For executable accounts, we need to set up dummy borrowed accounts by cluttering txn ctx state and resetting it after
  // TODO: Revisit this hacky approach
  txn_ctx->spad = spad;
  fd_spad_push( txn_ctx->spad );
  fd_executor_setup_borrowed_accounts_for_txn( txn_ctx );

  // Dump executable accounts
  for( ulong i = 0; i < txn_ctx->executable_cnt; ++i ) {
    if( !txn_ctx->executable_accounts[i].const_meta ) {
      continue;
    }
    dump_account_state( &txn_ctx->executable_accounts[i], &txn_context_msg->account_shared_data[txn_context_msg->account_shared_data_count++], spad );
  }

  // Reset state
  txn_ctx->funk_txn = NULL;
  txn_ctx->executable_cnt = 0;
  fd_spad_pop( txn_ctx->spad );

  // Dump LUT accounts
  fd_txn_acct_addr_lut_t const * address_lookup_tables = fd_txn_get_address_tables_const( txn_descriptor );
  for( ulong i = 0; i < txn_descriptor->addr_table_lookup_cnt; ++i ) {
    FD_TXN_ACCOUNT_DECL( txn_account );
    fd_pubkey_t * alut_key = (fd_pubkey_t *) (txn_payload + address_lookup_tables[i].addr_off);
    int ret = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, alut_key, txn_account );
    if( FD_UNLIKELY(ret != FD_ACC_MGR_SUCCESS) ) {
      continue;
    }
    dump_account_state( txn_account, &txn_context_msg->account_shared_data[txn_context_msg->account_shared_data_count++], spad );
  }

  // Dump sysvars
  for( ulong i = 0; i < num_sysvar_entries; i++ ) {
    FD_TXN_ACCOUNT_DECL( txn_account );
    int ret = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, &fd_relevant_sysvar_ids[i], txn_account );
    if( ret != FD_ACC_MGR_SUCCESS ) {
      continue;
    }

    // Make sure the account doesn't exist in the output accounts yet
    int account_exists = 0;
    for( ulong j = 0; j < txn_ctx->accounts_cnt; j++ ) {
      if ( 0 == memcmp( txn_ctx->account_keys[j].key, fd_relevant_sysvar_ids[i].uc, sizeof(fd_pubkey_t) ) ) {
        account_exists = true;
        break;
      }
    }
    // Copy it into output
    if (!account_exists) {
      dump_account_state( txn_account, &txn_context_msg->account_shared_data[txn_context_msg->account_shared_data_count++], spad );
    }
  }

  /* Transaction Context -> tx */
  txn_context_msg->has_tx = true;
  fd_exec_test_sanitized_transaction_t * sanitized_transaction = &txn_context_msg->tx;

  /* Transaction Context -> tx -> message */
  sanitized_transaction->has_message = true;
  fd_exec_test_transaction_message_t * message = &sanitized_transaction->message;

  /* Transaction Context -> tx -> message -> is_legacy */
  message->is_legacy = txn_descriptor->transaction_version == FD_TXN_VLEGACY;

  /* Transaction Context -> tx -> message -> header */
  message->has_header = true;
  fd_exec_test_message_header_t * header = &message->header;

  /* Transaction Context -> tx -> message -> header -> num_required_signatures */
  header->num_required_signatures = txn_descriptor->signature_cnt;

  /* Transaction Context -> tx -> message -> header -> num_readonly_signed_accounts */
  header->num_readonly_signed_accounts = txn_descriptor->readonly_signed_cnt;

  /* Transaction Context -> tx -> message -> header -> num_readonly_unsigned_accounts */
  header->num_readonly_unsigned_accounts = txn_descriptor->readonly_unsigned_cnt;

  /* Transaction Context -> tx -> message -> account_keys */
  message->account_keys_count = txn_descriptor->acct_addr_cnt;
  message->account_keys = fd_spad_alloc( spad, alignof(pb_bytes_array_t *), PB_BYTES_ARRAY_T_ALLOCSIZE( txn_descriptor->acct_addr_cnt * sizeof(pb_bytes_array_t *) ) );
  fd_acct_addr_t const * account_keys = fd_txn_get_acct_addrs( txn_descriptor, txn_payload );
  for( ulong i = 0; i < txn_descriptor->acct_addr_cnt; i++ ) {
    pb_bytes_array_t * account_key = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( sizeof(fd_pubkey_t) ) );
    account_key->size = sizeof(fd_pubkey_t);
    memcpy( account_key->bytes, &account_keys[i], sizeof(fd_pubkey_t) );
    message->account_keys[i] = account_key;
  }

  /* Transaction Context -> tx -> message -> recent_blockhash */
  uchar const * recent_blockhash = fd_txn_get_recent_blockhash( txn_descriptor, txn_payload );
  message->recent_blockhash = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( sizeof(fd_hash_t) ) );
  message->recent_blockhash->size = sizeof(fd_hash_t);
  memcpy( message->recent_blockhash->bytes, recent_blockhash, sizeof(fd_hash_t) );

  /* Transaction Context -> tx -> message -> instructions */
  message->instructions_count = txn_descriptor->instr_cnt;
  message->instructions = fd_spad_alloc( spad, alignof(fd_exec_test_compiled_instruction_t), txn_descriptor->instr_cnt * sizeof(fd_exec_test_compiled_instruction_t) );
  for( ulong i = 0; i < txn_descriptor->instr_cnt; ++i ) {
    fd_txn_instr_t instr = txn_descriptor->instr[i];
    fd_exec_test_compiled_instruction_t * compiled_instruction = &message->instructions[i];

    // compiled instruction -> program_id_index
    compiled_instruction->program_id_index = instr.program_id;

    // compiled instruction -> accounts
    compiled_instruction->accounts_count = instr.acct_cnt;
    compiled_instruction->accounts = fd_spad_alloc( spad, alignof(uint32_t), instr.acct_cnt * sizeof(uint32_t) );
    uchar const * instr_accounts = fd_txn_get_instr_accts( &instr, txn_payload );
    for( ulong j = 0; j < instr.acct_cnt; ++j ) {
      uchar instr_acct_index = instr_accounts[j];
      compiled_instruction->accounts[j] = instr_acct_index;
    }

    // compiled instruction -> data
    uchar const * instr_data = fd_txn_get_instr_data( &instr, txn_payload );
    compiled_instruction->data = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( instr.data_sz ) );
    compiled_instruction->data->size = instr.data_sz;
    memcpy( compiled_instruction->data->bytes, instr_data, instr.data_sz );
  }

  /* ALUT stuff (non-legacy) */
  message->address_table_lookups_count = 0;
  if( !message->is_legacy ) {
    /* Transaction Context -> tx -> message -> address_table_lookups */
    message->address_table_lookups_count = txn_descriptor->addr_table_lookup_cnt;
    message->address_table_lookups = fd_spad_alloc( spad,
                                                    alignof(fd_exec_test_message_address_table_lookup_t),
                                                    txn_descriptor->addr_table_lookup_cnt * sizeof(fd_exec_test_message_address_table_lookup_t) );
    for( ulong i = 0; i < txn_descriptor->addr_table_lookup_cnt; ++i ) {
      // alut -> account_key
      fd_pubkey_t * alut_key = (fd_pubkey_t *) (txn_payload + address_lookup_tables[i].addr_off);
      memcpy( message->address_table_lookups[i].account_key, alut_key, sizeof(fd_pubkey_t) );

      // Access ALUT account data to access its keys
      FD_TXN_ACCOUNT_DECL( addr_lut_rec );
      int err = fd_acc_mgr_view(txn_ctx->acc_mgr, txn_ctx->funk_txn, alut_key, addr_lut_rec);
      if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_ERR(( "addr lut not found" ));
      }

      // alut -> writable_indexes
      message->address_table_lookups[i].writable_indexes_count = address_lookup_tables[i].writable_cnt;
      message->address_table_lookups[i].writable_indexes = fd_spad_alloc( spad, alignof(uint32_t), address_lookup_tables[i].writable_cnt * sizeof(uint32_t) );
      uchar * writable_indexes = (uchar *) (txn_payload + address_lookup_tables[i].writable_off);
      for( ulong j = 0; j < address_lookup_tables[i].writable_cnt; ++j ) {
        message->address_table_lookups[i].writable_indexes[j] = writable_indexes[j];
      }

      // alut -> readonly_indexes
      message->address_table_lookups[i].readonly_indexes_count = address_lookup_tables[i].readonly_cnt;
      message->address_table_lookups[i].readonly_indexes = fd_spad_alloc( spad, alignof(uint32_t), address_lookup_tables[i].readonly_cnt * sizeof(uint32_t) );
      uchar * readonly_indexes = (uchar *) (txn_payload + address_lookup_tables[i].readonly_off);
      for( ulong j = 0; j < address_lookup_tables[i].readonly_cnt; ++j ) {
        message->address_table_lookups[i].readonly_indexes[j] = readonly_indexes[j];
      }
    }
  }

  /* Transaction Context -> tx -> message_hash */
  // Skip because it does not matter what's in here

  /* Transaction Context -> tx -> signatures */
  sanitized_transaction->signatures_count = txn_descriptor->signature_cnt;
  sanitized_transaction->signatures = fd_spad_alloc( spad, alignof(pb_bytes_array_t *), PB_BYTES_ARRAY_T_ALLOCSIZE( txn_descriptor->signature_cnt * sizeof(pb_bytes_array_t *) ) );
  fd_ed25519_sig_t const * signatures = fd_txn_get_signatures( txn_descriptor, txn_payload );
  for( uchar i = 0; i < txn_descriptor->signature_cnt; ++i ) {
    pb_bytes_array_t * signature = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( sizeof(fd_ed25519_sig_t) ) );
    signature->size = sizeof(fd_ed25519_sig_t);
    memcpy( signature->bytes, &signatures[i], sizeof(fd_ed25519_sig_t) );
    sanitized_transaction->signatures[i] = signature;
  }

  /* Transaction Context -> blockhash_queue
     NOTE: Agave's implementation of register_hash incorrectly allows the blockhash queue to hold max_age + 1 (max 301)
     entries. We have this incorrect logic implemented in fd_sysvar_recent_hashes:register_blockhash and it's not a
     huge issue, but something to keep in mind. */
  pb_bytes_array_t ** output_blockhash_queue = fd_spad_alloc(
                                                      spad,
                                                      alignof(pb_bytes_array_t *),
                                                      PB_BYTES_ARRAY_T_ALLOCSIZE( (FD_BLOCKHASH_QUEUE_MAX_ENTRIES + 1) * sizeof(pb_bytes_array_t *) ) );
  txn_context_msg->blockhash_queue_count = 0;
  txn_context_msg->blockhash_queue = output_blockhash_queue;

  // Iterate over all block hashes in the queue and save them
  fd_block_hash_queue_t const * queue = &txn_ctx->slot_bank->block_hash_queue;
  fd_hash_hash_age_pair_t_mapnode_t * nn;
  for ( fd_hash_hash_age_pair_t_mapnode_t * n = fd_hash_hash_age_pair_t_map_minimum( queue->ages_pool, queue->ages_root ); n; n = nn ) {
    nn = fd_hash_hash_age_pair_t_map_successor( queue->ages_pool, n );

    /* Get the index in the blockhash queue
       - Lower index = newer
       - 0 will be the most recent blockhash
       - Index range is [0, max_age] (not a typo) */
    ulong queue_index = queue->last_hash_index - n->elem.val.hash_index;
    fd_hash_t blockhash = n->elem.key;

    // Write the blockhash to the correct index (note we write in reverse order since in the Protobuf message, the oldest blockhash goes first)
    pb_bytes_array_t * output_blockhash = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( sizeof(fd_hash_t) ) );
    output_blockhash->size = sizeof(fd_hash_t);
    memcpy( output_blockhash->bytes, &blockhash, sizeof(fd_hash_t) );
    output_blockhash_queue[FD_BLOCKHASH_QUEUE_MAX_ENTRIES - queue_index] = output_blockhash;
    txn_context_msg->blockhash_queue_count++;
  }

  // Shift blockhash queue elements if num elements < 301
  if( txn_context_msg->blockhash_queue_count < FD_BLOCKHASH_QUEUE_MAX_ENTRIES + 1 ) {
    ulong index_offset = FD_BLOCKHASH_QUEUE_MAX_ENTRIES + 1 - txn_context_msg->blockhash_queue_count;
    for( ulong i = 0; i < txn_context_msg->blockhash_queue_count; i++ ) {
      output_blockhash_queue[i] = output_blockhash_queue[i + index_offset];
    }
  }

  /* Transaction Context -> epoch_ctx */
  txn_context_msg->has_epoch_ctx = true;
  txn_context_msg->epoch_ctx.has_features = true;
  dump_sorted_features( &txn_ctx->features, &txn_context_msg->epoch_ctx.features, spad );

  /* Transaction Context -> slot_ctx */
  txn_context_msg->has_slot_ctx  = true;
  txn_context_msg->slot_ctx.slot = txn_ctx->slot_bank->slot;
}

static void
create_instr_context_protobuf_from_instructions( fd_exec_test_instr_context_t * instr_context,
                                                 fd_exec_txn_ctx_t const *      txn_ctx,
                                                 fd_instr_info_t const *        instr ) {
  /* Prepare sysvar cache accounts */
  fd_pubkey_t const fd_relevant_sysvar_ids[] = {
    fd_sysvar_clock_id,
    fd_sysvar_epoch_schedule_id,
    fd_sysvar_epoch_rewards_id,
    fd_sysvar_fees_id,
    fd_sysvar_rent_id,
    fd_sysvar_slot_hashes_id,
    fd_sysvar_recent_block_hashes_id,
    fd_sysvar_stake_history_id,
    fd_sysvar_last_restart_slot_id,
    fd_sysvar_instructions_id,
  };
  const ulong num_sysvar_entries = (sizeof(fd_relevant_sysvar_ids) / sizeof(fd_pubkey_t));

  /* Program ID */
  fd_memcpy( instr_context->program_id, instr->program_id_pubkey.uc, sizeof(fd_pubkey_t) );

  /* Accounts */
  instr_context->accounts_count = (pb_size_t) txn_ctx->accounts_cnt;
  instr_context->accounts = fd_spad_alloc( txn_ctx->spad, alignof(fd_exec_test_acct_state_t), (instr_context->accounts_count + num_sysvar_entries + txn_ctx->executable_cnt) * sizeof(fd_exec_test_acct_state_t));
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    // Copy account information over
    fd_txn_account_t const *    txn_account    = &txn_ctx->accounts[i];
    fd_exec_test_acct_state_t * output_account = &instr_context->accounts[i];
    dump_account_state( txn_account, output_account, txn_ctx->spad );
  }

  /* Add sysvar cache variables */
  for( ulong i = 0; i < num_sysvar_entries; i++ ) {
    FD_TXN_ACCOUNT_DECL( txn_account );
    int ret = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, &fd_relevant_sysvar_ids[i], txn_account );
    if( ret != FD_ACC_MGR_SUCCESS ) {
      continue;
    }
    // Make sure the account doesn't exist in the output accounts yet
    int account_exists = 0;
    for( ulong j = 0; j < txn_ctx->accounts_cnt; j++ ) {
      if ( 0 == memcmp( txn_ctx->account_keys[j].key, fd_relevant_sysvar_ids[i].uc, sizeof(fd_pubkey_t) ) ) {
        account_exists = true;
        break;
      }
    }

    // Copy it into output
    if (!account_exists) {
      fd_exec_test_acct_state_t * output_account = &instr_context->accounts[instr_context->accounts_count++];
      dump_account_state( txn_account, output_account, txn_ctx->spad );
    }
  }

  /* Add executable accounts */
  for( ulong i = 0; i < txn_ctx->executable_cnt; i++ ) {
    FD_TXN_ACCOUNT_DECL( txn_account );
    int ret = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, txn_ctx->executable_accounts[i].pubkey, txn_account );
    if( ret != FD_ACC_MGR_SUCCESS ) {
      continue;
    }
    // Make sure the account doesn't exist in the output accounts yet
    bool account_exists = false;
    for( ulong j = 0; j < instr_context->accounts_count; j++ ) {
      if( 0 == memcmp( instr_context->accounts[j].address, txn_ctx->executable_accounts[i].pubkey->uc, sizeof(fd_pubkey_t) ) ) {
        account_exists = true;
        break;
      }
    }
    // Copy it into output
    if( !account_exists ) {
      fd_exec_test_acct_state_t * output_account = &instr_context->accounts[instr_context->accounts_count++];
      dump_account_state( txn_account, output_account, txn_ctx->spad );
    }
  }

  /* Instruction Accounts */
  instr_context->instr_accounts_count = (pb_size_t) instr->acct_cnt;
  instr_context->instr_accounts = fd_spad_alloc( txn_ctx->spad, alignof(fd_exec_test_instr_acct_t), instr_context->instr_accounts_count * sizeof(fd_exec_test_instr_acct_t) );
  for( ushort i = 0; i < instr->acct_cnt; i++ ) {
    fd_exec_test_instr_acct_t * output_instr_account = &instr_context->instr_accounts[i];

    uchar account_flag = instr->acct_flags[i];
    bool is_writable = account_flag & FD_INSTR_ACCT_FLAGS_IS_WRITABLE;
    bool is_signer = account_flag & FD_INSTR_ACCT_FLAGS_IS_SIGNER;

    output_instr_account->index = instr->acct_txn_idxs[i];
    output_instr_account->is_writable = is_writable;
    output_instr_account->is_signer = is_signer;
  }

  /* Data */
  instr_context->data = fd_spad_alloc( txn_ctx->spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( instr->data_sz ) );
  instr_context->data->size = (pb_size_t) instr->data_sz;
  fd_memcpy( instr_context->data->bytes, instr->data, instr->data_sz );

  /* Compute Units */
  instr_context->cu_avail = txn_ctx->compute_meter;

  /* Slot Context */
  instr_context->has_slot_context = true;

  /* Epoch Context */
  instr_context->has_epoch_context = true;
  instr_context->epoch_context.has_features = true;
  dump_sorted_features( &txn_ctx->features, &instr_context->epoch_context.features, txn_ctx->spad );
}

/***** PUBLIC APIs *****/

void
fd_dump_instr_to_protobuf( fd_exec_txn_ctx_t * txn_ctx,
                           fd_instr_info_t *   instr,
                           ushort              instruction_idx ) {
  FD_SPAD_FRAME_BEGIN( txn_ctx->spad ) {
    // Get base58-encoded tx signature
    const fd_ed25519_sig_t * signatures = fd_txn_get_signatures( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw );
    fd_ed25519_sig_t signature; fd_memcpy( signature, signatures[0], sizeof(fd_ed25519_sig_t) );
    char encoded_signature[FD_BASE58_ENCODED_64_SZ];
    ulong out_size;
    fd_base58_encode_64( signature, &out_size, encoded_signature );

    if (txn_ctx->capture_ctx->dump_proto_sig_filter) {
      ulong filter_strlen = (ulong) strlen(txn_ctx->capture_ctx->dump_proto_sig_filter);

      // Terminate early if the signature does not match
      if( memcmp( txn_ctx->capture_ctx->dump_proto_sig_filter, encoded_signature, filter_strlen < out_size ? filter_strlen : out_size ) ) {
        return;
      }
    }

    fd_exec_test_instr_context_t instr_context = FD_EXEC_TEST_INSTR_CONTEXT_INIT_DEFAULT;
    create_instr_context_protobuf_from_instructions( &instr_context, txn_ctx, instr );

    /* Output to file */
    ulong out_buf_size = 100 * 1024 * 1024;
    uint8_t * out = fd_spad_alloc( txn_ctx->spad, alignof(uchar) , out_buf_size );
    pb_ostream_t stream = pb_ostream_from_buffer( out, out_buf_size );
    if (pb_encode(&stream, FD_EXEC_TEST_INSTR_CONTEXT_FIELDS, &instr_context)) {
      char output_filepath[256]; fd_memset(output_filepath, 0, sizeof(output_filepath));
      char * position = fd_cstr_init(output_filepath);
      position = fd_cstr_append_cstr(position, txn_ctx->capture_ctx->dump_proto_output_dir);
      position = fd_cstr_append_cstr(position, "/instr-");
      position = fd_cstr_append_cstr(position, encoded_signature);
      position = fd_cstr_append_cstr(position, "-");
      position = fd_cstr_append_ushort_as_text(position, '0', 0, instruction_idx, 3); // Assume max 3 digits
      position = fd_cstr_append_cstr(position, ".bin");
      fd_cstr_fini(position);

      FILE * file = fopen(output_filepath, "wb");
      if( file ) {
        fwrite( out, 1, stream.bytes_written, file );
        fclose( file );
      }
    }
  } FD_SPAD_FRAME_END;
}

void
fd_dump_txn_to_protobuf( fd_exec_txn_ctx_t * txn_ctx, fd_spad_t * spad ) {
  FD_SPAD_FRAME_BEGIN( spad ) {
    // Get base58-encoded tx signature
    const fd_ed25519_sig_t * signatures = fd_txn_get_signatures( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw );
    fd_ed25519_sig_t signature; fd_memcpy( signature, signatures[0], sizeof(fd_ed25519_sig_t) );
    char encoded_signature[FD_BASE58_ENCODED_64_SZ];
    ulong out_size;
    fd_base58_encode_64( signature, &out_size, encoded_signature );

    if( txn_ctx->capture_ctx->dump_proto_sig_filter ) {
      // Terminate early if the signature does not match
      if( strcmp( txn_ctx->capture_ctx->dump_proto_sig_filter, encoded_signature ) ) {
        return;
      }
    }

    fd_exec_test_txn_context_t txn_context_msg = FD_EXEC_TEST_TXN_CONTEXT_INIT_DEFAULT;
    create_txn_context_protobuf_from_txn( &txn_context_msg, txn_ctx, spad );

    /* Output to file */
    ulong out_buf_size = 100 * 1024 * 1024;
    uint8_t * out = fd_spad_alloc( spad, alignof(uint8_t), out_buf_size );
    pb_ostream_t stream = pb_ostream_from_buffer( out, out_buf_size );
    if( pb_encode( &stream, FD_EXEC_TEST_TXN_CONTEXT_FIELDS, &txn_context_msg ) ) {
      char output_filepath[256]; fd_memset( output_filepath, 0, sizeof(output_filepath) );
      char * position = fd_cstr_init( output_filepath );
      position = fd_cstr_append_cstr( position, txn_ctx->capture_ctx->dump_proto_output_dir );
      position = fd_cstr_append_cstr( position, "/txn-" );
      position = fd_cstr_append_cstr( position, encoded_signature );
      position = fd_cstr_append_cstr(position, ".bin");
      fd_cstr_fini(position);

      FILE * file = fopen(output_filepath, "wb");
      if( file ) {
        fwrite( out, 1, stream.bytes_written, file );
        fclose( file );
      }
    }
  } FD_SPAD_FRAME_END;
}


void
fd_dump_vm_cpi_state( fd_vm_t *    vm,
                      char const * fn_name,
                      ulong        instruction_va,
                      ulong        acct_infos_va,
                      ulong        acct_info_cnt,
                      ulong        signers_seeds_va,
                      ulong        signers_seeds_cnt ) {
  char filename[100];
  fd_instr_info_t const *instr = vm->instr_ctx->instr;
  sprintf(filename, "vm_cpi_state/%lu_%lu%lu_%hu.sysctx", fd_tile_id(), instr->program_id_pubkey.ul[0], instr->program_id_pubkey.ul[1], instr->data_sz);

  // Check if file exists
  if( access (filename, F_OK) != -1 ) {
    return;
  }

  fd_exec_test_syscall_context_t sys_ctx = FD_EXEC_TEST_SYSCALL_CONTEXT_INIT_ZERO;
  sys_ctx.has_instr_ctx = 1;
  sys_ctx.has_vm_ctx = 1;
  sys_ctx.has_syscall_invocation = 1;

  // Copy function name
  sys_ctx.syscall_invocation.function_name.size = fd_uint_min( (uint) strlen(fn_name), sizeof(sys_ctx.syscall_invocation.function_name.bytes) );
  fd_memcpy( sys_ctx.syscall_invocation.function_name.bytes,
             fn_name,
             sys_ctx.syscall_invocation.function_name.size );

  // VM Ctx integral fields
  sys_ctx.vm_ctx.r1 = instruction_va;
  sys_ctx.vm_ctx.r2 = acct_infos_va;
  sys_ctx.vm_ctx.r3 = acct_info_cnt;
  sys_ctx.vm_ctx.r4 = signers_seeds_va;
  sys_ctx.vm_ctx.r5 = signers_seeds_cnt;

  sys_ctx.vm_ctx.rodata_text_section_length = vm->text_sz;
  sys_ctx.vm_ctx.rodata_text_section_offset = vm->text_off;

  sys_ctx.vm_ctx.heap_max = vm->heap_max; /* should be equiv. to txn_ctx->heap_sz */

  FD_SPAD_FRAME_BEGIN( vm->instr_ctx->txn_ctx->spad ) {
    sys_ctx.vm_ctx.rodata = fd_spad_alloc( vm->instr_ctx->txn_ctx->spad, 8UL, PB_BYTES_ARRAY_T_ALLOCSIZE( vm->rodata_sz ) );
    sys_ctx.vm_ctx.rodata->size = (pb_size_t) vm->rodata_sz;
    fd_memcpy( sys_ctx.vm_ctx.rodata->bytes, vm->rodata, vm->rodata_sz );

    pb_size_t stack_sz = (pb_size_t) ( (vm->frame_cnt + 1)*FD_VM_STACK_GUARD_SZ*2 );
    sys_ctx.syscall_invocation.stack_prefix = fd_spad_alloc( vm->instr_ctx->txn_ctx->spad, 8UL, PB_BYTES_ARRAY_T_ALLOCSIZE( stack_sz ) );
    sys_ctx.syscall_invocation.stack_prefix->size = stack_sz;
    fd_memcpy( sys_ctx.syscall_invocation.stack_prefix->bytes, vm->stack, stack_sz );

    sys_ctx.syscall_invocation.heap_prefix = fd_spad_alloc( vm->instr_ctx->txn_ctx->spad, 8UL, PB_BYTES_ARRAY_T_ALLOCSIZE( vm->heap_max ) );
    sys_ctx.syscall_invocation.heap_prefix->size = (pb_size_t) vm->instr_ctx->txn_ctx->heap_size;
    fd_memcpy( sys_ctx.syscall_invocation.heap_prefix->bytes, vm->heap, vm->instr_ctx->txn_ctx->heap_size );

    create_instr_context_protobuf_from_instructions( &sys_ctx.instr_ctx,
                                                        vm->instr_ctx->txn_ctx,
                                                        vm->instr_ctx->instr );

    // Serialize the protobuf to file (using mmap)
    size_t pb_alloc_size = 100 * 1024 * 1024; // 100MB (largest so far is 19MB)
    FILE *f = fopen(filename, "wb+");
    if( ftruncate(fileno(f), (off_t) pb_alloc_size) != 0 ) {
      FD_LOG_WARNING(("Failed to resize file %s", filename));
      fclose(f);
      return;
    }

    uchar *pb_alloc = mmap( NULL,
                            pb_alloc_size,
                            PROT_READ | PROT_WRITE,
                            MAP_SHARED,
                            fileno(f),
                            0 /* offset */);
    if( pb_alloc == MAP_FAILED ) {
      FD_LOG_WARNING(( "Failed to mmap file %d", errno ));
      fclose(f);
      return;
    }

    pb_ostream_t stream = pb_ostream_from_buffer(pb_alloc, pb_alloc_size);
    if( !pb_encode( &stream, FD_EXEC_TEST_SYSCALL_CONTEXT_FIELDS, &sys_ctx ) ) {
      FD_LOG_WARNING(( "Failed to encode instruction context" ));
    }
    // resize file to actual size
    if( ftruncate( fileno(f), (off_t) stream.bytes_written ) != 0 ) {
      FD_LOG_WARNING(( "Failed to resize file %s", filename ));
    }

    fclose(f);

  } FD_SPAD_FRAME_END;
}
