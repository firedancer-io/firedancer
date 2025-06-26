#include "fd_dump_pb.h"
#include "harness/generated/block.pb.h"
#include "harness/generated/invoke.pb.h"
#include "harness/generated/txn.pb.h"
#include "harness/generated/vm.pb.h"
#include "../fd_system_ids.h"
#include "../fd_runtime.h"
#include "../program/fd_address_lookup_table_program.h"
#include "../../../ballet/lthash/fd_lthash.h"
#include "../../../ballet/nanopb/pb_encode.h"
#include "../program/fd_bpf_program_util.h"


#include <errno.h>
#include <stdio.h> /* fopen */
#include <sys/mman.h> /* mmap */
#include <unistd.h> /* ftruncate */

#define SORT_NAME        sort_uint64_t
#define SORT_KEY_T       uint64_t
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../../util/tmpl/fd_sort.c"

/***** UTILITY FUNCTIONS *****/

/** GENERAL UTILITY FUNCTIONS AND MACROS **/

static int
is_builtin_account( fd_pubkey_t const * loaded_builtins,
                    ulong               num_loaded_builtins,
                    fd_pubkey_t const * account_key ) {
  for( ulong j = 0; j < num_loaded_builtins; ++j ) {
    if( !memcmp( account_key, &loaded_builtins[j], sizeof(fd_pubkey_t) ) ) {
      return 1;
    }
  }
  return 0;
}

/** FEATURE DUMPING **/
static void
dump_sorted_features( fd_features_t const * features,
                      fd_exec_test_feature_set_t * output_feature_set,
                      fd_spad_t * spad ) {
  /* NOTE: Caller must have a spad frame prepared */
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

/** ACCOUNT DUMPING **/
static void
dump_account_state( fd_txn_account_t const *    txn_account,
                    fd_exec_test_acct_state_t * output_account,
                    fd_spad_t *                 spad ) {
    // Address
    fd_memcpy(output_account->address, txn_account->pubkey, sizeof(fd_pubkey_t));

    // Lamports
    output_account->lamports = (uint64_t) txn_account->vt->get_lamports( txn_account );

    // Data
    output_account->data = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( txn_account->vt->get_data_len( txn_account ) ) );
    output_account->data->size = (pb_size_t) txn_account->vt->get_data_len( txn_account );
    fd_memcpy(output_account->data->bytes, txn_account->vt->get_data( txn_account ), txn_account->vt->get_data_len( txn_account ) );

    // Executable
    output_account->executable = (bool) txn_account->vt->is_executable( txn_account );

    // Rent epoch
    output_account->rent_epoch = (uint64_t) txn_account->vt->get_rent_epoch( txn_account );

    // Owner
    fd_memcpy(output_account->owner, txn_account->vt->get_owner( txn_account ), sizeof(fd_pubkey_t));

    // Seed address (not present)
    output_account->has_seed_addr = false;
}

static uchar
account_already_dumped( fd_exec_test_acct_state_t const * dumped_accounts,
                        ulong                             dumped_cnt,
                        fd_pubkey_t const *               account_key ) {
  for( ulong i=0UL; i<dumped_cnt; i++ ) {
    if( !memcmp( account_key, dumped_accounts[i].address, sizeof(fd_pubkey_t) ) ) {
      return 1;
    }
  }
  return 0;
}

/* Dumps a borrowed account if it exists and has not been dumped yet. Sets up the output borrowed
   account if it exists. Returns 0 if the account exists, 1 otherwise. */
static uchar
dump_account_if_not_already_dumped( fd_funk_t const *           funk,
                                    fd_funk_txn_t const *       funk_txn,
                                    fd_pubkey_t const *         account_key,
                                    fd_spad_t *                 spad,
                                    fd_exec_test_acct_state_t * out_acct_states,
                                    pb_size_t *                 out_acct_states_cnt,
                                    fd_txn_account_t *          opt_out_borrowed_account ) {
  FD_TXN_ACCOUNT_DECL( account );
  if( fd_txn_account_init_from_funk_readonly( account, account_key, funk, funk_txn ) ) {
    return 1;
  }

  if( !account_already_dumped( out_acct_states, *out_acct_states_cnt, account_key ) ) {
    dump_account_state( account, &out_acct_states[*out_acct_states_cnt], spad );
    (*out_acct_states_cnt)++;
  }

  if( opt_out_borrowed_account ) {
    *opt_out_borrowed_account = *account;
  }
  return 0;
}

/* TODO: This can be made slightly more efficient by dumping only the referenced ALUT accounts instead of all accounts */
static void
dump_lut_account_and_contained_accounts(  fd_exec_slot_ctx_t const *     slot_ctx,
                                          uchar const *                  txn_payload,
                                          fd_txn_acct_addr_lut_t const * lookup_table,
                                          fd_spad_t *                    spad,
                                          fd_exec_test_acct_state_t *    out_account_states,
                                          pb_size_t *                    out_account_states_count ) {
  FD_TXN_ACCOUNT_DECL( alut_account );
  fd_pubkey_t const * alut_pubkey = (fd_pubkey_t const *)((uchar *)txn_payload + lookup_table->addr_off);
  uchar account_exists = dump_account_if_not_already_dumped( slot_ctx->funk, slot_ctx->funk_txn, alut_pubkey, spad, out_account_states, out_account_states_count, alut_account );
  if( !account_exists || alut_account->vt->get_data_len( alut_account )<FD_LOOKUP_TABLE_META_SIZE ) {
    return;
  }

  /* Decode the ALUT account and find its referenced writable and readonly indices */
  if( alut_account->vt->get_data_len( alut_account ) & 0x1fUL ) {
    return;
  }

  fd_pubkey_t * lookup_addrs = (fd_pubkey_t *)&alut_account->vt->get_data( alut_account )[FD_LOOKUP_TABLE_META_SIZE];
  ulong lookup_addrs_cnt     = ( alut_account->vt->get_data_len( alut_account ) - FD_LOOKUP_TABLE_META_SIZE ) >> 5UL; // = (dlen - 56) / 32
  for( ulong i=0UL; i<lookup_addrs_cnt; i++ ) {
    fd_pubkey_t const * referenced_pubkey = &lookup_addrs[i];
    dump_account_if_not_already_dumped( slot_ctx->funk, slot_ctx->funk_txn, referenced_pubkey, spad, out_account_states, out_account_states_count, NULL );
  }
}

static void
dump_executable_account_if_exists( fd_funk_t const *                 funk,
                                   fd_funk_txn_t const *             funk_txn,
                                   fd_exec_test_acct_state_t const * program_account,
                                   fd_spad_t *                       spad,
                                   fd_exec_test_acct_state_t *       out_account_states,
                                   pb_size_t *                       out_account_states_count ) {
  if( FD_LIKELY( memcmp( program_account->owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return;
  }

  int err;
  fd_bpf_upgradeable_loader_state_t * program_loader_state = fd_bincode_decode_spad(
      bpf_upgradeable_loader_state,
      spad,
      program_account->data->bytes,
      program_account->data->size,
      &err );
  if( FD_UNLIKELY( err ) ) return;

  if( !fd_bpf_upgradeable_loader_state_is_program( program_loader_state ) ) {
    return;
  }

  fd_pubkey_t * programdata_acc = &program_loader_state->inner.program.programdata_address;
  dump_account_if_not_already_dumped( funk, funk_txn, programdata_acc, spad, out_account_states, out_account_states_count, NULL );
}

/** VOTE ACCOUNTS DUMPING **/
static void
dump_vote_accounts( fd_exec_slot_ctx_t const *        slot_ctx,
                    fd_vote_accounts_global_t const * vote_accounts,
                    fd_spad_t *                       spad,
                    fd_exec_test_vote_account_t **    out_vote_accounts,
                    pb_size_t *                       out_vote_accounts_count,
                    fd_exec_test_acct_state_t *       out_acct_states,
                    pb_size_t *                       out_acct_states_cnt ) {

  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_pool = fd_vote_accounts_vote_accounts_pool_join( vote_accounts );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root = fd_vote_accounts_vote_accounts_root_join( vote_accounts );

  pb_size_t idx            = 0UL;
  ulong vote_account_t_cnt = fd_vote_accounts_pair_global_t_map_size( vote_accounts_pool,
                                                                      vote_accounts_root );
  fd_exec_test_vote_account_t * vote_account_out = fd_spad_alloc( spad,
                                                                  alignof(fd_exec_test_vote_account_t),
                                                                  vote_account_t_cnt * sizeof(fd_exec_test_vote_account_t) );

  for( fd_vote_accounts_pair_global_t_mapnode_t const * curr = fd_vote_accounts_pair_global_t_map_minimum_const(
          vote_accounts_pool,
          vote_accounts_root );
       curr;
       curr = fd_vote_accounts_pair_global_t_map_successor_const( vote_accounts_pool, curr ) ) {
    fd_exec_test_vote_account_t * vote_out = &vote_account_out[idx++];

    vote_out->has_vote_account           = true;
    vote_out->stake                      = curr->elem.stake;
    vote_out->vote_account.lamports      = curr->elem.value.lamports;
    vote_out->vote_account.rent_epoch    = curr->elem.value.rent_epoch;
    vote_out->vote_account.executable    = curr->elem.value.executable;
    vote_out->vote_account.has_seed_addr = false;

    fd_memcpy( &vote_out->vote_account.address, &curr->elem.key, sizeof(fd_pubkey_t) );
    fd_memcpy( &vote_out->vote_account.owner, &curr->elem.value.owner, sizeof(fd_pubkey_t) );

    vote_out->vote_account.data = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( curr->elem.value.data_len ) );
    vote_out->vote_account.data->size = (pb_size_t) curr->elem.value.data_len;

    uchar * data = fd_solana_account_data_join( &curr->elem.value );
    fd_memcpy( &vote_out->vote_account.data->bytes, data, curr->elem.value.data_len );

    // Dump the vote account
    dump_account_if_not_already_dumped( slot_ctx->funk, slot_ctx->funk_txn, &curr->elem.key, spad, out_acct_states, out_acct_states_cnt, NULL );
  }

  *out_vote_accounts       = vote_account_out;
  *out_vote_accounts_count = idx;
}

/** TRANSACTION DUMPING **/

static void
dump_sanitized_transaction( fd_funk_t *                            funk,
                            fd_funk_txn_t const *                  funk_txn,
                            fd_txn_t const *                       txn_descriptor,
                            uchar const *                          txn_payload,
                            fd_spad_t *                            spad,
                            fd_exec_test_sanitized_transaction_t * sanitized_transaction ) {
  fd_txn_acct_addr_lut_t const * address_lookup_tables = fd_txn_get_address_tables_const( txn_descriptor );

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
  message->account_keys = fd_spad_alloc( spad, alignof(pb_bytes_array_t *), PB_BYTES_ARRAY_T_ALLOCSIZE(txn_descriptor->acct_addr_cnt * sizeof(pb_bytes_array_t *)) );
  fd_acct_addr_t const * account_keys = fd_txn_get_acct_addrs( txn_descriptor, txn_payload );
  for( ulong i = 0; i < txn_descriptor->acct_addr_cnt; i++ ) {
    pb_bytes_array_t * account_key = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE(sizeof(fd_pubkey_t)) );
    account_key->size = sizeof(fd_pubkey_t);
    memcpy( account_key->bytes, &account_keys[i], sizeof(fd_pubkey_t) );
    message->account_keys[i] = account_key;
  }

  /* Transaction Context -> tx -> message -> recent_blockhash */
  uchar const * recent_blockhash = fd_txn_get_recent_blockhash( txn_descriptor, txn_payload );
  message->recent_blockhash = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE(sizeof(fd_hash_t)) );
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
    compiled_instruction->data = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE(instr.data_sz) );
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
      FD_TXN_ACCOUNT_DECL(addr_lut_rec);
      int err = fd_txn_account_init_from_funk_readonly( addr_lut_rec, alut_key, funk, funk_txn );
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
  sanitized_transaction->signatures = fd_spad_alloc( spad, alignof(pb_bytes_array_t *), PB_BYTES_ARRAY_T_ALLOCSIZE(txn_descriptor->signature_cnt * sizeof(pb_bytes_array_t *)) );
  fd_ed25519_sig_t const * signatures = fd_txn_get_signatures( txn_descriptor, txn_payload );
  for( uchar i = 0; i < txn_descriptor->signature_cnt; ++i ) {
    pb_bytes_array_t * signature = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE(sizeof(fd_ed25519_sig_t)) );
    signature->size = sizeof(fd_ed25519_sig_t);
    memcpy( signature->bytes, &signatures[i], sizeof(fd_ed25519_sig_t) );
    sanitized_transaction->signatures[i] = signature;
  }
}

/** BLOCKHASH QUEUE DUMPING **/

static void
dump_blockhash_queue( fd_block_hash_queue_global_t const * queue,
                      fd_spad_t *                          spad,
                      pb_bytes_array_t **                  output_blockhash_queue,
                      pb_size_t *                          output_blockhash_queue_count ) {
  pb_size_t cnt = 0;
  fd_hash_hash_age_pair_t_mapnode_t * nn;

  fd_hash_hash_age_pair_t_mapnode_t * ages_pool = fd_block_hash_queue_ages_pool_join( queue );
  fd_hash_hash_age_pair_t_mapnode_t * ages_root = fd_block_hash_queue_ages_root_join( queue );

  // Iterate over all block hashes in the queue and save them in the output
  for( fd_hash_hash_age_pair_t_mapnode_t * n = fd_hash_hash_age_pair_t_map_minimum( ages_pool, ages_root ); n; n = nn ) {
    nn = fd_hash_hash_age_pair_t_map_successor( ages_pool, n );

    /* Get the index in the blockhash queue
       - Lower index = newer
       - 0 will be the most recent blockhash
       - Index range is [0, max_age] (not a typo) */
    ulong queue_index = queue->last_hash_index - n->elem.val.hash_index;
    fd_hash_t blockhash = n->elem.key;

    // Write the blockhash to the correct index (note we write in reverse order since in the Protobuf message, the oldest blockhash goes first)
    pb_bytes_array_t * output_blockhash = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE(sizeof(fd_hash_t)) );
    output_blockhash->size = sizeof(fd_hash_t);
    fd_memcpy( output_blockhash->bytes, &blockhash, sizeof(fd_hash_t) );
    output_blockhash_queue[FD_BLOCKHASH_QUEUE_MAX_ENTRIES - queue_index] = output_blockhash;
    cnt++;
  }

  // Shift blockhash queue elements if num elements < 301
  if( cnt<FD_BLOCKHASH_QUEUE_MAX_ENTRIES + 1UL ) {
    ulong index_offset = FD_BLOCKHASH_QUEUE_MAX_ENTRIES + 1UL - cnt;
    for( pb_size_t i=0; i<cnt; i++ ) {
      output_blockhash_queue[i] = output_blockhash_queue[i + index_offset];
    }
  }

  *output_blockhash_queue_count = cnt;
}

/** SECONDARY FUNCTIONS **/

static void
create_block_context_protobuf_from_block( fd_exec_test_block_context_t * block_context,
                                          fd_exec_slot_ctx_t const *     slot_ctx,
                                          fd_spad_t *                    spad ) {

  /* BlockContext -> acct_states */
  // Dump sysvars + builtins
  fd_pubkey_t const fd_relevant_sysvar_ids[] = {
    fd_sysvar_recent_block_hashes_id,
    fd_sysvar_clock_id,
    fd_sysvar_slot_history_id,
    fd_sysvar_slot_hashes_id,
    fd_sysvar_epoch_schedule_id,
    fd_sysvar_epoch_rewards_id,
    fd_sysvar_fees_id,
    fd_sysvar_rent_id,
    fd_sysvar_stake_history_id,
    fd_sysvar_last_restart_slot_id,
  };

  fd_pubkey_t const loaded_builtins[] = {
    fd_solana_system_program_id,
    fd_solana_vote_program_id,
    fd_solana_stake_program_id,
    fd_solana_config_program_id,
    fd_solana_zk_token_proof_program_id,
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
  };
  ulong num_sysvar_entries    = (sizeof(fd_relevant_sysvar_ids) / sizeof(fd_pubkey_t));
  ulong num_loaded_builtins   = (sizeof(loaded_builtins) / sizeof(fd_pubkey_t));

  fd_account_keys_global_t const *   stake_account_keys      = fd_bank_stake_account_keys_locking_query( slot_ctx->bank );
  fd_account_keys_pair_t_mapnode_t * stake_account_keys_pool = fd_account_keys_account_keys_pool_join( stake_account_keys );
  fd_account_keys_pair_t_mapnode_t * stake_account_keys_root = fd_account_keys_account_keys_root_join( stake_account_keys );


  fd_stakes_global_t const * stakes = fd_bank_stakes_locking_query( slot_ctx->bank );
  fd_delegation_pair_t_mapnode_t * stake_delegations_pool = fd_stakes_stake_delegations_pool_join( stakes );
  fd_delegation_pair_t_mapnode_t * stake_delegations_root = fd_stakes_stake_delegations_root_join( stakes );

  fd_vote_accounts_pair_global_t_mapnode_t * stakes_vote_accounts_pool = fd_vote_accounts_vote_accounts_pool_join( &stakes->vote_accounts );
  fd_vote_accounts_pair_global_t_mapnode_t * stakes_vote_accounts_root = fd_vote_accounts_vote_accounts_root_join( &stakes->vote_accounts );

  ulong new_stake_account_cnt = fd_account_keys_pair_t_map_size( stake_account_keys_pool, stake_account_keys_root );
  ulong stake_account_cnt     = fd_delegation_pair_t_map_size( stake_delegations_pool,
                                                               stake_delegations_root );

  ulong vote_account_t_cnt    = fd_vote_accounts_pair_global_t_map_size( stakes_vote_accounts_pool,
                                                                         stakes_vote_accounts_root );

  fd_bank_stake_account_keys_end_locking_query( slot_ctx->bank );
  fd_bank_stakes_end_locking_query( slot_ctx->bank );


  fd_vote_accounts_global_t const * next_epoch_stakes = fd_bank_next_epoch_stakes_locking_query( slot_ctx->bank );
  fd_vote_accounts_pair_global_t_mapnode_t * next_epoch_stakes_pool = fd_vote_accounts_vote_accounts_pool_join( next_epoch_stakes );
  fd_vote_accounts_pair_global_t_mapnode_t * next_epoch_stakes_root = fd_vote_accounts_vote_accounts_root_join( next_epoch_stakes );
  ulong vote_account_t_1_cnt  = fd_vote_accounts_pair_global_t_map_size( next_epoch_stakes_pool,
                                                                         next_epoch_stakes_root );
  fd_bank_next_epoch_stakes_end_locking_query( slot_ctx->bank );

  fd_vote_accounts_global_t const * epoch_stakes = fd_bank_epoch_stakes_locking_query( slot_ctx->bank );
  fd_vote_accounts_pair_global_t_mapnode_t * epoch_stakes_pool = fd_vote_accounts_vote_accounts_pool_join( epoch_stakes );
  fd_vote_accounts_pair_global_t_mapnode_t * epoch_stakes_root = fd_vote_accounts_vote_accounts_root_join( epoch_stakes );
  ulong vote_account_t_2_cnt  = fd_vote_accounts_pair_global_t_map_size( epoch_stakes_pool,
                                                                         epoch_stakes_root );
  fd_bank_epoch_stakes_end_locking_query( slot_ctx->bank );

  ulong total_num_accounts    = num_sysvar_entries +
                                num_loaded_builtins +
                                new_stake_account_cnt +
                                stake_account_cnt +
                                stake_account_cnt +
                                vote_account_t_cnt +
                                vote_account_t_1_cnt +
                                vote_account_t_2_cnt;

  block_context->acct_states_count = 0;
  block_context->acct_states       = fd_spad_alloc( spad,
                                                    alignof(fd_exec_test_acct_state_t),
                                                    total_num_accounts * sizeof(fd_exec_test_acct_state_t) );


  for( ulong i=0UL; i<num_sysvar_entries; i++ ) {
    dump_account_if_not_already_dumped( slot_ctx->funk, slot_ctx->funk_txn, &fd_relevant_sysvar_ids[i], spad, block_context->acct_states, &block_context->acct_states_count, NULL );
  }

  for( ulong i=0UL; i<num_loaded_builtins; i++ ) {
    dump_account_if_not_already_dumped( slot_ctx->funk, slot_ctx->funk_txn, &loaded_builtins[i], spad, block_context->acct_states, &block_context->acct_states_count, NULL );
  }

  /* BlockContext -> blockhash_queue */
  pb_bytes_array_t ** output_blockhash_queue = fd_spad_alloc( spad,
                                                              alignof(pb_bytes_array_t *),
                                                              PB_BYTES_ARRAY_T_ALLOCSIZE((FD_BLOCKHASH_QUEUE_MAX_ENTRIES + 1) * sizeof(pb_bytes_array_t *)) );
  block_context->blockhash_queue = output_blockhash_queue;

  fd_block_hash_queue_global_t * bhq      = (fd_block_hash_queue_global_t *)&slot_ctx->bank->block_hash_queue[0];
  dump_blockhash_queue( bhq, spad, block_context->blockhash_queue, &block_context->blockhash_queue_count );

  /* BlockContext -> SlotContext */
  block_context->has_slot_ctx                       = true;
  block_context->slot_ctx.slot                      = slot_ctx->slot;
  // HACK FOR NOW: block height gets incremented in process_new_epoch, so we should dump block height + 1
  block_context->slot_ctx.block_height              = fd_bank_block_height_get( slot_ctx->bank ) + 1UL;
  // fd_memcpy( block_context->slot_ctx.poh, &slot_ctx->slot_bank.poh, sizeof(fd_pubkey_t) ); // TODO: dump here when process epoch happens after poh verification
  fd_memcpy( block_context->slot_ctx.parent_bank_hash, fd_bank_bank_hash_query( slot_ctx->bank ), sizeof(fd_pubkey_t) );
  block_context->slot_ctx.prev_slot                 = fd_bank_prev_slot_get( slot_ctx->bank );
  block_context->slot_ctx.prev_lps                  = fd_bank_prev_lamports_per_signature_get( slot_ctx->bank );
  block_context->slot_ctx.prev_epoch_capitalization = fd_bank_capitalization_get( slot_ctx->bank );

  /* BlockContext -> EpochContext */
  block_context->has_epoch_ctx                        = true;
  block_context->epoch_ctx.has_features               = true;
  dump_sorted_features( fd_bank_features_query( slot_ctx->bank ), &block_context->epoch_ctx.features, spad );
  block_context->epoch_ctx.hashes_per_tick            = fd_bank_hashes_per_tick_get( slot_ctx->bank );
  block_context->epoch_ctx.ticks_per_slot             = fd_bank_ticks_per_slot_get( slot_ctx->bank );
  block_context->epoch_ctx.slots_per_year             = fd_bank_slots_per_year_get( slot_ctx->bank );
  block_context->epoch_ctx.has_inflation              = true;

  fd_inflation_t const * inflation = fd_bank_inflation_query( slot_ctx->bank );
  block_context->epoch_ctx.inflation                  = (fd_exec_test_inflation_t) {
    .initial         = inflation->initial,
    .terminal        = inflation->terminal,
    .taper           = inflation->taper,
    .foundation      = inflation->foundation,
    .foundation_term = inflation->foundation_term,
  };
  block_context->epoch_ctx.genesis_creation_time      = fd_bank_genesis_creation_time_get( slot_ctx->bank );

  /* Dumping stake accounts for this epoch */

  stakes = fd_bank_stakes_locking_query( slot_ctx->bank );
  stake_delegations_pool = fd_stakes_stake_delegations_pool_join( stakes );
  stake_delegations_root = fd_stakes_stake_delegations_root_join( stakes );

  /* Dumping all existing stake accounts */
  for( fd_delegation_pair_t_mapnode_t const * curr = fd_delegation_pair_t_map_minimum_const(
          stake_delegations_pool,
          stake_delegations_root );
       curr;
       curr = fd_delegation_pair_t_map_successor_const( stake_delegations_pool, curr ) ) {
    dump_account_if_not_already_dumped( slot_ctx->funk, slot_ctx->funk_txn, &curr->elem.account, spad, block_context->acct_states, &block_context->acct_states_count, NULL );
  }

  fd_bank_stakes_end_locking_query( slot_ctx->bank );

  stake_account_keys = fd_bank_stake_account_keys_locking_query( slot_ctx->bank );
  stake_account_keys_pool = fd_account_keys_account_keys_pool_join( stake_account_keys );
  stake_account_keys_root = fd_account_keys_account_keys_root_join( stake_account_keys );

  /* Dump all new stake accounts */
  for( fd_account_keys_pair_t_mapnode_t const * curr = fd_account_keys_pair_t_map_minimum_const(
          stake_account_keys_pool,
          stake_account_keys_root );
       curr;
       curr = fd_account_keys_pair_t_map_successor_const( stake_account_keys_pool, curr ) ) {
    dump_account_if_not_already_dumped( slot_ctx->funk, slot_ctx->funk_txn, &curr->elem.key, spad, block_context->acct_states, &block_context->acct_states_count, NULL );
  }

  fd_bank_stake_account_keys_end_locking_query( slot_ctx->bank );

  /* Dumping vote accounts for this epoch */

  stakes = fd_bank_stakes_locking_query( slot_ctx->bank );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_pool = fd_vote_accounts_vote_accounts_pool_join( &stakes->vote_accounts );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root = fd_vote_accounts_vote_accounts_root_join( &stakes->vote_accounts );

  /* Dump all existing vote accounts */
  for( fd_vote_accounts_pair_global_t_mapnode_t const * curr = fd_vote_accounts_pair_global_t_map_minimum_const(
          vote_accounts_pool,
          vote_accounts_root );
       curr;
       curr = fd_vote_accounts_pair_global_t_map_successor_const( vote_accounts_pool, curr ) ) {
    dump_account_if_not_already_dumped( slot_ctx->funk, slot_ctx->funk_txn, &curr->elem.key, spad, block_context->acct_states, &block_context->acct_states_count, NULL );
  }

  fd_bank_stakes_end_locking_query( slot_ctx->bank );

  fd_account_keys_global_t const * vote_account_keys = fd_bank_vote_account_keys_locking_query( slot_ctx->bank );
  fd_account_keys_pair_t_mapnode_t * vote_account_keys_pool = fd_account_keys_account_keys_pool_join( vote_account_keys );
  fd_account_keys_pair_t_mapnode_t * vote_account_keys_root = fd_account_keys_account_keys_root_join( vote_account_keys );


  /* Dump all new vote accounts */
  for( fd_account_keys_pair_t_mapnode_t const * curr = fd_account_keys_pair_t_map_minimum_const(
          vote_account_keys_pool,
          vote_account_keys_root );
       curr;
       curr = fd_account_keys_pair_t_map_successor_const( vote_account_keys_pool, curr ) ) {
    dump_account_if_not_already_dumped( slot_ctx->funk, slot_ctx->funk_txn, &curr->elem.key, spad, block_context->acct_states, &block_context->acct_states_count, NULL );
  }

  fd_bank_vote_account_keys_end_locking_query( slot_ctx->bank );

  // BlockContext -> EpochContext -> vote_accounts_t_1 (vote accounts at epoch T-1)
  fd_vote_accounts_global_t const * next_epoch_stakes_vaccs = fd_bank_next_epoch_stakes_locking_query( slot_ctx->bank );
  dump_vote_accounts( slot_ctx,
                      next_epoch_stakes_vaccs,
                      spad,
                      &block_context->epoch_ctx.vote_accounts_t_1,
                      &block_context->epoch_ctx.vote_accounts_t_1_count,
                      block_context->acct_states,
                      &block_context->acct_states_count );

  // BlockContext -> EpochContext -> vote_accounts_t_2 (vote accounts at epoch T-2)
  fd_vote_accounts_global_t const * epoch_stakes_vaccs = fd_bank_epoch_stakes_locking_query( slot_ctx->bank );
  dump_vote_accounts( slot_ctx,
                      epoch_stakes_vaccs,
                      spad,
                      &block_context->epoch_ctx.vote_accounts_t_2,
                      &block_context->epoch_ctx.vote_accounts_t_2_count,
                      block_context->acct_states,
                      &block_context->acct_states_count );
  fd_bank_epoch_stakes_end_locking_query( slot_ctx->bank );
}

static void
create_block_context_protobuf_from_block_tx_only( fd_exec_test_block_context_t *  block_context,
                                                  fd_runtime_block_info_t const * block_info,
                                                  fd_exec_slot_ctx_t const *      slot_ctx,
                                                  fd_spad_t *                     spad ) {
  /* BlockContext -> txns */
  block_context->txns_count = 0U;
  block_context->txns       = fd_spad_alloc( spad, alignof(fd_exec_test_sanitized_transaction_t), block_info->txn_cnt * sizeof(fd_exec_test_sanitized_transaction_t) );
  fd_memset( block_context->txns, 0, block_info->txn_cnt * sizeof(fd_exec_test_sanitized_transaction_t) );

  /* BlockContext -> acct_states
     Allocate additional space for the remaining accounts */
  fd_exec_test_acct_state_t * current_accounts = block_context->acct_states;
  block_context->acct_states                   = fd_spad_alloc( spad,
                                                                alignof(fd_exec_test_acct_state_t),
                                                                ( ( block_info->txn_cnt * 128UL ) + (ulong)block_context->acct_states_count ) *
                                                                sizeof(fd_exec_test_acct_state_t) );
  fd_memcpy( block_context->acct_states, current_accounts, block_context->acct_states_count * sizeof(fd_exec_test_acct_state_t) );

  /* BlockContext -> slot_ctx -> poh
     This currently needs to be done because POH verification is done after epoch boundary processing. That should probably be changed */
  fd_memcpy( block_context->slot_ctx.poh, fd_bank_poh_query( slot_ctx->bank )->hash, sizeof(fd_pubkey_t) );

  /* When iterating over microblocks batches and microblocks, we flatten the batches for the output block context (essentially just one big batch with several microblocks) */
  for( ulong i=0UL; i<block_info->microblock_batch_cnt; i++ ) {
    fd_microblock_batch_info_t const * microblock_batch = &block_info->microblock_batch_infos[i];

    for( ulong j=0UL; j<microblock_batch->microblock_cnt; j++ ) {
      fd_microblock_info_t const * microblock_info = &microblock_batch->microblock_infos[j];
      ulong                        txn_cnt         = microblock_info->microblock.hdr->txn_cnt;
      if (txn_cnt==0UL) continue;

      /* BlockContext -> txns */
      for( ulong k=0UL; k<txn_cnt; k++ ) {
        fd_txn_p_t const * txn_ptr      = &microblock_info->txns[k];
        fd_txn_t const * txn_descriptor = TXN( txn_ptr );
        dump_sanitized_transaction( slot_ctx->funk, slot_ctx->funk_txn, txn_descriptor, txn_ptr->payload, spad, &block_context->txns[block_context->txns_count++] );

        /* BlockContext -> acct_states */
        /* Dump account + alut + programdata accounts (if applicable). There's a lot more brute force work since none of the borrowed accounts are set up yet. We have to:
           1. Dump the raw txn account keys
           2. Dump the ALUT accounts
           3. Dump all referenced accounts in the ALUTs
           4. Dump any executable accounts
           5. Dump any sysvars + builtin accounts (occurs outside of this loop) */

        // 1. Dump any account keys that are referenced by transactions
        fd_acct_addr_t const * account_keys = fd_txn_get_acct_addrs( txn_descriptor, txn_ptr->payload );
        for( ushort l=0; l<txn_descriptor->acct_addr_cnt; l++ ) {
          fd_pubkey_t const * account_key = fd_type_pun_const( &account_keys[l] );
          dump_account_if_not_already_dumped( slot_ctx->funk, slot_ctx->funk_txn, account_key, spad, block_context->acct_states, &block_context->acct_states_count, NULL );
        }

        // 2 + 3. Dump any ALUT accounts + any accounts referenced in the ALUTs
        fd_txn_acct_addr_lut_t const * txn_lookup_tables = fd_txn_get_address_tables_const( txn_descriptor );
        for( ushort l=0; l<txn_descriptor->addr_table_lookup_cnt; l++ ) {
          fd_txn_acct_addr_lut_t const * lookup_table = &txn_lookup_tables[l];
          dump_lut_account_and_contained_accounts( slot_ctx, txn_ptr->payload, lookup_table, spad, block_context->acct_states, &block_context->acct_states_count );
        }

        // 4. Go through all dumped accounts and dump any executable accounts
        ulong dumped_accounts = block_context->acct_states_count;
        for( ulong l=0; l<dumped_accounts; l++ ) {
          fd_exec_test_acct_state_t const * maybe_program_account = &block_context->acct_states[l];
          dump_executable_account_if_exists( slot_ctx->funk, slot_ctx->funk_txn, maybe_program_account, spad, block_context->acct_states, &block_context->acct_states_count );
        }
      }
    }
  }
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
    // fd_solana_config_program_id, // migrated to BPF, so we should dump it
    // fd_solana_zk_token_proof_program_id,
    fd_solana_bpf_loader_v4_program_id,
    // fd_solana_address_lookup_table_program_id, // migrated to BPF, so we should dump it
    fd_solana_bpf_loader_deprecated_program_id,
    fd_solana_bpf_loader_program_id,
    fd_solana_bpf_loader_upgradeable_program_id,
    fd_solana_compute_budget_program_id,
    fd_solana_keccak_secp_256k_program_id,
    fd_solana_secp256r1_program_id,
    fd_solana_zk_elgamal_proof_program_id,
    fd_solana_ed25519_sig_verify_program_id,
  };
  const ulong num_loaded_builtins = (sizeof(loaded_builtins) / sizeof(fd_pubkey_t));

  /* Prepare sysvar cache accounts */
  fd_pubkey_t const fd_relevant_sysvar_ids[] = {
    fd_sysvar_recent_block_hashes_id,
    fd_sysvar_clock_id,
    fd_sysvar_slot_history_id,
    fd_sysvar_slot_hashes_id,
    fd_sysvar_epoch_schedule_id,
    fd_sysvar_epoch_rewards_id,
    fd_sysvar_fees_id,
    fd_sysvar_rent_id,
    fd_sysvar_stake_history_id,
    fd_sysvar_last_restart_slot_id,
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
                                                        (256UL*2UL + txn_descriptor->addr_table_lookup_cnt + num_sysvar_entries) * sizeof(fd_exec_test_acct_state_t) );
  for( ulong i = 0; i < txn_ctx->accounts_cnt; ++i ) {
    FD_TXN_ACCOUNT_DECL( txn_account );
    int ret = fd_txn_account_init_from_funk_readonly( txn_account, &txn_ctx->account_keys[i], txn_ctx->funk, txn_ctx->funk_txn );
    if( FD_UNLIKELY( ret ) ) {
      continue;
    }

    // Make sure account is not a builtin
    if( !is_builtin_account( loaded_builtins, num_loaded_builtins, &txn_ctx->account_keys[i] ) ) {
      dump_account_state( txn_account, &txn_context_msg->account_shared_data[txn_context_msg->account_shared_data_count++], spad );

    }
  }

  // Dump LUT accounts
  fd_txn_acct_addr_lut_t const * address_lookup_tables = fd_txn_get_address_tables_const( txn_descriptor );
  for( ulong i = 0; i < txn_descriptor->addr_table_lookup_cnt; ++i ) {
    FD_TXN_ACCOUNT_DECL( txn_account );
    fd_txn_acct_addr_lut_t const * addr_lut  = &address_lookup_tables[i];
    fd_pubkey_t * alut_key = (fd_pubkey_t *) (txn_payload + addr_lut[i].addr_off);
    int ret = fd_txn_account_init_from_funk_readonly( txn_account, alut_key, txn_ctx->funk, txn_ctx->funk_txn );
    if( FD_UNLIKELY( ret ) ) continue;

    dump_account_state( txn_account, &txn_context_msg->account_shared_data[txn_context_msg->account_shared_data_count++], spad );

    fd_acct_addr_t * lookup_addrs  = (fd_acct_addr_t *)&txn_account->vt->get_data( txn_account )[FD_LOOKUP_TABLE_META_SIZE];
    ulong lookup_addrs_cnt         = (txn_account->vt->get_data_len( txn_account ) - FD_LOOKUP_TABLE_META_SIZE) >> 5UL; // = (dlen - 56) / 32

    /* Dump any account state refererenced in ALUTs */
    uchar const * writable_lut_idxs = txn_payload + addr_lut->writable_off;
    for( ulong j=0; j<addr_lut->writable_cnt; j++ ) {
      if( writable_lut_idxs[j] >= lookup_addrs_cnt ) {
        continue;
      }
      fd_pubkey_t const * referenced_addr = fd_type_pun( &lookup_addrs[writable_lut_idxs[j]] );
      if( is_builtin_account( loaded_builtins, num_loaded_builtins, referenced_addr ) ) continue;

      FD_TXN_ACCOUNT_DECL( referenced_account );
      ret = fd_txn_account_init_from_funk_readonly( referenced_account, referenced_addr, txn_ctx->funk, txn_ctx->funk_txn );
      if( FD_UNLIKELY( ret ) ) continue;
      dump_account_state( referenced_account, &txn_context_msg->account_shared_data[txn_context_msg->account_shared_data_count++], spad );
    }

    uchar const * readonly_lut_idxs = txn_payload + addr_lut->readonly_off;
    for( ulong j = 0; j < addr_lut->readonly_cnt; j++ ) {
      if( readonly_lut_idxs[j] >= lookup_addrs_cnt ) {
        continue;
      }
      fd_pubkey_t const * referenced_addr = fd_type_pun( &lookup_addrs[readonly_lut_idxs[j]] );
      if( is_builtin_account( loaded_builtins, num_loaded_builtins, referenced_addr ) ) continue;

      FD_TXN_ACCOUNT_DECL( referenced_account );
      ret = fd_txn_account_init_from_funk_readonly( referenced_account, referenced_addr, txn_ctx->funk, txn_ctx->funk_txn );
      if( FD_UNLIKELY( ret ) ) continue;
      dump_account_state( referenced_account, &txn_context_msg->account_shared_data[txn_context_msg->account_shared_data_count++], spad );
    }
  }

  /* Dump the programdata accounts for any potential v3-owned program accounts */
  uint accounts_dumped_so_far = txn_context_msg->account_shared_data_count;
  for( uint i=0U; i<accounts_dumped_so_far; i++ ) {
    fd_exec_test_acct_state_t const * maybe_program_account = &txn_context_msg->account_shared_data[i];
    dump_executable_account_if_exists( txn_ctx->funk, txn_ctx->funk_txn, maybe_program_account, spad, txn_context_msg->account_shared_data, &txn_context_msg->account_shared_data_count );
  }

  /* Dump sysvars */
  for( ulong i = 0; i < num_sysvar_entries; i++ ) {
    FD_TXN_ACCOUNT_DECL( txn_account );
    int ret = fd_txn_account_init_from_funk_readonly( txn_account, &fd_relevant_sysvar_ids[i], txn_ctx->funk, txn_ctx->funk_txn );
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
  dump_sanitized_transaction( txn_ctx->funk, txn_ctx->funk_txn, txn_descriptor, txn_payload, spad, sanitized_transaction );

  /* Transaction Context -> blockhash_queue
     NOTE: Agave's implementation of register_hash incorrectly allows the blockhash queue to hold max_age + 1 (max 301)
     entries. We have this incorrect logic implemented in fd_sysvar_recent_hashes:register_blockhash and it's not a
     huge issue, but something to keep in mind. */
  pb_bytes_array_t ** output_blockhash_queue = fd_spad_alloc(
                                                      spad,
                                                      alignof(pb_bytes_array_t *),
                                                      PB_BYTES_ARRAY_T_ALLOCSIZE((FD_BLOCKHASH_QUEUE_MAX_ENTRIES + 1) * sizeof(pb_bytes_array_t *)) );
  txn_context_msg->blockhash_queue = output_blockhash_queue;
  fd_block_hash_queue_global_t * block_hash_queue = (fd_block_hash_queue_global_t *)&txn_ctx->bank->block_hash_queue[0];
  dump_blockhash_queue( block_hash_queue, spad, output_blockhash_queue, &txn_context_msg->blockhash_queue_count );

  /* Transaction Context -> epoch_ctx */
  txn_context_msg->has_epoch_ctx = true;
  txn_context_msg->epoch_ctx.has_features = true;
  dump_sorted_features( &txn_ctx->features, &txn_context_msg->epoch_ctx.features, spad );

  /* Transaction Context -> slot_ctx */
  txn_context_msg->has_slot_ctx  = true;
  txn_context_msg->slot_ctx.slot = txn_ctx->slot;
}

static void
create_instr_context_protobuf_from_instructions( fd_exec_test_instr_context_t * instr_context,
                                                 fd_exec_txn_ctx_t const *      txn_ctx,
                                                 fd_instr_info_t const *        instr ) {
  /* Prepare sysvar cache accounts */
  fd_pubkey_t const fd_relevant_sysvar_ids[] = {
    fd_sysvar_recent_block_hashes_id,
    fd_sysvar_clock_id,
    fd_sysvar_slot_history_id,
    fd_sysvar_slot_hashes_id,
    fd_sysvar_epoch_schedule_id,
    fd_sysvar_epoch_rewards_id,
    fd_sysvar_fees_id,
    fd_sysvar_rent_id,
    fd_sysvar_stake_history_id,
    fd_sysvar_last_restart_slot_id,
    fd_sysvar_instructions_id,
  };
  const ulong num_sysvar_entries = (sizeof(fd_relevant_sysvar_ids) / sizeof(fd_pubkey_t));

  /* Program ID */
  fd_memcpy( instr_context->program_id, txn_ctx->account_keys[ instr->program_id ].uc, sizeof(fd_pubkey_t) );

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
    int ret = fd_txn_account_init_from_funk_readonly( txn_account, &fd_relevant_sysvar_ids[i], txn_ctx->funk, txn_ctx->funk_txn );
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
    int ret = fd_txn_account_init_from_funk_readonly( txn_account, txn_ctx->executable_accounts[i].pubkey, txn_ctx->funk, txn_ctx->funk_txn );
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

    output_instr_account->index       = instr->accounts[i].index_in_transaction;
    output_instr_account->is_writable = instr->accounts[i].is_writable;
    output_instr_account->is_signer   = instr->accounts[i].is_signer;
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
      position = fd_cstr_append_cstr(position, ".instrctx");
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
      position = fd_cstr_append_cstr(position, ".txnctx");
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
fd_dump_block_to_protobuf( fd_exec_slot_ctx_t const *     slot_ctx,
                           fd_capture_ctx_t const *       capture_ctx,
                           fd_spad_t *                    spad,
                           fd_exec_test_block_context_t * block_context_msg /* output */ ) {
  /* No spad frame because these allocations must persist beyond the lifetime of this function call */
  if( FD_UNLIKELY( capture_ctx==NULL ) ) {
    FD_LOG_WARNING(( "Capture context may not be NULL when dumping blocks." ));
    return;
  }
  create_block_context_protobuf_from_block( block_context_msg, slot_ctx, spad );
}

void
fd_dump_block_to_protobuf_tx_only( fd_runtime_block_info_t const * block_info,
                                   fd_exec_slot_ctx_t const *      slot_ctx,
                                   fd_capture_ctx_t const *        capture_ctx,
                                   fd_spad_t *                     spad,
                                   fd_exec_test_block_context_t *  block_context_msg ) {
  FD_SPAD_FRAME_BEGIN( spad ) {
    if( FD_UNLIKELY( capture_ctx==NULL ) ) {
      FD_LOG_WARNING(( "Capture context may not be NULL when dumping blocks." ));
      return;
    }

    if( FD_UNLIKELY( block_info==NULL ) ) {
      FD_LOG_WARNING(( "Block info may not be NULL when dumping blocks." ));
      return;
    }

    create_block_context_protobuf_from_block_tx_only( block_context_msg, block_info, slot_ctx, spad );

    /* Output to file */
    ulong out_buf_size = 5UL<<30UL; /* 5 GB */
    uint8_t * out = fd_spad_alloc( spad, alignof(uint8_t), out_buf_size );
    pb_ostream_t stream = pb_ostream_from_buffer( out, out_buf_size );
    if( pb_encode( &stream, FD_EXEC_TEST_BLOCK_CONTEXT_FIELDS, block_context_msg ) ) {
      char output_filepath[256]; fd_memset( output_filepath, 0, sizeof(output_filepath) );
      char * position = fd_cstr_init( output_filepath );
      position = fd_cstr_append_printf( position, "%s/block-%lu.blockctx", capture_ctx->dump_proto_output_dir, slot_ctx->slot );
      fd_cstr_fini( position );

      FILE * file = fopen(output_filepath, "wb");
      if( file ) {
        fwrite( out, 1, stream.bytes_written, file );
        fclose( file );
      }
    }
  } FD_SPAD_FRAME_END;
}

void
fd_dump_vm_syscall_to_protobuf( fd_vm_t const * vm,
                                char const *    fn_name ) {
FD_SPAD_FRAME_BEGIN( vm->instr_ctx->txn_ctx->spad ) {

  fd_ed25519_sig_t signature;
  memcpy( signature, (uchar const *)vm->instr_ctx->txn_ctx->_txn_raw->raw + vm->instr_ctx->txn_ctx->txn_descriptor->signature_off, sizeof(fd_ed25519_sig_t) );
  char encoded_signature[FD_BASE58_ENCODED_64_SZ];
  fd_base58_encode_64( signature, NULL, encoded_signature );

  char filename[256];
  sprintf( filename,
          "%s/syscall-%s-%s-%d-%hhu-%lu.sysctx",
          vm->instr_ctx->txn_ctx->capture_ctx->dump_proto_output_dir,
          fn_name,
          encoded_signature,
          vm->instr_ctx->txn_ctx->current_instr_idx,
          vm->instr_ctx->txn_ctx->instr_stack_sz,
          vm->cu );

  /* The generated filename should be unique for every call. Silently return otherwise. */
  if( FD_UNLIKELY( access( filename, F_OK )!=-1 ) ) {
    return;
  }

  fd_exec_test_syscall_context_t sys_ctx = FD_EXEC_TEST_SYSCALL_CONTEXT_INIT_ZERO;

  /* SyscallContext -> vm_ctx */
  sys_ctx.has_vm_ctx = 1;

  /* SyscallContext -> vm_ctx -> heap_max */
  sys_ctx.vm_ctx.heap_max = vm->heap_max; /* should be equiv. to txn_ctx->heap_sz */

  /* SyscallContext -> vm_ctx -> rodata */
  sys_ctx.vm_ctx.rodata = fd_spad_alloc( vm->instr_ctx->txn_ctx->spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( vm->rodata_sz ) );
  sys_ctx.vm_ctx.rodata->size = (pb_size_t) vm->rodata_sz;
  fd_memcpy( sys_ctx.vm_ctx.rodata->bytes, vm->rodata, vm->rodata_sz );

  /* SyscallContext -> vm_ctx -> rodata_text_section_offset */
  sys_ctx.vm_ctx.rodata_text_section_offset = vm->text_off;

  /* SyscallContext -> vm_ctx -> rodata_text_section_length */
  sys_ctx.vm_ctx.rodata_text_section_length = vm->text_sz;

  /* SyscallContext -> vm_ctx -> r0-11 */
  sys_ctx.vm_ctx.r0  = vm->reg[0];
  sys_ctx.vm_ctx.r1  = vm->reg[1];
  sys_ctx.vm_ctx.r2  = vm->reg[2];
  sys_ctx.vm_ctx.r3  = vm->reg[3];
  sys_ctx.vm_ctx.r4  = vm->reg[4];
  sys_ctx.vm_ctx.r5  = vm->reg[5];
  sys_ctx.vm_ctx.r6  = vm->reg[6];
  sys_ctx.vm_ctx.r7  = vm->reg[7];
  sys_ctx.vm_ctx.r8  = vm->reg[8];
  sys_ctx.vm_ctx.r9  = vm->reg[9];
  sys_ctx.vm_ctx.r10 = vm->reg[10];
  sys_ctx.vm_ctx.r11 = vm->reg[11];

  /* SyscallContext -> vm_ctx -> entry_pc */
  sys_ctx.vm_ctx.entry_pc = vm->entry_pc;

  /* SyscallContext -> vm_ctx -> return_data */
  sys_ctx.vm_ctx.has_return_data = 1;

  /* SyscallContext -> vm_ctx -> return_data -> data */
  sys_ctx.vm_ctx.return_data.data = fd_spad_alloc( vm->instr_ctx->txn_ctx->spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( vm->instr_ctx->txn_ctx->return_data.len ) );
  sys_ctx.vm_ctx.return_data.data->size = (pb_size_t)vm->instr_ctx->txn_ctx->return_data.len;
  fd_memcpy( sys_ctx.vm_ctx.return_data.data->bytes, vm->instr_ctx->txn_ctx->return_data.data, vm->instr_ctx->txn_ctx->return_data.len );

  /* SyscallContext -> vm_ctx -> return_data -> program_id */
  sys_ctx.vm_ctx.return_data.program_id = fd_spad_alloc( vm->instr_ctx->txn_ctx->spad, alignof(pb_bytes_array_t), sizeof(fd_pubkey_t) );
  sys_ctx.vm_ctx.return_data.program_id->size = sizeof(fd_pubkey_t);
  fd_memcpy( sys_ctx.vm_ctx.return_data.program_id->bytes, vm->instr_ctx->txn_ctx->return_data.program_id.key, sizeof(fd_pubkey_t) );

  /* SyscallContext -> vm_ctx -> sbpf_version */
  sys_ctx.vm_ctx.sbpf_version = (uint)vm->sbpf_version;

  /* SyscallContext -> instr_ctx */
  sys_ctx.has_instr_ctx = 1;
  create_instr_context_protobuf_from_instructions( &sys_ctx.instr_ctx,
                                                    vm->instr_ctx->txn_ctx,
                                                    vm->instr_ctx->instr );

  /* SyscallContext -> syscall_invocation */
  sys_ctx.has_syscall_invocation = 1;

  /* SyscallContext -> syscall_invocation -> function_name */
  sys_ctx.syscall_invocation.function_name.size = fd_uint_min( (uint) strlen(fn_name), sizeof(sys_ctx.syscall_invocation.function_name.bytes) );
  fd_memcpy( sys_ctx.syscall_invocation.function_name.bytes,
             fn_name,
             sys_ctx.syscall_invocation.function_name.size );

  /* SyscallContext -> syscall_invocation -> heap_prefix */
  sys_ctx.syscall_invocation.heap_prefix = fd_spad_alloc( vm->instr_ctx->txn_ctx->spad, 8UL, PB_BYTES_ARRAY_T_ALLOCSIZE( vm->heap_max ) );
  sys_ctx.syscall_invocation.heap_prefix->size = (pb_size_t) vm->instr_ctx->txn_ctx->heap_size;
  fd_memcpy( sys_ctx.syscall_invocation.heap_prefix->bytes, vm->heap, vm->instr_ctx->txn_ctx->heap_size );

  /* SyscallContext -> syscall_invocation -> stack_prefix */
  pb_size_t stack_sz = (pb_size_t)FD_VM_STACK_MAX;
  sys_ctx.syscall_invocation.stack_prefix = fd_spad_alloc( vm->instr_ctx->txn_ctx->spad, 8UL, PB_BYTES_ARRAY_T_ALLOCSIZE( stack_sz ) );
  sys_ctx.syscall_invocation.stack_prefix->size = stack_sz;
  fd_memcpy( sys_ctx.syscall_invocation.stack_prefix->bytes, vm->stack, stack_sz );

  /* Output to file */
  ulong out_buf_size = 1UL<<29UL; /* 128 MB */
  uint8_t * out = fd_spad_alloc( vm->instr_ctx->txn_ctx->spad, alignof(uint8_t), out_buf_size );
  pb_ostream_t stream = pb_ostream_from_buffer( out, out_buf_size );
  if( pb_encode( &stream, FD_EXEC_TEST_SYSCALL_CONTEXT_FIELDS, &sys_ctx ) ) {
    FILE * file = fopen(filename, "wb");
    if( file ) {
      fwrite( out, 1, stream.bytes_written, file );
      fclose( file );
    }
  }
} FD_SPAD_FRAME_END;
}

void
fd_dump_elf_to_protobuf( fd_exec_txn_ctx_t * txn_ctx,
                         fd_txn_account_t *  program_acc ) {
FD_SPAD_FRAME_BEGIN( txn_ctx->spad ) {

  /* Get the programdata for the account */
  ulong         program_data_len = 0UL;
  uchar const * program_data     = fd_bpf_get_programdata_from_account( txn_ctx->funk, txn_ctx->funk_txn, program_acc, &program_data_len, txn_ctx->spad );
  if( program_data==NULL ) {
    return;
  }

  /* Serialize the ELF to protobuf */
  fd_ed25519_sig_t signature;
  memcpy( signature, (uchar const *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->signature_off, sizeof(fd_ed25519_sig_t) );
  char encoded_signature[FD_BASE58_ENCODED_64_SZ];
  fd_base58_encode_64( signature, NULL, encoded_signature );

  char filename[256];
  sprintf( filename,
          "%s/elf-%s-%s-%lu.elfctx",
          txn_ctx->capture_ctx->dump_proto_output_dir,
          encoded_signature,
          FD_BASE58_ENC_32_ALLOCA( program_acc->pubkey ),
          txn_ctx->slot );

  /* The generated filename should be unique for every call. Silently return otherwise. */
  if( FD_UNLIKELY( access( filename, F_OK )!=-1 ) ) {
    return;
  }

  fd_exec_test_elf_loader_ctx_t elf_ctx = FD_EXEC_TEST_ELF_LOADER_CTX_INIT_ZERO;

  /* ElfLoaderCtx -> elf */
  elf_ctx.has_elf = true;
  elf_ctx.elf.data = fd_spad_alloc( txn_ctx->spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( program_data_len ) );
  elf_ctx.elf.data->size = (pb_size_t)program_data_len;
  fd_memcpy( elf_ctx.elf.data->bytes, program_data, program_data_len );

  /* ElfLoaderCtx -> features */
  elf_ctx.has_features = true;
  dump_sorted_features( &txn_ctx->features, &elf_ctx.features, txn_ctx->spad );

  /* ElfLoaderCtx -> deploy_checks
     We hardcode this to true and rely the fuzzer to toggle this as it pleases */
  elf_ctx.deploy_checks = true;

  /* Output to file */
  ulong out_buf_size = 1UL<<29UL; /* 128 MB */
  uint8_t * out = fd_spad_alloc( txn_ctx->spad, alignof(uint8_t), out_buf_size );
  pb_ostream_t stream = pb_ostream_from_buffer( out, out_buf_size );
  if( pb_encode( &stream, FD_EXEC_TEST_ELF_LOADER_CTX_FIELDS, &elf_ctx ) ) {
    FILE * file = fopen(filename, "wb");
    if( file ) {
      fwrite( out, 1, stream.bytes_written, file );
      fclose( file );
    }
  }
} FD_SPAD_FRAME_END;
}
