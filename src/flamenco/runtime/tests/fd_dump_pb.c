#include "fd_dump_pb.h"
#include "generated/block.pb.h"
#include "generated/invoke.pb.h"
#include "generated/txn.pb.h"
#include "generated/vm.pb.h"
#include "../fd_system_ids.h"
#include "../fd_bank.h"
#include "../fd_runtime.h"
#include "../program/fd_precompiles.h"
#include "../program/fd_address_lookup_table_program.h"
#include "../../../ballet/nanopb/pb_encode.h"
#include "../../accdb/fd_accdb_sync.h"
#include "../../progcache/fd_prog_load.h"

#include <stdio.h> /* fopen */
#include <sys/mman.h> /* mmap */
#include <unistd.h> /* ftruncate */

#define SORT_NAME        sort_uint64_t
#define SORT_KEY_T       uint64_t
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../../util/tmpl/fd_sort.c"

struct fd_dump_account_key_node {
  fd_pubkey_t key;
  ulong       redblack_parent;
  ulong       redblack_left;
  ulong       redblack_right;
  int         redblack_color;
};
typedef struct fd_dump_account_key_node fd_dump_account_key_node_t;
#define REDBLK_T fd_dump_account_key_node_t
#define REDBLK_NAME fd_dump_account_key_map
long fd_dump_account_key_map_compare( fd_dump_account_key_node_t * left, fd_dump_account_key_node_t * right ) {
  return memcmp( left->key.uc, right->key.uc, sizeof(fd_pubkey_t) );
}
#include "../../../util/tmpl/fd_redblack.c"

/***** CONSTANTS *****/
static fd_pubkey_t const * fd_dump_sysvar_ids[] = {
  &fd_sysvar_recent_block_hashes_id,
  &fd_sysvar_clock_id,
  &fd_sysvar_slot_history_id,
  &fd_sysvar_slot_hashes_id,
  &fd_sysvar_epoch_schedule_id,
  &fd_sysvar_epoch_rewards_id,
  &fd_sysvar_fees_id,
  &fd_sysvar_rent_id,
  &fd_sysvar_stake_history_id,
  &fd_sysvar_last_restart_slot_id,
  &fd_sysvar_instructions_id,
};
static ulong const num_sysvar_entries = (sizeof(fd_dump_sysvar_ids) / sizeof(fd_pubkey_t *));

static fd_pubkey_t const * fd_dump_builtin_ids[] = {
  &fd_solana_system_program_id,
  &fd_solana_vote_program_id,
  &fd_solana_stake_program_id,
  &fd_solana_bpf_loader_v4_program_id,
  &fd_solana_bpf_loader_deprecated_program_id,
  &fd_solana_bpf_loader_program_id,
  &fd_solana_bpf_loader_upgradeable_program_id,
  &fd_solana_compute_budget_program_id,
  &fd_solana_keccak_secp_256k_program_id,
  &fd_solana_secp256r1_program_id,
  &fd_solana_zk_elgamal_proof_program_id,
  &fd_solana_ed25519_sig_verify_program_id,
};
static ulong const num_loaded_builtins = (sizeof(fd_dump_builtin_ids) / sizeof(fd_pubkey_t *));

/***** UTILITY FUNCTIONS *****/

/** FEATURE DUMPING **/
static void
dump_sorted_features( fd_features_t const *        features,
                      fd_exec_test_feature_set_t * output_feature_set,
                      fd_spad_t *                  spad ) {
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
dump_account_state( fd_pubkey_t const *         account_key,
                    fd_account_meta_t const *   account_meta,
                    fd_exec_test_acct_state_t * output_account,
                    fd_spad_t *                 spad ) {
    // Address
    fd_memcpy(output_account->address, account_key, sizeof(fd_pubkey_t));

    // Lamports
    output_account->lamports = (uint64_t)account_meta->lamports;

    // Data
    output_account->data = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( account_meta->dlen ) );
    output_account->data->size = (pb_size_t) account_meta->dlen;
    fd_memcpy(output_account->data->bytes, fd_account_data( account_meta ), account_meta->dlen );

    // Executable
    output_account->executable = (bool)account_meta->executable;

    // Owner
    fd_memcpy(output_account->owner, account_meta->owner, sizeof(fd_pubkey_t));
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

/* Dumps a borrowed account if it exists and has not been dumped yet.
   Sets up the output borrowed account if it exists. Returns 0 if the
   account exists, 1 otherwise.
   TODO: This can be optimized by using a set. */
static uchar
dump_account_if_not_already_dumped( fd_accdb_user_t *           accdb,
                                    fd_funk_txn_xid_t const *   xid,
                                    fd_pubkey_t const *         account_key,
                                    fd_spad_t *                 spad,
                                    fd_exec_test_acct_state_t * out_acct_states,
                                    pb_size_t *                 out_acct_states_cnt,
                                    fd_accdb_ro_t *             out_ro ) {
  fd_accdb_ro_t ro[1];
  if( !fd_accdb_open_ro( accdb, ro, xid, account_key ) ) {
    return 1;
  }

  if( !account_already_dumped( out_acct_states, *out_acct_states_cnt, account_key ) ) {
    dump_account_state( account_key, ro->meta, &out_acct_states[*out_acct_states_cnt], spad );
    (*out_acct_states_cnt)++;
  }

  if( out_ro ) {
    *out_ro = *ro;
  } else {
    fd_accdb_close_ro( accdb, ro );
  }
  return 0;
}

static void
dump_executable_account_if_exists( fd_accdb_user_t *                 accdb,
                                   fd_funk_txn_xid_t const *         xid,
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
  dump_account_if_not_already_dumped( accdb, xid, programdata_acc, spad, out_account_states, out_account_states_count, NULL );
}

static void
dump_sanitized_transaction( fd_accdb_user_t *                      accdb,
                            fd_funk_txn_xid_t const *              xid,
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
      fd_accdb_ro_t addr_lut_ro[1];
      if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, addr_lut_ro, xid, alut_key ) ) ) {
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

      fd_accdb_close_ro( accdb, addr_lut_ro );
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

static void
dump_blockhash_queue( fd_blockhashes_t const * queue,
                      fd_spad_t *              spad,
                      pb_bytes_array_t **      output_blockhash_queue,
                      pb_size_t *              output_blockhash_queue_count ) {
  ulong bhq_size = fd_ulong_min( FD_BLOCKHASHES_MAX, fd_blockhash_deq_cnt( queue->d.deque ) );

  // Iterate over all block hashes in the queue and save them in the output
  pb_size_t cnt = 0U;
  for( fd_blockhash_deq_iter_t iter=fd_blockhash_deq_iter_init_rev( queue->d.deque );
       !fd_blockhash_deq_iter_done_rev( queue->d.deque, iter ) && cnt<FD_BLOCKHASHES_MAX;
       iter=fd_blockhash_deq_iter_prev( queue->d.deque, iter ), cnt++ ) {
    fd_blockhash_info_t const * ele              = fd_blockhash_deq_iter_ele_const( queue->d.deque, iter );
    pb_bytes_array_t *          output_blockhash = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE(sizeof(fd_hash_t)) );
    output_blockhash->size = sizeof(fd_hash_t);
    fd_memcpy( output_blockhash->bytes, &ele->hash, sizeof(fd_hash_t) );
    output_blockhash_queue[ bhq_size-cnt-1UL ] = output_blockhash;
  }

  *output_blockhash_queue_count = cnt;
}

static void
dump_txn_bank( fd_bank_t *                  bank,
               fd_spad_t *                  spad,
               fd_exec_test_txn_context_t * txn_context ) {
  txn_context->has_bank              = true;
  fd_exec_test_txn_bank_t * txn_bank = &txn_context->bank;

  /* TxnBank -> blockhash_queue */
  fd_blockhashes_t const * bhq      = fd_bank_block_hash_queue_query( bank );
  ulong                    bhq_size = fd_ulong_min( FD_BLOCKHASHES_MAX, fd_blockhash_deq_cnt( bhq->d.deque ) );
  txn_bank->blockhash_queue         = fd_spad_alloc( spad, alignof(fd_exec_test_blockhash_queue_entry_t), bhq_size * sizeof(fd_exec_test_blockhash_queue_entry_t) );
  txn_bank->blockhash_queue_count   = (uint)bhq_size;

  ulong cnt = 0UL;
  for( fd_blockhash_deq_iter_t iter=fd_blockhash_deq_iter_init_rev( bhq->d.deque );
       !fd_blockhash_deq_iter_done_rev( bhq->d.deque, iter ) && cnt<bhq_size;
       iter=fd_blockhash_deq_iter_prev( bhq->d.deque, iter ), cnt++ ) {
    fd_blockhash_info_t const * ele              = fd_blockhash_deq_iter_ele_const( bhq->d.deque, iter );
    fd_exec_test_blockhash_queue_entry_t * entry = &txn_bank->blockhash_queue[bhq_size-cnt-1UL];
    fd_memcpy( entry->blockhash, ele->hash.uc, sizeof(fd_hash_t) );
    entry->lamports_per_signature = ele->fee_calculator.lamports_per_signature;
  }

  /* TxnBank -> rbh_lamports_per_signature */
  txn_bank->rbh_lamports_per_signature = (uint)fd_bank_rbh_lamports_per_sig_get( bank );

  /* TxnBank -> fee_rate_governor */
  fd_fee_rate_governor_t const * fee_rate_governor = fd_bank_fee_rate_governor_query( bank );
  txn_bank->has_fee_rate_governor = true;
  txn_bank->fee_rate_governor = (fd_exec_test_fee_rate_governor_t){
    .target_lamports_per_signature = fee_rate_governor->target_lamports_per_signature,
    .target_signatures_per_slot    = fee_rate_governor->target_signatures_per_slot,
    .min_lamports_per_signature    = fee_rate_governor->min_lamports_per_signature,
    .max_lamports_per_signature    = fee_rate_governor->max_lamports_per_signature,
    .burn_percent                  = fee_rate_governor->burn_percent,
  };

  /* TxnBank -> total_epoch_stake */
  txn_bank->total_epoch_stake = fd_bank_total_epoch_stake_get( bank );

  /* TxnBank -> epoch_schedule */
  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
  txn_bank->has_epoch_schedule = true;
  txn_bank->epoch_schedule = (fd_exec_test_epoch_schedule_t){
    .slots_per_epoch             = epoch_schedule->slots_per_epoch,
    .leader_schedule_slot_offset = epoch_schedule->leader_schedule_slot_offset,
    .warmup                      = epoch_schedule->warmup,
    .first_normal_epoch          = epoch_schedule->first_normal_epoch,
    .first_normal_slot           = epoch_schedule->first_normal_slot,
  };

  /* TxnBank -> rent */
  fd_rent_t const * rent = fd_bank_rent_query( bank );
  txn_bank->has_rent = true;
  txn_bank->rent = (fd_exec_test_rent_t){
    .lamports_per_byte_year = rent->lamports_per_uint8_year,
    .exemption_threshold    = rent->exemption_threshold,
    .burn_percent           = rent->burn_percent,
  };

  /* TxnBank -> features */
  txn_bank->has_features = true;
  dump_sorted_features( fd_bank_features_query( bank ), &txn_bank->features, spad );

  /* TxnBank -> epoch */
  txn_bank->epoch = fd_bank_epoch_get( bank );
}

/** SECONDARY FUNCTIONS **/

/* add_account_to_dumped_accounts adds an account to the dumped accounts
   set if it does not exist already. Returns 0 if the account already
   exists, and 1 if the account was added successfully.

   TODO: Txn dumping should be optimized to use these functions. */
static uchar
add_account_to_dumped_accounts( fd_dump_account_key_node_t *  pool,
                                fd_dump_account_key_node_t ** root,
                                fd_pubkey_t const *           pubkey ) {
  /* If the key already exists, return early. */
  fd_dump_account_key_node_t node = {
    .key = *pubkey,
  };
  if( fd_dump_account_key_map_find( pool, *root, &node ) ) {
    return 0;
  }

  fd_dump_account_key_node_t * new_node = fd_dump_account_key_map_acquire( pool );
  new_node->key = *pubkey;
  fd_dump_account_key_map_insert( pool, root, new_node );
  return 1;
}

/* add_account_and_programdata_to_dumped_accounts adds an account and
   its programdata account (if the account is a v3 program) to the
   dumped accounts set if they do not exist already. */
static void
add_account_and_programdata_to_dumped_accounts( fd_accdb_user_t *             accdb,
                                                fd_funk_txn_xid_t const *     xid,
                                                fd_dump_account_key_node_t *  pool,
                                                fd_dump_account_key_node_t ** root,
                                                fd_pubkey_t const *           pubkey ) {
  /* Add the current account to the dumped accounts set. We can save
     some time by enforcing an invariant that "if current account was
     dumped, then programdata account was also dumped," so we save
     ourselves a call to Funk. */
  uchar ret = add_account_to_dumped_accounts( pool, root, pubkey );
  if( ret==0 ) return;

  /* Read the account from Funk to see if its a program account and if
     it needs to be dumped. */
  fd_accdb_ro_t program_account[1];
  if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, program_account, xid, pubkey ) ) ) {
    return;
  }

  /* Return if its not owned by the v3 loader */
  if( FD_LIKELY( !fd_pubkey_eq( fd_accdb_ref_owner( program_account ), &fd_solana_bpf_loader_upgradeable_program_id ) ) ) {
    fd_accdb_close_ro( accdb, program_account );
    return;
  }

  /* Get the program account state */
  fd_bpf_upgradeable_loader_state_t program_account_state[1];
  if( FD_UNLIKELY( !fd_bincode_decode_static(
      bpf_upgradeable_loader_state,
      program_account_state,
      fd_accdb_ref_data_const( program_account ),
      fd_accdb_ref_data_sz   ( program_account ),
      NULL ) ) ) {
    fd_accdb_close_ro( accdb, program_account );
    return;
  }
  if( !fd_bpf_upgradeable_loader_state_is_program( program_account_state ) ) {
    fd_accdb_close_ro( accdb, program_account );
    return;
  }

  /* Dump the programdata address */
  add_account_to_dumped_accounts( pool, root, &program_account_state->inner.program.programdata_address );
  fd_accdb_close_ro( accdb, program_account );
}

/* add_lut_account_to_dumped_accounts adds an address lookup table
   account AND all pubkeys in the lookup table to the dumped accounts
   set if they do not exist already. */
static void
add_lut_accounts_to_dumped_accounts( fd_accdb_user_t *             accdb,
                                     fd_funk_txn_xid_t const *     xid,
                                     fd_dump_account_key_node_t *  pool,
                                     fd_dump_account_key_node_t ** root,
                                     fd_pubkey_t const *           pubkey ) {
  /* Add the current account to the dumped accounts set. */
  add_account_to_dumped_accounts( pool, root, pubkey );

  /* Read the account and dump all pubkeys within the lookup table. */
  fd_accdb_ro_t lut_account[1];
  if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, lut_account, xid, pubkey ) ) ) {
    return;
  }

  uchar const  * data     = fd_accdb_ref_data_const( lut_account );
  ulong          data_len = fd_accdb_ref_data_sz   ( lut_account );

  /* Decode the ALUT account and dump all pubkeys within the lookup
     table. */
  if( data_len<FD_LOOKUP_TABLE_META_SIZE || (data_len&0x1fUL) ) {
    fd_accdb_close_ro( accdb, lut_account );
    return;
  }
  fd_pubkey_t const * lookup_addrs     = fd_type_pun_const( data+FD_LOOKUP_TABLE_META_SIZE );
  ulong               lookup_addrs_cnt = ( data_len-FD_LOOKUP_TABLE_META_SIZE)>>5UL; // = (dlen - 56) / 32
  for( ulong i=0UL; i<lookup_addrs_cnt; i++ ) {
    fd_pubkey_t const * referenced_pubkey = &lookup_addrs[i];
    add_account_and_programdata_to_dumped_accounts( accdb, xid, pool, root, referenced_pubkey );
  }
  fd_accdb_close_ro( accdb, lut_account );
}

/* create_synthetic_vote_account_from_vote_state creates a synthetic
   vote account from a vote state cache element. It fills in default
   values for unspecified fields and encodes the vote state into
   out_vote_account's data field. */
static void
create_synthetic_vote_account_from_vote_state( fd_vote_state_ele_t const *   vote_state,
                                               fd_spad_t *                   spad,
                                               fd_exec_test_vote_account_t * out_vote_account,
                                               int                           is_t_1 ) {
  out_vote_account->has_vote_account = true;
  fd_memcpy( out_vote_account->vote_account.address, &vote_state->vote_account, sizeof(fd_pubkey_t) );
  out_vote_account->vote_account.executable = false;
  out_vote_account->vote_account.lamports = 100000UL;
  fd_memcpy( out_vote_account->vote_account.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) );
  out_vote_account->stake = is_t_1 ? vote_state->stake_t_1 : vote_state->stake_t_2;

  /* Construct the vote account data. Fill in missing fields with
     arbitrary defaults (since they're not used anyways) */
  fd_vote_state_versioned_t vsv = {
    .discriminant = fd_vote_state_versioned_enum_v3,
    .inner = {
      .v3 = {
        .node_pubkey           = vote_state->node_account,
        .authorized_withdrawer = vote_state->node_account,
        .commission            = 0,
        .root_slot             = 0UL,
        .has_root_slot         = 0,
        .last_timestamp        = {
          .timestamp           = vote_state->last_vote_timestamp,
          .slot                = vote_state->last_vote_slot,
        },
      }
    }
  };
  fd_vote_state_v3_t * synthetic_vote_state = &vsv.inner.v3;

  /* Create synthetic landed votes */
  synthetic_vote_state->votes = deq_fd_landed_vote_t_join(
      deq_fd_landed_vote_t_new(
          fd_spad_alloc(
              spad,
              deq_fd_landed_vote_t_align(),
              deq_fd_landed_vote_t_footprint( 32UL ) ),
          32UL ) );
  for( ulong i=0UL; i<32UL; i++ ) {
    fd_landed_vote_t elem = {0};
    deq_fd_landed_vote_t_push_tail( synthetic_vote_state->votes, elem );
  }

  /* Populate authoritzed voters */
  void * authorized_voters_pool_mem  = fd_spad_alloc(
      spad,
      fd_vote_authorized_voters_pool_align(),
      fd_vote_authorized_voters_pool_footprint( 5UL ) );
  void * authorized_voters_treap_mem = fd_spad_alloc(
      spad,
      fd_vote_authorized_voters_treap_align(),
      fd_vote_authorized_voters_treap_footprint( 5UL ) );
  synthetic_vote_state->authorized_voters.pool  = fd_vote_authorized_voters_pool_join( fd_vote_authorized_voters_pool_new( authorized_voters_pool_mem, 5UL ) );
  synthetic_vote_state->authorized_voters.treap = fd_vote_authorized_voters_treap_join( fd_vote_authorized_voters_treap_new( authorized_voters_treap_mem, 5UL ) );

  /* Encode the synthetic vote state */
  ulong encoded_sz                          = fd_vote_state_versioned_size( &vsv );
  out_vote_account->vote_account.data       = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( encoded_sz ) );
  out_vote_account->vote_account.data->size = (pb_size_t)encoded_sz;

  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = out_vote_account->vote_account.data->bytes,
    .dataend = out_vote_account->vote_account.data->bytes+encoded_sz,
  };
  fd_vote_state_versioned_encode( &vsv, &encode_ctx );
}

static void FD_FN_UNUSED
dump_prior_vote_accounts( fd_vote_states_t const *      vote_states,
                          fd_dump_account_key_node_t *  dumped_accounts_pool,
                          fd_dump_account_key_node_t ** dumped_accounts_root,
                          fd_exec_test_vote_account_t * out_vote_accounts,
                          pb_size_t *                   out_vote_accounts_count,
                          fd_spad_t *                   spad,
                          int                           is_t_1 ) {

  fd_vote_states_iter_t iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states );
                                     !fd_vote_states_iter_done( iter );
                                      fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t const * vote_state = fd_vote_states_iter_ele( iter );
    add_account_to_dumped_accounts( dumped_accounts_pool, dumped_accounts_root, &vote_state->vote_account );

    create_synthetic_vote_account_from_vote_state(
        vote_state,
        spad,
        &out_vote_accounts[(*out_vote_accounts_count)++],
        is_t_1 );
  }
}

static void
create_block_context_protobuf_from_block( fd_block_dump_ctx_t * dump_ctx,
                                          fd_banks_t *          banks,
                                          fd_bank_t *           bank,
                                          fd_accdb_user_t *     accdb ) {
  /* We should use the bank fields and funk txn from the parent slot in
     order to capture the block context from before the current block
     was executed, since dumping is happening in the block finalize
     step. */
  fd_bank_t parent_bank[1];
  fd_banks_get_parent( parent_bank, banks, bank );
  ulong                          current_slot   = fd_bank_slot_get( bank );
  ulong                          parent_slot    = fd_bank_slot_get( parent_bank );
  fd_funk_txn_xid_t              parent_xid     = { .ul = { parent_slot, parent_bank->data->idx } };
  fd_exec_test_block_context_t * block_context  = &dump_ctx->block_context;
  ulong                          dump_txn_count = dump_ctx->txns_to_dump_cnt;
  fd_spad_t *                    spad           = dump_ctx->spad;

  /* Get vote and stake delegation infos */
  fd_vote_states_t const * vote_states        = fd_bank_vote_states_locking_query( parent_bank );
  ulong                    vote_account_t_cnt = fd_vote_states_cnt( vote_states );
  fd_bank_vote_states_end_locking_query( parent_bank );

  fd_stake_delegations_t const * stake_delegations = fd_bank_stake_delegations_frontier_query( banks, parent_bank );
  ulong                          stake_account_cnt = fd_stake_delegations_cnt( stake_delegations );

  /* Collect account states in a temporary set before iterating over
     them and dumping them out. */
  ulong                        total_num_accounts   = num_sysvar_entries +  /* Sysvars */
                                                      num_loaded_builtins + /* Builtins */
                                                      stake_account_cnt +   /* Stake accounts */
                                                      vote_account_t_cnt +  /* Current vote accounts */
                                                      dump_txn_count*128UL; /* Txn accounts upper bound */
  void *                       dumped_accounts_mem  = fd_spad_alloc( spad, fd_dump_account_key_map_align(), fd_dump_account_key_map_footprint( total_num_accounts ) );
  fd_dump_account_key_node_t * dumped_accounts_pool = fd_dump_account_key_map_join( fd_dump_account_key_map_new( dumped_accounts_mem, total_num_accounts ) );
  fd_dump_account_key_node_t * dumped_accounts_root = NULL;

  /* BlockContext -> txns */
  block_context->txns_count = (pb_size_t)dump_txn_count;
  block_context->txns       = fd_spad_alloc( spad, alignof(fd_exec_test_sanitized_transaction_t), dump_ctx->txns_to_dump_cnt * sizeof(fd_exec_test_sanitized_transaction_t) );
  fd_memset( block_context->txns, 0, dump_ctx->txns_to_dump_cnt * sizeof(fd_exec_test_sanitized_transaction_t) );

  /* Dump sanitized transactions from the transaction descriptors */
  for( ulong i=0UL; i<dump_ctx->txns_to_dump_cnt; i++ ) {
    fd_txn_p_t const * txn_ptr        = &dump_ctx->txns_to_dump[i];
    fd_txn_t const *   txn_descriptor = TXN( txn_ptr );
    dump_sanitized_transaction( accdb, &parent_xid, txn_descriptor, txn_ptr->payload, spad, &block_context->txns[i] );

    /* Dump account + alut + programdata accounts (if applicable).
       1. Dump the raw txn account keys
       2. Dump the ALUT accounts
       3. Dump all referenced accounts in the ALUTs
       4. Dump any executable accounts */

    // 1 + 4. Dump any account keys that are referenced by transactions
    // + any programdata accounts (if applicable).
    fd_acct_addr_t const * account_keys = fd_txn_get_acct_addrs( txn_descriptor, txn_ptr->payload );
    for( ushort l=0; l<txn_descriptor->acct_addr_cnt; l++ ) {
      fd_pubkey_t const * account_key = fd_type_pun_const( &account_keys[l] );
      add_account_and_programdata_to_dumped_accounts( accdb, &parent_xid, dumped_accounts_pool, &dumped_accounts_root, account_key );
    }

    // 2 + 3 + 4. Dump any ALUT accounts + any accounts referenced in
    // the ALUTs + any programdata accounts (if applicable).
    fd_txn_acct_addr_lut_t const * txn_lookup_tables = fd_txn_get_address_tables_const( txn_descriptor );
    for( ushort l=0; l<txn_descriptor->addr_table_lookup_cnt; l++ ) {
      fd_txn_acct_addr_lut_t const * lookup_table = &txn_lookup_tables[l];
      fd_pubkey_t const *            lut_key      = fd_type_pun_const( txn_ptr->payload+lookup_table->addr_off );
      add_lut_accounts_to_dumped_accounts( accdb, &parent_xid, dumped_accounts_pool, &dumped_accounts_root, lut_key );
    }
  }

  /* Dump sysvars */
  for( ulong i=0UL; i<num_sysvar_entries; i++ ) {
    add_account_to_dumped_accounts( dumped_accounts_pool, &dumped_accounts_root, fd_dump_sysvar_ids[i] );
  }

  /* Dump builtins */
  for( ulong i=0UL; i<num_loaded_builtins; i++ ) {
    add_account_to_dumped_accounts( dumped_accounts_pool, &dumped_accounts_root, fd_dump_builtin_ids[i] );
  }

  /* Dump stake accounts for this epoch */
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t * stake_delegation = fd_stake_delegations_iter_ele( iter );
    add_account_to_dumped_accounts( dumped_accounts_pool, &dumped_accounts_root, &stake_delegation->stake_account );
  }

  /* Dump vote accounts for this epoch */
  vote_states = fd_bank_vote_states_locking_query( parent_bank );
  fd_vote_states_iter_t vote_iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( vote_iter_, vote_states ); !fd_vote_states_iter_done( iter ); fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t const * vote_state = fd_vote_states_iter_ele( iter );
    add_account_to_dumped_accounts( dumped_accounts_pool, &dumped_accounts_root, &vote_state->vote_account );
  }

  // BlockContext -> EpochContext -> vote_accounts_t_1 (vote accounts at epoch T-1)
  block_context->epoch_ctx.vote_accounts_t_1 = fd_spad_alloc(
      spad,
      alignof(fd_exec_test_vote_account_t),
      sizeof(fd_exec_test_vote_account_t)*fd_vote_states_cnt( vote_states ) );
  block_context->epoch_ctx.vote_accounts_t_1_count = 0U;
  dump_prior_vote_accounts(
      vote_states,
      dumped_accounts_pool,
      &dumped_accounts_root,
      block_context->epoch_ctx.vote_accounts_t_1,
      &block_context->epoch_ctx.vote_accounts_t_1_count,
      spad,
      1 );

  // // BlockContext -> EpochContext -> vote_accounts_t_2 (vote accounts at epoch T-2)
  block_context->epoch_ctx.vote_accounts_t_2 = fd_spad_alloc(
    spad,
    alignof(fd_exec_test_vote_account_t),
    sizeof(fd_exec_test_vote_account_t)*fd_vote_states_cnt( vote_states ) );
  block_context->epoch_ctx.vote_accounts_t_2_count = 0U;
  dump_prior_vote_accounts(
      vote_states,
      dumped_accounts_pool,
      &dumped_accounts_root,
      block_context->epoch_ctx.vote_accounts_t_2,
      &block_context->epoch_ctx.vote_accounts_t_2_count,
      spad,
      0 );

  fd_bank_vote_states_end_locking_query( parent_bank );

  /* BlockContext -> acct_states
     Iterate over the set and dump all the account keys in one pass. */
  block_context->acct_states_count = 0U;
  block_context->acct_states       = fd_spad_alloc(
      spad,
      alignof(fd_exec_test_acct_state_t),
      fd_dump_account_key_map_size( dumped_accounts_pool, dumped_accounts_root )*sizeof(fd_exec_test_acct_state_t) );
  for( fd_dump_account_key_node_t * node = fd_dump_account_key_map_minimum( dumped_accounts_pool, dumped_accounts_root );
                                    node;
                                    node = fd_dump_account_key_map_successor( dumped_accounts_pool, node ) ) {
    fd_accdb_ro_t ro[1];
    if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, ro, &parent_xid, &node->key ) ) ) {
      continue;
    }
    dump_account_state(
        fd_accdb_ref_address( ro ),
        ro->meta,
        &block_context->acct_states[block_context->acct_states_count++],
        spad );
    fd_accdb_close_ro( accdb, ro );
  }

  /* BlockContext -> blockhash_queue */
  fd_blockhashes_t const * bhq   = fd_bank_block_hash_queue_query( parent_bank );
  block_context->blockhash_queue = fd_spad_alloc(
      spad,
      alignof(pb_bytes_array_t *),
      PB_BYTES_ARRAY_T_ALLOCSIZE((FD_BLOCKHASHES_MAX) * sizeof(pb_bytes_array_t *)) );
  block_context->blockhash_queue_count = 0U;
  dump_blockhash_queue( bhq, spad, block_context->blockhash_queue, &block_context->blockhash_queue_count );

  /* BlockContext -> SlotContext */
  block_context->has_slot_ctx                       = true;
  block_context->slot_ctx.slot                      = current_slot;
  block_context->slot_ctx.block_height              = fd_bank_block_height_get( bank );
  block_context->slot_ctx.prev_slot                 = fd_bank_parent_slot_get( bank );

  // We need to store the POH hash for the current block since we don't
  // recalculate it in the harnesses.
  fd_memcpy( block_context->slot_ctx.poh, fd_bank_poh_query( bank ), sizeof(fd_pubkey_t) );
  fd_memcpy( block_context->slot_ctx.parent_bank_hash, fd_bank_bank_hash_query( parent_bank ), sizeof(fd_pubkey_t) );

  fd_lthash_value_t const * parent_lthash = fd_bank_lthash_locking_query( parent_bank );
  fd_memcpy( block_context->slot_ctx.parent_lthash, parent_lthash, sizeof(fd_lthash_value_t) );
  fd_bank_lthash_end_locking_query( parent_bank );

  block_context->slot_ctx.prev_epoch_capitalization = fd_bank_capitalization_get( parent_bank );

  /* BlockContext -> SlotContext -> fee_rate_governor */
  fd_fee_rate_governor_t const * fee_rate_governor = fd_bank_fee_rate_governor_query( parent_bank );
  block_context->slot_ctx.has_fee_rate_governor     = true;
  block_context->slot_ctx.fee_rate_governor         = (fd_exec_test_fee_rate_governor_t){
      .target_lamports_per_signature = fee_rate_governor->target_lamports_per_signature,
      .target_signatures_per_slot    = fee_rate_governor->target_signatures_per_slot,
      .min_lamports_per_signature    = fee_rate_governor->min_lamports_per_signature,
      .max_lamports_per_signature    = fee_rate_governor->max_lamports_per_signature,
      .burn_percent                  = fee_rate_governor->burn_percent,
  };

  /* BlockContext -> EpochContext */
  block_context->has_epoch_ctx                        = true;
  block_context->epoch_ctx.has_features               = true;
  dump_sorted_features( fd_bank_features_query( parent_bank ), &block_context->epoch_ctx.features, spad );
  block_context->epoch_ctx.hashes_per_tick            = fd_bank_hashes_per_tick_get( parent_bank );
  block_context->epoch_ctx.ticks_per_slot             = fd_bank_ticks_per_slot_get( parent_bank );
  block_context->epoch_ctx.has_inflation              = true;

  fd_inflation_t const * inflation = fd_bank_inflation_query( parent_bank );
  block_context->epoch_ctx.inflation                  = (fd_exec_test_inflation_t) {
      .initial         = inflation->initial,
      .terminal        = inflation->terminal,
      .taper           = inflation->taper,
      .foundation      = inflation->foundation,
      .foundation_term = inflation->foundation_term,
  };
  block_context->epoch_ctx.genesis_creation_time      = fd_bank_genesis_creation_time_get( parent_bank );
}

static void
create_txn_context_protobuf_from_txn( fd_exec_test_txn_context_t * txn_context_msg,
                                      fd_runtime_t *               runtime,
                                      fd_bank_t *                  bank,
                                      fd_txn_in_t const *          txn_in,
                                      fd_txn_out_t *               txn_out,
                                      fd_spad_t *                  spad ) {
  fd_txn_t const * txn_descriptor = TXN( txn_in->txn );
  uchar const *    txn_payload    = (uchar const *) txn_in->txn->payload;

  /* Transaction Context -> account_shared_data
     Contains:
      - Account data for regular accounts
      - Account data for LUT accounts
      - Account data for executable accounts
      - Account data for (almost) all sysvars */
  txn_context_msg->account_shared_data_count = 0;
  txn_context_msg->account_shared_data = fd_spad_alloc( spad,
                                                        alignof(fd_exec_test_acct_state_t),
                                                        (256UL*2UL + txn_descriptor->addr_table_lookup_cnt + num_sysvar_entries) * sizeof(fd_exec_test_acct_state_t) );
  fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( bank ), bank->data->idx } };

  /* Dump regular accounts first */
  for( ulong i = 0; i < txn_out->accounts.cnt; ++i ) {
    dump_account_if_not_already_dumped(
      runtime->accdb,
      &xid,
      &txn_out->accounts.keys[i],
      spad,
      txn_context_msg->account_shared_data,
      &txn_context_msg->account_shared_data_count,
      NULL
    );
  }

  // Dump LUT accounts
  fd_txn_acct_addr_lut_t const * address_lookup_tables = fd_txn_get_address_tables_const( txn_descriptor );
  for( ulong i = 0; i < txn_descriptor->addr_table_lookup_cnt; ++i ) {
    fd_txn_acct_addr_lut_t const * addr_lut  = &address_lookup_tables[i];
    fd_pubkey_t * alut_key = (fd_pubkey_t *) (txn_payload + addr_lut->addr_off);

    // Dump the LUT account itself if not already dumped
    fd_accdb_ro_t ro[1];
    int ret = dump_account_if_not_already_dumped(
        runtime->accdb,
        &xid,
        alut_key,
        spad,
        txn_context_msg->account_shared_data,
        &txn_context_msg->account_shared_data_count,
        ro
    );
    if( FD_UNLIKELY( ret ) ) continue;

    uchar const * alut_data = fd_accdb_ref_data_const( ro );
    ulong         alut_sz   = fd_accdb_ref_data_sz   ( ro );

    if( FD_UNLIKELY( alut_sz<FD_LOOKUP_TABLE_META_SIZE ) ) {
      /* Skip over invalid address lookup tables */
      fd_accdb_close_ro( runtime->accdb, ro );
      continue;
    }

    fd_pubkey_t const * lookup_addrs     = fd_type_pun_const( alut_data+FD_LOOKUP_TABLE_META_SIZE );
    ulong               lookup_addrs_cnt = (alut_sz - FD_LOOKUP_TABLE_META_SIZE) / sizeof(fd_pubkey_t);

    /* Dump any account state refererenced in ALUTs */
    uchar const * writable_lut_idxs = txn_payload + addr_lut->writable_off;
    for( ulong j=0; j<addr_lut->writable_cnt; j++ ) {
      if( writable_lut_idxs[j] >= lookup_addrs_cnt ) {
        continue;
      }
      fd_pubkey_t const * referenced_addr = lookup_addrs + writable_lut_idxs[j];
      dump_account_if_not_already_dumped(
          runtime->accdb,
          &xid,
          referenced_addr,
          spad,
          txn_context_msg->account_shared_data,
          &txn_context_msg->account_shared_data_count,
          NULL
      );
    }

    uchar const * readonly_lut_idxs = txn_payload + addr_lut->readonly_off;
    for( ulong j = 0; j < addr_lut->readonly_cnt; j++ ) {
      if( readonly_lut_idxs[j] >= lookup_addrs_cnt ) {
        continue;
      }
      fd_pubkey_t const * referenced_addr = lookup_addrs + readonly_lut_idxs[j];
      dump_account_if_not_already_dumped(
          runtime->accdb,
          &xid,
          referenced_addr,
          spad,
          txn_context_msg->account_shared_data,
          &txn_context_msg->account_shared_data_count,
          NULL
      );
    }

    fd_accdb_close_ro( runtime->accdb, ro );
  }

  /* Dump the programdata accounts for any potential v3-owned program accounts */
  uint accounts_dumped_so_far = txn_context_msg->account_shared_data_count;
  for( uint i=0U; i<accounts_dumped_so_far; i++ ) {
    fd_exec_test_acct_state_t const * maybe_program_account = &txn_context_msg->account_shared_data[i];
    dump_executable_account_if_exists( runtime->accdb, &xid, maybe_program_account, spad, txn_context_msg->account_shared_data, &txn_context_msg->account_shared_data_count );
  }

  /* Dump sysvars */
  for( ulong i = 0; i < num_sysvar_entries; i++ ) {
    dump_account_if_not_already_dumped(
        runtime->accdb,
        &xid,
        fd_dump_sysvar_ids[i],
        spad,
        txn_context_msg->account_shared_data,
        &txn_context_msg->account_shared_data_count,
        NULL
    );
  }

  /* Transaction Context -> tx */
  txn_context_msg->has_tx = true;
  fd_exec_test_sanitized_transaction_t * sanitized_transaction = &txn_context_msg->tx;
  dump_sanitized_transaction( runtime->accdb, &xid, txn_descriptor, txn_payload, spad, sanitized_transaction );

  /* Transaction Context -> bank */
  dump_txn_bank( bank, spad, txn_context_msg );
}

static void
create_instr_context_protobuf_from_instructions( fd_exec_test_instr_context_t * instr_context,
                                                 fd_runtime_t *                 runtime,
                                                 fd_bank_t *                    bank,
                                                 fd_txn_out_t *                 txn_out,
                                                 fd_instr_info_t const *        instr,
                                                 fd_spad_t *                    spad ) {
  /* Program ID */
  fd_memcpy( instr_context->program_id, txn_out->accounts.keys[ instr->program_id ].uc, sizeof(fd_pubkey_t) );

  fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( bank ), bank->data->idx } };

  /* Accounts */
  instr_context->accounts_count = (pb_size_t) txn_out->accounts.cnt;
  instr_context->accounts = fd_spad_alloc( spad, alignof(fd_exec_test_acct_state_t), (instr_context->accounts_count + num_sysvar_entries + runtime->accounts.executable_cnt) * sizeof(fd_exec_test_acct_state_t));
  for( ulong i = 0; i < txn_out->accounts.cnt; i++ ) {
    // Copy account information over
    fd_account_meta_t * account_meta = txn_out->accounts.account[i].meta;
    fd_exec_test_acct_state_t * output_account = &instr_context->accounts[i];
    dump_account_state( &txn_out->accounts.keys[i], account_meta, output_account, spad );
  }

  /* Add sysvar cache variables */
  for( ulong i = 0; i < num_sysvar_entries; i++ ) {
    fd_accdb_ro_t ro[1];
    if( !fd_accdb_open_ro( runtime->accdb, ro, &xid, fd_dump_sysvar_ids[i] ) ) {
      continue;
    }
    // Make sure the account doesn't exist in the output accounts yet
    int account_exists = 0;
    for( ulong j = 0; j < txn_out->accounts.cnt; j++ ) {
      if( fd_pubkey_eq( &txn_out->accounts.keys[j], fd_dump_sysvar_ids[i] ) ) {
        account_exists = true;
        break;
      }
    }

    // Copy it into output
    if( !account_exists ) {
      fd_exec_test_acct_state_t * output_account = &instr_context->accounts[instr_context->accounts_count++];
      dump_account_state( fd_accdb_ref_address( ro ), ro->meta, output_account, spad );
    }
    fd_accdb_close_ro( runtime->accdb, ro );
  }

  /* Add executable accounts */
  for( ulong i = 0; i < runtime->accounts.executable_cnt; i++ ) {
    // Make sure the account doesn't exist in the output accounts yet
    fd_accdb_ro_t const * ro = &runtime->accounts.executable[i];
    bool account_exists = false;
    for( ulong j = 0; j < instr_context->accounts_count; j++ ) {
      if( 0 == memcmp( instr_context->accounts[j].address, fd_accdb_ref_address( ro ), sizeof(fd_pubkey_t) ) ) {
        account_exists = true;
        break;
      }
    }
    // Copy it into output
    if( !account_exists ) {
      fd_exec_test_acct_state_t * output_account = &instr_context->accounts[instr_context->accounts_count++];
      dump_account_state( fd_accdb_ref_address( ro ), ro->meta, output_account, spad );
    }
  }

  /* Instruction Accounts */
  instr_context->instr_accounts_count = (pb_size_t) instr->acct_cnt;
  instr_context->instr_accounts = fd_spad_alloc( spad, alignof(fd_exec_test_instr_acct_t), instr_context->instr_accounts_count * sizeof(fd_exec_test_instr_acct_t) );
  for( ushort i = 0; i < instr->acct_cnt; i++ ) {
    fd_exec_test_instr_acct_t * output_instr_account = &instr_context->instr_accounts[i];

    output_instr_account->index       = instr->accounts[i].index_in_transaction;
    output_instr_account->is_writable = instr->accounts[i].is_writable;
    output_instr_account->is_signer   = instr->accounts[i].is_signer;
  }

  /* Data */
  instr_context->data = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( instr->data_sz ) );
  instr_context->data->size = (pb_size_t) instr->data_sz;
  fd_memcpy( instr_context->data->bytes, instr->data, instr->data_sz );

  /* Compute Units */
  instr_context->cu_avail = txn_out->details.compute_budget.compute_meter;

  /* Epoch Context */
  instr_context->has_epoch_context = true;
  instr_context->epoch_context.has_features = true;
  dump_sorted_features( fd_bank_features_query( bank ), &instr_context->epoch_context.features, spad );
}

/***** PUBLIC APIs *****/

void
fd_dump_instr_to_protobuf( fd_runtime_t *      runtime,
                           fd_bank_t *         bank,
                           fd_txn_in_t const * txn_in,
                           fd_txn_out_t *      txn_out,
                           fd_instr_info_t *   instr,
                           ushort              instruction_idx ) {
  /* Check program ID filter, if it exists */
  if( runtime->log.dump_proto_ctx->has_dump_instr_program_id_filter &&
      memcmp( txn_out->accounts.keys[ instr->program_id ].uc, runtime->log.dump_proto_ctx->dump_instr_program_id_filter, sizeof(fd_pubkey_t) ) ) {
    return;
  }

  fd_spad_t * spad = fd_spad_join( fd_spad_new( runtime->log.dumping_mem, 1UL<<28UL ) );

  FD_SPAD_FRAME_BEGIN( spad ) {
    // Get base58-encoded tx signature
    const fd_ed25519_sig_t * signatures = fd_txn_get_signatures( TXN( txn_in->txn ), txn_in->txn->payload );
    char encoded_signature[FD_BASE58_ENCODED_64_SZ];
    fd_base58_encode_64( signatures[0], NULL, encoded_signature );

    fd_exec_test_instr_context_t instr_context = FD_EXEC_TEST_INSTR_CONTEXT_INIT_DEFAULT;
    create_instr_context_protobuf_from_instructions( &instr_context, runtime, bank, txn_out, instr, spad );

    /* Output to file */
    ulong        out_buf_size = 100 * 1024 * 1024;
    uint8_t *    out          = fd_spad_alloc( spad, alignof(uchar) , out_buf_size );
    pb_ostream_t stream       = pb_ostream_from_buffer( out, out_buf_size );
    if (pb_encode(&stream, FD_EXEC_TEST_INSTR_CONTEXT_FIELDS, &instr_context)) {
      char output_filepath[ PATH_MAX ];
      snprintf( output_filepath, PATH_MAX, "%s/instr-%s-%hu.instrctx", runtime->log.dump_proto_ctx->dump_proto_output_dir, encoded_signature, instruction_idx );
      FILE * file = fopen(output_filepath, "wb");
      if( file ) {
        fwrite( out, 1, stream.bytes_written, file );
        fclose( file );
      }
    }
  } FD_SPAD_FRAME_END;
}

/* Writes a single account state into the resulting_state field of a
   TxnResult protobuf.  Sub-allocations for account data are bump-
   allocated from the caller's scratch region via _l. */
static void
write_account_to_result( fd_pubkey_t const *              pubkey,
                         fd_account_meta_t const *        meta,
                         fd_exec_test_acct_state_t *      out_accounts,
                         pb_size_t *                      out_accounts_cnt,
                         ulong *                          scratch_cur,
                         ulong                            scratch_end ) {
  fd_exec_test_acct_state_t * out_acct = &out_accounts[ *out_accounts_cnt ];
  (*out_accounts_cnt)++;

  memset( out_acct, 0, sizeof(fd_exec_test_acct_state_t) );
  memcpy( out_acct->address, pubkey, sizeof(fd_pubkey_t) );
  out_acct->lamports = meta->lamports;

  if( meta->dlen>0UL ) {
    pb_bytes_array_t * data = (pb_bytes_array_t *)fd_ulong_align_up( *scratch_cur, alignof(pb_bytes_array_t) );
    *scratch_cur = (ulong)data + PB_BYTES_ARRAY_T_ALLOCSIZE( meta->dlen );
    if( FD_UNLIKELY( *scratch_cur > scratch_end ) ) abort();
    data->size = (pb_size_t)meta->dlen;
    fd_memcpy( data->bytes, fd_account_data( meta ), meta->dlen );
    out_acct->data = data;
  }

  out_acct->executable = meta->executable;
  memcpy( out_acct->owner, meta->owner, sizeof(fd_pubkey_t) );
}

ulong
create_txn_result_protobuf_from_txn( fd_exec_test_txn_result_t ** txn_result_out,
                                     void *                       out_buf,
                                     ulong                        out_bufsz,
                                     fd_txn_in_t const *          txn_in,
                                     fd_txn_out_t *               txn_out,
                                     fd_bank_t *                  bank,
                                     int                          exec_res ) {
  FD_SCRATCH_ALLOC_INIT( l, out_buf );
  ulong out_end = (ulong)out_buf + out_bufsz;

  fd_exec_test_txn_result_t * txn_result =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_txn_result_t),
                                sizeof(fd_exec_test_txn_result_t) );
  if( FD_UNLIKELY( _l > out_end ) ) abort();
  fd_memset( txn_result, 0, sizeof(fd_exec_test_txn_result_t) );

  /* Map nonce errors into the agave expected ones. */
  if( FD_UNLIKELY( exec_res==FD_RUNTIME_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED ||
                   exec_res==FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_ADVANCE_NONCE_INSTR ||
                   exec_res==FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_WRONG_NONCE )) {
    exec_res = FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
  }

  /* Basic result fields */
  txn_result->executed                  = txn_out->err.is_committable;
  txn_result->sanitization_error        = !txn_out->err.is_committable;
  txn_result->modified_accounts_count   = 0;
  txn_result->rollback_accounts_count   = 0;
  txn_result->is_ok                     = !exec_res;
  txn_result->status                    = (uint32_t) -exec_res;
  txn_result->instruction_error         = 0;
  txn_result->instruction_error_index   = 0;
  txn_result->custom_error              = 0;
  txn_result->has_fee_details           = false;
  txn_result->loaded_accounts_data_size = txn_out->details.loaded_accounts_data_size;

  if( txn_result->sanitization_error ) {
    if( txn_out->err.is_fees_only ) {
      txn_result->has_fee_details                = true;
      txn_result->fee_details.prioritization_fee = txn_out->details.priority_fee;
      txn_result->fee_details.transaction_fee    = txn_out->details.execution_fee;
    }

    if( exec_res==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR ) {
      txn_result->instruction_error       = (uint32_t) -txn_out->err.exec_err;
      txn_result->instruction_error_index = (uint32_t) txn_out->err.exec_err_idx;
      if( txn_out->err.exec_err==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
        txn_result->custom_error = txn_out->err.custom_err;
      }
    }

    *txn_result_out = txn_result;
    return FD_SCRATCH_ALLOC_FINI( l, 1UL ) - (ulong)out_buf;
  }

  /* Capture instruction error code for executed transactions */
  if( exec_res==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR ) {
    fd_txn_t const * txn            = TXN( txn_in->txn );
    int              instr_err_idx  = txn_out->err.exec_err_idx;
    int              program_id_idx = txn->instr[instr_err_idx].program_id;

    txn_result->instruction_error       = (uint32_t) -txn_out->err.exec_err;
    txn_result->instruction_error_index = (uint32_t) instr_err_idx;

    if( txn_out->err.exec_err==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR &&
        fd_executor_lookup_native_precompile_program( &txn_out->accounts.keys[ program_id_idx ] )==NULL ) {
      txn_result->custom_error = txn_out->err.custom_err;
    }
  }

  txn_result->has_fee_details                = true;
  txn_result->fee_details.transaction_fee    = txn_out->details.execution_fee;
  txn_result->fee_details.prioritization_fee = txn_out->details.priority_fee;
  txn_result->executed_units                 = txn_out->details.compute_budget.compute_unit_limit - txn_out->details.compute_budget.compute_meter;

  /* Return data */
  if( txn_out->details.return_data.len>0 ) {
    txn_result->return_data = FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                                       PB_BYTES_ARRAY_T_ALLOCSIZE( txn_out->details.return_data.len ) );
    if( FD_UNLIKELY( _l > out_end ) ) abort();
    txn_result->return_data->size = (pb_size_t)txn_out->details.return_data.len;
    fd_memcpy( txn_result->return_data->bytes, txn_out->details.return_data.data, txn_out->details.return_data.len );
  }

  /* Modified accounts */
  txn_result->modified_accounts = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_acct_state_t), sizeof(fd_exec_test_acct_state_t) * txn_out->accounts.cnt );
  txn_result->rollback_accounts = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_acct_state_t), sizeof(fd_exec_test_acct_state_t) * 2UL );
  if( FD_UNLIKELY( _l > out_end ) ) abort();

  if( txn_out->err.is_fees_only || exec_res!=FD_RUNTIME_EXECUTE_SUCCESS ) {
    /* If the transaction errored, capture the rollback accounts (fee payer and nonce). */
    if( FD_LIKELY( txn_out->accounts.nonce_idx_in_txn!=FD_FEE_PAYER_TXN_IDX ) ) {
      write_account_to_result(
        &txn_out->accounts.keys[FD_FEE_PAYER_TXN_IDX],
        txn_out->accounts.rollback_fee_payer,
        txn_result->rollback_accounts,
        &txn_result->rollback_accounts_count,
        &_l,
        out_end
      );
    }

    if( txn_out->accounts.nonce_idx_in_txn!=ULONG_MAX ) {
      write_account_to_result(
        &txn_out->accounts.keys[txn_out->accounts.nonce_idx_in_txn],
        txn_out->accounts.rollback_nonce,
        txn_result->rollback_accounts,
        &txn_result->rollback_accounts_count,
        &_l,
        out_end
      );
    }
  }

  if( !txn_out->err.is_fees_only ) {
    /* Executed: capture fee payer and writable accounts. */
    for( ulong j=0UL; j<txn_out->accounts.cnt; j++ ) {
      if( !( fd_runtime_account_is_writable_idx( txn_in, txn_out, bank, (ushort)j ) ||
             j==FD_FEE_PAYER_TXN_IDX ) ) {
        continue;
      }

      write_account_to_result(
        &txn_out->accounts.keys[j],
        txn_out->accounts.account[j].meta,
        txn_result->modified_accounts,
        &txn_result->modified_accounts_count,
        &_l,
        out_end
      );
    }
  }

  *txn_result_out = txn_result;
  return FD_SCRATCH_ALLOC_FINI( l, 1UL ) - (ulong)out_buf;
}

void
fd_dump_txn_to_protobuf( fd_runtime_t *      runtime,
                         fd_bank_t *         bank,
                         fd_txn_in_t const * txn_in,
                         fd_txn_out_t *      txn_out ) {
  fd_spad_t * spad = fd_spad_join( fd_spad_new( runtime->log.dumping_mem, 1UL<<28UL ) );

  FD_SPAD_FRAME_BEGIN( spad ) {
    // Get base58-encoded tx signature
    const fd_ed25519_sig_t * signatures = fd_txn_get_signatures( TXN( txn_in->txn ), txn_in->txn->payload );
    char encoded_signature[FD_BASE58_ENCODED_64_SZ];
    fd_base58_encode_64( signatures[0], NULL, encoded_signature );

    fd_exec_test_txn_context_t txn_context_msg = FD_EXEC_TEST_TXN_CONTEXT_INIT_DEFAULT;
    create_txn_context_protobuf_from_txn( &txn_context_msg, runtime, bank, txn_in, txn_out, spad );

    /* Output to file */
    ulong        out_buf_size = 100UL<<20UL; // 100 MB
    uchar *      out          = fd_spad_alloc( spad, alignof(uchar), out_buf_size );
    pb_ostream_t stream       = pb_ostream_from_buffer( out, out_buf_size );
    if( pb_encode( &stream, FD_EXEC_TEST_TXN_CONTEXT_FIELDS, &txn_context_msg ) ) {
      char output_filepath[ PATH_MAX ];
      snprintf( output_filepath, PATH_MAX, "%s/txn-%s.txnctx", runtime->log.dump_proto_ctx->dump_proto_output_dir, encoded_signature );
      FILE * file = fopen(output_filepath, "wb");
      if( file ) {
        fwrite( out, 1, stream.bytes_written, file );
        fclose( file );
      }
    }
  } FD_SPAD_FRAME_END;
}

void
fd_dump_txn_context_to_protobuf( fd_txn_dump_ctx_t * txn_dump_ctx,
                                 fd_runtime_t *      runtime,
                                 fd_bank_t *         bank,
                                 fd_txn_in_t const * txn_in,
                                 fd_txn_out_t *      txn_out ) {
  fd_txn_dump_context_reset( txn_dump_ctx );

  txn_dump_ctx->fixture.has_metadata = true;
  strncpy(
      txn_dump_ctx->fixture.metadata.fn_entrypoint,
      "sol_compat_txn_execute_v1",
      sizeof(txn_dump_ctx->fixture.metadata.fn_entrypoint)-1UL
  );

  txn_dump_ctx->fixture.has_input = true;
  create_txn_context_protobuf_from_txn( &txn_dump_ctx->fixture.input,
                                        runtime, bank, txn_in, txn_out,
                                        txn_dump_ctx->spad );
}

void
fd_dump_txn_result_to_protobuf( fd_txn_dump_ctx_t * txn_dump_ctx,
                                fd_txn_in_t const * txn_in,
                                fd_txn_out_t *      txn_out,
                                fd_bank_t *         bank,
                                int                 exec_res ) {
  txn_dump_ctx->fixture.has_output = true;

  ulong  buf_sz = 100UL<<20UL;
  void * buf    = fd_spad_alloc( txn_dump_ctx->spad, alignof(fd_exec_test_txn_result_t), buf_sz );
  fd_exec_test_txn_result_t * result = NULL;
  create_txn_result_protobuf_from_txn( &result, buf, buf_sz, txn_in, txn_out, bank, exec_res );
  txn_dump_ctx->fixture.output = *result;
}

void
fd_dump_txn_fixture_to_file( fd_txn_dump_ctx_t *         txn_dump_ctx,
                             fd_dump_proto_ctx_t const * dump_proto_ctx,
                             fd_txn_in_t const *         txn_in ) {
  const fd_ed25519_sig_t * signatures = fd_txn_get_signatures( TXN( txn_in->txn ), txn_in->txn->payload );
  char encoded_signature[FD_BASE58_ENCODED_64_SZ];
  fd_base58_encode_64( signatures[0], NULL, encoded_signature );

  FD_SPAD_FRAME_BEGIN( txn_dump_ctx->spad ) {
    ulong        out_buf_size = 100UL<<20UL;
    uchar *      out          = fd_spad_alloc( txn_dump_ctx->spad, alignof(uchar), out_buf_size );
    pb_ostream_t stream       = pb_ostream_from_buffer( out, out_buf_size );

    char output_filepath[ PATH_MAX ];

    if( dump_proto_ctx->dump_txn_as_fixture ) {
      if( pb_encode( &stream, FD_EXEC_TEST_TXN_FIXTURE_FIELDS, &txn_dump_ctx->fixture ) ) {
        snprintf( output_filepath, PATH_MAX, "%s/txn-%s.fix", dump_proto_ctx->dump_proto_output_dir, encoded_signature );
        FILE * file = fopen( output_filepath, "wb" );
        if( file ) {
          fwrite( out, 1, stream.bytes_written, file );
          fclose( file );
        }
      }
    } else {
      if( pb_encode( &stream, FD_EXEC_TEST_TXN_CONTEXT_FIELDS, &txn_dump_ctx->fixture.input ) ) {
        snprintf( output_filepath, PATH_MAX, "%s/txn-%s.txnctx", dump_proto_ctx->dump_proto_output_dir, encoded_signature );
        FILE * file = fopen( output_filepath, "wb" );
        if( file ) {
          fwrite( out, 1, stream.bytes_written, file );
          fclose( file );
        }
      }
    }
  } FD_SPAD_FRAME_END;
}

void
fd_dump_block_to_protobuf_collect_tx( fd_block_dump_ctx_t * dump_block_ctx,
                                      fd_txn_p_t const *    txn ) {
  if( FD_UNLIKELY( dump_block_ctx->txns_to_dump_cnt>=FD_BLOCK_DUMP_CTX_MAX_TXN_CNT ) ) {
    FD_LOG_ERR(( "Please increase FD_BLOCK_DUMP_CTX_MAX_TXN_CNT to dump more than %lu transactions.", FD_BLOCK_DUMP_CTX_MAX_TXN_CNT ));
    return;
  }
  fd_memcpy( &dump_block_ctx->txns_to_dump[dump_block_ctx->txns_to_dump_cnt++], txn, sizeof(fd_txn_p_t) );
}

void
fd_dump_block_to_protobuf( fd_block_dump_ctx_t *       dump_block_ctx,
                           fd_banks_t *                banks,
                           fd_bank_t *                 bank,
                           fd_accdb_user_t *           accdb,
                           fd_dump_proto_ctx_t const * dump_proto_ctx ) {
  if( FD_UNLIKELY( dump_block_ctx==NULL ) ) {
    FD_LOG_WARNING(( "Block dumping context may not be NULL when dumping blocks." ));
    return;
  }

FD_SPAD_FRAME_BEGIN( dump_block_ctx->spad ) {
  if( FD_UNLIKELY( dump_proto_ctx==NULL ) ) {
    FD_LOG_WARNING(( "Protobuf dumping context may not be NULL when dumping blocks." ));
    return;
  }

  /* Dump the block context */
  create_block_context_protobuf_from_block( dump_block_ctx, banks, bank, accdb );

  /* Output to file */
  ulong        out_buf_size = 1UL<<30UL; /* 1 GB */
  uint8_t *    out          = fd_spad_alloc( dump_block_ctx->spad, alignof(uint8_t), out_buf_size );
  pb_ostream_t stream       = pb_ostream_from_buffer( out, out_buf_size );
  if( pb_encode( &stream, FD_EXEC_TEST_BLOCK_CONTEXT_FIELDS, &dump_block_ctx->block_context ) ) {
    char output_filepath[ PATH_MAX ];
    snprintf( output_filepath, PATH_MAX, "%s/block-%lu.blockctx", dump_proto_ctx->dump_proto_output_dir, fd_bank_slot_get( bank ) );
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
  char const * syscall_name_filter = vm->instr_ctx->runtime->log.dump_proto_ctx->dump_syscall_name_filter;
  if( syscall_name_filter && strlen( syscall_name_filter ) && strcmp( syscall_name_filter, fn_name ) ) {
    return;
  }

  fd_spad_t * spad = fd_spad_join( fd_spad_new( vm->instr_ctx->runtime->log.dumping_mem, 1UL<<28UL ) );

  FD_SPAD_FRAME_BEGIN( spad ) {

  fd_ed25519_sig_t signature;
  memcpy( signature, (uchar const *)vm->instr_ctx->txn_in->txn->payload + TXN( vm->instr_ctx->txn_in->txn )->signature_off, sizeof(fd_ed25519_sig_t) );
  char encoded_signature[FD_BASE58_ENCODED_64_SZ];
  fd_base58_encode_64( signature, NULL, encoded_signature );

  char filename[ PATH_MAX ];
  snprintf( filename,
          PATH_MAX,
          "%s/syscall-%s-%s-%d-%hhu-%lu.sysctx",
          vm->instr_ctx->runtime->log.dump_proto_ctx->dump_proto_output_dir,
          fn_name,
          encoded_signature,
          vm->instr_ctx->runtime->instr.current_idx,
          vm->instr_ctx->runtime->instr.stack_sz,
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
  sys_ctx.vm_ctx.rodata = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( vm->rodata_sz ) );
  sys_ctx.vm_ctx.rodata->size = (pb_size_t) vm->rodata_sz;
  fd_memcpy( sys_ctx.vm_ctx.rodata->bytes, vm->rodata, vm->rodata_sz );

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
  sys_ctx.vm_ctx.return_data.data = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( vm->instr_ctx->txn_out->details.return_data.len ) );
  sys_ctx.vm_ctx.return_data.data->size = (pb_size_t)vm->instr_ctx->txn_out->details.return_data.len;
  fd_memcpy( sys_ctx.vm_ctx.return_data.data->bytes, vm->instr_ctx->txn_out->details.return_data.data, vm->instr_ctx->txn_out->details.return_data.len );

  /* SyscallContext -> vm_ctx -> return_data -> program_id */
  sys_ctx.vm_ctx.return_data.program_id = fd_spad_alloc( spad, alignof(pb_bytes_array_t), sizeof(fd_pubkey_t) );
  sys_ctx.vm_ctx.return_data.program_id->size = sizeof(fd_pubkey_t);
  fd_memcpy( sys_ctx.vm_ctx.return_data.program_id->bytes, vm->instr_ctx->txn_out->details.return_data.program_id.key, sizeof(fd_pubkey_t) );

  /* SyscallContext -> vm_ctx -> sbpf_version */
  sys_ctx.vm_ctx.sbpf_version = (uint)vm->sbpf_version;

  /* SyscallContext -> instr_ctx */
  sys_ctx.has_instr_ctx = 1;
  create_instr_context_protobuf_from_instructions( &sys_ctx.instr_ctx,
                                                   vm->instr_ctx->runtime,
                                                   vm->instr_ctx->bank,
                                                   vm->instr_ctx->txn_out,
                                                   vm->instr_ctx->instr,
                                                   spad );

  /* SyscallContext -> syscall_invocation */
  sys_ctx.has_syscall_invocation = 1;

  /* SyscallContext -> syscall_invocation -> function_name */
  sys_ctx.syscall_invocation.function_name.size = fd_uint_min( (uint) strlen(fn_name), sizeof(sys_ctx.syscall_invocation.function_name.bytes) );
  fd_memcpy( sys_ctx.syscall_invocation.function_name.bytes,
             fn_name,
             sys_ctx.syscall_invocation.function_name.size );

  /* SyscallContext -> syscall_invocation -> heap_prefix */
  sys_ctx.syscall_invocation.heap_prefix = fd_spad_alloc( spad, 8UL, PB_BYTES_ARRAY_T_ALLOCSIZE( vm->heap_max ) );
  sys_ctx.syscall_invocation.heap_prefix->size = (pb_size_t) vm->instr_ctx->txn_out->details.compute_budget.heap_size;
  fd_memcpy( sys_ctx.syscall_invocation.heap_prefix->bytes, vm->heap, vm->instr_ctx->txn_out->details.compute_budget.heap_size );

  /* SyscallContext -> syscall_invocation -> stack_prefix */
  pb_size_t stack_sz = (pb_size_t)FD_VM_STACK_MAX;
  sys_ctx.syscall_invocation.stack_prefix = fd_spad_alloc( spad, 8UL, PB_BYTES_ARRAY_T_ALLOCSIZE( stack_sz ) );
  sys_ctx.syscall_invocation.stack_prefix->size = stack_sz;
  fd_memcpy( sys_ctx.syscall_invocation.stack_prefix->bytes, vm->stack, stack_sz );

  /* Output to file */
  ulong out_buf_size = 1UL<<29UL; /* 128 MB */
  uint8_t * out = fd_spad_alloc( spad, alignof(uint8_t), out_buf_size );
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
