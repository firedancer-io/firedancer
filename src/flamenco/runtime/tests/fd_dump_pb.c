#include "fd_dump_pb.h"
#include "generated/block.pb.h"
#include "generated/invoke.pb.h"
#include "generated/txn.pb.h"
#include "generated/vm.pb.h"
#include "../fd_system_ids.h"
#include "../fd_bank.h"
#include "../fd_runtime.h"
#include "../program/fd_address_lookup_table_program.h"
#include "../../../ballet/nanopb/pb_encode.h"
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

/** GENERAL UTILITY FUNCTIONS AND MACROS **/

static inline int
is_builtin_account( fd_pubkey_t const * account_key ) {
  for( ulong j=0UL; j<num_loaded_builtins; j++ ) {
    if( !memcmp( account_key, fd_dump_builtin_ids[j], sizeof(fd_pubkey_t) ) ) {
      return 1;
    }
  }
  return 0;
}

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
dump_account_state( fd_txn_account_t const *    txn_account,
                    fd_exec_test_acct_state_t * output_account,
                    fd_spad_t *                 spad ) {
    // Address
    fd_memcpy(output_account->address, txn_account->pubkey, sizeof(fd_pubkey_t));

    // Lamports
    output_account->lamports = (uint64_t)fd_txn_account_get_lamports( txn_account );

    // Data
    output_account->data = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( fd_txn_account_get_data_len( txn_account ) ) );
    output_account->data->size = (pb_size_t) fd_txn_account_get_data_len( txn_account );
    fd_memcpy(output_account->data->bytes, fd_txn_account_get_data( txn_account ), fd_txn_account_get_data_len( txn_account ) );

    // Executable
    output_account->executable = (bool)fd_txn_account_is_executable( txn_account );

    // Owner
    fd_memcpy(output_account->owner, fd_txn_account_get_owner( txn_account ), sizeof(fd_pubkey_t));
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
dump_account_if_not_already_dumped( fd_funk_t const *           funk,
                                    fd_funk_txn_xid_t const *   xid,
                                    fd_pubkey_t const *         account_key,
                                    fd_spad_t *                 spad,
                                    fd_exec_test_acct_state_t * out_acct_states,
                                    pb_size_t *                 out_acct_states_cnt,
                                    fd_txn_account_t *          opt_out_borrowed_account ) {
  fd_txn_account_t account[1];
  if( fd_txn_account_init_from_funk_readonly( account, account_key, funk, xid ) ) {
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

static void
dump_executable_account_if_exists( fd_funk_t const *                 funk,
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
  dump_account_if_not_already_dumped( funk, xid, programdata_acc, spad, out_account_states, out_account_states_count, NULL );
}

static void
dump_sanitized_transaction( fd_funk_t *                            funk,
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
      fd_txn_account_t addr_lut_rec[1];
      int err = fd_txn_account_init_from_funk_readonly( addr_lut_rec, alut_key, funk, xid );
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
add_account_and_programdata_to_dumped_accounts( fd_funk_t *                   funk,
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
  fd_txn_account_t program_account[1];
  int err = fd_txn_account_init_from_funk_readonly( program_account, pubkey, funk, xid );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return;
  }

  /* Return if its not owned by the v3 loader */
  if( FD_LIKELY( memcmp( fd_txn_account_get_owner( program_account ), fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return;
  }

  /* Get the program account state */
  fd_bpf_upgradeable_loader_state_t program_account_state[1];
  if( FD_UNLIKELY( !fd_bincode_decode_static(
      bpf_upgradeable_loader_state,
      program_account_state,
      fd_txn_account_get_data( program_account ),
      fd_txn_account_get_data_len( program_account ),
      NULL ) ) ) {
    return;
  }
  if( !fd_bpf_upgradeable_loader_state_is_program( program_account_state ) ) {
    return;
  }

  /* Dump the programdata address */
  add_account_to_dumped_accounts( pool, root, &program_account_state->inner.program.programdata_address );
}

/* add_lut_account_to_dumped_accounts adds an address lookup table
   account AND all pubkeys in the lookup table to the dumped accounts
   set if they do not exist already. */
static void
add_lut_accounts_to_dumped_accounts( fd_funk_t *                   funk,
                                     fd_funk_txn_xid_t const *     xid,
                                     fd_dump_account_key_node_t *  pool,
                                     fd_dump_account_key_node_t ** root,
                                     fd_pubkey_t const *           pubkey ) {
  /* Add the current account to the dumped accounts set. */
  add_account_to_dumped_accounts( pool, root, pubkey );

  /* Read the account and dump all pubkeys within the lookup table. */
  fd_txn_account_t lut_account[1];
  int err = fd_txn_account_init_from_funk_readonly( lut_account, pubkey, funk, xid );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return;
  }

  uchar const  * data     = fd_txn_account_get_data( lut_account );
  ulong          data_len = fd_txn_account_get_data_len( lut_account );

  /* Decode the ALUT account and dump all pubkeys within the lookup
     table. */
  if( data_len<FD_LOOKUP_TABLE_META_SIZE || (data_len&0x1fUL) ) {
    return;
  }
  fd_pubkey_t const * lookup_addrs     = fd_type_pun_const( data+FD_LOOKUP_TABLE_META_SIZE );
  ulong               lookup_addrs_cnt = ( data_len-FD_LOOKUP_TABLE_META_SIZE)>>5UL; // = (dlen - 56) / 32
  for( ulong i=0UL; i<lookup_addrs_cnt; i++ ) {
    fd_pubkey_t const * referenced_pubkey = &lookup_addrs[i];
    add_account_and_programdata_to_dumped_accounts( funk, xid, pool, root, referenced_pubkey );
  }
}

/* create_synthetic_vote_account_from_vote_state creates a synthetic
   vote account from a vote state cache element. It fills in default
   values for unspecified fields and encodes the vote state into
   out_vote_account's data field. */
static void
create_synthetic_vote_account_from_vote_state( fd_vote_state_ele_t const *   vote_state,
                                               fd_spad_t *                   spad,
                                               fd_exec_test_vote_account_t * out_vote_account ) {
  out_vote_account->has_vote_account = true;
  fd_memcpy( out_vote_account->vote_account.address, &vote_state->vote_account, sizeof(fd_pubkey_t) );
  out_vote_account->vote_account.executable = false;
  out_vote_account->vote_account.lamports = 100000UL;
  fd_memcpy( out_vote_account->vote_account.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) );
  out_vote_account->stake = vote_state->stake;

  /* Construct the vote account data. Fill in missing fields with
     arbitrary defaults (since they're not used anyways) */
  fd_vote_state_versioned_t vsv = {
    .discriminant = fd_vote_state_versioned_enum_v3,
    .inner = {
      .v3 = {
        .node_pubkey           = vote_state->node_account,
        .authorized_withdrawer = vote_state->node_account,
        .commission            = vote_state->commission,
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

static void
dump_prior_vote_accounts( fd_vote_states_t const *      vote_states,
                          fd_dump_account_key_node_t *  dumped_accounts_pool,
                          fd_dump_account_key_node_t ** dumped_accounts_root,
                          fd_exec_test_vote_account_t * out_vote_accounts,
                          pb_size_t *                   out_vote_accounts_count,
                          fd_spad_t *                   spad ) {

  fd_vote_states_iter_t iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states );
                                     !fd_vote_states_iter_done( iter );
                                      fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t const * vote_state = fd_vote_states_iter_ele( iter );
    add_account_to_dumped_accounts( dumped_accounts_pool, dumped_accounts_root, &vote_state->vote_account );

    create_synthetic_vote_account_from_vote_state(
        vote_state,
        spad,
        &out_vote_accounts[(*out_vote_accounts_count)++] );
  }
}

static void
create_block_context_protobuf_from_block( fd_block_dump_ctx_t * dump_ctx,
                                          fd_banks_t *          banks,
                                          fd_bank_t *           bank,
                                          fd_funk_t *           funk ) {
  /* We should use the bank fields and funk txn from the parent slot in
     order to capture the block context from before the current block
     was executed, since dumping is happening in the block finalize
     step. */
  fd_bank_t *                    parent_bank    = fd_banks_get_parent( banks, bank );
  ulong                          current_slot   = fd_bank_slot_get( bank );
  ulong                          parent_slot    = fd_bank_slot_get( parent_bank );
  fd_funk_txn_xid_t              parent_xid     = { .ul = { parent_slot, parent_bank->idx } };
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
    dump_sanitized_transaction( funk, &parent_xid, txn_descriptor, txn_ptr->payload, spad, &block_context->txns[i] );

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
      add_account_and_programdata_to_dumped_accounts( funk, &parent_xid, dumped_accounts_pool, &dumped_accounts_root, account_key );
    }

    // 2 + 3 + 4. Dump any ALUT accounts + any accounts referenced in
    // the ALUTs + any programdata accounts (if applicable).
    fd_txn_acct_addr_lut_t const * txn_lookup_tables = fd_txn_get_address_tables_const( txn_descriptor );
    for( ushort l=0; l<txn_descriptor->addr_table_lookup_cnt; l++ ) {
      fd_txn_acct_addr_lut_t const * lookup_table = &txn_lookup_tables[l];
      fd_pubkey_t const *            lut_key      = fd_type_pun_const( txn_ptr->payload+lookup_table->addr_off );
      add_lut_accounts_to_dumped_accounts( funk, &parent_xid, dumped_accounts_pool, &dumped_accounts_root, lut_key );
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
  fd_bank_vote_states_end_locking_query( parent_bank );

  // BlockContext -> EpochContext -> vote_accounts_t_1 (vote accounts at epoch T-1)
  fd_vote_states_t const * vote_states_prev        = fd_bank_vote_states_prev_locking_query( parent_bank );
  block_context->epoch_ctx.vote_accounts_t_1       = fd_spad_alloc(
      spad,
      alignof(fd_exec_test_vote_account_t),
      sizeof(fd_exec_test_vote_account_t)*fd_vote_states_cnt( vote_states_prev ) );
  block_context->epoch_ctx.vote_accounts_t_1_count = 0U;
  dump_prior_vote_accounts(
      vote_states_prev,
      dumped_accounts_pool,
      &dumped_accounts_root,
      block_context->epoch_ctx.vote_accounts_t_1,
      &block_context->epoch_ctx.vote_accounts_t_1_count,
      spad );
  fd_bank_vote_states_prev_end_locking_query( parent_bank );

  // BlockContext -> EpochContext -> vote_accounts_t_2 (vote accounts at epoch T-2)
  fd_vote_states_t const * vote_states_prev_prev   = fd_bank_vote_states_prev_prev_locking_query( parent_bank );
  block_context->epoch_ctx.vote_accounts_t_2       = fd_spad_alloc(
      spad,
      alignof(fd_exec_test_vote_account_t),
      sizeof(fd_exec_test_vote_account_t)*fd_vote_states_cnt( vote_states_prev_prev ) );
  block_context->epoch_ctx.vote_accounts_t_2_count = 0U;
  dump_prior_vote_accounts(
      vote_states_prev_prev,
      dumped_accounts_pool,
      &dumped_accounts_root,
      block_context->epoch_ctx.vote_accounts_t_2,
      &block_context->epoch_ctx.vote_accounts_t_2_count,
      spad );
  fd_bank_vote_states_prev_prev_end_locking_query( parent_bank );

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
    fd_txn_account_t txn_account[1];
    int ret = fd_txn_account_init_from_funk_readonly( txn_account, &node->key, funk, &parent_xid );
    if( FD_UNLIKELY( ret ) ) {
      continue;
    }
    dump_account_state( txn_account, &block_context->acct_states[block_context->acct_states_count++], spad );
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
  block_context->epoch_ctx.slots_per_year             = fd_bank_slots_per_year_get( parent_bank );
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
      - Account data for (almost) all sysvars

    We also don't want to store builtins in account shared data due to
    how Agave's bank handles them in the init phase. */
  // Dump regular accounts first
  txn_context_msg->account_shared_data_count = 0;
  txn_context_msg->account_shared_data = fd_spad_alloc( spad,
                                                        alignof(fd_exec_test_acct_state_t),
                                                        (256UL*2UL + txn_descriptor->addr_table_lookup_cnt + num_sysvar_entries) * sizeof(fd_exec_test_acct_state_t) );
  fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( bank ), bank->idx } };
  for( ulong i = 0; i < txn_out->accounts.accounts_cnt; ++i ) {
    // Make sure account is not a non-migrating builtin
    if( !is_builtin_account( &txn_out->accounts.account_keys[i] ) ) {
      dump_account_if_not_already_dumped(
          runtime->funk,
          &xid,
          &txn_out->accounts.account_keys[i],
          spad,
          txn_context_msg->account_shared_data,
          &txn_context_msg->account_shared_data_count,
          NULL
      );
    }
  }

  // Dump LUT accounts
  fd_txn_acct_addr_lut_t const * address_lookup_tables = fd_txn_get_address_tables_const( txn_descriptor );
  for( ulong i = 0; i < txn_descriptor->addr_table_lookup_cnt; ++i ) {
    fd_txn_account_t txn_account[1];
    fd_txn_acct_addr_lut_t const * addr_lut  = &address_lookup_tables[i];
    fd_pubkey_t * alut_key = (fd_pubkey_t *) (txn_payload + addr_lut->addr_off);

    // Dump the LUT account itself if not already dumped
    int ret = dump_account_if_not_already_dumped(
        runtime->funk,
        &xid,
        alut_key,
        spad,
        txn_context_msg->account_shared_data,
        &txn_context_msg->account_shared_data_count,
        txn_account
    );
    if( FD_UNLIKELY( ret ) ) continue;

    fd_acct_addr_t * lookup_addrs = (fd_acct_addr_t *)&fd_txn_account_get_data( txn_account )[FD_LOOKUP_TABLE_META_SIZE];
    ulong lookup_addrs_cnt        = (fd_txn_account_get_data_len( txn_account ) - FD_LOOKUP_TABLE_META_SIZE) >> 5UL; // = (dlen - 56) / 32

    /* Dump any account state refererenced in ALUTs */
    uchar const * writable_lut_idxs = txn_payload + addr_lut->writable_off;
    for( ulong j=0; j<addr_lut->writable_cnt; j++ ) {
      if( writable_lut_idxs[j] >= lookup_addrs_cnt ) {
        continue;
      }
      fd_pubkey_t const * referenced_addr = fd_type_pun( &lookup_addrs[writable_lut_idxs[j]] );
      if( is_builtin_account( referenced_addr ) ) continue;

      dump_account_if_not_already_dumped(
          runtime->funk,
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
      fd_pubkey_t const * referenced_addr = fd_type_pun( &lookup_addrs[readonly_lut_idxs[j]] );
      if( is_builtin_account( referenced_addr ) ) continue;

      dump_account_if_not_already_dumped(
          runtime->funk,
          &xid,
          referenced_addr,
          spad,
          txn_context_msg->account_shared_data,
          &txn_context_msg->account_shared_data_count,
          NULL
      );
    }
  }

  /* Dump the programdata accounts for any potential v3-owned program accounts */
  uint accounts_dumped_so_far = txn_context_msg->account_shared_data_count;
  for( uint i=0U; i<accounts_dumped_so_far; i++ ) {
    fd_exec_test_acct_state_t const * maybe_program_account = &txn_context_msg->account_shared_data[i];
    dump_executable_account_if_exists( runtime->funk, &xid, maybe_program_account, spad, txn_context_msg->account_shared_data, &txn_context_msg->account_shared_data_count );
  }

  /* Dump sysvars */
  for( ulong i = 0; i < num_sysvar_entries; i++ ) {
    dump_account_if_not_already_dumped(
        runtime->funk,
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
  dump_sanitized_transaction( runtime->funk, &xid, txn_descriptor, txn_payload, spad, sanitized_transaction );

  /* Transaction Context -> blockhash_queue
     NOTE: Agave's implementation of register_hash incorrectly allows the blockhash queue to hold max_age + 1 (max 301)
     entries. We have this incorrect logic implemented in fd_sysvar_recent_hashes:register_blockhash and it's not a
     huge issue, but something to keep in mind. */
  pb_bytes_array_t ** output_blockhash_queue = fd_spad_alloc(
                                                      spad,
                                                      alignof(pb_bytes_array_t *),
                                                      PB_BYTES_ARRAY_T_ALLOCSIZE((FD_BLOCKHASHES_MAX) * sizeof(pb_bytes_array_t *)) );
  txn_context_msg->blockhash_queue = output_blockhash_queue;
  fd_blockhashes_t const * block_hash_queue = fd_bank_block_hash_queue_query( bank );
  dump_blockhash_queue( block_hash_queue, spad, output_blockhash_queue, &txn_context_msg->blockhash_queue_count );

  /* Transaction Context -> epoch_ctx */
  txn_context_msg->has_epoch_ctx = true;
  txn_context_msg->epoch_ctx.has_features = true;
  dump_sorted_features( fd_bank_features_query( bank ), &txn_context_msg->epoch_ctx.features, spad );

  /* Transaction Context -> slot_ctx */
  txn_context_msg->has_slot_ctx  = true;
  txn_context_msg->slot_ctx.slot = fd_bank_slot_get( bank );
}

static void
create_instr_context_protobuf_from_instructions( fd_exec_test_instr_context_t * instr_context,
                                                 fd_runtime_t *                 runtime,
                                                 fd_bank_t *                    bank,
                                                 fd_txn_out_t *                 txn_out,
                                                 fd_instr_info_t const *        instr,
                                                 fd_spad_t *                    spad ) {
  /* Program ID */
  fd_memcpy( instr_context->program_id, txn_out->accounts.account_keys[ instr->program_id ].uc, sizeof(fd_pubkey_t) );

  fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( bank ), bank->idx } };

  /* Accounts */
  instr_context->accounts_count = (pb_size_t) txn_out->accounts.accounts_cnt;
  instr_context->accounts = fd_spad_alloc( spad, alignof(fd_exec_test_acct_state_t), (instr_context->accounts_count + num_sysvar_entries + runtime->executable.cnt) * sizeof(fd_exec_test_acct_state_t));
  for( ulong i = 0; i < txn_out->accounts.accounts_cnt; i++ ) {
    // Copy account information over
    fd_txn_account_t const *    txn_account    = &txn_out->accounts.accounts[i];
    fd_exec_test_acct_state_t * output_account = &instr_context->accounts[i];
    dump_account_state( txn_account, output_account, spad );
  }

  /* Add sysvar cache variables */
  for( ulong i = 0; i < num_sysvar_entries; i++ ) {
    fd_txn_account_t txn_account[1];
    int ret = fd_txn_account_init_from_funk_readonly( txn_account, fd_dump_sysvar_ids[i], runtime->funk, &xid );
    if( ret != FD_ACC_MGR_SUCCESS ) {
      continue;
    }
    // Make sure the account doesn't exist in the output accounts yet
    int account_exists = 0;
    for( ulong j = 0; j < txn_out->accounts.accounts_cnt; j++ ) {
      if ( 0 == memcmp( txn_out->accounts.account_keys[j].key, fd_dump_sysvar_ids[i], sizeof(fd_pubkey_t) ) ) {
        account_exists = true;
        break;
      }
    }

    // Copy it into output
    if (!account_exists) {
      fd_exec_test_acct_state_t * output_account = &instr_context->accounts[instr_context->accounts_count++];
      dump_account_state( txn_account, output_account, spad );
    }
  }

  /* Add executable accounts */
  for( ulong i = 0; i < runtime->executable.cnt; i++ ) {
    fd_txn_account_t txn_account[1];
    int ret = fd_txn_account_init_from_funk_readonly( txn_account, runtime->executable.accounts[i].pubkey, runtime->funk, &xid );
    if( ret != FD_ACC_MGR_SUCCESS ) {
      continue;
    }
    // Make sure the account doesn't exist in the output accounts yet
    bool account_exists = false;
    for( ulong j = 0; j < instr_context->accounts_count; j++ ) {
      if( 0 == memcmp( instr_context->accounts[j].address, runtime->executable.accounts[i].pubkey->uc, sizeof(fd_pubkey_t) ) ) {
        account_exists = true;
        break;
      }
    }
    // Copy it into output
    if( !account_exists ) {
      fd_exec_test_acct_state_t * output_account = &instr_context->accounts[instr_context->accounts_count++];
      dump_account_state( txn_account, output_account, spad );
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

  /* Slot Context */
  instr_context->has_slot_context = true;

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
  fd_spad_t * spad = fd_spad_join( fd_spad_new( runtime->log.dumping_mem, 1UL<<28UL ) );

  FD_SPAD_FRAME_BEGIN( spad ) {
    // Get base58-encoded tx signature
    const fd_ed25519_sig_t * signatures = fd_txn_get_signatures( TXN( txn_in->txn ), txn_in->txn->payload );
    fd_ed25519_sig_t signature; fd_memcpy( signature, signatures[0], sizeof(fd_ed25519_sig_t) );
    char encoded_signature[FD_BASE58_ENCODED_64_SZ];
    ulong out_size;
    fd_base58_encode_64( signature, &out_size, encoded_signature );

    if( runtime->log.capture_ctx->dump_proto_sig_filter ) {
      ulong filter_strlen = (ulong) strlen(runtime->log.capture_ctx->dump_proto_sig_filter);

      // Terminate early if the signature does not match
      if( memcmp( runtime->log.capture_ctx->dump_proto_sig_filter, encoded_signature, filter_strlen < out_size ? filter_strlen : out_size ) ) {
        return;
      }
    }

    fd_exec_test_instr_context_t instr_context = FD_EXEC_TEST_INSTR_CONTEXT_INIT_DEFAULT;
    create_instr_context_protobuf_from_instructions( &instr_context, runtime, bank, txn_out, instr, spad );

    /* Output to file */
    ulong        out_buf_size = 100 * 1024 * 1024;
    uint8_t *    out          = fd_spad_alloc( spad, alignof(uchar) , out_buf_size );
    pb_ostream_t stream       = pb_ostream_from_buffer( out, out_buf_size );
    if (pb_encode(&stream, FD_EXEC_TEST_INSTR_CONTEXT_FIELDS, &instr_context)) {
      char output_filepath[ PATH_MAX ];
      snprintf( output_filepath, PATH_MAX, "%s/instr-%s-%hu.instrctx", runtime->log.capture_ctx->dump_proto_output_dir, encoded_signature, instruction_idx );
      FILE * file = fopen(output_filepath, "wb");
      if( file ) {
        fwrite( out, 1, stream.bytes_written, file );
        fclose( file );
      }
    }
  } FD_SPAD_FRAME_END;
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
    fd_ed25519_sig_t signature; fd_memcpy( signature, signatures[0], sizeof(fd_ed25519_sig_t) );
    char encoded_signature[FD_BASE58_ENCODED_64_SZ];
    ulong out_size;
    fd_base58_encode_64( signature, &out_size, encoded_signature );

    if( runtime->log.capture_ctx->dump_proto_sig_filter ) {
      // Terminate early if the signature does not match
      if( strcmp( runtime->log.capture_ctx->dump_proto_sig_filter, encoded_signature ) ) {
        return;
      }
    }

    fd_exec_test_txn_context_t txn_context_msg = FD_EXEC_TEST_TXN_CONTEXT_INIT_DEFAULT;
    create_txn_context_protobuf_from_txn( &txn_context_msg, runtime, bank, txn_in, txn_out, spad );

    /* Output to file */
    ulong        out_buf_size = 100UL<<20UL; // 100 MB
    uchar *      out          = fd_spad_alloc( spad, alignof(uchar), out_buf_size );
    pb_ostream_t stream       = pb_ostream_from_buffer( out, out_buf_size );
    if( pb_encode( &stream, FD_EXEC_TEST_TXN_CONTEXT_FIELDS, &txn_context_msg ) ) {
      char output_filepath[ PATH_MAX ];
      snprintf( output_filepath, PATH_MAX, "%s/txn-%s.txnctx", runtime->log.capture_ctx->dump_proto_output_dir, encoded_signature );
      FILE * file = fopen(output_filepath, "wb");
      if( file ) {
        fwrite( out, 1, stream.bytes_written, file );
        fclose( file );
      }
    }
  } FD_SPAD_FRAME_END;
}

void
fd_dump_block_to_protobuf_collect_tx( fd_block_dump_ctx_t * dump_ctx,
                                      fd_txn_p_t const *    txn ) {
  if( FD_UNLIKELY( dump_ctx->txns_to_dump_cnt>=FD_BLOCK_DUMP_CTX_MAX_TXN_CNT ) ) {
    FD_LOG_ERR(( "Please increase FD_BLOCK_DUMP_CTX_MAX_TXN_CNT to dump more than %lu transactions.", FD_BLOCK_DUMP_CTX_MAX_TXN_CNT ));
    return;
  }
  fd_memcpy( &dump_ctx->txns_to_dump[dump_ctx->txns_to_dump_cnt++], txn, sizeof(fd_txn_p_t) );
}

void
fd_dump_block_to_protobuf( fd_block_dump_ctx_t *     dump_ctx,
                           fd_banks_t *              banks,
                           fd_bank_t *               bank,
                           fd_funk_t *               funk,
                           fd_capture_ctx_t const *  capture_ctx ) {
FD_SPAD_FRAME_BEGIN( dump_ctx->spad ) {
  if( FD_UNLIKELY( capture_ctx==NULL ) ) {
    FD_LOG_WARNING(( "Capture context may not be NULL when dumping blocks." ));
    return;
  }

  if( FD_UNLIKELY( dump_ctx==NULL ) ) {
    FD_LOG_WARNING(( "Block dumping context may not be NULL when dumping blocks." ));
    return;
  }

  /* Dump the block context */
  create_block_context_protobuf_from_block( dump_ctx, banks, bank, funk );

  /* Output to file */
  ulong        out_buf_size = 1UL<<30UL; /* 1 GB */
  uint8_t *    out          = fd_spad_alloc( dump_ctx->spad, alignof(uint8_t), out_buf_size );
  pb_ostream_t stream       = pb_ostream_from_buffer( out, out_buf_size );
  if( pb_encode( &stream, FD_EXEC_TEST_BLOCK_CONTEXT_FIELDS, &dump_ctx->block_context ) ) {
    char output_filepath[ PATH_MAX ];
    snprintf( output_filepath, PATH_MAX, "%s/block-%lu.blockctx", capture_ctx->dump_proto_output_dir, fd_bank_slot_get( bank ) );
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
          vm->instr_ctx->runtime->log.capture_ctx->dump_proto_output_dir,
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

void
fd_dump_elf_to_protobuf( fd_runtime_t *      runtime,
                         fd_bank_t *         bank,
                         fd_txn_in_t const * txn_in,
                         fd_txn_account_t *  program_acc ) {
fd_spad_t * spad = fd_spad_join( fd_spad_new( runtime->log.dumping_mem, 1UL<<28UL ) );

FD_SPAD_FRAME_BEGIN( spad ) {

  fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( bank ), bank->idx } };

  /* Get the programdata for the account */
  ulong         program_data_len = 0UL;
  uchar const * program_data     =
      fd_prog_load_elf( runtime->accdb, &xid, program_acc, &program_data_len, NULL );
  if( program_data==NULL ) {
    return;
  }

  /* Serialize the ELF to protobuf */
  fd_ed25519_sig_t signature;
  memcpy( signature, (uchar const *)txn_in->txn->payload + TXN( txn_in->txn )->signature_off, sizeof(fd_ed25519_sig_t) );
  char encoded_signature[FD_BASE58_ENCODED_64_SZ];
  fd_base58_encode_64( signature, NULL, encoded_signature );

  FD_BASE58_ENCODE_32_BYTES( program_acc->pubkey->uc, program_acc_b58 );
  char filename[ PATH_MAX ];
  snprintf( filename,
          PATH_MAX,
          "%s/elf-%s-%s-%lu.elfctx",
          runtime->log.capture_ctx->dump_proto_output_dir,
          encoded_signature,
          program_acc_b58,
          fd_bank_slot_get( bank ) );

  /* The generated filename should be unique for every call. Silently return otherwise. */
  if( FD_UNLIKELY( access( filename, F_OK )!=-1 ) ) {
    return;
  }

  fd_exec_test_elf_loader_ctx_t elf_ctx = FD_EXEC_TEST_ELF_LOADER_CTX_INIT_ZERO;

  /* ElfLoaderCtx -> elf */
  elf_ctx.has_elf = true;
  elf_ctx.elf.data = fd_spad_alloc( spad, alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( program_data_len ) );
  elf_ctx.elf.data->size = (pb_size_t)program_data_len;
  fd_memcpy( elf_ctx.elf.data->bytes, program_data, program_data_len );

  /* ElfLoaderCtx -> features */
  elf_ctx.has_features = true;
  dump_sorted_features( fd_bank_features_query( bank ), &elf_ctx.features, spad );

  /* ElfLoaderCtx -> deploy_checks
     We hardcode this to true and rely the fuzzer to toggle this as it pleases */
  elf_ctx.deploy_checks = true;

  /* Output to file */
  ulong out_buf_size = 1UL<<29UL; /* 128 MB */
  uint8_t * out = fd_spad_alloc( spad, alignof(uint8_t), out_buf_size );
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
