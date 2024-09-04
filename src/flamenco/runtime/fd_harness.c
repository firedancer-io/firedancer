#include "fd_harness.h"

#include "fd_account.h"

#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"

#include "fd_system_ids.h"

#include "../nanopb/pb_encode.h"

#include "tests/generated/instr_v2.pb.h"
#include "tests/generated/txn_v2.pb.h"
#include "tests/generated/slot_v2.pb.h"
#include "tests/generated/exec_v2.pb.h"

static void
fd_harness_dump_file( fd_v2_exec_env_t * exec_env, char const * filename ) {
  /* Encode the protobuf and output to file */
  
  /* TODO: Find a better bound for the out buf size */
  ulong out_buf_size = 100LU * 1024LU * 1024LU;
  uint8_t * out = fd_scratch_alloc( alignof(uint8_t), out_buf_size );
  pb_ostream_t stream = pb_ostream_from_buffer( out, out_buf_size );

  if( FD_UNLIKELY( !pb_encode( &stream, FD_V2_EXEC_ENV_FIELDS, exec_env ) ) ) {
    FD_LOG_ERR(( "Failed to encode execution environment protobuf" ));
  }

  FILE * file = fopen( filename, "wb" );
  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_ERR(( "Unable to open file=%s to write", filename ));
  }

  fwrite( out, 1, stream.bytes_written, file );
  fclose( file );
}

static void
fd_harness_dump_acct_state( fd_borrowed_account_t const * borrowed_account,
                            fd_v2_acct_state_t *          output_account ) {

  /* Account Meta */
  fd_memcpy( output_account->address, borrowed_account->pubkey, sizeof(fd_pubkey_t) );

  /* Lamports */
  output_account->lamports = borrowed_account->const_meta->info.lamports;

  /* Data */
  output_account->data       = fd_scratch_alloc( alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( borrowed_account->const_meta->dlen ) );
  output_account->data->size = (pb_size_t) borrowed_account->const_meta->dlen;
  fd_memcpy( output_account->data->bytes, borrowed_account->const_data, borrowed_account->const_meta->dlen );

  /* Executable */
  output_account->executable = borrowed_account->const_meta->info.executable;

  /* Rent Epoch */
  output_account->rent_epoch = borrowed_account->const_meta->info.rent_epoch;

  /* Owner */
  fd_memcpy( output_account->owner, borrowed_account->const_meta->info.owner, sizeof(fd_pubkey_t) );

  /* Seed address will always be false when dumping execution state. */
  output_account->has_seed_addr = false;
}

static void
fd_harness_dump_features( fd_features_t const * features, fd_v2_feature_t * output_features ) {
  uint idx = 0U;
  for( fd_feature_id_t const *id = fd_feature_iter_init(); 
       !fd_feature_iter_done( id ); 
       id = fd_feature_iter_next( id ) ) {
    output_features[ idx ].slot = features->f[ id->index ];
    fd_memcpy( &output_features[idx++].feature_id, &(id->id), sizeof(fd_pubkey_t) );
  }
} 

int
fd_harness_dump_instr( fd_exec_instr_ctx_t * instr_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {

  fd_exec_txn_ctx_t * txn_ctx = instr_ctx->txn_ctx;

  fd_v2_exec_env_t exec_env = {0};

  /* In order to capture all of the accounts required to execute an instruction,
     we need to copy over:
     1. All of the accounts in the transaction with LUTs unrolled
     2. Executable accounts
     3. Sysvar accounts
   */

  /* Make this static */
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

  ulong max_accs_to_save = txn_ctx->accounts_cnt + num_sysvar_entries + txn_ctx->executable_cnt;

  fd_v2_acct_state_t * acct_states = fd_scratch_alloc( alignof(fd_v2_acct_state_t), 
                                                       sizeof(fd_v2_acct_state_t) * max_accs_to_save );
  exec_env.acct_states = acct_states;

  uint num_acct_states = 0U;

  /* Copy the unrolled transaction accounts */
  for( uint i=0U; i<txn_ctx->accounts_cnt; i++ ) {
    fd_borrowed_account_t const * borrowed_account = &txn_ctx->borrowed_accounts[i];
    fd_v2_acct_state_t * output_account = &acct_states[num_acct_states++];
    fd_harness_dump_acct_state( borrowed_account, output_account );
  }

  /* Copy the sysvar entries */
  for( uint i=0U; i<num_sysvar_entries; i++ ) {
    FD_BORROWED_ACCOUNT_DECL( borrowed_account );
    int ret = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, 
                               &fd_relevant_sysvar_ids[i], borrowed_account );
    if( FD_UNLIKELY( ret!=FD_ACC_MGR_SUCCESS ) ) {
      continue;
    }

    /* Make sure the account doesn't exist in the output accounts yet */
    int account_exists = 0;
    for( uint j=0U; j<txn_ctx->accounts_cnt; j++ ) {
      if( !memcmp( acct_states[j].address, fd_relevant_sysvar_ids[i].uc, sizeof(fd_pubkey_t) ) ) {
        account_exists = true;
        break;
      }
    }

    /* Copy it into output */
    if( !account_exists ) {
      fd_v2_acct_state_t * output_account = &acct_states[num_acct_states++];
      fd_harness_dump_acct_state( borrowed_account, output_account );
    }
  }

  /* Copy in the executable accounts */
  for( uint i=0U; i<txn_ctx->executable_cnt; i++ ) {
    FD_BORROWED_ACCOUNT_DECL( borrowed_account );
    int ret = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, txn_ctx->executable_accounts[i].pubkey, borrowed_account );
    if( FD_UNLIKELY( ret!=FD_ACC_MGR_SUCCESS ) ) {
      continue;
    }
    /* Make sure the account doesn't exist in the output accounts yet */
    bool account_exists = false;
    for( uint j=0U; j<txn_ctx->accounts_cnt; j++ ) {
      if( !memcmp( acct_states[j].address, txn_ctx->executable_accounts[i].pubkey->uc, sizeof(fd_pubkey_t) ) ) {
        account_exists = true;
        break;
      }
    }
    /* Copy it into output */
    if( !account_exists ) {
      fd_v2_acct_state_t * output_account = &acct_states[num_acct_states++];
      fd_harness_dump_acct_state( borrowed_account, output_account );
    }
  }
  exec_env.acct_states_count = num_acct_states;

  /* Now that all relevant account states have been populated, copy over the
     feature set into the execution environment protobuf. */

  exec_env.features       = fd_scratch_alloc( alignof(fd_v2_feature_t), sizeof(fd_v2_feature_t) * FD_FEATURE_ID_CNT );
  exec_env.features_count = FD_FEATURE_ID_CNT;
  fd_harness_dump_features( &txn_ctx->epoch_ctx->features, exec_env.features );

  /* The leader schedule, status cache, and block hash queue don't need to be
     populated when dumping an instruction. */

  exec_env.slots_count = 1UL;
  exec_env.slots       = fd_scratch_alloc( alignof(fd_v2_slot_env_t), sizeof(fd_v2_slot_env_t) );

  fd_v2_slot_env_t * slot_env = &exec_env.slots[0];
  slot_env->txns_count        = 1UL;
  slot_env->slot_number       = txn_ctx->slot_ctx->slot_bank.slot;
  slot_env->txns              = fd_scratch_alloc( alignof(fd_v2_txn_env_t), sizeof(fd_v2_txn_env_t) );

  /* Populate the transaction environment with one instruction. At this point 
     the address lookup table should be unrolled. The order of accounts and the 
     transaction header should be populated. */

  fd_v2_txn_env_t * txn_env                      = &slot_env->txns[0];
  txn_env->has_header                            = true;
  txn_env->header.num_required_signatures        = txn_ctx->txn_descriptor->signature_cnt;
  txn_env->header.num_readonly_signed_accounts   = txn_ctx->txn_descriptor->readonly_signed_cnt;
  txn_env->header.num_readonly_unsigned_accounts = txn_ctx->txn_descriptor->readonly_unsigned_cnt;

  txn_env->is_legacy = txn_ctx->txn_descriptor->transaction_version == FD_TXN_VLEGACY;

  txn_env->account_keys = fd_scratch_alloc( alignof(fd_pubkey_t), sizeof(fd_pubkey_t) * txn_ctx->accounts_cnt );
  for( uint i=0U; i<txn_ctx->accounts_cnt; i++ ) {
    fd_memcpy( &txn_env->account_keys[i], txn_ctx->borrowed_accounts[i].pubkey, sizeof(fd_pubkey_t) );
  }

  txn_env->instructions_count = 1UL;

  fd_v2_instr_env_t * instr_env = fd_scratch_alloc( alignof(fd_v2_instr_env_t), sizeof(fd_v2_instr_env_t) );
  instr_env->program_id_idx     = instr_ctx->instr->program_id;
  instr_env->accounts_count     = instr_ctx->instr->acct_cnt;
  instr_env->accounts           = fd_scratch_alloc( alignof(fd_v2_instr_acct_t), sizeof(fd_v2_instr_acct_t) * instr_ctx->instr->acct_cnt );
  for( uint i=0U; i<instr_env->accounts_count; i++ ) {
    instr_env->accounts[i] = instr_ctx->instr->acct_txn_idxs[i];
  }

  instr_env->data       = fd_scratch_alloc( alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( instr_ctx->instr->data_sz ) );
  instr_env->data->size = instr_ctx->instr->data_sz;

  /* Now that the protobuf struct has been populated, dump the struct into
    a file. */
  fd_harness_dump_file( &exec_env, "instrexec_env.pb" );

  return 0;

  } FD_SCRATCH_SCOPE_END;
}

/* TODO: This is unimplemented. */
int
fd_harness_dump_txn( fd_exec_txn_ctx_t * txn_ctx ) {
  (void)txn_ctx;
  return 0;
}

/* TODO: This is unimplemented. */
int
fd_harness_dump_slot( fd_exec_slot_ctx_t * slot_ctx ) {
  (void)slot_ctx;
  return 0;
}

/* TODO: This is unimplemented. */
int
fd_harness_dump_runtime( fd_exec_epoch_ctx_t * epoch_ctx ) {
  (void)epoch_ctx;
  return 0;
}

/* Execute runtime environment ************************************************/

int
fd_harness_exec_instr( char const * filename ) {
  /* First read in file and decode the protobuf */
  (void)filename;
  return 0;
}

int
fd_harness_exec_txn( char const * filename ) {
  (void)filename;
  return 0;
}

int
fd_harness_exec_slot( char const * filename ) {
  (void)filename;
  return 0;
}

int
fd_harness_exec_runtime( char const * filename ) {
  (void)filename;
  return 0;
}
