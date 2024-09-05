#include "fd_harness.h"

#include "fd_account.h"

#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"

#include "fd_system_ids.h"

#include "../nanopb/pb_encode.h"
#include "../nanopb/pb_decode.h"
#include "sysvar/fd_sysvar_recent_hashes.h"


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
  txn_env->cu_avail                              = txn_ctx->compute_unit_limit;

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

static void
fd_harness_exec_restore_sysvars( fd_harness_ctx_t * ctx ) {
  fd_sysvar_cache_restore( ctx->slot_ctx->sysvar_cache, ctx->slot_ctx->acc_mgr, ctx->slot_ctx->funk_txn );
} 

static void
fd_harness_exec_restore_features( fd_harness_ctx_t * ctx, fd_v2_exec_env_t * exec_env ) {
  fd_exec_epoch_ctx_t * epoch_ctx = ctx->epoch_ctx;
  fd_features_disable_all( &epoch_ctx->features );
  for( uint i=0U; i<exec_env->features_count; i++ ) {
    const char * feature = (const char *)exec_env->features[i].feature_id;
    fd_features_enable_one_offs( &epoch_ctx->features, &feature, 1U, exec_env->features[i].slot );
  }
}

static void
fd_harness_exec_setup( fd_harness_ctx_t * ctx ) {

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) {
    cpu_idx = 0UL;
  }
  ctx->wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 3, fd_shmem_cpu_idx( fd_shmem_numa_idx( cpu_idx ) ), "wksp", 0UL );

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( ctx->wksp, fd_alloc_align(), fd_alloc_footprint(), 2UL ), 2UL ), 0UL );
  
  /* TODO: use scratch methods here and define things out */
  void * smem = fd_wksp_alloc_laddr( ctx->wksp, fd_scratch_smem_align(), 1<<30, 22UL );
  void * fmem = fd_wksp_alloc_laddr( ctx->wksp, fd_scratch_fmem_align(), 64UL,  22UL );
   
  fd_scratch_attach( smem, fmem, 1<<30, 64UL );

  fd_scratch_push();

  void * funk_mem = fd_scratch_alloc( fd_funk_align(), fd_funk_footprint() );
  ctx->funk       = fd_funk_join( fd_funk_new( funk_mem, 999UL, (ulong)fd_tickcount(), 4UL+fd_tile_cnt(), 1024UL ) );

  fd_funk_txn_xid_t xid[1] = {0};
  xid[0] = fd_funk_generate_xid();
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( ctx->funk, NULL, xid, 1 );


  uchar * epoch_ctx_mem = fd_scratch_alloc( fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( 128UL ) );
  uchar * slot_ctx_mem  = fd_scratch_alloc( FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT  );
  uchar * txn_ctx_mem   = fd_scratch_alloc( FD_EXEC_TXN_CTX_ALIGN,   FD_EXEC_TXN_CTX_FOOTPRINT   );

  ctx->epoch_ctx        = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, 128UL ) );
  ctx->slot_ctx         = fd_exec_slot_ctx_join ( fd_exec_slot_ctx_new ( slot_ctx_mem, fd_alloc_virtual( alloc ) ) );
  ctx->txn_ctx          = fd_exec_txn_ctx_join  ( fd_exec_txn_ctx_new  ( txn_ctx_mem ) );

  ctx->slot_ctx->acc_mgr = fd_acc_mgr_new( fd_scratch_alloc( FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT ), ctx->funk );

  /* Hook everything up */

  ctx->txn_ctx->valloc     = ctx->slot_ctx->valloc;
  ctx->slot_ctx->epoch_ctx = ctx->epoch_ctx;
  ctx->slot_ctx->funk_txn  = funk_txn;

  /* TODO:FIXME: Finish assigning values to everything here */
  fd_slot_bank_new( &ctx->slot_ctx->slot_bank );
  fd_block_block_hash_entry_t * recent_block_hashes = deq_fd_block_block_hash_entry_t_alloc( ctx->slot_ctx->valloc, FD_SYSVAR_RECENT_HASHES_CAP );
  ctx->slot_ctx->slot_bank.recent_block_hashes.hashes = recent_block_hashes;
  fd_block_block_hash_entry_t * recent_block_hash = deq_fd_block_block_hash_entry_t_push_tail_nocopy( recent_block_hashes );
  fd_memset( recent_block_hash, 0, sizeof(fd_block_block_hash_entry_t) );
}

static void
fd_harness_exec_load_acc( fd_harness_ctx_t *      ctx,
                          fd_borrowed_account_t * borrowed_account, 
                          fd_v2_acct_state_t *    acc ) {
  
  fd_acc_mgr_t *  acc_mgr  = ctx->slot_ctx->acc_mgr;
  fd_funk_txn_t * funk_txn = ctx->slot_ctx->funk_txn;
  fd_pubkey_t *   pubkey   = (fd_pubkey_t*)acc->address;

  if( FD_UNLIKELY( fd_acc_mgr_view_raw( acc_mgr, funk_txn, pubkey, NULL, NULL ) ) ) {
    /* Don't need to load in the accounts if it already exists. TODO: consider
       even throwing an error here because it means the exec env is probably
       busted. */
    return;
  }

  fd_borrowed_account_init( borrowed_account );

  int err = fd_acc_mgr_modify( /* acc_mgr     */ acc_mgr,
                               /* txn         */ funk_txn,
                               /* pubkey      */ pubkey,
                               /* do_create   */ 1,
                               /* min_data_sz */ acc->data->size,
                                                 borrowed_account );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to load account into funk" ));
  }

  if( acc->data->size ) {
    fd_memcpy( borrowed_account->data, borrowed_account, acc->data->size );
  }
  borrowed_account->starting_lamports     = acc->lamports;
  borrowed_account->starting_dlen         = acc->data->size;
  borrowed_account->meta->info.lamports   = acc->lamports;
  borrowed_account->meta->info.executable = acc->executable;
  borrowed_account->meta->info.rent_epoch = acc->rent_epoch;
  borrowed_account->meta->dlen            = acc->data->size;
  fd_memcpy( borrowed_account->meta->info.owner, acc->owner, sizeof(fd_pubkey_t) );

  /* Make account read-only */
  borrowed_account->meta = NULL;
  borrowed_account->data = NULL;
  borrowed_account->rec  = NULL;
}

int
fd_harness_exec_instr( uchar const * filename, ulong file_sz ) {

  /* First read in file and decode the protobuf */
  fd_v2_exec_env_t exec_env = {0};

  pb_istream_t istream = pb_istream_from_buffer( filename, file_sz );
  int err = pb_decode_ex( &istream, &fd_v2_exec_env_t_msg, &exec_env, 0x01U );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to decode exec env pb at file=%s with size=%lu", filename, file_sz ));
  }

  fd_v2_txn_env_t *   txn_env   = &exec_env.slots[0].txns[0];
  fd_v2_instr_env_t * instr_env = &txn_env->instructions[0];

  /* Setup the basic execution environment: allocate contexts and important
     data structures (funk, wksp, acc_mgr, etc. ) */
  fd_harness_ctx_t ctx = {0};
  fd_harness_exec_setup( &ctx );

  /* Load in all account states into the borrowed accounts/acc_mgr.
     Need to load in the transaction accounts, the corresponding programdata
     accounts, and the sysvars in their own ways.
     TODO: SPLIT INTO TWO BUCKETS. */
  for( uint i=0U; i<exec_env.acct_states_count; i++ ) {
    fd_v2_acct_state_t * acc = &exec_env.acct_states[i];
    fd_harness_exec_load_acc( &ctx, &ctx.txn_ctx->borrowed_accounts[i], acc );
  } 

  ctx.txn_ctx->compute_unit_limit = txn_env->cu_avail;
  ctx.txn_ctx->compute_meter      = txn_env->cu_avail;
  fd_exec_txn_ctx_setup( ctx.txn_ctx, NULL, NULL );

  /* Load in all features */
  fd_harness_exec_restore_features( &ctx, &exec_env );

  fd_instr_info_t instr = {0};
  instr.data            = instr_env->data->bytes;
  instr.data_sz         = (ushort)instr_env->data->size;

  fd_pubkey_t * program_id = &ctx.txn_ctx->accounts[instr_env->program_id_idx];
  fd_memcpy( &instr.program_id, program_id, sizeof(fd_pubkey_t) );

  /* TODO: all of the cache stuff should go here */
  fd_harness_exec_restore_sysvars( &ctx );

  /* TODO: recent blockhash stuff */

  /* TODO: fill out account flags and whatnot */


  return 0;
}

int
fd_harness_exec_txn( uchar const * filename, ulong file_sz ) {
  (void)filename;
  (void)file_sz;
  return 0;
}

int
fd_harness_exec_slot( uchar const * filename, ulong file_sz ) {
  (void)filename;
  (void)file_sz;
  return 0;
}

int
fd_harness_exec_runtime( uchar const * filename, ulong file_sz ) {
  (void)filename;
  (void)file_sz;
  return 0;
}
