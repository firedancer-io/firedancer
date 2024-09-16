#include "fd_harness.h"
#include "../runtime/sysvar/fd_sysvar_clock.h"
#include "../runtime/tests/generated/invoke.pb.h"

/* TODO: some of these helpers can be factored out to some common utils file */

/* Instruction dumping helpers ************************************************/

void
fd_harness_dump_file( fd_v2_exec_env_t  const * exec_env,
                      fd_exec_txn_ctx_t const * txn_ctx,
                      ushort                    instr_idx ) {

  /* Create a filename. TODO: This should be moved to a utils file. */

  char filename[256] = {0};
  char txn_sig[128];
  uchar * sig        = (uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->signature_off;
  FD_LOG_WARNING(("sig %64J", sig));
  fd_base58_encode_64( sig, NULL, txn_sig );

  /* TODO: Replace this with the capture_ctx directory*/
  char proto_output_dir[64] = "/data/ibhatt/";
  
  char * position = fd_cstr_init( filename );
  position        = fd_cstr_append_cstr( position, proto_output_dir );
  position        = fd_cstr_append_cstr( position, "/instr-" );
  position        = fd_cstr_append_cstr_safe( position, txn_sig, 88UL ); /* Length of decoded tx signature */
  position        = fd_cstr_append_cstr( position, "-" );
  position        = fd_cstr_append_ushort_as_text( position, '0', 0, instr_idx, 2UL );
  position        = fd_cstr_append_cstr(position, ".pb.bin" );
  fd_cstr_fini( position );

  /* Encode the protobuf and output to file */
  
  /* TODO: Find a better bound for the out buf size */
  ulong out_buf_size = 100UL * 1024UL * 1024UL;
  uint8_t * out = fd_scratch_alloc( alignof(uint8_t), out_buf_size );
  pb_ostream_t stream = pb_ostream_from_buffer( out, out_buf_size );

  if( FD_UNLIKELY( !pb_encode( &stream, FD_V2_EXEC_ENV_FIELDS, exec_env ) ) ) {
    FD_LOG_ERR(( "Failed to encode execution environment protobuf" ));
  }

  FILE * file = fopen( filename, "wb" );
  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_ERR(( "Unable to open file=%s to write", filename ));
  }

  FD_LOG_NOTICE(("Writing to file=%s", filename));

  fwrite( out, 1, stream.bytes_written, file );
  fclose( file );
}

void
fd_harness_dump_acct_state( fd_borrowed_account_t const * borrowed_account,
                            fd_v2_acct_state_t *          output_account ) {

  FD_LOG_WARNING(("borrowed_account %32J", borrowed_account->pubkey));
  /* Account Meta */
  fd_memcpy( output_account->address, borrowed_account->pubkey, sizeof(fd_pubkey_t) );

  /* Lamports */
  output_account->lamports = borrowed_account->const_meta->info.lamports;

  /* Data */
  output_account->data       = fd_scratch_alloc( alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( borrowed_account->const_meta->dlen ) );
  output_account->data->size = (uint)borrowed_account->const_meta->dlen;
  fd_memcpy( output_account->data->bytes, borrowed_account->const_data, borrowed_account->const_meta->dlen );
  //FD_LOG_HEXDUMP_WARNING(("ACCOUNT DATA", output_account->data->bytes, output_account->data->size));

  /* Executable */
  output_account->executable = borrowed_account->const_meta->info.executable;

  /* Rent Epoch */
  output_account->rent_epoch = borrowed_account->const_meta->info.rent_epoch;

  /* Owner */
  fd_memcpy( output_account->owner, borrowed_account->const_meta->info.owner, sizeof(fd_pubkey_t) );

  /* Seed address will always be false when dumping execution state. */
  output_account->has_seed_addr = false;
}

void
fd_harness_dump_features( fd_features_t const * features, fd_v2_feature_t * output_features ) {
  uint idx = 0U;
  for( fd_feature_id_t const *id = fd_feature_iter_init(); 
       !fd_feature_iter_done( id ); 
       id = fd_feature_iter_next( id ) ) {
    
    output_features[ idx ].slot = features->f[ id->index ];
    fd_memcpy( &output_features[idx++].feature_id, &(id->id), sizeof(fd_pubkey_t) );
  }
} 
 

/* Execute instruction helpers ************************************************/

void
fd_harness_exec_restore_sysvars( fd_harness_ctx_t * ctx ) {

  fd_exec_slot_ctx_t * slot_ctx = ctx->slot_ctx;

  fd_sysvar_cache_restore( slot_ctx->sysvar_cache, slot_ctx->acc_mgr, slot_ctx->funk_txn );

  /* TODO: FIX THIS PLEASE THIS IS A MEGA MEGA HACK */
  fd_block_block_hash_entry_t * recent_block_hashes = deq_fd_block_block_hash_entry_t_alloc( slot_ctx->valloc, FD_SYSVAR_RECENT_HASHES_CAP );
  slot_ctx->slot_bank.recent_block_hashes.hashes = recent_block_hashes;
  fd_block_block_hash_entry_t * recent_block_hash = deq_fd_block_block_hash_entry_t_push_tail_nocopy( recent_block_hashes );
  fd_memset( recent_block_hash, 0, sizeof(fd_block_block_hash_entry_t) );
  fd_recent_block_hashes_t const * rbh = fd_sysvar_cache_recent_block_hashes( slot_ctx->sysvar_cache );
  if( rbh && !deq_fd_block_block_hash_entry_t_empty( rbh->hashes ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_tail_const( rbh->hashes );
    if( last ) {
      *recent_block_hash = *last;
      slot_ctx->slot_bank.lamports_per_signature = last->fee_calculator.lamports_per_signature;
      slot_ctx->prev_lamports_per_signature = last->fee_calculator.lamports_per_signature;
    }
  }

} 

void
fd_harness_exec_restore_features( fd_harness_ctx_t * ctx, fd_v2_exec_env_t * exec_env ) {
  fd_exec_epoch_ctx_t * epoch_ctx = ctx->epoch_ctx;
  fd_features_disable_all( &epoch_ctx->features );
  for( uint i=0U; i<exec_env->features_count; i++ ) {
    fd_pubkey_t * feature = (fd_pubkey_t*)exec_env->features[i].feature_id;
    fd_features_enable_decoded_one_off( &epoch_ctx->features, feature, exec_env->features[i].slot );
  }
}

void
fd_harness_exec_setup( fd_harness_ctx_t * ctx, fd_v2_exec_env_t * exec_env ) {

  /* Allocate new workspace. */

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) {
    cpu_idx = 0UL;
  }
  ctx->wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 3, fd_shmem_cpu_idx( fd_shmem_numa_idx( cpu_idx ) ), "wksp", 0UL );

  /* Declare an alloc from the wksp. */

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( ctx->wksp, fd_alloc_align(), fd_alloc_footprint(), 2UL ), 2UL ), 0UL );
  
  /* Allocate, attach, and push a scratch frame. */

  /* TODO: use scratch methods here and define things out. */

  void * smem = fd_wksp_alloc_laddr( ctx->wksp, fd_scratch_smem_align(), 1<<30, 22UL );
  void * fmem = fd_wksp_alloc_laddr( ctx->wksp, fd_scratch_fmem_align(), 64UL,  22UL );
  fd_scratch_attach( smem, fmem, 1<<30, 64UL );
  fd_scratch_push();

  /* Scratch allocate a funk that will exist for the scope of the execution. */

  void * funk_mem = fd_scratch_alloc( fd_funk_align(), fd_funk_footprint() );
  ctx->funk       = fd_funk_join( fd_funk_new( funk_mem, 999UL, (ulong)fd_tickcount(), 4UL+fd_tile_cnt(), 1024UL ) );

  /* Allocate txn, slot, and epoch contexts. */

  uchar * epoch_ctx_mem = fd_scratch_alloc( fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( 128UL ) );
  uchar * slot_ctx_mem  = fd_scratch_alloc( FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT  );
  uchar * txn_ctx_mem   = fd_scratch_alloc( FD_EXEC_TXN_CTX_ALIGN,   FD_EXEC_TXN_CTX_FOOTPRINT   );

  ctx->epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, 128UL ) );
  ctx->slot_ctx  = fd_exec_slot_ctx_join ( fd_exec_slot_ctx_new ( slot_ctx_mem, fd_alloc_virtual( alloc ) ) );
  ctx->txn_ctx   = fd_exec_txn_ctx_join  ( fd_exec_txn_ctx_new  ( txn_ctx_mem ) );

  /* Allocate acc mgr and generate a funk transaction. Populate other slot ctx
     fields needed for execution. */

  fd_funk_txn_xid_t xid = fd_funk_generate_xid();

  fd_funk_start_write( ctx->funk );

  ctx->slot_ctx->acc_mgr   = fd_acc_mgr_new( fd_scratch_alloc( FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT ), ctx->funk );
  ctx->slot_ctx->funk_txn  = fd_funk_txn_prepare( ctx->funk, NULL, &xid, 1 );
  ctx->slot_ctx->epoch_ctx = ctx->epoch_ctx;

  /* Setup the slot bank and set the slot number. */

  fd_slot_bank_new( &ctx->slot_ctx->slot_bank ); 
  ctx->slot_ctx->slot_bank.slot = exec_env->slots[0].slot_number;

  /* Populate relevant txn context fields. */

  fd_exec_txn_ctx_setup( ctx->txn_ctx, NULL, NULL );
  ctx->txn_ctx->epoch_ctx = ctx->epoch_ctx;
  ctx->txn_ctx->slot_ctx  = ctx->slot_ctx;
  ctx->txn_ctx->funk_txn  = ctx->slot_ctx->funk_txn;
  ctx->txn_ctx->acc_mgr   = ctx->slot_ctx->acc_mgr;
  ctx->txn_ctx->valloc    = ctx->slot_ctx->valloc;

}

void
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
    fd_memcpy( borrowed_account->data, acc->data->bytes, acc->data->size );
    borrowed_account->const_data = borrowed_account->data;
  }

  borrowed_account->starting_lamports     = acc->lamports;
  borrowed_account->starting_dlen         = acc->data->size;
  borrowed_account->meta->info.lamports   = acc->lamports;
  borrowed_account->meta->info.executable = acc->executable;
  borrowed_account->meta->info.rent_epoch = acc->rent_epoch;
  borrowed_account->meta->dlen            = acc->data->size;
  fd_memcpy( borrowed_account->meta->info.owner, acc->owner, sizeof(fd_pubkey_t) );
}

void
fd_harness_exec_write_effects( fd_exec_txn_ctx_t * txn_ctx,
                               int                 res,
                               char const *        filename ) {

  fd_v2_exec_effects_t  exec_effects  = FD_V2_EXEC_EFFECTS_INIT_ZERO;
  fd_v2_slot_effects_t  slot_effects  = FD_V2_SLOT_EFFECTS_INIT_ZERO;
  fd_v2_txn_effects_t   txn_effects   = FD_V2_TXN_EFFECTS_INIT_ZERO;
  fd_v2_instr_effects_t instr_effects = FD_V2_INSTR_EFFECTS_INIT_ZERO;

  exec_effects.harness_type       = FD_V2_HARNESS_TYPE_INSTR;
  exec_effects.slot_effects_count = 1UL;
  exec_effects.slot_effects       = &slot_effects;
  exec_effects.acct_states_count  = (uint)txn_ctx->accounts_cnt;
  exec_effects.acct_states        = fd_scratch_alloc( alignof(fd_v2_acct_state_t), sizeof(fd_v2_acct_state_t) * txn_ctx->accounts_cnt );

  for( uint i=0U; i<txn_ctx->accounts_cnt; i++ ) {
    fd_v2_acct_state_t * output_account = &exec_effects.acct_states[i];
    fd_harness_dump_acct_state( &txn_ctx->borrowed_accounts[i], output_account );
  }

  slot_effects.txn_effects_count = 1UL;
  slot_effects.txn_effects       = &txn_effects;

  txn_effects.instr_effects_count = 1UL;
  txn_effects.instr_effects       = &instr_effects;
  txn_effects.cus_remain          = txn_ctx->compute_meter;
  txn_effects.return_data         = fd_scratch_alloc( 1UL, PB_BYTES_ARRAY_T_ALLOCSIZE( txn_ctx->return_data.len ) );
  txn_effects.return_data->size   = (uint)txn_ctx->return_data.len;
  fd_memcpy( txn_effects.return_data->bytes, txn_ctx->return_data.data, txn_ctx->return_data.len );

  instr_effects.result     = res;
  instr_effects.custom_err = res == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ? txn_ctx->custom_err : 0U;

  /* Encode the protobuf and output to file */
  
  /* TODO: Find a better bound for the out buf size */
  ulong out_buf_size  = 100UL * 1024UL * 1024UL;
  uint8_t * out       = fd_scratch_alloc( alignof(uint8_t), out_buf_size );
  pb_ostream_t stream = pb_ostream_from_buffer( out, out_buf_size );

  if( FD_UNLIKELY( !pb_encode( &stream, FD_V2_EXEC_EFFECTS_FIELDS, &exec_effects ) ) ) {
    FD_LOG_ERR(( "Failed to encode execution environment protobuf" ));
  }

  FILE * file = fopen( filename, "wb" );
  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_ERR(( "Unable to open file=%s to write", filename ));
  }

  FD_LOG_NOTICE(("Writing to file=%s", filename));

  fwrite( out, 1, stream.bytes_written, file );
  fclose( file );


}


/* Instruction API start*/

int
fd_harness_dump_instr( fd_exec_txn_ctx_t const * txn_ctx, 
                       fd_instr_info_t   const * instr, 
                       ushort                    instr_idx ) {
  FD_SCRATCH_SCOPE_BEGIN {

  (void)instr_idx;
  (void)instr;

  fd_v2_exec_env_t exec_env = FD_V2_EXEC_ENV_INIT_DEFAULT;
  exec_env.harness_type     = FD_V2_HARNESS_TYPE_INSTR;

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
  FD_LOG_NOTICE(("NUM SYSVAR ENTREIS %lu", num_sysvar_entries));

  ulong max_accs_to_save = txn_ctx->accounts_cnt + num_sysvar_entries;

  fd_v2_acct_state_t * acct_states = fd_scratch_alloc( alignof(fd_v2_acct_state_t), 
                                                       sizeof(fd_v2_acct_state_t) * max_accs_to_save );
  exec_env.acct_states = acct_states;
  exec_env.acct_states_count = (uint)max_accs_to_save;

  uint num_acct_states = 0U;

  /* Copy the unrolled transaction acaccounts */
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
    //FD_LOG_NOTICE(("ACC MGR VIEW ret %d pubkey %32J", ret, &fd_relevant_sysvar_ids[i]));
    if( FD_UNLIKELY( ret!=FD_ACC_MGR_SUCCESS ) ) {
      continue;
    }

    /* Make sure the account doesn't exist in the output accounts yet */
    int account_exists = 0;
    for( uint j=0U; j<txn_ctx->accounts_cnt; j++ ) {
      if( !memcmp( acct_states[j].address, fd_relevant_sysvar_ids[i].uc, sizeof(fd_pubkey_t) ) ) {
        account_exists = true;
        FD_LOG_NOTICE(("ACCOUNT EXISTS"));
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

  fd_v2_slot_env_t slot_env = FD_V2_SLOT_ENV_INIT_DEFAULT;
  exec_env.slots_count      = 1UL;
  exec_env.slots            = &slot_env;


  fd_v2_txn_env_t txn_env = FD_V2_TXN_ENV_INIT_DEFAULT;
  slot_env.slot_number    = txn_ctx->slot_ctx->slot_bank.slot;
  slot_env.txns_count     = 1UL;
  slot_env.txns           = &txn_env;

  /* Populate the transaction environment with one instruction. At this point 
     the address lookup table should be unrolled. The order of accounts and the 
     transaction header should be populated. */

  txn_env.has_header                            = true;
  txn_env.header.num_required_signatures        = txn_ctx->txn_descriptor->signature_cnt;
  txn_env.header.num_readonly_signed_accounts   = txn_ctx->txn_descriptor->readonly_signed_cnt;
  txn_env.header.num_readonly_unsigned_accounts = txn_ctx->txn_descriptor->readonly_unsigned_cnt;
  txn_env.cu_avail                              = txn_ctx->compute_unit_limit;
  txn_env.is_legacy                             = txn_ctx->txn_descriptor->transaction_version == FD_TXN_VLEGACY;
  txn_env.account_keys_count                    = (uint)txn_ctx->accounts_cnt;
  txn_env.account_keys                          = fd_scratch_alloc( alignof(pb_bytes_array_t*), PB_BYTES_ARRAY_T_ALLOCSIZE( txn_ctx->accounts_cnt * sizeof(pb_bytes_array_t*) ) );
  for( uint i=0U; i < txn_ctx->accounts_cnt; i++ ) {
    txn_env.account_keys[i]       = fd_scratch_alloc( alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( sizeof(fd_pubkey_t) ) );
    txn_env.account_keys[i]->size = sizeof(fd_pubkey_t);
    memcpy( txn_env.account_keys[i]->bytes, &txn_ctx->accounts[i], sizeof(fd_pubkey_t) );
  }
  
  fd_v2_instr_env_t instr_env = FD_V2_INSTR_ENV_INIT_DEFAULT;
  txn_env.instrs_count        = 1UL;
  txn_env.instrs              = &instr_env;

  instr_env.program_id_idx = instr->program_id;
  instr_env.accounts       = fd_scratch_alloc( alignof(pb_byte_t), PB_BYTES_ARRAY_T_ALLOCSIZE( sizeof(pb_byte_t) * instr->acct_cnt ) );
  instr_env.accounts->size = instr->acct_cnt;
  for( uint i=0U; i<instr->acct_cnt; i++ ) {
    instr_env.accounts->bytes[i] = instr->acct_txn_idxs[i];
  }

  instr_env.data       = fd_scratch_alloc( alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( instr->data_sz ) );
  instr_env.data->size = instr->data_sz;
  fd_memcpy( instr_env.data->bytes, instr->data, instr->data_sz );

  /* Now that the protobuf struct has been populated, dump the struct into
    a file with the format {dump dir}/instr_{tx signature}_{instr idx}.pb. */

  fd_harness_dump_file( &exec_env, txn_ctx, instr_idx );

  return 0;

  } FD_SCRATCH_SCOPE_END;
}

int
fd_harness_exec_instr( uchar const * file_buf, ulong file_sz ) {

  /* First read in file and decode the protobuf */

  fd_v2_exec_env_t exec_env_struct = FD_V2_EXEC_ENV_INIT_ZERO;

  pb_istream_t istream = pb_istream_from_buffer( file_buf, file_sz );
  if( FD_UNLIKELY( !pb_decode( &istream, FD_V2_EXEC_ENV_FIELDS, &exec_env_struct ) ) ) {
    FD_LOG_ERR(( "Failed to decode exec env pb" ));
  }

  fd_v2_exec_env_t *  exec_env  = &exec_env_struct;
  fd_v2_slot_env_t *  slot_env  = &exec_env->slots[0];
  fd_v2_txn_env_t *   txn_env   = &slot_env->txns[0];
  fd_v2_instr_env_t * instr_env = &txn_env->instrs[0];

  /* Setup the basic execution environment: allocate contexts and important
     data structures (funk, wksp, acc_mgr, etc. ) */
  fd_harness_ctx_t ctx = {0};
  fd_harness_exec_setup( &ctx, exec_env );

  /* Load in all account states into the borrowed accounts/acc_mgr.
     Need to load in the transaction accounts, the corresponding programdata
     accounts, and the sysvars in their own ways. */

  for( uint i=0U; i<exec_env->acct_states_count; i++ ) {
    fd_v2_acct_state_t * acc = &exec_env->acct_states[i];
    fd_harness_exec_load_acc( &ctx, &ctx.txn_ctx->borrowed_accounts[i], acc );
  } 

  /* Restore the sysvars from the account states that are loaded in from the
     exec env's acct states. */

  fd_harness_exec_restore_sysvars( &ctx );

  /* Setup the transaction context with the relevant fields. */

  fd_exec_txn_ctx_setup( ctx.txn_ctx, NULL, NULL );
  ctx.txn_ctx->compute_unit_limit = txn_env->cu_avail;
  ctx.txn_ctx->compute_meter      = txn_env->cu_avail;
  ctx.txn_ctx->accounts_cnt       = txn_env->account_keys_count;

  for( uint i=0U; i<txn_env->account_keys_count; i++ ) {
    fd_pubkey_t * pubkey = (fd_pubkey_t*)txn_env->account_keys[i]->bytes;
    fd_memcpy( &ctx.txn_ctx->accounts[i], pubkey, sizeof(fd_pubkey_t) );
  }

  /* Load in all features from the execution environment. */

  fd_harness_exec_restore_features( &ctx, exec_env );

  /* Set the required fields for the transaction descriptor and instruction.
     This allows for the instruction parsing and setup to be handled by the
     same function that is used in the runtime. 
     
     An optimization/hack that is used here to prevent a memcpy is the fact
     that the fd_instr_info's data and the instr_acc_idxs fields are populated
     using data offsets into txn_ctx->_txn_raw. The _txn_raw is just set to
     the account indicies. The instr data is reset after the function call. */

  fd_txn_t * txn_descriptor             = fd_scratch_alloc( alignof(fd_txn_t), sizeof(fd_txn_t) );
  txn_descriptor->signature_cnt         = (uchar)txn_env->header.num_required_signatures;
  txn_descriptor->readonly_signed_cnt   = (uchar)txn_env->header.num_readonly_signed_accounts;
  txn_descriptor->readonly_unsigned_cnt = (uchar)txn_env->header.num_readonly_unsigned_accounts;
  txn_descriptor->transaction_version   = txn_env->is_legacy ? FD_TXN_VLEGACY : FD_TXN_V0;
  txn_descriptor->acct_addr_cnt         = (ushort)txn_env->account_keys_count;
  txn_descriptor->instr_cnt             = 1;

  fd_txn_instr_t * txn_instr = fd_scratch_alloc( alignof(fd_txn_instr_t), sizeof(fd_txn_instr_t) );
  txn_instr->program_id      = (uchar)instr_env->program_id_idx;
  txn_instr->acct_cnt        = (ushort)instr_env->accounts->size;
  txn_instr->data_sz         = (ushort)instr_env->data->size;
  txn_instr->acct_off        = (ushort)0;

  ctx.txn_ctx->txn_descriptor   = txn_descriptor;
  ctx.txn_ctx->_txn_raw->raw    = instr_env->accounts->bytes;
  ctx.txn_ctx->_txn_raw->txn_sz = (ushort)instr_env->accounts->size;

  /* Populate the instruction */
  fd_instr_info_t instr = {0};
  fd_convert_txn_instr_to_instr( ctx.txn_ctx,
                                 txn_instr,
                                 ctx.txn_ctx->borrowed_accounts,
                                 &instr );
  instr.data = instr_env->data->bytes;

  fd_funk_end_write( ctx.funk );

  /* The instruciton at this point should be fully set up. */

  int res = fd_execute_instr( ctx.txn_ctx, &instr );
  FD_LOG_NOTICE(("res %d", res));
  FD_LOG_NOTICE(("instr data %lx data sz %lu", instr.data, instr.data_sz));

  /* Now that the instruction has been executed, the execution effects can be
     derived from the transaction context. */

  fd_harness_exec_write_effects( ctx.txn_ctx, res, "/data/ibhatt/instr_effects.pb.bin" );  

  return 0;
}

int
fd_harness_convert_legacy_instr( uchar const * file_buf, ulong file_sz ) {

  /* TODO: FACTOR WKSP AND ALLOCATOR CODE OUT TO COMMON FUNCTION */

  /* Declare a wksp. */

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 3, fd_shmem_cpu_idx( fd_shmem_numa_idx( cpu_idx ) ), "wksp", 0UL );

  /* Declare an alloc from the wksp. */

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( ctx->wksp, fd_alloc_align(), fd_alloc_footprint(), 2UL ), 2UL ), 0UL );
  
  /* Allocate, attach, and push a scratch frame. */

  /* TODO: use scratch methods here and define things out. */

  void * smem = fd_wksp_alloc_laddr( ctx->wksp, fd_scratch_smem_align(), 1<<30, 22UL );
  void * fmem = fd_wksp_alloc_laddr( ctx->wksp, fd_scratch_fmem_align(), 64UL,  22UL );
  fd_scratch_attach( smem, fmem, 1<<30, 64UL );
  fd_scratch_push();

  fd_exec_test_instr_context_t legacy_instr = FD_EXEC_TEST_INSTR_CONTEXT_INIT_DEFAULT;

  pb_istream_t istream = pb_istream_from_buffer( file_buf, file_sz );
  if( FD_UNLIKELY( !pb_decode( &istream, FD_EXEC_TEST_INSTR_CONTEXT_FIELDS, &legacy_instr ) ) ) {
    FD_LOG_ERR(( "Failed to decode exec env pb" ));
  }

  fd_v2_exec_env_t  exec_env  = FD_V2_EXEC_ENV_INIT_DEFAULT;
  fd_v2_slot_env_t  slot_env  = FD_V2_SLOT_ENV_INIT_DEFAULT;
  fd_v2_txn_env_t   txn_env   = FD_V2_TXN_ENV_INIT_DEFAULT;
  fd_v2_instr_env_t instr_env = FD_V2_INSTR_ENV_INIT_DEFAULT;


  /* Populate the account states, and add in the missing sysvars required for
     program execution. */
  FD_TEST(legacy_instr.accounts_count <= 256UL, "Too many accounts in legacy instr");
  exec_env.acct_states_count = legacy_instr.accounts_count;
  exec_env.acct_states       = fd_scratch_alloc( alignof(fd_v2_acct_state_t), sizeof(fd_v2_acct_state_t) * 256UL );
  
  /* First copy over the existing account state. */

  for( uint i=0U; i<legacy_instr.accounts_count; i++ ) {
    fd_memcpy( exec_env.acct_states[i].address, legacy_instr.accounts[i].address, sizeof(fd_pubkey_t) );
    exec_env.acct_states[i].lamports      = legacy_instr.accounts[i].lamports;
    exec_env.acct_states[i].data          = fd_scratch_alloc( alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE( legacy_instr.accounts[i].data_len ) );
    exec_env.acct_states[i].data->size    = legacy_instr.accounts[i].data_len;
    fd_memcpy( exec_env.acct_states[i].data->bytes, legacy_instr.accounts[i].data->bytes, legacy_instr.accounts[i].data->size );
    exec_env.acct_states[i].executable    = legacy_instr.accounts[i].executable;
    exec_env.acct_states[i].rent_epoch    = legacy_instr.accounts[i].rent_epoch;
    fd_memcpy( exec_env.acct_states[i].owner, legacy_instr.accounts[i].owner, sizeof(fd_pubkey_t) );
    exec_env.acct_states[i].has_seed_addr = false;
  }

  /* Now iterate over the existing accounts and figure out which sysvars are
     not inlcuded in the account. If this is the case, then default sysvars
     accounts will be injected to the v2 format. The value of these default
     sysvars will match the ones used in the legacy harness to maintain ease
     of validation between the two formats.
     
     TODO: This can be optimized to be an O(N*M) loop where N is number of 
     accounts and M is the number of sysvars; it can be combined into the
     previous one. */

  for( uint i=0U; i<legacy_instr.accounts_count; i++ ) {
    for()
  }

  return 0;
}
