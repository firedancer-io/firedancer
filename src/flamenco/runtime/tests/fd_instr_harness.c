#include "fd_solfuzz_private.h"
#include "fd_instr_harness.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../program/fd_bpf_loader_program.h"
#include "../program/fd_precompiles.h"
#include "../fd_system_ids.h"
#include "../../progcache/fd_progcache_admin.h"
#include "../../log_collector/fd_log_collector.h"

void
fd_solfuzz_pb_instr_ctx_create( fd_solfuzz_runner_t *                runner,
                                fd_exec_instr_ctx_t *                ctx,
                                fd_exec_test_instr_context_t const * test_ctx ) {

  memset( ctx, 0, sizeof(fd_exec_instr_ctx_t) );

  /* Create temporary fork for account loading */

  runner->bank->progcache_fork_id = fd_progcache_attach_child( runner->progcache->join, fd_progcache_fork_id_initial() );
  runner->bank->accdb_fork_id     = fd_accdb_attach_child( runner->accdb, runner->root_fork_id );

  fd_txn_in_t *  txn_in  = fd_spad_alloc( runner->spad, alignof(fd_txn_in_t), sizeof(fd_txn_in_t) );
  fd_txn_out_t * txn_out = fd_spad_alloc( runner->spad, alignof(fd_txn_out_t), sizeof(fd_txn_out_t) );

  fd_log_collector_t * log = fd_spad_alloc( runner->spad, alignof(fd_log_collector_t), sizeof(fd_log_collector_t) );

  fd_runtime_t * runtime = runner->runtime;

  runtime->log.log_collector = log;

  ctx->txn_out = txn_out;
  ctx->txn_in  = txn_in;

  fd_memset( txn_out->accounts.keys,       0, sizeof(fd_pubkey_t)*MAX_TX_ACCOUNT_LOCKS );
  fd_memset( runtime->accounts.account,    0, sizeof(fd_acc_t)*MAX_TX_ACCOUNT_LOCKS );
  fd_memset( runtime->accounts.executable, 0, sizeof(fd_acc_t)*MAX_TX_ACCOUNT_LOCKS );
  for( ulong j=0UL; j<MAX_TX_ACCOUNT_LOCKS; j++ ) {
    txn_out->accounts.account[ j ]    = &runtime->accounts.account[ j ];
    txn_out->accounts.executable[ j ] = &runtime->accounts.executable[ j ];
  }
  txn_out->accounts.executable_cnt = 0UL;

  /* Bank manager */
  fd_banks_clear_bank( runner->banks, runner->bank, 4UL );

  /* Restore features */
  FD_TEST( test_ctx->has_features );
  fd_features_t * features = &runner->bank->f.features;
  fd_exec_test_feature_set_t const * feature_set = &test_ctx->features;
  FD_TEST( fd_solfuzz_pb_restore_features( features, feature_set ) );

  /* Blockhash queue init */
  ulong blockhash_seed; FD_TEST( fd_rng_secure( &blockhash_seed, sizeof(ulong) ) );
  fd_blockhashes_t * blockhashes = fd_blockhashes_init( &runner->bank->f.block_hash_queue, blockhash_seed );
  fd_memset( fd_blockhash_deq_push_tail_nocopy( blockhashes->d.deque ), 0, sizeof(fd_hash_t) );

  /* Set up mock txn descriptor and payload
     FIXME: More fields may need to be initialized. This seems to be
     the minimal set of fields needed to retain full context for
     precompile execution. */
  fd_txn_p_t * txn            = fd_spad_alloc_check( runner->spad, alignof(fd_txn_p_t), sizeof(fd_txn_p_t) );
  fd_txn_t *   txn_descriptor = TXN( txn );
  if( test_ctx->data ) {
    memcpy( txn->payload, test_ctx->data->bytes, test_ctx->data->size );
    txn->payload_sz = test_ctx->data->size;
  } else {
    txn->payload_sz = 0;
  }
  txn_descriptor->transaction_version = FD_TXN_VLEGACY;
  txn_descriptor->acct_addr_cnt       = (ushort)test_ctx->accounts_count;
  txn_descriptor->instr_cnt           = 1;
  txn_descriptor->instr[0]            = (fd_txn_instr_t) {
    .acct_cnt = (ushort)test_ctx->accounts_count,
    .data_off = 0,
    .data_sz  = (ushort)txn->payload_sz,
  };

  runtime->log.enable_log_collector = 0;

  fd_compute_budget_details_new( &txn_out->details.compute_budget );
  runtime->instr.stack_sz            = 0;
  txn_out->accounts.cnt     = 0UL;
  txn_out->accounts.executable_cnt   = 0UL;

  txn_out->details.loaded_accounts_data_size = 0UL;
  txn_out->details.accounts_resize_delta     = 0L;

  memset( txn_out->details.return_data.program_id.key, 0, sizeof(fd_pubkey_t) );
  txn_out->details.return_data.len = 0;

  runtime->log.capture_ctx    = NULL;
  runtime->log.dump_proto_ctx = NULL;
  runtime->log.txn_dump_ctx   = NULL;

  runtime->instr.trace_length = 1UL;

  txn_out->err.exec_err       = 0;
  txn_out->err.exec_err_kind  = FD_EXECUTOR_ERR_KIND_NONE;
  runtime->instr.current_idx  = 0;

  txn_in->txn                                        = txn;
  txn_out->details.compute_budget.compute_unit_limit = test_ctx->cu_avail;
  txn_out->details.compute_budget.compute_meter      = test_ctx->cu_avail;
  runtime->log.enable_vm_tracing                     = runner->enable_vm_tracing;
  runtime->log.tracing_mem                           = runner->enable_vm_tracing ?
                                                       fd_spad_alloc_check( runner->spad, FD_RUNTIME_VM_TRACE_STATIC_ALIGN, FD_RUNTIME_VM_TRACE_STATIC_FOOTPRINT * FD_MAX_INSTRUCTION_STACK_DEPTH ) :
                                                       NULL;

  /* Set up instruction context */
  fd_instr_info_t * info = &runtime->instr.trace[ 0UL ];
  memset( info, 0, sizeof(fd_instr_info_t) );
  info->stack_height = 1;

  if( test_ctx->data ) {
    if( FD_UNLIKELY( test_ctx->data->size>FD_INSTR_DATA_MAX ) ) {
      FD_LOG_ERR(( "invariant violation: instr data sz is too large %u > %lu", test_ctx->data->size, FD_INSTR_DATA_MAX ));
    }
    info->data_sz = (ushort)test_ctx->data->size;
    memcpy( info->data, test_ctx->data->bytes, info->data_sz );
  }

  /* Prepare borrowed account table (correctly handles aliasing) */

  if( FD_UNLIKELY( test_ctx->accounts_count > MAX_TX_ACCOUNT_LOCKS ) ) {
    FD_LOG_ERR(( "invariant violation: too many accounts (%lu > %lu)",
                 (ulong)test_ctx->accounts_count, (ulong)MAX_TX_ACCOUNT_LOCKS ));
  }

  /* Load accounts from input */

  /* Mimic Agave's mock_compile_message: put the program + referenced
     instruction accounts in the first txn slots, the rest after. */
  uchar account_in_message[ MAX_TX_ACCOUNT_LOCKS ] = {0};
  uint  input_txn_idx     [ MAX_TX_ACCOUNT_LOCKS ];

  for( ulong i=0UL; i<test_ctx->instr_accounts_count; i++ ) {
    uint index = test_ctx->instr_accounts[ i ].index;
    if( FD_UNLIKELY( index>=test_ctx->accounts_count ) ) {
      FD_LOG_ERR(( "invariant violation: instruction account index out of range (%u >= %u)",
                   index, test_ctx->accounts_count ));
    }
    account_in_message[ index ] = 1;
  }

  ulong program_idx = ULONG_MAX;
  for( ulong i=0UL; i<test_ctx->accounts_count; i++ ) {
    if( !memcmp( test_ctx->accounts[ i ].address, test_ctx->program_id, sizeof(fd_pubkey_t) ) ) {
      account_in_message[ i ] = 1;
      program_idx = i;
      break;
    }
  }

  /* Ensure the program id is in the set of accounts */
  FD_TEST( program_idx!=ULONG_MAX );

  /* Compile the message by filling the transaction accounts with
     only accounts referenced by the instruction. */
  uint message_account_cnt = 0U;
  uint tail_txn_idx        = test_ctx->accounts_count;
  for( ulong i=0UL; i<test_ctx->accounts_count; i++ ) {
    input_txn_idx[ i ] = account_in_message[ i ] ? message_account_cnt++ : --tail_txn_idx;
  }

  info->program_id      = (uchar)input_txn_idx[ program_idx ];
  txn_out->accounts.cnt = message_account_cnt;

  for( ulong j=0UL; j < test_ctx->accounts_count; j++ ) {
    if( !account_in_message[j] ) continue;

    ulong txn_idx = input_txn_idx[j];
    fd_pubkey_t * acc_key = (fd_pubkey_t *)test_ctx->accounts[j].address;

    uint dlen = test_ctx->accounts[j].data ? test_ctx->accounts[j].data->size : 0U;
    uchar * data_buf = fd_spad_alloc( runner->spad, FD_ACCOUNT_REC_ALIGN, FD_RUNTIME_ACC_SZ_MAX );
    if( dlen ) {
      fd_memcpy( data_buf, test_ctx->accounts[j].data->bytes, dlen );
    }

    /* Initialize entry with in-memory account data (no DB backing) */
    fd_acc_t * acc = txn_out->accounts.account[txn_idx];
    memcpy( acc->pubkey, acc_key->key, 32 );
    memcpy( acc->owner, test_ctx->accounts[j].owner, 32 );
    acc->lamports   = test_ctx->accounts[j].lamports;
    acc->executable = test_ctx->accounts[j].executable;
    acc->data_len   = dlen;
    acc->data       = data_buf;
    acc->_writable  = 1;
    acc->commit     = 0;

    txn_out->accounts.is_writable[txn_idx] = 1U;
    runtime->accounts.refcnt[txn_idx] = 0UL;
    txn_out->accounts.keys[txn_idx] = *acc_key;
  }

  /* Load in executable accounts */
  for( ulong i=0UL; i<test_ctx->accounts_count; i++ ) {
    fd_exec_test_acct_state_t const * prog  = &test_ctx->accounts[i];
    fd_pubkey_t const *               owner = fd_type_pun_const( prog->owner );

    if( !fd_executor_pubkey_is_bpf_loader( owner ) ) {
      continue;
    }

    if( FD_UNLIKELY( !memcmp( owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
      if( FD_UNLIKELY( !prog->data ) ) continue;

      fd_bpf_state_t program_loader_state[1];
      int err = fd_bpf_loader_program_get_state2( prog->data->bytes, prog->data->size, program_loader_state );
      if( FD_UNLIKELY( err!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
        continue;
      }

      if( program_loader_state->discriminant!=FD_BPF_STATE_PROGRAM ) {
        continue;
      }

      fd_pubkey_t * programdata_acc = &program_loader_state->inner.program.programdata_address;

      fd_exec_test_acct_state_t const * pd = NULL;
      for( ulong j=0UL; j<test_ctx->accounts_count; j++ ) {
        if( !memcmp( test_ctx->accounts[j].address, programdata_acc, sizeof(fd_pubkey_t) ) ) {
          pd = &test_ctx->accounts[j];
          break;
        }
      }
      if( FD_UNLIKELY( pd==NULL || !pd->data ) ) {
        continue;
      }

      FD_TEST( txn_out->accounts.executable_cnt < MAX_TX_ACCOUNT_LOCKS );
      fd_acc_t * exe = txn_out->accounts.executable[ txn_out->accounts.executable_cnt ];
      memcpy( exe->pubkey, programdata_acc->key, 32 );
      memcpy( exe->owner,  pd->owner, sizeof(fd_pubkey_t) );
      /* Agave loads a program into its ProgramCache from the
         programdata bytes independently of the on-chain lamports
         snapshot.  An instruction fixture may capture a programdata
         account with zero lamports (a real 0-lamport account would
         otherwise have all its other fields cleared between
         transactions), and still expect the program to execute.  The
         runtime treats an executable account as "deployed" only when it
         exists, so present the programdata as existing whenever it
         carries program data.  This executable account is read-only on
         the invoke path and its lamports are never consumed, only used
         as an existence gate. */
      exe->lamports   = ( !pd->lamports && pd->data->size ) ? 1UL : pd->lamports;
      exe->executable = pd->executable;
      exe->data_len   = pd->data->size;
      exe->data       = (uchar *)pd->data->bytes;
      txn_out->accounts.executable_cnt++;
    }
  }

  /* Load instruction accounts */

  if( FD_UNLIKELY( test_ctx->instr_accounts_count > FD_INSTR_ACCT_MAX ) ) {
    FD_LOG_ERR(( "invariant violation: too many instruction accounts (%lu > %lu)",
                 (ulong)test_ctx->instr_accounts_count, (ulong)FD_INSTR_ACCT_MAX ));
  }

  /* Restore sysvar cache */
  fd_sysvar_cache_t * sysvar_cache = &runner->bank->f.sysvar_cache;
  ctx->sysvar_cache = sysvar_cache;
  for( ulong i=0UL; i<test_ctx->accounts_count; i++ ) {
    fd_exec_test_acct_state_t const * account = &test_ctx->accounts[i];
    if( FD_UNLIKELY( !account->data ) ) continue;

    fd_pubkey_t const * address = fd_type_pun_const( account->address );
    fd_sysvar_cache_restore_one( sysvar_cache,
                                 address,
                                 account->lamports,
                                 account->data->bytes,
                                 account->data->size );
  }

  ctx->runtime = runtime;

  fd_sol_sysvar_clock_t clock_[1];
  fd_sol_sysvar_clock_t * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, clock_ );
  FD_TEST( clock );
  runner->bank->f.slot = clock->slot;

  runner->bank->progcache_fork_id = fd_progcache_attach_child( runner->progcache->join, runner->bank->progcache_fork_id );

  fd_epoch_schedule_t epoch_schedule_[1];
  fd_epoch_schedule_t * epoch_schedule = fd_sysvar_cache_epoch_schedule_read( ctx->sysvar_cache, epoch_schedule_ );
  FD_TEST( epoch_schedule );
  runner->bank->f.epoch_schedule = *epoch_schedule;

  fd_rent_t rent_[1];
  fd_rent_t * rent = fd_sysvar_cache_rent_read( ctx->sysvar_cache, rent_ );
  FD_TEST( rent );
  runner->bank->f.rent = *rent;

  if( !fd_sysvar_cache_recent_hashes_is_empty( sysvar_cache ) ) {
    uchar const * rbh_data  = sysvar_cache->bin_recent_hashes;
    ulong         rbh_len   = FD_LOAD( ulong, rbh_data );
    ulong         entry_off = sizeof(ulong) + ((rbh_len - 1UL) * 40UL);
    uchar const * entry     = rbh_data + entry_off;
    FD_TEST( entry_off+40UL <= sysvar_cache->desc[ FD_SYSVAR_recent_hashes_IDX ].data_sz );

    fd_blockhashes_t * blockhashes = &runner->bank->f.block_hash_queue;
    fd_blockhashes_pop_new( blockhashes );
    fd_hash_t hash = FD_LOAD( fd_hash_t, entry );
    fd_blockhash_info_t * info = fd_blockhashes_push_new( blockhashes, &hash );
    info->lamports_per_signature = runner->bank->f.rbh_lamports_per_sig =
        FD_LOAD( ulong, entry+32UL );
  }

  /* Agave compiles the instruction into a message, OR-ing duplicate
     accounts' writable/signer flags. */
  uchar instr_is_writable[ FD_TXN_ACCT_ADDR_MAX ] = {0};
  uchar instr_is_signer  [ FD_TXN_ACCT_ADDR_MAX ] = {0};
  int   bpf_upgradeable_present = !memcmp( test_ctx->program_id, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) );
  for( ulong j=0UL; j < test_ctx->instr_accounts_count; j++ ) {
    uint index = test_ctx->instr_accounts[j].index;

    instr_is_writable[index] = (uchar)( instr_is_writable[index] | test_ctx->instr_accounts[j].is_writable );
    instr_is_signer[index]   = (uchar)( instr_is_signer[index]   | test_ctx->instr_accounts[j].is_signer );
    if( !memcmp( test_ctx->accounts[index].address, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
      bpf_upgradeable_present = 1;
    }
  }

  uchar acc_idx_seen[ FD_TXN_ACCT_ADDR_MAX ] = {0};
  for( ulong j=0UL; j < test_ctx->instr_accounts_count; j++ ) {
    uint index = test_ctx->instr_accounts[j].index;

    /* A program account is demoted to read-only unless the upgradeable
       loader is present. */
    uchar is_writable = instr_is_writable[index];
    if( !bpf_upgradeable_present && !memcmp( test_ctx->accounts[index].address, test_ctx->program_id, sizeof(fd_pubkey_t) ) ) {
      is_writable = 0;
    }

    /* Setup instruction accounts */
    fd_instr_info_setup_instr_account( info,
                                       acc_idx_seen,
                                       (ushort)input_txn_idx[index],
                                       (ushort)j,
                                       (ushort)j,
                                       is_writable,
                                       instr_is_signer[index] );
  }
  info->acct_cnt          = (ushort)test_ctx->instr_accounts_count;

  ctx->instr              = info;
  ctx->runtime->progcache = runner->progcache;
  ctx->runtime->accdb     = runner->accdb;

  runtime->log.enable_log_collector = 0;

  fd_log_collector_init( ctx->runtime->log.log_collector, 0 );
  fd_base58_encode_32( txn_out->accounts.keys[ ctx->instr->program_id ].uc, NULL, ctx->program_id_base58 );
}

void
fd_solfuzz_pb_instr_ctx_destroy( fd_solfuzz_runner_t * runner,
                                 fd_exec_instr_ctx_t * ctx ) {
  if( !ctx ) return;

  fd_progcache_reset( runner->progcache->join );

  /* Purge the fork attached in ctx_create so the accdb fork pool slot
     is released back for reuse.  Without this, repeated harness
     invocations (e.g. under a fuzzer) exhaust max_live_slots. */
  fd_accdb_purge( runner->accdb, runner->bank->accdb_fork_id );
  int charge_busy = 0;
  fd_accdb_background( runner->accdb, &charge_busy );

  /* Compact the progcache allocator so empty superblocks are returned
     to the workspace.  Required for the leak check to pass. */
  fd_alloc_compact( runner->progcache->join->alloc );
}

/* Txn index for addr among the compiled-message accounts [0,cnt).
   Returns ULONG_MAX if not found. */
static ulong
instr_harness_idx_of( fd_txn_out_t const * txn_out, uchar const * addr ) {
  for( ulong i=0UL; i<txn_out->accounts.cnt; i++ ) {
    if( !memcmp( txn_out->accounts.keys[i].key, addr, sizeof(fd_pubkey_t) ) ) return i;
  }
  return ULONG_MAX;
}

ulong
fd_solfuzz_pb_instr_run( fd_solfuzz_runner_t * runner,
                         void const *          input_,
                         void **               output_,
                         void *                output_buf,
                         ulong                 output_bufsz ) {
  fd_exec_test_instr_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_instr_effects_t **      output = fd_type_pun( output_ );

  /* Convert the Protobuf inputs to a fd_exec context */
  fd_exec_instr_ctx_t ctx[1];
  fd_solfuzz_pb_instr_ctx_create( runner, ctx, input );

  fd_instr_info_t * instr = (fd_instr_info_t *) ctx->instr;

  /* Execute the test */
  int exec_result = fd_execute_instr( ctx->runtime, runner->bank, ctx->txn_in, ctx->txn_out, instr );

  /* Allocate space to capture outputs */
  ulong output_end = (ulong)output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );

  fd_exec_test_instr_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_instr_effects_t),
                                sizeof (fd_exec_test_instr_effects_t) );
  if( FD_UNLIKELY( _l > output_end ) ) {
    fd_solfuzz_pb_instr_ctx_destroy( runner, ctx );
    return 0UL;
  }
  fd_memset( effects, 0, sizeof(fd_exec_test_instr_effects_t) );

  /* Capture error code */

  effects->result   = -exec_result;
  effects->cu_avail = ctx->txn_out->details.compute_budget.compute_meter;

  /* Don't capture custom error codes if the program is a precompile */
  if( FD_LIKELY( effects->result ) ) {
    int program_id_idx = ctx->instr[ 0UL ].program_id;
    if( exec_result==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR &&
        fd_executor_lookup_native_precompile_program( &ctx->txn_out->accounts.keys[ program_id_idx ] )==NULL ) {
      effects->custom_err = ctx->txn_out->err.custom_err;
    }
  }

  /* Allocate space for captured accounts */
  ulong modified_acct_cnt = input->accounts_count;

  fd_exec_test_acct_state_t * modified_accts =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_acct_state_t),
                                sizeof (fd_exec_test_acct_state_t) * modified_acct_cnt );
  if( FD_UNLIKELY( _l > output_end ) ) {
    fd_solfuzz_pb_instr_ctx_destroy( runner, ctx );
    return 0;
  }
  effects->modified_accounts       = modified_accts;
  effects->modified_accounts_count = 0UL;

  /* Capture any accounts which may have changed */

  for( ulong j=0UL; j < input->accounts_count; j++ ) {
    fd_exec_test_acct_state_t const * in_acct = &input->accounts[j];

    ulong         lamports;
    uchar const * data;
    ulong         data_len;
    int           executable;
    uchar const * owner;

    /* Capture the account from the message in case it was modified,
       or just report the input account otherwise. */
    ulong txn_idx = instr_harness_idx_of( ctx->txn_out, in_acct->address );
    if( txn_idx!=ULONG_MAX ) {
      fd_acc_t const * acc = ctx->txn_out->accounts.account[txn_idx];
      lamports   = acc->lamports;
      data       = acc->data;
      data_len   = acc->data_len;
      executable = acc->executable;
      owner      = acc->owner;
    } else {
      lamports   = in_acct->lamports;
      data       = in_acct->data ? in_acct->data->bytes : NULL;
      data_len   = in_acct->data ? in_acct->data->size  : 0UL;
      executable = in_acct->executable;
      owner      = in_acct->owner;
    }

    ulong modified_idx = effects->modified_accounts_count;
    if( FD_UNLIKELY( modified_idx >= modified_acct_cnt ) ) {
      FD_LOG_CRIT(( "invalid modified account index" ));
    }

    fd_exec_test_acct_state_t * out_acct = &effects->modified_accounts[ modified_idx ];
    memset( out_acct, 0, sizeof(fd_exec_test_acct_state_t) );

    /* Copy over account content */
    memcpy( out_acct->address, in_acct->address, sizeof(fd_pubkey_t) );
    out_acct->lamports = lamports;
    if( data_len>0UL ) {
      out_acct->data =
        FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                    PB_BYTES_ARRAY_T_ALLOCSIZE( data_len ) );
      if( FD_UNLIKELY( _l > output_end ) ) {
        fd_solfuzz_pb_instr_ctx_destroy( runner, ctx );
        return 0UL;
      }
      out_acct->data->size = (pb_size_t)data_len;
      fd_memcpy( out_acct->data->bytes, data, data_len );
    }

    out_acct->executable = executable;
    memcpy( out_acct->owner, owner, sizeof(fd_pubkey_t) );

    effects->modified_accounts_count++;
  }

  fd_solfuzz_direct_mapping_handle_cu_exhaustion(
      runner, effects->cu_avail, effects->result,
      effects->modified_accounts, (pb_size_t)effects->modified_accounts_count );

  /* Capture return data */
  fd_txn_return_data_t * return_data = &ctx->txn_out->details.return_data;
  if( return_data->len>0UL ) {
    effects->return_data = FD_SCRATCH_ALLOC_APPEND(l, alignof(pb_bytes_array_t),
                                PB_BYTES_ARRAY_T_ALLOCSIZE( return_data->len ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      fd_solfuzz_pb_instr_ctx_destroy( runner, ctx );
      return 0UL;
    }
    effects->return_data->size = (pb_size_t)return_data->len;
    fd_memcpy( effects->return_data->bytes, return_data->data, return_data->len );
  }

  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  fd_solfuzz_pb_instr_ctx_destroy( runner, ctx );

  *output = effects;
  return actual_end - (ulong)output_buf;
}
