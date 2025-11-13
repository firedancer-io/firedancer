#undef FD_SPAD_USE_HANDHOLDING
#define FD_SPAD_USE_HANDHOLDING 1

#include "fd_solfuzz_private.h"
#include "fd_instr_harness.h"
#include "../fd_executor.h"
#include "../fd_runtime_stack.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../program/fd_bpf_loader_program.h"
#include "../sysvar/fd_sysvar.h"
#include "../sysvar/fd_sysvar_clock.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../sysvar/fd_sysvar_recent_hashes.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_last_restart_slot.h"
#include "../fd_system_ids.h"
#include <assert.h>

int
fd_solfuzz_pb_instr_ctx_create( fd_solfuzz_runner_t *                runner,
                                fd_exec_instr_ctx_t *                ctx,
                                fd_exec_test_instr_context_t const * test_ctx,
                                bool                                 is_syscall ) {

  memset( ctx, 0, sizeof(fd_exec_instr_ctx_t) );

  fd_funk_t * funk = runner->accdb->funk;

  /* Generate unique ID for funk txn */

  fd_funk_txn_xid_t xid[1] = {{ .ul={ LONG_MAX, LONG_MAX } }};

  /* Create temporary funk transaction and txn / slot / epoch contexts */

  fd_funk_txn_xid_t parent_xid; fd_funk_txn_xid_set_root( &parent_xid );
  fd_accdb_attach_child        ( runner->accdb_admin,     &parent_xid, xid );
  fd_progcache_txn_attach_child( runner->progcache_admin, &parent_xid, xid );

  /* Allocate contexts */
  uchar *             txn_ctx_mem = fd_spad_alloc( runner->spad, FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
  fd_exec_txn_ctx_t * txn_ctx     = fd_exec_txn_ctx_join( fd_exec_txn_ctx_new( txn_ctx_mem ) );

  ctx->txn_ctx = txn_ctx;

  ctx->txn_ctx->exec_stack    = runner->exec_stack;
  ctx->txn_ctx->exec_accounts = runner->exec_accounts;

  /* Bank manager */
  fd_banks_clear_bank( runner->banks, runner->bank );

  fd_features_t * features = fd_bank_features_modify( runner->bank );
  fd_exec_test_feature_set_t const * feature_set = &test_ctx->epoch_context.features;
  if( !fd_solfuzz_pb_restore_features( features, feature_set ) ) {
    return 0;
  }

  /* Setup vote states accounts */
  fd_vote_states_t * vote_states = fd_vote_states_join( fd_vote_states_new( fd_bank_vote_states_locking_modify( runner->bank ), 4UL, 999UL ) );
  if( FD_UNLIKELY( !vote_states ) ) FD_LOG_ERR(( "fd_vote_states_new failed" ));
  fd_bank_vote_states_end_locking_modify( runner->bank );

  fd_vote_states_t * vote_states_prev = fd_vote_states_join( fd_vote_states_new( fd_bank_vote_states_prev_locking_modify( runner->bank ), 4UL, 999UL ) );
  if( FD_UNLIKELY( !vote_states_prev ) ) FD_LOG_ERR(( "fd_vote_states_new for prev failed" ));
  fd_bank_vote_states_prev_end_locking_modify( runner->bank );

  fd_vote_states_t * vote_states_prev_prev = fd_vote_states_join( fd_vote_states_new( fd_bank_vote_states_prev_prev_locking_modify( runner->bank ), 4UL, 999UL ) );
  if( FD_UNLIKELY( !vote_states_prev_prev ) ) FD_LOG_ERR(( "fd_vote_staets_new for prev2 failed" ));
  fd_bank_vote_states_prev_prev_end_locking_modify( runner->bank );

  /* Blockhash queue init */

  ulong blockhash_seed; FD_TEST( fd_rng_secure( &blockhash_seed, sizeof(ulong) ) );
  fd_blockhashes_t * blockhashes = fd_blockhashes_init( fd_bank_block_hash_queue_modify( runner->bank ), blockhash_seed );
  fd_memset( fd_blockhash_deq_push_tail_nocopy( blockhashes->d.deque ), 0, sizeof(fd_hash_t) );

  /* Set up mock txn descriptor */
  fd_txn_p_t * txn                    = fd_spad_alloc_check( runner->spad, fd_txn_align(), fd_txn_footprint( 1UL, 0UL ) );
  fd_txn_t *   txn_descriptor         = TXN( txn );
  txn_descriptor->transaction_version = FD_TXN_V0;
  txn_descriptor->acct_addr_cnt       = (ushort)test_ctx->accounts_count;

  uchar * progcache_scratch = fd_spad_alloc_check( runner->spad, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT );

  if( FD_UNLIKELY( !fd_funk_join( txn_ctx->funk, runner->accdb->funk->shmem ) ) ) {
    FD_LOG_CRIT(( "fd_funk_join(accdb) failed" ));
  }

  if( runner->progcache->funk->shmem ) {
    txn_ctx->progcache = fd_progcache_join( txn_ctx->_progcache, runner->progcache->funk->shmem, progcache_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT );
    if( FD_UNLIKELY( !txn_ctx->progcache ) ) {
      FD_LOG_CRIT(( "fd_progcache_join() failed" ));
    }
  }

  txn_ctx->xid[0]                    = *xid;
  txn_ctx->status_cache              = NULL;
  txn_ctx->bank_hash_cmp             = NULL;
  txn_ctx->log.enable_exec_recording = !!( runner->bank->flags & FD_BANK_FLAGS_EXEC_RECORDING );
  txn_ctx->bank                      = runner->bank;

  fd_compute_budget_details_new( &txn_ctx->details.compute_budget );
  txn_ctx->instr.stack_sz            = 0;
  txn_ctx->accounts.accounts_cnt     = 0UL;
  txn_ctx->accounts.executable_cnt   = 0UL;

  txn_ctx->details.programs_to_reverify_cnt       = 0UL;
  txn_ctx->details.loaded_accounts_data_size      = 0UL;
  txn_ctx->details.loaded_accounts_data_size_cost = 0UL;
  txn_ctx->details.accounts_resize_delta          = 0UL;

  memset( txn_ctx->details.return_data.program_id.key, 0, sizeof(fd_pubkey_t) );
  txn_ctx->details.return_data.len = 0;

  txn_ctx->log.capture_ctx   = NULL;

  txn_ctx->instr.info_cnt     = 0UL;
  txn_ctx->instr.trace_length = 0UL;

  txn_ctx->err.exec_err       = 0;
  txn_ctx->err.exec_err_kind  = FD_EXECUTOR_ERR_KIND_NONE;
  txn_ctx->instr.current_idx  = 0;

  txn_ctx->txn                                               = *txn;
  txn_ctx->details.compute_budget.compute_unit_limit = test_ctx->cu_avail;
  txn_ctx->details.compute_budget.compute_meter      = test_ctx->cu_avail;
  txn_ctx->instr.info_cnt                                    = 1UL;
  txn_ctx->log.enable_vm_tracing                             = runner->enable_vm_tracing;
  txn_ctx->log.tracing_mem                                   = runner->enable_vm_tracing ?
                                                               fd_spad_alloc_check( runner->spad, FD_RUNTIME_VM_TRACE_STATIC_ALIGN, FD_RUNTIME_VM_TRACE_STATIC_FOOTPRINT * FD_MAX_INSTRUCTION_STACK_DEPTH ) :
                                                               NULL;

  /* Set up instruction context */

  fd_instr_info_t * info = fd_spad_alloc( runner->spad, 8UL, sizeof(fd_instr_info_t) );
  assert( info );
  memset( info, 0, sizeof(fd_instr_info_t) );

  if( test_ctx->data ) {
    info->data_sz = (ushort)test_ctx->data->size;
    info->data    = test_ctx->data->bytes;
  }

  txn_ctx->instr.infos[ 0UL ] = *info;

  /* Prepare borrowed account table (correctly handles aliasing) */

  if( FD_UNLIKELY( test_ctx->accounts_count > MAX_TX_ACCOUNT_LOCKS ) ) {
    FD_LOG_NOTICE(( "too many accounts" ));
    return 0;
  }

  /* Load accounts into database */

  fd_txn_account_t * accts = txn_ctx->accounts.accounts;
  fd_memset( accts, 0, test_ctx->accounts_count * sizeof(fd_txn_account_t) );
  txn_ctx->accounts.accounts_cnt = test_ctx->accounts_count;

  int has_program_id = 0;

  for( ulong j=0UL; j < test_ctx->accounts_count; j++ ) {
    fd_pubkey_t * acc_key = (fd_pubkey_t *)test_ctx->accounts[j].address;

    memcpy(  &(txn_ctx->accounts.account_keys[j]), test_ctx->accounts[j].address, sizeof(fd_pubkey_t) );
    if( !fd_solfuzz_pb_load_account( &accts[j], runner->accdb, xid, &test_ctx->accounts[j], 0 ) ) {
      return 0;
    }

    fd_txn_account_t * acc = &accts[j];
    if( fd_txn_account_get_meta( acc ) ) {
      uchar *             data     = fd_spad_alloc( runner->spad, FD_ACCOUNT_REC_ALIGN, FD_ACC_TOT_SZ_MAX );
      ulong               dlen     = fd_txn_account_get_data_len( acc );
      fd_account_meta_t * meta     = (fd_account_meta_t *)data;
      fd_memcpy( data, fd_txn_account_get_meta( acc ), sizeof(fd_account_meta_t)+dlen );
      if( FD_UNLIKELY( !fd_txn_account_join( fd_txn_account_new( acc, acc_key, meta, 0 ) ) ) ) {
        FD_LOG_CRIT(( "Failed to join and new a txn account" ));
      }
    }

    if( !memcmp( accts[j].pubkey, test_ctx->program_id, sizeof(fd_pubkey_t) ) ) {
      has_program_id = 1;
      info->program_id = (uchar)txn_ctx->accounts.accounts_cnt;
    }

    /* Since the instructions sysvar is set as mutable at the txn level, we need to make it mutable here as well. */
    if( !memcmp( accts[j].pubkey, &fd_sysvar_instructions_id, sizeof(fd_pubkey_t) ) ) {
      fd_txn_account_set_mutable( acc );
    }
  }

  /* If the program id is not in the set of accounts it must be added to the set of accounts. */
  if( FD_UNLIKELY( !has_program_id ) ) {
    fd_txn_account_t * program_acc = &accts[ test_ctx->accounts_count ];
    fd_pubkey_t *      program_key = &txn_ctx->accounts.account_keys[ txn_ctx->accounts.accounts_cnt ];
    memcpy( program_key, test_ctx->program_id, sizeof(fd_pubkey_t) );

    fd_account_meta_t * meta = fd_spad_alloc( runner->spad, alignof(fd_account_meta_t), sizeof(fd_account_meta_t) );
    fd_account_meta_init( meta );

    if( FD_UNLIKELY( !fd_txn_account_join( fd_txn_account_new(
          program_acc,
          program_key,
          meta,
          1 ) ) ) ) {
      FD_LOG_CRIT(( "Failed to join and new a txn account" ));
    }

    info->program_id = (uchar)txn_ctx->accounts.accounts_cnt;
    txn_ctx->accounts.accounts_cnt++;
  }

  /* Load in executable accounts */
  for( ulong i = 0; i < txn_ctx->accounts.accounts_cnt; i++ ) {
    fd_pubkey_t * acc_key = (fd_pubkey_t *)test_ctx->accounts[i].address;

    fd_txn_account_t * acc = &accts[i];
    if ( !fd_executor_pubkey_is_bpf_loader( fd_txn_account_get_owner( acc ) ) ) {
      continue;
    }

    fd_account_meta_t const * meta = fd_txn_account_get_meta( acc );
    if( meta == NULL ) {
      uchar * mem = fd_spad_alloc( runner->spad, FD_TXN_ACCOUNT_ALIGN, sizeof(fd_account_meta_t) );
      fd_account_meta_t * meta = (fd_account_meta_t *)mem;
      memset( meta, 0, sizeof(fd_account_meta_t) );
      if( FD_UNLIKELY( !fd_txn_account_join( fd_txn_account_new( acc, acc_key, meta, 0 ) ) ) ) {
        FD_LOG_CRIT(( "Failed to join and new a txn account" ));
      }
      continue;
    }

    if( FD_UNLIKELY( !memcmp( meta->owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
      fd_bpf_upgradeable_loader_state_t program_loader_state[1];
      int err = fd_bpf_loader_program_get_state( acc, program_loader_state );
      if( FD_UNLIKELY( err!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
        continue;
      }

      if( !fd_bpf_upgradeable_loader_state_is_program( program_loader_state ) ) {
        continue;
      }

      fd_pubkey_t * programdata_acc = &program_loader_state->inner.program.programdata_address;
      if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( &txn_ctx->accounts.executable_accounts[txn_ctx->accounts.executable_cnt],
                                                               programdata_acc,
                                                               txn_ctx->funk,
                                                               txn_ctx->xid ) ) ) {
        continue;
      }
      txn_ctx->accounts.executable_cnt++;
    }
  }

  /* Set slot bank variables and ensure all relevant sysvars are present */
  fd_sol_sysvar_last_restart_slot_t last_restart_slot_[1];
  FD_TEST( fd_sysvar_last_restart_slot_read( funk, xid, last_restart_slot_ ) );

  fd_sol_sysvar_clock_t clock_[1];
  fd_sol_sysvar_clock_t * clock = fd_sysvar_clock_read( funk, xid, clock_ );
  FD_TEST( clock );
  fd_bank_slot_set( runner->bank, clock->slot );

  fd_epoch_schedule_t epoch_schedule_[1];
  fd_epoch_schedule_t * epoch_schedule = fd_sysvar_epoch_schedule_read( funk, xid, epoch_schedule_ );
  FD_TEST( epoch_schedule );
  fd_bank_epoch_schedule_set( runner->bank, *epoch_schedule );

  /* Override epoch bank rent setting */
  fd_rent_t rent[1];
  FD_TEST( fd_sysvar_rent_read( funk, xid, rent ) );
  fd_bank_rent_set( runner->bank, *rent );

  /* Override most recent blockhash if given */
  uchar __attribute__((aligned(FD_SYSVAR_RECENT_HASHES_ALIGN))) rbh_mem[FD_SYSVAR_RECENT_HASHES_FOOTPRINT];
  fd_recent_block_hashes_t const * rbh = fd_sysvar_recent_hashes_read( funk, xid, rbh_mem );
  FD_TEST( rbh );
  if( !deq_fd_block_block_hash_entry_t_empty( rbh->hashes ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_tail_const( rbh->hashes );
    if( last ) {
      fd_blockhashes_t * blockhashes = fd_bank_block_hash_queue_modify( runner->bank );
      fd_blockhashes_pop_new( blockhashes );
      fd_blockhash_info_t * info = fd_blockhashes_push_new( blockhashes, &last->blockhash );
      info->fee_calculator = last->fee_calculator;

      fd_bank_rbh_lamports_per_sig_set( runner->bank, last->fee_calculator.lamports_per_signature );
    }
  }

  /* Load instruction accounts */

  if( FD_UNLIKELY( test_ctx->instr_accounts_count > MAX_TX_ACCOUNT_LOCKS ) ) {
    FD_LOG_NOTICE(( "too many instruction accounts" ));
    return 0;
  }

  /* Restore sysvar cache */
  fd_sysvar_cache_restore_fuzz( runner->bank, runner->accdb->funk, xid );
  ctx->sysvar_cache = fd_bank_sysvar_cache_modify( runner->bank );

  uchar acc_idx_seen[ FD_INSTR_ACCT_MAX ] = {0};
  for( ulong j=0UL; j < test_ctx->instr_accounts_count; j++ ) {
    uint index = test_ctx->instr_accounts[j].index;
    if( index >= test_ctx->accounts_count ) {
      FD_LOG_NOTICE( ( "instruction account index out of range (%u > %u)", index, test_ctx->instr_accounts_count ) );
      return 0;
    }

    fd_txn_account_t * acc = &accts[ index ];

    /* Setup instruction accounts */
    fd_instr_info_setup_instr_account( info,
                                       acc_idx_seen,
                                       (ushort)index,
                                       (ushort)j,
                                       (ushort)j,
                                       test_ctx->instr_accounts[j].is_writable,
                                       test_ctx->instr_accounts[j].is_signer );

    if( test_ctx->instr_accounts[j].is_writable ) {
      fd_txn_account_set_mutable( acc );
    }
  }
  info->acct_cnt = (uchar)test_ctx->instr_accounts_count;

  /* The remaining checks enforce that the program is in the accounts list. */
  bool found_program_id = false;
  for( uint i = 0; i < test_ctx->accounts_count; i++ ) {
    if( 0 == memcmp( test_ctx->accounts[i].address, test_ctx->program_id, sizeof(fd_pubkey_t) ) ) {
      info->program_id = (uchar) i;
      found_program_id = true;
      break;
    }
  }

  /* Early returning only happens in instruction execution. */
  if( !is_syscall && !found_program_id ) {
    FD_LOG_NOTICE(( " Unable to find program_id in accounts" ));
    return 0;
  }

  ctx->instr = info;

  if( FD_UNLIKELY( !fd_funk_join( txn_ctx->funk, runner->accdb->funk->shmem ) ) ) {
    FD_LOG_CRIT(( "fd_funk_join(accdb) failed" ));
  }

  if( runner->progcache->funk->shmem ) {
    txn_ctx->progcache = fd_progcache_join( txn_ctx->_progcache, runner->progcache->funk->shmem, progcache_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT );
    if( FD_UNLIKELY( !txn_ctx->progcache ) ) {
      FD_LOG_CRIT(( "fd_progcache_join() failed" ));
    }
  }

  txn_ctx->xid[0]                    = *xid;
  txn_ctx->status_cache              = NULL;
  txn_ctx->bank_hash_cmp             = NULL;
  txn_ctx->log.enable_exec_recording = !!( runner->bank->flags & FD_BANK_FLAGS_EXEC_RECORDING );
  txn_ctx->bank                      = runner->bank;

  fd_log_collector_init( &ctx->txn_ctx->log.log_collector, 1 );
  fd_base58_encode_32( txn_ctx->accounts.account_keys[ ctx->instr->program_id ].uc, NULL, ctx->program_id_base58 );

  return 1;
}

void
fd_solfuzz_pb_instr_ctx_destroy( fd_solfuzz_runner_t * runner,
                                 fd_exec_instr_ctx_t * ctx ) {
  if( !ctx ) return;
  fd_accdb_clear( runner->accdb_admin );
  fd_progcache_clear( runner->progcache_admin );
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
  if( !fd_solfuzz_pb_instr_ctx_create( runner, ctx, input, false ) ) {
    fd_solfuzz_pb_instr_ctx_destroy( runner, ctx );
    return 0UL;
  }

  fd_instr_info_t * instr = (fd_instr_info_t *) ctx->instr;

  /* Execute the test */
  int exec_result = fd_execute_instr( ctx->txn_ctx, instr );

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
  effects->cu_avail = ctx->txn_ctx->details.compute_budget.compute_meter;

  /* Don't capture custom error codes if the program is a precompile */
  if( FD_LIKELY( effects->result ) ) {
    int program_id_idx = ctx->instr[ 0UL ].program_id;
    if( exec_result==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR &&
        fd_executor_lookup_native_precompile_program( &ctx->txn_ctx->accounts.accounts[ program_id_idx ] )==NULL ) {
      effects->custom_err = ctx->txn_ctx->err.custom_err;
    }
  }

  /* Allocate space for captured accounts */
  ulong modified_acct_cnt = ctx->txn_ctx->accounts.accounts_cnt;

  fd_exec_test_acct_state_t * modified_accts =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_acct_state_t),
                                sizeof (fd_exec_test_acct_state_t) * modified_acct_cnt );
  if( FD_UNLIKELY( _l > output_end ) ) {
    fd_solfuzz_pb_instr_ctx_destroy( runner, ctx );
    return 0;
  }
  effects->modified_accounts       = modified_accts;
  effects->modified_accounts_count = 0UL;

  /* Capture borrowed accounts */

  for( ulong j=0UL; j < ctx->txn_ctx->accounts.accounts_cnt; j++ ) {
    fd_txn_account_t * acc = &ctx->txn_ctx->accounts.accounts[j];
    if( !fd_txn_account_get_meta( acc ) ) {
      continue;
    }

    ulong modified_idx = effects->modified_accounts_count;
    assert( modified_idx < modified_acct_cnt );

    fd_exec_test_acct_state_t * out_acct = &effects->modified_accounts[ modified_idx ];
    memset( out_acct, 0, sizeof(fd_exec_test_acct_state_t) );
    /* Copy over account content */

    memcpy( out_acct->address, acc->pubkey, sizeof(fd_pubkey_t) );
    out_acct->lamports = fd_txn_account_get_lamports( acc );
    if( fd_txn_account_get_data_len( acc )>0UL ) {
      out_acct->data =
        FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                    PB_BYTES_ARRAY_T_ALLOCSIZE( fd_txn_account_get_data_len( acc ) ) );
      if( FD_UNLIKELY( _l > output_end ) ) {
        fd_solfuzz_pb_instr_ctx_destroy( runner, ctx );
        return 0UL;
      }
      out_acct->data->size = (pb_size_t)fd_txn_account_get_data_len( acc );
      fd_memcpy( out_acct->data->bytes, fd_txn_account_get_data( acc ), fd_txn_account_get_data_len( acc ) );
    }

    out_acct->executable = fd_txn_account_is_executable( acc );
    memcpy( out_acct->owner, fd_txn_account_get_owner( acc ), sizeof(fd_pubkey_t) );

    effects->modified_accounts_count++;
  }

  /* Capture return data */
  fd_txn_return_data_t * return_data = &ctx->txn_ctx->details.return_data;
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
