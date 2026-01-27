#undef FD_SPAD_USE_HANDHOLDING
#define FD_SPAD_USE_HANDHOLDING 1

#include "fd_solfuzz_private.h"
#include "fd_instr_harness.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../program/fd_bpf_loader_program.h"
#include "../program/fd_loader_v4_program.h"
#include "../fd_system_ids.h"
#include "../../accdb/fd_accdb_admin_v1.h"
#include "../../log_collector/fd_log_collector.h"
#include <assert.h>

int
fd_solfuzz_pb_instr_ctx_create( fd_solfuzz_runner_t *                runner,
                                fd_exec_instr_ctx_t *                ctx,
                                fd_exec_test_instr_context_t const * test_ctx,
                                bool                                 is_syscall ) {

  memset( ctx, 0, sizeof(fd_exec_instr_ctx_t) );

  /* Generate unique ID for funk txn */

  fd_funk_txn_xid_t xid[1] = {{ .ul={ LONG_MAX, LONG_MAX } }};

  /* Create temporary funk transaction and txn / slot / epoch contexts */

  fd_funk_txn_xid_t parent_xid; fd_funk_txn_xid_set_root( &parent_xid );
  fd_accdb_attach_child        ( runner->accdb_admin,     &parent_xid, xid );
  fd_progcache_txn_attach_child( runner->progcache_admin, &parent_xid, xid );

  fd_txn_in_t *  txn_in  = fd_spad_alloc( runner->spad, alignof(fd_txn_in_t), sizeof(fd_txn_in_t) );
  fd_txn_out_t * txn_out = fd_spad_alloc( runner->spad, alignof(fd_txn_out_t), sizeof(fd_txn_out_t) );

  fd_log_collector_t * log = fd_spad_alloc( runner->spad, alignof(fd_log_collector_t), sizeof(fd_log_collector_t) );

  fd_runtime_t * runtime = runner->runtime;

  runtime->log.log_collector = log;

  ctx->txn_out = txn_out;
  ctx->txn_in  = txn_in;

  memset( txn_out->accounts.account, 0, sizeof(fd_accdb_rw_t) * MAX_TX_ACCOUNT_LOCKS );

  memset( txn_out->accounts.account, 0, sizeof(fd_accdb_rw_t) * MAX_TX_ACCOUNT_LOCKS );

  /* Bank manager */
  fd_banks_clear_bank( runner->banks, runner->bank, 4UL );

  fd_features_t * features = fd_bank_features_modify( runner->bank );
  fd_exec_test_feature_set_t const * feature_set = &test_ctx->epoch_context.features;
  if( !fd_solfuzz_pb_restore_features( features, feature_set ) ) {
    return 0;
  }

  /* Blockhash queue init */

  ulong blockhash_seed; FD_TEST( fd_rng_secure( &blockhash_seed, sizeof(ulong) ) );
  fd_blockhashes_t * blockhashes = fd_blockhashes_init( fd_bank_block_hash_queue_modify( runner->bank ), blockhash_seed );
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
  runtime->accounts.executable_cnt   = 0UL;

  txn_out->details.programs_to_reverify_cnt  = 0UL;
  txn_out->details.loaded_accounts_data_size = 0UL;
  txn_out->details.accounts_resize_delta     = 0UL;

  memset( txn_out->details.return_data.program_id.key, 0, sizeof(fd_pubkey_t) );
  txn_out->details.return_data.len = 0;

  runtime->log.capture_ctx   = NULL;

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
    FD_LOG_NOTICE(( "too many accounts" ));
    return 0;
  }

  /* Load accounts into database */

  fd_account_meta_t * metas[MAX_TX_ACCOUNT_LOCKS] = {0};
  txn_out->accounts.cnt = test_ctx->accounts_count;

  int has_program_id = 0;

  for( ulong j=0UL; j < test_ctx->accounts_count; j++ ) {
    fd_pubkey_t * acc_key = (fd_pubkey_t *)test_ctx->accounts[j].address;

    memcpy( &(txn_out->accounts.keys[j]), test_ctx->accounts[j].address, sizeof(fd_pubkey_t) );
    runtime->accounts.refcnt[j] = 0UL;

    uchar *             data     = fd_spad_alloc( runner->spad, FD_ACCOUNT_REC_ALIGN, FD_ACC_TOT_SZ_MAX );
    fd_account_meta_t * meta     = (fd_account_meta_t *)data;
    uint dlen = test_ctx->accounts[j].data ? test_ctx->accounts[j].data->size : 0U;
    if( test_ctx->accounts[j].data ) {
      fd_memcpy( meta+1, test_ctx->accounts[j].data->bytes, dlen );
    }
    meta->dlen = dlen;
    meta->lamports = test_ctx->accounts[j].lamports;
    meta->executable = test_ctx->accounts[j].executable;
    fd_memcpy( meta->owner, test_ctx->accounts[j].owner, sizeof(fd_pubkey_t) );
    metas[j] = meta;
    fd_accdb_rw_init_nodb( &txn_out->accounts.account[j], acc_key, metas[j], FD_RUNTIME_ACC_SZ_MAX );
    txn_out->accounts.keys[j] = *acc_key;

    if( !memcmp( acc_key, test_ctx->program_id, sizeof(fd_pubkey_t) ) ) {
      has_program_id = 1;
      info->program_id = (uchar)txn_out->accounts.cnt;
    }
  }

  /* If the program id is not in the set of accounts it must be added to the set of accounts. */
  if( FD_UNLIKELY( !has_program_id ) ) {
    fd_pubkey_t * program_key = &txn_out->accounts.keys[ txn_out->accounts.cnt ];
    memcpy( program_key, test_ctx->program_id, sizeof(fd_pubkey_t) );

    fd_account_meta_t * meta = fd_spad_alloc( runner->spad, alignof(fd_account_meta_t), sizeof(fd_account_meta_t) );
    fd_account_meta_init( meta );

    txn_out->accounts.account[test_ctx->accounts_count].meta = meta;

    info->program_id = (uchar)txn_out->accounts.cnt;
    txn_out->accounts.cnt++;
  }

  /* Load in executable accounts */
  for( ulong i = 0; i < txn_out->accounts.cnt; i++ ) {

    fd_account_meta_t * meta = txn_out->accounts.account[i].meta;
    if( !fd_executor_pubkey_is_bpf_loader( fd_type_pun( meta->owner ) ) ) {
      continue;
    }

    if( FD_UNLIKELY( !memcmp( meta->owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
      fd_bpf_upgradeable_loader_state_t program_loader_state[1];
      int err = fd_bpf_loader_program_get_state( meta, program_loader_state );
      if( FD_UNLIKELY( err!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
        continue;
      }

      if( !fd_bpf_upgradeable_loader_state_is_program( program_loader_state ) ) {
        continue;
      }

      fd_pubkey_t * programdata_acc = &program_loader_state->inner.program.programdata_address;

      meta = NULL;
      for( ulong j=0UL; j<test_ctx->accounts_count; j++ ) {
        if( !memcmp( test_ctx->accounts[j].address, programdata_acc, sizeof(fd_pubkey_t) ) ) {
          meta = txn_out->accounts.account[j].meta;
          break;
        }
      }
      if( FD_UNLIKELY( meta==NULL ) ) {
        continue;
      }

      FD_TEST( runtime->accounts.executable_cnt < MAX_TX_ACCOUNT_LOCKS );
      fd_accdb_ro_t * ro = &runtime->accounts.executable[ runtime->accounts.executable_cnt ];
      fd_accdb_ro_init_nodb( ro, programdata_acc, meta );
      runtime->accounts.executable_cnt++;
    } else if( FD_UNLIKELY( !memcmp( meta->owner, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) ||
                            !memcmp( meta->owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
      meta = txn_out->accounts.account[i].meta;
    } else if( !memcmp( meta->owner, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {
      int err;
      fd_loader_v4_state_t const * state = fd_loader_v4_get_state( fd_account_data( meta ), meta->dlen, &err );
      if( FD_UNLIKELY( err ) ) {
        continue;
      }

      /* The program must be deployed or finalized. */
      if( FD_UNLIKELY( fd_loader_v4_status_is_retracted( state ) ) ) {
        continue;
      }
      meta = txn_out->accounts.account[i].meta;
    }

    FD_SPAD_FRAME_BEGIN( runner->spad ) {
      uchar * scratch = fd_spad_alloc( runner->spad, FD_FUNK_REC_ALIGN, meta->dlen );
      fd_progcache_inject_rec( runner->progcache_admin,
                                &txn_out->accounts.keys[i],
                                meta,
                                features,
                                fd_bank_slot_get( runner->bank ),
                                scratch,
                                meta->dlen );
    } FD_SPAD_FRAME_END;
  }

  fd_funk_txn_xid_t exec_xid[1] = {{ .ul={ fd_bank_slot_get( runner->bank ), runner->bank->data->idx } }};
  fd_accdb_attach_child        ( runner->accdb_admin,     xid, exec_xid );
  fd_progcache_txn_attach_child( runner->progcache_admin, xid, exec_xid );

  /* Load instruction accounts */

  if( FD_UNLIKELY( test_ctx->instr_accounts_count > FD_INSTR_ACCT_MAX ) ) {
    FD_LOG_NOTICE(( "too many instruction accounts" ));
    return 0;
  }

  /* Restore sysvar cache */
  fd_sysvar_cache_t * sysvar_cache = fd_bank_sysvar_cache_modify( runner->bank );
  ctx->sysvar_cache = sysvar_cache;
  for( ulong i=0UL; i<txn_out->accounts.cnt; i++ ) {
    fd_sysvar_cache_restore_from_ref( sysvar_cache, txn_out->accounts.account[i].ro );
  }

  ctx->runtime = runtime;

  fd_sol_sysvar_clock_t clock_[1];
  fd_sol_sysvar_clock_t * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, clock_ );
  FD_TEST( clock );
  fd_bank_slot_set( runner->bank, clock->slot );

  fd_epoch_schedule_t epoch_schedule_[1];
  fd_epoch_schedule_t * epoch_schedule = fd_sysvar_cache_epoch_schedule_read( ctx->sysvar_cache, epoch_schedule_ );
  if( FD_UNLIKELY( !epoch_schedule ) ) { return 0; }
  fd_bank_epoch_schedule_set( runner->bank, *epoch_schedule );

  fd_rent_t rent_[1];
  fd_rent_t * rent = fd_sysvar_cache_rent_read( ctx->sysvar_cache, rent_ );
  FD_TEST( rent );
  fd_bank_rent_set( runner->bank, *rent );

  fd_block_block_hash_entry_t const * deq = fd_sysvar_cache_recent_hashes_join_const( ctx->sysvar_cache );
  FD_TEST( deq );
  if( !deq_fd_block_block_hash_entry_t_empty( deq ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_tail_const( deq );
    if( last ) {
      fd_blockhashes_t * blockhashes = fd_bank_block_hash_queue_modify( runner->bank );
      fd_blockhashes_pop_new( blockhashes );
      fd_blockhash_info_t * info = fd_blockhashes_push_new( blockhashes, &last->blockhash );
      info->fee_calculator = last->fee_calculator;

      fd_bank_rbh_lamports_per_sig_set( runner->bank, last->fee_calculator.lamports_per_signature );
    }
  }
  fd_sysvar_cache_recent_hashes_leave_const( ctx->sysvar_cache, deq );

  uchar acc_idx_seen[ FD_TXN_ACCT_ADDR_MAX ] = {0};
  for( ulong j=0UL; j < test_ctx->instr_accounts_count; j++ ) {
    uint index = test_ctx->instr_accounts[j].index;
    if( index >= test_ctx->accounts_count ) {
      FD_LOG_NOTICE( ( "instruction account index out of range (%u > %u)", index, test_ctx->instr_accounts_count ) );
      return 0;
    }

    /* Setup instruction accounts */
    fd_instr_info_setup_instr_account( info,
                                       acc_idx_seen,
                                       (ushort)index,
                                       (ushort)j,
                                       (ushort)j,
                                       test_ctx->instr_accounts[j].is_writable,
                                       test_ctx->instr_accounts[j].is_signer );
  }
  info->acct_cnt = (ushort)test_ctx->instr_accounts_count;

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

  ctx->instr              = info;
  ctx->runtime->progcache = runner->progcache;
  ctx->runtime->accdb     = runner->accdb;

  runtime->log.enable_log_collector = 0;

  fd_log_collector_init( ctx->runtime->log.log_collector, 1 );
  fd_base58_encode_32( txn_out->accounts.keys[ ctx->instr->program_id ].uc, NULL, ctx->program_id_base58 );

  return 1;
}

void
fd_solfuzz_pb_instr_ctx_destroy( fd_solfuzz_runner_t * runner,
                                 fd_exec_instr_ctx_t * ctx ) {
  if( !ctx ) return;
  fd_accdb_v1_clear( runner->accdb_admin );
  fd_progcache_clear( runner->progcache_admin );

  /* In order to check for leaks in the workspace, we need to compact the
     allocators. Without doing this, empty superblocks may be retained
     by the fd_alloc instance, which mean we cannot check for leaks. */
  fd_alloc_compact( fd_accdb_admin_v1_funk( runner->accdb_admin )->alloc );
  fd_alloc_compact( runner->progcache_admin->funk->alloc );
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
  ulong modified_acct_cnt = ctx->txn_out->accounts.cnt;

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

  for( ulong j=0UL; j < ctx->txn_out->accounts.cnt; j++ ) {
    fd_pubkey_t * acc_key = &ctx->txn_out->accounts.keys[j];
    fd_account_meta_t * acc = ctx->txn_out->accounts.account[j].meta;
    if( !acc ) {
      continue;
    }

    ulong modified_idx = effects->modified_accounts_count;
    assert( modified_idx < modified_acct_cnt );

    fd_exec_test_acct_state_t * out_acct = &effects->modified_accounts[ modified_idx ];
    memset( out_acct, 0, sizeof(fd_exec_test_acct_state_t) );
    /* Copy over account content */

    memcpy( out_acct->address, acc_key, sizeof(fd_pubkey_t) );
    out_acct->lamports = acc->lamports;
    if( acc->dlen>0UL ) {
      out_acct->data =
        FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                    PB_BYTES_ARRAY_T_ALLOCSIZE( acc->dlen ) );
      if( FD_UNLIKELY( _l > output_end ) ) {
        fd_solfuzz_pb_instr_ctx_destroy( runner, ctx );
        return 0UL;
      }
      out_acct->data->size = (pb_size_t)acc->dlen;
      fd_memcpy( out_acct->data->bytes, fd_account_data( acc ), acc->dlen );
    }

    out_acct->executable = acc->executable;
    memcpy( out_acct->owner, acc->owner, sizeof(fd_pubkey_t) );

    effects->modified_accounts_count++;
  }

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
