
#undef FD_SPAD_USE_HANDHOLDING
#define FD_SPAD_USE_HANDHOLDING 1

#include "fd_instr_harness.h"
#include "../../fd_system_ids.h"
#include "../../sysvar/fd_sysvar_clock.h"
#include "../../sysvar/fd_sysvar_epoch_schedule.h"
#include "../../sysvar/fd_sysvar_recent_hashes.h"
#include "../../sysvar/fd_sysvar_last_restart_slot.h"
#include "../../sysvar/fd_sysvar_rent.h"

int
fd_runtime_fuzz_instr_ctx_create( fd_runtime_fuzz_runner_t *           runner,
                                  fd_exec_instr_ctx_t *                ctx,
                                  fd_exec_test_instr_context_t const * test_ctx,
                                  bool                                 is_syscall ) {

  memset( ctx, 0, sizeof(fd_exec_instr_ctx_t) );

  fd_funk_t * funk = runner->funk;

  /* Generate unique ID for funk txn */

  fd_funk_txn_xid_t xid[1] = {0};
  xid[0] = fd_funk_generate_xid();

  /* Create temporary funk transaction and txn / slot / epoch contexts */

  fd_funk_txn_start_write( funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( funk, NULL, xid, 1 );
  fd_funk_txn_end_write( funk );

  /* Allocate contexts */
  uchar *               slot_ctx_mem  = fd_spad_alloc( runner->spad,FD_EXEC_SLOT_CTX_ALIGN,  FD_EXEC_SLOT_CTX_FOOTPRINT  );
  uchar *               txn_ctx_mem   = fd_spad_alloc( runner->spad,FD_EXEC_TXN_CTX_ALIGN,   FD_EXEC_TXN_CTX_FOOTPRINT   );

  fd_exec_slot_ctx_t *  slot_ctx      = fd_exec_slot_ctx_join ( fd_exec_slot_ctx_new ( slot_ctx_mem ) );
  fd_exec_txn_ctx_t *   txn_ctx       = fd_exec_txn_ctx_join  ( fd_exec_txn_ctx_new  ( txn_ctx_mem ), runner->spad, fd_wksp_containing( runner->spad ) );

  assert( slot_ctx  );

  ctx->txn_ctx = txn_ctx;

  /* Set up slot context */

  slot_ctx->funk_txn     = funk_txn;
  slot_ctx->funk         = funk;

  /* Bank manager */

  slot_ctx->bank = runner->bank;
  fd_bank_clear_bank( slot_ctx->bank );

  fd_features_t * features = fd_bank_features_modify( slot_ctx->bank );
  fd_exec_test_feature_set_t const * feature_set = &test_ctx->epoch_context.features;
  if( !fd_runtime_fuzz_restore_features( features, feature_set ) ) {
    return 0;
  }

  /* Set up epoch context. Defaults obtained from GenesisConfig::Default() */

  fd_rent_t * rent_bm = fd_bank_rent_modify( slot_ctx->bank );
  rent_bm->lamports_per_uint8_year = 3480;
  rent_bm->exemption_threshold = 2;
  rent_bm->burn_percent = 50;

  /* Blockhash queue init */

  fd_block_hash_queue_global_t * block_hash_queue = fd_bank_block_hash_queue_modify( slot_ctx->bank );

  uchar * last_hash_mem = (uchar *)fd_ulong_align_up( (ulong)block_hash_queue + sizeof(fd_block_hash_queue_global_t), alignof(fd_hash_t) );
  uchar * ages_pool_mem = (uchar *)fd_ulong_align_up( (ulong)last_hash_mem + sizeof(fd_hash_t), fd_hash_hash_age_pair_t_map_align() );
  fd_hash_hash_age_pair_t_mapnode_t * ages_pool = fd_hash_hash_age_pair_t_map_join( fd_hash_hash_age_pair_t_map_new( ages_pool_mem, 400 ) );

  block_hash_queue->max_age          = FD_BLOCKHASH_QUEUE_MAX_ENTRIES;
  block_hash_queue->ages_root_offset = 0UL;
  fd_block_hash_queue_ages_pool_update( block_hash_queue, ages_pool );
  block_hash_queue->last_hash_index  = 0UL;
  block_hash_queue->last_hash_offset = (ulong)last_hash_mem - (ulong)block_hash_queue;

  memset( last_hash_mem, 0, sizeof(fd_hash_t) );

  /* Set up txn context */

  fd_wksp_t * funk_wksp          = fd_funk_wksp( funk );
  fd_wksp_t * runtime_wksp       = fd_wksp_containing( slot_ctx );
  ulong       funk_txn_gaddr     = fd_wksp_gaddr( funk_wksp, funk_txn );
  ulong       funk_gaddr         = fd_wksp_gaddr( funk_wksp, funk->shmem );

  /* Set up mock txn descriptor */
  fd_txn_t * txn_descriptor           = fd_spad_alloc( runner->spad, fd_txn_align(), fd_txn_footprint( 1UL, 0UL ) );
  txn_descriptor->transaction_version = FD_TXN_V0;
  txn_descriptor->acct_addr_cnt       = (ushort)test_ctx->accounts_count;

  fd_exec_txn_ctx_from_exec_slot_ctx( slot_ctx,
                                      txn_ctx,
                                      funk_wksp,
                                      runtime_wksp,
                                      funk_txn_gaddr,
                                      funk_gaddr,
                                      NULL );
  fd_exec_txn_ctx_setup_basic( txn_ctx );

  txn_ctx->txn_descriptor     = txn_descriptor;
  txn_ctx->compute_unit_limit = test_ctx->cu_avail;
  txn_ctx->compute_meter      = test_ctx->cu_avail;
  txn_ctx->vote_accounts_pool = NULL;
  txn_ctx->spad               = runner->spad;
  txn_ctx->instr_info_cnt     = 1UL;

  /* Set up instruction context */

  fd_instr_info_t * info = fd_spad_alloc( runner->spad, 8UL, sizeof(fd_instr_info_t) );
  assert( info );
  memset( info, 0, sizeof(fd_instr_info_t) );

  if( test_ctx->data ) {
    info->data_sz = (ushort)test_ctx->data->size;
    info->data    = test_ctx->data->bytes;
  }

  /* Prepare borrowed account table (correctly handles aliasing) */

  if( FD_UNLIKELY( test_ctx->accounts_count > MAX_TX_ACCOUNT_LOCKS ) ) {
    FD_LOG_NOTICE(( "too many accounts" ));
    return 0;
  }

  /* Load accounts into database */

  fd_txn_account_t * accts = txn_ctx->accounts;
  fd_memset( accts, 0, test_ctx->accounts_count * sizeof(fd_txn_account_t) );
  txn_ctx->accounts_cnt = test_ctx->accounts_count;

  int has_program_id = 0;

  for( ulong j=0UL; j < test_ctx->accounts_count; j++ ) {
    memcpy(  &(txn_ctx->account_keys[j]), test_ctx->accounts[j].address, sizeof(fd_pubkey_t) );
    if( !fd_runtime_fuzz_load_account( &accts[j], funk, funk_txn, &test_ctx->accounts[j], 0 ) ) {
      return 0;
    }

    fd_txn_account_t * acc = &accts[j];
    if( acc->vt->get_meta( acc ) ) {
      uchar * data = fd_spad_alloc( txn_ctx->spad, FD_ACCOUNT_REC_ALIGN, FD_ACC_TOT_SZ_MAX );
      ulong   dlen = acc->vt->get_data_len( acc );
      fd_memcpy( data, acc->vt->get_meta( acc ), sizeof(fd_account_meta_t)+dlen );
      fd_txn_account_init_from_meta_and_data_readonly( acc,
                                                       (fd_account_meta_t const *)data,
                                                       data + sizeof(fd_account_meta_t) );
    }

    if( !memcmp( accts[j].pubkey, test_ctx->program_id, sizeof(fd_pubkey_t) ) ) {
      has_program_id = 1;
      info->program_id = (uchar)txn_ctx->accounts_cnt;
    }

    /* Since the instructions sysvar is set as mutable at the txn level, we need to make it mutable here as well. */
    if( !memcmp( accts[j].pubkey, &fd_sysvar_instructions_id, sizeof(fd_pubkey_t) ) ) {
      acc->vt->set_mutable( acc );
    }
  }

  /* If the program id is not in the set of accounts it must be added to the set of accounts. */
  if( FD_UNLIKELY( !has_program_id ) ) {
    fd_txn_account_t * program_acc = &accts[ test_ctx->accounts_count ];
    fd_pubkey_t *      program_key = &txn_ctx->account_keys[ txn_ctx->accounts_cnt ];
    fd_txn_account_init( program_acc );
    memcpy( program_key, test_ctx->program_id, sizeof(fd_pubkey_t) );
    memcpy( program_acc->pubkey, test_ctx->program_id, sizeof(fd_pubkey_t) );
    fd_account_meta_t * meta = fd_spad_alloc( txn_ctx->spad, alignof(fd_account_meta_t), sizeof(fd_account_meta_t) );
    fd_account_meta_init( meta );
    program_acc->vt->set_meta_mutable( program_acc, meta );
    info->program_id = (uchar)txn_ctx->accounts_cnt;
    txn_ctx->accounts_cnt++;
  }

  /* Load in executable accounts */
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    fd_txn_account_t * acc = &accts[i];
    if ( !fd_executor_pubkey_is_bpf_loader( acc->vt->get_owner( acc ) ) ) {
      continue;
    }

    fd_account_meta_t const * meta = acc->vt->get_meta( acc );
    if (meta == NULL) {
      fd_txn_account_setup_sentinel_meta_readonly( acc, txn_ctx->spad, txn_ctx->spad_wksp );
      continue;
    }

    if( FD_UNLIKELY( 0 == memcmp(meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t)) ) ) {
      int err = 0;
      fd_bpf_upgradeable_loader_state_t * program_loader_state = read_bpf_upgradeable_loader_state_for_program( txn_ctx,
                                                                                                                (ushort)i,
                                                                                                                &err );

      if( FD_UNLIKELY( !program_loader_state ) ) {
        continue;
      }

      if( !fd_bpf_upgradeable_loader_state_is_program( program_loader_state ) ) {
        continue;
      }

      fd_pubkey_t * programdata_acc = &program_loader_state->inner.program.programdata_address;
      if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( &txn_ctx->executable_accounts[txn_ctx->executable_cnt],
                                                               programdata_acc,
                                                               txn_ctx->funk,
                                                               txn_ctx->funk_txn ) ) ) {
        continue;
      }
      txn_ctx->executable_cnt++;
    }
  }

  /* Add accounts to bpf program cache */
  fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, runner->spad );

  /* Fill missing sysvar cache values with defaults */
  /* We create mock accounts for each of the sysvars and hardcode the data fields before loading it into the account manager */
  /* We use Agave sysvar defaults for data field values */

  /* Clock */
  // https://github.com/firedancer-io/solfuzz-agave/blob/agave-v2.0/src/lib.rs#L466-L474
  fd_sol_sysvar_clock_t const * clock = fd_sysvar_clock_read( funk, funk_txn, runner->spad );
  if( !clock ) {
    fd_sol_sysvar_clock_t sysvar_clock = {
                                          .slot                  = 10UL,
                                          .epoch_start_timestamp = 0L,
                                          .epoch                 = 0UL,
                                          .leader_schedule_epoch = 0UL,
                                          .unix_timestamp        = 0L
                                        };
    fd_sysvar_clock_write( slot_ctx->bank, slot_ctx->funk, slot_ctx->funk_txn, &sysvar_clock );
  }

  /* Epoch schedule */
  // https://github.com/firedancer-io/solfuzz-agave/blob/agave-v2.0/src/lib.rs#L476-L483
  fd_epoch_schedule_t const * epoch_schedule = fd_sysvar_epoch_schedule_read( funk, funk_txn, runner->spad );
  if( !epoch_schedule ) {
    fd_epoch_schedule_t sysvar_epoch_schedule = {
                                                  .slots_per_epoch             = 432000UL,
                                                  .leader_schedule_slot_offset = 432000UL,
                                                  .warmup                      = 1,
                                                  .first_normal_epoch          = 14UL,
                                                  .first_normal_slot           = 524256UL
                                                };
    fd_sysvar_epoch_schedule_write( slot_ctx, &sysvar_epoch_schedule );
  }

  /* Rent */
  // https://github.com/firedancer-io/solfuzz-agave/blob/agave-v2.0/src/lib.rs#L487-L500
  fd_rent_t const * rent = fd_sysvar_rent_read( funk, funk_txn, runner->spad );
  if( !rent ) {
    fd_rent_t sysvar_rent = {
                              .lamports_per_uint8_year = 3480UL,
                              .exemption_threshold     = 2.0,
                              .burn_percent            = 50
                            };
    fd_sysvar_rent_write( slot_ctx, &sysvar_rent );
  }

  fd_sol_sysvar_last_restart_slot_t const * last_restart_slot = fd_sysvar_last_restart_slot_read( funk, funk_txn, runner->spad );
  if( !last_restart_slot ) {

    fd_sol_sysvar_last_restart_slot_t restart = { .slot = 5000UL };

    fd_sysvar_set( slot_ctx->bank,
                   slot_ctx->funk,
                   slot_ctx->funk_txn,
                   &fd_sysvar_owner_id,
                   &fd_sysvar_last_restart_slot_id,
                   &restart.slot,
                   sizeof(ulong),
                   slot_ctx->slot );

  }

  /* Set slot bank variables */
  clock = fd_sysvar_clock_read( funk, funk_txn, runner->spad );

  slot_ctx->slot = clock->slot;
  slot_ctx->bank->slot = clock->slot;

  /* Handle undefined behavior if sysvars are malicious (!!!) */

  /* Override epoch bank rent setting */
  rent = fd_sysvar_rent_read( funk, funk_txn, runner->spad );
  if( rent ) {
    fd_bank_rent_set( slot_ctx->bank, *rent );
  }

  /* Override most recent blockhash if given */
  fd_recent_block_hashes_global_t const * rbh_global = fd_sysvar_recent_hashes_read( funk, funk_txn, runner->spad );
  fd_recent_block_hashes_t rbh[1];
  if( rbh_global ) {
    rbh->hashes = deq_fd_block_block_hash_entry_t_join( (uchar*)rbh_global + rbh_global->hashes_offset );
  }

  if( rbh_global && !deq_fd_block_block_hash_entry_t_empty( rbh->hashes ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_tail_const( rbh->hashes );
    if( last ) {
      block_hash_queue = (fd_block_hash_queue_global_t *)&slot_ctx->bank->block_hash_queue[0];
      fd_hash_t * last_hash = fd_block_hash_queue_last_hash_join( block_hash_queue );
      fd_memcpy( last_hash, &last->blockhash, sizeof(fd_hash_t) );

      fd_bank_lamports_per_signature_set( slot_ctx->bank, last->fee_calculator.lamports_per_signature );

      fd_bank_prev_lamports_per_signature_set( slot_ctx->bank, last->fee_calculator.lamports_per_signature );
    }
  }

  /* Load instruction accounts */

  if( FD_UNLIKELY( test_ctx->instr_accounts_count > MAX_TX_ACCOUNT_LOCKS ) ) {
    FD_LOG_NOTICE(( "too many instruction accounts" ));
    return 0;
  }

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
      acc->vt->set_mutable( acc );
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

  /* Refresh the setup from the updated slot and epoch ctx. */
  fd_exec_txn_ctx_from_exec_slot_ctx( slot_ctx,
                                      txn_ctx,
                                      funk_wksp,
                                      runtime_wksp,
                                      funk_txn_gaddr,
                                      funk_gaddr,
                                      NULL );

  fd_log_collector_init( &ctx->txn_ctx->log_collector, 1 );
  fd_base58_encode_32( txn_ctx->account_keys[ ctx->instr->program_id ].uc, NULL, ctx->program_id_base58 );

  return 1;
}



void
fd_runtime_fuzz_instr_ctx_destroy( fd_runtime_fuzz_runner_t * runner,
                                   fd_exec_instr_ctx_t *      ctx ) {
  if( !ctx ) return;
  fd_funk_txn_t * funk_txn = ctx->txn_ctx->funk_txn;

  fd_funk_txn_cancel( runner->funk, funk_txn, 1 );
}


ulong
fd_runtime_fuzz_instr_run( fd_runtime_fuzz_runner_t * runner,
                           void const *               input_,
                           void **                    output_,
                           void *                     output_buf,
                           ulong                      output_bufsz ) {
  fd_exec_test_instr_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_instr_effects_t **      output = fd_type_pun( output_ );

  /* Convert the Protobuf inputs to a fd_exec context */
  fd_exec_instr_ctx_t ctx[1];
  if( !fd_runtime_fuzz_instr_ctx_create( runner, ctx, input, false ) ) {
    fd_runtime_fuzz_instr_ctx_destroy( runner, ctx );
    return 0UL;
  }

  fd_instr_info_t * instr = (fd_instr_info_t *) ctx->instr;

  /* Execute the test */
  int exec_result = fd_execute_instr(ctx->txn_ctx, instr);

  /* Allocate space to capture outputs */

  ulong output_end = (ulong)output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );

  fd_exec_test_instr_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_instr_effects_t),
                                sizeof (fd_exec_test_instr_effects_t) );
  if( FD_UNLIKELY( _l > output_end ) ) {
    fd_runtime_fuzz_instr_ctx_destroy( runner, ctx );
    return 0UL;
  }
  fd_memset( effects, 0, sizeof(fd_exec_test_instr_effects_t) );

  /* Capture error code */

  effects->result   = -exec_result;
  effects->cu_avail = ctx->txn_ctx->compute_meter;

  if( exec_result == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
    effects->custom_err     = ctx->txn_ctx->custom_err;
  }

  /* Allocate space for captured accounts */
  ulong modified_acct_cnt = ctx->txn_ctx->accounts_cnt;

  fd_exec_test_acct_state_t * modified_accts =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_acct_state_t),
                                sizeof (fd_exec_test_acct_state_t) * modified_acct_cnt );
  if( FD_UNLIKELY( _l > output_end ) ) {
    fd_runtime_fuzz_instr_ctx_destroy( runner, ctx );
    return 0;
  }
  effects->modified_accounts       = modified_accts;
  effects->modified_accounts_count = 0UL;

  /* Capture borrowed accounts */

  for( ulong j=0UL; j < ctx->txn_ctx->accounts_cnt; j++ ) {
    fd_txn_account_t * acc = &ctx->txn_ctx->accounts[j];
    if( !acc->vt->get_meta( acc ) ) {
      continue;
    }

    ulong modified_idx = effects->modified_accounts_count;
    assert( modified_idx < modified_acct_cnt );

    fd_exec_test_acct_state_t * out_acct = &effects->modified_accounts[ modified_idx ];
    memset( out_acct, 0, sizeof(fd_exec_test_acct_state_t) );
    /* Copy over account content */

    memcpy( out_acct->address, acc->pubkey, sizeof(fd_pubkey_t) );
    out_acct->lamports = acc->vt->get_lamports( acc );
    if( acc->vt->get_data_len( acc )>0UL ) {
      out_acct->data =
        FD_SCRATCH_ALLOC_APPEND( l, alignof(pb_bytes_array_t),
                                    PB_BYTES_ARRAY_T_ALLOCSIZE( acc->vt->get_data_len( acc ) ) );
      if( FD_UNLIKELY( _l > output_end ) ) {
        fd_runtime_fuzz_instr_ctx_destroy( runner, ctx );
        return 0UL;
      }
      out_acct->data->size = (pb_size_t)acc->vt->get_data_len( acc );
      fd_memcpy( out_acct->data->bytes, acc->vt->get_data( acc ), acc->vt->get_data_len( acc ) );
    }

    out_acct->executable     = acc->vt->is_executable( acc );
    out_acct->rent_epoch     = acc->vt->get_rent_epoch( acc );
    memcpy( out_acct->owner, acc->vt->get_owner( acc ), sizeof(fd_pubkey_t) );

    effects->modified_accounts_count++;
  }

  /* Capture return data */
  fd_txn_return_data_t * return_data = &ctx->txn_ctx->return_data;
  if( return_data->len>0UL ) {
    effects->return_data = FD_SCRATCH_ALLOC_APPEND(l, alignof(pb_bytes_array_t),
                                PB_BYTES_ARRAY_T_ALLOCSIZE( return_data->len ) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      fd_runtime_fuzz_instr_ctx_destroy( runner, ctx );
      return 0UL;
    }
    effects->return_data->size = (pb_size_t)return_data->len;
    fd_memcpy( effects->return_data->bytes, return_data->data, return_data->len );
  }

  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  fd_runtime_fuzz_instr_ctx_destroy( runner, ctx );

  *output = effects;
  return actual_end - (ulong)output_buf;

}
