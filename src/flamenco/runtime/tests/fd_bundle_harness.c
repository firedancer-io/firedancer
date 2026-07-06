#include "fd_bundle_harness.h"
#include "fd_solfuzz_private.h"
#include "fd_txn_harness.h"
#include "fd_dump_pb.h"
#include "generated/bundle.pb.h"
#include "../fd_cost_tracker.h"
#include "../fd_slot_params.h"
#include "../fd_runtime.h"
#include "../sysvar/fd_sysvar_cache.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../../progcache/fd_progcache_admin.h"
#include "../../log_collector/fd_log_collector.h"  /* IWYU pragma: keep */
#include "../../stakes/fd_stakes.h"

static void
fd_solfuzz_bundle_ctx_destroy( fd_solfuzz_runner_t * runner ) {
  if( runner->bank->new_votes_fork_id!=USHORT_MAX ) {
    fd_new_votes_evict_fork( fd_bank_new_votes( runner->bank ), runner->bank->new_votes_fork_id );
    runner->bank->new_votes_fork_id = USHORT_MAX;
  }
  fd_banks_stake_delegations_evict_bank_fork( runner->banks, runner->bank );

  fd_progcache_reset( runner->progcache->join );

  /* Purge the fork attached in ctx_create so the accdb fork pool slot
     is released back for reuse.  Without this, repeated harness
     invocations (e.g. under a fuzzer) exhaust max_live_slots. */
  fd_accdb_purge( runner->accdb, runner->bank->accdb_fork_id );
  int charge_busy = 0;
  fd_accdb_background( runner->accdb, &charge_busy );

  /* Keep the runner reusable across many bundle inputs. */
  fd_alloc_compact( runner->progcache->join->alloc );
}

static fd_txn_p_t *
fd_solfuzz_pb_bundle_ctx_create( fd_solfuzz_runner_t *                 runner,
                                 fd_exec_test_bundle_context_t const * test_ctx,
                                 ulong *                               out_txn_cnt ) {
  ulong txn_cnt = (ulong)test_ctx->txns_count;
  FD_TEST( txn_cnt<=FD_PACK_MAX_TXN_PER_BUNDLE );

  fd_accdb_t * accdb = runner->accdb;

  ulong slot = fd_solfuzz_pb_get_slot( test_ctx->account_shared_data, test_ctx->account_shared_data_count );

  /* Initialize bank from input txn bank */
  fd_banks_clear_bank( runner->banks, runner->bank, 2048UL );

  runner->bank->f.slot = slot;
  runner->bank->bank_seq = runner->bank->idx;

  runner->bank->progcache_fork_id = fd_progcache_attach_child( runner->progcache->join, fd_progcache_fork_id_initial() );
  runner->bank->accdb_fork_id     = fd_accdb_attach_child( accdb, runner->root_fork_id );

  FD_TEST( test_ctx->has_bank );
  fd_exec_test_txn_bank_t const * txn_bank = &test_ctx->bank;

  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( runner->banks );
  runner->bank->stake_delegations_fork_id = fd_stake_delegations_new_fork( stake_delegations );
  runner->bank->new_votes_fork_id = fd_new_votes_new_fork( fd_bank_new_votes( runner->bank ) );

  fd_solfuzz_pb_restore_blockhash_queue( runner->bank, txn_bank->blockhash_queue, txn_bank->blockhash_queue_count );
  runner->bank->f.rbh_lamports_per_sig = txn_bank->rbh_lamports_per_signature;

  FD_TEST( txn_bank->has_fee_rate_governor );
  fd_solfuzz_pb_restore_fee_rate_governor( runner->bank, &txn_bank->fee_rate_governor );

  runner->bank->f.parent_slot       = slot-1UL;
  runner->bank->f.total_epoch_stake = txn_bank->total_epoch_stake;

  FD_TEST( txn_bank->has_features );
  FD_TEST( fd_solfuzz_pb_restore_features( &runner->bank->f.features, &txn_bank->features ) );

  for( ulong i=0UL; i<test_ctx->account_shared_data_count; i++ ) {
    fd_solfuzz_pb_load_account( runner->runtime, accdb, runner->bank->accdb_fork_id, &test_ctx->account_shared_data[i], i );
  }

  runner->bank->f.ticks_per_slot             = 64;
  runner->bank->f.slot_params                = FD_SLOT_PARAMS_400MS;
  runner->bank->f.slot_params.slots_per_year = SECONDS_PER_YEAR * (1000000000.0 / (double)6250000) / (double)(runner->bank->f.ticks_per_slot);
  runner->bank->f.slot_params_default        = runner->bank->f.slot_params;

  fd_sysvar_cache_restore_fuzz( runner->bank, runner->accdb );

  FD_TEST( fd_sysvar_cache_epoch_schedule_read( &runner->bank->f.sysvar_cache, &runner->bank->f.epoch_schedule ) );
  runner->bank->f.epoch = fd_slot_to_epoch( &runner->bank->f.epoch_schedule, slot, NULL );

  FD_TEST( fd_sysvar_cache_rent_read( &runner->bank->f.sysvar_cache, &runner->bank->f.rent ) );

  /* Initialize cost tracker */
  fd_cost_tracker_t * cost_tracker = fd_bank_cost_tracker_modify( runner->bank );
  fd_cost_tracker_init( cost_tracker, &runner->bank->f.features, &runner->bank->f.slot_params, slot );

  fd_txn_p_t * txns = fd_spad_alloc( runner->spad, alignof(fd_txn_p_t), txn_cnt*sizeof(fd_txn_p_t) );
  fd_memset( txns, 0, txn_cnt*sizeof(fd_txn_p_t) );

  for( ulong i=0UL; i<txn_cnt; i++ ) {
    ulong msg_sz = fd_solfuzz_pb_txn_serialize( txns[i].payload, &test_ctx->txns[i] );
    if( FD_UNLIKELY( msg_sz==ULONG_MAX ) ) return NULL;
    if( FD_UNLIKELY( !fd_txn_parse( txns[i].payload, msg_sz, TXN( &txns[i] ), NULL ) ) ) return NULL;
    txns[i].payload_sz = msg_sz;
  }

  *out_txn_cnt = txn_cnt;
  return txns;
}

static void
fd_solfuzz_bundle_mark_uncommittable( fd_txn_out_t * txn_outs,
                                      ulong          txn_cnt ) {
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    txn_outs[i].err.is_committable = 0;
  }
}

static int
fd_solfuzz_bundle_execute( fd_solfuzz_runner_t *                 runner,
                           fd_exec_test_bundle_context_t const * input,
                           int                                   is_bundle,
                           void *                                output_buf,
                           ulong                                 output_bufsz,
                           fd_exec_test_bundle_effects_t **      effects_out,
                           ulong *                               output_used ) {
  ulong txn_cnt = 0UL;
  fd_txn_p_t * txns = fd_solfuzz_pb_bundle_ctx_create( runner, input, &txn_cnt );
  if( FD_UNLIKELY( !txns ) ) {
    fd_solfuzz_bundle_ctx_destroy( runner );
    return 0;
  }

  FD_SCRATCH_ALLOC_INIT( l, output_buf );
  ulong output_end = (ulong)output_buf + output_bufsz;

  fd_exec_test_bundle_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_bundle_effects_t),
                                sizeof(fd_exec_test_bundle_effects_t) );
  if( FD_UNLIKELY( _l>output_end ) ) abort();
  fd_memset( effects, 0, sizeof(fd_exec_test_bundle_effects_t) );

  effects->txn_results_count = (pb_size_t)txn_cnt;
  effects->txn_results = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_txn_result_t),
                                                  txn_cnt*sizeof(fd_exec_test_txn_result_t) );
  if( FD_UNLIKELY( _l>output_end ) ) abort();
  fd_memset( effects->txn_results, 0, txn_cnt*sizeof(fd_exec_test_txn_result_t) );

  ulong update_max = txn_cnt*MAX_TX_ACCOUNT_LOCKS;
  effects->stake_deltas = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_stake_delta_t),
                                                   update_max*sizeof(fd_exec_test_stake_delta_t) );
  if( FD_UNLIKELY( _l>output_end ) ) abort();
  fd_memset( effects->stake_deltas, 0, update_max*sizeof(fd_exec_test_stake_delta_t) );
  effects->stake_deltas_count = 0UL;

  effects->vote_updates = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_vote_update_t),
                                                   update_max*sizeof(fd_exec_test_vote_update_t) );
  if( FD_UNLIKELY( _l>output_end ) ) abort();
  fd_memset( effects->vote_updates, 0, update_max*sizeof(fd_exec_test_vote_update_t) );
  effects->vote_updates_count = 0UL;

  effects->new_votes = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_new_vote_t),
                                                update_max*sizeof(fd_exec_test_new_vote_t) );
  if( FD_UNLIKELY( _l>output_end ) ) abort();
  fd_memset( effects->new_votes, 0, update_max*sizeof(fd_exec_test_new_vote_t) );
  effects->new_votes_count = 0UL;

  fd_runtime_t *       runtime      = runner->runtime;
  fd_txn_out_t *       txn_outs     = fd_spad_alloc( runner->spad, alignof(fd_txn_out_t), txn_cnt*sizeof(fd_txn_out_t) );
  fd_txn_in_t  *       txn_ins      = fd_spad_alloc( runner->spad, alignof(fd_txn_in_t),  txn_cnt*sizeof(fd_txn_in_t)  );
  fd_log_collector_t * logs         = fd_spad_alloc( runner->spad, alignof(fd_log_collector_t), txn_cnt*sizeof(fd_log_collector_t) );
  ulong                ran_cnt      = 0UL;
  int                  saw_exec_err = 0;

  /* Set up every txn_in up-front.  For bundles, acquire all of the
     bundle's accounts in a single acquire_a/acquire_b pair before any
     txn executes; each txn then binds to this shared pool, which is
     released once after the bundle is committed or cancelled. */
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    txn_ins[i]                     = (fd_txn_in_t){0};
    txn_ins[i].txn                 = &txns[i];
    txn_ins[i].bundle.is_bundle    = is_bundle;
    txn_ins[i].bundle.prev_txn_cnt = is_bundle ? i : 0UL;
    for( ulong j=0UL; is_bundle && j<i; j++ ) txn_ins[i].bundle.prev_txn_outs[j] = &txn_outs[j];
  }
  /* Mirror fd_execle_tile: a failed bundle prepare acquires nothing, so
     every txn fails and fd_runtime_fini_bundle must be skipped.  An
     empty bundle likewise acquires nothing and must skip fini. */
  int bundle_prep_ok = 1;
  if( is_bundle ) {
    runtime->accdb = runner->accdb;
    if( FD_LIKELY( txn_cnt ) ) {
      int prepare_err = fd_runtime_prepare_bundle_accounts( runtime, runner->bank, txn_ins, txn_outs, txn_cnt );
      if( FD_UNLIKELY( prepare_err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
        bundle_prep_ok = 0;
        saw_exec_err   = 1;
      }
    }
  }

  for( ulong i=0UL; bundle_prep_ok && i<txn_cnt; i++ ) {
    fd_txn_in_t * txn_in = &txn_ins[i];

    int exec_res = 0;
    runtime->log.log_collector = &logs[i];
    fd_solfuzz_txn_ctx_exec( runner, runtime, txn_in, &exec_res, &txn_outs[i], 1 );
    ran_cnt = i+1UL;

    if( exec_res!=FD_RUNTIME_EXECUTE_SUCCESS ) {
      saw_exec_err = 1;
      if( is_bundle ) {
        fd_solfuzz_bundle_mark_uncommittable( txn_outs, ran_cnt );
      } else {
        txn_outs[i].err.is_committable = 0;
        fd_runtime_cancel_txn( runtime, &txn_outs[i] );
      }
      break;
    }

    fd_exec_test_txn_result_t * txn_result = NULL;
    ulong txn_result_sz = create_txn_result_protobuf_from_txn(
        &txn_result,
        (void *)_l,
        output_end - _l,
        txn_in,
        &txn_outs[i],
        exec_res );
    FD_TEST( txn_result_sz );
    FD_TEST( txn_result );
    effects->txn_results[i] = *txn_result;
    _l += txn_result_sz;

    for( ulong j=0UL; j<txn_outs[i].accounts.cnt; j++ ) {
      if( txn_outs[i].accounts.stake_update[j] ) {
        fd_exec_test_stake_delta_t * stake_delta = &effects->stake_deltas[effects->stake_deltas_count++];
        fd_memcpy( stake_delta->address, &txn_outs[i].accounts.keys[j], sizeof(fd_pubkey_t) );
        stake_delta->delta = 0UL;

        fd_stake_state_t const * stake_state = fd_stakes_get_state( txn_outs[i].accounts.account[j] );
        if( stake_state && stake_state->stake_type==FD_STAKE_STATE_STAKE ) {
          stake_delta->delta = stake_state->stake.stake.delegation.stake;
        }
      }

      if( txn_outs[i].accounts.vote_update[j] ) {
        fd_vote_block_timestamp_t last_vote;
        if( !fd_vote_account_last_timestamp( txn_outs[i].accounts.account[j]->data,
                                             txn_outs[i].accounts.account[j]->data_len,
                                             &last_vote ) ) {
          fd_exec_test_vote_update_t * vote_update = &effects->vote_updates[effects->vote_updates_count++];
          fd_memcpy( vote_update->address, &txn_outs[i].accounts.keys[j], sizeof(fd_pubkey_t) );
          vote_update->last_vote_slot      = last_vote.slot;
          vote_update->last_vote_timestamp = (ulong)last_vote.timestamp;
        }
      }
    }

    if( !is_bundle ) fd_runtime_commit_txn( runtime, runner->bank, &txn_outs[i] );
  }

  if( is_bundle && !saw_exec_err ) {
    for( ulong i=0UL; i<txn_cnt; i++ ) {
      fd_runtime_commit_txn( runtime, runner->bank, &txn_outs[i] );
    }
  }

  /* Release the bundle's shared account pool exactly once now that all of
     its txns have been committed or cancelled. */
  if( is_bundle && bundle_prep_ok && txn_cnt ) fd_runtime_fini_bundle( runtime );

  effects->has_error = saw_exec_err;
  if( saw_exec_err ) {
    effects->txn_results_count  = 0UL;
    effects->txn_results        = NULL;
    effects->stake_deltas_count = 0UL;
    effects->stake_deltas       = NULL;
    effects->vote_updates_count = 0UL;
    effects->vote_updates       = NULL;
    effects->new_votes_count    = 0UL;
    effects->new_votes          = NULL;
  } else {
    ushort fork_idx = runner->bank->new_votes_fork_id;
    uchar iter_mem[ FD_NEW_VOTES_ITER_FOOTPRINT ] __attribute__((aligned(FD_NEW_VOTES_ITER_ALIGN)));
    fd_new_votes_iter_t * iter = fd_new_votes_iter_init( fd_bank_new_votes( runner->bank ), &fork_idx, 1UL, iter_mem );
    for( ; !fd_new_votes_iter_done( iter ); fd_new_votes_iter_next( iter ) ) {
      FD_TEST( effects->new_votes_count<update_max );

      fd_exec_test_new_vote_t * new_vote = &effects->new_votes[effects->new_votes_count++];
      int is_tombstone;
      fd_pubkey_t const * pubkey = fd_new_votes_iter_ele( iter, &is_tombstone );
      new_vote->is_tombstone = !!is_tombstone;
      fd_memcpy( new_vote->address, pubkey, sizeof(fd_pubkey_t) );
    }
    fd_new_votes_iter_fini( iter );
  }

  *effects_out = effects;
  *output_used = FD_SCRATCH_ALLOC_FINI( l, 1UL ) - (ulong)output_buf;

  fd_solfuzz_bundle_ctx_destroy( runner );
  return 1;
}

static void
fd_solfuzz_bundle_assert_same_success( fd_solfuzz_runner_t *          runner,
                                       fd_exec_test_bundle_effects_t * regular,
                                       fd_exec_test_bundle_effects_t * bundle ) {
  ulong   buf_sz      = 100000000UL;
  uchar * regular_buf = fd_spad_alloc( runner->spad, 1UL, buf_sz );
  uchar * bundle_buf  = fd_spad_alloc( runner->spad, 1UL, buf_sz );

  ulong regular_sz = buf_sz;
  ulong bundle_sz  = buf_sz;
  FD_TEST( sol_compat_encode( regular_buf, &regular_sz, regular, &fd_exec_test_bundle_effects_t_msg ) );
  FD_TEST( sol_compat_encode( bundle_buf,  &bundle_sz,  bundle,  &fd_exec_test_bundle_effects_t_msg ) );

  if( FD_UNLIKELY( regular_sz!=bundle_sz || !fd_memeq( regular_buf, bundle_buf, regular_sz ) ) ) {
    FD_LOG_ERR(( "bundle transaction effects mismatch" ));
  }
}

ulong
fd_solfuzz_pb_bundle_run( fd_solfuzz_runner_t * runner,
                          void const *          input_,
                          void **               output_,
                          void *                output_buf,
                          ulong                 output_bufsz ) {
  fd_exec_test_bundle_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_bundle_effects_t **      output = fd_type_pun( output_ );

  FD_SPAD_FRAME_BEGIN( runner->spad ) {
    void * regular_buf = fd_spad_alloc( runner->spad, 1UL, output_bufsz );

    fd_exec_test_bundle_effects_t * regular_effects = NULL;
    fd_exec_test_bundle_effects_t * bundle_effects  = NULL;
    ulong                           regular_sz      = 0UL;
    ulong                           bundle_sz       = 0UL;

    int regular_ok = fd_solfuzz_bundle_execute( runner, input, 0, regular_buf, output_bufsz, &regular_effects, &regular_sz );
    int bundle_ok  = fd_solfuzz_bundle_execute( runner, input, 1, output_buf,  output_bufsz, &bundle_effects,  &bundle_sz  );

    if( FD_UNLIKELY( regular_ok!=bundle_ok ) ) {
      FD_LOG_ERR(( "bundle harness setup parity mismatch: regular_ok=%d bundle_ok=%d", regular_ok, bundle_ok ));
    }
    if( FD_UNLIKELY( !regular_ok ) ) {
      return 0UL;
    }

    (void)regular_sz;
    if( FD_UNLIKELY( regular_effects->has_error!=bundle_effects->has_error ) ) {
      FD_LOG_ERR(( "bundle success parity mismatch: regular_has_error=%d bundle_has_error=%d",
                   regular_effects->has_error, bundle_effects->has_error ));
    }

    if( !regular_effects->has_error ) {
      fd_solfuzz_bundle_assert_same_success( runner, regular_effects, bundle_effects );
    }

    *output = bundle_effects;
    return bundle_sz;
  } FD_SPAD_FRAME_END;
}
