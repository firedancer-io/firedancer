#include "fd_solfuzz_private.h"
#include "../fd_cost_tracker.h"
#include "fd_txn_harness.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"
#include "../fd_runtime_stack.h"
#include "../program/fd_stake_program.h"
#include "../program/vote/fd_vote_state_versioned.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_recent_hashes.h"
#include "../../accdb/fd_accdb_admin_v1.h"
#include "../../accdb/fd_accdb_impl_v1.h"
#include "../../accdb/fd_accdb_sync.h"
#include "../../log_collector/fd_log_collector.h"
#include "../../rewards/fd_rewards.h"
#include "../../types/fd_types.h"
#include "generated/block.pb.h"
#include "../../capture/fd_capture_ctx.h"
#include "../../capture/fd_solcap_writer.h"

/* Templatized leader schedule sort helper functions */
typedef struct {
  fd_pubkey_t pk;
  ulong       sched_pos; /* track original position in sched[] */
} pk_with_pos_t;

#define SORT_NAME        sort_pkpos
#define SORT_KEY_T       pk_with_pos_t
#define SORT_BEFORE(a,b) (memcmp(&(a).pk, &(b).pk, sizeof(fd_pubkey_t))<0)
#include "../../../util/tmpl/fd_sort.c"  /* generates templatized sort_pkpos_*() APIs */

/* Fixed leader schedule hash seed (consistent with solfuzz-agave) */
#define LEADER_SCHEDULE_HASH_SEED 0xDEADFACEUL

/* Registers a single vote account into the current votes cache.  The
   entry is derived from the current present account state.  This
   function also registers a vote timestamp for the vote account. */
static void
fd_solfuzz_block_register_vote_account( fd_accdb_user_t *         accdb,
                                        fd_funk_txn_xid_t const * xid,
                                        fd_vote_stakes_t *        vote_stakes,
                                        fd_pubkey_t *             pubkey ) {
  fd_accdb_ro_t ro[1];
  if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, ro, xid, pubkey ) ) ) return;

  if( !fd_pubkey_eq( fd_accdb_ref_owner( ro ), &fd_solana_vote_program_id ) ||
      fd_accdb_ref_lamports( ro )==0UL ||
      !fd_vsv_is_correct_size_and_initialized( ro->meta ) ) {
    fd_accdb_close_ro( accdb, ro );
    return;
  }
  fd_vote_stakes_insert_root_key( vote_stakes, pubkey, 0UL );
  fd_accdb_close_ro( accdb, ro );
}

static void
fd_solfuzz_block_update_prev_epoch_stakes( fd_vote_stakes_t *                 vote_stakes,
                                           fd_exec_test_prev_vote_account_t * vote_accounts,
                                           pb_size_t                          vote_accounts_cnt,
                                           uchar                              is_t_1 ) {
  if( FD_UNLIKELY( !vote_accounts ) ) return;
  for( uint i=0U; i<vote_accounts_cnt; i++ ) {
    fd_pubkey_t vote_pubkey = FD_LOAD( fd_pubkey_t, &vote_accounts[i].address );
    fd_pubkey_t node_pubkey = FD_LOAD( fd_pubkey_t, &vote_accounts[i].node_pubkey );
    ulong       stake       = vote_accounts[i].stake;
    /* TODO: uchar commission = (uchar)vote_accounts[i].commission; */

    fd_vote_stakes_insert_root_update( vote_stakes, &vote_pubkey, &node_pubkey, stake, is_t_1 );
  }
}

/* Stores an entry in the stake delegations cache for the given vote
   account.  Deserializes and uses the present account state to derive
   delegation information. */
static void
fd_solfuzz_block_register_stake_delegation( fd_accdb_user_t *         accdb,
                                            fd_funk_txn_xid_t const * xid,
                                            fd_stake_delegations_t *  stake_delegations,
                                            fd_pubkey_t *             pubkey ) {
  fd_accdb_ro_t ro[1];
  if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, ro, xid, pubkey ) ) ) return;

  fd_stake_state_v2_t stake_state;
  if( !fd_pubkey_eq( fd_accdb_ref_owner( ro ), &fd_solana_stake_program_id ) ||
      fd_accdb_ref_lamports( ro )==0UL ||
      0!=fd_stake_get_state( ro->meta, &stake_state ) ||
      !fd_stake_state_v2_is_stake( &stake_state ) ||
      stake_state.inner.stake.stake.delegation.stake==0UL ) {
    fd_accdb_close_ro( accdb, ro );
    return;
  }

  fd_stake_delegations_update(
      stake_delegations,
      pubkey,
      &stake_state.inner.stake.stake.delegation.voter_pubkey,
      stake_state.inner.stake.stake.delegation.stake,
      stake_state.inner.stake.stake.delegation.activation_epoch,
      stake_state.inner.stake.stake.delegation.deactivation_epoch,
      stake_state.inner.stake.stake.credits_observed,
      stake_state.inner.stake.stake.delegation.warmup_cooldown_rate );
  fd_accdb_close_ro( accdb, ro );
}

static void
fd_solfuzz_pb_block_ctx_destroy( fd_solfuzz_runner_t * runner ) {
  /* Release the stake delegations fork allocated in ctx_create */
  if( runner->bank->data->stake_delegations_fork_id!=USHORT_MAX ) {
    fd_stake_delegations_delta_t * sd_delta = fd_banks_get_stake_delegations_delta( runner->banks->data );
    fd_stake_delegations_delta_evict_fork( sd_delta, runner->bank->data->stake_delegations_fork_id );
    runner->bank->data->stake_delegations_fork_id = USHORT_MAX;
  }

  fd_accdb_v1_clear( runner->accdb_admin );
  fd_progcache_clear( runner->progcache_admin );

  /* In order to check for leaks in the workspace, we need to compact the
     allocators. Without doing this, empty superblocks may be retained
     by the fd_alloc instance, which mean we cannot check for leaks. */
  fd_alloc_compact( fd_accdb_user_v1_funk( runner->accdb )->alloc );
  fd_alloc_compact( runner->progcache_admin->funk->alloc );
}

/* Sets up block execution context from an input test case to execute
   against the runtime.  Returns block_info on success and NULL on
   failure. */
static fd_txn_p_t *
fd_solfuzz_pb_block_ctx_create( fd_solfuzz_runner_t *                runner,
                                fd_exec_test_block_context_t const * test_ctx,
                                ulong *                              out_txn_cnt,
                                fd_hash_t *                          poh ) {
  fd_accdb_user_t * accdb = runner->accdb;
  fd_bank_t *       bank  = runner->bank;
  fd_banks_t *      banks = runner->banks;

  fd_runtime_stack_t * runtime_stack = runner->runtime_stack;

  /* Must match fd_banks_footprint max_vote_accounts (2048) to avoid buffer overrun
     when fd_vote_stakes_new reinitializes and epoch boundary inserts from vote_ele_map */
  fd_banks_clear_bank( banks, bank, 2048UL );

  /* Generate unique ID for funk txn */
  fd_funk_txn_xid_t xid[1] = {{ .ul={ 0UL, 0UL } }};

  /* Create temporary funk transaction and slot / epoch contexts */
  fd_funk_txn_xid_t parent_xid; fd_funk_txn_xid_set_root( &parent_xid );
  fd_accdb_attach_child( runner->accdb_admin, &parent_xid, xid );
  fd_progcache_txn_attach_child( runner->progcache_admin, &parent_xid, xid );

  /* Restore features */
  fd_features_t features = {0};
  if( !fd_solfuzz_pb_restore_features( &features, &test_ctx->epoch_ctx.features ) ) {
    return NULL;
  }
  fd_bank_features_set( bank, features );

  /* Initialize bank from input block bank */
  FD_TEST( test_ctx->has_bank );
  fd_exec_test_block_bank_t const * block_bank = &test_ctx->bank;

  /* Slot */
  ulong slot = block_bank->slot;
  fd_bank_slot_set( bank, slot );

  /* Blockhash queue */
  fd_solfuzz_pb_restore_blockhash_queue( bank, block_bank->blockhash_queue, block_bank->blockhash_queue_count );

  /* RBH lamports per signature. In the Agave harness this is set inside
     the fee rate governor itself. */
  fd_bank_rbh_lamports_per_sig_set( runner->bank, block_bank->rbh_lamports_per_signature );

  /* Fee rate governor */
  FD_TEST( block_bank->has_fee_rate_governor );
  fd_solfuzz_pb_restore_fee_rate_governor( bank, &block_bank->fee_rate_governor );

  /* Parent slot */
  ulong parent_slot = block_bank->parent_slot;
  fd_bank_parent_slot_set( bank, parent_slot );

  /* Capitalization */
  fd_bank_capitalization_set( bank, block_bank->capitalization );

  /* Inflation */
  FD_TEST( block_bank->has_inflation );
  fd_inflation_t inflation = {
    .initial         = block_bank->inflation.initial,
    .terminal        = block_bank->inflation.terminal,
    .taper           = block_bank->inflation.taper,
    .foundation      = block_bank->inflation.foundation,
    .foundation_term = block_bank->inflation.foundation_term,
  };
  fd_bank_inflation_set( bank, inflation );

  /* Block height */
  fd_bank_block_height_set( bank, block_bank->block_height );

  /* POH (set right before finalize since we don't fuzz POH calculation) */
  fd_memcpy( poh, block_bank->poh, sizeof(fd_hash_t) );

  /* Bank hash (parent bank hash because current bank hash gets computed
     after the block executes) */
  fd_hash_t * bank_hash = fd_bank_bank_hash_modify( bank );
  fd_memcpy( bank_hash, block_bank->parent_bank_hash, sizeof(fd_hash_t) );

  /* Parent signature count */
  fd_bank_parent_signature_cnt_set( bank, block_bank->parent_signature_count );

  /* Epoch schedule */
  FD_TEST( block_bank->has_epoch_schedule );
  fd_solfuzz_pb_restore_epoch_schedule( bank, &block_bank->epoch_schedule );

  /* Rent */
  FD_TEST( block_bank->has_rent );
  fd_solfuzz_pb_restore_rent( bank, &block_bank->rent );

  /* Feature set */
  FD_TEST( block_bank->has_features );
  fd_exec_test_feature_set_t const * feature_set = &block_bank->features;
  fd_features_t * features_bm = fd_bank_features_modify( bank );
  FD_TEST( fd_solfuzz_pb_restore_features( features_bm, feature_set ) );

  /* Total epoch stake (derived from T-1 vote accounts) */
  ulong total_epoch_stake = 0UL;
  for( uint i=0U; i<block_bank->vote_accounts_t_1_count; i++ ) {
    total_epoch_stake += block_bank->vote_accounts_t_1[i].stake;
  }
  fd_bank_total_epoch_stake_set( bank, total_epoch_stake );

  /* Using default configuration of 64 ticks per slot
     https://github.com/anza-xyz/solana-sdk/blob/time-utils%40v3.0.0/time-utils/src/lib.rs#L18-L27 */
  uint128 ns_per_slot = FD_LOAD(uint128, block_bank->ns_per_slot );
  fd_bank_ns_per_slot_set( bank, (fd_w_u128_t){ .ud = ns_per_slot } );
  fd_bank_ticks_per_slot_set( bank, 64UL );
  fd_bank_slots_per_year_set( runner->bank, (double)SECONDS_PER_YEAR * 1e9 / (double)ns_per_slot );
  fd_bank_hashes_per_tick_set( bank, (slot+1UL)*64UL );

  /* Load in acccounts, populate stake delegations and vote accounts */
  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( banks );
  fd_stake_delegations_init( stake_delegations );

  fd_stake_delegations_delta_t * stake_delegations_delta = fd_banks_get_stake_delegations_delta( banks->data );
  bank->data->stake_delegations_fork_id = fd_stake_delegations_delta_new_fork( stake_delegations_delta );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes_locking_modify( bank );
  bank->data->vote_stakes_fork_id = fd_vote_stakes_get_root_idx( vote_stakes );

  for( ushort i=0; i<test_ctx->acct_states_count; i++ ) {
    fd_solfuzz_pb_load_account( runner->runtime, accdb, xid, &test_ctx->acct_states[i], i );

    /* Update vote accounts cache for epoch T */
    fd_pubkey_t pubkey;
    memcpy( &pubkey, test_ctx->acct_states[i].address, sizeof(fd_pubkey_t) );
    fd_solfuzz_block_register_vote_account(
        accdb,
        xid,
        vote_stakes,
        &pubkey );

    /* Update the stake delegations cache for epoch T */
    fd_solfuzz_block_register_stake_delegation( accdb, xid, stake_delegations, &pubkey );
  }

  /* Current epoch gets updated in process_new_epoch, so use the epoch
     from the parent slot */
  fd_bank_epoch_set( bank, fd_slot_to_epoch( fd_bank_epoch_schedule_query( bank ), parent_slot, NULL ) );

  /* Update vote cache for epoch T-1 */
  fd_solfuzz_block_update_prev_epoch_stakes( vote_stakes, block_bank->vote_accounts_t_1, block_bank->vote_accounts_t_1_count, 1 );

  /* Update vote cache for epoch T-2 */
  fd_solfuzz_block_update_prev_epoch_stakes( vote_stakes, block_bank->vote_accounts_t_2, block_bank->vote_accounts_t_2_count, 0 );

  /* Finalize root fork.  Required before epoch boundary processing which
     may call fd_vote_stakes_advance_root.  See fd_vote_stakes.h. */
  fd_vote_stakes_fini_root( vote_stakes );

  FD_TEST( fd_vote_rewards_map_join( fd_vote_rewards_map_new( runtime_stack->stakes.vote_map_mem, 2048UL, 999 ) ) );

  /* Populate vote_ele and vote_ele_map for partitioned epoch rewards.
     Use epoch_credits from the proto if available (captured at epoch
     boundary time), otherwise fall back to the vote account in funk. */
  fd_vote_rewards_map_t * vote_ele_map = fd_type_pun( runtime_stack->stakes.vote_map_mem );
  for( uint i=0U; i<block_bank->vote_accounts_t_1_count; i++ ) {
    fd_exec_test_prev_vote_account_t const * pva         = &block_bank->vote_accounts_t_1[i];
    fd_pubkey_t                              vote_pubkey = FD_LOAD( fd_pubkey_t, pva->address );

    fd_vote_rewards_t * vote_ele = &runtime_stack->stakes.vote_ele[i];
    fd_memcpy( vote_ele->pubkey.uc, &vote_pubkey, sizeof(fd_pubkey_t) );
    vote_ele->stake      = pva->stake;
    vote_ele->commission = (uchar)pva->commission;
    vote_ele->invalid    = 0;

    FD_TEST( pva->epoch_credits_count<=FD_EPOCH_CREDITS_MAX );
    for( ulong j=0UL; j<pva->epoch_credits_count; j++ ) {
      vote_ele->epoch_credits.epoch[j]        = (ushort)pva->epoch_credits[j].epoch;
      vote_ele->epoch_credits.credits[j]      = pva->epoch_credits[j].credits;
      vote_ele->epoch_credits.prev_credits[j] = pva->epoch_credits[j].prev_credits;
    }
    vote_ele->epoch_credits.cnt = pva->epoch_credits_count;

    fd_vote_rewards_map_idx_insert( vote_ele_map, i, runtime_stack->stakes.vote_ele );
  }

  fd_bank_vote_stakes_end_locking_modify( bank );

  /* Update leader schedule */
  fd_runtime_update_leaders( bank, runtime_stack );

  /* Make a new funk transaction since we're done loading in accounts for context */
  fd_funk_txn_xid_t fork_xid = { .ul = { slot, 0UL } };
  fd_accdb_attach_child        ( runner->accdb_admin,     xid, &fork_xid );
  fd_progcache_txn_attach_child( runner->progcache_admin, xid, &fork_xid );
  xid[0] = fork_xid;

  /* Set the initial lthash from the input since we're in a new Funk txn */
  fd_lthash_value_t * lthash = fd_bank_lthash_locking_modify( bank );
  fd_memcpy( lthash, block_bank->parent_lt_hash, sizeof(fd_lthash_value_t) );
  fd_bank_lthash_end_locking_modify( bank );

  /* Restore sysvar cache */
  fd_sysvar_cache_restore_fuzz( bank, accdb, xid );

  /* Prepare raw transaction pointers and block / microblock infos */
  ulong        txn_cnt  = test_ctx->txns_count;
  fd_txn_p_t * txn_ptrs = fd_spad_alloc( runner->spad, alignof(fd_txn_p_t), txn_cnt * sizeof(fd_txn_p_t) );
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn    = &txn_ptrs[i];
    ulong        msg_sz = fd_solfuzz_pb_txn_serialize( txn->payload, &test_ctx->txns[i] );

    // Reject any transactions over 1232 bytes
    if( FD_UNLIKELY( msg_sz==ULONG_MAX ) ) {
      return NULL;
    }
    txn->payload_sz = msg_sz;

    // Reject any transactions that cannot be parsed
    if( FD_UNLIKELY( !fd_txn_parse( txn->payload, msg_sz, TXN( txn ), NULL ) ) ) {
      return NULL;
    }
  }

  *out_txn_cnt = txn_cnt;
  return txn_ptrs;
}

/* Takes in a list of txn_p_t created from
   fd_runtime_fuzz_block_ctx_create and executes it against the runtime.
   Returns the execution result. */
static int
fd_solfuzz_block_ctx_exec( fd_solfuzz_runner_t * runner,
                           fd_txn_p_t *          txn_ptrs,
                           ulong                 txn_cnt,
                           fd_hash_t *           poh ) {
  int res = 0;

  // Prepare. Execute. Finalize.
  FD_SPAD_FRAME_BEGIN( runner->spad ) {
    fd_capture_ctx_t * capture_ctx = NULL;

    if( runner->solcap ) {
      void * capture_ctx_mem = fd_spad_alloc( runner->spad, fd_capture_ctx_align(), fd_capture_ctx_footprint() );
      capture_ctx = fd_capture_ctx_join( fd_capture_ctx_new( capture_ctx_mem ) );
      if( FD_UNLIKELY( !capture_ctx ) ) {
        FD_LOG_ERR(( "Failed to initialize capture_ctx" ));
      }

      fd_capture_link_file_t * capture_link_file =
        fd_spad_alloc( runner->spad, alignof(fd_capture_link_file_t), sizeof(fd_capture_link_file_t) );
      if( FD_UNLIKELY( !capture_link_file ) ) {
        FD_LOG_ERR(( "Failed to allocate capture_link_file" ));
      }

      capture_link_file->base.vt = &fd_capture_link_file_vt;

      int solcap_fd = (int)(ulong)runner->solcap_file;
      capture_link_file->fd          = solcap_fd;
      capture_ctx->capture_link      = &capture_link_file->base;
      capture_ctx->capctx_type.file  = capture_link_file;
      capture_ctx->solcap_start_slot = fd_bank_slot_get( runner->bank );
      capture_ctx->capture_solcap    = 1;

      fd_solcap_writer_init( capture_ctx->capture, solcap_fd );
    }

    /* TODO: Make sure this is able to work with booting up inside
       the partitioned epoch rewards distribution phase. */
    fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( runner->bank ), runner->bank->data->idx } };
    fd_rewards_recalculate_partitioned_rewards( runner->banks, runner->bank, runner->accdb, &xid, runner->runtime_stack, capture_ctx );

    /* Process new epoch may push a new spad frame onto the runtime spad. We should make sure this frame gets
       cleared (if it was allocated) before executing the block. */
    int is_epoch_boundary = 0;
    fd_runtime_block_execute_prepare( runner->banks, runner->bank, runner->accdb, runner->runtime_stack, capture_ctx, &is_epoch_boundary );

    /* Sequential transaction execution */
    for( ulong i=0UL; i<txn_cnt; i++ ) {
      fd_txn_p_t * txn = &txn_ptrs[i];

      /* Execute the transaction against the runtime */
      res = FD_RUNTIME_EXECUTE_SUCCESS;
      fd_txn_in_t  txn_in = { .txn = txn, .bundle.is_bundle = 0 };
      fd_txn_out_t txn_out;
      fd_runtime_t * runtime = runner->runtime;
      fd_log_collector_t log[1];
      runtime->log.log_collector = log;
      runtime->acc_pool = runner->acc_pool;
      fd_solfuzz_txn_ctx_exec( runner, runtime, &txn_in, &res, &txn_out );
      txn_out.err.exec_err = res;

      if( FD_UNLIKELY( !txn_out.err.is_committable ) ) {
        fd_runtime_cancel_txn( runtime, &txn_out );
        return 0;
      }

      /* Finalize the transaction */
      fd_runtime_commit_txn( runtime, runner->bank, &txn_out );

      if( FD_UNLIKELY( !txn_out.err.is_committable ) ) {
        return 0;
      }

    }

    /* At this point we want to set the poh.  This is what will get
       updated in the blockhash queue. */
    fd_bank_poh_set( runner->bank, *poh );
    /* Finalize the block */
    fd_runtime_block_execute_finalize( runner->bank, runner->accdb, capture_ctx );
  } FD_SPAD_FRAME_END;

  return 1;
}

/* Canonical (Agave-aligned) schedule hash
   Unique pubkeys referenced by sched, sorted deterministically
   Per-rotation indices mapped into sorted-uniq array */
ulong
fd_solfuzz_block_hash_epoch_leaders( fd_solfuzz_runner_t *      runner,
                                     fd_epoch_leaders_t const * leaders,
                                     ulong                      seed,
                                     uchar                      out[16] ) {
  /* Single contiguous spad allocation for uniq[] and sched_mapped[] */
  void *buf = fd_spad_alloc(
    runner->spad,
    alignof(pk_with_pos_t),
    leaders->sched_cnt*sizeof(pk_with_pos_t) +
    leaders->sched_cnt*sizeof(uint) );

  pk_with_pos_t * tmp          = (pk_with_pos_t *)buf;
  uint          * sched_mapped = (uint *)( tmp + leaders->sched_cnt );

  /* Gather all pubkeys and original positions from sched[] (skip invalid) */
  ulong gather_cnt = 0UL;
  for( ulong i=0UL; i<leaders->sched_cnt; i++ ) {
    uint idx = leaders->sched[i];
    if( idx>=leaders->pub_cnt ) { /* invalid slot leader */
      sched_mapped[i] = 0U;       /* prefill invalid mapping */
      continue;
    }
    fd_memcpy( &tmp[gather_cnt].pk, &leaders->pub[idx], sizeof(fd_pubkey_t) );
    tmp[gather_cnt].sched_pos = i;
    gather_cnt++;
  }

  if( gather_cnt==0UL ) {
    /* No leaders => hash:=0, count:=0 */
    fd_memset( out, 0, sizeof(ulong)*2 );
    return 0UL;
  }

  /* Sort tmp[] by pubkey, note: comparator relies on first struct member */
  sort_pkpos_inplace( tmp, (ulong)gather_cnt );

  /* Dedupe and assign indices into sched_mapped[] during single pass */
  ulong uniq_cnt = 0UL;
  for( ulong i=0UL; i<gather_cnt; i++ ) {
    if( i==0UL || memcmp( &tmp[i].pk, &tmp[i-1].pk, sizeof(fd_pubkey_t) )!=0 )
      uniq_cnt++;
    /* uniq_cnt-1 is index in uniq set */
    sched_mapped[tmp[i].sched_pos] = (uint)(uniq_cnt-1UL);
  }

  /* Reconstruct contiguous uniq[] for hashing */
  fd_pubkey_t *uniq = fd_spad_alloc( runner->spad,
                                     alignof(fd_pubkey_t),
                                     uniq_cnt*sizeof(fd_pubkey_t) );
  {
    ulong write_pos = 0UL;
    for( ulong i=0UL; i<gather_cnt; i++ ) {
      if( i==0UL || memcmp( &tmp[i].pk, &tmp[i-1].pk, sizeof(fd_pubkey_t) )!=0 )
      fd_memcpy( &uniq[write_pos++], &tmp[i].pk, sizeof(fd_pubkey_t) );
    }
  }

  /* Hash sorted unique pubkeys */
  ulong h1 = fd_hash( seed, uniq, uniq_cnt * sizeof(fd_pubkey_t) );
  fd_memcpy( out, &h1, sizeof(ulong) );

  /* Hash mapped indices */
  ulong h2 = fd_hash( seed, sched_mapped, leaders->sched_cnt * sizeof(uint) );
  fd_memcpy( out + sizeof(ulong), &h2, sizeof(ulong) );

  return uniq_cnt;
}

static void
fd_solfuzz_pb_build_leader_schedule_effects( fd_solfuzz_runner_t *          runner,
                                             fd_funk_txn_xid_t const *      xid,
                                             fd_exec_test_block_effects_t * effects ) {
  /* Read epoch schedule sysvar */
  fd_epoch_schedule_t es_;
  fd_epoch_schedule_t * sched = fd_sysvar_epoch_schedule_read( runner->accdb, xid, &es_ );
  FD_TEST( sched!=NULL );

  /* We will capture the leader schedule for the current epoch that we
     are in.  This will capture the leader schedule generated by an
     epoch boundary if one was crossed. */
  ulong epoch          = fd_bank_epoch_get( runner->bank );
  ulong ls_slot0       = fd_epoch_slot0( sched, epoch );
  ulong slots_in_epoch = fd_epoch_slot_cnt( sched, epoch );

  fd_epoch_leaders_t const * effects_leaders = fd_bank_epoch_leaders_query( runner->bank );

  /* Fill out effects struct from the Agave epoch info */
  effects->has_leader_schedule               = 1;
  effects->leader_schedule.leaders_epoch     = epoch;
  effects->leader_schedule.leaders_slot0     = ls_slot0;
  effects->leader_schedule.leaders_slot_cnt  = slots_in_epoch;
  effects->leader_schedule.leaders_sched_cnt = slots_in_epoch;
  effects->leader_schedule.leader_pub_cnt    = fd_solfuzz_block_hash_epoch_leaders(
      runner, effects_leaders,
      LEADER_SCHEDULE_HASH_SEED,
      effects->leader_schedule.leader_schedule_hash
  );
}

ulong
fd_solfuzz_pb_block_run( fd_solfuzz_runner_t * runner,
                          void const *         input_,
                          void **              output_,
                          void *               output_buf,
                          ulong                output_bufsz ) {
  fd_exec_test_block_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_block_effects_t **      output = fd_type_pun( output_ );

  FD_SPAD_FRAME_BEGIN( runner->spad ) {
    ulong txn_cnt;
    fd_hash_t poh = {0};
    fd_txn_p_t * txn_ptrs = fd_solfuzz_pb_block_ctx_create( runner, input, &txn_cnt, &poh );
    if( txn_ptrs==NULL ) {
      fd_solfuzz_pb_block_ctx_destroy( runner );
      return 0;
    }

    fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( runner->bank ), runner->bank->data->idx } };

    /* Execute the constructed block against the runtime. */
    int is_committable = fd_solfuzz_block_ctx_exec( runner, txn_ptrs, txn_cnt, &poh );

    /* Start saving block exec results */
    FD_SCRATCH_ALLOC_INIT( l, output_buf );
    ulong output_end = (ulong)output_buf + output_bufsz;

    fd_exec_test_block_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_block_effects_t),
                                sizeof(fd_exec_test_block_effects_t) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      abort();
    }
    fd_memset( effects, 0, sizeof(fd_exec_test_block_effects_t) );

    /* Capture error status */
    effects->has_error = !is_committable;

    /* Capture capitalization */
    effects->slot_capitalization = !effects->has_error ? fd_bank_capitalization_get( runner->bank ) : 0UL;

    /* Capture hashes */
    fd_hash_t bank_hash = !effects->has_error ? fd_bank_bank_hash_get( runner->bank ) : (fd_hash_t){0};
    fd_memcpy( effects->bank_hash, bank_hash.hash, sizeof(fd_hash_t) );

    /* Capture cost tracker */
    fd_cost_tracker_t const * cost_tracker = fd_bank_cost_tracker_locking_query( runner->bank );
    effects->has_cost_tracker = 1;
    effects->cost_tracker = (fd_exec_test_cost_tracker_t) {
      .block_cost = cost_tracker ? cost_tracker->block_cost : 0UL,
      .vote_cost  = cost_tracker ? cost_tracker->vote_cost  : 0UL,
    };
    fd_bank_cost_tracker_end_locking_query( runner->bank );

    /* Effects: build T-epoch (bank epoch), T-stakes ephemeral leaders and report */
    fd_solfuzz_pb_build_leader_schedule_effects( runner, &xid, effects );

    ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
    fd_solfuzz_pb_block_ctx_destroy( runner );

    *output = effects;
    return actual_end - (ulong)output_buf;
  } FD_SPAD_FRAME_END;
}
