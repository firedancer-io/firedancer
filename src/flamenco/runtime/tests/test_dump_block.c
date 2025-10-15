/* test_dump_block.c - Unit tests for fd_dump_pb.c block dumping functionality */

#include "fd_dump_pb.h"
#include "fd_txn_harness.h"
#include "../../../util/fd_util.h"
#include "../context/fd_capture_ctx.h"
#include "../fd_bank.h"
#include "../fd_blockhashes.h"
#include "../fd_system_ids.h"
#include "../../stakes/fd_vote_states.h"
#include "../../stakes/fd_stake_delegations.h"
#include "../program/fd_stake_program.h"
#include "../program/fd_vote_program.h"
#include "../../../ballet/nanopb/pb_decode.h"
#include "generated/block.pb.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Test configuration constants */
#define TEST_WKSP_PAGE_CNT       (10UL)
#define TEST_WKSP_PAGE_SZ        (FD_SHMEM_GIGANTIC_PAGE_SZ)
#define TEST_FUNK_TXN_MAX        (32UL)
#define TEST_FUNK_REC_MAX        (1024UL)
#define TEST_SPAD_MEM_MAX        (512UL<<20)  /* 512 MB */
#define TEST_BANK_MAX            (2UL)
#define TEST_FORK_MAX            (1UL)
#define TEST_OUTPUT_DIR          "/tmp/test_dump_output"

FD_IMPORT_BINARY( normal_block_ctx, "src/flamenco/runtime/tests/fixtures/block-241.blockctx" );
FD_IMPORT_BINARY( epoch_boundary_block_ctx, "src/flamenco/runtime/tests/fixtures/block-384.blockctx" );

/* Holds all testing context */
typedef struct test_ctx {
  /* Workspace */
  fd_wksp_t * wksp;

  /* Funk (account database) */
  fd_funk_t funk[1];

  /* Funk transactions */
  fd_funk_txn_xid_t parent_xid;  /* Parent funk txn (slot 99, parent_bank->idx) */
  fd_funk_txn_xid_t child_xid;   /* Child funk txn (slot 100, child_bank->idx) */

  /* Banks (slot/epoch management) */
  fd_banks_t * banks;
  fd_bank_t *  parent_bank;  /* Parent bank */
  fd_bank_t *  child_bank;   /* Child bank */

  /* Scratch pad for temporary allocations */
  fd_spad_t * spad;

  /* Block dump context */
  fd_block_dump_ctx_t * dump_ctx;

  /* Capture context (required for dump function) */
  fd_capture_ctx_t * capture_ctx;
} test_ctx_t;

/* Setup function - initializes all test infrastructure */
static test_ctx_t *
test_ctx_setup( void ) {
  /* Create workspace */
  char const * _page_sz = fd_env_strip_cmdline_cstr( NULL, NULL, "--page-sz",  NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( NULL, NULL, "--page-cnt", NULL, TEST_WKSP_PAGE_CNT );
  ulong        page_sz  = fd_cstr_to_shmem_page_sz( _page_sz );
  FD_TEST( page_sz );

  ulong       wksp_tag = 2UL;
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( page_sz, page_cnt, fd_log_cpu_id(), "test_wksp", 0UL );
  FD_TEST( wksp );

  test_ctx_t * test_ctx = fd_wksp_alloc_laddr( wksp, alignof(test_ctx_t), sizeof(test_ctx_t), wksp_tag );
  FD_TEST( test_ctx );
  fd_memset( test_ctx, 0, sizeof(test_ctx_t) );
  test_ctx->wksp = wksp;

  /* Allocate memory for funk (account database) */
  ulong  funk_footprint = fd_funk_footprint( TEST_FUNK_TXN_MAX, TEST_FUNK_REC_MAX );
  void * funk_mem       = fd_wksp_alloc_laddr( test_ctx->wksp, fd_funk_align(), funk_footprint, wksp_tag );
  FD_TEST( funk_mem );

  /* Initialize funk */
  void * shfunk = fd_funk_new( funk_mem, wksp_tag, 42UL, TEST_FUNK_TXN_MAX, TEST_FUNK_REC_MAX );
  FD_TEST( shfunk );
  FD_TEST( fd_funk_join( test_ctx->funk, funk_mem ) );

  /* Allocate memory for banks */
  ulong  banks_footprint = fd_banks_footprint( TEST_BANK_MAX, TEST_FORK_MAX );
  void * banks_mem       = fd_wksp_alloc_laddr( test_ctx->wksp, fd_banks_align(), banks_footprint, wksp_tag );
  FD_TEST( banks_mem );

  /* Initialize banks */
  test_ctx->banks = fd_banks_join( fd_banks_new( banks_mem, TEST_BANK_MAX, TEST_FORK_MAX ) );
  FD_TEST( test_ctx->banks );

  /* Initialize stake delegations at the root level */
  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( test_ctx->banks );
  stake_delegations = fd_stake_delegations_join( fd_stake_delegations_new( stake_delegations, FD_RUNTIME_MAX_STAKE_ACCOUNTS, 0 ) );
  FD_TEST( stake_delegations );

  /* ===== Create Parent Bank ===== */
  test_ctx->parent_bank = fd_banks_init_bank( test_ctx->banks );
  FD_TEST( test_ctx->parent_bank );

  /* Initialize vote states for parent bank */
  fd_vote_states_t * parent_vote_states = fd_bank_vote_states_locking_modify( test_ctx->parent_bank );
  parent_vote_states                    = fd_vote_states_join( fd_vote_states_new( parent_vote_states, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  FD_TEST( parent_vote_states );
  fd_bank_vote_states_end_locking_modify( test_ctx->parent_bank );

  fd_vote_states_t * parent_vote_states_prev = fd_bank_vote_states_prev_locking_modify( test_ctx->parent_bank );
  parent_vote_states_prev                    = fd_vote_states_join( fd_vote_states_new( parent_vote_states_prev, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  FD_TEST( parent_vote_states_prev );

  fd_bank_vote_states_prev_end_locking_modify( test_ctx->parent_bank );
  fd_vote_states_t * parent_vote_states_prev_prev = fd_bank_vote_states_prev_prev_locking_modify( test_ctx->parent_bank );
  parent_vote_states_prev_prev                    = fd_vote_states_join( fd_vote_states_new( parent_vote_states_prev_prev, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  FD_TEST( parent_vote_states_prev_prev );
  fd_bank_vote_states_prev_prev_end_locking_modify( test_ctx->parent_bank );

  /* ===== Create Child Bank ===== */
  ulong child_bank_idx = fd_banks_new_bank( test_ctx->banks, test_ctx->parent_bank->idx, 0L )->idx;
  test_ctx->child_bank = fd_banks_clone_from_parent( test_ctx->banks, child_bank_idx, test_ctx->parent_bank->idx );
  FD_TEST( test_ctx->child_bank );

  /* Allocate scratch pad */
  ulong  spad_footprint = fd_spad_footprint( TEST_SPAD_MEM_MAX );
  void * spad_mem       = fd_wksp_alloc_laddr( test_ctx->wksp, fd_spad_align(), spad_footprint, wksp_tag++ );
  FD_TEST( spad_mem );

  test_ctx->spad = fd_spad_join( fd_spad_new( spad_mem, TEST_SPAD_MEM_MAX ) );
  FD_TEST( test_ctx->spad );

  /* Allocate block dump context */
  ulong  dump_ctx_footprint = fd_block_dump_context_footprint();
  void * dump_ctx_mem       = fd_wksp_alloc_laddr( test_ctx->wksp, fd_block_dump_context_align(), dump_ctx_footprint, wksp_tag++ );
  FD_TEST( dump_ctx_mem );

  test_ctx->dump_ctx = fd_block_dump_context_join( fd_block_dump_context_new( dump_ctx_mem ) );
  FD_TEST( test_ctx->dump_ctx );

  /* Allocate capture context */
  ulong  capture_ctx_footprint = fd_capture_ctx_footprint();
  void * capture_ctx_mem       = fd_wksp_alloc_laddr( test_ctx->wksp, fd_capture_ctx_align(), capture_ctx_footprint, wksp_tag++ );
  FD_TEST( capture_ctx_mem );

  test_ctx->capture_ctx = fd_capture_ctx_join( fd_capture_ctx_new( capture_ctx_mem ) );
  FD_TEST( test_ctx->capture_ctx );

  /* Set up capture context for dumping */
  test_ctx->capture_ctx->dump_proto_output_dir = TEST_OUTPUT_DIR;
  test_ctx->capture_ctx->dump_proto_sig_filter = NULL;
  test_ctx->capture_ctx->dump_proto_start_slot = 0UL;
  test_ctx->capture_ctx->dump_block_to_pb = 1;

  /* Create output directory if it doesn't exist */
  mkdir( TEST_OUTPUT_DIR, 0755 );

  return test_ctx;
}

/* Teardown function - cleans up all test infrastructure */
static void
test_ctx_teardown( test_ctx_t * test_ctx ) {
  if( !test_ctx ) return;

  /* Clean up capture context */
  fd_wksp_free_laddr( fd_capture_ctx_delete( fd_capture_ctx_leave( test_ctx->capture_ctx ) ) );

  /* Clean up dump context */
  fd_wksp_free_laddr( fd_block_dump_context_delete( fd_block_dump_context_leave( test_ctx->dump_ctx ) ) );

  /* Clean up spad */
  fd_wksp_free_laddr( fd_spad_delete( fd_spad_leave( test_ctx->spad ) ) );

  /* Clean up banks */
  fd_wksp_free_laddr( fd_banks_delete( fd_banks_leave( test_ctx->banks ) ) );

  /* Clean up funk */
  void * shfunk = NULL;
  fd_funk_leave( test_ctx->funk, &shfunk );
  if( shfunk ) fd_wksp_free_laddr( fd_funk_delete( shfunk ) );

  /* Delete test context */
  fd_wksp_free_laddr( test_ctx );

  /* Delete workspace (should be done last) */
  fd_wksp_delete_anonymous( test_ctx->wksp );
}

/* Helper: Restore features from protobuf feature set */
static int
restore_features_from_proto( fd_features_t * features, fd_exec_test_feature_set_t const * feature_set ) {
  /* Initialize all features as disabled */
  for( ulong i=0UL; i<FD_FEATURE_ID_CNT; i++ ) {
    features->f[i] = FD_FEATURE_DISABLED;
  }

  /* Activate features from the input set */
  for( pb_size_t i=0U; i<feature_set->features_count; i++ ) {
    fd_feature_id_t const * feature_id = fd_feature_id_query( feature_set->features[i] );
    if( FD_UNLIKELY( !feature_id ) ) {
      FD_LOG_WARNING(( "Unknown feature ID: %lu", feature_set->features[i] ));
      continue;
    }
    features->f[ feature_id->index ] = 0UL;  /* Active from slot 0 */
  }
  return 1;
}

/* Helper: Register a vote account from an account in funk */
static void
register_vote_account_from_funk( fd_funk_t *               funk,
                                 fd_funk_txn_xid_t const * xid,
                                 fd_vote_states_t *        vote_states,
                                 fd_pubkey_t *             pubkey,
                                 fd_spad_t *               spad ) {
  fd_txn_account_t acc[1];
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( acc, pubkey, funk, xid ) ) ) {
    return;
  }

  /* Account must be owned by the vote program */
  if( memcmp( fd_txn_account_get_owner( acc ), fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return;
  }

  /* Account must have > 0 lamports */
  if( fd_txn_account_get_lamports( acc )==0UL ) {
    return;
  }

  /* Account must be initialized correctly */
  if( FD_UNLIKELY( !fd_vote_state_versions_is_correct_and_initialized( acc ) ) ) {
    return;
  }

  /* Get the vote state from the account data */
  fd_vote_state_versioned_t * vsv = NULL;
  int err = fd_vote_get_state( acc, spad, &vsv );
  if( FD_UNLIKELY( err ) ) {
    return;
  }

  fd_vote_states_update_from_account(
      vote_states,
      acc->pubkey,
      fd_txn_account_get_data( acc ),
      fd_txn_account_get_data_len( acc ) );
}

/* Helper: Register a stake delegation from an account in funk */
static void
register_stake_delegation_from_funk( fd_funk_t *               funk,
                                     fd_funk_txn_xid_t const * xid,
                                     fd_stake_delegations_t *  stake_delegations,
                                     fd_pubkey_t *             pubkey ) {
  fd_txn_account_t acc[1];
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( acc, pubkey, funk, xid ) ) ) {
    return;
  }

  /* Account must be owned by the stake program */
  if( memcmp( fd_txn_account_get_owner( acc ), fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return;
  }

  /* Account must have > 0 lamports */
  if( fd_txn_account_get_lamports( acc )==0UL ) {
    return;
  }

  /* Stake state must exist and be initialized correctly */
  fd_stake_state_v2_t stake_state;
  if( FD_UNLIKELY( fd_stake_get_state( acc, &stake_state ) || !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
    return;
  }

  /* Skip 0-stake accounts */
  if( FD_UNLIKELY( stake_state.inner.stake.stake.delegation.stake==0UL ) ) {
    return;
  }

  /* Register the stake delegation */
  fd_stake_delegations_update(
      stake_delegations,
      pubkey,
      &stake_state.inner.stake.stake.delegation.voter_pubkey,
      stake_state.inner.stake.stake.delegation.stake,
      stake_state.inner.stake.stake.delegation.activation_epoch,
      stake_state.inner.stake.stake.delegation.deactivation_epoch,
      stake_state.inner.stake.stake.credits_observed,
      stake_state.inner.stake.stake.delegation.warmup_cooldown_rate );
}

/* Helper: Load accounts from protobuf into funk */
static void
load_accounts_from_proto( fd_funk_t * funk,
                          fd_funk_txn_xid_t const * xid,
                          fd_exec_test_acct_state_t const * acct_states,
                          pb_size_t acct_states_count ) {
  for( pb_size_t i=0U; i<acct_states_count; i++ ) {
    fd_exec_test_acct_state_t const * state = &acct_states[i];

    /* Skip zero-lamport accounts */
    if( state->lamports==0UL ) continue;

    ulong size = state->data ? state->data->size : 0UL;
    fd_pubkey_t pubkey[1];
    fd_memcpy( pubkey, state->address, sizeof(fd_pubkey_t) );

    /* Create account in funk */
    fd_funk_rec_prepare_t prepare = {0};
    fd_txn_account_t acc[1];

    int err = fd_txn_account_init_from_funk_mutable( acc, pubkey, funk, xid, 1, size, &prepare );
    if( FD_UNLIKELY( err ) ) {
      continue;
    }

    /* Set account data */
    if( state->data && size ) {
      fd_txn_account_set_data( acc, state->data->bytes, size );
    }

    /* Set account metadata */
    acc->starting_lamports = state->lamports;
    acc->starting_dlen = size;
    fd_txn_account_set_lamports( acc, state->lamports );
    fd_txn_account_set_executable( acc, state->executable );
    fd_txn_account_set_owner( acc, (fd_pubkey_t const *)state->owner );
    fd_txn_account_set_readonly( acc );

    fd_txn_account_mutable_fini( acc, funk, &prepare );
  }
}

/* Helper function: Tests block dump with round-trip verification for a given block context */
static void
test_block_round_trip( test_ctx_t *  test_ctx,
                       uchar const * block_ctx_data,
                       ulong         block_ctx_sz,
                       char const *  test_name ) {
FD_SPAD_FRAME_BEGIN( test_ctx->spad ) {
  FD_LOG_NOTICE(( "TEST: %s", test_name ));

  /* Decode the input block context */
  pb_istream_t                 input_stream = pb_istream_from_buffer( block_ctx_data, block_ctx_sz );
  fd_exec_test_block_context_t input_ctx    = FD_EXEC_TEST_BLOCK_CONTEXT_INIT_DEFAULT;
  int                          decode_ok    = pb_decode( &input_stream, FD_EXEC_TEST_BLOCK_CONTEXT_FIELDS, &input_ctx );
  FD_TEST( decode_ok );

  /* Extract slot information */
  ulong parent_slot = input_ctx.slot_ctx.prev_slot;
  ulong child_slot  = input_ctx.slot_ctx.slot;

  /* Cancel existing funk transactions from the previous test */
  fd_funk_txn_cancel_all( test_ctx->funk );

  /* Reuse existing parent bank */
  FD_TEST( test_ctx->parent_bank != NULL );

  /* Set parent bank fields from input context */
  fd_bank_slot_set( test_ctx->parent_bank, parent_slot );
  fd_bank_parent_slot_set( test_ctx->parent_bank, parent_slot - 1 );
  fd_bank_block_height_set( test_ctx->parent_bank, parent_slot );  /* Assume block_height == slot for simplicity */
  fd_bank_capitalization_set( test_ctx->parent_bank, input_ctx.slot_ctx.prev_epoch_capitalization );
  fd_bank_lamports_per_signature_set( test_ctx->parent_bank, input_ctx.slot_ctx.prev_lps );
  fd_bank_prev_lamports_per_signature_set( test_ctx->parent_bank, input_ctx.slot_ctx.prev_lps );
  fd_bank_hashes_per_tick_set( test_ctx->parent_bank, input_ctx.epoch_ctx.hashes_per_tick );
  fd_bank_ticks_per_slot_set( test_ctx->parent_bank, input_ctx.epoch_ctx.ticks_per_slot );
  fd_bank_slots_per_year_set( test_ctx->parent_bank, input_ctx.epoch_ctx.slots_per_year );
  fd_bank_genesis_creation_time_set( test_ctx->parent_bank, input_ctx.epoch_ctx.genesis_creation_time );

  /* Set parent bank hash */
  fd_hash_t * parent_bank_hash = fd_bank_bank_hash_modify( test_ctx->parent_bank );
  fd_memcpy( parent_bank_hash, input_ctx.slot_ctx.parent_bank_hash, sizeof(fd_hash_t) );

  /* Set parent lthash */
  fd_lthash_value_t * parent_lthash = fd_bank_lthash_locking_modify( test_ctx->parent_bank );
  fd_memcpy( parent_lthash, input_ctx.slot_ctx.parent_lthash, sizeof(fd_lthash_value_t) );
  fd_bank_lthash_end_locking_modify( test_ctx->parent_bank );

  /* Set features */
  fd_features_t features = {0};
  restore_features_from_proto( &features, &input_ctx.epoch_ctx.features );
  fd_bank_features_set( test_ctx->parent_bank, features );

  /* Set fee rate governor */
  if( input_ctx.slot_ctx.has_fee_rate_governor ) {
    fd_fee_rate_governor_t * frg       = fd_bank_fee_rate_governor_modify( test_ctx->parent_bank );
    frg->target_lamports_per_signature = input_ctx.slot_ctx.fee_rate_governor.target_lamports_per_signature;
    frg->target_signatures_per_slot    = input_ctx.slot_ctx.fee_rate_governor.target_signatures_per_slot;
    frg->min_lamports_per_signature    = input_ctx.slot_ctx.fee_rate_governor.min_lamports_per_signature;
    frg->max_lamports_per_signature    = input_ctx.slot_ctx.fee_rate_governor.max_lamports_per_signature;
    frg->burn_percent                  = (uchar)input_ctx.slot_ctx.fee_rate_governor.burn_percent;
  }

  /* Set inflation */
  if( input_ctx.epoch_ctx.has_inflation ) {
    fd_inflation_t * inflation = fd_bank_inflation_modify( test_ctx->parent_bank );
    inflation->initial         = input_ctx.epoch_ctx.inflation.initial;
    inflation->terminal        = input_ctx.epoch_ctx.inflation.terminal;
    inflation->taper           = input_ctx.epoch_ctx.inflation.taper;
    inflation->foundation      = input_ctx.epoch_ctx.inflation.foundation;
    inflation->foundation_term = input_ctx.epoch_ctx.inflation.foundation_term;
  }

  /* Populate previous epoch vote accounts */
  if( input_ctx.epoch_ctx.vote_accounts_t_1_count ) {
    fd_vote_states_t * vote_states_prev = fd_bank_vote_states_prev_locking_modify( test_ctx->parent_bank );

    for( pb_size_t i=0U; i<input_ctx.epoch_ctx.vote_accounts_t_1_count; i++ ) {
      fd_exec_test_vote_account_t const * vote_acct = &input_ctx.epoch_ctx.vote_accounts_t_1[i];
      if( !vote_acct->has_vote_account ) continue;

      fd_pubkey_t vote_address;
      fd_memcpy( &vote_address, vote_acct->vote_account.address, sizeof(fd_pubkey_t) );

      fd_vote_states_update_from_account( vote_states_prev,
                                         &vote_address,
                                         vote_acct->vote_account.data->bytes,
                                         vote_acct->vote_account.data->size );
      fd_vote_states_update_stake( vote_states_prev, &vote_address, vote_acct->stake );
    }

    fd_bank_vote_states_prev_end_locking_modify( test_ctx->parent_bank );
  }

  /* Populate previous-to-previous epoch vote accounts */
  if( input_ctx.epoch_ctx.vote_accounts_t_2_count ) {
    fd_vote_states_t * vote_states_prev_prev = fd_bank_vote_states_prev_prev_locking_modify( test_ctx->parent_bank );

    for( pb_size_t i=0U; i<input_ctx.epoch_ctx.vote_accounts_t_2_count; i++ ) {
      fd_exec_test_vote_account_t const * vote_acct = &input_ctx.epoch_ctx.vote_accounts_t_2[i];
      if( !vote_acct->has_vote_account ) continue;

      fd_pubkey_t vote_address;
      fd_memcpy( &vote_address, vote_acct->vote_account.address, sizeof(fd_pubkey_t) );

      fd_vote_states_update_from_account( vote_states_prev_prev,
                                         &vote_address,
                                         vote_acct->vote_account.data->bytes,
                                         vote_acct->vote_account.data->size );
      fd_vote_states_update_stake( vote_states_prev_prev, &vote_address, vote_acct->stake );
    }

    fd_bank_vote_states_prev_prev_end_locking_modify( test_ctx->parent_bank );
  }

  /* Initialize and populate blockhash queue from input context */
  ulong              blockhash_seed = 42UL;
  fd_blockhashes_t * blockhashes    = fd_blockhashes_init( fd_bank_block_hash_queue_modify( test_ctx->parent_bank ), blockhash_seed );

  /* Push blockhashes in reverse order because dump_blockhash_queue
     reverses them when serializing. Input array is newest-to-oldest,
     queue needs oldest-to-newest. */
  for( pb_size_t i=input_ctx.blockhash_queue_count; i>0U; i-- ) {
    pb_size_t idx = i-1U;
    FD_TEST( input_ctx.blockhash_queue[idx]->size==32U );

    fd_hash_t hash;
    fd_memcpy( &hash, input_ctx.blockhash_queue[idx]->bytes, sizeof(fd_hash_t) );

    fd_blockhash_info_t * info = fd_blockhashes_push_old( blockhashes, &hash );
    if( info ) {
      /* Set fee calculator to match parent LPS */
      info->fee_calculator.lamports_per_signature = input_ctx.slot_ctx.prev_lps;
    }
  }

  /* Create parent funk transaction */
  test_ctx->parent_xid.ul[0] = parent_slot;
  test_ctx->parent_xid.ul[1] = test_ctx->parent_bank->idx;
  fd_funk_txn_xid_t root_xid;
  fd_funk_txn_xid_set_root( &root_xid );
  fd_funk_txn_prepare( test_ctx->funk, &root_xid, &test_ctx->parent_xid );

  /* Load accounts into Funk */
  load_accounts_from_proto( test_ctx->funk, &test_ctx->parent_xid, input_ctx.acct_states, input_ctx.acct_states_count );

  /* Initialize and populate stake delegations cache from accounts */
  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( test_ctx->banks );
  stake_delegations = fd_stake_delegations_join( fd_stake_delegations_new( stake_delegations, FD_RUNTIME_MAX_STAKE_ACCOUNTS, 0 ) );

  /* Initialize and populate current epoch vote states from accounts */
  fd_vote_states_t * vote_states_current = fd_bank_vote_states_locking_modify( test_ctx->parent_bank );

  for( pb_size_t i=0U; i<input_ctx.acct_states_count; i++ ) {
    fd_pubkey_t pubkey;
    fd_memcpy( &pubkey, input_ctx.acct_states[i].address, sizeof(fd_pubkey_t) );

    /* Register vote account in current epoch */
    register_vote_account_from_funk( test_ctx->funk, &test_ctx->parent_xid, vote_states_current, &pubkey, test_ctx->spad );

    /* Register stake delegation */
    register_stake_delegation_from_funk( test_ctx->funk, &test_ctx->parent_xid, stake_delegations, &pubkey );
  }

  fd_bank_vote_states_end_locking_modify( test_ctx->parent_bank );

  /* Reuse existing child bank */
  FD_TEST( test_ctx->child_bank );

  /* Set child bank fields */
  fd_bank_slot_set( test_ctx->child_bank, child_slot );
  fd_bank_parent_slot_set( test_ctx->child_bank, parent_slot );
  fd_bank_block_height_set( test_ctx->child_bank, input_ctx.slot_ctx.block_height );

  /* Set child POH */
  fd_hash_t * child_poh = fd_bank_poh_modify( test_ctx->child_bank );
  fd_memcpy( child_poh, input_ctx.slot_ctx.poh, sizeof(fd_hash_t) );

  /* Create child funk transaction */
  test_ctx->child_xid.ul[0] = child_slot;
  test_ctx->child_xid.ul[1] = test_ctx->child_bank->idx;
  fd_funk_txn_prepare( test_ctx->funk, &test_ctx->parent_xid, &test_ctx->child_xid );

  /* Reset dump context and collect transactions */
  fd_block_dump_context_reset( test_ctx->dump_ctx );

  /* Serialize and collect transactions from input context */
  for( pb_size_t i=0; i<input_ctx.txns_count; i++ ) {
    fd_exec_test_sanitized_transaction_t const * txn = &input_ctx.txns[i];

    /* Allocate fd_txn_p_t on spad */
    fd_txn_p_t * txn_p = (fd_txn_p_t *)fd_spad_alloc( test_ctx->spad, alignof(fd_txn_p_t), sizeof(fd_txn_p_t) );
    FD_TEST( txn_p );

    /* Serialize the protobuf transaction to raw txn format */
    ulong msg_sz = fd_runtime_fuzz_serialize_txn( txn_p->payload, txn );
    FD_TEST( msg_sz!=ULONG_MAX );

    txn_p->payload_sz = msg_sz;

    /* Parse the transaction to validate it */
    ulong parse_result = fd_txn_parse( txn_p->payload, msg_sz, TXN( txn_p ), NULL );
    FD_TEST( parse_result );

    /* Collect the transaction for dumping */
    fd_dump_block_to_protobuf_collect_tx( test_ctx->dump_ctx, txn_p );
  }

  /* Call the dump function */
  fd_dump_block_to_protobuf(
      test_ctx->dump_ctx,
      test_ctx->banks,
      test_ctx->child_bank,
      test_ctx->funk,
      test_ctx->capture_ctx
  );

  /* Verify output file was created */
  char output_path[PATH_MAX];
  snprintf( output_path, PATH_MAX, "%s/block-%lu.blockctx", TEST_OUTPUT_DIR, child_slot );

  FILE * output_file = fopen( output_path, "rb" );
  FD_TEST( output_file );

  fseek( output_file, 0, SEEK_END );
  long output_size = ftell( output_file );
  fseek( output_file, 0, SEEK_SET );
  FD_TEST( output_size > 0 );

  uchar * output_buf = (uchar *)malloc( (ulong)output_size );
  FD_TEST( output_buf );
  ulong read_bytes = fread( output_buf, 1, (ulong)output_size, output_file );
  FD_TEST( read_bytes == (ulong)output_size );
  fclose( output_file );

  /* Decode output */
  pb_istream_t output_stream = pb_istream_from_buffer( output_buf, (ulong)output_size );
  fd_exec_test_block_context_t output_ctx = FD_EXEC_TEST_BLOCK_CONTEXT_INIT_DEFAULT;
  decode_ok = pb_decode( &output_stream, FD_EXEC_TEST_BLOCK_CONTEXT_FIELDS, &output_ctx );
  FD_TEST( decode_ok );

  /* Verify basic fields match */
  FD_TEST( output_ctx.slot_ctx.slot == input_ctx.slot_ctx.slot );
  FD_TEST( output_ctx.slot_ctx.block_height == input_ctx.slot_ctx.block_height );
  FD_TEST( output_ctx.slot_ctx.prev_slot == input_ctx.slot_ctx.prev_slot );
  FD_TEST( output_ctx.slot_ctx.prev_lps == input_ctx.slot_ctx.prev_lps );
  FD_TEST( output_ctx.slot_ctx.prev_epoch_capitalization == input_ctx.slot_ctx.prev_epoch_capitalization );

  /* Verify POH matches */
  FD_TEST( !memcmp( output_ctx.slot_ctx.poh, input_ctx.slot_ctx.poh, 32 ) );

  /* Verify parent bank hash matches */
  FD_TEST( !memcmp( output_ctx.slot_ctx.parent_bank_hash, input_ctx.slot_ctx.parent_bank_hash, 32 ) );

  /* Verify epoch context fields */
  FD_TEST( output_ctx.epoch_ctx.hashes_per_tick == input_ctx.epoch_ctx.hashes_per_tick );
  FD_TEST( output_ctx.epoch_ctx.ticks_per_slot == input_ctx.epoch_ctx.ticks_per_slot );
  FD_TEST( output_ctx.epoch_ctx.slots_per_year == input_ctx.epoch_ctx.slots_per_year );
  FD_TEST( output_ctx.epoch_ctx.genesis_creation_time == input_ctx.epoch_ctx.genesis_creation_time );

  /* Verify inflation */
  FD_TEST( output_ctx.epoch_ctx.has_inflation == input_ctx.epoch_ctx.has_inflation );
  if( output_ctx.epoch_ctx.has_inflation ) {
    FD_TEST( output_ctx.epoch_ctx.inflation.initial == input_ctx.epoch_ctx.inflation.initial );
    FD_TEST( output_ctx.epoch_ctx.inflation.terminal == input_ctx.epoch_ctx.inflation.terminal );
    FD_TEST( output_ctx.epoch_ctx.inflation.taper == input_ctx.epoch_ctx.inflation.taper );
    FD_TEST( output_ctx.epoch_ctx.inflation.foundation == input_ctx.epoch_ctx.inflation.foundation );
    FD_TEST( output_ctx.epoch_ctx.inflation.foundation_term == input_ctx.epoch_ctx.inflation.foundation_term );
  }

  /* Verify features */
  FD_TEST( output_ctx.epoch_ctx.has_features == input_ctx.epoch_ctx.has_features );
  if( output_ctx.epoch_ctx.has_features ) {
    FD_TEST( output_ctx.epoch_ctx.features.features_count == input_ctx.epoch_ctx.features.features_count );
    for( pb_size_t i=0U; i<output_ctx.epoch_ctx.features.features_count; i++ ) {
      FD_TEST( output_ctx.epoch_ctx.features.features[i] == input_ctx.epoch_ctx.features.features[i] );
    }
  }

  /* Verify parent lthash */
  FD_TEST( 0 == memcmp( output_ctx.slot_ctx.parent_lthash, input_ctx.slot_ctx.parent_lthash, 2048 ) );

  /* Verify fee rate governor */
  FD_TEST( output_ctx.slot_ctx.has_fee_rate_governor == input_ctx.slot_ctx.has_fee_rate_governor );
  if( output_ctx.slot_ctx.has_fee_rate_governor ) {
    FD_TEST( output_ctx.slot_ctx.fee_rate_governor.target_lamports_per_signature ==
             input_ctx.slot_ctx.fee_rate_governor.target_lamports_per_signature );
    FD_TEST( output_ctx.slot_ctx.fee_rate_governor.target_signatures_per_slot ==
             input_ctx.slot_ctx.fee_rate_governor.target_signatures_per_slot );
    FD_TEST( output_ctx.slot_ctx.fee_rate_governor.min_lamports_per_signature ==
             input_ctx.slot_ctx.fee_rate_governor.min_lamports_per_signature );
    FD_TEST( output_ctx.slot_ctx.fee_rate_governor.max_lamports_per_signature ==
             input_ctx.slot_ctx.fee_rate_governor.max_lamports_per_signature );
    FD_TEST( output_ctx.slot_ctx.fee_rate_governor.burn_percent ==
             input_ctx.slot_ctx.fee_rate_governor.burn_percent );
  }

  /* Verify parent signature count */
  FD_TEST( output_ctx.slot_ctx.parent_signature_count == input_ctx.slot_ctx.parent_signature_count );

  /* Verify blockhash queue */
  if( input_ctx.blockhash_queue_count>0U || output_ctx.blockhash_queue_count>0U ) {
    FD_TEST( output_ctx.blockhash_queue_count==input_ctx.blockhash_queue_count );
    for( pb_size_t i=0U; i<output_ctx.blockhash_queue_count; i++ ) {
      FD_TEST( output_ctx.blockhash_queue[i]->size==input_ctx.blockhash_queue[i]->size );
      FD_TEST( !memcmp( output_ctx.blockhash_queue[i]->bytes,
                        input_ctx.blockhash_queue[i]->bytes,
                        output_ctx.blockhash_queue[i]->size ) );
    }
  }

  /* Verify account states */
  FD_TEST( output_ctx.acct_states_count==input_ctx.acct_states_count );
  /* For each output account, find the matching input account */
  for( pb_size_t out_idx=0U; out_idx<output_ctx.acct_states_count; out_idx++ ) {
    fd_exec_test_acct_state_t const * out_acct = &output_ctx.acct_states[out_idx];

    /* Find matching input account */
    fd_exec_test_acct_state_t const * in_acct = NULL;
    for( pb_size_t in_idx=0U; in_idx<input_ctx.acct_states_count; in_idx++ ) {
      if( !memcmp( out_acct->address, input_ctx.acct_states[in_idx].address, 32 ) ) {
        in_acct = &input_ctx.acct_states[in_idx];
        break;
      }
    }

    FD_TEST( in_acct );  /* Output account must exist in input */

    /* Verify account fields match */
    FD_TEST( out_acct->lamports==in_acct->lamports );
    FD_TEST( out_acct->executable==in_acct->executable );
    FD_TEST( !memcmp( out_acct->owner, in_acct->owner, 32 ) );

    /* Verify data */
    if( in_acct->data != NULL && out_acct->data != NULL ) {
      FD_TEST( out_acct->data->size==in_acct->data->size );
      FD_TEST( !memcmp( out_acct->data->bytes, in_acct->data->bytes, out_acct->data->size ) );
    } else {
      FD_TEST( in_acct->data==out_acct->data );
    }
  }

  /* Verify vote_accounts_t_1 (vote accounts at epoch T-1) */
  FD_TEST( output_ctx.epoch_ctx.vote_accounts_t_1_count == input_ctx.epoch_ctx.vote_accounts_t_1_count );
  for( pb_size_t i=0U; i<output_ctx.epoch_ctx.vote_accounts_t_1_count; i++ ) {
    fd_exec_test_vote_account_t const * in_vote  = &input_ctx.epoch_ctx.vote_accounts_t_1[i];
    fd_exec_test_vote_account_t const * out_vote = &output_ctx.epoch_ctx.vote_accounts_t_1[i];

    FD_TEST( out_vote->has_vote_account==in_vote->has_vote_account );
    if( !out_vote->has_vote_account ) continue;

    /* Verify vote account address */
    FD_TEST( !memcmp( out_vote->vote_account.address, in_vote->vote_account.address, 32 ) );

    /* Verify vote account lamports */
    FD_TEST( out_vote->vote_account.lamports==in_vote->vote_account.lamports );

    /* Verify vote account data */
    FD_TEST( out_vote->vote_account.data->size==in_vote->vote_account.data->size );
    FD_TEST( !memcmp( out_vote->vote_account.data->bytes,
                      in_vote->vote_account.data->bytes,
                      out_vote->vote_account.data->size ) );

    /* Verify vote account executable flag */
    FD_TEST( out_vote->vote_account.executable==in_vote->vote_account.executable );

    /* Verify vote account owner */
    FD_TEST( !memcmp( out_vote->vote_account.owner, in_vote->vote_account.owner, 32 ) );

    /* Verify stake */
    FD_TEST( out_vote->stake==in_vote->stake );
  }

  /* Verify vote_accounts_t_2 (vote accounts at epoch T-2) */
  FD_TEST( output_ctx.epoch_ctx.vote_accounts_t_2_count == input_ctx.epoch_ctx.vote_accounts_t_2_count );
  for( pb_size_t i=0U; i<output_ctx.epoch_ctx.vote_accounts_t_2_count; i++ ) {
    fd_exec_test_vote_account_t const * in_vote  = &input_ctx.epoch_ctx.vote_accounts_t_2[i];
    fd_exec_test_vote_account_t const * out_vote = &output_ctx.epoch_ctx.vote_accounts_t_2[i];

    FD_TEST( out_vote->has_vote_account==in_vote->has_vote_account );
    if( !out_vote->has_vote_account ) continue;

    /* Verify vote account address */
    FD_TEST( !memcmp( out_vote->vote_account.address, in_vote->vote_account.address, 32 ) );

    /* Verify vote account lamports */
    FD_TEST( out_vote->vote_account.lamports == in_vote->vote_account.lamports );

    /* Verify vote account data */
    FD_TEST( out_vote->vote_account.data->size == in_vote->vote_account.data->size );
    FD_TEST( !memcmp( out_vote->vote_account.data->bytes,
                      in_vote->vote_account.data->bytes,
                      out_vote->vote_account.data->size ) );

    /* Verify vote account executable flag */
    FD_TEST( out_vote->vote_account.executable == in_vote->vote_account.executable );

    /* Verify vote account owner */
    FD_TEST( !memcmp( out_vote->vote_account.owner, in_vote->vote_account.owner, 32 ) );

    /* Verify stake */
    FD_TEST( out_vote->stake == in_vote->stake );
  }

  /* Verify all transaction fields match (if we have transactions) */
  FD_TEST( output_ctx.txns_count==input_ctx.txns_count );
  for( pb_size_t txn_idx=0U; txn_idx<output_ctx.txns_count; txn_idx++ ) {
    fd_exec_test_sanitized_transaction_t const * in_txn  = &input_ctx.txns[txn_idx];
    fd_exec_test_sanitized_transaction_t const * out_txn = &output_ctx.txns[txn_idx];

    /* Verify message hash */
    FD_TEST( !memcmp( out_txn->message_hash, in_txn->message_hash, 32 ) );

    /* Verify signatures */
    FD_TEST( out_txn->signatures_count == in_txn->signatures_count );
    for( pb_size_t sig_idx=0U; sig_idx<out_txn->signatures_count; sig_idx++ ) {
      FD_TEST( !memcmp( out_txn->signatures[sig_idx]->bytes,
                        in_txn->signatures[sig_idx]->bytes, 64 ) );
    }

    /* Verify message exists */
    FD_TEST( out_txn->has_message == in_txn->has_message );
    if( !out_txn->has_message ) continue;

    /* Verify message header */
    FD_TEST( out_txn->message.has_header==in_txn->message.has_header );
    FD_TEST( out_txn->message.header.num_required_signatures ==
             in_txn->message.header.num_required_signatures );
    FD_TEST( out_txn->message.header.num_readonly_signed_accounts ==
             in_txn->message.header.num_readonly_signed_accounts );
    FD_TEST( out_txn->message.header.num_readonly_unsigned_accounts ==
             in_txn->message.header.num_readonly_unsigned_accounts );

    /* Verify is_legacy flag */
    FD_TEST( out_txn->message.is_legacy == in_txn->message.is_legacy );

    /* Verify account keys */
    FD_TEST( out_txn->message.account_keys_count == in_txn->message.account_keys_count );
    for( pb_size_t key_idx = 0; key_idx < out_txn->message.account_keys_count; key_idx++ ) {
      FD_TEST( out_txn->message.account_keys[key_idx]->size ==
                in_txn->message.account_keys[key_idx]->size );
      FD_TEST( !memcmp( out_txn->message.account_keys[key_idx]->bytes,
                        in_txn->message.account_keys[key_idx]->bytes,
                        32 ) );
    }

    /* Verify recent blockhash */
    FD_TEST( out_txn->message.recent_blockhash->size ==
              in_txn->message.recent_blockhash->size );
    FD_TEST( !memcmp( out_txn->message.recent_blockhash->bytes,
                      in_txn->message.recent_blockhash->bytes,
                      32 ) );

    /* Verify instructions */
    FD_TEST( out_txn->message.instructions_count == in_txn->message.instructions_count );
    for( pb_size_t instr_idx=0U; instr_idx<out_txn->message.instructions_count; instr_idx++ ) {
      fd_exec_test_compiled_instruction_t const * in_instr  = &in_txn->message.instructions[instr_idx];
      fd_exec_test_compiled_instruction_t const * out_instr = &out_txn->message.instructions[instr_idx];

      /* Verify program_id_index */
      FD_TEST( out_instr->program_id_index == in_instr->program_id_index );

      /* Verify accounts */
      FD_TEST( out_instr->accounts_count == in_instr->accounts_count );
      for( pb_size_t acc_idx=0U; acc_idx<out_instr->accounts_count; acc_idx++ ) {
        FD_TEST( out_instr->accounts[acc_idx] == in_instr->accounts[acc_idx] );
      }

      /* Verify instruction data */
      FD_TEST( out_instr->data->size==in_instr->data->size );
      FD_TEST( !memcmp( out_instr->data->bytes,
                        in_instr->data->bytes,
                        out_instr->data->size ) );
    }

    /* Verify address table lookups (for v0 transactions) */
    FD_TEST( out_txn->message.address_table_lookups_count ==
              in_txn->message.address_table_lookups_count );
    for( pb_size_t lut_idx=0U; lut_idx<out_txn->message.address_table_lookups_count; lut_idx++ ) {
      fd_exec_test_message_address_table_lookup_t const * in_lut  =
        &in_txn->message.address_table_lookups[lut_idx];
      fd_exec_test_message_address_table_lookup_t const * out_lut =
        &out_txn->message.address_table_lookups[lut_idx];

      /* Verify account key */
      FD_TEST( !memcmp( out_lut->account_key, in_lut->account_key, 32 ) );

      /* Verify writable indexes */
      FD_TEST( out_lut->writable_indexes_count==in_lut->writable_indexes_count );
      for( pb_size_t i=0U; i<out_lut->writable_indexes_count; i++ ) {
        FD_TEST( out_lut->writable_indexes[i]==in_lut->writable_indexes[i] );
      }

      /* Verify readonly indexes */
      FD_TEST( out_lut->readonly_indexes_count==in_lut->readonly_indexes_count );
      for( pb_size_t i=0U; i<out_lut->readonly_indexes_count; i++ ) {
        FD_TEST( out_lut->readonly_indexes[i] == in_lut->readonly_indexes[i] );
      }
    }
  }

  /* Clean up - delete the output file */
  if( unlink( output_path ) ) {
    FD_LOG_WARNING(( "Failed to delete output file: %s", output_path ));
  }

  FD_LOG_NOTICE(( "PASS: %s", test_name ));

  free( output_buf );
} FD_SPAD_FRAME_END;
}

/* Main test entry point */
int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  /* Set up test fixture */
  test_ctx_t * test_ctx = test_ctx_setup();
  FD_TEST( test_ctx );

  /* Run tests */
  test_block_round_trip( test_ctx, normal_block_ctx, normal_block_ctx_sz, "test_dump_block_with_transactions" );
  test_block_round_trip( test_ctx, epoch_boundary_block_ctx, epoch_boundary_block_ctx_sz, "test_dump_block_epoch_boundary" );

  /* Clean up */
  test_ctx_teardown( test_ctx );

  FD_LOG_NOTICE(( "All tests passed!" ));
  fd_halt();
  return 0;
}

