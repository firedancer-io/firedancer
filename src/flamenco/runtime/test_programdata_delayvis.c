/* test_programdata_delayvis: same-block cross-txn conformance for the
   implicit-programdata parent-fork fix (PROGRAMDATA_PLAN.md §8.3).

   A txn invoking upgradeable program P does not list P's programdata D,
   so the executor acquires D read-only from the frozen PARENT fork and
   the loader's DelayVisibility check gates on the accdb pd_write probe
   instead of D's program_data.slot (which a parent copy cannot have
   updated).  These tests drive real transactions through
   fd_runtime_prepare_and_execute_txn / fd_runtime_prepare_bundle_accounts
   on a parent+child fork pair and assert the exact Agave-equivalent
   outcomes (UnsupportedProgramId + "Program is not deployed" for
   deploy-status changes this slot; success otherwise). */

#include "tests/fd_svm_mini.h"
#include "fd_runtime.h"
#include "fd_bank.h"
#include "fd_executor.h"
#include "fd_system_ids.h"
#include "fd_executor_err.h"
#include "fd_runtime_err.h"
#include "program/fd_bpf_loader_program.h"
#include "sysvar/fd_sysvar_rent.h"
#include "../accdb/fd_accdb.h"
#include "../features/fd_features.h"
#include "../../disco/fd_txn_p.h"
#include "../../ballet/txn/fd_txn_build.h"

#include <stdlib.h>

FD_IMPORT_BINARY( test_elf, "src/ballet/sbpf/fixtures/hello_solana_program.so" );

#define TEST_SLOTS_PER_EPOCH (32UL)
#define TEST_PARENT_SLOT     (9UL)
#define TEST_CHILD_SLOT      (10UL)

struct test_env {
  fd_svm_mini_t *    mini;
  fd_bank_t *        parent_bank;
  fd_bank_t *        bank;         /* child (executing) */
  fd_accdb_fork_id_t parent_fork;
  fd_accdb_fork_id_t fork_id;      /* child */
  fd_runtime_t *     runtime;
  fd_txn_in_t        txn_in;
  fd_txn_out_t       txn_out[ 5UL ];

  fd_pubkey_t payer;
  fd_pubkey_t authority;
  fd_pubkey_t program;
  fd_pubkey_t programdata;
  ulong       pd_dlen;             /* programdata account data length */
};
typedef struct test_env test_env_t;

static void
put_account( fd_accdb_t *        accdb,
             fd_accdb_fork_id_t  fork_id,
             fd_pubkey_t const * pubkey,
             ulong               lamports,
             uchar const *       data,
             ulong               dlen,
             fd_pubkey_t const * owner,
             int                 executable ) {
  fd_acc_t acc = fd_accdb_write_one( accdb, fork_id, pubkey->key );
  if( data && dlen ) memcpy( acc.data, data, dlen );
  acc.data_len   = dlen;
  acc.lamports   = lamports;
  acc.executable = executable;
  memcpy( acc.owner, owner->key, 32UL );
  acc.commit = 1;
  fd_accdb_unwrite_one( accdb, &acc );
}

/* setup_env resets svm_mini and lays down a valid upgradeable program
   (P executable -> D with hello_solana ELF, deployed at parent slot-1)
   on the ROOT (= parent) fork, then attaches the executing child. */

static void
setup_env( test_env_t * env, fd_svm_mini_t * mini ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->mini    = mini;
  env->runtime = mini->runtime;

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch = TEST_SLOTS_PER_EPOCH;
  params->root_slot       = TEST_PARENT_SLOT;
  ulong root_idx = fd_svm_mini_reset( mini, params );
  env->parent_bank = fd_svm_mini_bank( mini, root_idx );
  env->parent_fork = env->parent_bank->accdb_fork_id;

  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, TEST_CHILD_SLOT );
  env->bank    = fd_svm_mini_bank( mini, child_idx );
  env->fork_id = fd_svm_mini_fork_id( mini, child_idx );

  fd_features_enable_cleaned_up( &env->bank->f.features );

  fd_blockhashes_t * bhq = fd_blockhashes_init( &env->bank->f.block_hash_queue, 12345UL );
  fd_hash_t dummy_hash = {0};
  fd_memset( dummy_hash.uc, 0xAB, FD_HASH_FOOTPRINT );
  fd_blockhash_info_t * info = fd_blockhashes_push_new( bhq, &dummy_hash );
  info->lamports_per_signature = 0UL;

  env->payer       = (fd_pubkey_t){ .ul = { 0xfee10001UL } };
  env->authority   = (fd_pubkey_t){ .ul = { 0xa07401UL } };
  env->program     = (fd_pubkey_t){ .ul = { 0x50524f4752414dUL } };
  env->programdata = (fd_pubkey_t){ .ul = { 0x50524f4744415441UL } };

  fd_accdb_t * accdb = env->runtime->accdb;

  put_account( accdb, env->parent_fork, &env->payer,     1000000000UL, NULL, 0UL, &fd_solana_system_program_id, 0 );
  put_account( accdb, env->parent_fork, &env->authority, 1000000000UL, NULL, 0UL, &fd_solana_system_program_id, 0 );

  /* Program account: Program{ programdata_address = D } */
  uchar program_data[ SIZE_OF_PROGRAM ];
  fd_bpf_state_t program_state = {
    .discriminant = FD_BPF_STATE_PROGRAM,
    .inner.program.programdata_address = env->programdata,
  };
  ulong out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &program_state, program_data, sizeof(program_data), &out_sz ) );
  put_account( accdb, env->parent_fork, &env->program,
               fd_rent_exempt_minimum_balance( &env->bank->f.rent, sizeof(program_data) ),
               program_data, sizeof(program_data),
               &fd_solana_bpf_loader_upgradeable_program_id, 1 );

  /* Programdata: ProgramData{ slot = parent-1, authority } + ELF */
  env->pd_dlen = PROGRAMDATA_METADATA_SIZE + test_elf_sz;
  uchar * pd_data = malloc( env->pd_dlen );
  FD_TEST( pd_data );
  fd_bpf_state_t pd_state = {
    .discriminant = FD_BPF_STATE_PROGRAM_DATA,
    .inner.program_data = {
      .slot                          = TEST_PARENT_SLOT-1UL,
      .upgrade_authority_address     = env->authority,
      .has_upgrade_authority_address = 1,
    },
  };
  out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &pd_state, pd_data, PROGRAMDATA_METADATA_SIZE, &out_sz ) );
  memcpy( pd_data+PROGRAMDATA_METADATA_SIZE, test_elf, test_elf_sz );
  put_account( accdb, env->parent_fork, &env->programdata,
               fd_rent_exempt_minimum_balance( &env->bank->f.rent, env->pd_dlen ),
               pd_data, env->pd_dlen,
               &fd_solana_bpf_loader_upgradeable_program_id, 0 );
  free( pd_data );
}

/* Txn builders (real serialized txns through the production parser) */

static void
build_invoke_txn( test_env_t * env, fd_txn_p_t * out ) {
  fd_hash_t const * rbh = fd_blockhashes_peek_last_hash( &env->bank->f.block_hash_queue );
  FD_TEST( rbh );
  fd_txn_builder_t b[1];
  FD_TEST( fd_txn_builder_new( b, 4UL ) );
  FD_TEST( fd_txn_builder_fee_payer_set( b, &env->payer ) );
  fd_txn_builder_blockhash_set( b, rbh );
  FD_TEST( fd_txn_builder_instr_open( b, &env->program, NULL, 0UL ) );
  fd_txn_builder_instr_close( b );
  fd_memset( out, 0, sizeof(fd_txn_p_t) );
  FD_TEST( fd_txn_build_p( b, out ) );
  out->pack_cu.non_execution_cus                 = 1000U;
  out->pack_cu.requested_exec_plus_acct_data_cus = 300000U;
  fd_txn_builder_delete( b );
}

static void
build_loader_txn( test_env_t *  env,
                  fd_txn_p_t *  out,
                  uchar const * instr_data,
                  ulong         instr_data_sz,
                  fd_pubkey_t const * const * accts,
                  uint const *  cats,
                  ulong         acct_cnt ) {
  fd_hash_t const * rbh = fd_blockhashes_peek_last_hash( &env->bank->f.block_hash_queue );
  FD_TEST( rbh );
  fd_txn_builder_t b[1];
  FD_TEST( fd_txn_builder_new( b, 4UL ) );
  FD_TEST( fd_txn_builder_fee_payer_set( b, &env->payer ) );
  fd_txn_builder_blockhash_set( b, rbh );
  FD_TEST( fd_txn_builder_instr_open( b, &fd_solana_bpf_loader_upgradeable_program_id, instr_data, instr_data_sz ) );
  for( ulong i=0UL; i<acct_cnt; i++ ) FD_TEST( fd_txn_builder_instr_account_push( b, accts[i], cats[i] ) );
  fd_txn_builder_instr_close( b );
  fd_memset( out, 0, sizeof(fd_txn_p_t) );
  FD_TEST( fd_txn_build_p( b, out ) );
  out->pack_cu.non_execution_cus                 = 1000U;
  out->pack_cu.requested_exec_plus_acct_data_cus = 1400000U;
  fd_txn_builder_delete( b );
}

static void
build_transfer_txn( test_env_t * env, fd_txn_p_t * out, fd_pubkey_t const * to, ulong lamports ) {
  fd_hash_t const * rbh = fd_blockhashes_peek_last_hash( &env->bank->f.block_hash_queue );
  FD_TEST( rbh );
  struct __attribute__((packed)) { uint discriminant; ulong lamports; } data = { 2U, lamports };
  fd_txn_builder_t b[1];
  FD_TEST( fd_txn_builder_new( b, 4UL ) );
  FD_TEST( fd_txn_builder_fee_payer_set( b, &env->payer ) );
  fd_txn_builder_blockhash_set( b, rbh );
  FD_TEST( fd_txn_builder_instr_open( b, &fd_solana_system_program_id, &data, sizeof(data) ) );
  FD_TEST( fd_txn_builder_instr_account_push( b, &env->payer, FD_TXN_ACCT_CAT_WRITABLE|FD_TXN_ACCT_CAT_SIGNER ) );
  FD_TEST( fd_txn_builder_instr_account_push( b, to, FD_TXN_ACCT_CAT_WRITABLE ) );
  fd_txn_builder_instr_close( b );
  fd_memset( out, 0, sizeof(fd_txn_p_t) );
  FD_TEST( fd_txn_build_p( b, out ) );
  out->pack_cu.non_execution_cus                 = 1000U;
  out->pack_cu.requested_exec_plus_acct_data_cus = 300000U;
  fd_txn_builder_delete( b );
}

/* exec_single runs one non-bundle txn on the child bank and commits or
   cancels it based on committability.  Returns the txn_out used. */

static fd_txn_out_t *
exec_single( test_env_t * env, fd_txn_p_t * txn ) {
  fd_memset( &env->txn_in, 0, sizeof(env->txn_in) );
  env->txn_in.txn = txn;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  if( FD_LIKELY( env->txn_out[0].err.is_committable ) ) {
    fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
  } else {
    fd_runtime_cancel_txn( env->runtime, NULL, NULL, &env->txn_out[0], 0 );
  }
  return &env->txn_out[0];
}

/* assert_invoke_not_deployed: the invoke must fail with the loader's
   DelayVisibility outcome: InstructionError + UnsupportedProgramId. */

static void
assert_invoke_not_deployed( fd_txn_out_t const * o ) {
  FD_TEST( o->err.is_committable );
  FD_TEST( o->err.txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR );
  FD_TEST( o->err.exec_err==FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID );
}

static void
assert_invoke_success( fd_txn_out_t const * o ) {
  FD_TEST( o->err.is_committable );
  FD_TEST( o->err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
}

/* pd_write_committed_on_child: probe oracle for mark-site verification */

static int
pd_write_committed_on_child( test_env_t * env ) {
  int   pd  = 0;
  ulong len = ULONG_MAX;
  fd_accdb_probe_pd_this_fork( env->runtime->accdb, env->fork_id, env->programdata.uc, &pd, &len );
  return pd;
}

/* upgrade_sim commits a deploy-status change of D on the child fork the
   way an Upgrade commit lands in accdb: new bytes + pd_write=1.  Used
   for the Deploy/Upgrade gate cases (the mark path itself is covered
   end-to-end by the real Extend/Close txns below). */

static void
upgrade_sim( test_env_t * env ) {
  fd_accdb_t * accdb = env->runtime->accdb;
  fd_acc_t acc = fd_accdb_write_one( accdb, env->fork_id, env->programdata.uc );
  fd_bpf_state_t pd_state = {
    .discriminant = FD_BPF_STATE_PROGRAM_DATA,
    .inner.program_data = {
      .slot                          = TEST_CHILD_SLOT,
      .upgrade_authority_address     = env->authority,
      .has_upgrade_authority_address = 1,
    },
  };
  ulong out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &pd_state, acc.data, PROGRAMDATA_METADATA_SIZE, &out_sz ) );
  memcpy( acc.data+PROGRAMDATA_METADATA_SIZE, test_elf, test_elf_sz );
  acc.data_len = env->pd_dlen;
  acc.commit   = 1;
  acc.pd_write = 1;
  fd_accdb_unwrite_one( accdb, &acc );
}

/* ------------------------------------------------------------------ */

/* Case: no same-slot mutation -> invoke succeeds off the parent copy. */
static void
test_invoke_baseline( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_env( env, mini );
  fd_txn_p_t txn[1];
  build_invoke_txn( env, txn );
  assert_invoke_success( exec_single( env, txn ) );
  FD_LOG_NOTICE(( "invoke baseline (no same-slot write)... ok" ));
}

/* Case 2 (upgrade -> invoke) via upgrade_sim: probe sees gen-match +
   pd_write -> "Program is not deployed", old bytes never executed. */
static void
test_upgrade_then_invoke( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_env( env, mini );
  upgrade_sim( env );
  fd_txn_p_t txn[1];
  build_invoke_txn( env, txn );
  assert_invoke_not_deployed( exec_single( env, txn ) );
  FD_LOG_NOTICE(( "upgrade -> invoke rejected... ok" ));
}

/* Case 6 (lamport credit -> invoke): a plain transfer write-locks D but
   is not a deploy-status change -> pd_write=0 -> invoke succeeds.  This
   is exactly the racing-writer shape from the original bug report; with
   the parent-fork read it is now both crash-free and Agave-equivalent. */
static void
test_lamport_credit_then_invoke( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_env( env, mini );
  fd_txn_p_t txn[1];
  build_transfer_txn( env, txn, &env->programdata, 1UL );
  fd_txn_out_t * o = exec_single( env, txn );
  FD_TEST( o->err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !pd_write_committed_on_child( env ) );
  build_invoke_txn( env, txn );
  assert_invoke_success( exec_single( env, txn ) );
  FD_LOG_NOTICE(( "lamport credit -> invoke succeeds... ok" ));
}

/* Case 5 (setauthority -> invoke): real SetAuthority txn; writes D but
   does not change deploy status -> no pd_write -> invoke succeeds. */
static void
test_setauthority_then_invoke( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_env( env, mini );

  fd_pubkey_t new_authority = { .ul = { 0xa07402UL } };
  uint instr_data = FD_BPF_INSTR_SET_AUTHORITY;
  fd_pubkey_t const * accts[3] = { &env->programdata, &env->authority, &new_authority };
  uint                cats [3] = { FD_TXN_ACCT_CAT_WRITABLE, FD_TXN_ACCT_CAT_SIGNER, 0U };
  fd_txn_p_t txn[1];
  build_loader_txn( env, txn, (uchar const *)&instr_data, sizeof(instr_data), accts, cats, 3UL );
  fd_txn_out_t * o = exec_single( env, txn );
  FD_TEST( o->err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !pd_write_committed_on_child( env ) ); /* SetAuthority must NOT set the bit */

  build_invoke_txn( env, txn );
  assert_invoke_success( exec_single( env, txn ) );
  FD_LOG_NOTICE(( "setauthority -> invoke succeeds... ok" ));
}

/* Case 4 (close -> invoke): real Close txn (the fails-open case: the
   parent copy is still funded and would pass the legacy slot check, so
   the pd_write bit is the only defense).  Asserts the Close mark-site
   fired and the invoke fails. */
static void
test_close_then_invoke( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_env( env, mini );

  fd_pubkey_t recipient = { .ul = { 0x1ec1b1e47UL } };
  uint instr_data = FD_BPF_INSTR_CLOSE;
  fd_pubkey_t const * accts[4] = { &env->programdata, &recipient, &env->authority, &env->program };
  uint                cats [4] = { FD_TXN_ACCT_CAT_WRITABLE, FD_TXN_ACCT_CAT_WRITABLE, FD_TXN_ACCT_CAT_SIGNER, FD_TXN_ACCT_CAT_WRITABLE };
  fd_txn_p_t txn[1];
  build_loader_txn( env, txn, (uchar const *)&instr_data, sizeof(instr_data), accts, cats, 4UL );
  fd_txn_out_t * o = exec_single( env, txn );
  FD_TEST( o->err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( pd_write_committed_on_child( env ) ); /* Close mark-site fired */

  build_invoke_txn( env, txn );
  assert_invoke_not_deployed( exec_single( env, txn ) );
  FD_LOG_NOTICE(( "close -> invoke rejected (mark fired)... ok" ));
}

/* Case 3 (extend -> invoke): real ExtendProgram txn through
   common_extend_program (mark-site end-to-end); Agave DelayVisibility-
   fails a same-slot-extended program.  Also case 12 direction 1: the
   invoke's loaded-account-size must count the EXTENDED size (probe
   data_len), not the smaller parent size. */
static void
test_extend_then_invoke( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_env( env, mini );

  ulong const additional = 4096UL;
  struct __attribute__((packed)) { uint discriminant; uint additional_bytes; } instr_data =
    { FD_BPF_INSTR_EXTEND_PROGRAM, (uint)additional };
  fd_pubkey_t const * accts[4] = { &env->programdata, &env->program, &fd_solana_system_program_id, &env->payer };
  uint                cats [4] = { FD_TXN_ACCT_CAT_WRITABLE, FD_TXN_ACCT_CAT_WRITABLE, 0U, FD_TXN_ACCT_CAT_WRITABLE|FD_TXN_ACCT_CAT_SIGNER };
  fd_txn_p_t txn[1];
  build_loader_txn( env, txn, (uchar const *)&instr_data, sizeof(instr_data), accts, cats, 4UL );
  fd_txn_out_t * o = exec_single( env, txn );
  FD_TEST( o->err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( pd_write_committed_on_child( env ) ); /* Extend mark-site fired */

  build_invoke_txn( env, txn );
  o = exec_single( env, txn );
  assert_invoke_not_deployed( o );
  /* case 12: base sizes for payer + program + the programdata counted at
     its EXTENDED length */
  ulong expect = 3UL*FD_TRANSACTION_ACCOUNT_BASE_SIZE
               + SIZE_OF_PROGRAM
               + env->pd_dlen + additional;
  FD_TEST( o->details.loaded_accounts_data_size==expect );
  FD_LOG_NOTICE(( "extend -> invoke rejected, extended size counted... ok" ));
}

/* Case 1 (deploy -> invoke): D does not exist on the parent fork at all
   -> exists(parent) skips it -> get_executable_account NULL -> same
   "not deployed" error.  Also case 12 direction 3: Agave still counts
   the current-fork size, via the skipped-key probe. */
static void
test_deploy_then_invoke( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_env( env, mini );

  /* Erase D from the parent (leave P pointing at it), then deploy-sim D
     on the child only. */
  fd_accdb_t * accdb = env->runtime->accdb;
  {
    fd_acc_t acc = fd_accdb_write_one( accdb, env->parent_fork, env->programdata.uc );
    acc.lamports = 0UL;
    acc.data_len = 0UL;
    acc.commit   = 1;
    fd_accdb_unwrite_one( accdb, &acc );
  }
  upgrade_sim( env ); /* the child-fork deploy: full D contents + pd_write */

  fd_txn_p_t txn[1];
  build_invoke_txn( env, txn );
  fd_txn_out_t * o = exec_single( env, txn );
  assert_invoke_not_deployed( o );
  /* case 12: payer + program bases + skipped-key programdata size */
  ulong expect = 3UL*FD_TRANSACTION_ACCOUNT_BASE_SIZE
               + SIZE_OF_PROGRAM
               + env->pd_dlen;
  FD_TEST( o->details.loaded_accounts_data_size==expect );
  FD_LOG_NOTICE(( "deploy -> invoke rejected, size counted via skipped probe... ok" ));
}

/* Case 7 (mutation on the PARENT slot, invoke on the child): the
   parent-committed version has gen(P) != gen(C) -> probe gen-mismatch ->
   bit ignored -> invoke succeeds (Agave: effective_slot = P+1 <= C). */
static void
test_parent_slot_upgrade_then_invoke( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_env( env, mini );

  /* Commit a pd_write=1 version of D on the PARENT fork (models an
     upgrade that landed in the parent block). */
  fd_accdb_t * accdb = env->runtime->accdb;
  fd_acc_t acc = fd_accdb_write_one( accdb, env->parent_fork, env->programdata.uc );
  fd_bpf_state_t pd_state = {
    .discriminant = FD_BPF_STATE_PROGRAM_DATA,
    .inner.program_data = {
      .slot                          = TEST_PARENT_SLOT,
      .upgrade_authority_address     = env->authority,
      .has_upgrade_authority_address = 1,
    },
  };
  ulong out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &pd_state, acc.data, PROGRAMDATA_METADATA_SIZE, &out_sz ) );
  memcpy( acc.data+PROGRAMDATA_METADATA_SIZE, test_elf, test_elf_sz );
  acc.data_len = env->pd_dlen;
  acc.commit   = 1;
  acc.pd_write = 1;
  fd_accdb_unwrite_one( accdb, &acc );

  fd_txn_p_t txn[1];
  build_invoke_txn( env, txn );
  assert_invoke_success( exec_single( env, txn ) );
  FD_LOG_NOTICE(( "parent-slot upgrade -> child invoke succeeds... ok" ));
}

/* Case 8 (listed provenance): the invoke txn LISTS D, so the loader
   reads the current-fork copy and keeps the legacy slot check -- a
   same-slot program_data.slot rejects even without the bit. */
static void
test_listed_programdata_slot_check( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_env( env, mini );

  /* Same-slot mutation, but WITHOUT pd_write (bit path disabled): only
     the listed-path slot check can reject. */
  fd_accdb_t * accdb = env->runtime->accdb;
  fd_acc_t acc = fd_accdb_write_one( accdb, env->fork_id, env->programdata.uc );
  fd_bpf_state_t pd_state = {
    .discriminant = FD_BPF_STATE_PROGRAM_DATA,
    .inner.program_data = {
      .slot                          = TEST_CHILD_SLOT,
      .upgrade_authority_address     = env->authority,
      .has_upgrade_authority_address = 1,
    },
  };
  ulong out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &pd_state, acc.data, PROGRAMDATA_METADATA_SIZE, &out_sz ) );
  memcpy( acc.data+PROGRAMDATA_METADATA_SIZE, test_elf, test_elf_sz );
  acc.data_len = env->pd_dlen;
  acc.commit   = 1;
  fd_accdb_unwrite_one( accdb, &acc );

  /* Invoke listing D read-only -> current-fork copy -> slot check. */
  fd_hash_t const * rbh = fd_blockhashes_peek_last_hash( &env->bank->f.block_hash_queue );
  fd_txn_builder_t b[1];
  FD_TEST( fd_txn_builder_new( b, 4UL ) );
  FD_TEST( fd_txn_builder_fee_payer_set( b, &env->payer ) );
  fd_txn_builder_blockhash_set( b, rbh );
  FD_TEST( fd_txn_builder_instr_open( b, &env->program, NULL, 0UL ) );
  FD_TEST( fd_txn_builder_instr_account_push( b, &env->programdata, 0U ) );
  fd_txn_builder_instr_close( b );
  fd_txn_p_t txn[1];
  fd_memset( txn, 0, sizeof(fd_txn_p_t) );
  FD_TEST( fd_txn_build_p( b, txn ) );
  txn->pack_cu.non_execution_cus                 = 1000U;
  txn->pack_cu.requested_exec_plus_acct_data_cus = 300000U;
  fd_txn_builder_delete( b );

  assert_invoke_not_deployed( exec_single( env, txn ) );
  FD_LOG_NOTICE(( "listed programdata -> legacy slot check rejects... ok" ));
}

/* Case 10 (bundle, cross-txn unlisted invoke after a same-slot
   deploy-status change): the R2-CRITICAL-1 case.  The bundle binding
   must classify the acquire_b copy as parent provenance -> bit gate ->
   rejected.  Under the broken discriminator this executed old bytes. */
static void
test_bundle_upgrade_gate( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_env( env, mini );
  upgrade_sim( env );

  fd_txn_p_t invoke[1];
  build_invoke_txn( env, invoke );

  fd_txn_in_t prep_in[1] = {0};
  prep_in[0].txn              = invoke;
  prep_in[0].bundle.is_bundle = 1;
  fd_runtime_prepare_bundle_accounts( env->runtime, env->bank, prep_in, env->txn_out, 1UL );

  fd_memset( &env->txn_in, 0, sizeof(env->txn_in) );
  env->txn_in.txn              = invoke;
  env->txn_in.bundle.is_bundle = 1;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  assert_invoke_not_deployed( &env->txn_out[0] );

  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
  fd_runtime_fini_bundle( env->runtime );
  FD_LOG_NOTICE(( "bundle unlisted invoke after upgrade rejected... ok" ));
}

/* Bundle variant of the deploy-this-slot case: D has no parent copy so
   the bundle pd scan skips it, but Agave still counts its current-fork
   size toward loaded-accounts-data-size before the invoke fails. */
static void
test_bundle_deploy_size_counted( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_env( env, mini );

  fd_accdb_t * accdb = env->runtime->accdb;
  {
    fd_acc_t acc = fd_accdb_write_one( accdb, env->parent_fork, env->programdata.uc );
    acc.lamports = 0UL;
    acc.data_len = 0UL;
    acc.commit   = 1;
    fd_accdb_unwrite_one( accdb, &acc );
  }
  upgrade_sim( env ); /* the child-fork deploy */

  fd_txn_p_t invoke[1];
  build_invoke_txn( env, invoke );

  fd_txn_in_t prep_in[1] = {0};
  prep_in[0].txn              = invoke;
  prep_in[0].bundle.is_bundle = 1;
  fd_runtime_prepare_bundle_accounts( env->runtime, env->bank, prep_in, env->txn_out, 1UL );

  fd_memset( &env->txn_in, 0, sizeof(env->txn_in) );
  env->txn_in.txn              = invoke;
  env->txn_in.bundle.is_bundle = 1;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  assert_invoke_not_deployed( &env->txn_out[0] );
  ulong expect = 3UL*FD_TRANSACTION_ACCOUNT_BASE_SIZE
               + SIZE_OF_PROGRAM
               + env->pd_dlen;
  FD_TEST( env->txn_out[0].details.loaded_accounts_data_size==expect );

  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
  fd_runtime_fini_bundle( env->runtime );
  FD_LOG_NOTICE(( "bundle deploy-this-slot size counted... ok" ));
}

/* Bundle control: no same-slot mutation -> bundle invoke succeeds off
   the parent-fork binding. */
static void
test_bundle_invoke_baseline( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_env( env, mini );

  fd_txn_p_t invoke[1];
  build_invoke_txn( env, invoke );

  fd_txn_in_t prep_in[1] = {0};
  prep_in[0].txn              = invoke;
  prep_in[0].bundle.is_bundle = 1;
  fd_runtime_prepare_bundle_accounts( env->runtime, env->bank, prep_in, env->txn_out, 1UL );

  fd_memset( &env->txn_in, 0, sizeof(env->txn_in) );
  env->txn_in.txn              = invoke;
  env->txn_in.bundle.is_bundle = 1;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  assert_invoke_success( &env->txn_out[0] );

  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
  fd_runtime_fini_bundle( env->runtime );
  FD_LOG_NOTICE(( "bundle invoke baseline... ok" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_invoke_baseline              ( mini );
  test_upgrade_then_invoke          ( mini );
  test_lamport_credit_then_invoke   ( mini );
  test_setauthority_then_invoke     ( mini );
  test_close_then_invoke            ( mini );
  test_extend_then_invoke           ( mini );
  test_deploy_then_invoke           ( mini );
  test_parent_slot_upgrade_then_invoke( mini );
  test_listed_programdata_slot_check( mini );
  test_bundle_upgrade_gate          ( mini );
  test_bundle_deploy_size_counted   ( mini );
  test_bundle_invoke_baseline       ( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
