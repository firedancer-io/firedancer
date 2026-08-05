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
#include "fd_pubkey_utils.h"
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
  ulong lamports = 0UL;
  fd_accdb_probe_pd_this_fork( env->runtime->accdb, env->fork_id, env->programdata.uc, &pd, &len, &lamports );
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

/* Cross-txn bundle cases (SIMD-0186 loaded-accounts-data-size).  Each
   runs [ txn1: mutates D or P , txn2: lists P but not D ] both as a
   bundle and sequentially, and requires the two to agree.  The bundle
   path binds D per txn against the shared pool; the sequential path
   rebuilds it from accdb.  Anything an earlier bundle txn did to P or D
   must land the same way on both. */

struct pd_fields {
  ulong loaded_sz;
  int   txn_err;
  int   exec_err;
  ulong exe_cnt;
  ulong skip_cnt;
  ulong skip_len; /* ULONG_MAX when skip_cnt==0 */
};
typedef struct pd_fields pd_fields_t;

static void
pd_fields_capture( pd_fields_t * f, fd_txn_out_t const * o ) {
  f->loaded_sz = o->details.loaded_accounts_data_size;
  f->txn_err   = o->err.txn_err;
  f->exec_err  = o->err.exec_err;
  f->exe_cnt   = o->accounts.executable_cnt;
  f->skip_cnt  = o->accounts.executable_skipped_cnt;
  f->skip_len  = f->skip_cnt ? o->accounts.executable_skipped_len[0] : ULONG_MAX;
}

/* pd_fields_assert_same requires the same answer by the same route.
   Comparing only loaded_sz would let a wrong-arm binding pass whenever
   the two arms happen to produce the same number. */

static void
pd_fields_assert_same( char const *        what,
                       pd_fields_t const * b,
                       pd_fields_t const * s,
                       ulong               expect ) {
  FD_LOG_NOTICE(( "%s: bundle sz=%lu exe=%lu skip=%lu/%lu | sequential sz=%lu exe=%lu skip=%lu/%lu",
                  what, b->loaded_sz, b->exe_cnt, b->skip_cnt, b->skip_len,
                  s->loaded_sz, s->exe_cnt, s->skip_cnt, s->skip_len ));
  FD_TEST( s->loaded_sz==expect     );
  FD_TEST( b->loaded_sz==s->loaded_sz );
  FD_TEST( b->txn_err  ==s->txn_err   );
  FD_TEST( b->exec_err ==s->exec_err  );
  FD_TEST( b->exe_cnt  ==s->exe_cnt   );
  FD_TEST( b->skip_cnt ==s->skip_cnt  );
  FD_TEST( b->skip_len ==s->skip_len  );
}

/* find_pool_acc returns the txn's copy of key, NULL if undeclared. */

static fd_acc_t const *
find_pool_acc( fd_txn_out_t const * o, fd_pubkey_t const * key ) {
  for( ushort j=0; j<o->accounts.cnt; j++ ) {
    if( !memcmp( o->accounts.keys[j].uc, key->uc, 32UL ) ) return o->accounts.account[j];
  }
  return NULL;
}

/* run_pair executes [ mutate , invoke ] and captures the invoke's
   accounting.  bundle!=0 runs them the way fd_execle_tile:handle_bundle
   does: one prepare, shared pool, execute both, then commit both.  mid
   runs after the mutate, and asserts whatever precondition the case
   depends on so it cannot pass vacuously. */

typedef void (*pd_mid_fn)( test_env_t * env, int bundle );

static void
run_pair( test_env_t *  env,
          fd_txn_p_t *  mutate,
          fd_txn_p_t *  invoke,
          int           bundle,
          pd_mid_fn     mid,
          pd_fields_t * f ) {
  if( !bundle ) {
    fd_txn_out_t * o = exec_single( env, mutate );
    FD_TEST( o->err.is_committable );
    FD_TEST( o->err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
    mid( env, 0 );
    pd_fields_capture( f, exec_single( env, invoke ) );
    return;
  }

  fd_txn_p_t * txns[2] = { mutate, invoke };
  fd_txn_in_t  in[2];
  for( ulong i=0UL; i<2UL; i++ ) {
    in[i]                     = (fd_txn_in_t){0};
    in[i].txn                 = txns[i];
    in[i].bundle.is_bundle    = 1;
    in[i].bundle.prev_txn_cnt = i;
    for( ulong j=0UL; j<i; j++ ) in[i].bundle.prev_txn_outs[j] = &env->txn_out[j];
  }
  FD_TEST( fd_runtime_prepare_bundle_accounts( env->runtime, env->bank, in, env->txn_out, 2UL )
           ==FD_RUNTIME_EXECUTE_SUCCESS );

  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &in[0], &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  mid( env, 1 );

  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &in[1], &env->txn_out[1] );
  pd_fields_capture( f, &env->txn_out[1] );

  for( ulong i=0UL; i<2UL; i++ ) {
    if( FD_LIKELY( env->txn_out[i].err.is_committable ) ) fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[i], 0 );
    else                                                  fd_runtime_cancel_txn( env->runtime, NULL, NULL, &env->txn_out[i], 0 );
  }
  fd_runtime_fini_bundle( env->runtime );
}

/* ------------------------------------------------------------------ */

static const fd_pubkey_t test_buffer_key = { .ul = { 0xb0ffe4UL } };

/* setup_env_undeployed lays down the pre-deploy world: P a loader-owned
   zeroed SIZE_OF_PROGRAM account (Uninitialized), D the real loader PDA
   of P and absent on both forks, and a Buffer holding the ELF.  P is
   loader-owned rather than system-owned because the deploy's Program{D}
   set_state write requires it; Uninitialized parses as !=Program either
   way, which is what makes the prebind skip the P->D derivation. */

static void
setup_env_undeployed( test_env_t * env, fd_svm_mini_t * mini ) {
  setup_env( env, mini );

  fd_accdb_t * accdb = env->runtime->accdb;

  /* Re-point P at a fresh key and derive D as its loader PDA; the
     deploy checks find_program_address( loader, [P] )==D.  setup_env's
     P/D pair stays behind under other keys, unreferenced. */
  env->program = (fd_pubkey_t){ .ul = { 0x50524f47554e4445UL } };
  uchar const * seeds[1]; seeds[0] = env->program.uc;
  ulong seed_sz    = sizeof(fd_pubkey_t);
  uchar bump_seed  = 0;
  uint  custom_err = 0U;
  FD_TEST( !fd_pubkey_find_program_address( &fd_solana_bpf_loader_upgradeable_program_id, 1UL,
                                            seeds, &seed_sz, &env->programdata, &bump_seed, &custom_err ) );
  env->pd_dlen = PROGRAMDATA_METADATA_SIZE + test_elf_sz;

  uchar uninit[ SIZE_OF_PROGRAM ] = {0};
  put_account( accdb, env->parent_fork, &env->program,
               fd_rent_exempt_minimum_balance( &env->bank->f.rent, SIZE_OF_PROGRAM ),
               uninit, SIZE_OF_PROGRAM,
               &fd_solana_bpf_loader_upgradeable_program_id, 0 );

  ulong   buffer_dlen = BUFFER_METADATA_SIZE + test_elf_sz;
  uchar * buffer_data = malloc( buffer_dlen );
  FD_TEST( buffer_data );
  fd_bpf_state_t buffer_state = {
    .discriminant = FD_BPF_STATE_BUFFER,
    .inner.buffer = {
      .authority_address     = env->authority,
      .has_authority_address = 1,
    },
  };
  ulong out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &buffer_state, buffer_data, BUFFER_METADATA_SIZE, &out_sz ) );
  memcpy( buffer_data+BUFFER_METADATA_SIZE, test_elf, test_elf_sz );
  put_account( accdb, env->parent_fork, &test_buffer_key,
               fd_rent_exempt_minimum_balance( &env->bank->f.rent, buffer_dlen ),
               buffer_data, buffer_dlen,
               &fd_solana_bpf_loader_upgradeable_program_id, 0 );
  free( buffer_data );

  /* The payer funds D's rent-exempt balance. */
  put_account( accdb, env->parent_fork, &env->payer, 10000000000UL, NULL, 0UL, &fd_solana_system_program_id, 0 );
}

/* Instruction account order per fd_bpf_loader_program.c
   FD_BPF_INSTR_DEPLOY_WITH_MAX_DATA_LEN: payer, programdata, program,
   buffer, rent, clock, system, authority. */

static void
build_deploy_txn( test_env_t * env, fd_txn_p_t * out ) {
  struct __attribute__((packed)) { uint discriminant; ulong max_data_len; } instr_data =
    { FD_BPF_INSTR_DEPLOY_WITH_MAX_DATA_LEN, test_elf_sz };
  fd_pubkey_t const * accts[8] = { &env->payer, &env->programdata, &env->program, &test_buffer_key,
                                   &fd_sysvar_rent_id, &fd_sysvar_clock_id,
                                   &fd_solana_system_program_id, &env->authority };
  uint                cats [8] = { FD_TXN_ACCT_CAT_WRITABLE|FD_TXN_ACCT_CAT_SIGNER,
                                   FD_TXN_ACCT_CAT_WRITABLE,
                                   FD_TXN_ACCT_CAT_WRITABLE,
                                   FD_TXN_ACCT_CAT_WRITABLE,
                                   0U, 0U, 0U,
                                   FD_TXN_ACCT_CAT_SIGNER };
  build_loader_txn( env, out, (uchar const *)&instr_data, sizeof(instr_data), accts, cats, 8UL );
}

/* pd_child_only_funded kills D on the parent and recreates it live on
   the child fork only, as a deploy earlier in this slot would leave it.
   Both paths then route through the size-only skipped arm. */

static void
pd_child_only_funded( test_env_t * env ) {
  fd_accdb_t * accdb = env->runtime->accdb;

  {
    fd_acc_t acc = fd_accdb_write_one( accdb, env->parent_fork, env->programdata.uc );
    acc.lamports = 0UL;
    acc.data_len = 0UL;
    acc.commit   = 1;
    fd_accdb_unwrite_one( accdb, &acc );
  }
  FD_TEST( !fd_accdb_exists( accdb, env->parent_fork, env->programdata.uc ) );

  fd_acc_t acc = fd_accdb_write_one( accdb, env->fork_id, env->programdata.uc );
  fd_bpf_state_t pd_state = {
    .discriminant = FD_BPF_STATE_PROGRAM_DATA,
    .inner.program_data = {
      .slot                          = TEST_PARENT_SLOT-1UL,
      .upgrade_authority_address     = env->authority,
      .has_upgrade_authority_address = 1,
    },
  };
  ulong out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &pd_state, acc.data, PROGRAMDATA_METADATA_SIZE, &out_sz ) );
  memcpy( acc.data+PROGRAMDATA_METADATA_SIZE, test_elf, test_elf_sz );
  acc.data_len = env->pd_dlen;
  acc.lamports = fd_rent_exempt_minimum_balance( &env->bank->f.rent, env->pd_dlen );
  memcpy( acc.owner, fd_solana_bpf_loader_upgradeable_program_id.key, 32UL );
  acc.commit   = 1;
  fd_accdb_unwrite_one( accdb, &acc );
}

/* ------------------------------------------------------------------ */

/* Case 11 (in-bundle deploy -> unlisted P): at prebind P is still
   Uninitialized, so the P->D derivation is skipped and D lands in
   neither executable[] nor executable_skipped_*[].  At execution
   fd_collect_loaded_account re-reads the live pool copy of P, which
   txn1's deploy mutated, derives D and must still count it.  Binding
   once up front charged 0 here. */

static void
deploy_mid( test_env_t * env, int bundle ) {
  if( bundle ) {
    fd_acc_t const * p = find_pool_acc( &env->txn_out[0], &env->program     );
    fd_acc_t const * d = find_pool_acc( &env->txn_out[0], &env->programdata );
    FD_TEST( p ); FD_TEST( d );
    fd_bpf_state_t st[1];
    FD_TEST( fd_bpf_loader_program_get_state( p, st )==FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( st->discriminant==FD_BPF_STATE_PROGRAM );
    FD_TEST( !memcmp( st->inner.program.programdata_address.uc, env->programdata.uc, 32UL ) );
    FD_TEST( d->data_len==env->pd_dlen );
  } else {
    int   pd = 0; ulong len = ULONG_MAX; ulong lamports = 0UL;
    FD_TEST( fd_accdb_probe_pd_this_fork( env->runtime->accdb, env->fork_id, env->programdata.uc, &pd, &len, &lamports ) );
    FD_TEST( len==env->pd_dlen );
  }
}

static void
test_bundle_deploy_size_counted2( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  pd_fields_t b[1], s[1];

  setup_env_undeployed( env, mini );
  fd_txn_p_t deploy[1]; build_deploy_txn ( env, deploy );
  fd_txn_p_t invoke[1]; build_invoke_txn ( env, invoke );
  run_pair( env, deploy, invoke, 1, deploy_mid, b );

  setup_env_undeployed( env, mini );
  build_deploy_txn( env, deploy );
  build_invoke_txn( env, invoke );
  run_pair( env, deploy, invoke, 0, deploy_mid, s );

  /* payer + P, plus the implied D. */
  pd_fields_assert_same( "in-bundle deploy -> unlisted P", b, s,
                      3UL*FD_TRANSACTION_ACCOUNT_BASE_SIZE + SIZE_OF_PROGRAM
                      + PROGRAMDATA_METADATA_SIZE + test_elf_sz );
  FD_LOG_NOTICE(( "bundle in-bundle deploy size counted... ok" ));
}

/* Case 12 (in-bundle revive -> unlisted P): a transfer resurrects a
   parent-dead D, so D is in the pool but not live on the parent.  Both
   paths must take the skipped arm and charge nothing, since the revived
   D is still zero length. */

static void
revive_mid( test_env_t * env, int bundle ) {
  if( bundle ) {
    fd_acc_t const * d = find_pool_acc( &env->txn_out[0], &env->programdata );
    FD_TEST( d );
    FD_TEST( d->lamports>0UL );
    FD_TEST( d->data_len==0UL );
  } else {
    int   pd = 0; ulong len = ULONG_MAX; ulong lamports = 0UL;
    FD_TEST( fd_accdb_probe_pd_this_fork( env->runtime->accdb, env->fork_id, env->programdata.uc, &pd, &len, &lamports ) );
    FD_TEST( lamports>0UL );
    FD_TEST( len==0UL );
  }
}

static void
setup_revive( test_env_t * env, fd_svm_mini_t * mini, fd_txn_p_t * xfer, fd_txn_p_t * invoke ) {
  setup_env( env, mini );
  fd_accdb_t * accdb = env->runtime->accdb;
  fd_acc_t acc = fd_accdb_write_one( accdb, env->parent_fork, env->programdata.uc );
  acc.lamports = 0UL;
  acc.data_len = 0UL;
  acc.commit   = 1;
  fd_accdb_unwrite_one( accdb, &acc );
  FD_TEST( !fd_accdb_exists( accdb, env->parent_fork, env->programdata.uc ) );

  build_transfer_txn( env, xfer, &env->programdata, fd_rent_exempt_minimum_balance( &env->bank->f.rent, 0UL ) );
  build_invoke_txn  ( env, invoke );
}

static void
test_bundle_revive_pd_size_counted( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  pd_fields_t b[1], s[1];
  fd_txn_p_t xfer[1], invoke[1];

  setup_revive( env, mini, xfer, invoke );
  run_pair( env, xfer, invoke, 1, revive_mid, b );

  setup_revive( env, mini, xfer, invoke );
  run_pair( env, xfer, invoke, 0, revive_mid, s );

  pd_fields_assert_same( "in-bundle revive -> unlisted P", b, s,
                      2UL*FD_TRANSACTION_ACCOUNT_BASE_SIZE + SIZE_OF_PROGRAM );
  FD_LOG_NOTICE(( "bundle revive-pd size counted... ok" ));
}

/* Case 13 (in-bundle close -> unlisted P): the two paths hold a dead D
   in different shapes.  Close leaves the pool copy at zero lamports with
   data_len still SIZE_OF_UNINITIALIZED, since nothing normalizes it
   mid-bundle, while the sequential replay probes a committed record that
   fd_runtime_lthash_account normalized to length 0.  Without the
   liveness test in fd_runtime_setup_bundle_executables the bundle charges
   FD_TRANSACTION_ACCOUNT_BASE_SIZE+SIZE_OF_UNINITIALIZED extra. */

static void
close_mid( test_env_t * env, int bundle ) {
  if( bundle ) {
    fd_acc_t const * d = find_pool_acc( &env->txn_out[0], &env->programdata );
    FD_TEST( d );
    FD_TEST( d->lamports==0UL );
    FD_TEST( d->data_len==SIZE_OF_UNINITIALIZED ); /* dead, not normalized */
  } else {
    int   pd = 0; ulong len = ULONG_MAX; ulong lamports = ULONG_MAX;
    FD_TEST( fd_accdb_probe_pd_this_fork( env->runtime->accdb, env->fork_id, env->programdata.uc, &pd, &len, &lamports ) );
    FD_TEST( lamports==0UL );
    FD_TEST( len==0UL ); /* commit normalized it */
  }
}

static void
setup_close( test_env_t * env, fd_svm_mini_t * mini, fd_txn_p_t * close, fd_txn_p_t * invoke ) {
  static const fd_pubkey_t recipient = { .ul = { 0xc105ec1UL } };
  setup_env( env, mini );
  pd_child_only_funded( env );

  uint instr_data = FD_BPF_INSTR_CLOSE;
  fd_pubkey_t const * accts[4] = { &env->programdata, &recipient, &env->authority, &env->program };
  uint                cats [4] = { FD_TXN_ACCT_CAT_WRITABLE, FD_TXN_ACCT_CAT_WRITABLE,
                                   FD_TXN_ACCT_CAT_SIGNER,   FD_TXN_ACCT_CAT_WRITABLE };
  build_loader_txn( env, close, (uchar const *)&instr_data, sizeof(instr_data), accts, cats, 4UL );
  build_invoke_txn( env, invoke );
}

static void
test_bundle_close_pd_size_counted( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  pd_fields_t b[1], s[1];
  fd_txn_p_t close[1], invoke[1];

  setup_close( env, mini, close, invoke );
  run_pair( env, close, invoke, 1, close_mid, b );

  setup_close( env, mini, close, invoke );
  run_pair( env, close, invoke, 0, close_mid, s );

  pd_fields_assert_same( "in-bundle close -> unlisted P", b, s,
                      2UL*FD_TRANSACTION_ACCOUNT_BASE_SIZE + SIZE_OF_PROGRAM );
  FD_LOG_NOTICE(( "bundle close-pd size counted... ok" ));
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
  test_bundle_deploy_size_counted2  ( mini );
  test_bundle_revive_pd_size_counted( mini );
  test_bundle_close_pd_size_counted ( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
