/* Test for SIMD-0312: create_account_allow_prefund */

#include "../tests/fd_svm_mini.h"
#include "../../accdb/fd_accdb.h"
#include "../fd_system_ids.h"
#include "../../features/fd_features.h"
#include "../../../disco/fd_txn_p.h"

#define TEST_SLOTS_PER_EPOCH      (32UL)
#define TEST_SLOT                 (10UL)
#define TEST_LAMPORTS             (100000000000UL)

static fd_pubkey_t const TO_PUBKEY = {{
  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
}};

static fd_pubkey_t const FROM_PUBKEY = {{
  0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
  0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
  0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
  0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
}};

static fd_pubkey_t const OWNER_PUBKEY = {{
  0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
  0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
  0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
  0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
}};

struct test_env {
  fd_svm_mini_t *    mini;
  fd_bank_t *        bank;
  fd_accdb_fork_id_t fork_id;
  fd_txn_p_t         txn_p[1];
  fd_txn_in_t        txn_in[1];
  fd_txn_out_t       txn_out[1];
};
typedef struct test_env test_env_t;

static void
create_account_raw( fd_accdb_t *        accdb,
                    fd_accdb_fork_id_t  fork_id,
                    fd_pubkey_t const * pubkey,
                    ulong               lamports,
                    uint                dlen,
                    uchar *             data,
                    fd_pubkey_t const * owner ) {
  fd_accdb_entry_t entry = fd_accdb_write_one( accdb, fork_id, pubkey->key );
  if( data && dlen ) memcpy( entry.data, data, dlen );
  entry.data_len   = dlen;
  entry.lamports   = lamports;
  entry.executable = 0;
  if( owner ) memcpy( entry.owner, owner->key, 32UL );
  else        memset( entry.owner, 0,          32UL );
  entry.commit = 1;
  fd_accdb_unwrite_one( accdb, &entry );
}

static void
setup_test( test_env_t * env, fd_svm_mini_t * mini, int enable_feature ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->mini = mini;

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch = TEST_SLOTS_PER_EPOCH;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, TEST_SLOT );
  env->bank = fd_svm_mini_bank( mini, child_idx );
  env->fork_id = fd_svm_mini_fork_id( mini, child_idx );

  fd_features_enable_cleaned_up( &env->bank->f.features );
  if( enable_feature ) {
    FD_FEATURE_SET_ACTIVE( &env->bank->f.features, create_account_allow_prefund, 0UL );
  }
}

/* Build a legacy transaction containing a single CreateAccountAllowPrefund
   instruction (discriminant 13).

   num_ix_accts controls how many accounts the instruction references:
     0 — no accounts (for testing missing-account errors)
     1 — to only     (for lamports==0 path)
     2 — to + from   (for lamports>0 path)

   When from_is_fee_payer is set, from is placed first in the
   transaction account list so it becomes the fee payer.  This is
   needed when the to-account has non-zero data or a non-system owner
   that would fail fee payer validation. */

static void
build_txn( test_env_t *        env,
           ulong               lamports,
           ulong               space,
           fd_pubkey_t const * owner,
           fd_pubkey_t const * to,
           fd_pubkey_t const * from,
           int                 to_is_signer,
           int                 from_is_signer,
           int                 from_is_fee_payer,
           int                 num_ix_accts ) {
  uchar * p     = env->txn_p->payload;
  uchar * start = p;

  int has_from    = (from != NULL);

  /* Validate invariants */
  FD_TEST( num_ix_accts>=0 && num_ix_accts<=2 );
  FD_TEST( num_ix_accts<2 || has_from );
  FD_TEST( !from_is_fee_payer || (has_from && from_is_signer) );

  int num_signers = 0;
  if( to_is_signer               ) num_signers++;
  if( has_from && from_is_signer ) num_signers++;
  if( num_signers==0             ) num_signers = 1;

  int from_first = has_from && ( ( !to_is_signer && from_is_signer ) || from_is_fee_payer );

  /* Signatures */
  *p++ = (uchar)num_signers;
  for( int i=0; i<num_signers; i++ ) {
    memset( p, 0, 64 );
    p += 64;
  }

  /* Message header */
  uchar num_accounts = (uchar)( has_from ? 3 : 2 );
  *p++ = (uchar)num_signers;
  *p++ = 0; /* num_readonly_signed */
  *p++ = 1; /* num_readonly_unsigned (system_program) */

  /* Account keys — fee payer must be first */
  *p++ = num_accounts;
  if( from_first ) {
    memcpy( p, from->key, 32 ); p += 32;
    memcpy( p, to->key,   32 ); p += 32;
  } else {
    memcpy( p, to->key, 32 ); p += 32;
    if( has_from ) { memcpy( p, from->key, 32 ); p += 32; }
  }
  memcpy( p, fd_solana_system_program_id.key, 32 ); p += 32;

  /* Recent blockhash */
  memset( p, 0xAB, 32 ); p += 32;

  /* Single instruction */
  *p++ = 1;
  *p++ = (uchar)(num_accounts - 1); /* program_id index */

  *p++ = (uchar)num_ix_accts;
  if( num_ix_accts>=1 ) {
    *p++ = from_first ? 1 : 0; /* to */
  }
  if( num_ix_accts>=2 ) {
    *p++ = from_first ? 0 : 1; /* from */
  }

  /* Instruction data: u32(13) | u64 lamports | u64 space | [u8;32] owner */
  *p++ = 52;
  uint disc = 13;
  memcpy( p, &disc,      4  ); p += 4;
  memcpy( p, &lamports,  8  ); p += 8;
  memcpy( p, &space,     8  ); p += 8;
  memcpy( p, owner->key, 32 ); p += 32;

  ulong payload_sz = (ulong)(p - start);
  env->txn_p->payload_sz = payload_sz;
  FD_TEST( fd_txn_parse( env->txn_p->payload, payload_sz, TXN(env->txn_p), NULL ) > 0 );

  env->txn_in->txn              = env->txn_p;
  env->txn_in->bundle.is_bundle = 0;
}

struct test_case {
  char const *        name;
  int                 enable_feature;

  /* to account setup */
  ulong               to_lamports;
  uint                to_dlen;
  uchar *             to_data;
  fd_pubkey_t const * to_owner;    /* NULL → system program */

  /* from account setup (NULL → no from account) */
  fd_pubkey_t const * from;
  ulong               from_lamports;
  uint                from_dlen;
  uchar *             from_data;

  /* instruction params */
  ulong               ix_lamports;
  ulong               ix_space;
  fd_pubkey_t const * ix_owner;
  int                 to_is_signer;
  int                 from_is_signer;
  int                 from_is_fee_payer;
  int                 num_ix_accts;    /* 0, 1, or 2 */

  /* expected result */
  int                 expect_success;
  int                 expect_instr_err; /* -1 → don't check */
};
typedef struct test_case test_case_t;

static void
run_test( fd_svm_mini_t * mini, test_case_t const * tc ) {
  static test_env_t env[1];
  setup_test( env, mini, tc->enable_feature );

  fd_pubkey_t const * effective_to_owner = tc->to_owner ? tc->to_owner : &fd_solana_system_program_id;
  create_account_raw( env->mini->runtime->accdb, env->fork_id, &TO_PUBKEY, tc->to_lamports, tc->to_dlen, tc->to_data, effective_to_owner );

  if( tc->from ) {
    create_account_raw( env->mini->runtime->accdb, env->fork_id, &FROM_PUBKEY, tc->from_lamports, tc->from_dlen, tc->from_data, &fd_solana_system_program_id );
  }

  build_txn( env, tc->ix_lamports, tc->ix_space, tc->ix_owner,
             &TO_PUBKEY, tc->from ? &FROM_PUBKEY : NULL,
             tc->to_is_signer, tc->from_is_signer, tc->from_is_fee_payer,
             tc->num_ix_accts );

  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );

  int ok = env->txn_out[0].err.is_committable &&
           env->txn_out[0].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS;

  if( tc->expect_success ) {
    FD_TEST( ok );
  } else {
    FD_TEST( !ok );
    if( tc->expect_instr_err >= 0 ) {
      FD_TEST( env->txn_out[0].err.exec_err == tc->expect_instr_err );
    }
  }

  FD_LOG_NOTICE(( "%s... ok", tc->name ));
}

/* Shorthands for common from-account configurations */
#define NO_FROM       NULL, 0UL, 0, NULL
#define STD_FROM      &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL

/* Shorthands for common instruction configurations */
#define STD_IX        1000UL, 100UL, &OWNER_PUBKEY
#define BOTH_SIGN     1, 1, 0, 2
#define BOTH_SIGN_FP  1, 1, 1, 2   /* from is fee payer */

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  uchar some_data[32]  = {0xFF};
  uchar from_data[16]  = {1};

  test_case_t tests[] = {

    /* Feature gate */
    { "feature_inactive",
      0, TEST_LAMPORTS, 0, NULL, NULL,
      STD_FROM, STD_IX, BOTH_SIGN,
      0, FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA },

    { "feature_active_happy_path",
      1, TEST_LAMPORTS, 0, NULL, NULL,
      STD_FROM, STD_IX, BOTH_SIGN,
      1, -1 },

    /* Account count */
    { "lamports_gt0_missing_from",
      1, TEST_LAMPORTS, 0, NULL, NULL,
      NO_FROM, STD_IX, 1, 0, 0, 1,
      0, FD_EXECUTOR_INSTR_ERR_MISSING_ACC },

    { "lamports_zero_one_account",
      1, TEST_LAMPORTS, 0, NULL, NULL,
      NO_FROM, 0UL, 100UL, &OWNER_PUBKEY, 1, 0, 0, 1,
      1, -1 },

    { "lamports_zero_missing_to",
      1, TEST_LAMPORTS, 0, NULL, NULL,
      NO_FROM, 0UL, 100UL, &OWNER_PUBKEY, 1, 0, 0, 0,
      0, FD_EXECUTOR_INSTR_ERR_MISSING_ACC },

    /* Signer checks */
    { "to_not_signer",
      1, TEST_LAMPORTS, 0, NULL, NULL,
      STD_FROM, STD_IX, 0, 1, 0, 2,
      0, -1 },

    { "from_not_signer",
      1, TEST_LAMPORTS, 0, NULL, NULL,
      STD_FROM, STD_IX, 1, 0, 0, 2,
      0, -1 },

    /* To-account state: "already in use" errors.
       from_is_fee_payer=1 so the fee payer (from) is a clean
       system-owned account — avoids fee payer validation failure. */
    { "to_has_data",
      1, TEST_LAMPORTS, 32, some_data, NULL,
      STD_FROM, STD_IX, BOTH_SIGN_FP,
      0, FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR },

    { "to_nonsystem_owner",
      1, TEST_LAMPORTS, 0, NULL, &OWNER_PUBKEY,
      STD_FROM, STD_IX, BOTH_SIGN_FP,
      0, FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR },

    { "to_data_and_nonsystem_owner",
      1, TEST_LAMPORTS, 16, some_data, &OWNER_PUBKEY,
      STD_FROM, STD_IX, BOTH_SIGN_FP,
      0, FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR },

    { "to_lamports_and_data",
      1, 500000UL, 16, some_data, NULL,
      STD_FROM, STD_IX, BOTH_SIGN_FP,
      0, FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR },

    /* Space validation */
    { "space_zero",
      1, TEST_LAMPORTS, 0, NULL, NULL,
      STD_FROM, 1000UL, 0UL, &OWNER_PUBKEY, BOTH_SIGN,
      1, -1 },

    { "space_exceeds_max",
      1, TEST_LAMPORTS, 0, NULL, NULL,
      STD_FROM, 1000UL, 10485761UL, &OWNER_PUBKEY, BOTH_SIGN,
      0, -1 },

    { "space_at_max",
      1, TEST_LAMPORTS, 0, NULL, NULL,
      STD_FROM, 1000UL, 10485760UL, &OWNER_PUBKEY, BOTH_SIGN,
      1, -1 },

    /* Owner = system program (no-op in assign) */
    { "owner_system_program",
      1, TEST_LAMPORTS, 0, NULL, NULL,
      STD_FROM, 1000UL, 100UL, &fd_solana_system_program_id, BOTH_SIGN,
      1, -1 },

    /* Transfer errors */
    { "from_insufficient_lamports",
      1, TEST_LAMPORTS, 0, NULL, NULL,
      &FROM_PUBKEY, 500UL, 0, NULL,
      STD_IX, BOTH_SIGN,
      0, -1 },

    { "from_has_data",
      1, TEST_LAMPORTS, 0, NULL, NULL,
      &FROM_PUBKEY, TEST_LAMPORTS, 16, from_data,
      STD_IX, BOTH_SIGN,
      0, -1 },

    /* Prefunded main use case: lamports=0, to already has rent */
    { "prefunded_main_use_case",
      1, 10000000UL, 0, NULL, NULL,
      NO_FROM, 0UL, 100UL, &OWNER_PUBKEY, 1, 0, 0, 1,
      1, -1 },
  };

  ulong num_tests = sizeof(tests) / sizeof(tests[0]);
  for( ulong i=0UL; i<num_tests; i++ ) {
    run_test( mini, &tests[i] );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
