#include "fd_executor.h"
#include "fd_acc_mgr.h"
#include "fd_hashes.h"
#include "fd_runtime.h"
#include "fd_runtime_err.h"

#include "context/fd_exec_slot_ctx.h"
#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"

#include "../../util/rng/fd_rng.h"
#include "fd_system_ids.h"
#include "program/fd_address_lookup_table_program.h"
#include "program/fd_bpf_loader_program.h"
#include "program/fd_loader_v4_program.h"
#include "program/fd_compute_budget_program.h"
#include "program/fd_config_program.h"
#include "program/fd_precompiles.h"
#include "program/fd_stake_program.h"
#include "program/fd_system_program.h"
#include "program/fd_builtin_programs.h"
#include "program/fd_vote_program.h"
#include "program/fd_zk_elgamal_proof_program.h"
#include "program/fd_bpf_program_util.h"
#include "sysvar/fd_sysvar_slot_history.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_instructions.h"
#include "sysvar/fd_sysvar_slot_hashes.h"
#include "sysvar/fd_sysvar_rent.h"

#include "tests/fd_dump_pb.h"

#include "../../ballet/base58/fd_base58.h"
#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"

#include "../../util/bits/fd_uwide.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>   /* snprintf(3) */
#include <fcntl.h>   /* openat(2) */
#include <unistd.h>  /* write(3) */
#include <time.h>

struct fd_native_prog_info {
  fd_pubkey_t key;
  fd_exec_instr_fn_t fn;
  uchar is_bpf_loader;
};
typedef struct fd_native_prog_info fd_native_prog_info_t;

#define MAP_PERFECT_NAME fd_native_program_fn_lookup_tbl
#define MAP_PERFECT_LG_TBL_SZ 4
#define MAP_PERFECT_T fd_native_prog_info_t
#define MAP_PERFECT_HASH_C 478U
#define MAP_PERFECT_KEY key.uc
#define MAP_PERFECT_KEY_T fd_pubkey_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u))>>28)&0xFU)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a08 | (a09<<8) | (a10<<16) | (a11<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr + 8UL ) )

#define MAP_PERFECT_0       ( VOTE_PROG_ID            ), .fn = fd_vote_program_execute,                      .is_bpf_loader = 0
#define MAP_PERFECT_1       ( SYS_PROG_ID             ), .fn = fd_system_program_execute,                    .is_bpf_loader = 0
#define MAP_PERFECT_2       ( CONFIG_PROG_ID          ), .fn = fd_config_program_execute,                    .is_bpf_loader = 0
#define MAP_PERFECT_3       ( STAKE_PROG_ID           ), .fn = fd_stake_program_execute,                     .is_bpf_loader = 0
#define MAP_PERFECT_4       ( COMPUTE_BUDGET_PROG_ID  ), .fn = fd_compute_budget_program_execute,            .is_bpf_loader = 0
#define MAP_PERFECT_5       ( ADDR_LUT_PROG_ID        ), .fn = fd_address_lookup_table_program_execute,      .is_bpf_loader = 0
#define MAP_PERFECT_6       ( ZK_EL_GAMAL_PROG_ID     ), .fn = fd_executor_zk_elgamal_proof_program_execute, .is_bpf_loader = 0
#define MAP_PERFECT_7       ( BPF_LOADER_1_PROG_ID    ), .fn = fd_bpf_loader_program_execute,                .is_bpf_loader = 1
#define MAP_PERFECT_8       ( BPF_LOADER_2_PROG_ID    ), .fn = fd_bpf_loader_program_execute,                .is_bpf_loader = 1
#define MAP_PERFECT_9       ( BPF_UPGRADEABLE_PROG_ID ), .fn = fd_bpf_loader_program_execute,                .is_bpf_loader = 1
#define MAP_PERFECT_10      ( LOADER_V4_PROG_ID       ), .fn = fd_loader_v4_program_execute,                 .is_bpf_loader = 1

#include "../../util/tmpl/fd_map_perfect.c"
#undef PERFECT_HASH

#define MAP_PERFECT_NAME fd_native_precompile_program_fn_lookup_tbl
#define MAP_PERFECT_LG_TBL_SZ 2
#define MAP_PERFECT_T fd_native_prog_info_t
#define MAP_PERFECT_HASH_C 63546U
#define MAP_PERFECT_KEY key.uc
#define MAP_PERFECT_KEY_T fd_pubkey_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u))>>30)&0x3U)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a00 | (a01<<8)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_2( (uchar const *)ptr ) )

#define MAP_PERFECT_0      ( ED25519_SV_PROG_ID      ), .fn = fd_precompile_ed25519_verify
#define MAP_PERFECT_1      ( KECCAK_SECP_PROG_ID     ), .fn = fd_precompile_secp256k1_verify
#define MAP_PERFECT_2      ( SECP256R1_PROG_ID       ), .fn = fd_precompile_secp256r1_verify

#include "../../util/tmpl/fd_map_perfect.c"
#undef PERFECT_HASH

fd_exec_instr_fn_t
fd_executor_lookup_native_precompile_program( fd_txn_account_t const * prog_acc ) {
  fd_pubkey_t const * pubkey                = prog_acc->pubkey;
  const fd_native_prog_info_t null_function = {0};
  return fd_native_precompile_program_fn_lookup_tbl_query( pubkey, &null_function )->fn;
}

uchar
fd_executor_pubkey_is_bpf_loader( fd_pubkey_t const * pubkey ) {
  fd_native_prog_info_t const null_function = {0};
  return fd_native_program_fn_lookup_tbl_query( pubkey, &null_function )->is_bpf_loader;
}

/* fd_executor_lookup_native_program returns the appropriate instruction processor for the given
   native program ID. Returns NULL if given ID is not a recognized native program.
   https://github.com/anza-xyz/agave/blob/v2.2.6/program-runtime/src/invoke_context.rs#L520-L544 */
static int
fd_executor_lookup_native_program( fd_txn_account_t const * prog_acc,
                                   fd_exec_txn_ctx_t *      txn_ctx,
                                   fd_exec_instr_fn_t *     native_prog_fn,
                                   uchar *                  is_precompile ) {
  /* First lookup to see if the program key is a precompile */
  *is_precompile = 0;
  *native_prog_fn = fd_executor_lookup_native_precompile_program( prog_acc );
  if( FD_UNLIKELY( *native_prog_fn!=NULL ) ) {
    *is_precompile = 1;
    return 0;
  }

  fd_pubkey_t const * pubkey = prog_acc->pubkey;
  fd_pubkey_t const * owner  = prog_acc->vt->get_owner( prog_acc );

  /* Native programs should be owned by the native loader...
     This will not be the case though once core programs are migrated to BPF. */
  int is_native_program = !memcmp( owner, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) );

  if( !is_native_program && FD_FEATURE_ACTIVE_BANK( txn_ctx->bank, remove_accounts_executable_flag_checks ) ) {
    if( FD_UNLIKELY( !fd_executor_pubkey_is_bpf_loader( owner ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
    }
  }

  fd_pubkey_t const *         lookup_pubkey = is_native_program ? pubkey : owner;

  /* Migrated programs must be executed via the corresponding BPF
     loader(s), not natively. This check is performed at the transaction
     level, but we re-check to please the instruction level (and below)
     fuzzers. */
  uchar has_migrated;
  if( FD_UNLIKELY( fd_is_migrating_builtin_program( txn_ctx, lookup_pubkey, &has_migrated ) && has_migrated ) ) {
    *native_prog_fn = NULL;
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

  fd_native_prog_info_t const null_function = {0};
  *native_prog_fn                           = fd_native_program_fn_lookup_tbl_query( lookup_pubkey, &null_function )->fn;
  return 0;
}

static int
fd_executor_is_system_nonce_account( fd_txn_account_t * account, fd_spad_t * exec_spad ) {
  if( memcmp( account->vt->get_owner( account ), fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) ) == 0 ) {
    if( !account->vt->get_data_len( account ) ) {
      return 0;
    } else {
      if( account->vt->get_data_len( account )!=FD_SYSTEM_PROGRAM_NONCE_DLEN ) {
        return -1;
      }

      int err;
      fd_nonce_state_versions_t * versions = fd_bincode_decode_spad(
          nonce_state_versions, exec_spad,
          account->vt->get_data( account ),
          account->vt->get_data_len( account ),
          &err );
      if( FD_UNLIKELY( err ) ) {
        return -1;
      }

      fd_nonce_state_t * state = NULL;
      if( fd_nonce_state_versions_is_current( versions ) ) {
        state = &versions->inner.current;
      } else {
        state = &versions->inner.legacy;
      }

      if( fd_nonce_state_is_initialized( state ) ) {
        return 1;
      }

    }
  }

  return -1;
}

/* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/svm_rent_collector.rs#L117-L136 */
static uchar
fd_executor_rent_transition_allowed( fd_rent_state_t const * pre_rent_state,
                                     fd_rent_state_t const * post_rent_state ) {
  switch( post_rent_state->discriminant ) {
    case fd_rent_state_enum_uninitialized:
    case fd_rent_state_enum_rent_exempt: {
      return 1;
    }
    case fd_rent_state_enum_rent_paying: {
      switch( pre_rent_state->discriminant ) {
        case fd_rent_state_enum_uninitialized:
        case fd_rent_state_enum_rent_exempt: {
          return 0;
        }
        case fd_rent_state_enum_rent_paying: {
          return post_rent_state->inner.rent_paying.data_size==pre_rent_state->inner.rent_paying.data_size &&
                 post_rent_state->inner.rent_paying.lamports<=pre_rent_state->inner.rent_paying.lamports;
        }
        default: {
          __builtin_unreachable();
        }
      }
    }
    default: {
      __builtin_unreachable();
    }
  }
}

/* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/svm_rent_collector.rs#L61-L77 */
static int
fd_executor_check_rent_state_with_account( fd_txn_account_t const * account,
                                           fd_rent_state_t const *  pre_rent_state,
                                           fd_rent_state_t const *  post_rent_state ) {
  if( FD_UNLIKELY( memcmp( account->pubkey->key, fd_sysvar_incinerator_id.key, sizeof(fd_pubkey_t) ) &&
                   !fd_executor_rent_transition_allowed( pre_rent_state, post_rent_state ) ) ) {
    return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
  }
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/svm_rent_collector.rs#L87-L101 */
fd_rent_state_t
fd_executor_get_account_rent_state( fd_txn_account_t const * account, fd_rent_t const * rent ) {
  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/svm_rent_collector.rs#L88-L89 */
  if( account->vt->get_lamports( account )==0UL ) {
    return (fd_rent_state_t){
      .discriminant = fd_rent_state_enum_uninitialized
    };
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/svm_rent_collector.rs#L90-L94 */
  if( account->vt->get_lamports( account )>=fd_rent_exempt_minimum_balance( rent, account->vt->get_data_len( account ) ) ) {
    return (fd_rent_state_t){
      .discriminant = fd_rent_state_enum_rent_exempt
    };
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/svm_rent_collector.rs#L95-L99 */
  return (fd_rent_state_t){
    .discriminant = fd_rent_state_enum_rent_paying,
    .inner = {
      .rent_paying = {
        .lamports = account->vt->get_lamports( account ),
        .data_size = account->vt->get_data_len( account )
      }
    }
  };
}

/* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L293-L342 */
static int
fd_validate_fee_payer( fd_txn_account_t * account,
                       fd_rent_t const *  rent,
                       ulong              fee,
                       fd_spad_t *        exec_spad ) {
  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L301-L304 */
  if( FD_UNLIKELY( account->vt->get_lamports( account )==0UL ) ) {
    return FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L305-L308 */
  int is_nonce = fd_executor_is_system_nonce_account( account, exec_spad );
  if( FD_UNLIKELY( is_nonce<0 ) ) {
    return FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_FOR_FEE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L309-L318 */
  ulong min_balance = 0UL;
  if( is_nonce ) {
    min_balance = fd_rent_exempt_minimum_balance( rent, 80 );
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L320-L327 */
  if( FD_UNLIKELY( min_balance>account->vt->get_lamports( account ) ||
                   fee>account->vt->get_lamports( account )-min_balance ) ) {
    return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L329 */
  fd_rent_state_t payer_pre_rent_state = fd_executor_get_account_rent_state( account, rent );

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L330-L332 */
  int err = account->vt->checked_sub_lamports( account, fee );
  if( FD_UNLIKELY( err!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L334 */
  fd_rent_state_t payer_post_rent_state = fd_executor_get_account_rent_state( account, rent );

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L335-L342 */
  return fd_executor_check_rent_state_with_account( account, &payer_pre_rent_state, &payer_post_rent_state );
}

static int FD_FN_UNUSED
status_check_tower( ulong slot, void * _ctx ) {
  fd_exec_txn_ctx_t * ctx = (fd_exec_txn_ctx_t *)_ctx;
  if( slot==ctx->slot ) {
    return 1;
  }

  if( fd_txncache_is_rooted_slot( ctx->status_cache, slot ) ) {
    return 1;
  }

  fd_slot_history_global_t * slot_history = fd_sysvar_slot_history_read( ctx->funk,
                                                                         ctx->funk_txn,
                                                                         ctx->spad );
  if( FD_UNLIKELY( !slot_history ) ) {
    FD_LOG_ERR(( "Unable to read and decode slot history sysvar" ));
  }

  if( fd_sysvar_slot_history_find_slot( slot_history,
                                        slot,
                                        ctx->runtime_pub_wksp ) == FD_SLOT_HISTORY_SLOT_FOUND ) {
    return 1;
  }

  return 0;
}

static int
fd_executor_check_status_cache( fd_exec_txn_ctx_t * txn_ctx ) {

  if( FD_UNLIKELY( !txn_ctx->status_cache ) ) {
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }

  fd_hash_t * blockhash = (fd_hash_t *)((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->recent_blockhash_off);

  fd_txncache_query_t curr_query;
  curr_query.blockhash = blockhash->uc;
  fd_blake3_t b3[1];

  /* Compute the blake3 hash of the transaction message
     https://github.com/anza-xyz/agave/blob/v2.1.7/sdk/program/src/message/versions/mod.rs#L159-L167 */
  fd_blake3_init( b3 );
  fd_blake3_append( b3, "solana-tx-message-v1", 20UL );
  fd_blake3_append( b3, ((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->message_off),(ulong)( txn_ctx->_txn_raw->txn_sz - txn_ctx->txn_descriptor->message_off ) );
  fd_blake3_fini( b3, &txn_ctx->blake_txn_msg_hash );
  curr_query.txnhash = txn_ctx->blake_txn_msg_hash.uc;

  // FIXME: Commenting out until txncache is fixed
  (void)curr_query;
  // int err;
  // fd_txncache_query_batch( txn_ctx->status_cache,
  //                          &curr_query,
  //                          1UL,
  //                          (void *)txn_ctx,
  //                          status_check_tower, &err );
  return 0;
}

/* https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/check_transactions.rs#L77-L141 */
static int
fd_executor_check_transaction_age_and_compute_budget_limits( fd_exec_txn_ctx_t * txn_ctx ) {
  /* Note that in Agave, although this function is called after the
     compute budget limits are sanitized, if the transaction age checks
     fail, then we return the transaction age error instead of the
     compute budget error.
     https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/check_transactions.rs#L128-L136 */
  int err = fd_check_transaction_age( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/check_transactions.rs#L103 */
  err = fd_sanitize_compute_unit_limits( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/check_transactions.rs#L61-L75 */
int
fd_executor_check_transactions( fd_exec_txn_ctx_t * txn_ctx ) {
  /* https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/check_transactions.rs#L68-L73 */
  int err = fd_executor_check_transaction_age_and_compute_budget_limits( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/check_transactions.rs#L74 */
  err = fd_executor_check_status_cache( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* `verify_transaction()` is the first function called in the
   transaction execution pipeline. It is responsible for deserializing
   the transaction, verifying the message hash (sigverify), verifying
   the precompiles, and processing compute budget instructions. We
   leave sigverify out for now to easily bypass this function's
   checks for fuzzing.

   TODO: Maybe support adding sigverify in here, and toggling it
   on/off with a flag.

   https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank.rs#L5725-L5753 */
int
fd_executor_verify_transaction( fd_exec_txn_ctx_t * txn_ctx ) {
  int err = FD_RUNTIME_EXECUTE_SUCCESS;

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L566-L569 */
  err = fd_executor_compute_budget_program_execute_instructions( txn_ctx );
  if( FD_UNLIKELY( err ) ) return err;

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

static void
fd_executor_setup_instr_infos_from_txn_instrs( fd_exec_txn_ctx_t * txn_ctx ) {
  ushort instr_cnt = txn_ctx->txn_descriptor->instr_cnt;

  /* Set up the instr infos for the transaction */
  for( ushort i=0; i<instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &txn_ctx->txn_descriptor->instr[i];
    fd_instr_info_init_from_txn_instr( &txn_ctx->instr_infos[i], txn_ctx, instr );
  }

  txn_ctx->instr_info_cnt = instr_cnt;
}

/* https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/account_loader.rs#L410-427 */
static int
accumulate_and_check_loaded_account_data_size( ulong   acc_size,
                                               ulong   requested_loaded_accounts_data_size,
                                               ulong * accumulated_account_size ) {
  *accumulated_account_size = fd_ulong_sat_add( *accumulated_account_size, acc_size );
  if( FD_UNLIKELY( *accumulated_account_size>requested_loaded_accounts_data_size ) ) {
    return FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED;
  }
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* This function contains special casing for loading and collecting rent from
   each transaction account. The logic is as follows:
     1. If the account is the instructions sysvar, then load in the compiled
        instructions from the transactions into the sysvar's data.
     2. If the account is a fee payer, then it is already loaded.
     3. Otherwise load in the account from the accounts DB. If the account is
        writable and exists, try to collect rent from it.

   https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L536-L580 */
static void
load_transaction_account( fd_exec_txn_ctx_t * txn_ctx,
                          fd_txn_account_t *  acct,
                          uchar               is_writable,
                          ulong               epoch,
                          uchar               unknown_acc ) {
  /* Handling the sysvar instructions account explictly.
     https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L544-L551 */
  if( FD_UNLIKELY( !memcmp( acct->pubkey->key, fd_sysvar_instructions_id.key, sizeof(fd_pubkey_t) ) ) ) {
    fd_sysvar_instructions_serialize_account( txn_ctx, (fd_instr_info_t const *)txn_ctx->instr_infos, txn_ctx->txn_descriptor->instr_cnt );
    return;
  }

  /* This next block calls `load_account()` which loads the account from the accounts db. If the
     account exists and is writable, collect rent from it.
     https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L552-L565 */
  if( FD_LIKELY( !unknown_acc ) ) {
    if( is_writable ) {
      txn_ctx->collected_rent += fd_runtime_collect_rent_from_account( fd_bank_epoch_schedule_query( txn_ctx->bank ),
                                                                       fd_bank_rent_query( txn_ctx->bank ),
                                                                       fd_bank_slots_per_year_get( txn_ctx->bank ),
                                                                       acct,
                                                                       epoch );
      acct->starting_lamports = acct->vt->get_lamports( acct ); /* TODO: why do we do this everywhere? */
    }
    return;
  }

  /* The rest of this function is a no-op for us since we already set up the transaction accounts
     for unknown accounts within `fd_executor_setup_accounts_for_txn()`.
     https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L566-L577 */
}

/* This big function contains a lot of logic and special casing for loading transaction accounts.
   Because of the `enable_transaction_loading_failure_fees` feature, it is imperative that we
   are conformant with Agave's logic here and reject / accept transactions here where they do.

   In the firedancer client only some of these steps are necessary because
   all of the accounts are loaded in from the accounts db into borrowed
   accounts already.

   https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L393-L534 */
int
fd_executor_load_transaction_accounts( fd_exec_txn_ctx_t * txn_ctx ) {
  ulong requested_loaded_accounts_data_size = txn_ctx->compute_budget_details.loaded_accounts_data_size_limit;

  fd_epoch_schedule_t schedule[1];
  if( FD_UNLIKELY( !fd_sysvar_epoch_schedule_read( txn_ctx->funk, txn_ctx->funk_txn, schedule ) ) ) {
    FD_LOG_ERR(( "Unable to read and decode epoch schedule sysvar" ));
  }

  ulong epoch = fd_slot_to_epoch( schedule, txn_ctx->slot, NULL );

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L429-L443 */
  for( ushort i=0; i<txn_ctx->accounts_cnt; i++ ) {
    fd_txn_account_t * acct = &txn_ctx->accounts[i];
    uchar unknown_acc = !!(fd_exec_txn_ctx_get_account_at_index( txn_ctx, i, &acct, fd_txn_account_check_exists ) ||
                            acct->vt->get_lamports( acct )==0UL);
    ulong acc_size    = unknown_acc ? 0UL : acct->vt->get_data_len( acct );
    uchar is_writable = !!(fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, i ));

    /* Collect the fee payer account separately
       https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L429-L431 */
    if( FD_UNLIKELY( i==FD_FEE_PAYER_TXN_IDX ) ) {
      /* Note that the dlen for most fee payers is 0, but we want to consider the case where the fee payer
         is a nonce account. */
      int err = accumulate_and_check_loaded_account_data_size( acc_size,
                                                               requested_loaded_accounts_data_size,
                                                               &txn_ctx->loaded_accounts_data_size );
      if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
        return err;
      }
      continue;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L435-L441 */
    load_transaction_account( txn_ctx, acct, is_writable, epoch, unknown_acc );

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L442 */
    int err = accumulate_and_check_loaded_account_data_size( acc_size,
                                                             requested_loaded_accounts_data_size,
                                                             &txn_ctx->loaded_accounts_data_size );

    if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      return err;
    }
  }

  /* TODO: Consider using a hash set (if its more performant) */
  ushort      instr_cnt             = txn_ctx->txn_descriptor->instr_cnt;
  fd_pubkey_t validated_loaders[instr_cnt];
  ushort      validated_loaders_cnt = 0;

  /* The logic below handles special casing with loading instruction accounts.
     https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L445-L525 */
  for( ushort i=0; i<instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &txn_ctx->txn_descriptor->instr[i];

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L449-L451 */
    if( FD_UNLIKELY( !memcmp( txn_ctx->account_keys[ instr->program_id ].key, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) ) ) {
      continue;
    }

    /* Mimicking `load_account()` here with 0-lamport check as well.
       https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L455-L462 */
    fd_txn_account_t * program_account = NULL;
    int err = fd_exec_txn_ctx_get_account_at_index( txn_ctx,
                                                    instr->program_id,
                                                    &program_account,
                                                    fd_txn_account_check_exists );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS || program_account->vt->get_lamports( program_account )==0UL ) ) {
      return FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L464-L471 */
    if( FD_UNLIKELY( !FD_FEATURE_ACTIVE_BANK( txn_ctx->bank, remove_accounts_executable_flag_checks ) &&
                     !program_account->vt->is_executable( program_account ) ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L474-L477 */
    if( !memcmp( program_account->vt->get_owner( program_account ), fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) ) {
      continue;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L479-L522 */
    uchar loader_seen = 0;
    for( ushort j=0; j<validated_loaders_cnt; j++ ) {
      if( !memcmp( validated_loaders[j].key, program_account->vt->get_owner( program_account ), sizeof(fd_pubkey_t) ) ) {
        /* If the owner account has already been seen, skip the owner checks
           and do not acccumulate the account size. */
        loader_seen = 1;
        break;
      }
    }
    if( loader_seen ) continue;

    /* The agave client does checks on the program account's owners as well.
       However, it is important to not do these checks multiple times as the
       total size of accounts and their owners are accumulated: duplicate owners
       should be avoided.
       https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L496-L517 */
    FD_TXN_ACCOUNT_DECL( owner_account );
    err = fd_txn_account_init_from_funk_readonly( owner_account,
                                                  program_account->vt->get_owner( program_account ),
                                                  txn_ctx->funk,
                                                  txn_ctx->funk_txn );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L520 */
      return FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
    }


    /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L502-L510 */
    if( FD_UNLIKELY( memcmp( owner_account->vt->get_owner( owner_account ), fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) ||
                     ( !FD_FEATURE_ACTIVE_BANK( txn_ctx->bank, remove_accounts_executable_flag_checks ) &&
                       !owner_account->vt->is_executable( owner_account ) ) ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION;
    }

    /* Count the owner's data in the loaded account size for program accounts.
       However, it is important to not double count repeated owners.
       https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L511-L517 */
    err = accumulate_and_check_loaded_account_data_size( owner_account->vt->get_data_len( owner_account ),
                                                         requested_loaded_accounts_data_size,
                                                         &txn_ctx->loaded_accounts_data_size );
    if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      return err;
    }

    fd_memcpy( validated_loaders[ validated_loaders_cnt++ ].key, owner_account->pubkey, sizeof(fd_pubkey_t) );
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L118 */
int
fd_executor_validate_account_locks( fd_exec_txn_ctx_t const * txn_ctx ) {
  /* Ensure the number of account keys does not exceed the transaction lock limit
     https://github.com/anza-xyz/agave/blob/v2.2.17/accounts-db/src/account_locks.rs#L121 */
  ulong tx_account_lock_limit = get_transaction_account_lock_limit( txn_ctx );
  if( FD_UNLIKELY( txn_ctx->accounts_cnt>tx_account_lock_limit ) ) {
    return FD_RUNTIME_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS;
  }

  /* Duplicate account check
     https://github.com/anza-xyz/agave/blob/v2.2.17/accounts-db/src/account_locks.rs#L123 */
  for( ushort i=0; i<txn_ctx->accounts_cnt; i++ ) {
    for( ushort j=(ushort)(i+1U); j<txn_ctx->accounts_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( &txn_ctx->account_keys[i], &txn_ctx->account_keys[j], sizeof(fd_pubkey_t) ) ) ) {
        return FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE;
      }
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.17/accounts-db/src/account_locks.rs#L124-L126 */
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.3.1/compute-budget/src/compute_budget_limits.rs#L62-L70 */
static ulong
fd_get_prioritization_fee( fd_compute_budget_details_t const * compute_budget_details ) {
  uint128 micro_lamport_fee = fd_uint128_sat_mul( compute_budget_details->compute_unit_price, compute_budget_details->compute_unit_limit );
  uint128 fee = fd_uint128_sat_add( micro_lamport_fee, MICRO_LAMPORTS_PER_LAMPORT-1UL ) / MICRO_LAMPORTS_PER_LAMPORT;
  return fee>(uint128)ULONG_MAX ? ULONG_MAX : (ulong)fee;
}

static ulong
fd_executor_lamports_per_signature( fd_fee_rate_governor_t const * fee_rate_governor ) {
  // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110
  return fee_rate_governor->target_lamports_per_signature / 2;
}

static void
fd_executor_calculate_fee( fd_exec_txn_ctx_t *  txn_ctx,
                          fd_txn_t const *      txn_descriptor,
                          fd_rawtxn_b_t const * txn_raw,
                          ulong *               ret_execution_fee,
                          ulong *               ret_priority_fee) {
  /* The execution fee is just the signature fee. The priority fee
     is calculated based on the compute budget details.
     https://github.com/anza-xyz/agave/blob/v2.3.1/fee/src/lib.rs#L66-L83 */

  // let signature_fee = Self::get_num_signatures_in_message(message) .saturating_mul(fee_structure.lamports_per_signature);
  ulong num_signatures = txn_descriptor->signature_cnt;
  for (ushort i=0; i<txn_descriptor->instr_cnt; ++i ) {
    fd_txn_instr_t const * txn_instr  = &txn_descriptor->instr[i];
    fd_pubkey_t *          program_id = &txn_ctx->account_keys[txn_instr->program_id];
    if( !memcmp(program_id->uc, fd_solana_keccak_secp_256k_program_id.key, sizeof(fd_pubkey_t)) ||
        !memcmp(program_id->uc, fd_solana_ed25519_sig_verify_program_id.key, sizeof(fd_pubkey_t)) ||
        (!memcmp(program_id->uc, fd_solana_secp256r1_program_id.key, sizeof(fd_pubkey_t)) && FD_FEATURE_ACTIVE_BANK( txn_ctx->bank, enable_secp256r1_precompile )) ) {
      if( !txn_instr->data_sz ) {
        continue;
      }
      uchar * data   = (uchar *)txn_raw->raw + txn_instr->data_off;
      num_signatures = fd_ulong_sat_add(num_signatures, (ulong)(data[0]));
    }
  }

  *ret_execution_fee = fd_executor_lamports_per_signature( fd_bank_fee_rate_governor_query( txn_ctx->bank ) ) * num_signatures;
  *ret_priority_fee  = fd_get_prioritization_fee( &txn_ctx->compute_budget_details );
}

/* This function creates a rollback account for just the fee payer. Although Agave
   also sets up rollback accounts for both the fee payer and nonce account here,
   we already set up the rollback nonce account in earlier sanitization checks. Here
   we have to capture the entire fee payer record so that if the transaction fails,
   the fee payer state can be rolled back to it's state pre-transaction, and then debited
   any transaction fees.

   Our implementation is slightly different than Agave's in several ways:
   1. The rollback nonce account has already been set up when checking the transaction age
   2. When the nonce and fee payer accounts are the same...
      - Agave copies the data from the rollback nonce account into the rollback fee payer account,
        and then uses that new fee payer account as the rollback account.
      - We simply set the rent epoch and lamports of the rollback nonce account (since the other fields
        of the account do not change)

   https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/rollback_accounts.rs#L34-L77 */
static void
fd_executor_create_rollback_fee_payer_account( fd_exec_txn_ctx_t * txn_ctx,
                                               ulong               total_fee ) {
  fd_txn_account_t * fee_payer_rec = &txn_ctx->accounts[FD_FEE_PAYER_TXN_IDX];
  fd_txn_account_t * rollback_fee_payer_rec;

  /* When setting the data of the rollback fee payer, there is an edge case where the fee payer is the nonce account.
     In this case, we can just deduct fees from the nonce account and return, because we save the nonce account in the
     commit phase anyways. */
  if( FD_UNLIKELY( txn_ctx->nonce_account_idx_in_txn==FD_FEE_PAYER_TXN_IDX ) ) {
    rollback_fee_payer_rec = txn_ctx->rollback_nonce_account;

    /* We also need to update the rent epoch because technically, Agave copies these fields
       from the fee payer account (since the rollback account does not reflect these changes yet) */
    rollback_fee_payer_rec->vt->set_rent_epoch( rollback_fee_payer_rec,
                                                fee_payer_rec->vt->get_rent_epoch( fee_payer_rec ) );
  } else {

    /* In this case, the fee payer is not equal to the nonce account (whether or not it exists).
       Load in a copy of the fee payer account from funk */
    rollback_fee_payer_rec = fd_txn_account_init( txn_ctx->rollback_fee_payer_account );
    fd_txn_account_init_from_funk_readonly( rollback_fee_payer_rec, &txn_ctx->account_keys[FD_FEE_PAYER_TXN_IDX], txn_ctx->funk, txn_ctx->funk_txn );
    memcpy( rollback_fee_payer_rec->pubkey->key, &txn_ctx->account_keys[FD_FEE_PAYER_TXN_IDX], sizeof(fd_pubkey_t) );

    /* This allocation should only ever be 104 bytes (since dlen should be 0). */
    ulong  data_len       = txn_ctx->accounts[FD_FEE_PAYER_TXN_IDX].vt->get_data_len( &txn_ctx->accounts[FD_FEE_PAYER_TXN_IDX] );
    void * fee_payer_data = fd_spad_alloc( txn_ctx->spad, FD_ACCOUNT_REC_ALIGN, sizeof(fd_account_meta_t) + data_len );
    fd_txn_account_make_mutable( rollback_fee_payer_rec, fee_payer_data, txn_ctx->spad_wksp );

    /* There's another weird edge case where if the transaction contains a nonce account, you also have
       to save the rent epoch field of the fee payer account.
       https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/rollback_accounts.rs#L68-L75 */
    if( txn_ctx->nonce_account_idx_in_txn!=ULONG_MAX ) {
      rollback_fee_payer_rec->vt->set_rent_epoch( rollback_fee_payer_rec,
                                                  fee_payer_rec->vt->get_rent_epoch( fee_payer_rec ) );
    }
  }

  /* Deduct the transaction fees from the rollback account. Because of prior checks, this should never fail. */
  if( FD_UNLIKELY( rollback_fee_payer_rec->vt->checked_sub_lamports( rollback_fee_payer_rec, total_fee ) ) ) {
    FD_LOG_ERR(( "fd_executor_create_rollback_fee_payer_account(): failed to deduct fees from rollback account" ));
  }
}

/* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L557-L634 */
int
fd_executor_validate_transaction_fee_payer( fd_exec_txn_ctx_t * txn_ctx ) {
  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L574-L580 */
  fd_txn_account_t * fee_payer_rec = NULL;
  int err = fd_exec_txn_ctx_get_account_at_index( txn_ctx,
                                                  FD_FEE_PAYER_TXN_IDX,
                                                  &fee_payer_rec,
                                                  fd_txn_account_check_fee_payer_writable );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND;
  }

  /* Collect rent from the fee payer
     https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L583-L589 */
  ulong epoch              = fd_slot_to_epoch( fd_bank_epoch_schedule_query( txn_ctx->bank ), txn_ctx->slot, NULL );
  txn_ctx->collected_rent += fd_runtime_collect_rent_from_account( fd_bank_epoch_schedule_query( txn_ctx->bank ),
                                                                  fd_bank_rent_query( txn_ctx->bank ),
                                                                  fd_bank_slots_per_year_get( txn_ctx->bank ),
                                                                  fee_payer_rec,
                                                                  epoch );

  /* Calculate transaction fees
     https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L597-L606 */
  ulong execution_fee = 0UL;
  ulong priority_fee  = 0UL;

  fd_executor_calculate_fee( txn_ctx, txn_ctx->txn_descriptor, txn_ctx->_txn_raw, &execution_fee, &priority_fee );
  ulong total_fee = fd_ulong_sat_add( execution_fee, priority_fee );

  if( !FD_FEATURE_ACTIVE_BANK( txn_ctx->bank, remove_rounding_in_fee_calculation ) ) {
    total_fee = fd_rust_cast_double_to_ulong( round( (double)total_fee ) );
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L609-L616 */
  err = fd_validate_fee_payer( fee_payer_rec, fd_bank_rent_query( txn_ctx->bank ), total_fee, txn_ctx->spad );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* Create the rollback fee payer account
     https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L620-L626 */
  fd_executor_create_rollback_fee_payer_account( txn_ctx, total_fee );

  /* Set the starting lamports (to avoid unbalanced lamports issues in instruction execution) */
  fee_payer_rec->starting_lamports = fee_payer_rec->vt->get_lamports( fee_payer_rec ); /* TODO: why do we do this everywhere? */

  txn_ctx->execution_fee = execution_fee;
  txn_ctx->priority_fee  = priority_fee;

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* Simply unpacks the account keys from the serialized transaction and sets them in the txn_ctx. */
void
fd_executor_setup_txn_account_keys( fd_exec_txn_ctx_t * txn_ctx ) {
  txn_ctx->accounts_cnt = (uchar)txn_ctx->txn_descriptor->acct_addr_cnt;
  fd_pubkey_t * tx_accs = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->acct_addr_off);

  // Set up accounts in the transaction body and perform checks
  for( ulong i = 0UL; i < txn_ctx->txn_descriptor->acct_addr_cnt; i++ ) {
    txn_ctx->account_keys[i] = tx_accs[i];
  }
}

/* Resolves any address lookup tables referenced in the transaction and adds
   them to the transaction's account keys. Returns 0 on success or if the transaction
   is a legacy transaction, and 1 on failure. */
int
fd_executor_setup_txn_alut_account_keys( fd_exec_txn_ctx_t * txn_ctx ) {
  if( txn_ctx->txn_descriptor->transaction_version == FD_TXN_V0 ) {
    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/runtime/src/bank/address_lookup_table.rs#L44-L48 */
    fd_slot_hashes_global_t const * slot_hashes_global = fd_sysvar_slot_hashes_read( txn_ctx->funk, txn_ctx->funk_txn, txn_ctx->spad );
    if( FD_UNLIKELY( !slot_hashes_global ) ) {
      return FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND;
    }

    fd_slot_hash_t * slot_hash = deq_fd_slot_hash_t_join( (uchar *)slot_hashes_global + slot_hashes_global->hashes_offset );

    fd_acct_addr_t * accts_alt = (fd_acct_addr_t *) fd_type_pun( &txn_ctx->account_keys[txn_ctx->accounts_cnt] );
    int err = fd_runtime_load_txn_address_lookup_tables( txn_ctx->txn_descriptor,
                                                         txn_ctx->_txn_raw->raw,
                                                         txn_ctx->funk,
                                                         txn_ctx->funk_txn,
                                                         txn_ctx->slot,
                                                         slot_hash,
                                                         accts_alt );
    txn_ctx->accounts_cnt += txn_ctx->txn_descriptor->addr_table_adtl_cnt;
    if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) return err;

  }
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L319-L357 */
static inline int
fd_txn_ctx_push( fd_exec_txn_ctx_t * txn_ctx,
                 fd_instr_info_t *   instr ) {
  /* Earlier checks in the permalink are redundant since Agave maintains instr stack and trace accounts separately
     https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L327-L328 */
  ulong starting_lamports_h = 0UL;
  ulong starting_lamports_l = 0UL;
  int err = fd_instr_info_sum_account_lamports( instr,
                                                txn_ctx,
                                                &starting_lamports_h,
                                                &starting_lamports_l );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  instr->starting_lamports_h = starting_lamports_h;
  instr->starting_lamports_l = starting_lamports_l;

  /* Check that the caller's lamport sum has not changed.
     https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L329-L340 */
  if( txn_ctx->instr_stack_sz>0 ) {
    /* https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L330 */
    fd_exec_instr_ctx_t const * caller_instruction_context = &txn_ctx->instr_stack[ txn_ctx->instr_stack_sz-1 ];

    /* https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L331-L332 */
    ulong original_caller_lamport_sum_h = caller_instruction_context->instr->starting_lamports_h;
    ulong original_caller_lamport_sum_l = caller_instruction_context->instr->starting_lamports_l;

    /* https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L333-L334 */
    ulong current_caller_lamport_sum_h = 0UL;
    ulong current_caller_lamport_sum_l = 0UL;
    int err = fd_instr_info_sum_account_lamports( caller_instruction_context->instr,
                                                  caller_instruction_context->txn_ctx,
                                                  &current_caller_lamport_sum_h,
                                                  &current_caller_lamport_sum_l );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    /* https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L335-L339 */
    if( FD_UNLIKELY( current_caller_lamport_sum_h!=original_caller_lamport_sum_h ||
                     current_caller_lamport_sum_l!=original_caller_lamport_sum_l ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L347-L351 */
  if( FD_UNLIKELY( txn_ctx->instr_trace_length>=FD_MAX_INSTRUCTION_TRACE_LENGTH ) ) {
    return FD_EXECUTOR_INSTR_ERR_MAX_INSN_TRACE_LENS_EXCEEDED;
  }
  txn_ctx->instr_trace_length++;

  /* https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L352-L356 */
  if( FD_UNLIKELY( txn_ctx->instr_stack_sz>=FD_MAX_INSTRUCTION_STACK_DEPTH ) ) {
    return FD_EXECUTOR_INSTR_ERR_CALL_DEPTH;
  }
  txn_ctx->instr_stack_sz++;

  /* A beloved refactor moves sysvar instructions updating to the instruction level as of v2.2.12...
     https://github.com/anza-xyz/agave/blob/v2.2.12/transaction-context/src/lib.rs#L396-L407 */
  int idx = fd_exec_txn_ctx_find_index_of_account( txn_ctx, &fd_sysvar_instructions_id );
  if( FD_UNLIKELY( idx!=-1 ) ) {
    /* https://github.com/anza-xyz/agave/blob/v2.2.12/transaction-context/src/lib.rs#L397-L400 */
    fd_txn_account_t * sysvar_instructions_account = NULL;
    err = fd_exec_txn_ctx_get_account_at_index( txn_ctx, (ushort)idx, &sysvar_instructions_account, NULL );
    if( FD_UNLIKELY( err ) ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.12/transaction-context/src/lib.rs#L401-L402 */
    if( FD_UNLIKELY( !sysvar_instructions_account->vt->try_borrow_mut( sysvar_instructions_account ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.12/transaction-context/src/lib.rs#L403-L406 */
    fd_sysvar_instructions_update_current_instr_idx( sysvar_instructions_account, (ushort)txn_ctx->current_instr_idx );
    sysvar_instructions_account->vt->drop( sysvar_instructions_account );
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* Pushes a new instruction onto the instruction stack and trace. This check loops through all instructions in the current call stack
   and checks for reentrancy violations. If successful, simply increments the instruction stack and trace size and returns. It is
   the responsibility of the caller to populate the newly pushed instruction fields, which are undefined otherwise.

   https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/program-runtime/src/invoke_context.rs#L246-L290 */
int
fd_instr_stack_push( fd_exec_txn_ctx_t *     txn_ctx,
                     fd_instr_info_t *       instr ) {
  /* Agave keeps a vector of vectors called program_indices that stores the program_id index for each instruction within the transaction.
     https://github.com/anza-xyz/agave/blob/v2.1.7/svm/src/account_loader.rs#L347-L402
     If and only if the program_id is the native loader, then the vector for respective specific instruction (account_indices) is empty.
     https://github.com/anza-xyz/agave/blob/v2.1.7/svm/src/account_loader.rs#L350-L358
     While trying to push a new instruction onto the instruction stack, if the vector for the respective instruction is empty, Agave throws UnsupportedProgramId
     https://github.com/anza-xyz/agave/blob/v2.1.7/program-runtime/src/invoke_context.rs#L253-L255
     The only way for the vector to be empty is if the program_id is the native loader, so we can a program_id check here
     */

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/program-runtime/src/invoke_context.rs#L250-L252 */
  fd_pubkey_t const * program_id_pubkey = NULL;
  int err = fd_exec_txn_ctx_get_key_of_account_at_index( txn_ctx,
                                                         instr->program_id,
                                                         &program_id_pubkey );
  if( FD_UNLIKELY( err ||
                   !memcmp( program_id_pubkey->key, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

  /* https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/program-runtime/src/invoke_context.rs#L256-L286 */
  if( txn_ctx->instr_stack_sz ) {
    /* https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/program-runtime/src/invoke_context.rs#L261-L285 */
    uchar contains = 0;
    uchar is_last  = 0;

    // Checks all previous instructions in the stack for reentrancy
    for( uchar level=0; level<txn_ctx->instr_stack_sz; level++ ) {
      fd_exec_instr_ctx_t * instr_ctx = &txn_ctx->instr_stack[level];
      // Optimization: compare program id index instead of pubkey since account keys are unique
      if( instr->program_id == instr_ctx->instr->program_id ) {
        // Reentrancy not allowed unless caller is calling itself
        if( level == txn_ctx->instr_stack_sz-1 ) {
          is_last = 1;
        }
        contains = 1;
      }
    }
    /* https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/program-runtime/src/invoke_context.rs#L282-L285 */
    if( FD_UNLIKELY( contains && !is_last ) ) {
      return FD_EXECUTOR_INSTR_ERR_REENTRANCY_NOT_ALLOWED;
    }
  }
  /* "Push" a new instruction onto the stack by simply incrementing the stack and trace size counters
     https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/program-runtime/src/invoke_context.rs#L289 */
  return fd_txn_ctx_push( txn_ctx, instr );
}

/* Pops an instruction from the instruction stack. Agave's implementation performs instruction balancing checks every time pop is called,
   but error codes returned from `pop` are only used if the program's execution was successful. Therefore, we can optimize our code by only
   checking for unbalanced instructions if the program execution was successful within fd_execute_instr.

   https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/program-runtime/src/invoke_context.rs#L293-L298 */
int
fd_instr_stack_pop( fd_exec_txn_ctx_t *       txn_ctx,
                    fd_instr_info_t const *   instr ) {
  /* https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L362-L364 */
  if( FD_UNLIKELY( txn_ctx->instr_stack_sz==0 ) ) {
    return FD_EXECUTOR_INSTR_ERR_CALL_DEPTH;
  }
  txn_ctx->instr_stack_sz--;

  /* Verify all executable accounts have no outstanding refs
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L367-L371 */
  for( ushort i=0; i<instr->acct_cnt; i++ ) {
    ushort idx_in_txn = instr->accounts[i].index_in_transaction;
    fd_txn_account_t * account = &txn_ctx->accounts[ idx_in_txn ];
    if( FD_UNLIKELY( account->vt->is_executable( account ) &&
                     account->vt->is_borrowed( account ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_OUTSTANDING;
    }
  }

  /* Verify lamports are balanced before and after instruction
     https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L366-L380 */
  ulong ending_lamports_h = 0UL;
  ulong ending_lamports_l = 0UL;
  int err = fd_instr_info_sum_account_lamports( instr,
                                                txn_ctx,
                                                &ending_lamports_h,
                                                &ending_lamports_l );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  if( FD_UNLIKELY( ending_lamports_l != instr->starting_lamports_l || ending_lamports_h != instr->starting_lamports_h ) ) {
   return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;;
}

/* This function mimics Agave's `.and(self.pop())` functionality,
   where we always pop the instruction stack no matter what the error code is.
   https://github.com/anza-xyz/agave/blob/v2.2.12/program-runtime/src/invoke_context.rs#L480 */
static inline int
fd_execute_instr_end( fd_exec_instr_ctx_t * instr_ctx,
                      fd_instr_info_t *     instr,
                      int                   instr_exec_result ) {
  int stack_pop_err = fd_instr_stack_pop( instr_ctx->txn_ctx, instr );

  /* Only report the stack pop error on success */
  if( FD_UNLIKELY( instr_exec_result==FD_EXECUTOR_INSTR_SUCCESS && stack_pop_err ) ) {
    FD_TXN_PREPARE_ERR_OVERWRITE( instr_ctx->txn_ctx );
    FD_TXN_ERR_FOR_LOG_INSTR( instr_ctx->txn_ctx, stack_pop_err, instr_ctx->txn_ctx->instr_err_idx );
    instr_exec_result = stack_pop_err;
  }

  if( FD_UNLIKELY( instr_exec_result && !instr_ctx->txn_ctx->failed_instr ) ) {
    instr_ctx->txn_ctx->failed_instr = instr_ctx;
  }

  return instr_exec_result;
}

int
fd_execute_instr( fd_exec_txn_ctx_t * txn_ctx,
                  fd_instr_info_t *   instr ) {
  FD_RUNTIME_TXN_SPAD_FRAME_BEGIN( txn_ctx->spad, txn_ctx ) {
    int instr_exec_result = fd_instr_stack_push( txn_ctx, instr );
    if( FD_UNLIKELY( instr_exec_result ) ) {
      FD_TXN_PREPARE_ERR_OVERWRITE( txn_ctx );
      FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, instr_exec_result, txn_ctx->instr_err_idx );
      return instr_exec_result;
    }

    /* `process_executable_chain()`
        https://github.com/anza-xyz/agave/blob/v2.2.12/program-runtime/src/invoke_context.rs#L512-L619 */
    fd_exec_instr_ctx_t * ctx = &txn_ctx->instr_stack[ txn_ctx->instr_stack_sz - 1 ];
    *ctx = (fd_exec_instr_ctx_t) {
      .instr     = instr,
      .txn_ctx   = txn_ctx,
    };
    fd_base58_encode_32( txn_ctx->accounts[ instr->program_id ].pubkey->uc, NULL, ctx->program_id_base58 );

    txn_ctx->instr_trace[ txn_ctx->instr_trace_length - 1 ] = (fd_exec_instr_trace_entry_t) {
      .instr_info = instr,
      .stack_height = txn_ctx->instr_stack_sz,
    };

    /* Look up the native program. We check for precompiles within the lookup function as well.
       https://github.com/anza-xyz/agave/blob/v2.1.6/svm/src/message_processor.rs#L88 */
    fd_exec_instr_fn_t native_prog_fn;
    uchar              is_precompile;
    int                err = fd_executor_lookup_native_program( &txn_ctx->accounts[ instr->program_id ],
                                                                txn_ctx,
                                                                &native_prog_fn,
                                                                &is_precompile );

    if( FD_UNLIKELY( err ) ) {
      FD_TXN_PREPARE_ERR_OVERWRITE( txn_ctx );
      FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, err, txn_ctx->instr_err_idx );
      return err;
    }

    if( FD_LIKELY( native_prog_fn!=NULL ) ) {
      /* If this branch is taken, we've found an entrypoint to execute. */
      fd_log_collector_program_invoke( ctx );

      /* Only reset the return data when executing a native builtin program (not a precompile)
         https://github.com/anza-xyz/agave/blob/v2.1.6/program-runtime/src/invoke_context.rs#L536-L537 */
      if( FD_LIKELY( !is_precompile ) ) {
        fd_exec_txn_ctx_reset_return_data( txn_ctx );
      }

      /* Execute the native program. */
      instr_exec_result = native_prog_fn( ctx );
    } else {
      /* Unknown program. In this case specifically, we should not log the program id. */
      instr_exec_result = FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
      FD_TXN_PREPARE_ERR_OVERWRITE( txn_ctx );
      FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, instr_exec_result, txn_ctx->instr_err_idx );
      return fd_execute_instr_end( ctx, instr, instr_exec_result );
    }

    if( FD_LIKELY( instr_exec_result==FD_EXECUTOR_INSTR_SUCCESS ) ) {
      /* Log success */
      fd_log_collector_program_success( ctx );
    } else {
      /* Log failure cases.
         We assume that the correct type of error is stored in ctx.
         Syscalls are expected to log when the error is generated, while
         native programs will be logged here.
         (This is because syscall errors often carry data with them.)

         TODO: This hackily handles cases where the exec_err and exec_err_kind
         is not set yet. We should change our native programs to set
         this in their respective processors. */
      if( !txn_ctx->exec_err ) {
        FD_TXN_PREPARE_ERR_OVERWRITE( txn_ctx );
        FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, instr_exec_result, txn_ctx->instr_err_idx );
        fd_log_collector_program_failure( ctx );
      } else {
        fd_log_collector_program_failure( ctx );
        FD_TXN_PREPARE_ERR_OVERWRITE( txn_ctx );
        FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, instr_exec_result, txn_ctx->instr_err_idx );
      }
    }

    return fd_execute_instr_end( ctx, instr, instr_exec_result );
  } FD_RUNTIME_TXN_SPAD_FRAME_END;
}

void
fd_txn_reclaim_accounts( fd_exec_txn_ctx_t * txn_ctx ) {
  for( ushort i=0; i<txn_ctx->accounts_cnt; i++ ) {
    fd_txn_account_t * acc_rec = &txn_ctx->accounts[i];

    /* An account writable iff it is writable AND it is not being
       demoted. If this criteria is not met, the account should not be
       marked as touched via updating its most recent slot. */
    if( !fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, i ) ) {
      continue;
    }

    acc_rec->vt->set_slot( acc_rec, txn_ctx->slot );

    if( !acc_rec->vt->get_lamports( acc_rec ) ) {
      acc_rec->vt->set_data_len( acc_rec, 0UL );
      acc_rec->vt->clear_owner( acc_rec );
    }
  }
}

void
fd_exec_txn_ctx_from_exec_slot_ctx( fd_exec_slot_ctx_t const * slot_ctx,
                                    fd_exec_txn_ctx_t *        ctx,
                                    fd_wksp_t const *          funk_wksp,
                                    fd_wksp_t const *          runtime_pub_wksp,
                                    ulong                      funk_txn_gaddr,
                                    ulong                      funk_gaddr,
                                    fd_bank_hash_cmp_t *       bank_hash_cmp ) {

  ctx->runtime_pub_wksp = (fd_wksp_t *)runtime_pub_wksp;

  ctx->funk_txn = fd_wksp_laddr( funk_wksp, funk_txn_gaddr );
  if( FD_UNLIKELY( !ctx->funk_txn ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction" ));
  }

  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_wksp_laddr( funk_wksp, funk_gaddr ) ) ) ) {
    FD_LOG_ERR(( "Could not find valid funk %lu", funk_gaddr ));
  }

  ctx->status_cache = slot_ctx->status_cache;

  ctx->bank_hash_cmp = bank_hash_cmp;

  ctx->enable_exec_recording = fd_bank_enable_exec_recording_get( slot_ctx->bank );

  ctx->bank = slot_ctx->bank;

  ctx->slot = fd_bank_slot_get( slot_ctx->bank );

  ctx->features = fd_bank_features_get( ctx->bank );
}

fd_txn_account_t *
fd_executor_setup_txn_account( fd_exec_txn_ctx_t * txn_ctx,
                               ushort              idx ) {
  fd_pubkey_t *      acc         = &txn_ctx->account_keys[ idx ];
  int                err         = fd_txn_account_init_from_funk_readonly( &txn_ctx->accounts[ idx ],
                                                                           acc,
                                                                           txn_ctx->funk,
                                                                           txn_ctx->funk_txn );
  fd_txn_account_t * txn_account = &txn_ctx->accounts[ idx ];

  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS && err!=FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
    FD_LOG_ERR(( "fd_txn_account_init_from_funk_readonly err=%d", err ));
  }

  uchar is_unknown_account = err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  memcpy( txn_account->pubkey->key, acc, sizeof(fd_pubkey_t) );

  if( fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, idx ) || idx==FD_FEE_PAYER_TXN_IDX ) {
    void * txn_account_data = fd_spad_alloc( txn_ctx->spad, FD_ACCOUNT_REC_ALIGN, FD_ACC_TOT_SZ_MAX );

    /* promote the account to mutable, which requires a memcpy*/
    fd_txn_account_make_mutable( txn_account, txn_account_data, txn_ctx->spad_wksp );

    /* All new accounts should have their rent epoch set to ULONG_MAX.
       https://github.com/anza-xyz/agave/blob/89050f3cb7e76d9e273f10bea5e8207f2452f79f/svm/src/account_loader.rs#L485-L497 */
    if( FD_UNLIKELY( is_unknown_account ) ) {
      txn_account->vt->set_rent_epoch( txn_account, ULONG_MAX );
    }
  }

  fd_account_meta_t const * meta = txn_account->vt->get_meta( txn_account );

  if( meta==NULL ) {
    fd_txn_account_setup_sentinel_meta_readonly( txn_account, txn_ctx->spad, txn_ctx->spad_wksp );
    return NULL;
  }

  return txn_account;
}

void
fd_executor_setup_executable_account( fd_exec_txn_ctx_t * txn_ctx,
                                      ushort              acc_idx,
                                      ushort *            executable_idx ) {
  int err = 0;
  fd_bpf_upgradeable_loader_state_t * program_loader_state = read_bpf_upgradeable_loader_state_for_program( txn_ctx, acc_idx, &err );
  if( FD_UNLIKELY( !program_loader_state ) ) {
    return;
  }

  if( !fd_bpf_upgradeable_loader_state_is_program( program_loader_state ) ) {
    return;
  }

  /* Attempt to load the program data account from funk. This prevents any unknown program
      data accounts from getting loaded into the executable accounts list. If such a program is
      invoked, the call will fail at the instruction execution level since the programdata
      account will not exist within the executable accounts list. */
  fd_pubkey_t * programdata_acc = &program_loader_state->inner.program.programdata_address;
  if( FD_LIKELY( fd_txn_account_init_from_funk_readonly( &txn_ctx->executable_accounts[ *executable_idx ],
                                                            programdata_acc,
                                                            txn_ctx->funk,
                                                            txn_ctx->funk_txn )==0 ) ) {
    (*executable_idx)++;
  }
}

void
fd_executor_setup_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx ) {
  ushort j = 0UL;
  fd_memset( txn_ctx->accounts, 0, sizeof(fd_txn_account_t) * txn_ctx->accounts_cnt );

  for( ushort i=0; i<txn_ctx->accounts_cnt; i++ ) {

    fd_txn_account_t * txn_account = fd_executor_setup_txn_account( txn_ctx, i );

    if( FD_UNLIKELY( txn_account &&
                     memcmp( txn_account->vt->get_owner( txn_account ), fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
      fd_executor_setup_executable_account( txn_ctx, i, &j );
    }
  }

  /* Dumping ELF files to protobuf, if applicable */
  int dump_elf_to_pb = txn_ctx->capture_ctx &&
                       txn_ctx->slot >= txn_ctx->capture_ctx->dump_proto_start_slot &&
                       txn_ctx->capture_ctx->dump_elf_to_pb;
  if( FD_UNLIKELY( dump_elf_to_pb ) ) {
    for( ushort i=0; i<txn_ctx->accounts_cnt; i++ ) {
      fd_dump_elf_to_protobuf( txn_ctx, &txn_ctx->accounts[i] );
    }
  }

  txn_ctx->nonce_account_idx_in_txn = ULONG_MAX;
  txn_ctx->executable_cnt           = j;

  /* Set up instr infos from the txn descriptor. No Agave equivalent to this function. */
  fd_executor_setup_instr_infos_from_txn_instrs( txn_ctx );
}

/* Stuff to be done before multithreading can begin */
int
fd_execute_txn_prepare_start( fd_exec_slot_ctx_t const * slot_ctx,
                              fd_exec_txn_ctx_t *        txn_ctx,
                              fd_txn_t const *           txn_descriptor,
                              fd_rawtxn_b_t const *      txn_raw ) {

  fd_funk_t * funk               = slot_ctx->funk;
  fd_wksp_t * funk_wksp          = fd_funk_wksp( funk );
  /* FIXME: just pass in the runtime workspace, instead of getting it from fd_wksp_containing */
  fd_wksp_t * runtime_pub_wksp   = fd_wksp_containing( slot_ctx );
  ulong       funk_txn_gaddr     = fd_wksp_gaddr( funk_wksp, slot_ctx->funk_txn );
  ulong       funk_gaddr         = fd_wksp_gaddr( funk_wksp, slot_ctx->funk->shmem );

  /* Init txn ctx */
  fd_exec_txn_ctx_new( txn_ctx );
  fd_exec_txn_ctx_from_exec_slot_ctx( slot_ctx,
                                      txn_ctx,
                                      funk_wksp,
                                      runtime_pub_wksp,
                                      funk_txn_gaddr,
                                      funk_gaddr,
                                      NULL );
  fd_exec_txn_ctx_setup( txn_ctx, txn_descriptor, txn_raw );

  /* Set up the core account keys */
  fd_executor_setup_txn_account_keys( txn_ctx );

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int
fd_executor_txn_verify( fd_exec_txn_ctx_t * txn_ctx ) {
  fd_sha512_t * shas[ FD_TXN_ACTUAL_SIG_MAX ];
  for ( ulong i=0UL; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( fd_spad_alloc( txn_ctx->spad, alignof(fd_sha512_t), sizeof(fd_sha512_t) ) ) );
    if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512_join failed" ));
    shas[i] = sha;
  }

  uchar  signature_cnt = txn_ctx->txn_descriptor->signature_cnt;
  ushort signature_off = txn_ctx->txn_descriptor->signature_off;
  ushort acct_addr_off = txn_ctx->txn_descriptor->acct_addr_off;
  ushort message_off   = txn_ctx->txn_descriptor->message_off;

  uchar const * signatures = (uchar *)txn_ctx->_txn_raw->raw + signature_off;
  uchar const * pubkeys = (uchar *)txn_ctx->_txn_raw->raw + acct_addr_off;
  uchar const * msg = (uchar *)txn_ctx->_txn_raw->raw + message_off;
  ulong msg_sz = (ulong)txn_ctx->_txn_raw->txn_sz - message_off;

  /* Verify signatures */
  int res = fd_ed25519_verify_batch_single_msg( msg, msg_sz, signatures, pubkeys, shas, signature_cnt );
  if( FD_UNLIKELY( res != FD_ED25519_SUCCESS ) ) {
    return -1;
  }

  return 0;
}

int
fd_execute_txn( fd_execute_txn_task_info_t * task_info ) {
  /* Don't execute transactions that are fee only.
     https://github.com/anza-xyz/agave/blob/v2.1.6/svm/src/transaction_processor.rs#L341-L357 */
  if( FD_UNLIKELY( task_info->txn->flags & FD_TXN_P_FLAGS_FEES_ONLY ) ) {
    /* return the existing error */
    return task_info->exec_res;
  }

  fd_exec_txn_ctx_t * txn_ctx   = task_info->txn_ctx;
  bool                dump_insn = txn_ctx->capture_ctx && txn_ctx->slot >= txn_ctx->capture_ctx->dump_proto_start_slot && txn_ctx->capture_ctx->dump_instr_to_pb;

  /* Initialize log collection */
  fd_log_collector_init( &txn_ctx->log_collector, txn_ctx->enable_exec_recording );

  for( ushort i = 0; i < txn_ctx->txn_descriptor->instr_cnt; i++ ) {
    txn_ctx->current_instr_idx = i;
    if( FD_UNLIKELY( dump_insn ) ) {
      // Capture the input and convert it into a Protobuf message
      fd_dump_instr_to_protobuf( txn_ctx, &txn_ctx->instr_infos[i], i );
    }

    int instr_exec_result = fd_execute_instr( txn_ctx, &txn_ctx->instr_infos[i] );
    if( FD_UNLIKELY( instr_exec_result!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
      if ( txn_ctx->instr_err_idx==INT_MAX ) {
        txn_ctx->instr_err_idx = i;
      }
      return FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
    }
  }

  /* TODO: This function needs to be split out of fd_execute_txn and be placed
      into the replay tile once it is implemented. */
  int err = fd_executor_txn_check( txn_ctx );
  if( FD_UNLIKELY( err!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    FD_LOG_WARNING(( "fd_executor_txn_check failed (%d)", err ));
    return err;
  }
  return 0;
}

int
fd_executor_txn_check( fd_exec_txn_ctx_t * txn_ctx ) {
  fd_rent_t const * rent = fd_bank_rent_query( txn_ctx->bank );

  ulong starting_lamports_l = 0;
  ulong starting_lamports_h = 0;

  ulong ending_lamports_l = 0;
  ulong ending_lamports_h = 0;

  /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L63 */
  for( ulong idx = 0; idx < txn_ctx->accounts_cnt; idx++ ) {
    fd_txn_account_t * b = &txn_ctx->accounts[idx];

    // Was this account written to?
    /* TODO: Clean this logic up... lots of redundant checks with our newer account loading model.
       We should be using the rent transition checking logic instead, along with a small refactor
       to keep check ordering consistent. */
    if( b->vt->get_meta( b )!=NULL ) {
      fd_uwide_inc( &ending_lamports_h, &ending_lamports_l, ending_lamports_h, ending_lamports_l, b->vt->get_lamports( b ) );

      /* Rent states are defined as followed:
         - lamports == 0                      -> Uninitialized
         - 0 < lamports < rent_exempt_minimum -> RentPaying
         - lamports >= rent_exempt_minimum    -> RentExempt
         In Agave, 'self' refers to our 'after' state. */
      uchar after_uninitialized  = b->vt->get_lamports( b ) == 0;
      uchar after_rent_exempt    = b->vt->get_lamports( b ) >= fd_rent_exempt_minimum_balance( rent, b->vt->get_data_len( b ) );

      /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L96 */
      if( FD_LIKELY( memcmp( b->pubkey->key, fd_sysvar_incinerator_id.key, sizeof(fd_pubkey_t) ) != 0 ) ) {
        /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L44 */
        if( after_uninitialized || after_rent_exempt ) {
          // no-op
        } else {
          /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L45-L59 */
          uchar before_uninitialized = b->starting_dlen == ULONG_MAX || b->starting_lamports == 0;
          uchar before_rent_exempt   = b->starting_dlen != ULONG_MAX && b->starting_lamports >= fd_rent_exempt_minimum_balance( rent, b->starting_dlen );

          /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L50 */
          if( before_uninitialized || before_rent_exempt ) {
            FD_LOG_DEBUG(( "Rent exempt error for %s Curr len %lu Starting len %lu Curr lamports %lu Starting lamports %lu Curr exempt %lu Starting exempt %lu",
                           FD_BASE58_ENC_32_ALLOCA( b->pubkey->uc ),
                           b->vt->get_data_len( b ),
                           b->starting_dlen,
                           b->vt->get_lamports( b ),
                           b->starting_lamports,
                           fd_rent_exempt_minimum_balance( rent, b->vt->get_data_len( b ) ),
                           fd_rent_exempt_minimum_balance( rent, b->starting_dlen ) ));
            /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L104 */
            return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
          /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L56 */
          } else if( (b->vt->get_data_len( b ) == b->starting_dlen) && b->vt->get_lamports( b ) <= b->starting_lamports ) {
            // no-op
          } else {
            FD_LOG_DEBUG(( "Rent exempt error for %s Curr len %lu Starting len %lu Curr lamports %lu Starting lamports %lu Curr exempt %lu Starting exempt %lu",
                           FD_BASE58_ENC_32_ALLOCA( b->pubkey->uc ),
                           b->vt->get_data_len( b ),
                           b->starting_dlen,
                           b->vt->get_lamports( b ),
                           b->starting_lamports,
                           fd_rent_exempt_minimum_balance( rent, b->vt->get_data_len( b ) ),
                           fd_rent_exempt_minimum_balance( rent, b->starting_dlen ) ));
            /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L104 */
            return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
          }
        }
      }

      if( b->starting_lamports != ULONG_MAX ) {
        fd_uwide_inc( &starting_lamports_h, &starting_lamports_l, starting_lamports_h, starting_lamports_l, b->starting_lamports );
      }
    }
  }

  /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/transaction_processor.rs#L839-L845 */
  if( FD_UNLIKELY( ending_lamports_l!=starting_lamports_l || ending_lamports_h!=starting_lamports_h ) ) {
    FD_LOG_DEBUG(( "Lamport sum mismatch: starting %lx%lx ending %lx%lx", starting_lamports_h, starting_lamports_l, ending_lamports_h, ending_lamports_l ));
    return FD_RUNTIME_TXN_ERR_UNBALANCED_TRANSACTION;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* fd_executor_instr_strerror() returns the error message corresponding to err,
   intended to be logged by log_collector, or an empty string if the error code
   should be omitted in logs for whatever reason.  Omitted examples are success,
   fatal (placeholder just in firedancer), custom error.
   See also fd_log_collector_program_failure(). */
FD_FN_CONST char const *
fd_executor_instr_strerror( int err ) {

  switch( err ) {
  case FD_EXECUTOR_INSTR_SUCCESS                                : return ""; // not used
  case FD_EXECUTOR_INSTR_ERR_FATAL                              : return ""; // not used
  case FD_EXECUTOR_INSTR_ERR_GENERIC_ERR                        : return "generic instruction error";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ARG                        : return "invalid program argument";
  case FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA                 : return "invalid instruction data";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA                   : return "invalid account data for instruction";
  case FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL                 : return "account data too small for instruction";
  case FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS                 : return "insufficient funds for instruction";
  case FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID               : return "incorrect program id for instruction";
  case FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE         : return "missing required signature for instruction";
  case FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED            : return "instruction requires an uninitialized account";
  case FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT              : return "instruction requires an initialized account";
  case FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR                   : return "sum of account balances before and after instruction do not match";
  case FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID                : return "instruction illegally modified the program id of an account";
  case FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND     : return "instruction spent from the balance of an account it does not own";
  case FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED             : return "instruction modified data of an account it does not own";
  case FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE            : return "instruction changed the balance of a read-only account";
  case FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED             : return "instruction modified data of a read-only account";
  case FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_IDX              : return "instruction contains duplicate accounts";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED                : return "instruction changed executable bit of an account";
  case FD_EXECUTOR_INSTR_ERR_RENT_EPOCH_MODIFIED                : return "instruction modified rent epoch of an account";
  case FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS                : return "insufficient account keys for instruction";
  case FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED              : return "program other than the account's owner changed the size of the account data";
  case FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE                 : return "instruction expected an executable account";
  case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED                  : return "instruction tries to borrow reference for an account which is already borrowed";
  case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_OUTSTANDING             : return "instruction left account with an outstanding borrowed reference";
  case FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_OUT_OF_SYNC      : return "instruction modifications of multiply-passed account differ";
  case FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR                         : return ""; // custom handling via txn_ctx->custom_err
  case FD_EXECUTOR_INSTR_ERR_INVALID_ERR                        : return "program returned invalid error code";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_DATA_MODIFIED           : return "instruction changed executable accounts data";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE          : return "instruction changed the balance of an executable account";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT : return "executable accounts must be rent exempt";
  case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID             : return "Unsupported program id";
  case FD_EXECUTOR_INSTR_ERR_CALL_DEPTH                         : return "Cross-program invocation call depth too deep";
  case FD_EXECUTOR_INSTR_ERR_MISSING_ACC                        : return "An account required by the instruction is missing";
  case FD_EXECUTOR_INSTR_ERR_REENTRANCY_NOT_ALLOWED             : return "Cross-program invocation reentrancy not allowed for this instruction";
  case FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED           : return "Length of the seed is too long for address generation";
  case FD_EXECUTOR_INSTR_ERR_INVALID_SEEDS                      : return "Provided seeds do not result in a valid address";
  case FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC                    : return "Failed to reallocate account data";
  case FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED            : return "Computational budget exceeded";
  case FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION               : return "Cross-program invocation with unauthorized signer or writable account";
  case FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE  : return "Failed to create program execution environment";
  case FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPLETE         : return "Program failed to complete";
  case FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPILE          : return "Program failed to compile";
  case FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE                      : return "Account is immutable";
  case FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY                : return "Incorrect authority provided";
  case FD_EXECUTOR_INSTR_ERR_BORSH_IO_ERROR                     : return "Failed to serialize or deserialize account data"; // truncated
  case FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT                : return "An account does not have enough lamports to be rent-exempt";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER                  : return "Invalid account owner";
  case FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW                : return "Program arithmetic overflowed";
  case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR                 : return "Unsupported sysvar";
  case FD_EXECUTOR_INSTR_ERR_ILLEGAL_OWNER                      : return "Provided owner is not allowed";
  case FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_ALLOCS_EXCEEDED      : return "Accounts data allocations exceeded the maximum allowed per transaction";
  case FD_EXECUTOR_INSTR_ERR_MAX_ACCS_EXCEEDED                  : return "Max accounts exceeded";
  case FD_EXECUTOR_INSTR_ERR_MAX_INSN_TRACE_LENS_EXCEEDED       : return "Max instruction trace length exceeded";
  case FD_EXECUTOR_INSTR_ERR_BUILTINS_MUST_CONSUME_CUS          : return "Builtin programs must consume compute units";
  default: break;
  }

  return "";
}

// This is purely linker magic to force the inclusion of the yaml type walker so that it is
// available for debuggers
void
fd_debug_symbology(void) {
  (void)fd_get_types_yaml();
}
