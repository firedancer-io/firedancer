#include "fd_executor.h"
#include "fd_bank.h"
#include "fd_runtime.h"
#include "fd_runtime_err.h"
#include "fd_acc_pool.h"

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
#include "sysvar/fd_sysvar_cache.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_instructions.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_slot_history.h"
#include "tests/fd_dump_pb.h"

#include "../accdb/fd_accdb_sync.h"
#include "../log_collector/fd_log_collector.h"

#include "../../ballet/base58/fd_base58.h"

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
  ulong feature_enable_offset; /* offset to the feature that enables this program, if any */
};
typedef struct fd_native_prog_info fd_native_prog_info_t;

/* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/rent_state.rs#L5-L15 */
struct fd_rent_state {
  uint  discriminant;
  ulong lamports;
  ulong data_size;
};
typedef struct fd_rent_state fd_rent_state_t;

#define FD_RENT_STATE_UNINITIALIZED (0U)
#define FD_RENT_STATE_RENT_PAYING   (1U)
#define FD_RENT_STATE_RENT_EXEMPT   (2U)

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

#define MAP_PERFECT_0       ( VOTE_PROG_ID            ), .fn = fd_vote_program_execute,                      .is_bpf_loader = 0, .feature_enable_offset = ULONG_MAX
#define MAP_PERFECT_1       ( SYS_PROG_ID             ), .fn = fd_system_program_execute,                    .is_bpf_loader = 0, .feature_enable_offset = ULONG_MAX
#define MAP_PERFECT_2       ( CONFIG_PROG_ID          ), .fn = fd_config_program_execute,                    .is_bpf_loader = 0, .feature_enable_offset = ULONG_MAX
#define MAP_PERFECT_3       ( STAKE_PROG_ID           ), .fn = fd_stake_program_execute,                     .is_bpf_loader = 0, .feature_enable_offset = ULONG_MAX
#define MAP_PERFECT_4       ( COMPUTE_BUDGET_PROG_ID  ), .fn = fd_compute_budget_program_execute,            .is_bpf_loader = 0, .feature_enable_offset = ULONG_MAX
#define MAP_PERFECT_5       ( ADDR_LUT_PROG_ID        ), .fn = fd_address_lookup_table_program_execute,      .is_bpf_loader = 0, .feature_enable_offset = ULONG_MAX
#define MAP_PERFECT_6       ( ZK_EL_GAMAL_PROG_ID     ), .fn = fd_executor_zk_elgamal_proof_program_execute, .is_bpf_loader = 0, .feature_enable_offset = ULONG_MAX
#define MAP_PERFECT_7       ( BPF_LOADER_1_PROG_ID    ), .fn = fd_bpf_loader_program_execute,                .is_bpf_loader = 1, .feature_enable_offset = ULONG_MAX
#define MAP_PERFECT_8       ( BPF_LOADER_2_PROG_ID    ), .fn = fd_bpf_loader_program_execute,                .is_bpf_loader = 1, .feature_enable_offset = ULONG_MAX
#define MAP_PERFECT_9       ( BPF_UPGRADEABLE_PROG_ID ), .fn = fd_bpf_loader_program_execute,                .is_bpf_loader = 1, .feature_enable_offset = ULONG_MAX
#define MAP_PERFECT_10      ( LOADER_V4_PROG_ID       ), .fn = fd_loader_v4_program_execute,                 .is_bpf_loader = 1, .feature_enable_offset = offsetof( fd_features_t, enable_loader_v4 )

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
fd_executor_lookup_native_precompile_program( fd_pubkey_t const * pubkey ) {
  const fd_native_prog_info_t null_function = {0};
  return fd_native_precompile_program_fn_lookup_tbl_query( pubkey, &null_function )->fn;
}

uchar
fd_executor_pubkey_is_bpf_loader( fd_pubkey_t const * pubkey ) {
  fd_native_prog_info_t const null_function = {0};
  return fd_native_program_fn_lookup_tbl_query( pubkey, &null_function )->is_bpf_loader;
}

uchar
fd_executor_program_is_active( fd_bank_t *         bank,
                               fd_pubkey_t const * pubkey ) {
  fd_native_prog_info_t const null_function = {0};
  ulong feature_offset = fd_native_program_fn_lookup_tbl_query( pubkey, &null_function )->feature_enable_offset;

  return feature_offset==ULONG_MAX ||
         FD_FEATURE_ACTIVE_BANK_OFFSET( bank, feature_offset );
}

/* fd_executor_lookup_native_program returns the appropriate instruction processor for the given
   native program ID. Returns NULL if given ID is not a recognized native program.
   https://github.com/anza-xyz/agave/blob/v2.2.6/program-runtime/src/invoke_context.rs#L520-L544 */
static int
fd_executor_lookup_native_program( fd_pubkey_t const *       pubkey,
                                   fd_account_meta_t const * meta,
                                   fd_bank_t *               bank,
                                   fd_exec_instr_fn_t *      native_prog_fn,
                                   uchar *                   is_precompile ) {
  /* First lookup to see if the program key is a precompile */
  *is_precompile = 0;
  *native_prog_fn = fd_executor_lookup_native_precompile_program( pubkey );
  if( FD_UNLIKELY( *native_prog_fn!=NULL ) ) {
    *is_precompile = 1;
    return 0;
  }

  fd_pubkey_t const * owner = (fd_pubkey_t const *)meta->owner;

  /* Native programs should be owned by the native loader...
     This will not be the case though once core programs are migrated to BPF. */
  int is_native_program = !memcmp( owner, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) );

  if( !is_native_program ) {
    if( FD_UNLIKELY( !fd_executor_pubkey_is_bpf_loader( owner ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
    }
  }

  fd_pubkey_t const * lookup_pubkey = is_native_program ? pubkey : owner;

  /* Migrated programs must be executed via the corresponding BPF
     loader(s), not natively. This check is performed at the transaction
     level, but we re-check to please the instruction level (and below)
     fuzzers. */
  uchar has_migrated;
  if( FD_UNLIKELY( fd_is_migrating_builtin_program( bank, lookup_pubkey, &has_migrated ) && has_migrated ) ) {
    *native_prog_fn = NULL;
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

  /* We perform feature gate checks here to emulate the absence of
     a native program in Agave's ProgramCache when the program's feature
     gate is not activated.
     https://github.com/anza-xyz/agave/blob/v3.0.3/program-runtime/src/invoke_context.rs#L546-L549 */

  if( FD_UNLIKELY( !fd_executor_program_is_active( bank, lookup_pubkey ) ) ) {
    *native_prog_fn = NULL;
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

  fd_native_prog_info_t const null_function = {0};
  *native_prog_fn                           = fd_native_program_fn_lookup_tbl_query( lookup_pubkey, &null_function )->fn;
  return 0;
}

/* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/svm_rent_collector.rs#L117-L136 */
static uchar
fd_executor_rent_transition_allowed( fd_rent_state_t const * pre_rent_state,
                                     fd_rent_state_t const * post_rent_state ) {
  switch( post_rent_state->discriminant ) {
    case FD_RENT_STATE_UNINITIALIZED:
    case FD_RENT_STATE_RENT_EXEMPT: {
      return 1;
    }
    case FD_RENT_STATE_RENT_PAYING: {
      switch( pre_rent_state->discriminant ) {
        case FD_RENT_STATE_UNINITIALIZED:
        case FD_RENT_STATE_RENT_EXEMPT: {
          return 0;
        }
        case FD_RENT_STATE_RENT_PAYING: {
          return post_rent_state->data_size==pre_rent_state->data_size &&
                 post_rent_state->lamports<=pre_rent_state->lamports;
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
fd_executor_check_rent_state_with_account( fd_pubkey_t const *     pubkey,
                                           fd_rent_state_t const * pre_rent_state,
                                           fd_rent_state_t const * post_rent_state ) {
  if( FD_UNLIKELY( memcmp( pubkey, fd_sysvar_incinerator_id.key, sizeof(fd_pubkey_t) ) &&
                   !fd_executor_rent_transition_allowed( pre_rent_state, post_rent_state ) ) ) {
    return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
  }
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/svm_rent_collector.rs#L87-L101 */
fd_rent_state_t
fd_executor_get_account_rent_state( fd_account_meta_t const * meta, fd_rent_t const * rent ) {
  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/svm_rent_collector.rs#L88-L89 */
  if( meta->lamports==0UL ) {
    return (fd_rent_state_t){
      .discriminant = FD_RENT_STATE_UNINITIALIZED
    };
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/svm_rent_collector.rs#L90-L94 */
  if( meta->lamports>=fd_rent_exempt_minimum_balance( rent, meta->dlen ) ) {
    return (fd_rent_state_t){
      .discriminant = FD_RENT_STATE_RENT_EXEMPT
    };
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm-rent-collector/src/svm_rent_collector.rs#L95-L99 */
  return (fd_rent_state_t){
    .discriminant = FD_RENT_STATE_RENT_PAYING,
    .lamports     = meta->lamports,
    .data_size    = meta->dlen
  };
}

/* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L293-L342 */
static int
fd_validate_fee_payer( fd_pubkey_t const * pubkey,
                       fd_account_meta_t * meta,
                       fd_rent_t const *   rent,
                       ulong               fee ) {

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L301-L304 */
  if( FD_UNLIKELY( meta->lamports==0UL ) ) {
    FD_BASE58_ENCODE_32_BYTES( pubkey->uc, pubkey_b58 );
    FD_LOG_DEBUG(( "Fee payer doesn't exist %s", pubkey_b58 ));
    return FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L305-L308 */
  int system_account_kind = fd_get_system_account_kind( meta );
  if( FD_UNLIKELY( system_account_kind==FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_UNKNOWN ) ) {
    return FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_FOR_FEE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L309-L318 */
  ulong min_balance = 0UL;
  if( system_account_kind==FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_NONCE ) {
    min_balance = fd_rent_exempt_minimum_balance( rent, FD_SYSTEM_PROGRAM_NONCE_DLEN );
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L320-L327 */
  if( FD_UNLIKELY( min_balance>meta->lamports || fee>meta->lamports-min_balance ) ) {
    return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L329 */
  fd_rent_state_t payer_pre_rent_state = fd_executor_get_account_rent_state( meta, rent );

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L330-L332 */
  int err = fd_account_meta_checked_sub_lamports( meta, fee );
  if( FD_UNLIKELY( err!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L334 */
  fd_rent_state_t payer_post_rent_state = fd_executor_get_account_rent_state( meta, rent );

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/account_loader.rs#L335-L342 */
  return fd_executor_check_rent_state_with_account( pubkey, &payer_pre_rent_state, &payer_post_rent_state );
}

static int
fd_executor_check_status_cache( fd_txncache_t *     status_cache,
                                fd_bank_t *         bank,
                                fd_txn_in_t const * txn_in,
                                fd_txn_out_t *      txn_out ) {
  if( FD_UNLIKELY( !status_cache ) ) {
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }

  if( FD_UNLIKELY( txn_out->accounts.nonce_idx_in_txn!=ULONG_MAX ) ) {
    /* In Agave, durable nonce transactions are inserted to the status
       cache the same as any others, but this is only to serve RPC
       requests, they do not need to be in there for correctness as the
       nonce mechanism itself prevents double spend.  We skip this logic
       entirely to simplify and improve performance of the txn cache. */
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }

  /* Compute the blake3 hash of the transaction message
     https://github.com/anza-xyz/agave/blob/v2.1.7/sdk/program/src/message/versions/mod.rs#L159-L167 */
  fd_blake3_t b3[1];
  fd_blake3_init( b3 );
  fd_blake3_append( b3, "solana-tx-message-v1", 20UL );
  fd_blake3_append( b3, ((uchar *)txn_in->txn->payload + TXN( txn_in->txn )->message_off),(ulong)( txn_in->txn->payload_sz - TXN( txn_in->txn )->message_off ) );
  fd_blake3_fini( b3, &txn_out->details.blake_txn_msg_hash );

  fd_hash_t * blockhash = (fd_hash_t *)((uchar *)txn_in->txn->payload + TXN( txn_in->txn )->recent_blockhash_off);
  int found = fd_txncache_query( status_cache, bank->data->txncache_fork_id, blockhash->uc, txn_out->details.blake_txn_msg_hash.uc );
  if( FD_UNLIKELY( found ) ) return FD_RUNTIME_TXN_ERR_ALREADY_PROCESSED;

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/check_transactions.rs#L77-L141 */
static int
fd_executor_check_transaction_age_and_compute_budget_limits( fd_runtime_t *      runtime,
                                                             fd_bank_t *         bank,
                                                             fd_txn_in_t const * txn_in,
                                                             fd_txn_out_t *      txn_out ) {
  /* Note that in Agave, although this function is called after the
     compute budget limits are sanitized, if the transaction age checks
     fail, then we return the transaction age error instead of the
     compute budget error.
     https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/check_transactions.rs#L128-L136 */
  int err = fd_check_transaction_age( runtime, bank, txn_in, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/check_transactions.rs#L103 */
  err = fd_sanitize_compute_unit_limits( txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.0.9/runtime/src/bank.rs#L3239-L3251 */
static inline ulong
get_transaction_account_lock_limit( fd_bank_t * bank ) {
  return fd_ulong_if( FD_FEATURE_ACTIVE_BANK( bank, increase_tx_account_lock_limit ), MAX_TX_ACCOUNT_LOCKS, 64UL );
}

/* https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/check_transactions.rs#L61-L75 */
int
fd_executor_check_transactions( fd_runtime_t *      runtime,
                                fd_bank_t *         bank,
                                fd_txn_in_t const * txn_in,
                                fd_txn_out_t *      txn_out ) {
  /* https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/check_transactions.rs#L68-L73 */
  int err = fd_executor_check_transaction_age_and_compute_budget_limits( runtime, bank, txn_in, txn_out );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/check_transactions.rs#L74 */
  err = fd_executor_check_status_cache( runtime->status_cache, bank, txn_in, txn_out );
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
fd_executor_verify_transaction( fd_bank_t const *   bank,
                                fd_txn_in_t const * txn_in,
                                fd_txn_out_t *      txn_out ) {
  int err = FD_RUNTIME_EXECUTE_SUCCESS;

  /* SIMD-0160: enforce static limit on number of instructions.
     https://github.com/anza-xyz/agave/blob/v3.1.4/runtime/src/bank.rs#L4710-L4716 */
  if( FD_UNLIKELY( FD_FEATURE_ACTIVE_BANK( bank, static_instruction_limit ) &&
                   TXN( txn_in->txn )->instr_cnt > FD_MAX_INSTRUCTION_TRACE_LENGTH ) ) {
    return FD_RUNTIME_TXN_ERR_SANITIZE_FAILURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L566-L569 */
  err = fd_executor_compute_budget_program_execute_instructions( bank, txn_in, txn_out );
  if( FD_UNLIKELY( err ) ) return err;

  return FD_RUNTIME_EXECUTE_SUCCESS;
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

   Returns the loaded transaction account size, which is the value that
   must be used when accumulating and checking against the
   transactions's loaded account data size limit.

   Agave relies on this function to actually load accounts from their
   accounts db. However, since our accounts model is slightly different,
   our account loading logic is handled earlier in the transaction
   execution pipeline within `fd_executor_setup_accounts_for_txn()`.
   Therefore, the name of this function is slightly misleading - we
   don't actually load accounts here, but we still need to collect
   rent from writable accounts and accumulate the transaction's
   total loaded account size.

   https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L199-L228 */
static ulong
load_transaction_account( fd_runtime_t *      runtime,
                          fd_bank_t *         bank,
                          fd_txn_in_t const * txn_in,
                          fd_txn_out_t *      txn_out,
                          fd_pubkey_t const * pubkey,
                          fd_account_meta_t * meta,
                          uchar               unknown_acc,
                          ulong               txn_idx ) {

  /* Handling the sysvar instructions account explictly.
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L817-L824 */
  if( FD_UNLIKELY( !memcmp( pubkey, fd_sysvar_instructions_id.key, sizeof(fd_pubkey_t) ) ) ) {
    /* The sysvar instructions account cannot be "loaded" since it's
       constructed by the SVM and modified within each transaction's
       instruction execution only, so it incurs a loaded size cost
       of 0. */
    fd_sysvar_instructions_serialize_account( runtime, bank, txn_in, txn_out, txn_idx );
    return 0UL;
  }

  /* This next block calls `account_loader::load_transaction_account()`
     which loads the account from the accounts db. If the account exists
     and is writable, collect rent from it.

     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L828-L835 */
  if( FD_LIKELY( !unknown_acc ) ) {
    /* SIMD-0186 introduces a base account size of 64 bytes for all
       transaction counts that exist prior to the transaction's
       execution.

       https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L204-L208 */
    ulong base_account_size = FD_FEATURE_ACTIVE_BANK( bank, formalize_loaded_transaction_data_size ) ? FD_TRANSACTION_ACCOUNT_BASE_SIZE : 0UL;

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L828-L835 */
    return fd_ulong_sat_add( base_account_size, meta->dlen );
  }

  /* The rest of this function is a no-op for us since we already set up
     the transaction accounts for unknown accounts within
     `fd_executor_setup_accounts_for_txn()`. We also do not need to
     add a base cost to the loaded account size because the SIMD
     states that accounts that do not exist prior to the transaction's
     execution should not incur a loaded size cost.
     https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L566-L577 */
  return 0UL;
}

/* This big function contains a lot of logic and special casing for loading transaction accounts.
   Because of the `enable_transaction_loading_failure_fees` feature, it is imperative that we
   are conformant with Agave's logic here and reject / accept transactions here where they do.

   In the firedancer client only some of these steps are necessary because
   all of the accounts are loaded in from the accounts db into borrowed
   accounts already.

   https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L691-L807 */
static int
fd_executor_load_transaction_accounts_old( fd_runtime_t *      runtime,
                                           fd_bank_t *         bank,
                                           fd_txn_in_t const * txn_in,
                                           fd_txn_out_t *      txn_out ) {
  ulong requested_loaded_accounts_data_size = txn_out->details.compute_budget.loaded_accounts_data_size_limit;

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L429-L443 */
  for( ushort i=0; i<txn_out->accounts.cnt; i++ ) {
    fd_account_meta_t * meta = txn_out->accounts.account[i].meta;
    uchar unknown_acc = !!(fd_runtime_get_account_at_index( txn_in, txn_out, i, fd_runtime_account_check_exists ) ||
                            meta->lamports==0UL);

    /* Collect the fee payer account separately (since it was already)
       loaded during fee payer validation.

       https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L727-L729 */
    if( FD_UNLIKELY( i==FD_FEE_PAYER_TXN_IDX ) ) {
      /* Note that the dlen for most fee payers is 0, but we want to
         consider the case where the fee payer is a nonce account.
         We also don't need to add a base account size to this value
         because this branch would only be taken BEFORE SIMD-0186
         is enabled. */
      int err = accumulate_and_check_loaded_account_data_size( meta->dlen,
                                                               requested_loaded_accounts_data_size,
                                                               &txn_out->details.loaded_accounts_data_size );
      if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
        return err;
      }
      continue;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L733-L740 */
    ulong loaded_acc_size = load_transaction_account( runtime, bank, txn_in, txn_out, &txn_out->accounts.keys[i], meta, unknown_acc, i );
    int err = accumulate_and_check_loaded_account_data_size( loaded_acc_size,
                                                             requested_loaded_accounts_data_size,
                                                             &txn_out->details.loaded_accounts_data_size );

    if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      return err;
    }
  }

  /* TODO: Consider using a hash set (if its more performant) */
  ushort            instr_cnt             = TXN( txn_in->txn )->instr_cnt;
  fd_pubkey_t       validated_loaders[instr_cnt];
  ushort            validated_loaders_cnt = 0;
  fd_funk_txn_xid_t xid                   = { .ul = { fd_bank_slot_get( bank ), bank->data->idx } };

  /* The logic below handles special casing with loading instruction accounts.
     https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L445-L525 */
  for( ushort i=0; i<instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &TXN( txn_in->txn )->instr[i];

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L449-L451 */
    if( FD_UNLIKELY( !memcmp( txn_out->accounts.keys[ instr->program_id ].key, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) ) ) {
      continue;
    }

    /* Mimicking `load_account()` here with 0-lamport check as well.
       https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L455-L462 */
    fd_account_meta_t * program_meta = txn_out->accounts.account[instr->program_id].meta;
    int err = fd_runtime_get_account_at_index( txn_in,
                                               txn_out,
                                               instr->program_id,
                                               fd_runtime_account_check_exists );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS || program_meta->lamports==0UL ) ) {
      return FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L474-L477 */
    if( !memcmp( program_meta->owner, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) ) {
      continue;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L479-L522 */
    uchar loader_seen = 0;
    for( ushort j=0; j<validated_loaders_cnt; j++ ) {
      if( !memcmp( validated_loaders[j].key, program_meta->owner, sizeof(fd_pubkey_t) ) ) {
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

    fd_accdb_ro_t owner_ro[1];
    fd_pubkey_t const * owner_pubkey  = (fd_pubkey_t const *)program_meta->owner;
    if( FD_UNLIKELY( !fd_accdb_open_ro( runtime->accdb, owner_ro, &xid, owner_pubkey ) ) ) {
      /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L520 */
      return FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
    }
    ulong       const owner_sz    = fd_accdb_ref_data_sz( owner_ro );
    fd_pubkey_t const owner_owner = FD_LOAD( fd_pubkey_t, fd_accdb_ref_owner( owner_ro ) );
    fd_accdb_close_ro( runtime->accdb, owner_ro );

    /* https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L502-L510 */
    if( FD_UNLIKELY( !fd_pubkey_eq( &owner_owner, &fd_solana_native_loader_id ) ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION;
    }

    /* Count the owner's data in the loaded account size for program accounts.
       However, it is important to not double count repeated owners.
       https://github.com/anza-xyz/agave/blob/v2.2.0/svm/src/account_loader.rs#L511-L517 */
    err = accumulate_and_check_loaded_account_data_size( owner_sz,
                                                         requested_loaded_accounts_data_size,
                                                         &txn_out->details.loaded_accounts_data_size );
    if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      return err;
    }

    fd_memcpy( validated_loaders[ validated_loaders_cnt++ ].key, owner_pubkey, sizeof(fd_pubkey_t) );
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L494-L515 */
static int
fd_increase_calculated_data_size( fd_txn_out_t * txn_out,
                                  ulong          data_size_delta ) {
  /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L500-L503 */
  if( FD_UNLIKELY( data_size_delta>UINT_MAX ) ) {
    return FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L505-L507 */
  txn_out->details.loaded_accounts_data_size = fd_ulong_sat_add( txn_out->details.loaded_accounts_data_size, data_size_delta );

  if( FD_UNLIKELY( txn_out->details.loaded_accounts_data_size>txn_out->details.compute_budget.loaded_accounts_data_size_limit ) ) {
    return FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* This function is represented as a closure in Agave.
   https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L578-L640 */
static int
fd_collect_loaded_account( fd_runtime_t *            runtime,
                           fd_txn_out_t *            txn_out,
                           fd_bank_t *               bank,
                           fd_account_meta_t const * account_meta,
                           ulong                     loaded_acc_size,
                           fd_pubkey_t *             additional_loaded_account_keys,
                           ulong *                   additional_loaded_account_keys_cnt ) {

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L586-L590 */
  int err = fd_increase_calculated_data_size( txn_out, loaded_acc_size );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  /* The remainder of this function is a deep-nested set of if
     statements. I've inverted the logic to make it easier to read.
     The purpose of the following code is to ensure that loader v3
     programdata accounts are accounted for exactly once in the account
     loading logic.

     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L611 */
  if( FD_LIKELY( memcmp( account_meta->owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }

  /* Try to read the program state
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L612-L634 */
  fd_bpf_upgradeable_loader_state_t loader_state[1];
  err = fd_bpf_loader_program_get_state( account_meta, loader_state );
  if( FD_UNLIKELY( err!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }

  /* Make sure the account is a v3 program */
  if( !fd_bpf_upgradeable_loader_state_is_program( loader_state ) ) {
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }

  /* Iterate through the account keys and make sure the programdata
     account is not present so it doesn't get loaded twice.
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L617 */
  for( ushort i=0; i<txn_out->accounts.cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( &txn_out->accounts.keys[i], &loader_state->inner.program.programdata_address, sizeof(fd_pubkey_t) ) ) ) {
      return FD_RUNTIME_EXECUTE_SUCCESS;
    }
  }

  /* Check that the programdata account has not been already counted
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L618 */
  for( ushort i=0; i<*additional_loaded_account_keys_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( &additional_loaded_account_keys[i], &loader_state->inner.program.programdata_address, sizeof(fd_pubkey_t) ) ) ) {
      return FD_RUNTIME_EXECUTE_SUCCESS;
    }
  }

  /* Programdata account size check */
  fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( bank ), bank->data->idx } };
  fd_accdb_ro_t programdata_ro[1];
  if( FD_UNLIKELY( !fd_accdb_open_ro( runtime->accdb, programdata_ro, &xid, &loader_state->inner.program.programdata_address ) ) ) {
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }
  ulong programdata_sz = fd_accdb_ref_data_sz( programdata_ro );
  fd_accdb_close_ro( runtime->accdb, programdata_ro );

  /* Try to accumulate the programdata's data size
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L625-L630 */
  ulong programdata_size_delta = fd_ulong_sat_add( FD_TRANSACTION_ACCOUNT_BASE_SIZE, programdata_sz );
  err = fd_increase_calculated_data_size( txn_out, programdata_size_delta );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  /* Add the programdata account to the list of loaded programdata accounts
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L631 */
  fd_memcpy(
    &additional_loaded_account_keys[(*additional_loaded_account_keys_cnt)++],
    &loader_state->inner.program.programdata_address,
    sizeof(fd_pubkey_t) );

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* Simplified transaction loading logic for SIMD-0186 which does the
   following:
   - Calculates the loaded data size for each address lookup table
   - Calculates the loaded data size for each transaction account
   - Calculates the loaded data size for each v3 programdata account
     not directly referenced in the transaction accounts
   - Collects rent from all referenced transaction accounts (excluding
     the fee payer)
   - Validates that each program invoked in a top-level instruction
     exists, is executable, and is owned by either the native loader
     or a bpf loader

   https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L550-L689 */
static int
fd_executor_load_transaction_accounts_simd_186( fd_runtime_t *      runtime,
                                                fd_bank_t *         bank,
                                                fd_txn_in_t const * txn_in,
                                                fd_txn_out_t *      txn_out ) {
  /* Programdata accounts that are loaded by this transaction.
     We keep track of these to ensure they are not counted twice.
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L559 */
  fd_pubkey_t additional_loaded_account_keys[ FD_TXN_ACCT_ADDR_MAX ] = { 0 };
  ulong       additional_loaded_account_keys_cnt                     = 0UL;

  /* Charge a base fee for each address lookup table.
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L570-L576 */
  ulong aluts_size = fd_ulong_sat_mul( TXN( txn_in->txn )->addr_table_lookup_cnt,
                                       FD_ADDRESS_LOOKUP_TABLE_BASE_SIZE );
  int err = fd_increase_calculated_data_size( txn_out, aluts_size );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L642-L660 */
  for( ushort i=0; i<txn_out->accounts.cnt; i++ ) {
    fd_account_meta_t * meta = txn_out->accounts.account[i].meta;

    uchar unknown_acc = !!(fd_runtime_get_account_at_index( txn_in, txn_out, i, fd_runtime_account_check_exists ) ||
                            meta->lamports==0UL);

    /* Collect the fee payer account separately (since it was already)
       loaded during fee payer validation.

       https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L644-L648 */
    if( FD_UNLIKELY( i==FD_FEE_PAYER_TXN_IDX ) ) {
      /* Note that the dlen for most fee payers is 0, but we want to
         consider the case where the fee payer is a nonce account.
         We also must add a base account size to this value
         because this branch would only be taken AFTER SIMD-0186
         is enabled. */
      ulong loaded_acc_size = fd_ulong_sat_add( FD_TRANSACTION_ACCOUNT_BASE_SIZE,
                                                meta->dlen );
      int err = fd_collect_loaded_account(
        runtime,
        txn_out,
        bank,
        meta,
        loaded_acc_size,
        additional_loaded_account_keys,
        &additional_loaded_account_keys_cnt );
      if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
        return err;
      }
      continue;
    }

    /* Load and collect any remaining accounts
       https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L652-L659 */
    ulong loaded_acc_size = load_transaction_account( runtime, bank, txn_in, txn_out, &txn_out->accounts.keys[i], meta, unknown_acc, i );
    int err = fd_collect_loaded_account(
      runtime,
      txn_out,
      bank,
      meta,
      loaded_acc_size,
      additional_loaded_account_keys,
      &additional_loaded_account_keys_cnt );
    if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      return err;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L662-L686 */
  ushort instr_cnt = TXN( txn_in->txn )->instr_cnt;
  for( ushort i=0; i<instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &TXN( txn_in->txn )->instr[i];

    /* Mimicking `load_account()` here with 0-lamport check as well.
       https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L663-L666 */
    fd_account_meta_t * program_meta = txn_out->accounts.account[instr->program_id].meta;
    int err = fd_runtime_get_account_at_index( txn_in,
                                               txn_out,
                                               instr->program_id,
                                               fd_runtime_account_check_exists );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS || program_meta->lamports==0UL ) ) {
      return FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L677-L681 */
    fd_pubkey_t const * owner_id = (fd_pubkey_t const *)program_meta->owner;
    if( FD_UNLIKELY( memcmp( owner_id->key, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) &&
                     !fd_executor_pubkey_is_bpf_loader( owner_id ) ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION;
    }
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L518-L548 */
int
fd_executor_load_transaction_accounts( fd_runtime_t *      runtime,
                                       fd_bank_t *         bank,
                                       fd_txn_in_t const * txn_in,
                                       fd_txn_out_t *      txn_out ) {
  if( FD_FEATURE_ACTIVE_BANK( bank, formalize_loaded_transaction_data_size ) ) {
    return fd_executor_load_transaction_accounts_simd_186( runtime, bank, txn_in, txn_out );
  } else {
    return fd_executor_load_transaction_accounts_old( runtime, bank, txn_in, txn_out );
  }
}

/* https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L118 */
int
fd_executor_validate_account_locks( fd_bank_t *          bank,
                                    fd_txn_out_t const * txn_out ) {
  /* Ensure the number of account keys does not exceed the transaction lock limit
     https://github.com/anza-xyz/agave/blob/v2.2.17/accounts-db/src/account_locks.rs#L121 */
  ulong tx_account_lock_limit = get_transaction_account_lock_limit( bank );
  if( FD_UNLIKELY( txn_out->accounts.cnt>tx_account_lock_limit ) ) {
    return FD_RUNTIME_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS;
  }

  /* Duplicate account check
     https://github.com/anza-xyz/agave/blob/v2.2.17/accounts-db/src/account_locks.rs#L123 */
  for( ushort i=0; i<txn_out->accounts.cnt; i++ ) {
    for( ushort j=(ushort)(i+1U); j<txn_out->accounts.cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( &txn_out->accounts.keys[i], &txn_out->accounts.keys[j], sizeof(fd_pubkey_t) ) ) ) {
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

static void
fd_executor_calculate_fee( fd_bank_t *      bank,
                           fd_txn_out_t *   txn_out,
                           fd_txn_t const * txn_descriptor,
                           uchar const *    payload,
                           ulong *          ret_execution_fee,
                           ulong *          ret_priority_fee ) {
  /* The execution fee is just the signature fee. The priority fee
     is calculated based on the compute budget details.
     https://github.com/anza-xyz/agave/blob/v3.0.3/fee/src/lib.rs#L65-L84 */

  // let signature_fee = Self::get_num_signatures_in_message(message) .saturating_mul(fee_structure.lamports_per_signature);
  ulong num_signatures = txn_descriptor->signature_cnt;
  for (ushort i=0; i<txn_descriptor->instr_cnt; ++i ) {
    fd_txn_instr_t const * txn_instr  = &txn_descriptor->instr[i];
    fd_pubkey_t *          program_id = &txn_out->accounts.keys[txn_instr->program_id];
    if( !memcmp(program_id->uc, fd_solana_keccak_secp_256k_program_id.key, sizeof(fd_pubkey_t)) ||
        !memcmp(program_id->uc, fd_solana_ed25519_sig_verify_program_id.key, sizeof(fd_pubkey_t)) ||
        (!memcmp(program_id->uc, fd_solana_secp256r1_program_id.key, sizeof(fd_pubkey_t)) && FD_FEATURE_ACTIVE_BANK( bank, enable_secp256r1_precompile )) ) {
      if( !txn_instr->data_sz ) {
        continue;
      }
      uchar const * data = payload + txn_instr->data_off;
      num_signatures     = fd_ulong_sat_add(num_signatures, (ulong)(data[0]));
    }
  }
  *ret_execution_fee = FD_RUNTIME_FEE_STRUCTURE_LAMPORTS_PER_SIGNATURE * num_signatures;
  *ret_priority_fee  = fd_get_prioritization_fee( &txn_out->details.compute_budget );
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
fd_executor_create_rollback_fee_payer_account( fd_runtime_t *      runtime,
                                               fd_bank_t *         bank,
                                               fd_txn_in_t const * txn_in,
                                               fd_txn_out_t *      txn_out,
                                               ulong               total_fee ) {
  fd_pubkey_t * fee_payer_key = &txn_out->accounts.keys[FD_FEE_PAYER_TXN_IDX];

  /* When setting the data of the rollback fee payer, there is an edge
     case where the fee payer is the nonce account.  In this case, we
     can just deduct fees from the nonce account and return, because
     we save the nonce account in the commit phase anyways. */
  if( FD_UNLIKELY( txn_out->accounts.nonce_idx_in_txn==FD_FEE_PAYER_TXN_IDX ) ) {
    txn_out->accounts.rollback_fee_payer = txn_out->accounts.rollback_nonce;
  } else {
    uchar * fee_payer_data = txn_out->accounts.rollback_fee_payer_mem;
    txn_out->accounts.rollback_fee_payer = fd_type_pun( fee_payer_data );

    fd_account_meta_t const * meta = NULL;
    if( FD_UNLIKELY( txn_in->bundle.is_bundle ) ) {
      int is_found = 0;
      for( ulong i=txn_in->bundle.prev_txn_cnt; i>0UL && !is_found; i-- ) {;
        fd_txn_out_t const * prev_txn_out = txn_in->bundle.prev_txn_outs[ i-1 ];
        for( ushort j=0UL; j<prev_txn_out->accounts.cnt; j++ ) {
          if( fd_pubkey_eq( &prev_txn_out->accounts.keys[ j ], fee_payer_key ) && prev_txn_out->accounts.is_writable[j] ) {
            meta = prev_txn_out->accounts.account[j].meta;
            is_found = 1;
            break;
          }
        }
      }
    }

    if( meta ) {
      /* Account modified in a previous transaction */
      fd_memcpy( fee_payer_data, (uchar *)meta, sizeof(fd_account_meta_t) + meta->dlen );
    } else {
      /* Copy from account database */
      fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( bank ), bank->data->idx } };
      fd_accdb_ro_t fee_payer_ro[1];
      if( FD_UNLIKELY( !fd_accdb_open_ro( runtime->accdb, fee_payer_ro, &xid, fee_payer_key ) ) ) {
        FD_BASE58_ENCODE_32_BYTES( fee_payer_key->uc, fee_payer_key_b58 );
        FD_LOG_CRIT(( "accdb query for fee payer account failed: xid=%lu:%lu address=%s", xid.ul[0], xid.ul[1], fee_payer_key_b58 ));
      }
      fd_memcpy( fee_payer_data,
                 fee_payer_ro->meta,
                 sizeof(fd_account_meta_t) );
      fd_memcpy( fee_payer_data+sizeof(fd_account_meta_t),
                 fd_accdb_ref_data_const( fee_payer_ro ),
                 fd_accdb_ref_data_sz   ( fee_payer_ro ) );
      fd_accdb_close_ro( runtime->accdb, fee_payer_ro );
    }
  }

  /* Deduct the transaction fees from the rollback account. Because of prior checks, this should never fail. */
  if( FD_UNLIKELY( fd_account_meta_checked_sub_lamports( txn_out->accounts.rollback_fee_payer, total_fee ) ) ) {
    FD_LOG_ERR(( "fd_executor_create_rollback_fee_payer_account(): failed to deduct fees from rollback account" ));
  }
}

/* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L557-L634 */
int
fd_executor_validate_transaction_fee_payer( fd_runtime_t *      runtime,
                                            fd_bank_t *         bank,
                                            fd_txn_in_t const * txn_in,
                                            fd_txn_out_t *      txn_out ) {
  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L574-L580 */
  int err = fd_runtime_get_account_at_index( txn_in,
                                             txn_out,
                                             FD_FEE_PAYER_TXN_IDX,
                                             fd_runtime_account_check_fee_payer_writable );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    FD_BASE58_ENCODE_32_BYTES( txn_out->accounts.keys[FD_FEE_PAYER_TXN_IDX].uc, pubkey_b58 );
    FD_LOG_DEBUG(( "Fee payer isn't writable %s", pubkey_b58 ));
    return FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND;
  }

  fd_pubkey_t *       fee_payer_key  = &txn_out->accounts.keys[FD_FEE_PAYER_TXN_IDX];
  fd_account_meta_t * fee_payer_meta = txn_out->accounts.account[FD_FEE_PAYER_TXN_IDX].meta;

  /* Calculate transaction fees
     https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L597-L606 */
  ulong execution_fee = 0UL;
  ulong priority_fee  = 0UL;

  fd_executor_calculate_fee( bank, txn_out, TXN( txn_in->txn ), txn_in->txn->payload, &execution_fee, &priority_fee );
  ulong total_fee = fd_ulong_sat_add( execution_fee, priority_fee );

  /* https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L609-L616 */
  err = fd_validate_fee_payer( fee_payer_key, fee_payer_meta, fd_bank_rent_query( bank ), total_fee );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* Create the rollback fee payer account
     https://github.com/anza-xyz/agave/blob/v2.2.13/svm/src/transaction_processor.rs#L620-L626 */
  fd_executor_create_rollback_fee_payer_account( runtime, bank, txn_in, txn_out, total_fee );

  /* Set the starting lamports (to avoid unbalanced lamports issues in instruction execution) */
  runtime->accounts.starting_lamports[FD_FEE_PAYER_TXN_IDX] = fee_payer_meta->lamports;

  txn_out->details.execution_fee = execution_fee;
  txn_out->details.priority_fee  = priority_fee;

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* Simply unpacks the account keys from the serialized transaction and
   sets them in the txn_out. */
void
fd_executor_setup_txn_account_keys( fd_txn_in_t const * txn_in,
                                    fd_txn_out_t *      txn_out ) {
  txn_out->accounts.cnt = (uchar)TXN( txn_in->txn )->acct_addr_cnt;
  fd_pubkey_t * tx_accs = (fd_pubkey_t *)((uchar *)txn_in->txn->payload + TXN( txn_in->txn )->acct_addr_off);

  // Set up accounts in the transaction body and perform checks
  for( ulong i = 0UL; i < TXN( txn_in->txn )->acct_addr_cnt; i++ ) {
    txn_out->accounts.keys[i] = tx_accs[i];
  }
}

/* Resolves any address lookup tables referenced in the transaction and adds
   them to the transaction's account keys. Returns 0 on success or if the transaction
   is a legacy transaction, and an FD_RUNTIME_TXN_ERR_* on failure. */
int
fd_executor_setup_txn_alut_account_keys( fd_runtime_t *      runtime,
                                         fd_bank_t *         bank,
                                         fd_txn_in_t const * txn_in,
                                         fd_txn_out_t *      txn_out ) {
  if( TXN( txn_in->txn )->transaction_version == FD_TXN_V0 ) {
    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/runtime/src/bank/address_lookup_table.rs#L44-L48 */
    fd_sysvar_cache_t const * sysvar_cache = fd_bank_sysvar_cache_query( bank );
    fd_slot_hash_t const * slot_hashes = fd_sysvar_cache_slot_hashes_join_const( sysvar_cache );
    if( FD_UNLIKELY( !slot_hashes ) ) {
      FD_LOG_DEBUG(( "fd_executor_setup_txn_alut_account_keys(): failed to get slot hashes" ));
      return FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND;
    }
    fd_funk_txn_xid_t xid       = { .ul = { fd_bank_slot_get( bank ), bank->data->idx } };
    fd_acct_addr_t *  accts_alt = (fd_acct_addr_t *) fd_type_pun( &txn_out->accounts.keys[txn_out->accounts.cnt] );
    int err = fd_runtime_load_txn_address_lookup_tables( TXN( txn_in->txn ),
                                                         txn_in->txn->payload,
                                                         runtime->accdb,
                                                         &xid,
                                                         fd_bank_slot_get( bank ),
                                                         slot_hashes,
                                                         accts_alt );
    fd_sysvar_cache_slot_hashes_leave_const( sysvar_cache, slot_hashes );
    txn_out->accounts.cnt += TXN( txn_in->txn )->addr_table_adtl_cnt;
    if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) return err;

  }
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.0.0/sdk/src/transaction_context.rs#L319-L357 */
static inline int
fd_txn_ctx_push( fd_runtime_t *      runtime,
                 fd_txn_in_t const * txn_in,
                 fd_txn_out_t *      txn_out,
                 fd_instr_info_t *   instr ) {
  /* Earlier checks in the permalink are redundant since Agave maintains instr stack and trace accounts separately
     https://github.com/anza-xyz/agave/blob/v2.0.0/sdk/src/transaction_context.rs#L327-L328 */
  ulong starting_lamports_h = 0UL;
  ulong starting_lamports_l = 0UL;
  int err = fd_instr_info_sum_account_lamports( instr,
                                                txn_out,
                                                &starting_lamports_h,
                                                &starting_lamports_l );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  instr->starting_lamports_h = starting_lamports_h;
  instr->starting_lamports_l = starting_lamports_l;

  /* Check that the caller's lamport sum has not changed.
     https://github.com/anza-xyz/agave/blob/v2.0.0/sdk/src/transaction_context.rs#L329-L340 */
  if( runtime->instr.stack_sz>0 ) {
    /* https://github.com/anza-xyz/agave/blob/v2.0.0/sdk/src/transaction_context.rs#L330 */
    fd_exec_instr_ctx_t const * caller_instruction_context = &runtime->instr.stack[ runtime->instr.stack_sz-1 ];

    /* https://github.com/anza-xyz/agave/blob/v2.0.0/sdk/src/transaction_context.rs#L331-L332 */
    ulong original_caller_lamport_sum_h = caller_instruction_context->instr->starting_lamports_h;
    ulong original_caller_lamport_sum_l = caller_instruction_context->instr->starting_lamports_l;

    /* https://github.com/anza-xyz/agave/blob/v2.0.0/sdk/src/transaction_context.rs#L333-L334 */
    ulong current_caller_lamport_sum_h = 0UL;
    ulong current_caller_lamport_sum_l = 0UL;
    int err = fd_instr_info_sum_account_lamports( caller_instruction_context->instr,
                                                  caller_instruction_context->txn_out,
                                                  &current_caller_lamport_sum_h,
                                                  &current_caller_lamport_sum_l );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.0.0/sdk/src/transaction_context.rs#L335-L339 */
    if( FD_UNLIKELY( current_caller_lamport_sum_h!=original_caller_lamport_sum_h ||
                     current_caller_lamport_sum_l!=original_caller_lamport_sum_l ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
    }
  }

  /* Note that we don't update the trace length here - since the caller
     allocates out of the trace array, they are also responsible for
     incrementing the trace length variable.
     https://github.com/anza-xyz/agave/blob/v2.0.0/sdk/src/transaction_context.rs#L347-L351 */
  if( FD_UNLIKELY( runtime->instr.trace_length>FD_MAX_INSTRUCTION_TRACE_LENGTH ) ) {
    return FD_EXECUTOR_INSTR_ERR_MAX_INSN_TRACE_LENS_EXCEEDED;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.0/sdk/src/transaction_context.rs#L352-L356 */
  if( FD_UNLIKELY( runtime->instr.stack_sz>=FD_MAX_INSTRUCTION_STACK_DEPTH ) ) {
    return FD_EXECUTOR_INSTR_ERR_CALL_DEPTH;
  }
  runtime->instr.stack_sz++;

  /* A beloved refactor moves sysvar instructions updating to the instruction level as of v2.2.12...
     https://github.com/anza-xyz/agave/blob/v2.2.12/transaction-context/src/lib.rs#L396-L407 */
  int idx = fd_runtime_find_index_of_account( txn_out, &fd_sysvar_instructions_id );
  if( FD_UNLIKELY( idx!=-1 ) ) {
    /* https://github.com/anza-xyz/agave/blob/v2.2.12/transaction-context/src/lib.rs#L397-L400 */
    err = fd_runtime_get_account_at_index( txn_in, txn_out, (ushort)idx, NULL );
    if( FD_UNLIKELY( err ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    ulong refcnt = runtime->accounts.refcnt[idx];
    /* https://github.com/anza-xyz/agave/blob/v2.2.12/transaction-context/src/lib.rs#L401-L402 */
    if( FD_UNLIKELY( refcnt!=0UL ) ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
    }
    refcnt++;

    /* https://github.com/anza-xyz/agave/blob/v2.2.12/transaction-context/src/lib.rs#L403-L406 */
    fd_sysvar_instructions_update_current_instr_idx( txn_out->accounts.account[idx].meta, (ushort)runtime->instr.current_idx );
    refcnt--;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* Pushes a new instruction onto the instruction stack and trace. This check loops through all instructions in the current call stack
   and checks for reentrancy violations. If successful, simply increments the instruction stack and trace size and returns. It is
   the responsibility of the caller to populate the newly pushed instruction fields, which are undefined otherwise.

   https://github.com/anza-xyz/agave/blob/v2.0.0/program-runtime/src/invoke_context.rs#L246-L290 */
int
fd_instr_stack_push( fd_runtime_t *      runtime,
                     fd_txn_in_t const * txn_in,
                     fd_txn_out_t *      txn_out,
                     fd_instr_info_t *   instr ) {
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
  int err = fd_runtime_get_key_of_account_at_index( txn_out,
                                                    instr->program_id,
                                                    &program_id_pubkey );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.0/program-runtime/src/invoke_context.rs#L256-L286 */
  if( runtime->instr.stack_sz ) {
    /* https://github.com/anza-xyz/agave/blob/v2.0.0/program-runtime/src/invoke_context.rs#L261-L285 */
    uchar contains = 0;
    uchar is_last  = 0;

    // Checks all previous instructions in the stack for reentrancy
    for( uchar level=0; level<runtime->instr.stack_sz; level++ ) {
      fd_exec_instr_ctx_t * instr_ctx = &runtime->instr.stack[level];
      // Optimization: compare program id index instead of pubkey since account keys are unique
      if( instr->program_id == instr_ctx->instr->program_id ) {
        // Reentrancy not allowed unless caller is calling itself
        if( level == runtime->instr.stack_sz-1 ) {
          is_last = 1;
        }
        contains = 1;
      }
    }
    /* https://github.com/anza-xyz/agave/blob/v2.0.0/program-runtime/src/invoke_context.rs#L282-L285 */
    if( FD_UNLIKELY( contains && !is_last ) ) {
      return FD_EXECUTOR_INSTR_ERR_REENTRANCY_NOT_ALLOWED;
    }
  }
  /* "Push" a new instruction onto the stack by simply incrementing the stack and trace size counters
     https://github.com/anza-xyz/agave/blob/v2.0.0/program-runtime/src/invoke_context.rs#L289 */
  return fd_txn_ctx_push( runtime, txn_in, txn_out, instr );
}

/* Pops an instruction from the instruction stack. Agave's implementation performs instruction balancing checks every time pop is called,
   but error codes returned from `pop` are only used if the program's execution was successful. Therefore, we can optimize our code by only
   checking for unbalanced instructions if the program execution was successful within fd_execute_instr.

   https://github.com/anza-xyz/agave/blob/v2.0.0/program-runtime/src/invoke_context.rs#L293-L298 */
int
fd_instr_stack_pop( fd_runtime_t *          runtime,
                    fd_txn_out_t *          txn_out,
                    fd_instr_info_t const * instr ) {
  /* https://github.com/anza-xyz/agave/blob/v2.0.0/sdk/src/transaction_context.rs#L362-L364 */
  if( FD_UNLIKELY( runtime->instr.stack_sz==0 ) ) {
    return FD_EXECUTOR_INSTR_ERR_CALL_DEPTH;
  }
  runtime->instr.stack_sz--;

  /* Verify all executable accounts have no outstanding refs
     https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L367-L371 */
  for( ushort i=0; i<instr->acct_cnt; i++ ) {
    ushort idx_in_txn = instr->accounts[i].index_in_transaction;
    fd_account_meta_t const * meta = txn_out->accounts.account[ idx_in_txn ].meta;
    ulong refcnt = runtime->accounts.refcnt[idx_in_txn];
    if( FD_UNLIKELY( meta->executable && refcnt!=0UL ) ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_OUTSTANDING;
    }
  }

  /* Verify lamports are balanced before and after instruction
     https://github.com/anza-xyz/agave/blob/v2.0.0/sdk/src/transaction_context.rs#L366-L380 */
  ulong ending_lamports_h = 0UL;
  ulong ending_lamports_l = 0UL;
  int err = fd_instr_info_sum_account_lamports( instr,
                                                txn_out,
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
  int stack_pop_err = fd_instr_stack_pop( instr_ctx->runtime, instr_ctx->txn_out, instr );

  /* Only report the stack pop error on success */
  if( FD_UNLIKELY( instr_exec_result==FD_EXECUTOR_INSTR_SUCCESS && stack_pop_err ) ) {
    FD_TXN_PREPARE_ERR_OVERWRITE( instr_ctx->txn_out );
    FD_TXN_ERR_FOR_LOG_INSTR( instr_ctx->txn_out, stack_pop_err, instr_ctx->txn_out->err.exec_err_idx );
    instr_exec_result = stack_pop_err;
  }

  return instr_exec_result;
}

int
fd_execute_instr( fd_runtime_t *      runtime,
                  fd_bank_t *         bank,
                  fd_txn_in_t const * txn_in,
                  fd_txn_out_t *      txn_out,
                  fd_instr_info_t *   instr ) {
  fd_sysvar_cache_t const * sysvar_cache = fd_bank_sysvar_cache_query( bank );
  int instr_exec_result = fd_instr_stack_push( runtime, txn_in, txn_out, instr );
  if( FD_UNLIKELY( instr_exec_result ) ) {
    FD_TXN_PREPARE_ERR_OVERWRITE( txn_out );
    FD_TXN_ERR_FOR_LOG_INSTR( txn_out, instr_exec_result, txn_out->err.exec_err_idx );
    return instr_exec_result;
  }

  /* `process_executable_chain()`
      https://github.com/anza-xyz/agave/blob/v2.2.12/program-runtime/src/invoke_context.rs#L512-L619 */
  fd_exec_instr_ctx_t * ctx = &runtime->instr.stack[ runtime->instr.stack_sz - 1 ];
  *ctx = (fd_exec_instr_ctx_t) {
    .instr        = instr,
    .sysvar_cache = sysvar_cache,
    .runtime      = runtime,
    .txn_in       = txn_in,
    .txn_out      = txn_out,
    .bank         = bank,
  };
  fd_base58_encode_32( txn_out->accounts.keys[ instr->program_id ].uc, NULL, ctx->program_id_base58 );

  /* Look up the native program. We check for precompiles within the lookup function as well.
     https://github.com/anza-xyz/agave/blob/v2.1.6/svm/src/message_processor.rs#L88 */
  fd_exec_instr_fn_t native_prog_fn;
  uchar              is_precompile;
  int                err = fd_executor_lookup_native_program( &txn_out->accounts.keys[ instr->program_id ],
                                                              txn_out->accounts.account[ instr->program_id ].meta,
                                                              bank,
                                                              &native_prog_fn,
                                                              &is_precompile );

  if( FD_UNLIKELY( err ) ) {
    FD_TXN_PREPARE_ERR_OVERWRITE( txn_out );
    FD_TXN_ERR_FOR_LOG_INSTR( txn_out, err, txn_out->err.exec_err_idx );
    return err;
  }

  if( FD_LIKELY( native_prog_fn!=NULL ) ) {
    /* If this branch is taken, we've found an entrypoint to execute. */
    fd_log_collector_program_invoke( ctx );

    /* Only reset the return data when executing a native builtin program (not a precompile)
       https://github.com/anza-xyz/agave/blob/v2.1.6/program-runtime/src/invoke_context.rs#L536-L537 */
    if( FD_LIKELY( !is_precompile ) ) {
      txn_out->details.return_data.len = 0;
    }

    /* Execute the native program. */
    instr_exec_result = native_prog_fn( ctx );
  } else {
    /* Unknown program. In this case specifically, we should not log the program id. */
    instr_exec_result = FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
    FD_TXN_PREPARE_ERR_OVERWRITE( txn_out );
    FD_TXN_ERR_FOR_LOG_INSTR( txn_out, instr_exec_result, txn_out->err.exec_err_idx );
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
    if( !txn_out->err.exec_err ) {
      FD_TXN_PREPARE_ERR_OVERWRITE( txn_out );
      FD_TXN_ERR_FOR_LOG_INSTR( txn_out, instr_exec_result, txn_out->err.exec_err_idx );
      fd_log_collector_program_failure( ctx );
    } else {
      fd_log_collector_program_failure( ctx );
      FD_TXN_PREPARE_ERR_OVERWRITE( txn_out );
      FD_TXN_ERR_FOR_LOG_INSTR( txn_out, instr_exec_result, txn_out->err.exec_err_idx );
    }
  }

  return fd_execute_instr_end( ctx, instr, instr_exec_result );
}

void
fd_executor_reclaim_account( fd_account_meta_t * meta,
                             ulong               slot ) {
  meta->slot = slot;
  if( FD_UNLIKELY( meta->lamports==0UL ) ) {
    meta->dlen = 0UL;
    memset( meta->owner, 0, sizeof(fd_pubkey_t) );
  }
}

static void
fd_executor_setup_txn_account( fd_runtime_t *      runtime,
                               fd_bank_t *         bank,
                               fd_txn_in_t const * txn_in,
                               fd_txn_out_t *      txn_out,
                               ushort              idx,
                               uchar * *           writable_accs_mem,
                               ulong *             writable_accs_idx_out ) {
  /* To setup a transaction account, we need to first retrieve a
     read-only handle to the account from the database. */

  fd_pubkey_t *   address  = &txn_out->accounts.keys[ idx ];
  fd_accdb_rw_t * ref_slot = &txn_out->accounts.account[ idx ];

  fd_accdb_rw_t * account = NULL;
  int is_found_in_bundle = 0;
  if( txn_in->bundle.is_bundle ) {
    /* If we are in a bundle, that means that the latest version of an
       account may be a transaction account from a previous transaction
       and not in the accounts database.  This means we have to
       reference the previous transaction's account.  Because we are in
       a bundle, we know that the transaction accounts for all previous
       bundle transactions are valid.  We will also assume that the
       transactions are in execution order.

       TODO: This lookup can be made more performant by using a map
       from pubkey to the bundle transaction index and only inserting
       or updating when the account is writable. */

    for( ulong i=txn_in->bundle.prev_txn_cnt; i>0UL && !is_found_in_bundle; i-- ) {
      fd_txn_out_t * prev_txn_out = txn_in->bundle.prev_txn_outs[ i-1 ];
      for( ushort j=0UL; j<prev_txn_out->accounts.cnt; j++ ) {
        if( fd_pubkey_eq( &prev_txn_out->accounts.keys[ j ], address ) && prev_txn_out->accounts.is_writable[j] ) {
          /* Found the account in a previous transaction.
             Move ownership of reference from previous transaction to
             this one. */
          fd_memcpy( ref_slot, prev_txn_out->accounts.account[ j ].ref, sizeof(fd_accdb_rw_t) );
          account = ref_slot;
          is_found_in_bundle = 1;
          break;
        }
      }
    }
  }

  if( FD_LIKELY( !account ) ) {
    fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( bank ), bank->data->idx } };
    account = (fd_accdb_rw_t *)fd_accdb_open_ro( runtime->accdb, ref_slot->ro, &xid, address );
    /* creates a database reference, which is explicitly dropped here
       or in commit/cancel */
  }

  if( txn_out->accounts.is_writable[ idx ] ) {
    /* If the account is writable or a fee payer, then we need to create
       staging regions for the account. If the account exists, copy the
       account data into the staging area; otherwise, initialize a new
       metadata. */
    uchar * new_raw_data = writable_accs_mem[ *writable_accs_idx_out ];
    ulong   dlen         = !!account ? fd_accdb_ref_data_sz( (fd_accdb_ro_t *)account ) : 0UL;
    (*writable_accs_idx_out)++;

    if( FD_LIKELY( account ) ) {
      /* Create copy of account, release reference of original */
      fd_memcpy( new_raw_data, account->meta, sizeof(fd_account_meta_t)+dlen );
      fd_accdb_close_ro( runtime->accdb, (fd_accdb_ro_t *)account );
    } else {
      /* Account did not exist, set up metadata */
      fd_account_meta_init( (fd_account_meta_t *)new_raw_data );
    }

    account = fd_accdb_rw_init_nodb(
        (fd_accdb_rw_t *)ref_slot,
        address,
        (fd_account_meta_t *)new_raw_data,
        FD_RUNTIME_ACC_SZ_MAX
    );

  } else {
    /* If the account is not writable, then we can simply initialize
       the txn account with the read-only accountsdb record. However,
       if the account does not exist, we need to initialize a new
       metadata. */
    if( FD_UNLIKELY( fd_pubkey_eq( address, &fd_sysvar_instructions_id ) ) ) {
      fd_account_meta_t * meta = fd_account_meta_init( (void *)runtime->accounts.sysvar_instructions_mem );
      account = (fd_accdb_rw_t *)fd_accdb_ro_init_nodb( (fd_accdb_ro_t *)ref_slot, address, meta );
    } else if( FD_LIKELY( account && !is_found_in_bundle ) ) {
      /* transfer ownership of reference to runtime struct
         account is freed in cancel/commit */
    } else if( FD_LIKELY( account && is_found_in_bundle ) ) {
      /* If the account is found in the bundle, we need to create a new
      reference to the account */
      account = (fd_accdb_rw_t *)fd_accdb_ro_init_nodb( (fd_accdb_ro_t *)ref_slot, address, account->meta );
    } else {
      account = (fd_accdb_rw_t *)fd_accdb_ro_init_nodb( (fd_accdb_ro_t *)ref_slot, address, &FD_ACCOUNT_META_DEFAULT );
    }
  }

  runtime->accounts.starting_lamports[idx] = fd_accdb_ref_lamports( account->ro );
  runtime->accounts.starting_dlen[idx]     = fd_accdb_ref_data_sz ( account->ro );
  runtime->accounts.refcnt[idx]            = 0UL;
}

static void
fd_executor_setup_executable_account( fd_runtime_t *            runtime,
                                      fd_bank_t *               bank,
                                      fd_account_meta_t const * program_meta,
                                      ushort *                  executable_idx ) {
  fd_bpf_upgradeable_loader_state_t program_loader_state[1];
  int err = fd_bpf_loader_program_get_state( program_meta, program_loader_state );
  if( FD_UNLIKELY( err!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return;
  }

  if( !fd_bpf_upgradeable_loader_state_is_program( program_loader_state ) ) {
    return;
  }

  /* Attempt to load the program data account from funk. This prevents any unknown program
      data accounts from getting loaded into the executable accounts list. If such a program is
      invoked, the call will fail at the instruction execution level since the programdata
      account will not exist within the executable accounts list. */
  fd_pubkey_t *     programdata_acc = &program_loader_state->inner.program.programdata_address;
  fd_funk_txn_xid_t xid             = { .ul = { fd_bank_slot_get( bank ), bank->data->idx } };

  fd_accdb_ro_t * ro = &runtime->accounts.executable[ *executable_idx ];
  ro = fd_accdb_open_ro( runtime->accdb, ro, &xid, programdata_acc );
  if( FD_LIKELY( ro ) ) (*executable_idx)++;
}

void
fd_executor_setup_accounts_for_txn( fd_runtime_t *      runtime,
                                    fd_bank_t *         bank,
                                    fd_txn_in_t const * txn_in,
                                    fd_txn_out_t *      txn_out ) {

  /* At this point, the total number of writable accounts in the
     transaction is known.  We can now attempt to get the required
     amount of memory from the account memory pool. */

  ushort writable_account_cnt = 0U;
  for( ushort i=0; i<txn_out->accounts.cnt; i++ ) {
    if( fd_runtime_account_is_writable_idx( txn_in, txn_out, bank, i ) ) {
      txn_out->accounts.is_writable[ i ] = 1;
      writable_account_cnt++;
    } else {
      txn_out->accounts.is_writable[ i ] = 0;
    }
  }

  /* At this point we know which accounts are writable, but we don't
     know if we will need to create an account for the rollback fee
     payer or nonce account.  To avoid a potential deadlock, we want to
     request the worst-case number of accounts (# writable accounts + 2
     rollback accounts) for the transaction in one call to
     fd_acc_pool_acquire. */

  ulong   writable_accs_idx = 0UL;
  uchar * writable_accs_mem[ MAX_TX_ACCOUNT_LOCKS + 2UL ];
  fd_acc_pool_acquire( runtime->acc_pool, writable_account_cnt + 2UL, writable_accs_mem );
  txn_out->accounts.rollback_fee_payer_mem = writable_accs_mem[ writable_account_cnt ];
  txn_out->accounts.rollback_nonce_mem     = writable_accs_mem[ writable_account_cnt+1UL ];

  ushort executable_idx = 0U;
  for( ushort i=0; i<txn_out->accounts.cnt; i++ ) {
    fd_executor_setup_txn_account( runtime, bank, txn_in, txn_out, i, writable_accs_mem, &writable_accs_idx );
    fd_account_meta_t * meta = txn_out->accounts.account[ i ].meta;

    if( FD_UNLIKELY( meta && memcmp( meta->owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
      fd_executor_setup_executable_account( runtime, bank, meta, &executable_idx );
    }
  }

  txn_out->accounts.is_setup         = 1;
  txn_out->accounts.nonce_idx_in_txn = ULONG_MAX;
  runtime->accounts.executable_cnt   = executable_idx;

# if FD_HAS_FLATCC
  /* Dumping ELF files to protobuf, if applicable */
  int dump_elf_to_pb = runtime->log.capture_ctx &&
                       fd_bank_slot_get( bank ) >= runtime->log.capture_ctx->dump_proto_start_slot &&
                       runtime->log.capture_ctx->dump_elf_to_pb;
  if( FD_UNLIKELY( dump_elf_to_pb ) ) {
    for( ushort i=0; i<txn_out->accounts.cnt; i++ ) {
      fd_account_meta_t * acc_meta = txn_out->accounts.account[i].meta;
      fd_pubkey_t *       acc_pubkey = &txn_out->accounts.keys[i];
      fd_dump_elf_to_protobuf( runtime, bank, txn_in, acc_pubkey, acc_meta );
    }
  }
# endif
}

int
fd_executor_txn_verify( fd_txn_p_t *  txn_p,
                        fd_sha512_t * shas[ FD_TXN_ACTUAL_SIG_MAX ] ) {
  fd_txn_t * txn = TXN( txn_p );

  uchar * signatures = txn_p->payload + txn->signature_off;
  uchar * pubkeys    = txn_p->payload + txn->acct_addr_off;
  uchar * msg        = txn_p->payload + txn->message_off;
  ulong   msg_sz     = txn_p->payload_sz - txn->message_off;

  int res = fd_ed25519_verify_batch_single_msg( msg, msg_sz, signatures, pubkeys, shas, txn->signature_cnt );
  if( FD_UNLIKELY( res != FD_ED25519_SUCCESS ) ) {
    return FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

static int
fd_executor_txn_check( fd_runtime_t * runtime,
                       fd_bank_t *    bank,
                       fd_txn_out_t * txn_out ) {
  fd_rent_t const * rent = fd_bank_rent_query( bank );

  ulong starting_lamports_l = 0;
  ulong starting_lamports_h = 0;

  ulong ending_lamports_l = 0;
  ulong ending_lamports_h = 0;

  /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L63 */
  for( ulong idx = 0; idx < txn_out->accounts.cnt; idx++ ) {
    ulong               starting_lamports  = runtime->accounts.starting_lamports[idx];
    ulong               starting_dlen      = runtime->accounts.starting_dlen[idx];
    fd_account_meta_t * meta               = txn_out->accounts.account[idx].meta;
    fd_pubkey_t *       pubkey             = &txn_out->accounts.keys[idx];

    // Was this account written to?
    /* TODO: Clean this logic up... lots of redundant checks with our newer account loading model.
       We should be using the rent transition checking logic instead, along with a small refactor
       to keep check ordering consistent. */
    if( meta!=NULL ) {

      fd_uwide_inc( &ending_lamports_h, &ending_lamports_l, ending_lamports_h, ending_lamports_l, meta->lamports );

      /* Rent states are defined as followed:
         - lamports == 0                      -> Uninitialized
         - 0 < lamports < rent_exempt_minimum -> RentPaying
         - lamports >= rent_exempt_minimum    -> RentExempt
         In Agave, 'self' refers to our 'after' state. */
      uchar after_uninitialized  = meta->lamports == 0;
      uchar after_rent_exempt    = meta->lamports >= fd_rent_exempt_minimum_balance( rent, meta->dlen );

      /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L96 */
      if( FD_LIKELY( memcmp( pubkey, fd_sysvar_incinerator_id.key, sizeof(fd_pubkey_t) ) != 0 ) ) {
        /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L44 */
        if( after_uninitialized || after_rent_exempt ) {
          // no-op
        } else {
          /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L45-L59 */
          uchar before_uninitialized = starting_dlen == ULONG_MAX || starting_lamports == 0;
          uchar before_rent_exempt   = starting_dlen != ULONG_MAX && starting_lamports >= fd_rent_exempt_minimum_balance( rent, starting_dlen );

          /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L50 */
          if( before_uninitialized || before_rent_exempt ) {
            /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L104 */
            return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
          /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L56 */
          } else if( (meta->dlen == starting_dlen) && meta->lamports <= starting_lamports ) {
            // no-op
          } else {
            /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L104 */
            return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
          }
        }
      }

      if( starting_lamports != ULONG_MAX ) {
        fd_uwide_inc( &starting_lamports_h, &starting_lamports_l, starting_lamports_h, starting_lamports_l, starting_lamports );
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


int
fd_execute_txn( fd_runtime_t *      runtime,
                fd_bank_t *         bank,
                fd_txn_in_t const * txn_in,
                fd_txn_out_t *      txn_out ) {
  fd_accdb_user_t * accdb = runtime->accdb;

  bool dump_insn = runtime->log.capture_ctx && fd_bank_slot_get( bank ) >= runtime->log.capture_ctx->dump_proto_start_slot && runtime->log.capture_ctx->dump_instr_to_pb;
  (void)dump_insn;

  fd_txn_t const * txn = TXN( txn_in->txn );

  /* Initialize log collection. */
  fd_log_collector_init( runtime->log.log_collector, runtime->log.enable_log_collector );

  for( ushort i=0; i<TXN( txn_in->txn )->instr_cnt; i++ ) {
    /* Set up the instr info for the current instruction */
    fd_instr_info_t * instr_info = &runtime->instr.trace[runtime->instr.trace_length++];
    fd_instr_info_init_from_txn_instr(
        instr_info,
        bank,
        txn_in,
        txn_out,
        &txn->instr[i]
    );

#   if FD_HAS_FLATCC
    if( FD_UNLIKELY( dump_insn ) ) {
      // Capture the input and convert it into a Protobuf message
      fd_dump_instr_to_protobuf( runtime, bank, txn_in, txn_out, instr_info, i );
    }
#   endif

    /* Update the current executing instruction index */
    runtime->instr.current_idx = i;

    /* Execute the current instruction */
    ulong account_refs_pre = accdb->base.ro_active + accdb->base.rw_active;
    int instr_exec_result = fd_execute_instr( runtime, bank, txn_in, txn_out, instr_info );
    ulong account_refs_post = accdb->base.ro_active + accdb->base.rw_active;
    if( FD_UNLIKELY( account_refs_post != account_refs_pre ) ) {
      FD_BASE58_ENCODE_64_BYTES( fd_txn_get_signatures( txn, txn_in->txn->payload )[0], txn_b58 );
      FD_LOG_CRIT(( "fd_execute_instr(txn=%s,instr_idx=%u) leaked %lu account references",
                    txn_b58, i, account_refs_post-account_refs_pre ));
    }
    if( FD_UNLIKELY( instr_exec_result!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
      if( txn_out->err.exec_err_idx==INT_MAX ) {
        txn_out->err.exec_err_idx = i;
      }
      return FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
    }
  }

  /* TODO: This function needs to be split out of fd_execute_txn and be placed
      into the replay tile once it is implemented. */
  return fd_executor_txn_check( runtime, bank, txn_out );
}

int
fd_executor_consume_cus( fd_txn_out_t * txn_out,
                         ulong          cus ) {
  ulong new_cus   =  txn_out->details.compute_budget.compute_meter - cus;
  int   underflow = (txn_out->details.compute_budget.compute_meter < cus);
  if( FD_UNLIKELY( underflow ) ) {
    txn_out->details.compute_budget.compute_meter = 0UL;
    return FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED;
  }
  txn_out->details.compute_budget.compute_meter = new_cus;
  return FD_EXECUTOR_INSTR_SUCCESS;
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
  case FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR                         : return ""; // custom handling via txn_ctx->err.custom_err
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
