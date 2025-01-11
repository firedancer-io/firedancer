#include "fd_executor.h"
#include "fd_acc_mgr.h"
#include "fd_hashes.h"
#include "fd_runtime_err.h"
#include "context/fd_exec_slot_ctx.h"
#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"

#include "../../util/rng/fd_rng.h"
#include "fd_system_ids.h"
#include "fd_account.h"
#include "program/fd_address_lookup_table_program.h"
#include "program/fd_bpf_loader_program.h"
#include "program/fd_loader_v4_program.h"
#include "program/fd_compute_budget_program.h"
#include "program/fd_config_program.h"
#include "program/fd_precompiles.h"
#include "program/fd_stake_program.h"
#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"
#include "program/fd_zk_elgamal_proof_program.h"
#include "program/fd_bpf_program_util.h"
#include "sysvar/fd_sysvar_cache.h"
#include "sysvar/fd_sysvar_slot_history.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_instructions.h"

#include "tests/fd_dump_pb.h"

#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/pack/fd_pack.h"
#include "../../ballet/pack/fd_pack_cost.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"
#include "../../ballet/pack/fd_pack.h"

#include "../../util/bits/fd_uwide.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>   /* snprintf(3) */
#include <fcntl.h>   /* openat(2) */
#include <unistd.h>  /* write(3) */
#include <time.h>

#define MAX_COMPUTE_UNITS_PER_BLOCK                (48000000UL)
#define MAX_COMPUTE_UNITS_PER_WRITE_LOCKED_ACCOUNT (12000000UL)
/* We should strive for these max limits matching between pack and the
   runtime. If there's a reason for these limits to mismatch, and there
   could be, then someone should explicitly document that when relaxing
   these assertions. */
FD_STATIC_ASSERT( FD_PACK_MAX_COST_PER_BLOCK==MAX_COMPUTE_UNITS_PER_BLOCK,                     executor_pack_max_mismatch );
FD_STATIC_ASSERT( FD_PACK_MAX_WRITE_COST_PER_ACCT==MAX_COMPUTE_UNITS_PER_WRITE_LOCKED_ACCOUNT, executor_pack_max_mismatch );

/* TODO: precompiles currently enter this noop function. Once the move_precompile_verification_to_svm
   feature gets activated, this will need to be replaced with precompile verification functions. */
static int
fd_noop_instr_execute( fd_exec_instr_ctx_t * ctx FD_PARAM_UNUSED ) {
  return FD_EXECUTOR_INSTR_SUCCESS;
}

struct fd_native_prog_info {
  fd_pubkey_t key;
  fd_exec_instr_fn_t fn;
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

#define MAP_PERFECT_0       ( VOTE_PROG_ID            ), .fn = fd_vote_program_execute
#define MAP_PERFECT_1       ( SYS_PROG_ID             ), .fn = fd_system_program_execute
#define MAP_PERFECT_2       ( CONFIG_PROG_ID          ), .fn = fd_config_program_execute
#define MAP_PERFECT_3       ( STAKE_PROG_ID           ), .fn = fd_stake_program_execute
#define MAP_PERFECT_4       ( COMPUTE_BUDGET_PROG_ID  ), .fn = fd_compute_budget_program_execute
#define MAP_PERFECT_5       ( ADDR_LUT_PROG_ID        ), .fn = fd_address_lookup_table_program_execute
#define MAP_PERFECT_6       ( ZK_EL_GAMAL_PROG_ID     ), .fn = fd_executor_zk_elgamal_proof_program_execute
#define MAP_PERFECT_7       ( BPF_LOADER_1_PROG_ID    ), .fn = fd_bpf_loader_program_execute
#define MAP_PERFECT_8       ( BPF_LOADER_2_PROG_ID    ), .fn = fd_bpf_loader_program_execute
#define MAP_PERFECT_9       ( BPF_UPGRADEABLE_PROG_ID ), .fn = fd_bpf_loader_program_execute
#define MAP_PERFECT_10      ( LOADER_V4_PROG_ID       ), .fn = fd_loader_v4_program_execute
#define MAP_PERFECT_11      ( ED25519_SV_PROG_ID      ), .fn = fd_noop_instr_execute
#define MAP_PERFECT_12      ( KECCAK_SECP_PROG_ID     ), .fn = fd_noop_instr_execute
#define MAP_PERFECT_13      ( SECP256R1_PROG_ID       ), .fn = fd_noop_instr_execute

#include "../../util/tmpl/fd_map_perfect.c"
#undef PERFECT_HASH

/* https://github.com/anza-xyz/agave/blob/9efdd74b1b65ecfd85b0db8ad341c6bd4faddfef/program-runtime/src/invoke_context.rs#L461-L488 */
fd_exec_instr_fn_t
fd_executor_lookup_native_program( fd_borrowed_account_t const * prog_acc ) {
  fd_pubkey_t const * pubkey        = prog_acc->pubkey;
  fd_pubkey_t const * owner         = (fd_pubkey_t const *)prog_acc->const_meta->info.owner;

  /* Native programs should be owned by the native loader...
     This will not be the case though once core programs are migrated to BPF. */
  int is_native_program = !memcmp( owner, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) );
  if( FD_UNLIKELY( !memcmp( pubkey, fd_solana_ed25519_sig_verify_program_id.key, sizeof(fd_pubkey_t) ) &&
                   !memcmp( owner,  fd_solana_system_program_id.key,             sizeof(fd_pubkey_t) ) ) ) {
    /* ... except for the special case for testnet ed25519, which is
       bizarrely owned by the system program. */
    is_native_program = 1;
  }
  fd_pubkey_t const * lookup_pubkey = is_native_program ? pubkey : owner;
  const fd_native_prog_info_t null_function = (const fd_native_prog_info_t) {0};
  return fd_native_program_fn_lookup_tbl_query( lookup_pubkey, &null_function )->fn;
}

/* Returns 1 if the sysvar instruction is used, 0 otherwise */
uint
fd_executor_txn_uses_sysvar_instructions( fd_exec_txn_ctx_t const * txn_ctx ) {
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    if( FD_UNLIKELY( memcmp( txn_ctx->accounts[i].key, fd_sysvar_instructions_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
      return 1;
    }
  }

  return 0;
}

int
fd_executor_is_system_nonce_account( fd_borrowed_account_t * account ) {
FD_SCRATCH_SCOPE_BEGIN {
  if ( memcmp( account->const_meta->info.owner, fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) ) == 0 ) {
    if ( account->const_meta->dlen == 0 ) {
      return 0;
    } else if ( account->const_meta->dlen == 80 ) { // TODO: nonce size macro
      fd_bincode_decode_ctx_t decode = { .data = account->const_data,
                                         .dataend = account->const_data + account->const_meta->dlen,
                                         .valloc = fd_scratch_virtual() };
      fd_nonce_state_versions_t nonce_versions;
      if (fd_nonce_state_versions_decode( &nonce_versions, &decode ) != 0 ) {
        return -1;
      }
      fd_nonce_state_t * state;;
      if ( fd_nonce_state_versions_is_current( &nonce_versions ) ) {
        state = &nonce_versions.inner.current;
      } else {
        state = &nonce_versions.inner.legacy;
      }

      if ( fd_nonce_state_is_initialized( state ) ) {
        return 1;
      }
    }
  }

  return -1;
} FD_SCRATCH_SCOPE_END;
}

static int
check_rent_transition( fd_borrowed_account_t * account, fd_rent_t const * rent, ulong fee ) {
  ulong min_balance   = fd_rent_exempt_minimum_balance( rent, account->const_meta->dlen );
  ulong pre_lamports  = account->const_meta->info.lamports;
  uchar pre_is_exempt = pre_lamports >= min_balance;

  ulong post_lamports  = pre_lamports - fee;
  uchar post_is_exempt = post_lamports >= min_balance;

  if ( post_lamports == 0 || post_is_exempt ) {
    return 1;
  }

  if ( pre_lamports == 0 || pre_is_exempt ) {
    return 0;
  }

  return post_lamports <= pre_lamports;
}

/* https://github.com/anza-xyz/agave/blob/v2.0.2/svm/src/account_loader.rs#L103 */
int
fd_validate_fee_payer( fd_borrowed_account_t * account, fd_rent_t const * rent, ulong fee ) {
  if( FD_UNLIKELY( account->const_meta->info.lamports==0UL ) ) {
    return FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND;
  }

  ulong min_balance = 0UL;

  int is_nonce = fd_executor_is_system_nonce_account( account );
  if ( FD_UNLIKELY( is_nonce<0 ) ) {
    return FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_FOR_FEE;
  }

  if( is_nonce ) {
    min_balance = fd_rent_exempt_minimum_balance( rent, 80 );
  }

  ulong out = ULONG_MAX;
  int cf = fd_ulong_checked_sub( account->const_meta->info.lamports, min_balance, &out);
  if( FD_UNLIKELY( cf!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
  }

  cf = fd_ulong_checked_sub( out, fee, &out );
  if( FD_UNLIKELY( cf!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
  }

  if( FD_UNLIKELY( account->const_meta->info.lamports<fee ) ) {
    return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
  } else if( FD_UNLIKELY( memcmp( account->pubkey->key, fd_sysvar_incinerator_id.key, sizeof(fd_pubkey_t) ) != 0 &&
                          !check_rent_transition( account, rent, fee ) ) ) {
    return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

static int
status_check_tower( ulong slot, void * _ctx ) {
  fd_exec_slot_ctx_t * ctx = (fd_exec_slot_ctx_t *)_ctx;
  if( slot==ctx->slot_bank.slot ) {
    return 1;
  }

  if( fd_txncache_is_rooted_slot( ctx->status_cache, slot ) ) {
    return 1;
  }

  if( fd_sysvar_slot_history_find_slot( ctx->slot_history, slot ) == FD_SLOT_HISTORY_SLOT_FOUND ) {
    return 1;
  }

  return 0;
}

static int
fd_executor_check_status_cache( fd_exec_txn_ctx_t * txn_ctx ) {

  if( FD_UNLIKELY( !txn_ctx->slot_ctx->status_cache ) ) {
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

  // TODO: figure out if it is faster to batch query properly and loop all txns again
  int err;
  fd_txncache_query_batch( txn_ctx->slot_ctx->status_cache, &curr_query, 1UL, (void *)txn_ctx->slot_ctx, status_check_tower, &err );
  return err;
}

/* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/runtime/src/bank.rs#L3596-L3605 */
int
fd_executor_check_transactions( fd_exec_txn_ctx_t * txn_ctx ) {
  /* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/runtime/src/bank.rs#L3603 */
  int err = fd_check_transaction_age( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/runtime/src/bank.rs#L3604 */
  err = fd_executor_check_status_cache( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/verify_precompiles.rs#L11-L34 */
int
fd_executor_verify_precompiles( fd_exec_txn_ctx_t * txn_ctx ) {
  ushort                 instr_cnt = txn_ctx->txn_descriptor->instr_cnt;
  fd_acct_addr_t const * tx_accs   = fd_txn_get_acct_addrs( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw );
  int                    err       = 0;
  for( ushort i=0; i<instr_cnt; i++ ) {
    fd_txn_instr_t  const * instr      = &txn_ctx->txn_descriptor->instr[i];
    fd_acct_addr_t  const * program_id = tx_accs + instr->program_id;
    if( !memcmp( program_id, &fd_solana_ed25519_sig_verify_program_id, sizeof(fd_pubkey_t) ) ) {
      err = fd_precompile_ed25519_verify( txn_ctx, instr );
      if( FD_UNLIKELY( err ) ) {
        FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, err, i );
        return FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
      }
    } else if( !memcmp( program_id, &fd_solana_keccak_secp_256k_program_id, sizeof(fd_pubkey_t) )) {
      err = fd_precompile_secp256k1_verify( txn_ctx, instr );
      if( FD_UNLIKELY( err ) ) {
        FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, err, i );
        return FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
      }
    } else if( !memcmp( program_id, &fd_solana_secp256r1_program_id, sizeof(fd_pubkey_t)) && FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, enable_secp256r1_precompile ) ) {
      err = fd_precompile_secp256r1_verify( txn_ctx, instr );
      if( FD_UNLIKELY( err ) ) {
        FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, err, i );
        return FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
      }
    }
  }
  return FD_RUNTIME_EXECUTE_SUCCESS;
}


/* Only accounts in the transaction account keys that are owned by one of the four 
   loaders (bpf v1, v2, v3, v4) are iterated over in Agave's replenish_program_cache() 
   function to be loaded into the program cache. An account may be in the program cache 
   iff the owners match one of the four loaders since `filter_executable_program_accounts()` 
   filters out all other accounts here:
   https://github.com/anza-xyz/agave/blob/v2.1/svm/src/transaction_processor.rs#L530-L560
 
   If this check holds true, the account is promoted to an executable account within 
   `fd_execute_load_transaction_accounts()`, which sadly involves modifying its read-only metadata
   to set the `executable` flag to true.
 
   Note that although the v4 loader is not yet activated, Agave still checks that the
   owner matches one of the four bpf loaders provided in the hyperlink below
   within `filter_executable_program_accounts()`:
   https://github.com/anza-xyz/agave/blob/v2.1/sdk/account/src/lib.rs#L800-L806 */
FD_FN_PURE static inline int
is_maybe_in_loaded_program_cache( fd_borrowed_account_t const * acct ) {
  return !memcmp( acct->const_meta->info.owner, fd_solana_bpf_loader_deprecated_program_id.key,  sizeof(fd_pubkey_t) ) ||
         !memcmp( acct->const_meta->info.owner, fd_solana_bpf_loader_program_id.key,             sizeof(fd_pubkey_t) ) ||
         !memcmp( acct->const_meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ||
         !memcmp( acct->const_meta->info.owner, fd_solana_bpf_loader_v4_program_id.key,          sizeof(fd_pubkey_t) );
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

/* https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/account_loader.rs#L191-L372 */
int
fd_executor_load_transaction_accounts( fd_exec_txn_ctx_t * txn_ctx ) {

  ulong                 requested_loaded_accounts_data_size = txn_ctx->loaded_accounts_data_size_limit;
  ulong                 accumulated_account_size            = 0UL;
  fd_rawtxn_b_t const * txn_raw                             = txn_ctx->_txn_raw;
  ushort                instr_cnt                           = txn_ctx->txn_descriptor->instr_cnt;

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/svm/src/account_loader.rs#L323-L337 
     
     In the agave client, this big chunk of code is responsible for loading in all of the
     accounts in the transaction, mimicking each call to `load_transaction_account()`
     (https://github.com/anza-xyz/agave/blob/v2.1.0/svm/src/account_loader.rs#L406-L497)
     
     This contains a LOT of special casing as their accounts database and program cache
     is handled very differently than the FD client.

     The logic is as follows:
     1. If the account is the instructions sysvar, then load in the compiled
        instructions from the transactions into the sysvar's data.
     2. If the account is a fee payer, then it is already loaded.
     3. If the account is an account override, then handle seperately. Account
        overrides are used for simulating transactions. 
        - This is only used for testing.
     4. If the account is not writable and not an instruction account and it is
        in the loaded program cache, then load in a dummy account with the
        correct owner and the executable flag set to true.
        - See comments below
     5. Otherwise load in the account from the accounts DB. If the account is
        writable try to collect rent from the account.

     After the account is loaded, accumulate the data size to make sure the
     transaction doesn't violate the transaction loading limit.

     In the firedancer client only some of these steps are necessary because
     all of the accounts are loaded in from the accounts db into borrowed
     accounts already.
     1. If the account is writable, try to collect fees on the account. Unlike
        the agave client, this is also done on the fee payer account. The agave
        client tries to collect rent on the fee payer while the fee is being
        collected in validate_fees().
     2. If the account is not writable and it is not an instruction account
        and would be in the loaded program cache, then it should be replaced
        with a dummy value.
     */

  fd_epoch_schedule_t const * schedule = fd_sysvar_cache_epoch_schedule( txn_ctx->slot_ctx->sysvar_cache );
  ulong                       epoch    = fd_slot_to_epoch( schedule, txn_ctx->slot_ctx->slot_bank.slot, NULL );

  /* In `load_transaction_account()`, there are special checks based on the priviledges of each account key.
     We precompute the results here before proceeding with the special casing. Note the start range of 1 since
     `load_transaction_account()` doesn't handle the fee payer. */
  uchar txn_account_is_instruction_account[MAX_TX_ACCOUNT_LOCKS] = {0};
  for( ushort i=0UL; i<instr_cnt; i++ ) {
    /* Set up the instr infos for the transaction */
    fd_txn_instr_t const * instr = &txn_ctx->txn_descriptor->instr[i];
    fd_convert_txn_instr_to_instr( txn_ctx, instr, txn_ctx->borrowed_accounts, &txn_ctx->instr_infos[i] );

    uchar const * instr_acc_idxs = fd_txn_get_instr_accts( instr, txn_raw->raw );
    for( ushort j=0; j<instr->acct_cnt; j++ ) {
      uchar txn_acc_idx                               = instr_acc_idxs[j];
      txn_account_is_instruction_account[txn_acc_idx] = 1;
    }
  }
  txn_ctx->instr_info_cnt = txn_ctx->txn_descriptor->instr_cnt;

  for( ulong i=1UL; i<txn_ctx->accounts_cnt; i++ ) {
    fd_borrowed_account_t * acct = &txn_ctx->borrowed_accounts[i];

    /* https://github.com/anza-xyz/agave/blob/v2.1.0/svm/src/account_loader.rs#L418-L421 */
    uchar is_instruction_account = txn_account_is_instruction_account[i];
    uchar is_writable            = !!( fd_txn_account_is_writable_idx( txn_ctx, (int)i ) );

    /* https://github.com/anza-xyz/agave/blob/v2.1.0/svm/src/account_loader.rs#L417 */

    int   err      = fd_txn_borrowed_account_view_idx( txn_ctx, (uchar)i, &acct );
    ulong acc_size = err==FD_ACC_MGR_SUCCESS ? acct->const_meta->dlen : 0UL;

    /* `load_transaction_account()`
        https://github.com/anza-xyz/agave/blob/v2.1.0/svm/src/account_loader.rs#L406-L497 */

    /* First case: checking if the account is the instructions sysvar
       https://github.com/anza-xyz/agave/blob/v2.1.0/svm/src/account_loader.rs#L422-L429 */
    if( FD_UNLIKELY( !memcmp( acct->pubkey->key, fd_sysvar_instructions_id.key, sizeof(fd_pubkey_t) ) ) ) {
      acct->account_found = 1;
      fd_sysvar_instructions_serialize_account( txn_ctx, (fd_instr_info_t const *)txn_ctx->instr_infos, txn_ctx->txn_descriptor->instr_cnt );
      /* Continue because this should not be counted towards the total loaded account size.
         https://github.com/anza-xyz/agave/blob/v2.1.0/svm/src/account_loader.rs#L426 */
      continue;
    } 

    /* Second case: loading a program account that is not writable, not an instruction account,
       not already executable, and may be in the loaded program cache. We bypass this special casing
       if `disable_account_loader_special_case` is active.
       https://github.com/anza-xyz/agave/blob/v2.1.0/svm/src/account_loader.rs#L438-L451 */
    if( FD_UNLIKELY( !fd_account_is_executable( acct->const_meta ) && 
                     !is_instruction_account && !is_writable && 
                     !FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, disable_account_loader_special_case ) && 
                     is_maybe_in_loaded_program_cache( acct ) ) ) {
      /* In the corresponding branch in the agave client, a dummy account is loaded in that has the
         executable flag set to true. This is a hack to mirror those semantics.
         https://github.com/anza-xyz/agave/blob/v2.1.0/svm/src/account_loader.rs#L499-L507 */
      void * borrowed_account_data = fd_spad_alloc( txn_ctx->spad, FD_ACCOUNT_REC_ALIGN, FD_ACC_TOT_SZ_MAX );
      fd_borrowed_account_make_readonly_copy( acct, borrowed_account_data );
      fd_account_meta_t * meta = (fd_account_meta_t *)acct->const_meta;
      meta->info.executable = 1;
      acct->account_found = 1;
    }
    /* Third case: Default case 
       https://github.com/anza-xyz/agave/blob/v2.1.0/svm/src/account_loader.rs#L452-L494 */
    else {
      /* If the account exists and is writable, collect rent from it. */
      if( FD_LIKELY( acct->account_found ) ) {
        if( is_writable ) {
          txn_ctx->collected_rent += fd_runtime_collect_rent_from_account( txn_ctx->slot_ctx, acct->meta, acct->pubkey, epoch );
          acct->starting_lamports = acct->meta->info.lamports;
        }
      }
    }

    err = accumulate_and_check_loaded_account_data_size( acc_size,
                                                         requested_loaded_accounts_data_size,
                                                         &accumulated_account_size );

    if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      return err;
    }
  }

  fd_pubkey_t program_owners[instr_cnt];
  ushort      program_owners_cnt = 0;

  /* The logic below handles special casing with loading instruction accounts.
     https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/account_loader.rs#L297-L358 */
  for( ushort i=0; i<instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &txn_ctx->txn_descriptor->instr[i];
    /* https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/account_loader.rs#L304-306 */
    fd_borrowed_account_t * program_account = NULL;
    int err = fd_txn_borrowed_account_view_idx_allow_dead( txn_ctx, instr->program_id, &program_account );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      return FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/account_loader.rs#L307-309 */
    if( FD_UNLIKELY( !memcmp( program_account->pubkey->key, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) ) ) {
      continue;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/account_loader.rs#L311-L314 */
    if( FD_UNLIKELY( !program_account->account_found ) ) {
      return FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
    }

    /* The above checks from the mirrored `load_transaction_account()` function would promote
       this account to executable if necessary, so this check is sufficient.
       https://github.com/anza-xyz/agave/blob/89872fdb074e6658646b2b57a299984f0059cc84/svm/src/account_loader.rs#L493-L500 */
    if( FD_UNLIKELY( !FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, remove_accounts_executable_flag_checks ) && 
                     !fd_account_is_executable( program_account->const_meta ) ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION;
    }

    /* At this point, program_indices will no longer have 0 length, so we are set this flag to 1 */
    /* https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/account_loader.rs#L321 */

    /* https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/account_loader.rs#L322-325 */
    if( !memcmp( program_account->const_meta->info.owner, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) ) {
      continue;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/account_loader.rs#L326-330
       The agave client does checks on the program account's owners as well.
       However, it is important to not do these checks multiple times as the
       total size of accounts and their owners are accumulated: duplicate owners
       should be avoided. */

    /* https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/account_loader.rs#L334-353 */
    FD_BORROWED_ACCOUNT_DECL( owner_account );
    err = fd_acc_mgr_view( txn_ctx->slot_ctx->acc_mgr, txn_ctx->slot_ctx->funk_txn, (fd_pubkey_t *) program_account->const_meta->info.owner, owner_account );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      return FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
    }

    for( ushort i=0; i<program_owners_cnt; i++ ) {
      if( !memcmp( program_owners[i].key, owner_account->pubkey, sizeof(fd_pubkey_t) ) ) {
        /* If the owner account has already been seen, skip the owner checks
           and do not acccumulate the account size. */
        continue;
      }
    }

    /* https://github.com/anza-xyz/agave/blob/89872fdb074e6658646b2b57a299984f0059cc84/svm/src/account_loader.rs#L537-L545 */
    if( FD_UNLIKELY( memcmp( owner_account->const_meta->info.owner, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) ||
                     ( !FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, remove_accounts_executable_flag_checks ) &&
                       !fd_account_is_executable( owner_account->const_meta ) ) ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.0.9/svm/src/account_loader.rs#L342-347 */
    /* Count the owner's data in the loaded account size for program accounts.
       However, it is important to not double count repeated owners. */
    err = accumulate_and_check_loaded_account_data_size( owner_account->const_meta->dlen,
                                                         requested_loaded_accounts_data_size,
                                                         &accumulated_account_size );
    if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      return err;
    }

    fd_memcpy( &program_owners[ program_owners_cnt++ ], owner_account->pubkey, sizeof(fd_pubkey_t) );
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L118 */
int
fd_executor_validate_account_locks( fd_exec_txn_ctx_t const * txn_ctx ) {
  /* Ensure the number of account keys does not exceed the transaction lock limit
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L123 */
  ulong tx_account_lock_limit = get_transaction_account_lock_limit( txn_ctx->slot_ctx );
  if( FD_UNLIKELY( txn_ctx->accounts_cnt>tx_account_lock_limit ) ) {
    return FD_RUNTIME_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS;
  }

  /* Duplicate account check
     https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L125 */
  for( ushort i=0; i<txn_ctx->accounts_cnt; i++ ) {
    for( ushort j=(ushort)(i+1U); j<txn_ctx->accounts_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( &txn_ctx->accounts[i], &txn_ctx->accounts[j], sizeof(fd_pubkey_t) ) ) ) {
        return FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE;
      }
    }
  }

  /* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/sdk/src/transaction/sanitized.rs#L286-L288 */
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/89050f3cb7e76d9e273f10bea5e8207f2452f79f/svm/src/account_loader.rs#L101-L126 */
static int
fd_should_set_exempt_rent_epoch_max( fd_exec_slot_ctx_t const * slot_ctx,
                                     fd_borrowed_account_t *    rec ) {
  /* https://github.com/anza-xyz/agave/blob/89050f3cb7e76d9e273f10bea5e8207f2452f79f/svm/src/account_loader.rs#L109-L125 */
  if( FD_FEATURE_ACTIVE( slot_ctx, disable_rent_fees_collection ) ) {
    if( FD_LIKELY( rec->const_meta->info.rent_epoch!=ULONG_MAX
                && rec->const_meta->info.lamports>=fd_rent_exempt_minimum_balance( &slot_ctx->epoch_ctx->epoch_bank.rent, rec->const_meta->dlen ) ) ) {
      return 1;
    }
    return 0;
  }

  ulong epoch = fd_slot_to_epoch( &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, slot_ctx->slot_bank.slot, NULL );

  /* https://github.com/anza-xyz/agave/blob/89050f3cb7e76d9e273f10bea5e8207f2452f79f/sdk/src/rent_collector.rs#L158-L162 */
  if( rec->const_meta->info.rent_epoch==ULONG_MAX || rec->const_meta->info.rent_epoch>epoch ) {
    return 0;
  }

  /* https://github.com/anza-xyz/agave/blob/89050f3cb7e76d9e273f10bea5e8207f2452f79f/sdk/src/rent_collector.rs#L163-L166 */
  if( rec->const_meta->info.executable || !memcmp( rec->pubkey->key, fd_sysvar_incinerator_id.key, sizeof(fd_pubkey_t) ) ) {
    return 1;
  }

  /* https://github.com/anza-xyz/agave/blob/89050f3cb7e76d9e273f10bea5e8207f2452f79f/sdk/src/rent_collector.rs#L167-L183 */
  if( rec->const_meta->info.lamports && rec->const_meta->info.lamports<fd_rent_exempt_minimum_balance( &slot_ctx->epoch_ctx->epoch_bank.rent, rec->const_meta->dlen ) ) {
    return 0;
  }

  return 1;
}

static void
compute_priority_fee( fd_exec_txn_ctx_t const * txn_ctx,
                      ulong *                   fee,
                      ulong *                   priority ) {
  switch( txn_ctx->prioritization_fee_type ) {
  case FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED: {
    if( !txn_ctx->compute_unit_limit ) {
      *priority = 0UL;
    }
    else {
      uint128 micro_lamport_fee = (uint128)txn_ctx->compute_unit_price * (uint128)MICRO_LAMPORTS_PER_LAMPORT;
      uint128 _priority         = micro_lamport_fee / (uint128)txn_ctx->compute_unit_limit;
      *priority                 = _priority > (uint128)ULONG_MAX ? ULONG_MAX : (ulong)_priority;
    }

    *fee = txn_ctx->compute_unit_price;
    return;

  } case FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_COMPUTE_UNIT_PRICE: {
    uint128 micro_lamport_fee = (uint128)txn_ctx->compute_unit_price * (uint128)txn_ctx->compute_unit_limit;
    *priority                 = txn_ctx->compute_unit_price;
    uint128 _fee              = (micro_lamport_fee + (uint128)(MICRO_LAMPORTS_PER_LAMPORT - 1)) / (uint128)(MICRO_LAMPORTS_PER_LAMPORT);
    *fee                      = _fee > (uint128)ULONG_MAX ? ULONG_MAX : (ulong)_fee;
    return;

  }
  default:
    __builtin_unreachable();
  }
}

static ulong
fd_executor_lamports_per_signature( fd_slot_bank_t const *slot_bank ) {
  // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110
  return slot_bank->fee_rate_governor.target_lamports_per_signature / 2;
}

static void
fd_executor_calculate_fee( fd_exec_txn_ctx_t *txn_ctx,
                          fd_txn_t const *txn_descriptor,
                          fd_rawtxn_b_t const *txn_raw,
                          ulong *ret_execution_fee,
                          ulong *ret_priority_fee) {

  // https://github.com/anza-xyz/agave/blob/2e6ca8c1f62db62c1db7f19c9962d4db43d0d550/sdk/src/fee.rs#L82
  #define ACCOUNT_DATA_COST_PAGE_SIZE fd_ulong_sat_mul(32, 1024)

  // https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L4443
  ulong priority     = 0UL;
  ulong priority_fee = 0UL;
  compute_priority_fee( txn_ctx, &priority_fee, &priority );

  // let signature_fee = Self::get_num_signatures_in_message(message) .saturating_mul(fee_structure.lamports_per_signature);
  ulong num_signatures = txn_descriptor->signature_cnt;
  for (ushort i=0; i<txn_descriptor->instr_cnt; ++i ) {
    fd_txn_instr_t const * txn_instr  = &txn_descriptor->instr[i];
    fd_pubkey_t *          program_id = &txn_ctx->accounts[txn_instr->program_id];
    if( !memcmp(program_id->uc, fd_solana_keccak_secp_256k_program_id.key, sizeof(fd_pubkey_t)) ||
        !memcmp(program_id->uc, fd_solana_ed25519_sig_verify_program_id.key, sizeof(fd_pubkey_t)) ||
        (!memcmp(program_id->uc, fd_solana_secp256r1_program_id.key, sizeof(fd_pubkey_t)) && FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, enable_secp256r1_precompile )) ) {
      if( !txn_instr->data_sz ) {
        continue;
      }
      uchar * data   = (uchar *)txn_raw->raw + txn_instr->data_off;
      num_signatures = fd_ulong_sat_add(num_signatures, (ulong)(data[0]));
    }
  }

  ulong signature_fee = fd_executor_lamports_per_signature(&txn_ctx->slot_ctx->slot_bank) * num_signatures;

  // TODO: as far as I can tell, this is always 0
  //
  //            let write_lock_fee = Self::get_num_write_locks_in_message(message)
  //                .saturating_mul(fee_structure.lamports_per_write_lock);
  ulong lamports_per_write_lock = 0UL;
  ulong write_lock_fee          = fd_ulong_sat_mul(fd_txn_account_cnt(txn_descriptor, FD_TXN_ACCT_CAT_WRITABLE), lamports_per_write_lock);

  // TODO: the fee_structure bin is static and default..
  //        let loaded_accounts_data_size_cost = if include_loaded_account_data_size_in_fee {
  //            FeeStructure::calculate_memory_usage_cost(
  //                budget_limits.loaded_accounts_data_size_limit,
  //                budget_limits.heap_cost,
  //            )
  //        } else {
  //            0_u64
  //        };
  //        let total_compute_units =
  //            loaded_accounts_data_size_cost.saturating_add(budget_limits.compute_unit_limit);
  //        let compute_fee = self
  //            .compute_fee_bins
  //            .iter()
  //            .find(|bin| total_compute_units <= bin.limit)
  //            .map(|bin| bin.fee)
  //            .unwrap_or_else(|| {
  //                self.compute_fee_bins
  //                    .last()
  //                    .map(|bin| bin.fee)
  //                    .unwrap_or_default()
  //            });

  // https://github.com/anza-xyz/agave/blob/2e6ca8c1f62db62c1db7f19c9962d4db43d0d550/sdk/src/fee.rs#L203-L206
  ulong execution_fee = fd_ulong_sat_add( signature_fee, write_lock_fee );

  if( execution_fee >= ULONG_MAX ) {
    *ret_execution_fee = ULONG_MAX;
  } else {
    *ret_execution_fee = execution_fee;
  }

  if( priority_fee >= ULONG_MAX ) {
    *ret_priority_fee = ULONG_MAX;
  } else {
    *ret_priority_fee = priority_fee;
  }

  #undef ACCOUNT_DATA_COST_PAGE_SIZE
}

static int
fd_executor_collect_fees( fd_exec_txn_ctx_t * txn_ctx, fd_borrowed_account_t * fee_payer_rec ) {

  ulong execution_fee = 0UL;
  ulong priority_fee  = 0UL;

  fd_executor_calculate_fee( txn_ctx, txn_ctx->txn_descriptor, txn_ctx->_txn_raw, &execution_fee, &priority_fee );

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( txn_ctx->slot_ctx->epoch_ctx );
  ulong             total_fee  = fd_ulong_sat_add( execution_fee, priority_fee );

  // https://github.com/anza-xyz/agave/blob/2e6ca8c1f62db62c1db7f19c9962d4db43d0d550/sdk/src/fee.rs#L54
  if ( !FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, remove_rounding_in_fee_calculation ) ) {
    total_fee = fd_rust_cast_double_to_ulong( round( (double)total_fee ) );
  }

  int err = fd_validate_fee_payer( fee_payer_rec, &epoch_bank->rent, total_fee );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* At this point, the fee payer has been validated and the fee has been
     calculated. This means that the fee can be safely subtracted from the
     fee payer's borrowed account. However, the starting lamports of the
     account must be updated as well. Each instruction must have the net
     same (balanced) amount of lamports. This is done by comparing the
     borrowed accounts starting lamports and comparing it to the sum of
     the ending lamports. Therefore, we need to update the starting lamports
     specifically for the fee payer.

     This is especially important in the case where the transaction fails. This
     is because we need to roll back the account to the balance AFTER the fee
     is paid. It is also possible for the accounts data and owner to change.
     This means that the entire state of the borrowed account must be rolled
     back to this point. */

  fee_payer_rec->meta->info.lamports -= total_fee;
  fee_payer_rec->starting_lamports    = fee_payer_rec->meta->info.lamports;

  /* Update the fee payer's rent epoch to ULONG_MAX if it is rent exempt. */
  if( fd_should_set_exempt_rent_epoch_max( txn_ctx->slot_ctx, fee_payer_rec ) ) {
    fee_payer_rec->meta->info.rent_epoch = ULONG_MAX;
  }

  txn_ctx->execution_fee = execution_fee;
  txn_ctx->priority_fee  = priority_fee;

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L413-L497 */
int
fd_executor_validate_transaction_fee_payer( fd_exec_txn_ctx_t * txn_ctx ) {
  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/svm/src/transaction_processor.rs#L423-L430 */
  int err = fd_executor_compute_budget_program_execute_instructions( txn_ctx, txn_ctx->_txn_raw );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/svm/src/transaction_processor.rs#L431-L436 */
  fd_borrowed_account_t * fee_payer_rec = NULL;
  err = fd_txn_borrowed_account_modify_fee_payer( txn_ctx, &fee_payer_rec );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND;
  }

  /* Collect rent from the fee payer and set the starting lamports (to avoid unbalanced lamports issues in instruction execution)
     https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/svm/src/transaction_processor.rs#L438-L445 */
  fd_epoch_schedule_t const * schedule = fd_sysvar_cache_epoch_schedule( txn_ctx->slot_ctx->sysvar_cache );
  ulong                       epoch    = fd_slot_to_epoch( schedule, txn_ctx->slot_ctx->slot_bank.slot, NULL );
  txn_ctx->collected_rent += fd_runtime_collect_rent_from_account( txn_ctx->slot_ctx, fee_payer_rec->meta, fee_payer_rec->pubkey, epoch );
  fee_payer_rec->starting_lamports = fee_payer_rec->meta->info.lamports;

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/svm/src/transaction_processor.rs#L431-L488 */
  err = fd_executor_collect_fees( txn_ctx, fee_payer_rec );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int
fd_executor_setup_accessed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx ) {

  fd_pubkey_t * tx_accs   = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->acct_addr_off);

  // Set up accounts in the transaction body and perform checks
  for( ulong i = 0; i < txn_ctx->txn_descriptor->acct_addr_cnt; i++ ) {
    txn_ctx->accounts[i] = tx_accs[i];
  }

  txn_ctx->accounts_cnt += (uchar) txn_ctx->txn_descriptor->acct_addr_cnt;

  if( txn_ctx->txn_descriptor->transaction_version == FD_TXN_V0 ) {
    /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/runtime/src/bank/address_lookup_table.rs#L44-L48 */
    fd_slot_hashes_t const * slot_hashes = fd_sysvar_cache_slot_hashes( txn_ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !slot_hashes ) ) {
      return FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND;
    }

    fd_pubkey_t readonly_lut_accs[128];
    ulong readonly_lut_accs_cnt = 0;
    FD_SCRATCH_SCOPE_BEGIN {
      // Set up accounts in the account look up tables.
      fd_txn_acct_addr_lut_t const * addr_luts = fd_txn_get_address_tables_const( txn_ctx->txn_descriptor );
      for( ulong i = 0; i < txn_ctx->txn_descriptor->addr_table_lookup_cnt; i++ ) {
        fd_txn_acct_addr_lut_t const * addr_lut = &addr_luts[i];
        fd_pubkey_t const * addr_lut_acc = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + addr_lut->addr_off);

        /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/accounts-db/src/accounts.rs#L90-L94 */
        FD_BORROWED_ACCOUNT_DECL(addr_lut_rec);
        int err = fd_acc_mgr_view(txn_ctx->slot_ctx->acc_mgr, txn_ctx->slot_ctx->funk_txn, (fd_pubkey_t *) addr_lut_acc, addr_lut_rec);
        if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
          return FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND;
        }

        /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/accounts-db/src/accounts.rs#L96-L114 */
        if( FD_UNLIKELY( memcmp( addr_lut_rec->const_meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
          return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER;
        }

        /* Realistically impossible case, but need to make sure we don't cause an OOB data access
           https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L205-L209 */
        if( FD_UNLIKELY( addr_lut_rec->const_meta->dlen < FD_LOOKUP_TABLE_META_SIZE ) ) {
          return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
        }

        /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/accounts-db/src/accounts.rs#L141-L142 */
        fd_address_lookup_table_state_t addr_lookup_table_state;
        fd_bincode_decode_ctx_t decode_ctx = {
          .data = addr_lut_rec->const_data,
          .dataend = &addr_lut_rec->const_data[FD_LOOKUP_TABLE_META_SIZE],
          .valloc  = fd_scratch_virtual(),
        };

        /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L197-L214 */
        if( FD_UNLIKELY( fd_address_lookup_table_state_decode( &addr_lookup_table_state, &decode_ctx ) ) ) {
          return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
        }

        /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L200-L203 */
        if( FD_UNLIKELY( addr_lookup_table_state.discriminant != fd_address_lookup_table_state_enum_lookup_table ) ) {
          return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
        }

        /* Again probably an impossible case, but the ALUT data needs to be 32-byte aligned
           https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L210-L214 */
        if( FD_UNLIKELY( ( addr_lut_rec->const_meta->dlen - FD_LOOKUP_TABLE_META_SIZE ) & 0x1fUL ) ) {
          return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
        }

        /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/accounts-db/src/accounts.rs#L101-L112 */
        fd_pubkey_t * lookup_addrs = (fd_pubkey_t *)&addr_lut_rec->const_data[FD_LOOKUP_TABLE_META_SIZE];
        ulong lookup_addrs_cnt = ( addr_lut_rec->const_meta->dlen - FD_LOOKUP_TABLE_META_SIZE ) >> 5UL; // = (dlen - 56) / 32

        /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L175-L176 */
        ulong active_addresses_len;
        err = fd_get_active_addresses_len( &addr_lookup_table_state.inner.lookup_table,
                                           txn_ctx->slot_ctx->slot_bank.slot,
                                           slot_hashes->hashes,
                                           lookup_addrs_cnt,
                                           &active_addresses_len );
        if( FD_UNLIKELY( err ) ) {
          return err;
        }

        /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L169-L182 */
        uchar * writable_lut_idxs = (uchar *)txn_ctx->_txn_raw->raw + addr_lut->writable_off;
        for( ulong j = 0; j < addr_lut->writable_cnt; j++ ) {
          /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L177-L181 */
          if( writable_lut_idxs[j] >= active_addresses_len ) {
            return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX;
          }
          txn_ctx->accounts[txn_ctx->accounts_cnt++] = lookup_addrs[writable_lut_idxs[j]];
        }

        uchar * readonly_lut_idxs = (uchar *)txn_ctx->_txn_raw->raw + addr_lut->readonly_off;
        for( ulong j = 0; j < addr_lut->readonly_cnt; j++ ) {
          /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L177-L181 */
          if( readonly_lut_idxs[j] >= active_addresses_len ) {
            return FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX;
          }
          readonly_lut_accs[readonly_lut_accs_cnt++] = lookup_addrs[readonly_lut_idxs[j]];
        }
      }
    } FD_SCRATCH_SCOPE_END;

    fd_memcpy( &txn_ctx->accounts[txn_ctx->accounts_cnt], readonly_lut_accs, readonly_lut_accs_cnt * sizeof(fd_pubkey_t) );
    txn_ctx->accounts_cnt += readonly_lut_accs_cnt;
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
  int err = fd_instr_info_sum_account_lamports( instr, &starting_lamports_h, &starting_lamports_l );
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
    int err = fd_instr_info_sum_account_lamports( caller_instruction_context->instr, &current_caller_lamport_sum_h, &current_caller_lamport_sum_l );
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
  if( FD_UNLIKELY( !memcmp(instr->program_id_pubkey.key, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t)) ) ) {
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
     https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L369-L374 */
  for( ushort i=0; i<instr->acct_cnt; i++ ) {
    if( FD_UNLIKELY( instr->borrowed_accounts[i]->const_meta->info.executable &&
                      instr->borrowed_accounts[i]->refcnt_excl ) ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_OUTSTANDING;
    }
  }

  /* Verify lamports are balanced before and after instruction
     https://github.com/anza-xyz/agave/blob/c4b42ab045860d7b13b3912eafb30e6d2f4e593f/sdk/src/transaction_context.rs#L366-L380 */
  ulong ending_lamports_h = 0UL;
  ulong ending_lamports_l = 0UL;
  int err = fd_instr_info_sum_account_lamports( instr, &ending_lamports_h, &ending_lamports_l );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  if( FD_UNLIKELY( ending_lamports_l != instr->starting_lamports_l || ending_lamports_h != instr->starting_lamports_h ) ) {
   return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;;
}

int
fd_execute_instr( fd_exec_txn_ctx_t * txn_ctx,
                  fd_instr_info_t *   instr ) {
  FD_RUNTIME_TXN_SPAD_FRAME_BEGIN( txn_ctx->spad, txn_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {
    fd_exec_instr_ctx_t * parent = NULL;
    if( txn_ctx->instr_stack_sz ) {
      parent = &txn_ctx->instr_stack[ txn_ctx->instr_stack_sz - 1 ];
    }

    int err = fd_instr_stack_push( txn_ctx, instr );
    if( FD_UNLIKELY( err ) ) {
      FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, err, txn_ctx->instr_err_idx );
      return err;
    }

    fd_exec_instr_ctx_t * ctx = &txn_ctx->instr_stack[ txn_ctx->instr_stack_sz - 1 ];
    *ctx = (fd_exec_instr_ctx_t) {
      .instr     = instr,
      .txn_ctx   = txn_ctx,
      .epoch_ctx = txn_ctx->epoch_ctx,
      .slot_ctx  = txn_ctx->slot_ctx,
      .acc_mgr   = txn_ctx->acc_mgr,
      .funk_txn  = txn_ctx->funk_txn,
      .parent    = parent,
      .index     = parent ? (parent->child_cnt++) : 0,
      .depth     = parent ? (parent->depth+1    ) : 0,
      .child_cnt = 0U,
    };

    txn_ctx->instr_trace[ txn_ctx->instr_trace_length - 1 ] = (fd_exec_instr_trace_entry_t) {
      .instr_info = instr,
      .stack_height = txn_ctx->instr_stack_sz,
    };

    fd_exec_instr_fn_t native_prog_fn = fd_executor_lookup_native_program( &txn_ctx->borrowed_accounts[ instr->program_id ] );
    fd_exec_txn_ctx_reset_return_data( txn_ctx );
    int exec_result = FD_EXECUTOR_INSTR_SUCCESS;
    if( native_prog_fn != NULL ) {
      /* Log program invokation (internally caches program_id base58) */
      fd_log_collector_program_invoke( ctx );
      exec_result = native_prog_fn( ctx );
    } else {
      exec_result = FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
    }

    int stack_pop_err = fd_instr_stack_pop( txn_ctx, instr );
    if( FD_LIKELY( exec_result == FD_EXECUTOR_INSTR_SUCCESS ) ) {
      /* Log success */
      fd_log_collector_program_success( ctx );

      /* Only report the stack pop error on success */
      if( FD_UNLIKELY( stack_pop_err ) ) {
        FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, stack_pop_err, txn_ctx->instr_err_idx );
        return stack_pop_err;
      }
    } else {
      /* if txn_ctx->exec_err is not set, it indicates an instruction error */
      if( !txn_ctx->exec_err ) {
        FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, exec_result, txn_ctx->instr_err_idx );
      }

      if( !txn_ctx->failed_instr ) {
        txn_ctx->failed_instr = ctx;
        ctx->instr_err        = (uint)( -exec_result - 1 );
      }

      /* Log failure cases.
         We assume that the correct type of error is stored in ctx.
         Syscalls are expected to log when the error is generated, while
         native programs will be logged here.
         (This is because syscall errors often carry data with them.) */
      fd_log_collector_program_failure( ctx );
    }

#ifdef VLOG
  if ( FD_UNLIKELY( exec_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    FD_LOG_WARNING(( "instruction executed unsuccessfully: error code %d, custom err: %d, program id: %s", exec_result, txn_ctx->custom_err, FD_BASE58_ENC_32_ALLOCA( instr->program_id_pubkey.uc ));
  } else {
    FD_LOG_WARNING(( "instruction executed successfully: error code %d, custom err: %d, program id: %s", exec_result, txn_ctx->custom_err, FD_BASE58_ENC_32_ALLOCA( instr->program_id_pubkey.uc ));
  }
#endif

    return exec_result;
  } FD_SCRATCH_SCOPE_END;
  } FD_RUNTIME_TXN_SPAD_FRAME_END;
}

void
fd_txn_reclaim_accounts( fd_exec_txn_ctx_t * txn_ctx ) {
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];

    /* An account writable iff it is writable AND it is not being demoted.
        If this criteria is not met, the account should not be marked as touched
        via updating its most recent slot. */
    if( !fd_txn_account_is_writable_idx( txn_ctx, (int)i ) ) {
      continue;
    }

    acc_rec->meta->slot = txn_ctx->slot_ctx->slot_bank.slot;

    if( acc_rec->meta->info.lamports == 0 ) {
      acc_rec->meta->dlen = 0;
      memset( acc_rec->meta->info.owner, 0, sizeof(fd_pubkey_t) );
    }
  }
}

int
fd_executor_is_blockhash_valid_for_age( fd_block_hash_queue_t const * block_hash_queue,
                                        fd_hash_t const *             blockhash,
                                        ulong                         max_age ) {
  fd_hash_hash_age_pair_t_mapnode_t key;
  fd_memcpy( key.elem.key.uc, blockhash, sizeof(fd_hash_t) );

  fd_hash_hash_age_pair_t_mapnode_t * hash_age = fd_hash_hash_age_pair_t_map_find( block_hash_queue->ages_pool, block_hash_queue->ages_root, &key );
  if( hash_age==NULL ) {
    #ifdef VLOG
    FD_LOG_WARNING(( "txn with missing recent blockhash - blockhash: %s", FD_BASE58_ENC_32_ALLOCA( blockhash->uc ) ));
    #endif
    return 0;
  }
  ulong age = block_hash_queue->last_hash_index-hash_age->elem.val.hash_index;
#ifdef VLOG
  if( age>max_age ) {
    FD_LOG_WARNING(( "txn with old blockhash - age: %lu, blockhash: %s", age, FD_BASE58_ENC_32_ALLOCA( hash_age->elem.key.uc ) ));
  }
#endif
  return ( age<=max_age );
}

void
fd_executor_setup_borrowed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx ) {
  ulong j = 0;
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    FD_SCRATCH_SCOPE_BEGIN {

    fd_pubkey_t * acc = &txn_ctx->accounts[i];

    txn_ctx->is_nonce_accounts[i]  = 0U;
    txn_ctx->adv_nonce_accounts[i] = 0U;

    fd_borrowed_account_t * borrowed_account = fd_borrowed_account_init( &txn_ctx->borrowed_accounts[i] );
    int                     err              = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, acc, borrowed_account );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS && err!=FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
      FD_LOG_ERR(( "fd_acc_mgr_view err=%d", err ));
    }
    uchar is_unknown_account = err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
    memcpy( borrowed_account->pubkey->key, acc, sizeof(fd_pubkey_t) );
    if ( FD_UNLIKELY( is_unknown_account ) ) {
      borrowed_account->account_found = 0;
    }

    /* Create a borrowed account for all writable accounts and the fee payer
       account which is almost always writable, but doesn't have to be.

       TODO: The borrowed account semantics should better match Agave's. */
    if( fd_txn_account_is_writable_idx( txn_ctx, (int)i ) || i==FD_FEE_PAYER_TXN_IDX ) {
      void * borrowed_account_data = fd_spad_alloc( txn_ctx->spad, FD_ACCOUNT_REC_ALIGN, FD_ACC_TOT_SZ_MAX );
      fd_borrowed_account_make_modifiable( borrowed_account, borrowed_account_data );

      /* All new accounts should have their rent epoch set to ULONG_MAX.
         https://github.com/anza-xyz/agave/blob/89050f3cb7e76d9e273f10bea5e8207f2452f79f/svm/src/account_loader.rs#L485-L497 */
      if( is_unknown_account
          || ( i>0UL && fd_should_set_exempt_rent_epoch_max( txn_ctx->slot_ctx, borrowed_account ) ) ) {
        borrowed_account->meta->info.rent_epoch = ULONG_MAX;
      }
    }

    fd_account_meta_t const * meta = borrowed_account->const_meta ? borrowed_account->const_meta : borrowed_account->meta;
    if( meta==NULL ) {
      static const fd_account_meta_t sentinel = { .magic = FD_ACCOUNT_META_MAGIC, .info = { .rent_epoch = ULONG_MAX } };
      borrowed_account->const_meta        = &sentinel;
      borrowed_account->starting_lamports = 0UL;
      borrowed_account->starting_dlen     = 0UL;
      continue;
    }

    if( meta->info.executable ) {
      FD_BORROWED_ACCOUNT_DECL(owner_borrowed_account);
      int err = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, (fd_pubkey_t *)meta->info.owner, owner_borrowed_account );
      if( FD_UNLIKELY( err ) ) {
        borrowed_account->starting_owner_dlen = 0UL;
      } else {
        borrowed_account->starting_owner_dlen = owner_borrowed_account->const_meta->dlen;
      }
    }

    if( FD_UNLIKELY( memcmp( meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
      fd_bpf_upgradeable_loader_state_t program_loader_state = {0};
      int err = 0;
      if( FD_UNLIKELY( !read_bpf_upgradeable_loader_state_for_program( txn_ctx, (uchar) i, &program_loader_state, &err ) ) ) {
        continue;
      }

      if( !fd_bpf_upgradeable_loader_state_is_program( &program_loader_state ) ) {
        continue;
      }

      fd_pubkey_t * programdata_acc = &program_loader_state.inner.program.programdata_address;
      fd_borrowed_account_t * executable_account = fd_borrowed_account_init( &txn_ctx->executable_accounts[j] );
      fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, programdata_acc, executable_account);
      j++;
    }

    } FD_SCRATCH_SCOPE_END;
  }
  txn_ctx->executable_cnt = j;
}

/* Stuff to be done before multithreading can begin */
int
fd_execute_txn_prepare_start( fd_exec_slot_ctx_t *  slot_ctx,
                              fd_exec_txn_ctx_t *   txn_ctx,
                              fd_txn_t const *      txn_descriptor,
                              fd_rawtxn_b_t const * txn_raw ) {
  /* Init txn ctx */
  fd_exec_txn_ctx_new( txn_ctx );
  fd_exec_txn_ctx_from_exec_slot_ctx( slot_ctx, txn_ctx );
  fd_exec_txn_ctx_setup( txn_ctx, txn_descriptor, txn_raw );

  /* Unroll accounts from aluts and place into correct spots */
  int res = fd_executor_setup_accessed_accounts_for_txn( txn_ctx );

  return res;
  /* TODO:FIXME: MOVE THIS PELASE */
}

int
fd_executor_txn_verify( fd_exec_txn_ctx_t * txn_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {
    fd_sha512_t * shas[ FD_TXN_ACTUAL_SIG_MAX ];
    for ( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
      fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( fd_scratch_alloc( alignof( fd_sha512_t ), sizeof( fd_sha512_t ) ) ) );
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
  } FD_SCRATCH_SCOPE_END;
}

int
fd_execute_txn( fd_exec_txn_ctx_t * txn_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {
    uint use_sysvar_instructions = fd_executor_txn_uses_sysvar_instructions( txn_ctx );
    int ret = 0;

#ifdef VLOG
    fd_txn_t const *txn = txn_ctx->txn_descriptor;
    fd_rawtxn_b_t const *raw_txn = txn_ctx->_txn_raw;
    uchar * sig = (uchar *)raw_txn->raw + txn->signature_off;
#endif

    bool dump_insn = txn_ctx->capture_ctx && txn_ctx->slot_ctx->slot_bank.slot >= txn_ctx->capture_ctx->dump_proto_start_slot && txn_ctx->capture_ctx->dump_insn_to_pb;

    /* Initialize log collection */
    fd_log_collector_init( &txn_ctx->log_collector, txn_ctx->slot_ctx->enable_exec_recording );

    for ( ushort i = 0; i < txn_ctx->txn_descriptor->instr_cnt; i++ ) {
#ifdef VLOG
      FD_LOG_WARNING(( "Start of transaction for %d for %s", i, FD_BASE58_ENC_64_ALLOCA( sig ) ));
#endif

      if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
        ret = fd_sysvar_instructions_update_current_instr_idx( txn_ctx, i );
        if( ret != FD_ACC_MGR_SUCCESS ) {
          FD_LOG_WARNING(( "sysvar instructions failed to update instruction index" ));
          return ret;
        }
      }

      if( dump_insn ) {
        // Capture the input and convert it into a Protobuf message
        fd_dump_instr_to_protobuf(txn_ctx, &txn_ctx->instr_infos[i], i);
      }


      int exec_result = fd_execute_instr( txn_ctx, &txn_ctx->instr_infos[i] );
#ifdef VLOG
      FD_LOG_WARNING(( "fd_execute_instr result (%d) for %s", exec_result, FD_BASE58_ENC_64_ALLOCA( sig ) ));
#endif
      if( exec_result != FD_EXECUTOR_INSTR_SUCCESS ) {
        if ( txn_ctx->instr_err_idx == INT_MAX )
        {
          txn_ctx->instr_err_idx = i;
        }
  #ifdef VLOG
        if ( 257037453 == txn_ctx->slot_ctx->slot_bank.slot ) {
  #endif
          if (exec_result == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR ) {
  #ifdef VLOG
            FD_LOG_WARNING(( "fd_execute_instr failed (%d:%d) for %s",
                             exec_result,
                             txn_ctx->custom_err,
                             FD_BASE58_ENC_64_ALLOCA( sig ) ));
  #endif
          } else {
  #ifdef VLOG
            FD_LOG_WARNING(( "fd_execute_instr failed (%d) index %u for %s",
              exec_result,
              i,
              FD_BASE58_ENC_64_ALLOCA( sig ) ));
  #endif
          }
  #ifdef VLOG
        }
  #endif
        return exec_result;
      }
    }
    int err = fd_executor_txn_check( txn_ctx->slot_ctx, txn_ctx );
    if ( err != FD_EXECUTOR_INSTR_SUCCESS) {
      FD_TXN_ERR_FOR_LOG_INSTR( txn_ctx, err, txn_ctx->instr_err_idx );
      FD_LOG_DEBUG(( "fd_executor_txn_check failed (%d)", err ));
      return err;
    }

    return 0;
  } FD_SCRATCH_SCOPE_END;
}

int
fd_executor_txn_check( fd_exec_slot_ctx_t const * slot_ctx,
                       fd_exec_txn_ctx_t *        txn ) {
  fd_rent_t const * rent = fd_sysvar_cache_rent( slot_ctx->sysvar_cache );

  ulong starting_lamports_l = 0;
  ulong starting_lamports_h = 0;

  ulong ending_lamports_l = 0;
  ulong ending_lamports_h = 0;

  /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L63 */
  for( ulong idx = 0; idx < txn->accounts_cnt; idx++ ) {
    fd_borrowed_account_t * b = &txn->borrowed_accounts[idx];

    // Was this account written to?
    if( NULL != b->meta ) {
      fd_uwide_inc( &ending_lamports_h, &ending_lamports_l, ending_lamports_h, ending_lamports_l, b->meta->info.lamports );

      /* Rent states are defined as followed:
         - lamports == 0                      -> Uninitialized
         - 0 < lamports < rent_exempt_minimum -> RentPaying
         - lamports >= rent_exempt_minimum    -> RentExempt
         In Agave, 'self' refers to our 'after' state. */
      uchar after_uninitialized  = b->meta->info.lamports == 0;
      uchar after_rent_exempt    = b->meta->info.lamports >= fd_rent_exempt_minimum_balance( rent, b->meta->dlen );

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
                           b->meta->dlen,
                           b->starting_dlen,
                           b->meta->info.lamports,
                           b->starting_lamports,
                           fd_rent_exempt_minimum_balance( rent, b->meta->dlen ),
                           fd_rent_exempt_minimum_balance( rent, b->starting_dlen ) ));
            /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L104 */
            return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
          /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L56 */
          } else if( (b->meta->dlen == b->starting_dlen) && b->meta->info.lamports <= b->starting_lamports ) {
            // no-op
          } else {
            FD_LOG_DEBUG(( "Rent exempt error for %s Curr len %lu Starting len %lu Curr lamports %lu Starting lamports %lu Curr exempt %lu Starting exempt %lu",
                           FD_BASE58_ENC_32_ALLOCA( b->pubkey->uc ),
                           b->meta->dlen,
                           b->starting_dlen,
                           b->meta->info.lamports,
                           b->starting_lamports,
                           fd_rent_exempt_minimum_balance( rent, b->meta->dlen ),
                           fd_rent_exempt_minimum_balance( rent, b->starting_dlen ) ));
            /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/account_rent_state.rs#L104 */
            return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
          }
        }
      }

      if( b->starting_lamports != ULONG_MAX ) {
        fd_uwide_inc( &starting_lamports_h, &starting_lamports_l, starting_lamports_h, starting_lamports_l, b->starting_lamports );
      }
    } else if( NULL != b->const_meta ) {
      // Should these just kill the client?  They are impossible...
      if( b->starting_lamports != b->const_meta->info.lamports ) {
        FD_LOG_DEBUG(("Const rec mismatch %s starting %lu %lu ending %lu %lu", FD_BASE58_ENC_32_ALLOCA( b->pubkey->uc ), b->starting_dlen, b->starting_lamports, b->const_meta->dlen, b->const_meta->info.lamports));
        return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
      }
      if( b->starting_dlen != b->const_meta->dlen ) {
        FD_LOG_DEBUG(("Const rec mismatch %s starting %lu %lu ending %lu %lu", FD_BASE58_ENC_32_ALLOCA( b->pubkey->uc ), b->starting_dlen, b->starting_lamports, b->const_meta->dlen, b->const_meta->info.lamports));
        return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
      }
    }
  }

  /* https://github.com/anza-xyz/agave/blob/b2c388d6cbff9b765d574bbb83a4378a1fc8af32/svm/src/transaction_processor.rs#L839-L845 */
  if( FD_UNLIKELY( ending_lamports_l != starting_lamports_l || ending_lamports_h != starting_lamports_h ) ) {
    FD_LOG_DEBUG(( "Lamport sum mismatch: starting %lx%lx ending %lx%lx", starting_lamports_h, starting_lamports_l, ending_lamports_h, ending_lamports_l ));
    return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
#undef VLOG

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
