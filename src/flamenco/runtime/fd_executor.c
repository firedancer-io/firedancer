#include "fd_executor.h"
#include "fd_acc_mgr.h"
#include "fd_hashes.h"
#include "fd_runtime_err.h"
#include "context/fd_exec_slot_ctx.h"
#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"

#include "../nanopb/pb_encode.h"
#include "../../util/rng/fd_rng.h"
#include "fd_system_ids.h"
#include "fd_account.h"
#include "program/fd_address_lookup_table_program.h"
#include "program/fd_bpf_loader_v1_program.h"
#include "program/fd_bpf_loader_v2_program.h"
#include "program/fd_bpf_loader_v3_program.h"
#include "program/fd_compute_budget_program.h"
#include "program/fd_config_program.h"
#include "program/fd_precompiles.h"
#include "program/fd_stake_program.h"
#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"
//#include "program/fd_zk_token_proof_program.h"

#include "sysvar/fd_sysvar_instructions.h"

#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/pack/fd_pack.h"
#include "../../ballet/pack/fd_pack_cost.h"

#define SORT_NAME        sort_uint64_t
#define SORT_KEY_T       uint64_t
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../util/tmpl/fd_sort.c"

#include <assert.h>
#include <errno.h>
#include <stdio.h>   /* snprintf(3) */
#include <fcntl.h>   /* openat(2) */
#include <unistd.h>  /* write(3) */
#include <time.h>

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#define MAX_COMPUTE_UNITS_PER_BLOCK                (48000000UL)
#define MAX_COMPUTE_UNITS_PER_WRITE_LOCKED_ACCOUNT (12000000UL)

fd_exec_instr_fn_t
fd_executor_lookup_native_program( fd_pubkey_t const * pubkey ) {
  /* TODO:
     - replace with proper lookup table
     - precompiles ed25519, secp256k1 should not be here */
  if ( !memcmp( pubkey, fd_solana_vote_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_vote_program_execute;
  } else if ( !memcmp( pubkey, fd_solana_system_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_system_program_execute;
  } else if ( !memcmp( pubkey, fd_solana_config_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_config_program_execute;
  } else if ( !memcmp( pubkey, fd_solana_stake_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_stake_program_execute;
  } else if ( !memcmp( pubkey, fd_solana_ed25519_sig_verify_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_precompile_ed25519_verify;
  } else if ( !memcmp( pubkey, fd_solana_keccak_secp_256k_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_precompile_secp256k1_verify;
  } else if ( !memcmp( pubkey, fd_solana_bpf_loader_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_bpf_loader_v2_program_execute;
  } else if ( !memcmp( pubkey, fd_solana_bpf_loader_deprecated_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_bpf_loader_v1_program_execute;
  } else if ( !memcmp( pubkey, fd_solana_compute_budget_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return fd_compute_budget_program_execute;
  } else if( !memcmp( pubkey, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return fd_address_lookup_table_program_execute;
  //} else if( !memcmp( pubkey, fd_solana_zk_token_proof_program_id.key, sizeof(fd_pubkey_t) ) ) {
  //  return fd_executor_zk_token_proof_program_execute_instruction;
  } else {
    return NULL; /* FIXME */
  }
}

int
fd_executor_lookup_program( fd_exec_slot_ctx_t * slot_ctx,
                            fd_pubkey_t const * pubkey ) {
  if( fd_bpf_loader_v3_is_executable( slot_ctx, pubkey )==0 ) {
    return 0;
  }

  return -1;
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
is_invoked_account( fd_txn_t const * txn_descriptor, uchar idx ) {
  for ( uchar i = 0; i < txn_descriptor->instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &txn_descriptor->instr[i];
    if ( instr->program_id == idx ) return 1;
  }
  return 0;
}

int
is_passed_to_program_account( fd_txn_t const * txn_descriptor, fd_rawtxn_b_t const * raw_ptr, uchar idx ) {
  for ( uchar i = 0; i < txn_descriptor->instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &txn_descriptor->instr[i];
    uchar const * instr_accs = ((uchar const *)raw_ptr->raw + instr->acct_off );
    for ( uchar j = 0; j < instr->acct_cnt; j++ ) {
      if ( instr_accs[j] == idx ) return 1;
    }
  }
  return 0;
}

int
is_non_loader_program_key( fd_txn_t const * txn_descriptor, fd_rawtxn_b_t const * raw_ptr, uchar idx ) {
  return !is_invoked_account( txn_descriptor, idx ) || is_passed_to_program_account( txn_descriptor, raw_ptr, idx );
}

int
is_system_nonce_account( fd_borrowed_account_t * account ) {
FD_SCRATCH_SCOPE_BEGIN {
  if ( memcmp( account->const_meta->info.owner, fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) ) == 0 ) {
    if ( account->const_meta->dlen == 0 ) {
      return 0;
    } else if ( account->const_meta->dlen == 80 ) { // TODO: none size macro
      fd_bincode_decode_ctx_t decode = { .data = account->const_data,
                                         .dataend = account->const_data + account->const_meta->dlen,
                                         .valloc = fd_scratch_virtual() };
      fd_nonce_state_versions_t nonce_versions;
      if (fd_nonce_state_versions_decode( &nonce_versions, &decode ) != 0 ) {
        FD_LOG_ERR(("Not a nonce account"));
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

int
check_rent_transition( fd_borrowed_account_t * account, fd_rent_t const * rent, ulong fee ) {
  ulong min_balance   = fd_rent_exempt_minimum_balance2( rent, account->const_meta->dlen );
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

int
validate_fee_payer( fd_borrowed_account_t * account, fd_rent_t const * rent, ulong fee, uchar checked_arithmetic_feature ) {
  if ( account->const_meta->info.lamports == 0 ) {
    return FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND;
  }

  ulong min_balance = 0;

  int is_nonce = is_system_nonce_account( account );
  if ( is_nonce < 0 ) {
    return FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_FOR_FEE;
  }

  if ( is_nonce ) {
    min_balance = fd_rent_exempt_minimum_balance2( rent, 80 );
  }

  if ( checked_arithmetic_feature ) {
    ulong out = ULONG_MAX;
    int cf = fd_ulong_checked_sub( account->const_meta->info.lamports, min_balance, &out);
    if ( cf != FD_EXECUTOR_INSTR_SUCCESS ) {
      return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
    }

    cf = fd_ulong_checked_sub( out, fee, &out );
    if ( cf != FD_EXECUTOR_INSTR_SUCCESS ) {
      return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
    }
  } else {
    if ( account->const_meta->info.lamports < fee + min_balance ) {
      return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
    }
  }

  if ( account->const_meta->info.lamports < fee ) {
    return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
  } else {
    if ( memcmp( account->pubkey->key, fd_sysvar_incinerator_id.key, sizeof(fd_pubkey_t) ) != 0 && !check_rent_transition( account, rent, fee ) ) {
      return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
    }
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int
fd_executor_check_txn_accounts( fd_exec_txn_ctx_t * txn_ctx ) {
  ulong fee = fd_runtime_calculate_fee( txn_ctx, txn_ctx->txn_descriptor, txn_ctx->_txn_raw );

  if ( txn_ctx->txn_descriptor->signature_cnt == 0 && fee != 0 ) {
    return FD_RUNTIME_TXN_ERR_MISSING_SIGNATURE_FOR_FEE;
  }

  fd_pubkey_t * tx_accs   = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->acct_addr_off);

  ulong accumulated_account_size = 0;
  ulong requested_loaded_accounts_data_size;

  if ( FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, cap_transaction_accounts_data_size) ) {
    if ( txn_ctx->loaded_accounts_data_size_limit == 0 ) {
      return FD_RUNTIME_TXN_ERR_INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT;
    }
    requested_loaded_accounts_data_size = txn_ctx->loaded_accounts_data_size_limit;
  } else {
    requested_loaded_accounts_data_size = ULONG_MAX;
  }

  uchar validated_fee_payer = 0;

  // Set up accounts in the transaction body and perform checks
  for( ulong i = 0; i < txn_ctx->txn_descriptor->acct_addr_cnt; i++ ) {

    // Check for max loaded acct size
    FD_BORROWED_ACCOUNT_DECL(acct);
    ulong acc_size = 0;
    int err = fd_acc_mgr_view( txn_ctx->slot_ctx->acc_mgr, txn_ctx->slot_ctx->funk_txn, &tx_accs[i], acct );
    if ( err == FD_ACC_MGR_SUCCESS ) {
      acc_size = acct->const_meta->dlen;
    } else {
      continue;
    }
    accumulated_account_size = fd_ulong_sat_add( accumulated_account_size, acc_size );
    if ( accumulated_account_size > requested_loaded_accounts_data_size ) {
      return FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED;
    }

    if (!validated_fee_payer && is_non_loader_program_key( txn_ctx->txn_descriptor, txn_ctx->_txn_raw, (uchar)i)) {
      fd_rent_t const * rent = fd_sysvar_cache_rent( txn_ctx->slot_ctx->sysvar_cache );
      int err = validate_fee_payer( acct, rent, fee, FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, checked_arithmetic_in_fee_validation ) );
      if ( err != FD_RUNTIME_EXECUTE_SUCCESS ) {
        return err;
      }
      validated_fee_payer = 1;
    }

    if ( txn_ctx->slot_ctx->epoch_reward_status.is_active && fd_txn_account_is_writable_idx( txn_ctx->txn_descriptor, tx_accs, (int)i)
          && memcmp( acct->const_meta->info.owner, fd_solana_stake_program_id.uc, sizeof(fd_pubkey_t)) == 0 ) {
      return FD_RUNTIME_TXN_ERR_PROGRAM_EXECUTION_TEMPORARILY_RESTRICTED;
    }
  }
  if ( !validated_fee_payer ) {
    return FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_executor_setup_accessed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx ) {

  fd_pubkey_t * tx_accs   = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->acct_addr_off);

  // Set up accounts in the transaction body and perform checks
  for( ulong i = 0; i < txn_ctx->txn_descriptor->acct_addr_cnt; i++ ) {
    txn_ctx->accounts[i] = tx_accs[i];
  }

  txn_ctx->accounts_cnt += (uchar) txn_ctx->txn_descriptor->acct_addr_cnt;

  if( txn_ctx->txn_descriptor->transaction_version == FD_TXN_V0 ) {
    fd_pubkey_t readonly_lut_accs[128];
    ulong readonly_lut_accs_cnt = 0;

    FD_SCRATCH_SCOPE_BEGIN {
      // Set up accounts in the account look up tables.
      fd_txn_acct_addr_lut_t const * addr_luts = fd_txn_get_address_tables_const( txn_ctx->txn_descriptor );
      for( ulong i = 0; i < txn_ctx->txn_descriptor->addr_table_lookup_cnt; i++ ) {
        fd_txn_acct_addr_lut_t const * addr_lut = &addr_luts[i];
        fd_pubkey_t const * addr_lut_acc = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + addr_lut->addr_off);

        FD_BORROWED_ACCOUNT_DECL(addr_lut_rec);
        int err = fd_acc_mgr_view(txn_ctx->slot_ctx->acc_mgr, txn_ctx->slot_ctx->funk_txn, (fd_pubkey_t *) addr_lut_acc, addr_lut_rec);
        if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
          FD_LOG_ERR(( "addr lut not found" )); // TODO: return txn err code
        }

        fd_address_lookup_table_state_t addr_lookup_table_state;
        fd_bincode_decode_ctx_t decode_ctx = {
          .data = addr_lut_rec->const_data,
          .dataend = &addr_lut_rec->const_data[56], // TODO macro const.
          .valloc  = fd_scratch_virtual(),
        };
        if( fd_address_lookup_table_state_decode( &addr_lookup_table_state, &decode_ctx ) ) {
          FD_LOG_ERR(("fd_address_lookup_table_state_decode failed"));
        }
        if( addr_lookup_table_state.discriminant != fd_address_lookup_table_state_enum_lookup_table ) {
          FD_LOG_ERR(("addr lut is uninit"));
        }

        fd_pubkey_t * lookup_addrs = (fd_pubkey_t *)&addr_lut_rec->const_data[56];

        uchar * writable_lut_idxs = (uchar *)txn_ctx->_txn_raw->raw + addr_lut->writable_off;
        for( ulong j = 0; j < addr_lut->writable_cnt; j++ ) {
          txn_ctx->accounts[txn_ctx->accounts_cnt++] = lookup_addrs[writable_lut_idxs[j]];
        }

        uchar * readonly_lut_idxs = (uchar *)txn_ctx->_txn_raw->raw + addr_lut->readonly_off;
        for( ulong j = 0; j < addr_lut->readonly_cnt; j++ ) {
          readonly_lut_accs[readonly_lut_accs_cnt++] = lookup_addrs[readonly_lut_idxs[j]];
        }
      }
    } FD_SCRATCH_SCOPE_END;

    fd_memcpy( &txn_ctx->accounts[txn_ctx->accounts_cnt], readonly_lut_accs, readonly_lut_accs_cnt * sizeof(fd_pubkey_t) );
    txn_ctx->accounts_cnt += readonly_lut_accs_cnt;
  }
}

void
fd_set_exempt_rent_epoch_max( fd_exec_txn_ctx_t * txn_ctx,
                              void const *        addr ) {
  fd_borrowed_account_t * rec = NULL;
  int err = fd_txn_borrowed_account_view( txn_ctx, (fd_pubkey_t const *)addr, &rec);
  if( FD_UNLIKELY( err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) )
    return;
  FD_TEST( err==FD_ACC_MGR_SUCCESS );

  if( fd_pubkey_is_sysvar_id( rec->pubkey ) ) {
    return;
  }

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( txn_ctx->slot_ctx->epoch_ctx );
  if( rec->const_meta->info.lamports < fd_rent_exempt_minimum_balance2( &epoch_bank->rent,rec->const_meta->dlen ) )
    return;
  if( rec->const_meta->info.rent_epoch == ULONG_MAX )
    return;

  err = fd_txn_borrowed_account_modify( txn_ctx, (fd_pubkey_t const *)addr, 0, &rec);
  FD_TEST( err==FD_ACC_MGR_SUCCESS );

  rec->meta->info.rent_epoch = ULONG_MAX;
}

// loaded account data size defined consists of data encapsulated within accounts pointed to by these pubkeys:
// 1. static and dynamic account keys that are loaded for the message
// 2. owner program which inteprets the opaque data for each instruction
static int
fd_cap_transaction_accounts_data_size( fd_exec_txn_ctx_t * txn_ctx,
                                       fd_instr_info_t const *  instrs,
                                       ushort              instrs_cnt ) {
  ulong total_accounts_data_size = 0UL;
  for( ulong idx = 0; idx < txn_ctx->accounts_cnt; idx++ ) {
    fd_borrowed_account_t *b = &txn_ctx->borrowed_accounts[idx];
    ulong program_data_len = (NULL != b->meta) ? b->meta->dlen : (NULL != b->const_meta) ? b->const_meta->dlen : 0UL;
    total_accounts_data_size = fd_ulong_sat_add(total_accounts_data_size, program_data_len);
  }

  for( ushort i = 0; i < instrs_cnt; ++i ) {
    fd_instr_info_t const * instr = &instrs[i];

    fd_borrowed_account_t * p = NULL;
    int err = fd_txn_borrowed_account_view( txn_ctx, (fd_pubkey_t const *) &instr->program_id_pubkey, &p );
    if ( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "Error in ix borrowed acc view %d", err));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    total_accounts_data_size = fd_ulong_sat_add(total_accounts_data_size, p->starting_owner_dlen);
  }

  if (0 == txn_ctx->loaded_accounts_data_size_limit) {
    txn_ctx->custom_err = 33;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  if ( total_accounts_data_size > txn_ctx->loaded_accounts_data_size_limit ) {
    FD_LOG_WARNING(( "Total loaded accounts data size %lu has exceeded its set limit %lu", total_accounts_data_size, txn_ctx->loaded_accounts_data_size_limit ));
    return FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_SIZE_EXCEEDED;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_executor_collect_fee( fd_exec_slot_ctx_t *          slot_ctx,
                         fd_borrowed_account_t const * rec,
                         ulong                         fee ) {

  if (fee > rec->meta->info.lamports) {
    // TODO: Not enough lamports to pay for this txn...
    //
    // (Should this be lamps + whatever is required to keep the payer rent exempt?)
    FD_LOG_WARNING(( "Not enough lamps" ));
    return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
  }

  // FD_LOG_DEBUG(( "fd_execute_txn: global->collected: %ld->%ld (%ld)", slot_ctx->slot_bank.collected_fees, slot_ctx->slot_bank.collected_fees + fee, fee));
  // FD_LOG_DEBUG(( "calling set_lamports to charge the fee %lu", fee));

  if( FD_FEATURE_ACTIVE( slot_ctx, checked_arithmetic_in_fee_validation ) ) {
    ulong x;
    bool cf = __builtin_usubl_overflow( rec->meta->info.lamports, fee, &x );
    if (cf) {
      // Sature_sub failure
      FD_LOG_WARNING(( "Not enough lamps" ));
      return FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;;
    }
    rec->meta->info.lamports = x;
  } else {
    rec->meta->info.lamports -= fee;
  }

  if( FD_FEATURE_ACTIVE( slot_ctx, set_exempt_rent_epoch_max ) ) {
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    if( FD_LIKELY( rec->const_meta->info.lamports >= fd_rent_exempt_minimum_balance2( &epoch_bank->rent,rec->const_meta->dlen ) ) ) {
      if( !fd_pubkey_is_sysvar_id( rec->pubkey ) ) {
        rec->meta->info.rent_epoch = ULONG_MAX;
      }
    }
  }

  return 0;
}

static void
export_account_state( fd_borrowed_account_t * borrowed_account,
                      fd_exec_test_acct_state_t * output_account ) {
    // Address
    output_account->has_address = true;
    fd_memcpy(output_account->address, borrowed_account->pubkey, sizeof(fd_pubkey_t));

    // Lamports
    output_account->has_lamports = true;
    output_account->lamports = (uint64_t) borrowed_account->const_meta->info.lamports;

    // Data
    output_account->data = fd_scratch_alloc(alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE(borrowed_account->const_meta->dlen));
    output_account->data->size = (pb_size_t) borrowed_account->const_meta->dlen;
    fd_memcpy(output_account->data->bytes, borrowed_account->const_data, borrowed_account->const_meta->dlen);

    // Executable
    output_account->has_executable = true;
    output_account->executable = (bool) borrowed_account->const_meta->info.executable;

    // Rent epoch
    output_account->has_rent_epoch = true;
    output_account->rent_epoch = (uint64_t) borrowed_account->const_meta->info.rent_epoch;

    // Owner
    output_account->has_owner = true;
    fd_memcpy(output_account->owner, borrowed_account->const_meta->info.owner, sizeof(fd_pubkey_t));
}

void 
fd_create_instr_context_protobuf_from_instructions( fd_exec_test_instr_context_t * instr_context, 
                                                    fd_exec_txn_ctx_t *txn_ctx, 
                                                    fd_instr_info_t *instr ) {
  /*
  NOTE: Calling this function requires the caller to have a scratch frame ready (see dump_instr_to_protobuf)
  */
  
  /* Prepare sysvar cache accounts */
  fd_pubkey_t const fd_relevant_sysvar_ids[] = {
    fd_sysvar_clock_id,
    fd_sysvar_epoch_schedule_id,
    fd_sysvar_epoch_rewards_id,
    fd_sysvar_fees_id,
    fd_sysvar_rent_id,
    fd_sysvar_slot_hashes_id,
    fd_sysvar_recent_block_hashes_id,
    fd_sysvar_stake_history_id,
    fd_sysvar_last_restart_slot_id,
    fd_sysvar_instructions_id,
  };
  const ulong num_sysvar_entries = (sizeof(fd_relevant_sysvar_ids) / sizeof(fd_pubkey_t));

  /* Program ID */
  instr_context->has_program_id = true;
  fd_memcpy( instr_context->program_id, instr->program_id_pubkey.uc, sizeof(fd_pubkey_t) );

  /* Loader ID */
  instr_context->has_loader_id = 1;
  // For now, the loader ID will be the owner of the program ID
  fd_memcpy( instr_context->loader_id, txn_ctx->borrowed_accounts[instr->program_id].const_meta->info.owner, sizeof(fd_pubkey_t) );

  /* Accounts */
  instr_context->accounts_count = (pb_size_t) txn_ctx->accounts_cnt;
  instr_context->accounts = fd_scratch_alloc(alignof(fd_exec_test_acct_state_t), (instr_context->accounts_count + num_sysvar_entries + txn_ctx->executable_cnt) * sizeof(fd_exec_test_acct_state_t));
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    // Copy account information over
    fd_borrowed_account_t * borrowed_account = &txn_ctx->borrowed_accounts[i];
    fd_exec_test_acct_state_t * output_account = &instr_context->accounts[i];
    export_account_state( borrowed_account, output_account );
  }

  /* Add sysvar cache variables */
  for( ulong i = 0; i < num_sysvar_entries; i++ ) {
    FD_BORROWED_ACCOUNT_DECL(borrowed_account);
    int ret = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, &fd_relevant_sysvar_ids[i], borrowed_account );
    if( ret != FD_ACC_MGR_SUCCESS ) {
      continue;
    }
    // Make sure the account doesn't exist in the output accounts yet
    int account_exists = 0;
    for( ulong j = 0; j < txn_ctx->accounts_cnt; j++ ) {
      if ( 0 == memcmp( txn_ctx->accounts[j].key, fd_relevant_sysvar_ids[i].uc, sizeof(fd_pubkey_t) ) ) {
        account_exists = true;
        break;
      }
    }

    // Copy it into output
    if (!account_exists) {
      fd_exec_test_acct_state_t * output_account = &instr_context->accounts[instr_context->accounts_count++];
      export_account_state( borrowed_account, output_account );
    }
  }

  /* Add executable accounts */
  for( ulong i = 0; i < txn_ctx->executable_cnt; i++ ) {
    FD_BORROWED_ACCOUNT_DECL(borrowed_account);
    int ret = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, txn_ctx->executable_accounts[i].pubkey, borrowed_account );
    if( ret != FD_ACC_MGR_SUCCESS ) {
      continue;
    }
    // Make sure the account doesn't exist in the output accounts yet
    bool account_exists = false;
    for( ulong j = 0; j < instr_context->accounts_count; j++ ) {
      if( 0 == memcmp( instr_context->accounts[j].address, txn_ctx->executable_accounts[i].pubkey->uc, sizeof(fd_pubkey_t) ) ) {
        account_exists = true;
        break;
      }
    }

    // Copy it into output
    if( !account_exists ) {
      fd_exec_test_acct_state_t * output_account = &instr_context->accounts[instr_context->accounts_count++];
      export_account_state( borrowed_account, output_account );
    }
  }

  /* Instruction Accounts */
  instr_context->instr_accounts_count = (pb_size_t) instr->acct_cnt;
  instr_context->instr_accounts = fd_scratch_alloc( alignof(fd_exec_test_instr_acct_t), instr_context->instr_accounts_count * sizeof(fd_exec_test_instr_acct_t) );
  for( ushort i = 0; i < instr->acct_cnt; i++ ) {
    fd_exec_test_instr_acct_t * output_instr_account = &instr_context->instr_accounts[i];

    uchar account_flag = instr->acct_flags[i];
    bool is_writable = account_flag & FD_INSTR_ACCT_FLAGS_IS_WRITABLE;
    bool is_signer = account_flag & FD_INSTR_ACCT_FLAGS_IS_SIGNER;

    output_instr_account->has_index = true;
    output_instr_account->index = instr->acct_txn_idxs[i];

    output_instr_account->has_is_writable = true;
    output_instr_account->is_writable = is_writable;

    output_instr_account->has_is_signer = true;
    output_instr_account->is_signer = is_signer;
  }

  /* Data */
  instr_context->data = fd_scratch_alloc( alignof(pb_bytes_array_t), PB_BYTES_ARRAY_T_ALLOCSIZE(instr->data_sz) );
  instr_context->data->size = (pb_size_t) instr->data_sz;
  fd_memcpy( instr_context->data->bytes, instr->data, instr->data_sz );

  /* Compute Units */
  instr_context->has_cu_avail = true;
  instr_context->cu_avail = txn_ctx->compute_meter;

  /* Txn Context */
  instr_context->has_txn_context = true;
  // TODO: Fill in transaction context whenever it becomes supported

  /* Slot Context */
  instr_context->has_slot_context = true;

  /* Epoch Context */
  uint64_t * features = fd_scratch_alloc( alignof(uint64_t), FD_FEATURE_ID_CNT * sizeof(uint64_t) );
  ulong num_features = 0;
  for( const fd_feature_id_t * current_feature = fd_feature_iter_init(); !fd_feature_iter_done( current_feature ); current_feature = fd_feature_iter_next( current_feature ) ) {
    if (txn_ctx->epoch_ctx->features.f[current_feature->index] != FD_FEATURE_DISABLED) {
      features[num_features++] = (uint64_t) current_feature->id.ul[0];
    }
  }
  // Sort the features
  void * scratch = fd_scratch_alloc( sort_uint64_t_stable_scratch_align(), sort_uint64_t_stable_scratch_footprint(num_features) );
  uint64_t * sorted_features = sort_uint64_t_stable_fast( features, num_features, scratch );

  instr_context->has_epoch_context = true;
  instr_context->epoch_context.has_features = true;
  instr_context->epoch_context.features.features_count = (pb_size_t) num_features;
  instr_context->epoch_context.features.features = sorted_features;
}

/*  This function dumps individual instructions from a ledger replay.

    The following arguments can be added when replaying ledger transactions:
      --dump-insn-to-pb <0/1>
        * If enabled, instructions will be dumped to the specified output directory
      --dump-insn-sig-filter <base_58_enc_sig>
        * If enabled, only instructions with the specified signature will be dumped 
        * Provided signature must be base58-encoded
        * Default behavior if signature filter is not provided is to dump EVERY instruction
      --dump-insn-output-dir <output_dir>
        * Each file represents a single instruction as a serialized InstrContext Protobuf message
        * File name format is "instr-<base58_enc_sig>-<instruction_idx>.bin", where instruction_idx is 1-indexed

    solana-conformance (https://github.com/firedancer-io/solana-conformance) 
      * Allows decoding / debugging of instructions in an isolated environment
      * Allows execution result(s) comparison with Solana / Agave
      * See solana-conformance/README.md for functionality and use cases
*/
static void
dump_instr_to_protobuf( fd_exec_txn_ctx_t *txn_ctx,
                        fd_instr_info_t *instr,
                        ushort instruction_idx ) {


  FD_SCRATCH_SCOPE_BEGIN {
    // Get base58-encoded tx signature
    const fd_ed25519_sig_t * signatures = fd_txn_get_signatures( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw );
    fd_ed25519_sig_t signature; fd_memcpy( signature, signatures[0], sizeof(fd_ed25519_sig_t) );
    char encoded_signature[FD_BASE58_ENCODED_64_SZ];
    ulong out_size;
    fd_base58_encode_64( signature, &out_size, encoded_signature );

    if (txn_ctx->capture_ctx->dump_insn_sig_filter) {
      ulong filter_strlen = (ulong) strlen(txn_ctx->capture_ctx->dump_insn_sig_filter);

      // Terminate early if the signature does not match
      if (txn_ctx->capture_ctx->dump_insn_sig_filter &&
          memcmp(txn_ctx->capture_ctx->dump_insn_sig_filter, encoded_signature, filter_strlen < out_size ? filter_strlen : out_size)) {
        return;
      }
    }

    fd_exec_test_instr_context_t instr_context = FD_EXEC_TEST_INSTR_CONTEXT_INIT_DEFAULT;
    fd_create_instr_context_protobuf_from_instructions( &instr_context, txn_ctx, instr );

    /* Output to file */
    ulong out_buf_size = 100 * 1024 * 1024;
    uint8_t * out = fd_scratch_alloc(alignof(uint8_t), out_buf_size);
    pb_ostream_t stream = pb_ostream_from_buffer(out, out_buf_size);
    if (pb_encode(&stream, FD_EXEC_TEST_INSTR_CONTEXT_FIELDS, &instr_context)) {
      char output_filepath[256]; fd_memset(output_filepath, 0, sizeof(output_filepath));
      char * position = fd_cstr_init(output_filepath);
      position = fd_cstr_append_cstr(position, txn_ctx->capture_ctx->dump_insn_output_dir);
      position = fd_cstr_append_cstr(position, "/instr-");
      position = fd_cstr_append_cstr(position, encoded_signature);
      position = fd_cstr_append_cstr(position, "-");
      position = fd_cstr_append_ushort_as_text(position, '0', 0, instruction_idx, 3); // Assume max 3 digits
      position = fd_cstr_append_cstr(position, ".bin");
      fd_cstr_fini(position);

      FILE * file = fopen(output_filepath, "wb");
      if( file ) {
        fwrite( out, 1, stream.bytes_written, file );
        fclose( file );
      }
    }
  } FD_SCRATCH_SCOPE_END;
}

int
fd_execute_instr( fd_exec_txn_ctx_t * txn_ctx,
                  fd_instr_info_t *   instr ) {
  FD_SCRATCH_SCOPE_BEGIN {
    ulong max_num_instructions = FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, limit_max_instruction_trace_length ) ? 64 : ULONG_MAX;
    if( txn_ctx->num_instructions >= max_num_instructions ) {
      return -1;
    }
    txn_ctx->num_instructions++;
    fd_pubkey_t const * txn_accs = txn_ctx->accounts;

    ulong starting_lamports_h = 0;
    ulong starting_lamports_l = 0;
    int err = fd_instr_info_sum_account_lamports( instr, &starting_lamports_h, &starting_lamports_l );
    if( err ) {
      return err;
    }
    instr->starting_lamports_h = starting_lamports_h;
    instr->starting_lamports_l = starting_lamports_l;

    fd_exec_instr_ctx_t * parent = NULL;
    if( txn_ctx->instr_stack_sz )
      parent = &txn_ctx->instr_stack[ txn_ctx->instr_stack_sz - 1 ];

    fd_exec_instr_ctx_t * ctx = &txn_ctx->instr_stack[ txn_ctx->instr_stack_sz++ ];
    *ctx = (fd_exec_instr_ctx_t) {
      .instr     = instr,
      .txn_ctx   = txn_ctx,
      .epoch_ctx = txn_ctx->epoch_ctx,
      .slot_ctx  = txn_ctx->slot_ctx,
      .valloc    = fd_scratch_virtual(),
      .acc_mgr   = txn_ctx->acc_mgr,
      .funk_txn  = txn_ctx->funk_txn,
      .parent    = parent,
      .index     = parent ? (parent->child_cnt++) : 0,
      .depth     = parent ? (parent->depth+1    ) : 0,
      .child_cnt = 0U,
    };

    // defense in depth
    if( instr->program_id >= txn_ctx->txn_descriptor->acct_addr_cnt + txn_ctx->txn_descriptor->addr_table_adtl_cnt ) {
      FD_LOG_WARNING(( "INVALID PROGRAM ID, RUNTIME BUG!!!" ));
      int exec_result = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      txn_ctx->instr_stack_sz--;

      FD_LOG_WARNING(( "instruction executed unsuccessfully: error code %d", exec_result ));
      return exec_result;
    }

    fd_pubkey_t const * program_id = &txn_accs[ instr->program_id ];
    fd_exec_instr_fn_t  native_prog_fn = fd_executor_lookup_native_program( program_id );

    fd_exec_txn_ctx_reset_return_data( txn_ctx );
    int exec_result = FD_EXECUTOR_INSTR_SUCCESS;
    if( native_prog_fn != NULL ) {
      exec_result = native_prog_fn( *ctx );
    } else if( fd_bpf_loader_v3_is_executable( ctx->slot_ctx, program_id )==0 ||
               !memcmp( program_id, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof( fd_pubkey_t ) ) ) {
      exec_result = fd_bpf_loader_v3_program_execute( *ctx );
    } else if( fd_bpf_loader_v2_is_executable( ctx->slot_ctx, program_id )==0 ) {
      exec_result = fd_bpf_loader_v2_user_execute( *ctx );
    } else {
      exec_result = FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
    }

    // FD_LOG_NOTICE(("COMPUTE METER END %lu %lu %lu %64J", before_instr_cus - txn_ctx->compute_meter, txn_ctx->compute_meter, txn_ctx->compute_unit_limit, sig ));

    if( exec_result == FD_EXECUTOR_INSTR_SUCCESS ) {
      ulong ending_lamports_h = 0UL;
      ulong ending_lamports_l = 0UL;
      err = fd_instr_info_sum_account_lamports( instr, &ending_lamports_h, &ending_lamports_l );
      if( err ) {
        return err;
      }

      if( ending_lamports_l != starting_lamports_l || ending_lamports_h != starting_lamports_h ) {
        exec_result = FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
      }

      /* TODO where does Agave do this? */
      for( ulong j=0UL; j < txn_ctx->accounts_cnt; j++ ) {
        if( FD_UNLIKELY( txn_ctx->borrowed_accounts[j].refcnt_excl ) ) {
          FD_LOG_ERR(( "Txn %64J: Program %32J didn't release lock (%u) on %32J", fd_txn_get_signatures( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw )[0], instr->program_id_pubkey.uc, *(uint *)(instr->data), txn_ctx->borrowed_accounts[j].pubkey->uc ));
        }
      }
    } else if( !txn_ctx->failed_instr ) {
      txn_ctx->failed_instr = ctx;
      ctx->instr_err        = (uint)( -exec_result - 1 );
    }

#ifdef VLOG
  if ( 257035230 == ctx->slot_ctx->slot_bank.slot ) {
    if ( FD_UNLIKELY( exec_result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      FD_LOG_WARNING(( "instruction executed unsuccessfully: error code %d, custom err: %d, program id: %32J", exec_result, txn_ctx->custom_err, program_id_acc ));
    } else {
      FD_LOG_WARNING(( "instruction executed successfully: error code %d, custom err: %d, program id: %32J", exec_result, txn_ctx->custom_err, program_id_acc ));
    }
  }
#endif

    txn_ctx->instr_stack_sz--;

    /* TODO: sanity before/after checks: total lamports unchanged etc */
    return exec_result;
  } FD_SCRATCH_SCOPE_END;
}

void
fd_executor_setup_borrowed_accounts_for_txn( fd_exec_txn_ctx_t * txn_ctx ) {
  ulong j = 0;
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    fd_pubkey_t * acc = &txn_ctx->accounts[i];

    fd_borrowed_account_t * borrowed_account = fd_borrowed_account_init( &txn_ctx->borrowed_accounts[i] );
    int err = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, acc, borrowed_account );
    memcpy(borrowed_account->pubkey->key, acc, sizeof(*acc));

    if( FD_UNLIKELY( err ) ) {
      // FD_LOG_WARNING(( "fd_acc_mgr_view(%32J) failed (%d-%s)", acc->uc, err, fd_acc_mgr_strerror( err ) ));
    }

    if( fd_txn_account_is_writable_idx( txn_ctx->txn_descriptor, txn_ctx->accounts, (int)i ) ) {
        void * borrowed_account_data = fd_valloc_malloc( txn_ctx->valloc, 8UL, fd_borrowed_account_raw_size( borrowed_account ) );
        fd_borrowed_account_make_modifiable( borrowed_account, borrowed_account_data );
    }

    fd_account_meta_t const * meta = borrowed_account->const_meta ? borrowed_account->const_meta : borrowed_account->meta;
    if (meta == NULL) {
      static const fd_account_meta_t sentinel = { .magic = FD_ACCOUNT_META_MAGIC };
      borrowed_account->const_meta        = &sentinel;
      borrowed_account->starting_lamports = 0UL;
      borrowed_account->starting_dlen     = 0UL;
      continue;
    }

    if( meta->info.executable ) {
      FD_BORROWED_ACCOUNT_DECL(owner_borrowed_account);
      int err = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, (fd_pubkey_t *)meta->info.owner, owner_borrowed_account );
      if( FD_UNLIKELY( err ) ) {
        borrowed_account->starting_owner_dlen = 0;
      } else {
        borrowed_account->starting_owner_dlen = owner_borrowed_account->const_meta->dlen;
      }
    }

    if( FD_UNLIKELY( memcmp( meta->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) == 0 ) ) {
      fd_bpf_upgradeable_loader_state_t program_loader_state;
      int err = 0;
      if( FD_UNLIKELY( !read_bpf_upgradeable_loader_state_for_program( txn_ctx, (uchar) i, &program_loader_state, &err ) ) ) {
        continue;
      }
      fd_bincode_destroy_ctx_t ctx_d = { .valloc = txn_ctx->valloc };

      if( !fd_bpf_upgradeable_loader_state_is_program( &program_loader_state ) ) {
        fd_bpf_upgradeable_loader_state_destroy( &program_loader_state, &ctx_d );
        continue;
      }

      fd_pubkey_t * programdata_acc = &program_loader_state.inner.program.programdata_address;
      fd_borrowed_account_t * executable_account = fd_borrowed_account_init( &txn_ctx->executable_accounts[j] );
      fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, programdata_acc, executable_account);
      j++;
    }
  }
  txn_ctx->executable_cnt = j;
}

/* Stuff to be done before multithreading can begin */
int
fd_execute_txn_prepare_phase1( fd_exec_slot_ctx_t *  slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx,
                               fd_txn_t const * txn_descriptor,
                               fd_rawtxn_b_t const * txn_raw ) {
  fd_exec_txn_ctx_new( txn_ctx );
  fd_exec_txn_ctx_from_exec_slot_ctx( slot_ctx, txn_ctx );
  fd_exec_txn_ctx_setup( txn_ctx, txn_descriptor, txn_raw );

  fd_executor_setup_accessed_accounts_for_txn( txn_ctx );
  int err;
  int is_nonce = fd_has_nonce_account(txn_ctx, &err);
  if ((NULL == txn_descriptor) || !is_nonce) {
    if ( txn_raw == NULL ) {
      return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
    }
  }

  #ifdef VLOG
    fd_txn_t const *txn = txn_ctx->txn_descriptor;
    fd_rawtxn_b_t const *raw_txn = txn_ctx->_txn_raw;
    uchar * sig = (uchar *)raw_txn->raw + txn->signature_off;
    FD_LOG_WARNING(("Preparing Transaction %64J, %lu", sig, txn_ctx->heap_size));
  #endif

  int compute_budget_status = fd_executor_compute_budget_program_execute_instructions( txn_ctx, txn_ctx->_txn_raw );

  if ((NULL != txn_descriptor) && is_nonce) {
    uchar found_fee_payer = 0;
    for ( ulong i = 0; i < txn_descriptor->acct_addr_cnt; i++ ) {
      if( is_non_loader_program_key( txn_descriptor, txn_raw, (uchar)i ) ) {
        found_fee_payer = 1;
      }
    }
    if ( !found_fee_payer ) {
      return FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND;
    }
  }


  return compute_budget_status;
}

int
fd_execute_txn_prepare_phase2( fd_exec_slot_ctx_t *  slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx ) {

  fd_pubkey_t * tx_accs = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->acct_addr_off);

  fd_pubkey_t const * fee_payer_acc = &tx_accs[0];
  FD_BORROWED_ACCOUNT_DECL(rec);
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, fee_payer_acc, rec );

  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_acc_mgr_view(%32J) failed (%d-%s)", fee_payer_acc->uc, err, fd_acc_mgr_strerror( err ) ));
    // TODO: The fee payer does not seem to exist?!  what now?
    return -1;
  }

  FD_SCRATCH_SCOPE_BEGIN {
    void * rec_data = fd_valloc_malloc( fd_scratch_virtual(), 8UL, fd_borrowed_account_raw_size( rec ) );
    fd_borrowed_account_make_modifiable( rec, rec_data );

    ulong fee = fd_runtime_calculate_fee( txn_ctx, txn_ctx->txn_descriptor, txn_ctx->_txn_raw );
    if( fd_executor_collect_fee( slot_ctx, rec, fee ) ) {
      
      return -1;
    }
    slot_ctx->slot_bank.collected_fees += fee;

    err = fd_acc_mgr_save( slot_ctx->acc_mgr, rec );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fd_acc_mgr_save(%32J) failed (%d-%s)", fee_payer_acc->uc, err, fd_acc_mgr_strerror( err ) ));
      // TODO: The fee payer does not seem to exist?!  what now?
      return -1;
    }
  } FD_SCRATCH_SCOPE_END;

  return 0;
}

int
fd_execute_txn_prepare_phase3( fd_exec_slot_ctx_t * slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx,
                               fd_txn_p_t * txn ) {
  fd_funk_txn_t * parent_txn = slot_ctx->funk_txn;
  // fd_funk_txn_xid_t xid;
  // fd_ed25519_sig_t const * sig0 = &fd_txn_get_signatures( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw )[0];

  // fd_memcpy( xid.uc, sig0, sizeof( fd_funk_txn_xid_t ) );
  // fd_funk_txn_t * txn = fd_funk_txn_prepare( slot_ctx->acc_mgr->funk, parent_txn, &xid, 1 );
  // txn_ctx->funk_txn = txn;
  txn_ctx->funk_txn = parent_txn;

  if (FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, apply_cost_tracker_during_replay ) ) {
    ulong est_cost = fd_pack_compute_cost( txn, &txn->flags );
    if( slot_ctx->total_compute_units_requested + est_cost <= MAX_COMPUTE_UNITS_PER_BLOCK ) {
      slot_ctx->total_compute_units_requested += est_cost;
    } else {
      return FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_BLOCK_COST_LIMIT;
    }

    fd_pubkey_t * tx_accs   = txn_ctx->accounts;
    for( fd_txn_acct_iter_t ctrl = fd_txn_acct_iter_init( txn_ctx->txn_descriptor, FD_TXN_ACCT_CAT_WRITABLE & FD_TXN_ACCT_CAT_IMM );
         ctrl != fd_txn_acct_iter_end(); ctrl=fd_txn_acct_iter_next( ctrl ) ) {
      ulong i = fd_txn_acct_iter_idx( ctrl );
      fd_pubkey_t * acct = &tx_accs[i];
      int is_writable = fd_txn_account_is_writable_idx(txn_ctx->txn_descriptor, tx_accs, (int)i) &&
                        !fd_txn_account_is_demotion( txn_ctx, (int)i );
      if (!is_writable) {
        continue;
      }
      fd_account_compute_elem_t * elem = fd_account_compute_table_query( slot_ctx->account_compute_table, acct, NULL );
      if ( !elem ) {
        elem = fd_account_compute_table_insert( slot_ctx->account_compute_table, acct );
        elem->cu_consumed = 0;
      }

      if ( elem->cu_consumed + est_cost > MAX_COMPUTE_UNITS_PER_WRITE_LOCKED_ACCOUNT ) {
        return FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT;
      }

      elem->cu_consumed += est_cost;
    }
  }

  return 0;
}

int
fd_execute_txn_prepare_phase4( fd_exec_slot_ctx_t * slot_ctx,
                               fd_exec_txn_ctx_t * txn_ctx ) {
  fd_executor_setup_borrowed_accounts_for_txn( txn_ctx );
  /* Update rent exempt on writable accounts if feature activated
    TODO this should probably not run on executable accounts
        Also iterate over LUT accounts */
  if( FD_FEATURE_ACTIVE( slot_ctx, set_exempt_rent_epoch_max ) ) {
    fd_pubkey_t * tx_accs   = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->acct_addr_off);
    for( fd_txn_acct_iter_t ctrl = fd_txn_acct_iter_init( txn_ctx->txn_descriptor, FD_TXN_ACCT_CAT_WRITABLE );
         ctrl != fd_txn_acct_iter_end(); ctrl=fd_txn_acct_iter_next( ctrl ) ) {
      ulong i = fd_txn_acct_iter_idx( ctrl );
      if( (i == 0) || fd_pubkey_is_sysvar_id( &tx_accs[i] ) )
        continue;
      fd_set_exempt_rent_epoch_max( txn_ctx, &tx_accs[i] );
    }
  }

  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    txn_ctx->unknown_accounts[i] = 0;
    txn_ctx->nonce_accounts[i] = 0;
    if (fd_txn_is_writable(txn_ctx->txn_descriptor, (int)i)) {
      FD_BORROWED_ACCOUNT_DECL(writable_new);
      int err = fd_acc_mgr_view(txn_ctx->acc_mgr, txn_ctx->funk_txn, &txn_ctx->accounts[i], writable_new);
      if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
        txn_ctx->unknown_accounts[i] = 1;
      }
    }
  }

  return 0;
}

/* Stuff to be done after multithreading ends */
int
fd_execute_txn_finalize( fd_exec_slot_ctx_t * slot_ctx,
                         fd_exec_txn_ctx_t * txn_ctx,
                         int exec_txn_err ) {
  if( exec_txn_err != 0 ) {
    for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
      fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];
      void * acc_rec_data = fd_borrowed_account_destroy( acc_rec );
      if( acc_rec_data != NULL ) {
        fd_valloc_free( txn_ctx->valloc, acc_rec_data );
      }
    }

    // fd_funk_txn_cancel( slot_ctx->acc_mgr->funk, txn_ctx->funk_txn, 0 );
    return 0;
  }

  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    if( !fd_txn_account_is_writable_idx(txn_ctx->txn_descriptor, txn_ctx->accounts, (int)i) ) {
      continue;
    }

    fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];

    if( txn_ctx->unknown_accounts[i] ) {
      memset( acc_rec->meta->hash, 0xFF, sizeof(fd_hash_t) );
      if( FD_FEATURE_ACTIVE( slot_ctx, set_exempt_rent_epoch_max ) ) {
        fd_set_exempt_rent_epoch_max( txn_ctx, &txn_ctx->accounts[i] );
      }
    }

    int ret = fd_acc_mgr_save_non_tpool( txn_ctx->acc_mgr, txn_ctx->funk_txn, acc_rec );
    if( ret != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_ERR(( "failed to save edits to accounts" ));
      return -1;
    }

    void * borrow_account_data = fd_borrowed_account_destroy( acc_rec );
    if( borrow_account_data != NULL ) {
      fd_valloc_free( txn_ctx->valloc, borrow_account_data );
    }
  }

  return 0;
}

int
fd_execute_txn( fd_exec_txn_ctx_t * txn_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN {
    uint use_sysvar_instructions = fd_executor_txn_uses_sysvar_instructions( txn_ctx );

    fd_instr_info_t instrs[txn_ctx->txn_descriptor->instr_cnt];
    for ( ushort i = 0; i < txn_ctx->txn_descriptor->instr_cnt; i++ ) {
      fd_txn_instr_t const * txn_instr = &txn_ctx->txn_descriptor->instr[i];
      fd_convert_txn_instr_to_instr( txn_ctx, txn_instr, txn_ctx->borrowed_accounts, &instrs[i] );
    }

    int ret = 0;
    if ( FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, cap_transaction_accounts_data_size ) ) {
      int ret = fd_cap_transaction_accounts_data_size( txn_ctx, instrs, txn_ctx->txn_descriptor->instr_cnt );
      if ( ret != FD_EXECUTOR_INSTR_SUCCESS ) {
        fd_funk_txn_cancel(txn_ctx->acc_mgr->funk, txn_ctx->funk_txn, 0);
        return ret;
      }
    }

    if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
      ret = fd_sysvar_instructions_serialize_account( txn_ctx, instrs, txn_ctx->txn_descriptor->instr_cnt );
      if( ret != FD_ACC_MGR_SUCCESS ) {
        FD_LOG_WARNING(( "sysvar instrutions failed to serialize" ));
        return ret;
      }
    }

#ifdef VLOG
    fd_txn_t const *txn = txn_ctx->txn_descriptor;
    fd_rawtxn_b_t const *raw_txn = txn_ctx->_txn_raw;
    uchar * sig = (uchar *)raw_txn->raw + txn->signature_off;
#endif


    for ( ushort i = 0; i < txn_ctx->txn_descriptor->instr_cnt; i++ ) {
#ifdef VLOG
        if ( FD_UNLIKELY( 257037453 == txn_ctx->slot_ctx->slot_bank.slot ) )
          FD_LOG_WARNING(("Start of transaction for %d for %64J", i, sig));
#endif

      if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
        ret = fd_sysvar_instructions_update_current_instr_idx( txn_ctx, i );
        if( ret != FD_ACC_MGR_SUCCESS ) {
          FD_LOG_WARNING(( "sysvar instructions failed to update instruction index" ));
          return ret;
        }
      }

      if (txn_ctx->capture_ctx && txn_ctx->capture_ctx->dump_insn_to_pb && txn_ctx->slot_ctx->slot_bank.slot >= txn_ctx->capture_ctx->dump_insn_start_slot) {
        // Capture the input and convert it into a Protobuf message
        dump_instr_to_protobuf(txn_ctx, &instrs[i], i);
      }

      int exec_result = fd_execute_instr( txn_ctx, &instrs[i] );
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
            FD_LOG_WARNING(( "fd_execute_instr failed (%d:%d) for %64J", exec_result, txn_ctx->custom_err, sig ));
  #endif
          } else {
  #ifdef VLOG
            FD_LOG_WARNING(( "fd_execute_instr failed (%d) index %u for %64J", exec_result, i, sig ));
  #endif
          }
  #ifdef VLOG
        }
  #endif
        if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
          ret = fd_sysvar_instructions_cleanup_account( txn_ctx );
          if( ret != FD_ACC_MGR_SUCCESS ) {
            FD_LOG_WARNING(( "sysvar instructions failed to cleanup" ));
            return ret;
          }
        }
        return exec_result;
      }
    }
    int err = fd_executor_txn_check( txn_ctx->slot_ctx, txn_ctx );
    if ( err != FD_EXECUTOR_INSTR_SUCCESS) {
      FD_LOG_DEBUG(( "fd_executor_txn_check failed (%d)", err ));
      if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
        ret = fd_sysvar_instructions_cleanup_account( txn_ctx );
        if( ret != FD_ACC_MGR_SUCCESS ) {
          FD_LOG_WARNING(( "sysvar instructions failed to cleanup" ));
          return ret;
        }
      }
      return err;
    }

    if ( FD_UNLIKELY( use_sysvar_instructions ) ) {
      ret = fd_sysvar_instructions_cleanup_account( txn_ctx );
      if( ret != FD_ACC_MGR_SUCCESS ) {
        FD_LOG_WARNING(( "sysvar instructions failed to cleanup" ));
        return ret;
      }
    }

    for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
      fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];

      /* An account writable iff it is writable AND it is not being demoted.
         If this criteria is not met, the account should not be marked as touched
         via updating its most recent slot. */
      int is_writable = fd_txn_account_is_writable_idx(txn_ctx->txn_descriptor, txn_ctx->accounts, (int)i) &&
                        !fd_txn_account_is_demotion( txn_ctx, (int)i );
      if( !is_writable ) {
        continue;
      }

      acc_rec->meta->slot = txn_ctx->slot_ctx->slot_bank.slot;

      if( acc_rec->meta->info.lamports == 0 ) {
        acc_rec->meta->dlen = 0;
        memset( acc_rec->meta->info.owner, 0, sizeof(fd_pubkey_t) );
      }
    }

    return 0;
  } FD_SCRATCH_SCOPE_END;
}

int fd_executor_txn_check( fd_exec_slot_ctx_t * slot_ctx,  fd_exec_txn_ctx_t *txn ) {
  fd_rent_t const * rent = slot_ctx->sysvar_cache_old.rent;

  ulong ending_lamports = 0;
  ulong ending_dlen = 0;
  ulong starting_lamports = 0;
  ulong starting_dlen = 0;

  for( ulong idx = 0; idx < txn->accounts_cnt; idx++ ) {
    fd_borrowed_account_t * b = &txn->borrowed_accounts[idx];

    // Was this account written to?
    if( NULL != b->meta ) {
      ending_lamports += b->meta->info.lamports;
      ending_dlen += b->meta->dlen;

      // Lets prevent creating non-rent-exempt accounts...
      uchar after_exempt = fd_rent_exempt_minimum_balance2( rent, b->meta->dlen) <= b->meta->info.lamports;

      if( memcmp( b->pubkey->key, fd_sysvar_incinerator_id.key, sizeof(fd_pubkey_t) )!=0) {
        if (after_exempt || b->meta->info.lamports == 0) {
          // no-op
        } else {
          uchar before_exempt = (b->starting_dlen != ULONG_MAX) ?
            (fd_rent_exempt_minimum_balance2( rent, b->starting_dlen) <= b->starting_lamports) : 1;
          if (before_exempt || b->starting_lamports == 0) {
            FD_LOG_DEBUG(("Rent exempt error for %32J Curr len %lu Starting len %lu Curr lamports %lu Starting lamports %lu Curr exempt %lu Starting exempt %lu", b->pubkey->uc, b->meta->dlen, b->starting_dlen, b->meta->info.lamports, b->starting_lamports, fd_rent_exempt_minimum_balance2( rent, b->meta->dlen), fd_rent_exempt_minimum_balance2( rent, b->starting_dlen)));
            return FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT;
          } else if (!before_exempt && (b->meta->dlen == b->starting_dlen) && b->meta->info.lamports <= b->starting_lamports) {
            // no-op
          } else {
            FD_LOG_DEBUG(("Rent exempt error for %32J Curr len %lu Starting len %lu Curr lamports %lu Starting lamports %lu Curr exempt %lu Starting exempt %lu", b->pubkey->uc, b->meta->dlen, b->starting_dlen, b->meta->info.lamports, b->starting_lamports, fd_rent_exempt_minimum_balance2( rent, b->meta->dlen), fd_rent_exempt_minimum_balance2( rent, b->starting_dlen)));
            return FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT;
          }
        }
      }

      if (b->starting_lamports != ULONG_MAX)
        starting_lamports += b->starting_lamports;
      if (b->starting_dlen != ULONG_MAX)
        starting_dlen += b->starting_dlen;
    } else if (NULL != b->const_meta) {
      // FD_LOG_DEBUG(("Const rec mismatch %32J starting %lu %lu ending %lu %lu", b->pubkey->uc, b->starting_dlen, b->starting_lamports, b->const_meta->dlen, b->const_meta->info.lamports));
      // Should these just kill the client?  They are impossible...
      if (b->starting_lamports != b->const_meta->info.lamports) {
        FD_LOG_DEBUG(("Const rec mismatch %32J starting %lu %lu ending %lu %lu", b->pubkey->uc, b->starting_dlen, b->starting_lamports, b->const_meta->dlen, b->const_meta->info.lamports));
        return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
      }
      if (b->starting_dlen != b->const_meta->dlen) {
        FD_LOG_DEBUG(("Const rec mismatch %32J starting %lu %lu ending %lu %lu", b->pubkey->uc, b->starting_dlen, b->starting_lamports, b->const_meta->dlen, b->const_meta->info.lamports));
        return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
      }
    }
  }

  // Should these just kill the client?  They are impossible yet solana just throws an error
  if (ending_lamports != starting_lamports) {
    FD_LOG_DEBUG(("Lamport sum mismatch: starting %lu ending %lu", starting_lamports, ending_lamports));
    return FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR;
  }
#if 0
  // cap_accounts_data_allocations_per_transaction
  //    TODO: I am unsure if this is the correct check...
  if (((long)ending_dlen - (long)starting_dlen) > MAX_PERMITTED_DATA_INCREASE)
    return FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_SIZE_EXCEEDED;
#endif

  /* TODO unused variables */
  (void)ending_dlen; (void)starting_dlen;

  return FD_EXECUTOR_INSTR_SUCCESS;
}
#undef VLOG

FD_FN_CONST char const *
fd_executor_instr_strerror( int err ) {

  switch( err ) {
  case FD_EXECUTOR_INSTR_SUCCESS                                : return "success";
  case FD_EXECUTOR_INSTR_ERR_FATAL                              : return "FATAL";
  case FD_EXECUTOR_INSTR_ERR_GENERIC_ERR                        : return "GENERIC_ERR";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ARG                        : return "INVALID_ARG";
  case FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA                 : return "INVALID_INSTR_DATA";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA                   : return "INVALID_ACC_DATA";
  case FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL                 : return "ACC_DATA_TOO_SMALL";
  case FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS                 : return "INSUFFICIENT_FUNDS";
  case FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID               : return "INCORRECT_PROGRAM_ID";
  case FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE         : return "MISSING_REQUIRED_SIGNATURE";
  case FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED            : return "ACC_ALREADY_INITIALIZED";
  case FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT              : return "UNINITIALIZED_ACCOUNT";
  case FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR                   : return "UNBALANCED_INSTR";
  case FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID                : return "MODIFIED_PROGRAM_ID";
  case FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND     : return "EXTERNAL_ACCOUNT_LAMPORT_SPEND";
  case FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED             : return "EXTERNAL_DATA_MODIFIED";
  case FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE            : return "READONLY_LAMPORT_CHANGE";
  case FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED             : return "READONLY_DATA_MODIFIED";
  case FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_IDX              : return "DUPLICATE_ACCOUNT_IDX";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED                : return "EXECUTABLE_MODIFIED";
  case FD_EXECUTOR_INSTR_ERR_RENT_EPOCH_MODIFIED                : return "RENT_EPOCH_MODIFIED";
  case FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS                : return "NOT_ENOUGH_ACC_KEYS";
  case FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED              : return "ACC_DATA_SIZE_CHANGED";
  case FD_EXECUTOR_INSTR_ERR_ACC_NOT_EXECUTABLE                 : return "ACC_NOT_EXECUTABLE";
  case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED                  : return "ACC_BORROW_FAILED";
  case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_OUTSTANDING             : return "ACC_BORROW_OUTSTANDING";
  case FD_EXECUTOR_INSTR_ERR_DUPLICATE_ACCOUNT_OUT_OF_SYNC      : return "DUPLICATE_ACCOUNT_OUT_OF_SYNC";
  case FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR                         : return "CUSTOM_ERR";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ERR                        : return "INVALID_ERR";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_DATA_MODIFIED           : return "EXECUTABLE_DATA_MODIFIED";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_LAMPORT_CHANGE          : return "EXECUTABLE_LAMPORT_CHANGE";
  case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT : return "EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT";
  case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID             : return "UNSUPPORTED_PROGRAM_ID";
  case FD_EXECUTOR_INSTR_ERR_CALL_DEPTH                         : return "CALL_DEPTH";
  case FD_EXECUTOR_INSTR_ERR_MISSING_ACC                        : return "MISSING_ACC";
  case FD_EXECUTOR_INSTR_ERR_REENTRANCY_NOT_ALLOWED             : return "REENTRANCY_NOT_ALLOWED";
  case FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED           : return "MAX_SEED_LENGTH_EXCEEDED";
  case FD_EXECUTOR_INSTR_ERR_INVALID_SEEDS                      : return "INVALID_SEEDS";
  case FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC                    : return "INVALID_REALLOC";
  case FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED            : return "COMPUTE_BUDGET_EXCEEDED";
  case FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION               : return "PRIVILEGE_ESCALATION";
  case FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE  : return "PROGRAM_ENVIRONMENT_SETUP_FAILURE";
  case FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPLETE         : return "PROGRAM_FAILED_TO_COMPLETE";
  case FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPILE          : return "PROGRAM_FAILED_TO_COMPILE";
  case FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE                      : return "ACC_IMMUTABLE";
  case FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY                : return "INCORRECT_AUTHORITY";
  case FD_EXECUTOR_INSTR_ERR_BORSH_IO_ERROR                     : return "BORSH_IO_ERROR";
  case FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT                : return "ACC_NOT_RENT_EXEMPT";
  case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER                  : return "INVALID_ACC_OWNER";
  case FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW                : return "ARITHMETIC_OVERFLOW";
  case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR                 : return "UNSUPPORTED_SYSVAR";
  case FD_EXECUTOR_INSTR_ERR_ILLEGAL_OWNER                      : return "ILLEGAL_OWNER";
  case FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_SIZE_EXCEEDED        : return "MAX_ACCS_DATA_SIZE_EXCEEDED";
  case FD_EXECUTOR_INSTR_ERR_ACTIVE_VOTE_ACC_CLOSE              : return "ACTIVE_VOTE_ACC_CLOSE";
  default: break;
  }

  return "unknown";
}
