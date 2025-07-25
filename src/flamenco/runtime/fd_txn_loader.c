#include "fd_txn_loader.h"
#include "fd_executor.h"
#include "sysvar/fd_sysvar_instructions.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "program/fd_bpf_loader_program.h"
#include "fd_system_ids.h"

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
load_transaction_account( fd_exec_txn_ctx_t * txn_ctx,
                          fd_txn_account_t *  acct,
                          uchar               is_writable,
                          ulong               epoch,
                          uchar               unknown_acc ) {

  /* Handling the sysvar instructions account explictly.
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L817-L824 */
  if( FD_UNLIKELY( !memcmp( acct->pubkey->key, fd_sysvar_instructions_id.key, sizeof(fd_pubkey_t) ) ) ) {
    /* The sysvar instructions account cannot be "loaded" since it's
       constructed by the SVM and modified within each transaction's
       instruction execution only, so it incurs a loaded size cost
       of 0. */
    fd_sysvar_instructions_serialize_account( txn_ctx, (fd_instr_info_t const *)txn_ctx->instr_infos, txn_ctx->txn_descriptor->instr_cnt );
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
    ulong base_account_size = FD_FEATURE_ACTIVE_BANK( txn_ctx->bank, formalize_loaded_transaction_data_size ) ? FD_TRANSACTION_ACCOUNT_BASE_SIZE : 0UL;

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L828-L835 */
    if( is_writable ) {
      txn_ctx->collected_rent += fd_runtime_collect_rent_from_account( fd_bank_epoch_schedule_query( txn_ctx->bank ),
                                                                       fd_bank_rent_query( txn_ctx->bank ),
                                                                       fd_bank_slots_per_year_get( txn_ctx->bank ),
                                                                       acct,
                                                                       epoch );
      acct->starting_lamports = acct->vt->get_lamports( acct ); /* TODO: why do we do this everywhere? */
    }
    return fd_ulong_sat_add( base_account_size, acct->vt->get_data_len( acct ) );
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
load_transaction_accounts_old( fd_exec_txn_ctx_t * txn_ctx ) {
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
    uchar is_writable = !!(fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, i ));

    /* Collect the fee payer account separately (since it was already)
       loaded during fee payer validation.

       https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L727-L729 */
    if( FD_UNLIKELY( i==FD_FEE_PAYER_TXN_IDX ) ) {
      /* Note that the dlen for most fee payers is 0, but we want to
         consider the case where the fee payer is a nonce account.
         We also don't need to add a base account size to this value
         because this branch would only be taken BEFORE SIMD-0186
         is enabled. */
      int err = accumulate_and_check_loaded_account_data_size( acct->vt->get_data_len( acct ),
                                                               requested_loaded_accounts_data_size,
                                                               &txn_ctx->loaded_accounts_data_size );
      if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
        return err;
      }
      continue;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L733-L740 */
    ulong loaded_acc_size = load_transaction_account( txn_ctx, acct, is_writable, epoch, unknown_acc );
    int err = accumulate_and_check_loaded_account_data_size( loaded_acc_size,
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

/* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L494-L515 */
static int
increase_calculated_data_size( fd_exec_txn_ctx_t * txn_ctx,
                               ulong               data_size_delta ) {
  /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L500-L503 */
  if( FD_UNLIKELY( data_size_delta>UINT_MAX ) ) {
    return FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L505-L507 */
  txn_ctx->loaded_accounts_data_size = fd_ulong_sat_add( txn_ctx->loaded_accounts_data_size, data_size_delta );

  if( FD_UNLIKELY( txn_ctx->loaded_accounts_data_size>txn_ctx->compute_budget_details.loaded_accounts_data_size_limit ) ) {
    return FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* This function is represented as a closure in Agave.
   https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L578-L640 */
static int
collect_loaded_account( fd_exec_txn_ctx_t * txn_ctx,
                        ushort              idx,
                        ulong               loaded_acc_size ) {
  fd_txn_account_t const * account = &txn_ctx->accounts[idx];

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L586-L590 */
  int err = increase_calculated_data_size( txn_ctx, loaded_acc_size );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  /* The remainder of this function is a deep-nested set of if
     statements. I've inverted the logic to make it easier to read.
     The purpose of the following code is to ensure that loader v3
     programdata accounts are accounted for exactly once in the account
     loading logic.

     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L611 */
  if( FD_LIKELY( memcmp( account->vt->get_owner( account ), fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }

  /* Try to read the program state
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L612-L634 */
  fd_bpf_upgradeable_loader_state_t * loader_state = fd_bpf_loader_program_get_state( account, txn_ctx->spad, NULL );
  if( FD_UNLIKELY( !loader_state ) ) {
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }

  /* Make sure the account is a v3 program */
  if( !fd_bpf_upgradeable_loader_state_is_program( loader_state ) ) {
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }

  /* Iterate through the account keys and make sure the programdata
     account is not present so it doesn't get loaded twice.
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L617-L618 */
  for( ushort i=0; i<txn_ctx->accounts_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( &txn_ctx->account_keys[i], &loader_state->inner.program.programdata_address, sizeof(fd_pubkey_t) ) ) ) {
      return FD_RUNTIME_EXECUTE_SUCCESS;
    }
  }

  /* Load the programdata account from Funk to read the programdata length */
  FD_TXN_ACCOUNT_DECL( programdata_account );
  err = fd_txn_account_init_from_funk_readonly( programdata_account,
                                                &loader_state->inner.program.programdata_address,
                                                txn_ctx->funk,
                                                txn_ctx->funk_txn );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }

  /* Try to accumulate the programdata's data size
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L625-L630 */
  ulong programdata_size_delta = fd_ulong_sat_add( FD_TRANSACTION_ACCOUNT_BASE_SIZE,
                                                   programdata_account->vt->get_data_len( programdata_account ) );
  err = increase_calculated_data_size( txn_ctx, programdata_size_delta );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

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
load_transaction_accounts_simd_186( fd_exec_txn_ctx_t * txn_ctx ) {
  fd_epoch_schedule_t schedule[1];
  if( FD_UNLIKELY( !fd_sysvar_epoch_schedule_read( txn_ctx->funk, txn_ctx->funk_txn, schedule ) ) ) {
    FD_LOG_ERR(( "Unable to read and decode epoch schedule sysvar" ));
  }

  ulong epoch = fd_slot_to_epoch( schedule, txn_ctx->slot, NULL );

  /* Charge a base fee for each address lookup table.
     https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L570-L576 */
  ulong aluts_size = fd_ulong_sat_mul( txn_ctx->txn_descriptor->addr_table_lookup_cnt,
                                       FD_ADDRESS_LOOKUP_TABLE_BASE_SIZE );
  int err = increase_calculated_data_size( txn_ctx, aluts_size );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L642-L660 */
  for( ushort i=0; i<txn_ctx->accounts_cnt; i++ ) {
    fd_txn_account_t * acct = &txn_ctx->accounts[i];
    uchar unknown_acc = !!(fd_exec_txn_ctx_get_account_at_index( txn_ctx, i, &acct, fd_txn_account_check_exists ) ||
                            acct->vt->get_lamports( acct )==0UL);
    uchar is_writable = !!(fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, i ));

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
                                                acct->vt->get_data_len( acct ) );
      int err = collect_loaded_account( txn_ctx, i, loaded_acc_size );
      if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
        return err;
      }
      continue;
    }

    /* Load and collect any remaining accounts
       https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L652-L659 */
    ulong loaded_acc_size = load_transaction_account( txn_ctx, acct, is_writable, epoch, unknown_acc );
    int err = collect_loaded_account( txn_ctx, i, loaded_acc_size );
    if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      return err;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L662-L686 */
  ushort instr_cnt = txn_ctx->txn_descriptor->instr_cnt;
  for( ushort i=0; i<instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &txn_ctx->txn_descriptor->instr[i];

    /* Mimicking `load_account()` here with 0-lamport check as well.
       https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L663-L666 */
    fd_txn_account_t * program_account;
    int err = fd_exec_txn_ctx_get_account_at_index( txn_ctx,
                                                    instr->program_id,
                                                    &program_account,
                                                    fd_txn_account_check_exists );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS || program_account->vt->get_lamports( program_account )==0UL ) ) {
      return FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L668-L675 */
    if( FD_UNLIKELY( !FD_FEATURE_ACTIVE_BANK( txn_ctx->bank, remove_accounts_executable_flag_checks ) &&
                     !program_account->vt->is_executable( program_account ) ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.3.1/svm/src/account_loader.rs#L677-L681 */
    fd_pubkey_t const * owner_id = program_account->vt->get_owner( program_account );
    if( FD_UNLIKELY( memcmp( owner_id->key, fd_solana_native_loader_id.key, sizeof(fd_pubkey_t) ) &&
                     !fd_executor_pubkey_is_bpf_loader( owner_id ) ) ) {
      return FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION;
    }
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/**** PUBLIC FUNCTIONS ****/

int
fd_txn_loader_load_transaction_accounts( fd_exec_txn_ctx_t * txn_ctx ) {
  if( FD_FEATURE_ACTIVE_BANK( txn_ctx->bank, formalize_loaded_transaction_data_size ) ) {
    return load_transaction_accounts_simd_186( txn_ctx );
  } else {
    return load_transaction_accounts_old( txn_ctx );
  }
}
