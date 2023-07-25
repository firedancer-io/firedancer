#include "fd_stake_program.h"
#include "../runtime/program/fd_vote_program.h"
#include "../../util/bits/fd_sat.h"
#include "../runtime/sysvar/fd_sysvar.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L441 */

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/mod.rs#L12 */
#define ACCOUNT_STORAGE_OVERHEAD ( 128 )
#define MINIMUM_STAKE_DELEGATION ( 1 )
#define MINIMUM_DELEGATION_SOL ( 1 )
#define LAMPORTS_PER_SOL ( 1000000000 )
#define MERGE_KIND_INACTIVE ( 0 )
#define MERGE_KIND_ACTIVE_EPOCH ( 1 )
#define MERGE_KIND_FULLY_ACTIVE ( 2 )
#define MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION ( 5 )

static fd_acc_lamports_t get_minimum_delegation( fd_global_ctx_t* global ) {
  if ( FD_FEATURE_ACTIVE(global, stake_raise_minimum_delegation_to_1_sol )) {
    return MINIMUM_DELEGATION_SOL * LAMPORTS_PER_SOL;
  } else {
    return MINIMUM_STAKE_DELEGATION;
  }
}

int authorized_check_signers(instruction_ctx_t* ctx, uchar * instr_acc_idxs, fd_pubkey_t * txn_accs, fd_pubkey_t * staker) {
  // meta.authorized.check(signers, StakeAuthorize::Staker)?;
  for ( ulong i = 0; i < ctx->instr->acct_cnt; i++ ) {
    if ( instr_acc_idxs[i] < ctx->txn_ctx->txn_descriptor->signature_cnt ) {
      fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
      if ( memcmp( signer, staker, sizeof(fd_pubkey_t) ) == 0) {
        return FD_EXECUTOR_INSTR_SUCCESS;
      }
    }
  }
  return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
}

static int
acceptable_reference_epoch_credits( fd_vote_epoch_credits_t * epoch_credits, ulong current_epoch ) {
  ulong len = deq_fd_vote_epoch_credits_t_cnt(epoch_credits);
  if (len < MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION) {
    return 0;
  }
  for (ulong idx = len - 1; idx >= len - MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION; -- idx) {
    FD_LOG_NOTICE(("idx=%lu peek=%lu current_epoch=%lu", idx, deq_fd_vote_epoch_credits_t_peek_index(epoch_credits, idx)->epoch, current_epoch));
    if (deq_fd_vote_epoch_credits_t_peek_index(epoch_credits, idx)->epoch != current_epoch) {
      return 0;
    }
    current_epoch = fd_ulong_sat_sub(current_epoch, 1);
  }
  return 1;
}

static int
deactivate(fd_stake_state_t* stake_state, fd_pubkey_t* stake_acc, instruction_ctx_t* ctx, ulong epoch) {
  if (stake_state->inner.stake.stake.delegation.deactivation_epoch != ULONG_MAX) {
    ctx->txn_ctx->custom_err = 2; // Err(StakeError::AlreadyDeactivated)
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  stake_state->inner.stake.stake.delegation.deactivation_epoch = epoch;
  int result = write_stake_state(ctx->global, stake_acc, stake_state, 0);
  if ( FD_UNLIKELY(result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return result;
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
validate_delegated_amount( instruction_ctx_t* ctx, fd_acc_lamports_t account_lamports, fd_acc_lamports_t rent_exempt_reserve, fd_acc_lamports_t * stake_amount) {
  *stake_amount = fd_ulong_sat_sub( account_lamports, rent_exempt_reserve);
  if ((ctx->global->features.stake_allow_zero_undelegated_amount || ctx->global->features.stake_raise_minimum_delegation_to_1_sol) && (*stake_amount < get_minimum_delegation(ctx->global))) {
    ctx->txn_ctx->custom_err = 12; // Err(StakeError::InsufficientDelegation.into());
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
eligible_for_deactivate_delinquent( fd_vote_epoch_credits_t * epoch_credits, ulong current_epoch ) {
  fd_vote_epoch_credits_t * last = deq_fd_vote_epoch_credits_t_peek_tail(epoch_credits);
  if (last == NULL) {
    return 1;
  }
  if (current_epoch < MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION) {
    return 0;
  }
  return last->epoch <= (current_epoch - MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION);
}

void write_stake_config( fd_global_ctx_t* global, fd_stake_config_t* stake_config ) {
  ulong          sz = fd_stake_config_size( stake_config );
  unsigned char *enc = fd_alloca_check( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx3;
  ctx3.data = enc;
  ctx3.dataend = enc + sz;
  if ( fd_stake_config_encode( stake_config, &ctx3 ) )
    FD_LOG_ERR(("fd_stake_config_encode failed"));

  fd_solana_account_t account = {
    .lamports = 960480,
    .rent_epoch = 0,
    .data_len = (ulong) ((uchar *) ctx3.data - (uchar *) enc),
    .data = enc,
    .executable = (uchar) 0
  };
  fd_memcpy( account.owner.key, global->solana_config_program, sizeof(fd_pubkey_t) );
  fd_acc_mgr_write_structured_account( global->acc_mgr, global->funk_txn, global->bank.slot, (fd_pubkey_t *) global->solana_stake_program_config, &account );
}

int read_stake_config( fd_global_ctx_t* global, fd_stake_config_t* result ) {
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->solana_stake_program_config, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return read_result;
  }

  unsigned char *raw_acc_data = fd_alloca_check( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->solana_stake_program_config, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return read_result;
  }

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data;
  ctx.dataend = raw_acc_data + metadata.dlen;
  ctx.valloc  = global->valloc;
  if ( fd_stake_config_decode( result, &ctx ) ) {
    FD_LOG_WARNING(("fd_stake_config_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return FD_ACC_MGR_SUCCESS;
}

void fd_stake_program_config_init( fd_global_ctx_t* global ) {
  /* Defaults taken from
     https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/config.rs#L8-L11 */
  fd_stake_config_t stake_config = {
    .warmup_cooldown_rate = 0.25,
    .slash_penalty = 12,
  };
  write_stake_config( global, &stake_config );
}

int read_stake_state( fd_global_ctx_t* global, fd_pubkey_t* stake_acc, fd_stake_state_t* result ) {
  fd_memset( result, 0, STAKE_ACCOUNT_SIZE );
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, stake_acc, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return read_result;
  }

  unsigned char *raw_acc_data = fd_alloca_check( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, stake_acc, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return read_result;
  }

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data;
  ctx.dataend = raw_acc_data + metadata.dlen;
  ctx.valloc  = global->valloc;
  if ( fd_stake_state_decode( result, &ctx ) ) {
    FD_LOG_WARNING(("fd_stake_state_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return FD_ACC_MGR_SUCCESS;
}


static int validate_split_amount(
    instruction_ctx_t ctx,
    ushort source_account_index,
    ushort destination_account_index,
    ushort source_stake_is_some,
    fd_acc_lamports_t lamports,
    fd_acc_lamports_t additional_lamports,
    fd_acc_lamports_t * source_remaining_balance,
    fd_acc_lamports_t * destination_rent_exempt_reserve) {
    /// Ensure the split amount is valid.  This checks the source and destination accounts meet the
    /// minimum balance requirements, which is the rent exempt reserve plus the minimum stake
    /// delegation, and that the source account has enough lamports for the request split amount.  If
    /// not, return an error.
    // Split amount has to be something
    if (lamports == 0) {
      FD_LOG_WARNING(( "Split amount has to be something"));
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);

    // getting all source data
    fd_pubkey_t* source_acc         = &txn_accs[instr_acc_idxs[source_account_index]];
    fd_account_meta_t metadata_source;
    fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, source_acc, &metadata_source );
    fd_acc_lamports_t source_lamports = metadata_source.info.lamports;

    // Obviously cannot split more than what the source account has
    if (lamports > source_lamports) {
      FD_LOG_WARNING(( "Obviously cannot split more than what the source account has"));
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    ulong source_data_len = metadata_source.dlen;

    // getting all dest data
    fd_pubkey_t* dest_acc = &txn_accs[instr_acc_idxs[destination_account_index]];
    fd_account_meta_t metadata_dest;
    fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, dest_acc, &metadata_dest );

    fd_acc_lamports_t destination_lamports = metadata_dest.info.lamports;
    ulong destination_data_len = metadata_dest.dlen;

    // Verify that the source account still has enough lamports left after splitting:
    // EITHER at least the minimum balance, OR zero (in this case the source
    // account is transferring all lamports to new destination account, and the source
    // account will be closed)

    fd_stake_state_t source_state;
    read_stake_state( ctx.global, source_acc, &source_state );

    fd_acc_lamports_t source_minimum_balance = source_state.inner.initialized.rent_exempt_reserve + additional_lamports;
    *source_remaining_balance = source_lamports - lamports;
    if (*source_remaining_balance == 0) {
      // full amount is a withdrawal
      // nothing to do here
    } else if (*source_remaining_balance < source_minimum_balance) {
      FD_LOG_WARNING(( "remaining balance is too low to do the split" ));
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    } else {
      // all clear! nothing to do here
    }

    // Verify the destination account meets the minimum balance requirements
    // This must handle:
    // 1. The destination account having a different rent exempt reserve due to data size changes
    // 2. The destination account being prefunded, which would lower the minimum split amount
    // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_state.rs#L1277-L1289
    // Note stake_split_uses_rent_sysvar is inactive this time
    if (FD_FEATURE_ACTIVE(ctx.global, stake_split_uses_rent_sysvar)) {
      *destination_rent_exempt_reserve = fd_rent_exempt_minimum_balance(ctx.global, destination_data_len);
    } else {
      *destination_rent_exempt_reserve = source_state.inner.initialized.rent_exempt_reserve / fd_ulong_sat_add(source_data_len, ACCOUNT_STORAGE_OVERHEAD) * fd_ulong_sat_add(destination_data_len, ACCOUNT_STORAGE_OVERHEAD);
    }
    fd_acc_lamports_t dest_minimum_balance = fd_ulong_sat_add(*destination_rent_exempt_reserve, additional_lamports);

    if (fd_ulong_sat_add(lamports, destination_lamports) < dest_minimum_balance) {
      // FD_LOG_WARNING(( "lamports are less than dest_balance_deficit\n lamports=%lu,\n dest_balance_deficit=%lu destination_rent_exempt_reserve=%lu, \n additional_lamports=%lu \n destination_lamports=%lu", lamports, dest_balance_deficit, *destination_rent_exempt_reserve, additional_lamports, destination_lamports ));
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    if (
      !FD_FEATURE_ACTIVE(ctx.global, clean_up_delegation_errors) &&
      source_stake_is_some &&
      lamports < additional_lamports) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    // source_remaining_balance
    // destination_rent_exempt_reserve

    return FD_EXECUTOR_INSTR_SUCCESS;
}


static int merge_delegation_stake_and_credits_observed( fd_global_ctx_t* global, fd_stake_state_t* stake_state, fd_acc_lamports_t absorbed_lamports, fd_acc_lamports_t absorbed_credits_observed) {
  if (FD_FEATURE_ACTIVE(global, stake_merge_with_unmatched_credits_observed)) {
      // stake_state.inner.stake.stake.credits_observed =
    if (stake_state->inner.stake.stake.credits_observed == absorbed_credits_observed) {
      // Some(stake.credits_observed)
    } else {
      __uint128_t total_stake = fd_uint128_sat_add(stake_state->inner.stake.stake.delegation.stake, absorbed_lamports);
      __uint128_t total_weighted_credits = fd_uint128_sat_add(total_stake, fd_uint128_sat_mul( stake_state->inner.stake.stake.credits_observed, stake_state->inner.stake.stake.delegation.stake));
      total_weighted_credits = fd_uint128_sat_add(total_weighted_credits, fd_uint128_sat_mul(absorbed_credits_observed, absorbed_lamports));
      __uint128_t result_credits = fd_uint128_sat_sub(total_weighted_credits, 1) / total_stake;
      if (result_credits > ULONG_MAX) {
        return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
      }
      stake_state->inner.stake.stake.credits_observed = (ulong) result_credits;
    }
  }
  stake_state->inner.stake.stake.delegation.stake = fd_ulong_sat_add( stake_state->inner.stake.stake.delegation.stake, absorbed_lamports);
  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int get_if_mergeable( instruction_ctx_t* ctx, fd_stake_state_t* stake_state, fd_sol_sysvar_clock_t clock, fd_stake_history_t history, fd_merge_kind_t* merge_kind) {
    if ( fd_stake_state_is_stake( stake_state ) ) {
      fd_stake_history_entry_t entry = stake_activating_and_deactivating( &stake_state->inner.stake.stake.delegation, clock.epoch, &history);
      FD_LOG_NOTICE(( "effective = %lu, activating = %lu, deactivating = %lu", entry.effective, entry.activating, entry.deactivating ));
      if (entry.effective == 0 && entry.activating == 0 && entry.deactivating == 0) {
        // Ok(Self::Inactive(*meta, stake_lamports)),
        merge_kind->discriminant = MERGE_KIND_INACTIVE;
        merge_kind->is_active_stake = 0;
      } else if (entry.effective == 0) {
        // Ok(Self::ActivationEpoch(*meta, *stake)),
        merge_kind->discriminant = MERGE_KIND_ACTIVE_EPOCH;
        merge_kind->is_active_stake = 1;
      } else if (entry.activating == 0 && entry.deactivating == 0) {
        // Ok(Self::FullyActive(*meta, *stake)),
        merge_kind->discriminant = MERGE_KIND_FULLY_ACTIVE;
        merge_kind->is_active_stake = 1;
      } else {
        ctx->txn_ctx->custom_err = 5;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // StakeError::MergeTransientStake;
      }
  } else if ( fd_stake_state_is_initialized( stake_state ) ) {
    // Ok(Self::Inactive(*meta, stake_lamports))
    merge_kind->discriminant = MERGE_KIND_INACTIVE;
    merge_kind->is_active_stake = 0;
  } else {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int authorize(instruction_ctx_t ctx,
              uchar * instr_acc_idxs,
              fd_pubkey_t * txn_accs,
              fd_stake_authorize_t * stake_authorize,
              fd_pubkey_t * new_authority,
              fd_stake_state_t stake_state,
              fd_pubkey_t * stake_acc,
              fd_sol_sysvar_clock_t clock,
              fd_pubkey_t * custodian,
              bool require_custodian_for_locked_stake_authorize,
              fd_pubkey_t * signers) {

  fd_pubkey_t * staker = fd_stake_state_is_stake( &stake_state ) ? &stake_state.inner.stake.meta.authorized.staker : &stake_state.inner.initialized.authorized.staker;
  fd_pubkey_t * withdrawer = fd_stake_state_is_stake( &stake_state ) ? &stake_state.inner.stake.meta.authorized.withdrawer : &stake_state.inner.initialized.authorized.withdrawer;
  if ( fd_stake_authorize_is_staker( stake_authorize ) ) {
      uchar authorized_staker_signed = 0;
      uchar authorized_withdrawer_signed = 0;

      if ( signers ) {
        if ( !memcmp( signers, staker, sizeof(fd_pubkey_t) ) ) {
          authorized_staker_signed = 1;
        }
        if ( !memcmp( signers, withdrawer, sizeof(fd_pubkey_t) ) ) {
          authorized_withdrawer_signed = 1;
        }
      } else {
        for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
          if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
            fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
            if ( !memcmp( signer, staker, sizeof(fd_pubkey_t) ) ) {
              authorized_staker_signed = 1;
            }
            if ( !memcmp( signer, withdrawer, sizeof(fd_pubkey_t) ) ) {
              authorized_withdrawer_signed = 1;
            }
          }
        }
      }

      if (!authorized_staker_signed && !authorized_withdrawer_signed) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      memcpy(staker, new_authority, sizeof(fd_pubkey_t));
    } else {
      if ( require_custodian_for_locked_stake_authorize ) {
        fd_stake_lockup_t * lockup = fd_stake_state_is_stake( &stake_state ) ? &stake_state.inner.stake.meta.lockup : &stake_state.inner.initialized.lockup;
        if ( lockup->unix_timestamp > clock.unix_timestamp || lockup->epoch > clock.epoch ) {
          if ( custodian ) {
            uchar custodian_signed = 0;

            if ( signers ) {
              if ( !memcmp( signers, custodian, sizeof(fd_pubkey_t) ) ) {
                custodian_signed = 1;
              }
            } else {
              for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
                if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
                  fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
                  if ( !memcmp( signer, custodian, sizeof(fd_pubkey_t) ) ) {
                    custodian_signed = 1;
                  }
                }
              }
            }

            if ( !custodian_signed) {
              return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
            }

            if ( memcmp(&lockup->custodian, custodian, sizeof(fd_pubkey_t)) != 0) {
              // return Err(StakeError::CustodianSignatureMissing.into());
              ctx.txn_ctx->custom_err = 8;
              return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
            }

            if ( lockup->unix_timestamp > clock.unix_timestamp || lockup->epoch > clock.epoch ) {
              // return Err(StakeError::LockupInForce.into());
              ctx.txn_ctx->custom_err = 1;
              return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
            }
          } else {
            // return Err(StakeError::CustodianMissing.into());
            ctx.txn_ctx->custom_err = 7;
            return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          }
        }
      }
      uchar authorized_withdrawer_signed = 0;

      if ( signers ) {
        if ( !memcmp( signers, withdrawer, sizeof(fd_pubkey_t) ) ) {
          authorized_withdrawer_signed = 1;
        }
      } else {
        for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
          if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
            fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
            if ( !memcmp( signer, withdrawer, sizeof(fd_pubkey_t) ) ) {
              authorized_withdrawer_signed = 1;
            }
          }
        }
      }

      if ( !authorized_withdrawer_signed) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
      memcpy(withdrawer, new_authority, sizeof(fd_pubkey_t));
    }

    int write_result = write_stake_state(ctx.global, stake_acc, &stake_state, 0);
    if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to write stake account" ));
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }
    return 0;
}


int fd_executor_stake_program_execute_instruction(
  FD_FN_UNUSED instruction_ctx_t ctx
) {
  /* Deserialize the Stake instruction */
  uchar *data            = (uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->data_off;

  fd_stake_instruction_t instruction;
  fd_stake_instruction_new( &instruction );
  fd_bincode_decode_ctx_t ctx2;
  ctx2.data = data;
  ctx2.dataend = &data[ctx.instr->data_sz];
  ctx2.valloc  = ctx.global->valloc;
  if ( fd_stake_instruction_decode( &instruction, &ctx2 ) ) {
    FD_LOG_WARNING(("fd_stake_instruction_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);
  FD_LOG_NOTICE(("instruction discriminant=%d", instruction.discriminant));
  /* TODO: check that the instruction account 0 owner is the stake program ID
     https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L37 */
  if ( fd_stake_instruction_is_initialize( &instruction ) ) {
    /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L43 */

    FD_LOG_INFO(( "executing StakeInstruction::Initialize instruction" ));

    /* Check that Instruction Account 1 is the Rent account
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L44-L47 */
    if ( memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_rent, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* Check that the stake account is the correct size
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L441-L443 */
    fd_pubkey_t * stake_acc = &txn_accs[instr_acc_idxs[0]];
    fd_account_meta_t metadata;
    int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return read_result;
    }
    if ( metadata.dlen != STAKE_ACCOUNT_SIZE ) {
      FD_LOG_WARNING(( "Stake account size incorrect. expected %d got %lu", STAKE_ACCOUNT_SIZE, metadata.dlen ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* Read the current data in the Stake account */
    uchar *stake_acc_data = fd_valloc_malloc( ctx.global->valloc, 8UL, metadata.dlen);
    read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, (uchar*)stake_acc_data, sizeof(fd_account_meta_t), metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
    }

    fd_stake_state_t stake_state;
    fd_stake_state_new( &stake_state );
    fd_bincode_decode_ctx_t ctx3;
    ctx3.data = stake_acc_data;
    ctx3.dataend = &stake_acc_data[metadata.dlen];
    ctx3.valloc  = ctx.global->valloc;
    if ( fd_stake_state_decode( &stake_state, &ctx3 ) ) {
      FD_LOG_WARNING(("fd_stake_state_decode failed"));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* Check that the Stake account is Uninitialized */
    if ( !fd_stake_state_is_uninitialized( &stake_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* Check that the stake account has enough balance
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L445-L456 */
    fd_acc_lamports_t lamports;
    read_result = fd_acc_mgr_get_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &lamports );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read account data" ));
      return read_result;
    }
    ulong minimum_rent_exempt_balance = fd_rent_exempt_minimum_balance( ctx.global, metadata.dlen );
    ulong minimum_balance;
    if ( FD_FEATURE_ACTIVE(ctx.global, stake_allow_zero_undelegated_amount) ) {
      minimum_balance = minimum_rent_exempt_balance;
    } else {
      minimum_balance = get_minimum_delegation(ctx.global) + minimum_rent_exempt_balance;
    }

    if ( lamports < minimum_balance ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* Initialize the Stake Account
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L449-L453 */
    stake_state.discriminant = fd_stake_state_enum_initialized;
    fd_stake_state_meta_t* stake_state_meta = &stake_state.inner.initialized;
    stake_state_meta->rent_exempt_reserve = minimum_rent_exempt_balance;
    fd_stake_instruction_initialize_t* initialize_instruction = &instruction.inner.initialize;
    fd_memcpy( &stake_state_meta->authorized, &initialize_instruction->authorized, FD_STAKE_AUTHORIZED_FOOTPRINT );
    fd_memcpy( &stake_state_meta->lockup, &initialize_instruction->lockup, sizeof(fd_stake_lockup_t) );

    /* Write the initialized Stake account to the database */
    int result = write_stake_state( ctx.global, stake_acc, &stake_state, 0 );
    if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write stake account state: %d", result ));
      return result;
    }
  } // end of fd_stake_instruction_is_initialize
  else if ( fd_stake_instruction_is_authorize( &instruction ) ) { //authorize, discriminant 1
    // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L50
    fd_pubkey_t * stake_acc = &txn_accs[instr_acc_idxs[0]];

    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc, &stake_state );

    fd_stake_authorize_t * stake_authorize = &instruction.inner.authorize.stake_authorize;
    fd_pubkey_t * new_authority = &instruction.inner.authorize.pubkey;
    fd_sol_sysvar_clock_t clock;
    bool require_custodian_for_locked_stake_authorize = FD_FEATURE_ACTIVE(ctx.global, require_custodian_for_locked_stake_authorize);
    fd_pubkey_t * custodian = NULL;

    if ( require_custodian_for_locked_stake_authorize ) {
      if ( memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      fd_sysvar_clock_read( ctx.global, &clock );
      if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 3) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      if ( ctx.txn_ctx->txn_descriptor->acct_addr_cnt > 3 ) {
        custodian = &txn_accs[instr_acc_idxs[3]];
      }
    }

    if ( !fd_stake_state_is_stake( &stake_state ) && !fd_stake_state_is_initialized( &stake_state) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }
    int res = authorize(ctx, instr_acc_idxs, txn_accs, stake_authorize, new_authority, stake_state, stake_acc, clock, custodian, require_custodian_for_locked_stake_authorize, NULL);
    if ( res != 0 )
      return res;

  } // end of fd_stake_instruction_is_authorize, discriminant 1
  else if ( fd_stake_instruction_is_authorize_with_seed( &instruction ) ) {
    fd_pubkey_t * stake_acc = &txn_accs[instr_acc_idxs[0]];

    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc, &stake_state );

    fd_stake_authorize_t * stake_authorize = &instruction.inner.authorize_with_seed.stake_authorize;
    fd_pubkey_t * new_authority = &instruction.inner.authorize_with_seed.new_authorized_pubkey;
    char * authority_seed = instruction.inner.authorize_with_seed.authority_seed;
    fd_pubkey_t authority_owner = instruction.inner.authorize_with_seed.authority_owner;

    fd_sol_sysvar_clock_t clock;
    bool require_custodian_for_locked_stake_authorize = FD_FEATURE_ACTIVE(ctx.global, require_custodian_for_locked_stake_authorize);
    fd_pubkey_t * custodian = NULL;

    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 2) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    if ( require_custodian_for_locked_stake_authorize ) {
      if ( memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      fd_sysvar_clock_read( ctx.global, &clock );

      if ( ctx.txn_ctx->txn_descriptor->acct_addr_cnt > 3 ) {
        custodian = &txn_accs[instr_acc_idxs[3]];
      }
    }

    if ( !fd_stake_state_is_stake( &stake_state ) && !fd_stake_state_is_initialized( &stake_state) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_pubkey_t signer;
    uchar single_signer = 0;
    if ( instr_acc_idxs[1] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
      fd_pubkey_t * base_pubkey = &txn_accs[instr_acc_idxs[1]];
      fd_pubkey_create_with_seed(base_pubkey, authority_seed, &authority_owner, &signer);
      single_signer = 1;
    }
    fd_pubkey_t * signers = single_signer ? &signer : NULL;
    int res = authorize(ctx, instr_acc_idxs, txn_accs, stake_authorize, new_authority, stake_state, stake_acc, clock, custodian, require_custodian_for_locked_stake_authorize, signers);
    if ( res != 0 )
      return res;

  } // end of fd_stake_instruction_is_authorize_with_seed
  else if ( fd_stake_instruction_is_delegate_stake( &instruction ) ) {
    /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L126 */

    /* Check that the instruction accounts are correct
      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L127-L142 */
    fd_pubkey_t* stake_acc         = &txn_accs[instr_acc_idxs[0]];

    /* Check that the Instruction Account 2 is the Clock Sysvar account */
    if ( memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Check that the Instruction Account 3 is the Stake History Sysvar account */
    if ( memcmp( &txn_accs[instr_acc_idxs[3]], ctx.global->sysvar_stake_history, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_stake_history_t history;
    fd_sysvar_stake_history_read( ctx.global, &history);

    /* Check that Instruction Account 4 is the Stake Config Program account */
    if ( memcmp( &txn_accs[instr_acc_idxs[4]], ctx.global->solana_stake_program_config, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_stake_config_t stake_config;
    int result = read_stake_config( ctx.global, &stake_config );
    if ( FD_UNLIKELY(result != FD_EXECUTOR_INSTR_SUCCESS) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* Check that Instruction Account 1 is owned by the vote program
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L540 */
    fd_pubkey_t* vote_acc = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t vote_acc_owner;
    fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, &vote_acc_owner );
    if ( memcmp( &vote_acc_owner, ctx.global->solana_vote_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc, &stake_state );

    /* Require the Stake State to be either Initialized or Stake
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L573 */
    if ( !( fd_stake_state_is_initialized( &stake_state ) || fd_stake_state_is_stake( &stake_state ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_stake_state_meta_t* meta = NULL;
    if ( fd_stake_state_is_initialized( &stake_state ) ) {
      meta = &stake_state.inner.initialized;
    } else if ( fd_stake_state_is_stake( &stake_state ) ) {
      meta = &stake_state.inner.stake.meta;
    }

    /* Check that the authorized staker for this Stake account has signed the transaction
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L546 */

    // meta.authorized.check(signers, StakeAuthorize::Staker)?;
    result = authorized_check_signers(&ctx, instr_acc_idxs, txn_accs, &stake_state.inner.stake.meta.authorized.staker);
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }

    /* Ensire that we leave enough balance in the account such that the Stake account is rent exempt
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L837 */
    ulong stake_amount = 0;
    fd_acc_lamports_t lamports;
    int read_result = fd_acc_mgr_get_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &lamports );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read stake account data" ));
      return read_result;
    }
    if ( lamports > meta->rent_exempt_reserve ) {
      stake_amount = lamports - meta->rent_exempt_reserve;
    }

    if ((ctx.global->features.stake_allow_zero_undelegated_amount || ctx.global->features.stake_raise_minimum_delegation_to_1_sol) && stake_amount < get_minimum_delegation(ctx.global)) {
      ctx.txn_ctx->custom_err = 12;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    if ( fd_stake_state_is_initialized( &stake_state ) ) {
      /* Create the new stake state
         https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L549 */
      stake_state.discriminant = fd_stake_state_enum_stake;
      fd_stake_state_stake_t* stake_state_stake = &stake_state.inner.stake;
      fd_memcpy( &stake_state_stake->meta, meta, FD_STAKE_STATE_META_FOOTPRINT );
      stake_state_stake->stake.delegation.activation_epoch = clock.epoch;
      stake_state_stake->stake.delegation.deactivation_epoch = ULONG_MAX;
      stake_state_stake->stake.delegation.stake = stake_amount;
      fd_memcpy( &stake_state_stake->stake.delegation.voter_pubkey, vote_acc, sizeof(fd_pubkey_t) );
      stake_state_stake->stake.delegation.warmup_cooldown_rate = stake_config.warmup_cooldown_rate;

      ulong credits = 0;
      int acc_res = fd_vote_acc_credits( ctx.global, vote_acc, &credits );
      if( FD_UNLIKELY( !acc_res ) )
        return acc_res;  /* FIXME leak */
      stake_state_stake->stake.credits_observed = credits;
    } else {
      /* redelegate when fd_stake_state_is_stake( &stake_state )
        https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L562
      */
      if (stake_activating_and_deactivating( &stake_state.inner.stake.stake.delegation, clock.epoch, &history).effective != 0) {
        ushort stake_lamports_ok = (ctx.global->features.stake_redelegate_instruction) ? lamports >= stake_state.inner.stake.stake.delegation.stake : 1;
        if (stake_lamports_ok && clock.epoch == stake_state.inner.stake.stake.delegation.deactivation_epoch && memcmp( &stake_state.inner.stake.stake.delegation.voter_pubkey, vote_acc, sizeof(fd_pubkey_t) ) == 0) {
          stake_state.inner.stake.stake.delegation.deactivation_epoch = ULONG_MAX;
        } else {
          ctx.txn_ctx->custom_err = 3;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        }
      }
      
      stake_state.discriminant = fd_stake_state_enum_stake;
      fd_stake_state_stake_t* stake_state_stake = &stake_state.inner.stake;
      fd_memcpy( &stake_state_stake->meta, meta, FD_STAKE_STATE_META_FOOTPRINT );
      stake_state_stake->stake.delegation.activation_epoch = clock.epoch;
      stake_state_stake->stake.delegation.stake = stake_amount;
      fd_memcpy( &stake_state_stake->stake.delegation.voter_pubkey, vote_acc, sizeof(fd_pubkey_t) );
      stake_state_stake->stake.delegation.warmup_cooldown_rate = stake_config.warmup_cooldown_rate;

      ulong credits = 0;
      int acc_res = fd_vote_acc_credits( ctx.global, vote_acc, &credits );
      if( FD_UNLIKELY( !acc_res ) )
        return acc_res;  /* FIXME leak */
      stake_state_stake->stake.credits_observed = credits;
    }

    /* Write the stake state back to the database */
    result = write_stake_state( ctx.global, stake_acc, &stake_state, 0 );
    if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write stake account state: %d", result ));
      return result;
    }
  } // end of fd_stake_instruction_is_delegate_stake
  else if ( fd_stake_instruction_is_split( &instruction )) { // discriminant 3
    FD_LOG_NOTICE(( "stake_split_uses_rent_sysvar=%ld", ctx.global->features.stake_split_uses_rent_sysvar ));
    FD_LOG_NOTICE(( "stake_allow_zero_undelegated_amount=%ld", ctx.global->features.stake_allow_zero_undelegated_amount ));
    FD_LOG_NOTICE(( "clean_up_delegation_errors=%ld", ctx.global->features.clean_up_delegation_errors));
    FD_LOG_NOTICE(( "stake_raise_minimum_delegation_to_1_sol=%ld", ctx.global->features.stake_raise_minimum_delegation_to_1_sol));

  // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_instruction.rs#L192
    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 2) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    fd_pubkey_t* stake_acc = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t* split_acc = &txn_accs[instr_acc_idxs[1]];


    // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_state.rs#L666

    fd_pubkey_t split_acc_owner;
    fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, split_acc, &split_acc_owner );
    if ( memcmp( &split_acc_owner, ctx.global->solana_stake_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    fd_account_meta_t split_metadata;
    int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, split_acc, &split_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read split account metadata" ));
      return read_result;
    }

    if ( split_metadata.dlen != STAKE_ACCOUNT_SIZE ) {
      FD_LOG_WARNING(( "Split account size incorrect. expected %d got %lu", STAKE_ACCOUNT_SIZE, split_metadata.dlen ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_stake_state_t split_state;
    read_stake_state( ctx.global, split_acc, &split_state );
    if ( !fd_stake_state_is_uninitialized( &split_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_account_meta_t stake_metadata;
    read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &stake_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read stake account metadata" ));
      return read_result;
    }

    fd_acc_lamports_t split_lamports_balance = split_metadata.info.lamports;
    fd_acc_lamports_t lamports = instruction.inner.split; // split amount

    if ( lamports > stake_metadata.info.lamports ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc, &stake_state );

    if ( fd_stake_state_is_stake( &stake_state ) ) {
      // validate split amount, etc
      // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_state.rs#L698-L771

      uchar authorized_staker_signed = 0;

      for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
        if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
          fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
          if ( !memcmp( signer, stake_acc, sizeof(fd_pubkey_t) ) ) {
            authorized_staker_signed = 1;
            break;
          }
        }
      }

      if ( !authorized_staker_signed ) {
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }


      fd_acc_lamports_t minimum_delegation = FD_FEATURE_ACTIVE(ctx.global, stake_raise_minimum_delegation_to_1_sol) ? MINIMUM_DELEGATION_SOL * LAMPORTS_PER_SOL: MINIMUM_STAKE_DELEGATION;
      fd_acc_lamports_t source_remaining_balance, destination_rent_exempt_reserve;
      // todo: implement source_stake = Some(&stake)
      int validate_result = validate_split_amount(ctx, 0, 1, 1, lamports, minimum_delegation, &source_remaining_balance, &destination_rent_exempt_reserve);
      if (validate_result != FD_EXECUTOR_INSTR_SUCCESS) {
        return validate_result;
      }
      fd_acc_lamports_t remaining_stake_delta, split_stake_amount;
      if (source_remaining_balance == 0) {
        remaining_stake_delta = fd_ulong_sat_sub(lamports, stake_state.inner.initialized.rent_exempt_reserve);
        split_stake_amount = remaining_stake_delta;
      } else {
        if ( FD_FEATURE_ACTIVE(ctx.global, clean_up_delegation_errors) && stake_state.inner.stake.stake.delegation.stake < fd_ulong_sat_add(minimum_delegation, lamports)) {
          ctx.txn_ctx->custom_err = 12;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // (StakeError::InsufficientDelegation.into());
        }
        remaining_stake_delta = lamports;
        split_stake_amount = fd_ulong_sat_sub(lamports, fd_ulong_sat_sub(destination_rent_exempt_reserve, split_lamports_balance));
      }
      if (FD_FEATURE_ACTIVE(ctx.global, clean_up_delegation_errors) && split_stake_amount < minimum_delegation) {
        ctx.txn_ctx->custom_err = 12;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // (StakeError::InsufficientDelegation.into());
      }

      if (remaining_stake_delta > stake_state.inner.stake.stake.delegation.stake) {
        ctx.txn_ctx->custom_err = 4;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // Err(StakeError::InsufficientStake)
      }

      stake_state.inner.stake.stake.delegation.stake -= remaining_stake_delta;

      memcpy(&split_state, &stake_state, STAKE_ACCOUNT_SIZE);
      split_state.discriminant = fd_stake_state_enum_stake;
      split_state.inner.stake.stake.delegation.stake = split_stake_amount;
      split_state.inner.stake.meta.rent_exempt_reserve = destination_rent_exempt_reserve;

      /* Write the split and stake account to the database */
      write_stake_state( ctx.global, split_acc, &split_state, 1 );
      write_stake_state( ctx.global, stake_acc, &stake_state, 0 );

    } else if ( fd_stake_state_is_initialized( &stake_state ) ) {

      // meta.authorized.check(signers, StakeAuthorize::Staker)?;
      uchar authorized_staker_signed = 0;
      for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
        if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
          fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
          if ( !memcmp( signer, stake_acc, sizeof(fd_pubkey_t) ) ) {
            authorized_staker_signed = 1;
            break;
          }
        }
      }

      if ( !authorized_staker_signed ) {
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      // ./target/debug/solana feature status sTKz343FM8mqtyGvYWvbLpTThw3ixRM4Xk8QvZ985mw
      fd_acc_lamports_t additional_required_lamports = FD_FEATURE_ACTIVE(ctx.global, stake_allow_zero_undelegated_amount) ? 0 : ( FD_FEATURE_ACTIVE(ctx.global, stake_raise_minimum_delegation_to_1_sol) ? MINIMUM_DELEGATION_SOL * LAMPORTS_PER_SOL : MINIMUM_STAKE_DELEGATION);

      fd_acc_lamports_t source_remaining_balance, destination_rent_exempt_reserve;
      int validate_result = validate_split_amount(ctx, 0, 1, 0, lamports, additional_required_lamports, &source_remaining_balance, &destination_rent_exempt_reserve);
      if (validate_result != FD_EXECUTOR_INSTR_SUCCESS) {
        return validate_result;
      }

      memcpy(&split_state, &stake_state, STAKE_ACCOUNT_SIZE);
      split_state.discriminant = fd_stake_state_enum_initialized; // initialized
      split_state.inner.initialized.rent_exempt_reserve = destination_rent_exempt_reserve;

      /* Write the initialized split account to the database */
      int result = write_stake_state( ctx.global, split_acc, &split_state, 1 );
      if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to write split account state: %d", result ));
        return result;
      }

      } else if ( fd_stake_state_is_uninitialized( &stake_state ) ) {
      uint authorized_staker_signed = 0;
      for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
        if ( instr_acc_idxs[i] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
          fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
          if ( !memcmp( signer, stake_acc, sizeof(fd_pubkey_t) ) ) {
            authorized_staker_signed = 1;
            break;
          }
        }
      }

      if ( !authorized_staker_signed ) {
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    // Deinitialize state of stake acc (only if it has been initialized) upon zero balance
    if (lamports == stake_metadata.info.lamports && !fd_stake_state_is_uninitialized( &stake_state ) ) {
      stake_state.discriminant = fd_stake_state_enum_uninitialized; // de-initialize
      int result = write_stake_state( ctx.global, stake_acc, &stake_state, 0 );
      if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to write stake account state: %d", result ));
        return result;
      }
    }

    if (instr_acc_idxs[0] != instr_acc_idxs[1]) {
      // add to destination
      fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.slot, split_acc, split_metadata.info.lamports + lamports);
      // sub from source
      fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.slot, stake_acc, stake_metadata.info.lamports - lamports);
    }
  } // end of split, discriminant 3
  else if ( fd_stake_instruction_is_deactivate( &instruction )) { // discriminant 5

    /* Read the current State State from the Stake account */
    fd_pubkey_t* stake_acc         = &txn_accs[instr_acc_idxs[0]];
    fd_stake_state_t stake_state;
    int result = read_stake_state( ctx.global, stake_acc, &stake_state );
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }

    if (!fd_stake_state_is_stake( &stake_state )) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* Check that the Instruction Account 1 is the Clock Sysvar account */
    if ( memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    // meta.authorized.check(signers, StakeAuthorize::Staker)?;
    result = authorized_check_signers(&ctx, instr_acc_idxs, txn_accs, &stake_state.inner.stake.meta.authorized.staker);
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }

    //stake.deactivate(clock.epoch)?;
    if (stake_state.inner.stake.stake.delegation.deactivation_epoch != ULONG_MAX) {
      ctx.txn_ctx->custom_err = 2;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // Err(StakeError::AlreadyDeactivated)
    }

    stake_state.inner.stake.stake.delegation.deactivation_epoch = clock.epoch;

    //stake_account.set_state(&StakeState::Stake(meta, stake))
    result = write_stake_state( ctx.global, stake_acc, &stake_state, 0);
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }
  } // end of deactivate, discriminant 5
  else if ( fd_stake_instruction_is_set_lockup( &instruction )) { // set_lockup, discriminant 6
    int result;
    fd_pubkey_t* stake_acc = &txn_accs[instr_acc_idxs[0]];
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc, &stake_state );
    if ( (!fd_stake_state_is_initialized( &stake_state )) && (!fd_stake_state_is_stake( &stake_state )) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* read clock */
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    if (stake_state.inner.stake.meta.lockup.unix_timestamp > clock.unix_timestamp || stake_state.inner.stake.meta.lockup.epoch > clock.epoch) {
      result = authorized_check_signers(&ctx, instr_acc_idxs, txn_accs, &stake_state.inner.stake.meta.lockup.custodian);
      if (result != FD_EXECUTOR_INSTR_SUCCESS) {
        return result;
      }
    } else {
      result = authorized_check_signers(&ctx, instr_acc_idxs, txn_accs, &stake_state.inner.stake.meta.authorized.withdrawer);
      if (result != FD_EXECUTOR_INSTR_SUCCESS) {
        return result;
      }
    }
    fd_stake_state_walk(&stake_state, fd_printer_walker, "stake_state", 0);
    // fd_stake_instruction_initialize_t* initialize_instruction = &instruction.inner.initialize;
    // stake_state.inner.stake.meta.lockup.unix_timestamp = initialize_instruction->lockup.unix_timestamp;
    // stake_state.inner.stake.meta.lockup.epoch = initialize_instruction->lockup.epoch;
    // memcpy(&stake_state.inner.stake.meta.lockup.custodian, &initialize_instruction->lockup.custodian, sizeof(fd_pubkey_t));
    // FD_LOG_NOTICE(("ts=%lu epoch=%lu", *instruction.inner.set_lockup_checked.unix_timestamp,  *instruction.inner.set_lockup_checked.epoch));
    result = write_stake_state( ctx.global, stake_acc, &stake_state, 0);
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    } 
 
  } // end of set_lockup, discriminant 6
  else if ( fd_stake_instruction_is_merge( &instruction )) { // merge, discriminant 7
    // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_instruction.rs#L206

    /* Check that there are at least two instruction accounts */
    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 2) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    uchar * instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);


    /* Close the stake account-reference loophole */
    if (instr_acc_idxs[0] == instr_acc_idxs[1]) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* Check that the Instruction Account 2 is the Clock Sysvar account */
    if ( memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Check that the Instruction Account 3 is the Stake History Sysvar account */
    if ( memcmp( &txn_accs[instr_acc_idxs[3]], ctx.global->sysvar_stake_history, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_stake_history_t history;
    fd_sysvar_stake_history_read( ctx.global, &history);

    // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_state.rs#L830

    /* Get source account and check its owner */
    fd_pubkey_t* source_acc = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t source_acc_owner;
    fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, source_acc, &source_acc_owner );
    if ( memcmp( &source_acc_owner, ctx.global->solana_stake_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    fd_account_meta_t source_metadata;
    int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, source_acc, &source_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read split account metadata" ));
      return read_result;
    }
    /* Read the current State State from the Stake account */
    fd_stake_state_t source_state;
    read_stake_state( ctx.global, source_acc, &source_state );


    fd_acc_lamports_t source_lamports;
    read_result = fd_acc_mgr_get_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, source_acc, &source_lamports );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read source account lamports" ));
      return read_result;
    }

    /* Get stake account */
    fd_pubkey_t* stake_acc = &txn_accs[instr_acc_idxs[0]];
    fd_account_meta_t stake_metadata;
    read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &stake_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read split account metadata" ));
      return read_result;
    }
    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc, &stake_state );


    fd_acc_lamports_t stake_lamports;
    read_result = fd_acc_mgr_get_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &stake_lamports );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read stake (destination) account lamports" ));
      return read_result;
    }

    /* get if mergeable - Check if the destination stake acount is mergeable */
    // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_state.rs#L1347
    fd_merge_kind_t stake_merge_kind;
    int result = get_if_mergeable( &ctx, &stake_state, clock, history, &stake_merge_kind);
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }

    // meta.authorized.check(signers, StakeAuthorize::Staker)?;
    result = authorized_check_signers(&ctx, instr_acc_idxs, txn_accs, &stake_state.inner.stake.meta.authorized.staker);
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }

    /* Check if the source stake account is mergeable */
    fd_merge_kind_t source_merge_kind;
    result = get_if_mergeable( &ctx, &source_state, clock, history, &source_merge_kind);
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }
    /* Merging stake accounts */
    // metas_can_merge
    uint can_merge_lockups = memcmp(&source_state.inner.stake.meta.lockup, &stake_state.inner.stake.meta.lockup, sizeof(fd_stake_lockup_t)) == 0;
    uint can_merge_authorized = memcmp(&stake_state.inner.stake.meta.authorized, &source_state.inner.stake.meta.authorized, sizeof(fd_stake_lockup_t)) == 0;
    if (!can_merge_lockups || !can_merge_authorized) {
      FD_LOG_WARNING(("Unable to merge due to metadata mismatch"));
      ctx.txn_ctx->custom_err = 6;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // Err(StakeError::MergeMismatch.into())
    }

    if (source_merge_kind.is_active_stake && stake_merge_kind.is_active_stake && FD_FEATURE_ACTIVE(ctx.global, stake_merge_with_unmatched_credits_observed)) {
      // active_delegations_can_merge
      if (memcmp(&source_state.inner.stake.stake.delegation.voter_pubkey, &stake_state.inner.stake.stake.delegation.voter_pubkey, sizeof(fd_pubkey_t)) != 0) {
        FD_LOG_WARNING(( "Unable to merge due to voter mismatch" ));
        ctx.txn_ctx->custom_err = 6;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; //  Err(StakeError::MergeMismatch.into())
      }
      if ( fd_double_abs(stake_state.inner.stake.stake.delegation.warmup_cooldown_rate - source_state.inner.stake.stake.delegation.warmup_cooldown_rate) >= DBL_EPSILON
      || stake_state.inner.stake.stake.delegation.deactivation_epoch != ULONG_MAX
      || source_state.inner.stake.stake.delegation.deactivation_epoch != ULONG_MAX) {
          FD_LOG_WARNING(( "Unable to merge due to stake deactivation %lu %lu", stake_state.inner.stake.stake.delegation.deactivation_epoch, source_state.inner.stake.stake.delegation.deactivation_epoch));
          ctx.txn_ctx->custom_err = 6;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // Err(StakeError::MergeMismatch.into())
      }

    } else {
      // active_stakes_can_merge
      if (source_state.inner.stake.stake.credits_observed != stake_state.inner.stake.stake.credits_observed) {
        FD_LOG_WARNING(("Unable to merge due to credits observed mismatch"));
        ctx.txn_ctx->custom_err = 6;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // Err(StakeError::MergeMismatch.into())
      }
    }

    ushort is_some_merge = 0;
    if (stake_merge_kind.discriminant == MERGE_KIND_INACTIVE && source_merge_kind.discriminant == MERGE_KIND_INACTIVE) {
      // None
    } else if (stake_merge_kind.discriminant == MERGE_KIND_INACTIVE && source_merge_kind.discriminant == MERGE_KIND_ACTIVE_EPOCH) {
      // None
    } else if (stake_merge_kind.discriminant == MERGE_KIND_ACTIVE_EPOCH && source_merge_kind.discriminant == MERGE_KIND_INACTIVE) {
      is_some_merge = 1;
      stake_state.inner.stake.stake.delegation.stake = fd_ulong_sat_add( stake_state.inner.stake.stake.delegation.stake, source_lamports);
    } else if (stake_merge_kind.discriminant == MERGE_KIND_ACTIVE_EPOCH && source_merge_kind.discriminant == MERGE_KIND_ACTIVE_EPOCH) {
      is_some_merge = 1;
      fd_acc_lamports_t src_lamports = fd_ulong_sat_add(source_state.inner.stake.meta.rent_exempt_reserve, stake_state.inner.stake.stake.delegation.stake);
      merge_delegation_stake_and_credits_observed(ctx.global, &stake_state, src_lamports, source_state.inner.stake.stake.credits_observed);
    } else if (stake_merge_kind.discriminant == MERGE_KIND_FULLY_ACTIVE && source_merge_kind.discriminant == MERGE_KIND_FULLY_ACTIVE) {
      is_some_merge = 1;
      merge_delegation_stake_and_credits_observed(ctx.global, &stake_state, source_state.inner.stake.stake.delegation.stake, source_state.inner.stake.stake.credits_observed);
    } else {
      ctx.txn_ctx->custom_err = 6;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // Err(StakeError::MergeMismatch.into())
    }
    if (is_some_merge) {
      write_stake_state( ctx.global, stake_acc, &stake_state, 0);
    }
    /* Source is about to be drained, deinitialize its state */
    source_state.discriminant = fd_stake_state_enum_uninitialized;
    write_stake_state( ctx.global, source_acc, &source_state, 0);

    /* Drain the source account */
    // sub from source
    fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.slot, source_acc, source_metadata.info.lamports - source_lamports);
    // add to destination
    fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.slot, stake_acc, stake_metadata.info.lamports + source_lamports);

  } // end of merge, discriminant 7
  else if ( fd_stake_instruction_is_withdraw( &instruction )) { // discriminant X
    ulong lamports = instruction.inner.withdraw;
    // instruction_context.check_number_of_instruction_accounts(2)?;
    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 4) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    /* Check that the instruction accounts are correct */
    uchar* instr_acc_idxs = ((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.instr->acct_off);
    fd_pubkey_t* txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_ctx->txn_raw->raw + ctx.txn_ctx->txn_descriptor->acct_addr_off);
    fd_pubkey_t* stake_acc         = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t* to_acc            = &txn_accs[instr_acc_idxs[1]];

    /* Check that the Instruction Account 2 is the Clock Sysvar account */
    if ( memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    /* Check that the Instruction Account 3 is the Stake History Sysvar account */
    if ( memcmp( &txn_accs[instr_acc_idxs[3]], ctx.global->sysvar_stake_history, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_account_meta_t metadata;
    int               read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) ctx.global->sysvar_stake_history, &metadata );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
    read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) ctx.global->sysvar_stake_history, raw_acc_data, metadata.hlen, metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    fd_stake_history_t stake_history;

    fd_bincode_decode_ctx_t ctx4;
    ctx4.data = raw_acc_data;
    ctx4.dataend = raw_acc_data + metadata.dlen;
    ctx4.valloc  = ctx.global->valloc;
    fd_stake_history_decode( &stake_history, &ctx4 );

    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 5) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    /* Check that the Instruction Account 3 is the Stake History Sysvar account */
    if ( memcmp( &txn_accs[instr_acc_idxs[3]], ctx.global->sysvar_stake_history, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* Check that Instruction Account 4 is a signer */
    if(instr_acc_idxs[4] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    fd_pubkey_t * withdraw_authority_acc = &txn_accs[instr_acc_idxs[4]];

    fd_account_meta_t stake_acc_metadata;
    read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &stake_acc_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    if ( stake_acc_metadata.dlen != STAKE_ACCOUNT_SIZE ) {
      FD_LOG_WARNING(( "Stake account size incorrect. expected %d got %lu", STAKE_ACCOUNT_SIZE, stake_acc_metadata.dlen ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* Read the current data in the Stake account */
    uchar * stake_acc_data = fd_valloc_malloc( ctx.global->valloc, 8UL, stake_acc_metadata.dlen );
    read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, (uchar*)stake_acc_data, sizeof(fd_account_meta_t), stake_acc_metadata.dlen );
    if ( read_result != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to read stake account data" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }

    void* input            = (void *)stake_acc_data;
    void* dataend          = (void*)&stake_acc_data[stake_acc_metadata.dlen];

    fd_stake_state_t stake_state;
    fd_bincode_decode_ctx_t ctx5 = {
      .data    = input,
      .dataend = dataend,
      .valloc  = ctx.global->valloc
    };
    fd_stake_state_decode( &stake_state, &ctx5 );

    ulong reserve_lamports = 0;
    uint is_staked = 0;
    fd_stake_lockup_t lockup;
    if( fd_stake_state_is_stake( &stake_state ) ) {
      fd_pubkey_t * authorized_withdrawer_acc = &stake_state.inner.stake.meta.authorized.withdrawer;
      if( memcmp( authorized_withdrawer_acc, withdraw_authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      // // TODO: REMOVE
      // if( clock.epoch >= stake_state.inner.stake.stake.delegation.deactivation_epoch ) {
      //   return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;m
      // }

      ulong staked_lamports = (clock.epoch >= stake_state.inner.stake.stake.delegation.deactivation_epoch)
          ? stake_activating_and_deactivating(&stake_state.inner.stake.stake.delegation, clock.epoch, &stake_history).effective
          : stake_state.inner.stake.stake.delegation.stake;

      reserve_lamports = staked_lamports + stake_state.inner.stake.meta.rent_exempt_reserve;
      // Checked add
      if (reserve_lamports < staked_lamports || reserve_lamports < stake_state.inner.stake.meta.rent_exempt_reserve) {
        return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
      }

      is_staked = staked_lamports != 0;
      lockup = stake_state.inner.stake.meta.lockup;
    } else if ( fd_stake_state_is_initialized( &stake_state ) ) {
      fd_pubkey_t * authorized_withdrawer_acc = &stake_state.inner.stake.meta.authorized.withdrawer;
      if( memcmp( authorized_withdrawer_acc, withdraw_authority_acc, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
      if ( FD_FEATURE_ACTIVE(ctx.global, stake_allow_zero_undelegated_amount) ) {
        reserve_lamports = stake_state.inner.initialized.rent_exempt_reserve;
      } else {
        reserve_lamports = stake_state.inner.initialized.rent_exempt_reserve + get_minimum_delegation(ctx.global);

        // checked add
        if (reserve_lamports < stake_state.inner.initialized.rent_exempt_reserve ||
            reserve_lamports < get_minimum_delegation(ctx.global)) {
            return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;;
        }
      }

      is_staked = 0;
      lockup = stake_state.inner.initialized.lockup;
    } else if ( fd_stake_state_is_uninitialized( &stake_state ) ) {
      /* Check that the Stake account is Uninitialized, if it is, then only stack account can withdraw */
      if (instr_acc_idxs[0] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }
    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_pubkey_t* custodian = NULL;
    if (ctx.instr->acct_cnt >= 6) {
      if(instr_acc_idxs[5] < ctx.txn_ctx->txn_descriptor->signature_cnt) {
        custodian = &txn_accs[instr_acc_idxs[5]];
      }
    }

    if (!custodian || memcmp(custodian, &lockup.custodian, sizeof(fd_pubkey_t)) != 0) {
      if (lockup.unix_timestamp > clock.unix_timestamp || lockup.epoch > clock.epoch) {
        ctx.txn_ctx->custom_err = 1;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
    }

    ulong lamports_and_reserve = lamports + reserve_lamports;
    if (lamports_and_reserve < lamports || lamports_and_reserve < reserve_lamports) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }
    // TODO: a bunch of stuff
    if( is_staked && lamports_and_reserve > stake_acc_metadata.info.lamports ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    if (lamports != stake_acc_metadata.info.lamports && lamports_and_reserve > stake_acc_metadata.info.lamports) {
      // TODO: assert!(!is_staked)
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    FD_LOG_WARNING(( "XXX: %32J", to_acc));

    fd_acc_lamports_t receiver_lamports = 0;
    read_result = fd_acc_mgr_get_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, to_acc, &receiver_lamports );
    if ( FD_UNLIKELY( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
      /* Create new account if it doesn't exist */
      FD_LOG_DEBUG(( "transfer to unknown account: creating new account" ));
      fd_account_meta_t metadata;
      fd_account_meta_init(&metadata);
      int write_result = fd_acc_mgr_write_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, to_acc, &metadata, sizeof(metadata), NULL, 0, 0 );
      if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to create new account" ));
        return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
      }

    } else if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to get lamports" ));
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }

    fd_account_meta_t to_acc_metadata;

    read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, to_acc, &to_acc_metadata );
    if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read to account metadata %d", read_result ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    if( stake_acc_metadata.info.lamports == lamports ) {
      stake_state.discriminant = fd_stake_state_enum_uninitialized;
      int write_result = write_stake_state(ctx.global, stake_acc, &stake_state, 0);
      if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to write stake account" ));
        return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
      }
    }

    to_acc_metadata.info.lamports += lamports;
    stake_acc_metadata.info.lamports -= lamports;
    fd_acc_mgr_set_metadata(ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &stake_acc_metadata);
    fd_acc_mgr_set_metadata(ctx.global->acc_mgr, ctx.global->funk_txn, to_acc, &to_acc_metadata);

  }
  else if ( fd_stake_instruction_is_get_minimum_delegation( &instruction ) ) {
    if ( !ctx.global->features.add_get_minimum_delegation_instruction_to_stake_program ) {
      // still need to check if the first account is stake account
      fd_pubkey_t* stake_acc         = &txn_accs[instr_acc_idxs[0]];
      fd_pubkey_t stake_acc_owner;
      fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &stake_acc_owner );
      if ( memcmp( &stake_acc_owner, ctx.global->solana_stake_program, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
      }
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
    // ulong minimum_delegation = get_minimum_delegation(ctx.global);

    /* TODO: Fix this after CPI return data is implemented */
    // let minimum_delegation = Vec::from(minimum_delegation.to_le_bytes());
    // invoke_context
    //     .transaction_context
    //     .set_return_data(id(), minimum_delegation)

  }
  else if ( fd_stake_instruction_is_deactivate_delinquent( &instruction ) ) {
    if (!ctx.global->features.stake_deactivate_delinquent_instruction) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    /* check at least there are at least 3 accounts */
    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 3) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    /* Read the current State State from the Stake account */
    fd_pubkey_t* stake_acc         = &txn_accs[instr_acc_idxs[0]];
    fd_stake_state_t stake_state;
    int result = read_stake_state( ctx.global, stake_acc, &stake_state );
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }

    fd_pubkey_t * delinquent_vote_acc = &txn_accs[instr_acc_idxs[1]];
    fd_pubkey_t delinquent_vote_acc_owner;
    fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, delinquent_vote_acc, &delinquent_vote_acc_owner );
    if ( memcmp( &delinquent_vote_acc_owner, ctx.global->solana_vote_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    /* Read vote account */
    fd_account_meta_t         delinquent_vote_meta;
    fd_vote_state_versioned_t delinquent_vote_state;

    result = fd_vote_load_account( &delinquent_vote_state, &delinquent_vote_meta, ctx.global, delinquent_vote_acc );
    if( FD_UNLIKELY( result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      return result;
    }

    const fd_pubkey_t * reference_vote_acc = &txn_accs[instr_acc_idxs[2]];
    fd_pubkey_t reference_vote_acc_owner;
    fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, reference_vote_acc, &reference_vote_acc_owner );
    if ( memcmp( &reference_vote_acc_owner, ctx.global->solana_vote_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );
    /* uncomment this hard coded line to get tests to pass */
    // clock.epoch = 20;

    /* Read vote account */
    fd_account_meta_t         reference_vote_meta;
    fd_vote_state_versioned_t reference_vote_state;

    result = fd_vote_load_account( &reference_vote_state, &reference_vote_meta, ctx.global, reference_vote_acc );
    if( FD_UNLIKELY( result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      return result;
    }

    if (!acceptable_reference_epoch_credits(reference_vote_state.inner.current.epoch_credits, clock.epoch)) {
      ctx.txn_ctx->custom_err = 9;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // Err(StakeError::InsufficientReferenceVotes.into());
    }
    if ( !fd_stake_state_is_stake( &stake_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    if (memcmp(&stake_state.inner.stake.stake.delegation.voter_pubkey, delinquent_vote_acc, sizeof(fd_pubkey_t)) != 0) {
      ctx.txn_ctx->custom_err = 10; // return Err(StakeError::VoteAddressMismatch.into());
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    // Deactivate the stake account if its delegated vote account has never voted or has not
    // voted in the last `MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION`
    if ( !eligible_for_deactivate_delinquent( delinquent_vote_state.inner.current.epoch_credits, clock.epoch) ) {
      ctx.txn_ctx->custom_err = 11; //  Err(StakeError::MinimumDelinquentEpochsForDeactivationNotMet.into())
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    if (stake_state.inner.stake.stake.delegation.deactivation_epoch != ULONG_MAX) {
      ctx.txn_ctx->custom_err = 2; // Err(StakeError::AlreadyDeactivated)
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    stake_state.inner.stake.stake.delegation.deactivation_epoch = clock.epoch;
    result = write_stake_state(ctx.global, stake_acc, &stake_state, 0);
    if ( FD_UNLIKELY(result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      return result;
    }
  } // end of deactivate_delinquent, discriminant 14
  else if ( fd_stake_instruction_is_redelegate( &instruction ) ) {
    /* Read the current State State from the Stake account */
    fd_pubkey_t* stake_acc         = &txn_accs[instr_acc_idxs[0]];
    fd_stake_state_t stake_state;
    int result = read_stake_state( ctx.global, stake_acc, &stake_state );
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }

    if ( !ctx.global->features.stake_redelegate_instruction ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
    /* check at least there are at least 3 accounts */
    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 3) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    /* Check that Instruction Account 3 is the Stake Config Program account */
    if ( memcmp( &txn_accs[instr_acc_idxs[3]], ctx.global->solana_stake_program_config, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_stake_config_t stake_config;
    result = read_stake_config( ctx.global, &stake_config );
    if ( FD_UNLIKELY(result != FD_EXECUTOR_INSTR_SUCCESS) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_pubkey_t* uninitialized_stake_acc         = &txn_accs[instr_acc_idxs[1]];

    fd_pubkey_t uninitialized_stake_acc_owner;
    fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, uninitialized_stake_acc, &uninitialized_stake_acc_owner );
    if ( memcmp( &uninitialized_stake_acc_owner, ctx.global->solana_stake_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    fd_account_meta_t uninitialized_stake_acc_metadata;
    result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, uninitialized_stake_acc, &uninitialized_stake_acc_metadata );
    if ( FD_UNLIKELY( result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    if ( uninitialized_stake_acc_metadata.dlen != STAKE_ACCOUNT_SIZE ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_stake_state_t uninitialized_stake_state;
    result = read_stake_state( ctx.global, uninitialized_stake_acc, &uninitialized_stake_state );
    if ( FD_UNLIKELY(result != FD_EXECUTOR_INSTR_SUCCESS) ) {
      return result;
    }
    if ( !fd_stake_state_is_uninitialized(&uninitialized_stake_state) ) {
      FD_LOG_WARNING(("expected uninitialized stake account to be uninitialized"));
      return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
    }

    // validate the provided vote account
    fd_pubkey_t* vote_acc = &txn_accs[instr_acc_idxs[2]];
    fd_pubkey_t vote_acc_owner;
    fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, &vote_acc_owner );
    if ( memcmp( &vote_acc_owner, ctx.global->solana_vote_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    /* Read vote account */
    fd_account_meta_t         vote_meta;
    fd_vote_state_versioned_t vote_state;

    result = fd_vote_load_account( &vote_state, &vote_meta, ctx.global, vote_acc );
    if( FD_UNLIKELY( result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      return result;
    }

    if ( !fd_stake_state_is_stake(&stake_state) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }
    fd_sol_sysvar_clock_t clock;
    clock.epoch = 100;
    // result = fd_sysvar_clock_read( ctx.global, &clock );
    // if( FD_UNLIKELY( result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    //   return result;
    // }

    fd_stake_history_t * history = NULL;
    fd_sysvar_stake_history_read( ctx.global, history);

    fd_stake_history_entry_t entry = stake_activating_and_deactivating(&stake_state.inner.stake.stake.delegation, clock.epoch, history);
    if ( (entry.effective == 0) || (entry.activating != 0) || (entry.deactivating != 0)) {
      FD_LOG_WARNING(("stake is not active"));
      ctx.txn_ctx->custom_err = 13; // Err(StakeError::RedelegateTransientOrInactiveStake.into())
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    /* Deny redelegating to the same vote account. This is nonsensical and could be used to grief the global stake warm-up/cool-down rate */
    if ( memcmp(&stake_state.inner.stake.stake.delegation.voter_pubkey, vote_acc, sizeof(fd_pubkey_t)) == 0 ) {
      FD_LOG_WARNING(("redelegating to the same vote account not permitted"));
      ctx.txn_ctx->custom_err = 14; // Err(StakeError::RedelegateToSameVoteAccount.into())
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    result = authorized_check_signers(&ctx, instr_acc_idxs, txn_accs, &stake_state.inner.stake.meta.authorized.staker);
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }
    result = deactivate(&stake_state, stake_acc, &ctx, clock.epoch);
    if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
      return result;
    }

    // transfer the effective stake to the uninitialized stake account

    // add to destination
    fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.slot, uninitialized_stake_acc, uninitialized_stake_acc_metadata.info.lamports + entry.effective);
    // sub from source
    fd_account_meta_t stake_acc_metadata;
    result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &stake_acc_metadata );
    if ( FD_UNLIKELY( result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read stake account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.slot, stake_acc, stake_acc_metadata.info.lamports - entry.effective);

    // initialize and schedule `uninitialized_stake_account` for activation
    // uninitialized_stake_state = stake_state;
    // uninitialized_stake_acc_metadata = stake_acc_metadata;
    fd_rent_t rent;
    rent.lamports_per_uint8_year = 3480;
    rent.exemption_threshold = 2.0;
    rent.burn_percent = 50;
    uninitialized_stake_state.inner.stake.meta.rent_exempt_reserve = fd_rent_exempt_minimum_balance2( &rent, uninitialized_stake_acc_metadata.dlen );

    fd_acc_lamports_t stake_amount;
    result = validate_delegated_amount( &ctx, stake_acc_metadata.info.lamports - entry.effective, uninitialized_stake_state.inner.stake.meta.rent_exempt_reserve, &stake_amount);
    if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
      return result;
    }

    uninitialized_stake_state.inner.stake.stake.delegation.stake = stake_amount;
    uninitialized_stake_state.discriminant = fd_stake_state_enum_stake;
    memcpy(&uninitialized_stake_state.inner.stake.stake.delegation.voter_pubkey, vote_acc, sizeof(fd_pubkey_t));
    uninitialized_stake_state.inner.stake.stake.delegation.activation_epoch = clock.epoch;
    uninitialized_stake_state.inner.stake.stake.delegation.deactivation_epoch = stake_state.inner.stake.stake.delegation.deactivation_epoch;
    uninitialized_stake_state.inner.stake.stake.delegation.warmup_cooldown_rate = stake_config.warmup_cooldown_rate;
    uninitialized_stake_state.inner.stake.stake.credits_observed = vote_state.inner.current.epoch_credits->credits;
    write_stake_state(ctx.global, uninitialized_stake_acc, &uninitialized_stake_state, 1);

  }
  else {
    FD_LOG_NOTICE(( "unsupported StakeInstruction instruction: discriminant %d", instruction.discriminant ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  fd_bincode_destroy_ctx_t ctx3 = { .valloc = ctx.global->valloc };
  fd_stake_instruction_destroy( &instruction, &ctx3 );

  return FD_EXECUTOR_INSTR_SUCCESS;
}
