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


// These exist until charlie finishes the stake rewrite...
static inline int
fd_acc_mgr_modify_old( fd_acc_mgr_t *         acc_mgr,
                   fd_funk_txn_t *        txn,
                   fd_pubkey_t const *    pubkey,
                   int                    do_create,
                   ulong                  min_data_sz,
                   fd_funk_rec_t const *  opt_con_rec,
                   fd_funk_rec_t **       opt_out_rec,
                   fd_account_meta_t **   opt_out_meta,
                   uchar **               opt_out_data ) {

  int err = FD_ACC_MGR_SUCCESS;
  uchar * raw = fd_acc_mgr_modify_raw( acc_mgr, txn, pubkey, do_create, min_data_sz, opt_con_rec, opt_out_rec, &err );
  if( FD_UNLIKELY( !raw ) ) return err;

  fd_account_meta_t * meta = (fd_account_meta_t *)raw;
  if( opt_out_meta ) *opt_out_meta = meta;
  if( opt_out_data ) *opt_out_data = raw + meta->hlen;
  return FD_ACC_MGR_SUCCESS;
}

static inline int
fd_acc_mgr_view_old( fd_acc_mgr_t *             acc_mgr,
                 fd_funk_txn_t const *      txn,
                 fd_pubkey_t const *        pubkey,
                 fd_funk_rec_t const **     opt_out_rec,
                 fd_account_meta_t const ** opt_out_meta,
                 uchar const **             opt_out_data ) {

  int err = FD_ACC_MGR_SUCCESS;
  uchar const * raw = fd_acc_mgr_view_raw( acc_mgr, txn, pubkey, opt_out_rec, &err );
  if (FD_UNLIKELY(!FD_RAW_ACCOUNT_EXISTS(raw))) {
    if (err != FD_ACC_MGR_SUCCESS)
      return err;
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  fd_account_meta_t const * meta = (fd_account_meta_t const *)raw;
  if( opt_out_meta ) *opt_out_meta = meta;
  if( opt_out_data ) *opt_out_data = raw + meta->hlen;
  return FD_ACC_MGR_SUCCESS;
}


static fd_acc_lamports_t get_minimum_delegation( fd_global_ctx_t* global ) {
  if ( FD_FEATURE_ACTIVE(global, stake_raise_minimum_delegation_to_1_sol )) {
    return MINIMUM_DELEGATION_SOL * LAMPORTS_PER_SOL;
  } else {
    return MINIMUM_STAKE_DELEGATION;
  }
}

int authorized_check_signers(instruction_ctx_t* ctx, uchar const * instr_acc_idxs, fd_pubkey_t * txn_accs, fd_pubkey_t * staker) {
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
    FD_LOG_INFO(("idx=%lu peek=%lu current_epoch=%lu", idx, deq_fd_vote_epoch_credits_t_peek_index(epoch_credits, idx)->epoch, current_epoch));
    if (deq_fd_vote_epoch_credits_t_peek_index(epoch_credits, idx)->epoch != current_epoch) {
      return 0;
    }
    current_epoch = fd_ulong_sat_sub(current_epoch, 1);
  }
  return 1;
}

static int
deactivate(fd_stake_state_t* stake_state, fd_pubkey_t const * stake_acc, instruction_ctx_t* ctx, ulong epoch) {
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
  if (*stake_amount < get_minimum_delegation(ctx->global)) {
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

static void
write_stake_config( fd_global_ctx_t *         global,
                    fd_stake_config_t const * stake_config ) {

  ulong               data_sz = fd_stake_config_size( stake_config );
  fd_pubkey_t const * acc_key  = (fd_pubkey_t const *)global->solana_stake_program_config;
  fd_account_meta_t * acc_meta = NULL;
  uchar *             acc_data = NULL;
  int err = fd_acc_mgr_modify_old( global->acc_mgr, global->funk_txn, acc_key, 1, data_sz, NULL, NULL, &acc_meta, &acc_data );
  FD_TEST( !err );

  acc_meta->dlen            = data_sz;
  acc_meta->info.lamports   = 960480UL;
  acc_meta->info.rent_epoch = 0UL;
  acc_meta->info.executable = 0;


  fd_bincode_encode_ctx_t ctx3;
  ctx3.data    = acc_data;
  ctx3.dataend = acc_data + data_sz;
  if( fd_stake_config_encode( stake_config, &ctx3 ) )
    FD_LOG_ERR(("fd_stake_config_encode failed"));

  fd_memset( acc_data, 0, data_sz );
  fd_memcpy( acc_data, stake_config, sizeof(fd_stake_config_t) );
}

int
read_stake_config( fd_global_ctx_t *   global,
                   fd_stake_config_t * result ) {

  int read_result = 0;
  uchar const * acc_rec = fd_acc_mgr_view_raw( global->acc_mgr, global->funk_txn, (fd_pubkey_t const *)global->solana_stake_program_config, NULL, &read_result );
  if (FD_UNLIKELY(!FD_RAW_ACCOUNT_EXISTS(acc_rec))) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return read_result;
  }

  fd_account_meta_t const * metadata     = (fd_account_meta_t const *)acc_rec;
  uchar const *             raw_acc_data = acc_rec + metadata->hlen;

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data;
  ctx.dataend = raw_acc_data + metadata->dlen;
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

int
read_stake_state( fd_global_ctx_t const *   global,
                  fd_account_meta_t const * metadata,
                  fd_stake_state_t *        result ) {

  uchar const * raw_acc_data = (uchar const *)metadata + metadata->hlen;

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data;
  ctx.dataend = raw_acc_data + metadata->dlen;
  ctx.valloc  = global->valloc;
  if ( fd_stake_state_decode( result, &ctx ) ) {
    FD_LOG_DEBUG(("fd_stake_state_decode failed"));
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
      FD_LOG_DEBUG(( "Split amount has to be something"));
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
    fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;

    // getting all source data
    fd_pubkey_t *             source_acc      = &txn_accs[instr_acc_idxs[source_account_index]];
    fd_account_meta_t const * metadata_source = NULL;
    int err = fd_acc_mgr_view_old( ctx.global->acc_mgr, ctx.global->funk_txn, source_acc, NULL, &metadata_source, NULL );
    FD_TEST( !err );
    fd_acc_lamports_t source_lamports = metadata_source->info.lamports;

    // Obviously cannot split more than what the source account has
    if (lamports > source_lamports) {
      FD_LOG_WARNING(( "Obviously cannot split more than what the source account has"));
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    ulong source_data_len = metadata_source->dlen;

    // getting all dest data
    fd_pubkey_t *             dest_acc      = &txn_accs[instr_acc_idxs[destination_account_index]];
    fd_account_meta_t const * metadata_dest = NULL;
    err = fd_acc_mgr_view_old( ctx.global->acc_mgr, ctx.global->funk_txn, dest_acc, NULL, &metadata_dest, NULL );
    FD_TEST( !err );

    fd_acc_lamports_t destination_lamports = metadata_dest->info.lamports;
    ulong             destination_data_len = metadata_dest->dlen;

    // Verify that the source account still has enough lamports left after splitting:
    // EITHER at least the minimum balance, OR zero (in this case the source
    // account is transferring all lamports to new destination account, and the source
    // account will be closed)

    fd_stake_state_t source_state;
    read_stake_state( ctx.global, metadata_source, &source_state );

    fd_acc_lamports_t source_minimum_balance = source_state.inner.initialized.rent_exempt_reserve + additional_lamports;
    *source_remaining_balance = source_lamports - lamports;
    if (*source_remaining_balance == 0) {
      // full amount is a withdrawal
      // nothing to do here
    } else if (*source_remaining_balance < source_minimum_balance) {
      FD_LOG_DEBUG(( "remaining balance is too low to do the split" ));
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

static ulong next_power_of_two( ulong v )
{
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}

static ulong trailing_zeros( ulong v ) {
    ulong c = 0;
    while ( v % 2 == 0 ) {
      c++;
      v = v >> 1;
    }
    return c;
}

static ulong get_epoch_from_schedule( fd_epoch_schedule_t * epoch_schedule, ulong slot ) {
    const ulong MINIMUM_SLOTS_PER_EPOCH = 32;
    if ( slot < epoch_schedule->first_normal_slot ) {
      ulong epoch = fd_ulong_sat_add(slot, MINIMUM_SLOTS_PER_EPOCH);
      epoch = fd_ulong_sat_add(epoch, 1);
      epoch = next_power_of_two(epoch);
      epoch = trailing_zeros(epoch);
      FD_LOG_INFO(("Epoch %lu", epoch));
      epoch = fd_ulong_sat_sub(epoch, trailing_zeros(MINIMUM_SLOTS_PER_EPOCH));
      FD_LOG_INFO(("Epoch %lu", epoch));
      epoch = fd_ulong_sat_sub(epoch, 1);
      return epoch;
    } else {
      ulong normal_slot_index = fd_ulong_sat_sub(slot, epoch_schedule->first_normal_slot);
      ulong normal_epoch_index = epoch_schedule->slots_per_epoch ? normal_slot_index / epoch_schedule->slots_per_epoch : 0;
      return fd_ulong_sat_add(epoch_schedule->first_normal_epoch, normal_epoch_index);
    }
}

static int new_warmup_cooldown_rate_epoch( instruction_ctx_t* ctx, ulong * result ) {
    if (FD_FEATURE_ACTIVE(ctx->global, reduce_stake_warmup_cooldown)) {
      fd_epoch_schedule_t epoch_schedule;
      fd_sysvar_epoch_schedule_read(ctx->global, &epoch_schedule);
      ulong slot = ctx->global->features.reduce_stake_warmup_cooldown;
      *result = get_epoch_from_schedule( &epoch_schedule, slot);
    } else {
      return -1;
    }
    return 0;
}

static int get_if_mergeable( instruction_ctx_t* ctx, fd_stake_state_t* stake_state, fd_sol_sysvar_clock_t clock, fd_stake_history_t history, fd_merge_kind_t* merge_kind) {
    if ( fd_stake_state_is_stake( stake_state ) ) {
      ulong new_epoch;
      int err = new_warmup_cooldown_rate_epoch(ctx, &new_epoch);
      ulong * new_activation_epoch = err == 0 ? &new_epoch : NULL;
      fd_stake_history_entry_t entry = stake_activating_and_deactivating( &stake_state->inner.stake.stake.delegation, clock.epoch, &history, new_activation_epoch);
      FD_LOG_INFO(( "effective = %lu, activating = %lu, deactivating = %lu", entry.effective, entry.activating, entry.deactivating ));
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
              uchar const * instr_acc_idxs,
              fd_pubkey_t * txn_accs,
              fd_stake_authorize_t * stake_authorize,
              fd_pubkey_t * new_authority,
              fd_stake_state_t stake_state,
              fd_pubkey_t const * stake_acc,
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
  uchar *data            = ctx.instr->data;

  fd_stake_instruction_t instruction;
  fd_bincode_decode_ctx_t ctx2;
  ctx2.data = data;
  ctx2.dataend = &data[ctx.instr->data_sz];
  ctx2.valloc  = ctx.global->valloc;
  if ( fd_stake_instruction_decode( &instruction, &ctx2 ) ) {
    FD_LOG_DEBUG(("fd_stake_instruction_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }
  int res;

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;
  /* TODO: check that the instruction account 0 owner is the stake program ID */
  if( FD_UNLIKELY( ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* Check that first instruction account is stake account
     https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L37 */
  fd_pubkey_t const *       stake_acc      = &txn_accs[instr_acc_idxs[0]];
  fd_funk_rec_t const *     stake_acc_ro   = NULL;
  fd_account_meta_t const * stake_acc_meta = NULL;
  uchar const *             stake_acc_data = NULL;
  int read_result = fd_acc_mgr_view_old( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, &stake_acc_ro, &stake_acc_meta, &stake_acc_data );
  if( FD_UNLIKELY( read_result!=FD_ACC_MGR_SUCCESS ))
    return read_result;
  if( FD_UNLIKELY( 0!=memcmp( stake_acc_meta->info.owner, ctx.global->solana_stake_program, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  FD_LOG_INFO(("instruction discriminant=%d", instruction.discriminant));
  if ( fd_stake_instruction_is_initialize( &instruction ) ) {
    /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L43 */

    FD_LOG_INFO(( "executing StakeInstruction::Initialize instruction" ));

    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 2)
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

    /* Check that Instruction Account 1 is the Rent account
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L44-L47 */
    if ( memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_rent, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* Check that the stake account is the correct size
       https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L441-L443 */
    if( FD_UNLIKELY( stake_acc_meta->dlen != STAKE_ACCOUNT_SIZE ) ) {
      FD_LOG_DEBUG(( "Stake account size incorrect. expected %d got %lu", STAKE_ACCOUNT_SIZE, stake_acc_meta->dlen ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_stake_state_t stake_state;
    fd_bincode_decode_ctx_t ctx3;
    ctx3.data    = stake_acc_data;
    ctx3.dataend = stake_acc_data + stake_acc_meta->dlen;
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
    fd_acc_lamports_t lamports = stake_acc_meta->info.lamports;
    ulong minimum_rent_exempt_balance = fd_rent_exempt_minimum_balance( ctx.global, stake_acc_meta->dlen );
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

    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc_meta, &stake_state );

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
    res = authorize(ctx, instr_acc_idxs, txn_accs, stake_authorize, new_authority, stake_state, stake_acc, clock, custodian, require_custodian_for_locked_stake_authorize, NULL);
    if ( res != 0 )
      return res;

  } // end of fd_stake_instruction_is_authorize, discriminant 1
  else if ( fd_stake_instruction_is_delegate_stake( &instruction ) ) {
    /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L126 */
    if ( ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 5 ) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    /* Check that the instruction accounts are correct
      https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L127-L142 */

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
    fd_sysvar_stake_history_read( ctx.global, &history );

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
    fd_pubkey_t const * vote_acc = &txn_accs[instr_acc_idxs[1]];
    /* TODO unnecessary meta read */
    fd_account_meta_t const * vote_acc_meta = NULL;
    uchar const *             vote_acc_data = NULL;
    int err = fd_acc_mgr_view_old( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, NULL, &vote_acc_meta, &vote_acc_data );
    if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;  /* ???? -- I think tests are broken here, but our code is also broken, and broken+broken sometimes == correct */
    if( memcmp( vote_acc_meta->info.owner, ctx.global->solana_vote_program, sizeof(fd_pubkey_t) ) != 0 )
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;

    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc_meta, &stake_state );

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
    res = validate_delegated_amount( &ctx, stake_acc_meta->info.lamports, meta->rent_exempt_reserve, &stake_amount );
    if (res != FD_EXECUTOR_INSTR_SUCCESS) {
      return res;
    }

    ulong credits = 0;
    int acc_res = fd_vote_acc_credits( ctx, vote_acc_meta, vote_acc_data, &credits );
    if( FD_UNLIKELY( acc_res != FD_EXECUTOR_INSTR_SUCCESS ) )
      return acc_res;  /* FIXME leak */

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


      stake_state_stake->stake.credits_observed = credits;
    } else {
      /* redelegate when fd_stake_state_is_stake( &stake_state )
        https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L562
      */
      ulong new_epoch;
      int err = new_warmup_cooldown_rate_epoch(&ctx, &new_epoch);
      ulong * new_activation_epoch = err == 0 ? &new_epoch : NULL;
      fd_stake_state_stake_t* stake_state_stake = &stake_state.inner.stake;

      if (stake_activating_and_deactivating( &stake_state.inner.stake.stake.delegation, clock.epoch, &history, new_activation_epoch).effective != 0) {
        ushort stake_lamports_ok = ( FD_FEATURE_ACTIVE( ctx.global, stake_redelegate_instruction ) ) ? stake_amount >= stake_state.inner.stake.stake.delegation.stake : 1;
        if (stake_lamports_ok && clock.epoch == stake_state.inner.stake.stake.delegation.deactivation_epoch && memcmp( &stake_state.inner.stake.stake.delegation.voter_pubkey, vote_acc, sizeof(fd_pubkey_t) ) == 0) {
          stake_state_stake->stake.delegation.deactivation_epoch = ULONG_MAX;
        } else {
          ctx.txn_ctx->custom_err = 3;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        }
      } else {
        stake_state_stake->stake.delegation.activation_epoch = clock.epoch;
        stake_state_stake->stake.delegation.stake = stake_amount;
        stake_state_stake->stake.delegation.deactivation_epoch = ULONG_MAX;
        fd_memcpy( &stake_state_stake->stake.delegation.voter_pubkey, vote_acc, sizeof(fd_pubkey_t) );
        stake_state_stake->stake.credits_observed = credits;
        stake_state_stake->stake.delegation.warmup_cooldown_rate = stake_config.warmup_cooldown_rate;
      }

      stake_state.discriminant = fd_stake_state_enum_stake;
      fd_memcpy( &stake_state_stake->meta, meta, FD_STAKE_STATE_META_FOOTPRINT );

      ulong credits = 0;
      int acc_res = fd_vote_acc_credits( ctx, vote_acc_meta, vote_acc_data, &credits );
      if( FD_UNLIKELY( acc_res != FD_EXECUTOR_INSTR_SUCCESS ) )
        return acc_res;  /* FIXME leak */
      stake_state_stake->stake.credits_observed = credits;
    }

    /* Write the stake state back to the database */
    result = write_stake_state( ctx.global, stake_acc, &stake_state, 0 );
    if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
      FD_LOG_WARNING(( "failed to write stake account state: %d", result ));
      return result;
    }
  } // end of fd_stake_instruction_is_delegate_stake, discriminant 2
  else if ( fd_stake_instruction_is_split( &instruction )) { // discriminant 3
    FD_LOG_INFO(( "stake_split_uses_rent_sysvar=%ld",            FD_FEATURE_ACTIVE( ctx.global, stake_split_uses_rent_sysvar            ) ));
    FD_LOG_INFO(( "stake_allow_zero_undelegated_amount=%ld",     FD_FEATURE_ACTIVE( ctx.global, stake_allow_zero_undelegated_amount     ) ));
    FD_LOG_INFO(( "clean_up_delegation_errors=%ld",              FD_FEATURE_ACTIVE( ctx.global, clean_up_delegation_errors              ) ));
    FD_LOG_INFO(( "stake_raise_minimum_delegation_to_1_sol=%ld", FD_FEATURE_ACTIVE( ctx.global, stake_raise_minimum_delegation_to_1_sol ) ));

  // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_instruction.rs#L192
    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 2) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t* split_acc = &txn_accs[instr_acc_idxs[1]];

    // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_state.rs#L666

    fd_account_meta_t const * split_metadata = NULL;
    int read_result = fd_acc_mgr_view_old( ctx.global->acc_mgr, ctx.global->funk_txn, split_acc, NULL, &split_metadata, NULL );
    if( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_DEBUG(( "failed to read split account metadata" ));
      return read_result;
    }
    if( memcmp( split_metadata->info.owner, ctx.global->solana_stake_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    if( split_metadata->dlen != STAKE_ACCOUNT_SIZE ) {
      FD_LOG_DEBUG(( "Split account size incorrect. expected %d got %lu", STAKE_ACCOUNT_SIZE, split_metadata->dlen ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_stake_state_t split_state;
    read_stake_state( ctx.global, split_metadata, &split_state );  /* unnecessary view */
    if ( !fd_stake_state_is_uninitialized( &split_state ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_acc_lamports_t split_lamports_balance = split_metadata->info.lamports;
    fd_acc_lamports_t lamports = instruction.inner.split; // split amount

    if( lamports > stake_acc_meta->info.lamports ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc_meta, &stake_state );

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
    if (lamports == stake_acc_meta->info.lamports && !fd_stake_state_is_uninitialized( &stake_state ) ) {
      stake_state.discriminant = fd_stake_state_enum_uninitialized; // de-initialize
      int result = write_stake_state( ctx.global, stake_acc, &stake_state, 0 );
      if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to write stake account state: %d", result ));
        return result;
      }
    }

    if (instr_acc_idxs[0] != instr_acc_idxs[1]) {
      fd_account_meta_t * split_metadata_rw = NULL;
      fd_account_meta_t * stake_metadata_rw = NULL;
      FD_TEST( 0==fd_acc_mgr_modify_old( ctx.global->acc_mgr, ctx.global->funk_txn, split_acc, 0, 0UL, NULL, NULL, &split_metadata_rw, NULL ));
      FD_TEST( 0==fd_acc_mgr_modify_old( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, 0, 0UL, NULL, NULL, &stake_metadata_rw, NULL ));

      // add to destination
      split_metadata_rw->info.lamports += lamports;
      // sub from source
      stake_metadata_rw->info.lamports -= lamports;
    }
  } // end of split, discriminant 3
  else if ( fd_stake_instruction_is_withdraw( &instruction )) { // discriminant X
    ulong lamports = instruction.inner.withdraw;
    // instruction_context.check_number_of_instruction_accounts(2)?;
    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 4) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    /* Check that the instruction accounts are correct */
    uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
    fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;
    fd_pubkey_t* to_acc   = &txn_accs[instr_acc_idxs[1]];

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

    fd_stake_history_t stake_history;
    fd_sysvar_stake_history_read( ctx.global, &stake_history );

    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 5) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    /* Check that Instruction Account 4 is a signer */
    if(instr_acc_idxs[4] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    fd_pubkey_t * withdraw_authority_acc = &txn_accs[instr_acc_idxs[4]];

    if( FD_UNLIKELY( stake_acc_meta->dlen != STAKE_ACCOUNT_SIZE ) ) {
      FD_LOG_DEBUG(( "Stake account size incorrect. expected %d got %lu", STAKE_ACCOUNT_SIZE, stake_acc_meta->dlen ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_stake_state_t stake_state;
    fd_bincode_decode_ctx_t ctx5 = {
      .data    = stake_acc_data,
      .dataend = stake_acc_data + stake_acc_meta->dlen,
      .valloc  = ctx.global->valloc
    };
    int err = fd_stake_state_decode( &stake_state, &ctx5 );
    if( FD_UNLIKELY( err != 0 ) ) {
      FD_LOG_WARNING(( "failed to decode stake account state: %d", err ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

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
      ulong new_epoch;
      int err = new_warmup_cooldown_rate_epoch(&ctx, &new_epoch);
      ulong * new_activation_epoch = err == 0 ? &new_epoch : NULL;
      ulong staked_lamports = (clock.epoch >= stake_state.inner.stake.stake.delegation.deactivation_epoch)
          ? stake_activating_and_deactivating(&stake_state.inner.stake.stake.delegation, clock.epoch, &stake_history, new_activation_epoch).effective
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
      reserve_lamports = stake_state.inner.initialized.rent_exempt_reserve;

      is_staked = 0;
      lockup = stake_state.inner.initialized.lockup;
    } else if ( fd_stake_state_is_uninitialized( &stake_state ) ) {
      /* Check that the Stake account is Uninitialized, if it is, then only stack account can withdraw */
      if (instr_acc_idxs[0] >= ctx.txn_ctx->txn_descriptor->signature_cnt) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }
      memset(&lockup, 0, sizeof(fd_stake_lockup_t));
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
    if( is_staked && lamports_and_reserve > stake_acc_meta->info.lamports ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    if (lamports != stake_acc_meta->info.lamports && lamports_and_reserve > stake_acc_meta->info.lamports) {
      // TODO: assert!(!is_staked)
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    FD_LOG_DEBUG(( "XXX: %32J", to_acc));

    /* Check if account exists */
    fd_funk_rec_t const * to_acc_rec_ro = NULL;
    read_result = fd_acc_mgr_view_old( ctx.global->acc_mgr, ctx.global->funk_txn, to_acc, &to_acc_rec_ro, NULL, NULL );
    FD_TEST( (read_result==FD_ACC_MGR_SUCCESS) | (read_result==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT) );

    fd_account_meta_t * to_acc_metadata = NULL;
    uchar *             to_acc_data     = NULL;
    int write_result = fd_acc_mgr_modify_old( ctx.global->acc_mgr, ctx.global->funk_txn, to_acc, 1, 0UL, NULL, NULL, &to_acc_metadata, &to_acc_data );
    FD_TEST( !write_result );

    if( FD_UNLIKELY( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {
      /* Create new account if it doesn't exist */
      FD_LOG_DEBUG(( "transfer to unknown account: creating new account" ));
      if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to create new account" ));
        return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
      }
    }

    if( stake_acc_meta->info.lamports == lamports ) {
      FD_LOG_DEBUG(( "Closing stake account" ));
      stake_state.discriminant = fd_stake_state_enum_uninitialized;
      int write_result = write_stake_state(ctx.global, stake_acc, &stake_state, 0);
      if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to write stake account" ));
        return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
      }
    }

    fd_account_meta_t * stake_acc_metadata_rw = NULL;
    write_result = fd_acc_mgr_modify_old( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, 0, 0UL, stake_acc_ro, NULL, &stake_acc_metadata_rw, NULL );
    FD_TEST( !write_result );

    to_acc_metadata      ->info.lamports += lamports;
    stake_acc_metadata_rw->info.lamports -= lamports;

  } // end of withdraw, discriminant 4
  else if ( fd_stake_instruction_is_deactivate( &instruction )) { // discriminant 5

    /* Check that the Instruction Account 1 is the Clock Sysvar account */
    if ( memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    fd_stake_state_t stake_state;
    int result = read_stake_state( ctx.global, stake_acc_meta, &stake_state );
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }

    if (!fd_stake_state_is_stake( &stake_state )) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

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

    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc_meta, &stake_state );
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

    fd_lockup_args_t* lockup_args = &instruction.inner.set_lockup;
    if ( lockup_args->unix_timestamp ) {
      stake_state.inner.stake.meta.lockup.unix_timestamp = (long)*lockup_args->unix_timestamp;
    }
    if ( lockup_args->epoch ) {
      stake_state.inner.stake.meta.lockup.epoch = *lockup_args->epoch;
    }
    if ( lockup_args->custodian ) {
      memcpy(&stake_state.inner.stake.meta.lockup.custodian, lockup_args->custodian, sizeof(fd_pubkey_t));
    }

    result = write_stake_state( ctx.global, stake_acc, &stake_state, 0);
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }

  } // end of set_lockup, discriminant 6
  else if ( fd_stake_instruction_is_merge( &instruction )) { // merge, discriminant 7
    // https://github.com/firedancer-io/solana/blob/56bd357f0dfdb841b27c4a346a58134428173f42/programs/stake/src/stake_instruction.rs#L206

    /* Check that there are at least two instruction accounts */
    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 4) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }
    uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
    fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;

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
    fd_funk_rec_t const *     source_rec_ro   = NULL;
    fd_account_meta_t const * source_metadata = NULL;
    int read_result = fd_acc_mgr_view_old( ctx.global->acc_mgr, ctx.global->funk_txn, source_acc, &source_rec_ro, &source_metadata, NULL );
    if( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read split account metadata" ));
      return read_result;
    }
    if ( memcmp( &source_metadata->info.owner, ctx.global->solana_stake_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    /* Close the stake account-reference loophole */
    if (instr_acc_idxs[0] == instr_acc_idxs[1]) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    /* Read the current State State from the Stake account */
    fd_stake_state_t source_state;
    read_stake_state( ctx.global, source_metadata, &source_state );

    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc_meta, &stake_state );

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
    uint is_not_lockup = !(source_state.inner.stake.meta.lockup.epoch > clock.epoch || source_state.inner.stake.meta.lockup.unix_timestamp > clock.unix_timestamp) &&
                         !(stake_state.inner.stake.meta.lockup.epoch > clock.epoch || stake_state.inner.stake.meta.lockup.unix_timestamp > clock.unix_timestamp);
    uint can_merge_lockups = memcmp(&source_state.inner.stake.meta.lockup, &stake_state.inner.stake.meta.lockup, sizeof(fd_stake_lockup_t)) == 0 || is_not_lockup;
    uint can_merge_authorized = memcmp(&stake_state.inner.stake.meta.authorized, &source_state.inner.stake.meta.authorized, sizeof(fd_stake_lockup_t)) == 0;
    if (!can_merge_lockups || !can_merge_authorized) {
      FD_LOG_DEBUG(("Unable to merge due to metadata mismatch"));
      ctx.txn_ctx->custom_err = 6;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // Err(StakeError::MergeMismatch.into())
    }

    if (source_merge_kind.is_active_stake && stake_merge_kind.is_active_stake) {
      // active_delegations_can_merge
      if (memcmp(&source_state.inner.stake.stake.delegation.voter_pubkey, &stake_state.inner.stake.stake.delegation.voter_pubkey, sizeof(fd_pubkey_t)) != 0) {
        FD_LOG_DEBUG(( "Unable to merge due to voter mismatch" ));
        ctx.txn_ctx->custom_err = 6;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; //  Err(StakeError::MergeMismatch.into())
      } else if ( fd_double_abs(stake_state.inner.stake.stake.delegation.warmup_cooldown_rate - source_state.inner.stake.stake.delegation.warmup_cooldown_rate) < DBL_EPSILON
      && stake_state.inner.stake.stake.delegation.deactivation_epoch == ULONG_MAX
      && source_state.inner.stake.stake.delegation.deactivation_epoch == ULONG_MAX) {
      } else {
        FD_LOG_DEBUG(( "Unable to merge due to stake deactivation %lu %lu", stake_state.inner.stake.stake.delegation.deactivation_epoch, source_state.inner.stake.stake.delegation.deactivation_epoch));
        ctx.txn_ctx->custom_err = 6;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR; // Err(StakeError::MergeMismatch.into())
      }

      if (!FD_FEATURE_ACTIVE(ctx.global, stake_merge_with_unmatched_credits_observed) && stake_state.inner.stake.stake.credits_observed != source_state.inner.stake.stake.credits_observed) {
        FD_LOG_DEBUG(("Unable to merge due to credits observed mismatch"));
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
      stake_state.inner.stake.stake.delegation.stake = fd_ulong_sat_add( stake_state.inner.stake.stake.delegation.stake, source_metadata->info.lamports );
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

    /* Upgrade accounts to writeable handles */
    fd_account_meta_t * source_metadata_rw = NULL;
    uchar *             source_data_rw     = NULL;
    fd_account_meta_t * stake_metadata_rw  = NULL;
    uchar *             stake_data_rw      = NULL;
    int write_result = fd_acc_mgr_modify_old( ctx.global->acc_mgr, ctx.global->funk_txn, source_acc, 0, 0UL, source_rec_ro, NULL, &source_metadata_rw, &source_data_rw );
    FD_TEST( !write_result );
        write_result = fd_acc_mgr_modify_old( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc,  0, 0UL, stake_acc_ro,  NULL, &stake_metadata_rw,  &stake_data_rw );
    FD_TEST( !write_result );

    /* Note: source_metadata_rw and source_metadata might alias! */
    /* add to destination */
    stake_metadata_rw ->info.lamports += source_metadata->info.lamports;
    /* Drain the source account */
    source_metadata_rw->info.lamports -= source_metadata->info.lamports;

    if (is_some_merge) {
      fd_bincode_encode_ctx_t ctx3;
      ctx3.data    = stake_data_rw;
      ctx3.dataend = stake_data_rw + fd_stake_state_size( &stake_state );
      if( FD_UNLIKELY( fd_stake_state_encode( &stake_state, &ctx3 )!=FD_BINCODE_SUCCESS ) )
        FD_LOG_ERR(("fd_stake_state_encode failed"));
    }
    /* Source is about to be drained, deinitialize its state */
    source_state.discriminant = fd_stake_state_enum_uninitialized;
    fd_bincode_encode_ctx_t ctx3;
    ctx3.data    = source_data_rw;
    ctx3.dataend = source_data_rw + fd_stake_state_size( &source_state );
    if( FD_UNLIKELY( fd_stake_state_encode( &source_state, &ctx3 )!=FD_BINCODE_SUCCESS ) )
      FD_LOG_ERR(("fd_stake_state_encode failed"));
  } // end of merge, discriminant 7
  else if ( fd_stake_instruction_is_authorize_with_seed( &instruction ) ) {
    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    read_stake_state( ctx.global, stake_acc_meta, &stake_state );

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
      fd_pubkey_create_with_seed( base_pubkey->uc, authority_seed, strlen( authority_seed ), authority_owner.uc, signer.uc );
      single_signer = 1;
    }
    fd_pubkey_t * signers = single_signer ? &signer : NULL;
    res = authorize(ctx, instr_acc_idxs, txn_accs, stake_authorize, new_authority, stake_state, stake_acc, clock, custodian, require_custodian_for_locked_stake_authorize, signers);
    if ( res != 0 )
      return res;

  } // end of authorize_with_seed, discriminant 8
  else if ( fd_stake_instruction_is_initialize_checked( &instruction ) ) {
    if ( FD_FEATURE_ACTIVE( ctx.global, vote_stake_checked_instructions ) ) {
      /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L43 */

      FD_LOG_INFO(( "executing StakeInstruction::InitializeChecked instruction" ));

      if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 4) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      fd_pubkey_t * staker_pubkey = &txn_accs[instr_acc_idxs[2]];
      fd_pubkey_t * withdrawer_pubkey = &txn_accs[instr_acc_idxs[3]];

      if ( instr_acc_idxs[3] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      fd_stake_authorized_t authorized;
      authorized.staker = *staker_pubkey;
      authorized.withdrawer = *withdrawer_pubkey;

      fd_stake_lockup_t lockup;
      memset(&lockup, 0, sizeof(fd_stake_lockup_t));
      /* Check that Instruction Account 1 is the Rent account
        https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_instruction.rs#L44-L47 */
      if ( memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_rent, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      /* Check that the stake account is the correct size
        https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L441-L443 */
      if( FD_UNLIKELY( stake_acc_meta->dlen != STAKE_ACCOUNT_SIZE ) ) {
        FD_LOG_WARNING(( "Stake account size incorrect. expected %d got %lu", STAKE_ACCOUNT_SIZE, stake_acc_meta->dlen ));
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      fd_stake_state_t stake_state;
      fd_bincode_decode_ctx_t ctx3;
      ctx3.data    = stake_acc_data;
      ctx3.dataend = stake_acc_data + stake_acc_meta->dlen;
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
      ulong minimum_rent_exempt_balance = fd_rent_exempt_minimum_balance( ctx.global, stake_acc_meta->dlen );
      ulong minimum_balance;
      if ( FD_FEATURE_ACTIVE(ctx.global, stake_allow_zero_undelegated_amount) ) {
        minimum_balance = minimum_rent_exempt_balance;
      } else {
        minimum_balance = get_minimum_delegation(ctx.global) + minimum_rent_exempt_balance;
      }

      if( stake_acc_meta->info.lamports < minimum_balance ) {
        return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
      }

      /* Initialize the Stake Account
        https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/programs/stake/src/stake_state.rs#L449-L453 */
      stake_state.discriminant = fd_stake_state_enum_initialized;
      fd_stake_state_meta_t* stake_state_meta = &stake_state.inner.initialized;
      stake_state_meta->rent_exempt_reserve = minimum_rent_exempt_balance;

      fd_memcpy( &stake_state_meta->authorized, &authorized, FD_STAKE_AUTHORIZED_FOOTPRINT );
      fd_memcpy( &stake_state_meta->lockup, &lockup, sizeof(fd_stake_lockup_t) );

      /* Write the initialized Stake account to the database */
      int result = write_stake_state( ctx.global, stake_acc, &stake_state, 0 );
      if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
        FD_LOG_WARNING(( "failed to write stake account state: %d", result ));
        return result;
      }
    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
  } // end of initialize checked, discriminant 9
  else if ( fd_stake_instruction_is_authorize_checked( &instruction ) ) {
    if ( FD_FEATURE_ACTIVE( ctx.global, vote_stake_checked_instructions ) ) {
      if ( memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      fd_sol_sysvar_clock_t clock;
      fd_sysvar_clock_read( ctx.global, &clock );

      if ( ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 4 ) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }
      if ( instr_acc_idxs[3] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }

      fd_pubkey_t * authorized_pubkey = &txn_accs[instr_acc_idxs[3]];
      fd_pubkey_t * custodian = NULL;

      if ( ctx.txn_ctx->txn_descriptor->acct_addr_cnt > 4 ) {
        custodian = &txn_accs[instr_acc_idxs[4]];
      }
      fd_stake_authorize_t * stake_authorize = &instruction.inner.authorize_checked;

      /* Read the current State State from the Stake account */
      fd_stake_state_t stake_state;
      read_stake_state( ctx.global, stake_acc_meta, &stake_state);
      res = authorize(ctx, instr_acc_idxs, txn_accs, stake_authorize, authorized_pubkey, stake_state, stake_acc, clock, custodian, true, NULL);
      if ( res != 0 )
        return res;
    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
  } // end of authorize_checked, disciminant 10
  else if ( fd_stake_instruction_is_authorize_checked_with_seed( &instruction ) ) {
    if ( FD_FEATURE_ACTIVE( ctx.global, vote_stake_checked_instructions ) ) {
      /* Read the current State State from the Stake account */
      fd_stake_state_t stake_state;
      read_stake_state( ctx.global, stake_acc_meta, &stake_state );

      fd_stake_authorize_t * stake_authorize = &instruction.inner.authorize_checked_with_seed.stake_authorize;
      char * authority_seed = instruction.inner.authorize_checked_with_seed.authority_seed;
      fd_pubkey_t authority_owner = instruction.inner.authorize_checked_with_seed.authority_owner;

      fd_sol_sysvar_clock_t clock;
      fd_pubkey_t * custodian = NULL;

      if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 2) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      if ( memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof(fd_pubkey_t) ) != 0 ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }
      fd_sysvar_clock_read( ctx.global, &clock );

      if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 4) {
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      }

      fd_pubkey_t * authorized_pubkey = &txn_accs[instr_acc_idxs[3]];

      if ( instr_acc_idxs[3] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) {
        return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      }
      if ( ctx.txn_ctx->txn_descriptor->acct_addr_cnt > 4 ) {
        custodian = &txn_accs[instr_acc_idxs[4]];
      }

      if ( !fd_stake_state_is_stake( &stake_state ) && !fd_stake_state_is_initialized( &stake_state) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      fd_pubkey_t signer;
      uchar single_signer = 0;
      if ( instr_acc_idxs[1] < ctx.txn_ctx->txn_descriptor->signature_cnt ) {
        fd_pubkey_t * base_pubkey = &txn_accs[instr_acc_idxs[1]];
        fd_pubkey_create_with_seed( base_pubkey->uc, authority_seed, strlen( authority_seed ), authority_owner.uc, signer.uc );
        single_signer = 1;
      }
      fd_pubkey_t * signers = single_signer ? &signer : NULL;
      res = authorize(ctx, instr_acc_idxs, txn_accs, stake_authorize, authorized_pubkey, stake_state, stake_acc, clock, custodian, true, signers);
      if ( res != 0 )
        return res;
    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
  } // end of authorize_checked_with_seed, disciminant 11
  else if ( fd_stake_instruction_is_set_lockup_checked( &instruction ) ) {
    if ( FD_FEATURE_ACTIVE( ctx.global, vote_stake_checked_instructions ) ) {

      fd_pubkey_t * custodian = NULL;
      if ( ctx.txn_ctx->txn_descriptor->acct_addr_cnt > 2 ) {
        if ( instr_acc_idxs[2] >= ctx.txn_ctx->txn_descriptor->signature_cnt ) {
          return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        }
        custodian = &txn_accs[instr_acc_idxs[2]];
      }

      fd_stake_state_t stake_state;
      read_stake_state( ctx.global, stake_acc_meta, &stake_state );

      if ( (!fd_stake_state_is_initialized( &stake_state )) && (!fd_stake_state_is_stake( &stake_state )) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      /* read clock */
      fd_sol_sysvar_clock_t clock;
      fd_sysvar_clock_read( ctx.global, &clock );

      int result;
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

      fd_lockup_args_t lockup_args;
      lockup_args.unix_timestamp = instruction.inner.set_lockup_checked.unix_timestamp;
      lockup_args.epoch = instruction.inner.set_lockup_checked.epoch;
      lockup_args.custodian = custodian;

      if ( lockup_args.unix_timestamp ) {
        stake_state.inner.stake.meta.lockup.unix_timestamp = (long)*lockup_args.unix_timestamp;
      }
      if ( lockup_args.epoch ) {
        stake_state.inner.stake.meta.lockup.epoch = *lockup_args.epoch;
      }
      if ( lockup_args.custodian ) {
        memcpy(&stake_state.inner.stake.meta.lockup.custodian, lockup_args.custodian, sizeof(fd_pubkey_t));
      }

      result = write_stake_state( ctx.global, stake_acc, &stake_state, 0);
      if (result != FD_EXECUTOR_INSTR_SUCCESS) {
        return result;
      }
    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
  } // end of set lockup checked, discriminant 12
  else if ( fd_stake_instruction_is_get_minimum_delegation( &instruction ) ) {
    if( !FD_FEATURE_ACTIVE( ctx.global, add_get_minimum_delegation_instruction_to_stake_program ) ) {
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
    if( !FD_FEATURE_ACTIVE( ctx.global, stake_deactivate_delinquent_instruction ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    /* check at least there are at least 3 accounts */
    if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 3) {
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    }

    fd_pubkey_t const *       delinquent_vote_acc      = &txn_accs[instr_acc_idxs[1]];
    fd_account_meta_t const * delinquent_vote_acc_meta = NULL;
    uchar const *             delinquent_vote_acc_data = NULL;
    FD_TEST( 0==fd_acc_mgr_view_old( ctx.global->acc_mgr, ctx.global->funk_txn, delinquent_vote_acc, NULL, &delinquent_vote_acc_meta, &delinquent_vote_acc_data ) );
    if ( memcmp( &delinquent_vote_acc_meta->info.owner, ctx.global->solana_vote_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    /* Deserialize vote account */
    fd_bincode_decode_ctx_t decode = {
      .data    = delinquent_vote_acc_data,
      .dataend = delinquent_vote_acc_data + delinquent_vote_acc_meta->dlen,
      /* TODO: Make this a instruction-scoped allocator */
      .valloc  = ctx.global->valloc,
    };
    fd_vote_state_versioned_t delinquent_vote_state;
    int result = fd_vote_state_versioned_decode( &delinquent_vote_state, &decode );
    if( FD_UNLIKELY( result != FD_BINCODE_SUCCESS ) ) {
      FD_LOG_DEBUG(( "Failed to decode delinquent vote state: %d", result ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_pubkey_t const *       reference_vote_acc      = &txn_accs[instr_acc_idxs[2]];
    fd_account_meta_t const * reference_vote_acc_meta = NULL;
    uchar const *             reference_vote_acc_data = NULL;
    FD_TEST( 0==fd_acc_mgr_view_old( ctx.global->acc_mgr, ctx.global->funk_txn, reference_vote_acc, NULL, &reference_vote_acc_meta, &reference_vote_acc_data ) );
    if ( memcmp( &reference_vote_acc_meta->info.owner, ctx.global->solana_vote_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    fd_stake_state_t stake_state;
    result = read_stake_state( ctx.global, stake_acc_meta, &stake_state );
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      FD_LOG_DEBUG(( "Failed to read stake state: %d", result ));
      return result;
    }

    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );
    /* uncomment this hard coded line to get tests to pass */
    // clock.epoch = 20;

    /* Deserialize vote account */
    decode = (fd_bincode_decode_ctx_t) {
      .data    = reference_vote_acc_data,
      .dataend = reference_vote_acc_data + reference_vote_acc_meta->dlen,
      /* TODO: Make this a instruction-scoped allocator */
      .valloc  = ctx.global->valloc,
    };
    fd_vote_state_versioned_t reference_vote_state;
    result = fd_vote_state_versioned_decode( &reference_vote_state, &decode );
    if( FD_UNLIKELY( result != FD_BINCODE_SUCCESS ) ) {
      FD_LOG_DEBUG(( "Failed to decode reference vote state: %d", result ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
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
    if ( !FD_FEATURE_ACTIVE( ctx.global, stake_redelegate_instruction ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    /* Read the current State State from the Stake account */
    fd_stake_state_t stake_state;
    int result = read_stake_state( ctx.global, stake_acc_meta, &stake_state );
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      return result;
    }

    if( !FD_FEATURE_ACTIVE( ctx.global, stake_redelegate_instruction ) ) {
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

    fd_funk_rec_t     const * uninitialized_stake_acc_rec_ro   = NULL;
    fd_account_meta_t const * uninitialized_stake_acc_metadata = NULL;
    result = fd_acc_mgr_view_old( ctx.global->acc_mgr, ctx.global->funk_txn, uninitialized_stake_acc, &uninitialized_stake_acc_rec_ro, &uninitialized_stake_acc_metadata, NULL );
    if ( FD_UNLIKELY( result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    if( memcmp( &uninitialized_stake_acc_metadata->info.owner, ctx.global->solana_stake_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }
    if ( uninitialized_stake_acc_metadata->dlen != STAKE_ACCOUNT_SIZE ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_stake_state_t uninitialized_stake_state;
    result = read_stake_state( ctx.global, uninitialized_stake_acc_metadata, &uninitialized_stake_state );
    if ( FD_UNLIKELY(result != FD_EXECUTOR_INSTR_SUCCESS) ) {
      return result;
    }
    if ( !fd_stake_state_is_uninitialized(&uninitialized_stake_state) ) {
      FD_LOG_DEBUG(("expected uninitialized stake account to be uninitialized"));
      return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
    }

    // validate the provided vote account
    fd_account_meta_t const * vote_meta2 = NULL;
    uchar const *             vote_data  = NULL;
    fd_pubkey_t const *       vote_acc   = &txn_accs[instr_acc_idxs[2]];
    FD_TEST( 0==fd_acc_mgr_view_old( ctx.global->acc_mgr, ctx.global->funk_txn, vote_acc, NULL, &vote_meta2, &vote_data ) );
    if( memcmp( &vote_meta2->info.owner, ctx.global->solana_vote_program, sizeof(fd_pubkey_t) ) != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
    }

    /* Read vote account */
    fd_bincode_decode_ctx_t decode = {
      .data    = vote_data,
      .dataend = vote_data + vote_meta2->dlen,
      /* TODO: Make this a instruction-scoped allocator */
      .valloc  = ctx.global->valloc,
    };
    fd_vote_state_versioned_t vote_state;
    result = fd_vote_state_versioned_decode( &vote_state, &decode );
    if( FD_UNLIKELY( result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      return result;
    }

    if ( !fd_stake_state_is_stake(&stake_state) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }
    fd_sol_sysvar_clock_t clock;
    result = fd_sysvar_clock_read( ctx.global, &clock );
    if( FD_UNLIKELY( result != FD_EXECUTOR_INSTR_SUCCESS ) ) {
      return result;
    }

    fd_stake_history_t history;
    result = fd_sysvar_stake_history_read( ctx.global, &history);
    if (result != FD_EXECUTOR_INSTR_SUCCESS)
      return result;

    ulong new_epoch;
    int err = new_warmup_cooldown_rate_epoch(&ctx, &new_epoch);
    ulong * new_activation_epoch = err == 0 ? &new_epoch : NULL;
    fd_stake_history_entry_t entry = stake_activating_and_deactivating(&stake_state.inner.stake.stake.delegation, clock.epoch, &history, new_activation_epoch);
    if ( (entry.effective == 0) || (entry.activating != 0) || (entry.deactivating != 0)) {
      FD_LOG_DEBUG(("stake is not active"));
      ctx.txn_ctx->custom_err = 13; // Err(StakeError::RedelegateTransientOrInactiveStake.into())
      fd_bincode_destroy_ctx_t ctx3 = { .valloc = ctx.global->valloc };
      fd_stake_history_destroy(&history, &ctx3);
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    fd_bincode_destroy_ctx_t ctx3 = { .valloc = ctx.global->valloc };
    fd_stake_history_destroy(&history, &ctx3);

    /* Deny redelegating to the same vote account. This is nonsensical and could be used to grief the global stake warm-up/cool-down rate */
    if ( memcmp(&stake_state.inner.stake.stake.delegation.voter_pubkey, vote_acc, sizeof(fd_pubkey_t)) == 0 ) {
      FD_LOG_DEBUG(("redelegating to the same vote account not permitted"));
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

    fd_account_meta_t * uninitialized_stake_acc_metadata_rw = NULL;
    FD_TEST( 0==fd_acc_mgr_modify_old( ctx.global->acc_mgr, ctx.global->funk_txn, uninitialized_stake_acc, 0, 0UL, NULL, NULL, &uninitialized_stake_acc_metadata_rw, NULL ) );

    // add to destination
    ulong uninitialized_stake_lamports = uninitialized_stake_acc_metadata->info.lamports;
    uninitialized_stake_acc_metadata_rw->info.lamports += entry.effective;
    // sub from source
    fd_account_meta_t * stake_acc_metadata = NULL;
    result = fd_acc_mgr_modify_old( ctx.global->acc_mgr, ctx.global->funk_txn, stake_acc, 0, 0UL, stake_acc_ro, NULL, &stake_acc_metadata, NULL );
    if ( FD_UNLIKELY( result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to read stake account metadata" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    stake_acc_metadata->info.lamports -= entry.effective;

    // initialize and schedule `uninitialized_stake_account` for activation
    uninitialized_stake_state = stake_state;
    fd_rent_t rent;
    rent.lamports_per_uint8_year = 3480;
    rent.exemption_threshold = 2.0;
    rent.burn_percent = 50;
    uninitialized_stake_state.inner.stake.meta.rent_exempt_reserve = fd_rent_exempt_minimum_balance2( &rent, uninitialized_stake_acc_metadata->dlen );

    fd_acc_lamports_t stake_amount;
    result = validate_delegated_amount( &ctx, uninitialized_stake_lamports + entry.effective, uninitialized_stake_state.inner.stake.meta.rent_exempt_reserve, &stake_amount);
    if ( result != FD_EXECUTOR_INSTR_SUCCESS ) {
      return result;
    }

    uninitialized_stake_state.inner.stake.stake.delegation.stake = stake_amount;
    uninitialized_stake_state.discriminant = fd_stake_state_enum_stake;
    memcpy(&uninitialized_stake_state.inner.stake.stake.delegation.voter_pubkey, vote_acc, sizeof(fd_pubkey_t));
    uninitialized_stake_state.inner.stake.stake.delegation.activation_epoch = clock.epoch;
    uninitialized_stake_state.inner.stake.stake.delegation.deactivation_epoch = ULONG_MAX;
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
