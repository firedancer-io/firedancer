#include <limits.h>

#include "../../../util/bits/fd_sat.h"
#include "../fd_pubkey_utils.h"
#include "../fd_system_ids.h"
#include "../program/fd_program_util.h"
#include "../sysvar/fd_sysvar.h"

#include "fd_stake_program.h"

/**********************************************************************/
/* Errors                                                             */
/**********************************************************************/

// DO NOT REORDER: https://github.com/bincode-org/bincode/blob/trunk/docs/spec.md#enums
// https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L23
#define FD_STAKE_ERR_NO_CREDITS_TO_REDEEM                                                   ( 0 )
#define FD_STAKE_ERR_LOCKUP_IN_FORCE                                                        ( 1 )
#define FD_STAKE_ERR_ALREADY_DEACTIVATED                                                    ( 2 )
#define FD_STAKE_ERR_TOO_SOON_TO_REDELEGATE                                                 ( 3 )
#define FD_STAKE_ERR_INSUFFICIENT_STAKE                                                     ( 4 )
#define FD_STAKE_ERR_MERGE_TRANSIENT_STAKE                                                  ( 5 )
#define FD_STAKE_ERR_MERGE_MISMATCH                                                         ( 6 )
#define FD_STAKE_ERR_CUSTODIAN_MISSING                                                      ( 7 )
#define FD_STAKE_ERR_CUSTODIAN_SIGNATURE_MISSING                                            ( 8 )
#define FD_STAKE_ERR_INSUFFICIENT_REFERENCE_VOTES                                           ( 9 )
#define FD_STAKE_ERR_VOTE_ADDRESS_MISMATCH                                                  ( 10 )
#define FD_STAKE_ERR_MINIMUM_DELIQUENT_EPOCHS_FOR_DEACTIVATION_NOT_MET                      ( 11 )
#define FD_STAKE_ERR_INSUFFICIENT_DELEGATION                                                ( 12 )
#define FD_STAKE_ERR_REDELEGATE_TRANSIENT_OR_INACTIVE_STAKE                                 ( 13 )
#define FD_STAKE_ERR_REDELEGATE_TO_SAME_VOTE_ACCOUNT                                        ( 14 )
#define FD_STAKE_ERR_REDELEGATED_STAKE_MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION_IS_PERMITTED ( 15 )

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

// https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/mod.rs#L12
#define MINIMUM_STAKE_DELEGATION                   ( 1 )
#define MINIMUM_DELEGATION_SOL                     ( 1 )
#define LAMPORTS_PER_SOL                           ( 1000000000 )
#define MERGE_KIND_INACTIVE                        ( 0 )
#define MERGE_KIND_ACTIVE_EPOCH                    ( 1 )
#define MERGE_KIND_FULLY_ACTIVE                    ( 2 )
#define MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION ( 5 )
#define DEFAULT_WARMUP_COOLDOWN_RATE               ( 0.25 )
#define NEW_WARMUP_COOLDOWN_RATE                   ( 0.09 )

#define STAKE_AUTHORIZE_STAKER                                                                     \
  ( ( fd_stake_authorize_t ){ .discriminant = fd_stake_authorize_enum_staker, .inner = { 0 } } )
#define STAKE_AUTHORIZE_WITHDRAWER                                                                 \
  ( ( fd_stake_authorize_t ){ .discriminant = fd_stake_authorize_enum_withdrawer, .inner = { 0 } } )

/**********************************************************************/
/* MergeKind                                                          */
/**********************************************************************/

struct merge_kind_inactive {
  fd_stake_meta_t  meta;
  ulong            active_stake;
  fd_stake_flags_t stake_flags;
};
typedef struct merge_kind_inactive merge_kind_inactive_t;

struct merge_kind_activation_epoch {
  fd_stake_meta_t  meta;
  fd_stake_t       stake;
  fd_stake_flags_t stake_flags;
};
typedef struct merge_kind_activation_epoch merge_kind_activation_epoch_t;

struct merge_kind_fully_active {
  fd_stake_meta_t meta;
  fd_stake_t      stake;
};
typedef struct merge_kind_fully_active merge_kind_fully_active_t;

union merge_kind_inner {
  merge_kind_inactive_t         inactive;
  merge_kind_activation_epoch_t activation_epoch;
  merge_kind_fully_active_t     fully_active;
};
typedef union merge_kind_inner merge_kind_inner_t;

struct merge_kind {
  uint               discriminant;
  merge_kind_inner_t inner;
};
typedef struct merge_kind merge_kind_t;

enum { merge_kind_inactive = 0, merge_kind_activation_epoch = 1, merge_kind_fully_active = 2 };

typedef fd_stake_history_entry_t stake_activation_status_t;

struct effective_activating {
  ulong effective;
  ulong activating;
};
typedef struct effective_activating effective_activating_t;

/**********************************************************************/
/* Bincode                                                            */
/**********************************************************************/

static int
get_state( fd_borrowed_account_t const * self,
           fd_valloc_t const *           valloc,
           fd_stake_state_v2_t *         out ) {
  int rc;

  fd_bincode_decode_ctx_t bincode_ctx;
  bincode_ctx.data    = self->const_data;
  bincode_ctx.dataend = self->const_data + self->const_meta->dlen;
  bincode_ctx.valloc  = *valloc;

  rc = fd_stake_state_v2_decode( out, &bincode_ctx );
  if( FD_UNLIKELY( rc != FD_BINCODE_SUCCESS ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  return FD_PROGRAM_OK;
}

static int
set_state( fd_borrowed_account_t const * self, fd_stake_state_v2_t const * state ) {
  int     rc;
  uchar * data            = self->data;
  ulong   serialized_size = fd_stake_state_v2_size( state );
  if( FD_UNLIKELY( serialized_size > self->meta->dlen ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }
  fd_bincode_encode_ctx_t ctx = {
      .data    = data,
      .dataend = data + serialized_size,
  };
  rc = fd_stake_state_v2_encode( state, &ctx );
  if( FD_UNLIKELY( rc != FD_BINCODE_SUCCESS ) ) return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  return FD_PROGRAM_OK;
}

static void
write_stake_config( fd_exec_slot_ctx_t * slot_ctx, fd_stake_config_t const * stake_config ) {

  ulong                   data_sz  = fd_stake_config_size( stake_config );
  fd_pubkey_t const *     acc_key  = &fd_solana_stake_program_config_id;
  fd_account_meta_t *     acc_meta = NULL;
  uchar *                 acc_data = NULL;
  fd_borrowed_account_t * acc      = NULL;
  int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, acc_key, 1, data_sz, acc );
  FD_TEST( !err );

  acc_meta                  = acc->meta;
  acc_data                  = acc->data;
  acc_meta->dlen            = data_sz;
  acc_meta->info.lamports   = 960480UL;
  acc_meta->info.rent_epoch = 0UL;
  acc_meta->info.executable = 0;

  fd_bincode_encode_ctx_t ctx3;
  ctx3.data    = acc_data;
  ctx3.dataend = acc_data + data_sz;
  if( fd_stake_config_encode( stake_config, &ctx3 ) )
    FD_LOG_ERR( ( "fd_stake_config_encode failed" ) );

  fd_memset( acc_data, 0, data_sz );
  fd_memcpy( acc_data, stake_config, sizeof( fd_stake_config_t ) );
}

/**********************************************************************/
/* mod stake                                                          */
/**********************************************************************/

static inline ulong
get_minimum_delegation( fd_exec_slot_ctx_t * feature_set /* feature set */ ) {
  return fd_ulong_if( FD_FEATURE_ACTIVE( feature_set, stake_raise_minimum_delegation_to_1_sol ),
                      MINIMUM_STAKE_DELEGATION * LAMPORTS_PER_SOL,
                      MINIMUM_STAKE_DELEGATION );
}

/**********************************************************************/
/* mod stake/state                                                    */
/**********************************************************************/

static inline double
warmup_cooldown_rate( ulong current_epoch, ulong * new_rate_activation_epoch ) {
  return fd_double_if( current_epoch <
                           ( new_rate_activation_epoch ? *new_rate_activation_epoch : ULONG_MAX ),
                       DEFAULT_WARMUP_COOLDOWN_RATE,
                       NEW_WARMUP_COOLDOWN_RATE );
}

/**********************************************************************/
/* validated                                                          */
/**********************************************************************/

struct validated_delegated_info {
  ulong stake_amount;
};
typedef struct validated_delegated_info validated_delegated_info_t;

static int
validate_delegated_amount( fd_borrowed_account_t *      account,
                           fd_stake_meta_t const *      meta,
                           fd_exec_slot_ctx_t *         feature_set,
                           validated_delegated_info_t * out,
                           uint *                       custom_err ) {
  ulong stake_amount = fd_ulong_sat_sub( account->meta->info.lamports, meta->rent_exempt_reserve );

  if( FD_UNLIKELY( stake_amount < get_minimum_delegation( feature_set ) ) ) {
    *custom_err = FD_STAKE_ERR_INSUFFICIENT_DELEGATION;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  out->stake_amount = stake_amount;
  return FD_PROGRAM_OK;
}

struct validated_split_info {
  ulong source_remaining_balance;
  ulong destination_rent_exempt_reserve;
};
typedef struct validated_split_info validated_split_info_t;

static int
validate_split_amount( fd_exec_instr_ctx_t *                   invoke_context,
                       fd_exec_txn_ctx_t const *               transaction_context,
                       FD_PARAM_UNUSED fd_instr_info_t const * instruction_context,
                       uchar                                   source_account_index,
                       uchar                                   destination_account_index,
                       ulong                                   lamports,
                       fd_stake_meta_t const *                 source_meta,
                       ulong                                   additional_required_lamports,
                       bool                                    source_is_active,
                       validated_split_info_t *                out ) {
  int rc;

  fd_borrowed_account_t * source_account = NULL;
  rc                                     = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, source_account_index, &source_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  ulong source_lamports = source_account->meta->info.lamports;

  fd_borrowed_account_t * destination_account = NULL;
  rc                                          = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, destination_account_index, &destination_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  ulong destination_lamports = destination_account->meta->info.lamports;
  ulong destination_data_len = destination_account->meta->dlen;

  if( FD_UNLIKELY( lamports == 0 ) ) return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  if( FD_UNLIKELY( lamports > source_lamports ) ) return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;

  ulong source_minimum_balance =
      fd_ulong_sat_add( source_meta->rent_exempt_reserve, additional_required_lamports );
  ulong source_remaining_balance = fd_ulong_sat_sub( source_lamports, lamports );
  // FIXME FD_LIKELY
  if( source_remaining_balance == 0 ) {
  } else if( source_remaining_balance < source_minimum_balance ) {
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  } else {
  };

  fd_rent_t rent = { 0 };
  rc             = fd_sysvar_rent_read( invoke_context->slot_ctx, &rent );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

  ulong destination_rent_exempt_reserve =
      fd_rent_exempt_minimum_balance2( &rent, destination_data_len );

  if( FD_UNLIKELY(
           FD_FEATURE_ACTIVE( invoke_context->slot_ctx, require_rent_exempt_split_destination ) &&
           source_is_active && source_remaining_balance != 0 &&
           destination_lamports < destination_rent_exempt_reserve ) ) {
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }

  ulong destination_minimum_balance =
      fd_ulong_sat_add( destination_rent_exempt_reserve, additional_required_lamports );
  ulong destination_balance_deficit =
      fd_ulong_sat_sub( destination_minimum_balance, destination_lamports );
  if( FD_UNLIKELY( lamports < destination_balance_deficit ) ) {
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }

  out->source_remaining_balance        = source_remaining_balance;
  out->destination_rent_exempt_reserve = destination_rent_exempt_reserve;
  return FD_PROGRAM_OK;
}

/**********************************************************************/
/* impl Lockup                                                        */
/**********************************************************************/

static inline bool
lockup_is_in_force( fd_stake_lockup_t const *     self,
                    fd_sol_sysvar_clock_t const * clock,
                    fd_pubkey_t const *           custodian ) {
  // FIXME FD_LIKELY
  if( custodian && 0 == memcmp( custodian, &self->custodian, sizeof( fd_pubkey_t ) ) ) {
    return false;
  }
  return self->unix_timestamp > clock->unix_timestamp || self->epoch > clock->epoch;
}

/**********************************************************************/
/* impl Authorized                                                    */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/state.rs#L291
static inline int
authorized_check( fd_stake_authorized_t const * self,
                  fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
                  fd_stake_authorize_t          stake_authorize ) {
  /* clang-format off */
  switch ( stake_authorize.discriminant ) {
  case fd_stake_authorize_enum_staker:
    if( FD_LIKELY( fd_instr_ctx_signers_contains( signers, &self->staker ) ) ) {
      return FD_PROGRAM_OK;
    }
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  case fd_stake_authorize_enum_withdrawer:
    if( FD_LIKELY( fd_instr_ctx_signers_contains( signers, &self->withdrawer ) ) ) {
      return FD_PROGRAM_OK;
    }
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  default:
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }
  /* clang-format on */
}

// https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/state.rs#L303
static int
authorized_authorize( fd_stake_authorized_t *                  self,
                      fd_pubkey_t const *                      signers[static FD_TXN_SIG_MAX],
                      fd_pubkey_t const *                      new_authorized,
                      fd_stake_authorize_t const *             stake_authorize,
                      fd_stake_lockup_custodian_args_t const * lockup_custodian_args,
                      /* out */ uint *                         custom_err ) {
  int rc;
  switch ( stake_authorize->discriminant ) {
  case fd_stake_authorize_enum_staker:
    if( FD_UNLIKELY( !fd_instr_ctx_signers_contains( signers, &self->staker ) &&
                      !fd_instr_ctx_signers_contains( signers, &self->withdrawer ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
    self->staker = *new_authorized;
    break;
  case fd_stake_authorize_enum_withdrawer:
    if( FD_LIKELY( lockup_custodian_args ) ) {
      fd_stake_lockup_t const *     lockup    = &lockup_custodian_args->lockup;
      fd_sol_sysvar_clock_t const * clock     = &lockup_custodian_args->clock;
      fd_pubkey_t const *           custodian = lockup_custodian_args->custodian;

      // FIXME FD_LIKELY
      if( lockup_is_in_force( lockup, clock, NULL ) ) {
        // https://github.com/firedancer-io/solana/blob/debug-master/sdk/program/src/stake/state.rs#L321-L334
        if( !custodian ) { // FIXME FD_LIKELY
          *custom_err = FD_STAKE_ERR_CUSTODIAN_MISSING;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        } else {
          if( FD_UNLIKELY( !fd_instr_ctx_signers_contains( signers, custodian ) ) ) {
            *custom_err = FD_STAKE_ERR_CUSTODIAN_SIGNATURE_MISSING;
            return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          }

          if( FD_UNLIKELY( lockup_is_in_force( lockup, clock, custodian ) ) ) {
            *custom_err = FD_STAKE_ERR_LOCKUP_IN_FORCE;
            return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          }
        }
      }
      rc = authorized_check( self, signers, *stake_authorize );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      self->withdrawer = *new_authorized;
    }
  }
  return FD_PROGRAM_OK;
}

/**********************************************************************/
/* impl Meta                                                          */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/state.rs#L366
static inline int
set_lockup_meta( fd_stake_meta_t *             self,
                 fd_lockup_args_t const *      lockup,
                 fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
                 fd_sol_sysvar_clock_t const * clock ) {
  // FIXME FD_LIKELY
  if( lockup_is_in_force( &self->lockup, clock, NULL ) ) {
    if( !fd_instr_ctx_signers_contains( signers, &self->lockup.custodian ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
  } else if( !fd_instr_ctx_signers_contains( signers, &self->authorized.withdrawer ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }
  if( lockup->unix_timestamp )
    // FIXME bincode doesn't support long -- check: is Labs also doing this cast?
    self->lockup.unix_timestamp = (long)( *lockup->unix_timestamp );
  if( lockup->epoch ) self->lockup.epoch = *lockup->epoch;
  if( lockup->custodian ) self->lockup.custodian = *lockup->custodian;
  return FD_PROGRAM_OK;
}

/**********************************************************************/
/* impl Delegation                                                    */
/**********************************************************************/

typedef fd_stake_history_entry_t fd_stake_activation_status_t;

// https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/state.rs#L558
static effective_activating_t
stake_and_activating( fd_delegation_t const *    self,
                      ulong                      target_epoch,
                      fd_stake_history_t const * history,
                      ulong *                    new_rate_activation_epoch ) {
  ulong delegated_stake = self->stake;

  fd_stake_history_entry_t const * cluster_stake_at_activation_epoch;
  // FIXME FD_LIKELY
  // https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/state.rs#L453
  if( self->activation_epoch == ULONG_MAX ) {
    return ( effective_activating_t ){ .effective = delegated_stake, .activating = 0 };
  } else if( self->activation_epoch == self->deactivation_epoch ) {
    return ( effective_activating_t ){ .effective = 0, .activating = 0 };
  } else if( target_epoch == self->activation_epoch ) {
    return ( effective_activating_t ){ .effective = 0, .activating = delegated_stake };
  } else if( target_epoch < self->activation_epoch ) {
    return ( effective_activating_t ){ .effective = 0, .activating = 0 };
  } else if( history &&
              ( cluster_stake_at_activation_epoch = fd_stake_history_treap_ele_query_const(
                    history->treap, self->activation_epoch, history->pool ) ) ) {
    ulong                            prev_epoch         = self->activation_epoch;
    fd_stake_history_entry_t const * prev_cluster_stake = cluster_stake_at_activation_epoch;

    ulong current_epoch;
    ulong current_effective_stake = 0;
    for ( ;; ) {
      current_epoch = prev_epoch + 1;
      if( FD_LIKELY( prev_cluster_stake->activating == 0 ) ) { // FIXME always optimize loop break?
        break;
      }

      ulong  remaining_activating_stake = delegated_stake - current_effective_stake;
      double weight = (double)remaining_activating_stake / (double)prev_cluster_stake->activating;
      double warmup_cooldown_rate_ =
          warmup_cooldown_rate( current_epoch, new_rate_activation_epoch );

      double newly_effective_cluster_stake =
          (double)prev_cluster_stake->effective * warmup_cooldown_rate_;
      ulong newly_effective_stake =
          fd_ulong_max( ( (ulong)( weight * newly_effective_cluster_stake ) ), 1 );

      current_effective_stake += newly_effective_stake;
      if( FD_LIKELY( current_effective_stake >= delegated_stake ) ) {
        current_effective_stake = delegated_stake;
        break;
      }

      if( FD_LIKELY( current_epoch >= target_epoch ||
                      current_epoch >=
                          self->deactivation_epoch ) ) { // FIXME always optimize loop break
        break;
      }

      fd_stake_history_entry_t const * current_cluster_stake =
          fd_stake_history_treap_ele_query_const( history->treap, current_epoch, history->pool );
      if( FD_UNLIKELY( current_cluster_stake = fd_stake_history_treap_ele_query_const(
                            history->treap, current_epoch, history->pool ) ) ) {
        prev_epoch         = current_epoch;
        prev_cluster_stake = current_cluster_stake;
      } else {
        // FIXME always optimize loop break
        break;
      }
    }
    return ( effective_activating_t ){ .effective  = current_effective_stake,
                                       .activating = delegated_stake - current_effective_stake };
  } else {
    return ( effective_activating_t ){ .effective = delegated_stake, .activating = 0 };
  }
}

static fd_stake_activation_status_t
stake_activating_and_deactivating( fd_delegation_t const *    self,
                                   ulong                      target_epoch,
                                   fd_stake_history_t const * stake_history,
                                   ulong *                    new_rate_activation_epoch ) {

  effective_activating_t effective_activating =
      stake_and_activating( self, target_epoch, stake_history, new_rate_activation_epoch );

  ulong effective_stake  = effective_activating.effective;
  ulong activating_stake = effective_activating.activating;

  fd_stake_history_entry_t * cluster_stake_at_activation_epoch = NULL;

  fd_stake_history_entry_t k;
  k.epoch = self->deactivation_epoch;

  if( target_epoch < self->deactivation_epoch ) {
    // if is bootstrap
    if( activating_stake == 0 ) {
      return ( fd_stake_history_entry_t ){
          .effective = effective_stake, .deactivating = 0, .activating = 0 };
    } else {
      return ( fd_stake_history_entry_t ){
          .effective = effective_stake, .deactivating = 0, .activating = activating_stake };
    }
  } else if( target_epoch == self->deactivation_epoch ) {
    return ( fd_stake_history_entry_t ){
        .effective = effective_stake, .deactivating = effective_stake, .activating = 0 };
  } else if( stake_history != NULL ) {
    fd_stake_history_entry_t * n =
        fd_stake_history_treap_ele_query( stake_history->treap, k.epoch, stake_history->pool );

    if( NULL != n ) { cluster_stake_at_activation_epoch = n; }

    if( cluster_stake_at_activation_epoch == NULL ) {
      fd_stake_history_entry_t entry = { .effective = 0, .activating = 0, .deactivating = 0 };

      return entry;
    }
    ulong                      prev_epoch         = self->deactivation_epoch;
    fd_stake_history_entry_t * prev_cluster_stake = cluster_stake_at_activation_epoch;

    ulong current_epoch;
    ulong current_effective_stake = effective_stake;
    for ( ;; ) {
      current_epoch = prev_epoch + 1;
      if( prev_cluster_stake->deactivating == 0 ) break;

      double weight = (double)current_effective_stake / (double)prev_cluster_stake->deactivating;
      double warmup_cooldown_rate_ =
          warmup_cooldown_rate( current_epoch, new_rate_activation_epoch );

      double newly_not_effective_cluster_stake =
          (double)prev_cluster_stake->effective * warmup_cooldown_rate_;
      ;
      ulong newly_not_effective_stake =
          fd_ulong_max( (ulong)( weight * newly_not_effective_cluster_stake ), 1 );

      current_effective_stake =
          fd_ulong_sat_sub( current_effective_stake, newly_not_effective_stake );
      if( current_effective_stake == 0 ) break;

      if( current_epoch >= target_epoch ) break;

      fd_stake_history_entry_t * current_cluster_stake = NULL;
      if( ( current_cluster_stake = fd_stake_history_treap_ele_query(
                 stake_history->treap, current_epoch, stake_history->pool ) ) ) {
        prev_epoch         = current_epoch;
        prev_cluster_stake = current_cluster_stake;
      } else {
        break;
      }
    }
    return ( fd_stake_history_entry_t ){ .effective    = current_effective_stake,
                                         .deactivating = current_effective_stake,
                                         .activating   = 0 };
  } else {
    return ( fd_stake_history_entry_t ){ .effective = 0, .activating = 0, .deactivating = 0 };
  }
}

static inline ulong
delegation_stake( fd_delegation_t const *    self,
                  ulong                      epoch,
                  fd_stake_history_t const * history,
                  ulong *                    new_rate_activation_epoch ) {
  return stake_activating_and_deactivating( self, epoch, history, new_rate_activation_epoch )
      .effective;
}

/**********************************************************************/
/* mod tools                                                          */
/**********************************************************************/

static inline bool
acceptable_reference_epoch_credits( fd_vote_epoch_credits_t * epoch_credits, ulong current_epoch ) {
  ulong len            = deq_fd_vote_epoch_credits_t_cnt( epoch_credits );
  ulong epoch_index[1] = { ULONG_MAX };
  // FIXME FD_LIKELY
  if( !__builtin_usubl_overflow( len, MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION, epoch_index ) ) {
    ulong epoch = current_epoch;
    for ( ulong i = len - 1; i >= *epoch_index; i-- ) {
      ulong vote_epoch = deq_fd_vote_epoch_credits_t_peek_index( epoch_credits, i )->epoch;
      if( vote_epoch != epoch ) { return false; }
      epoch = fd_ulong_sat_sub( epoch, 1 );
    }
    return true;
  } else {
    return false;
  };
}

static inline bool
eligible_for_deactivate_delinquent( fd_vote_epoch_credits_t * epoch_credits, ulong current_epoch ) {
  fd_vote_epoch_credits_t * last = deq_fd_vote_epoch_credits_t_peek_index(
      epoch_credits, deq_fd_vote_epoch_credits_t_cnt( epoch_credits ) - 1 );
  if( !last ) { // FIXME FD_LIKELY
    return true;
  } else {
    ulong * epoch         = &last->epoch;
    ulong   minimum_epoch = ULONG_MAX;
    bool    cf            = __builtin_usubl_overflow(
        current_epoch, MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION, &minimum_epoch );
    if( !cf ) { // FIXME FD_LIKELY
      return *epoch <= minimum_epoch;
    } else {
      return false;
    }
  }
}

/**********************************************************************/
/* impl StakeFlags                                                    */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/debug-master/sdk/program/src/stake/stake_flags.rs#L29
#define STAKE_FLAGS_MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION_IS_PERMITTED                           \
  ( ( fd_stake_flags_t ){ .bits = 1 } )

// https://github.com/firedancer-io/solana/blob/debug-master/sdk/program/src/stake/stake_flags.rs#L32
#define STAKE_FLAGS_EMPTY ( ( fd_stake_flags_t ){ .bits = 0 } )

/**********************************************************************/
/* impl Stake                                                         */
/**********************************************************************/

static int
stake_split( fd_stake_t * self,
             ulong        remaining_stake_delta,
             ulong        split_stake_amount,
             uint *       custom_err,
             fd_stake_t * out ) {
  if( FD_UNLIKELY( remaining_stake_delta > self->delegation.stake ) ) {
    *custom_err = FD_STAKE_ERR_INSUFFICIENT_STAKE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  self->delegation.stake -= remaining_stake_delta;
  fd_stake_t new;
  new                  = *self;
  new.delegation.stake = split_stake_amount;
  *out                 = new;
  return FD_PROGRAM_OK;
}

static int
stake_deactivate( fd_stake_t * self, ulong epoch, uint * custom_err ) {
  if( FD_UNLIKELY( self->delegation.deactivation_epoch != ULONG_MAX ) ) {
    *custom_err = FD_STAKE_ERR_ALREADY_DEACTIVATED;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  } else {
    self->delegation.deactivation_epoch = epoch;
    return FD_PROGRAM_OK;
  }
}

/**********************************************************************/
/* util                                                               */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/state.rs#L185
FD_FN_CONST static inline ulong
stake_state_v2_size_of( void ) {
  return 200;
}

FD_FN_CONST static inline ulong
next_power_of_two( ulong v ) {
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v++;
  return v;
}

FD_FN_CONST static inline ulong
trailing_zeros( ulong v ) {
  ulong c = 0;
  while( v % 2 == 0 ) {
    c++;
    v = v >> 1;
  }
  return c;
}

static inline ulong
get_epoch_from_schedule( fd_epoch_schedule_t * epoch_schedule, ulong slot ) {
  const ulong MINIMUM_SLOTS_PER_EPOCH = 32;
  if( slot < epoch_schedule->first_normal_slot ) {
    ulong epoch = fd_ulong_sat_add( slot, MINIMUM_SLOTS_PER_EPOCH );
    epoch       = fd_ulong_sat_add( epoch, 1 );
    epoch       = next_power_of_two( epoch );
    epoch       = trailing_zeros( epoch );
    epoch       = fd_ulong_sat_sub( epoch, trailing_zeros( MINIMUM_SLOTS_PER_EPOCH ) );
    epoch       = fd_ulong_sat_sub( epoch, 1 );
    return epoch;
  } else {
    ulong normal_slot_index = fd_ulong_sat_sub( slot, epoch_schedule->first_normal_slot );
    ulong normal_epoch_index =
        epoch_schedule->slots_per_epoch ? normal_slot_index / epoch_schedule->slots_per_epoch : 0;
    return fd_ulong_sat_add( epoch_schedule->first_normal_epoch, normal_epoch_index );
  }
}

// https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L99
static inline bool
new_warmup_cooldown_rate_epoch( fd_exec_instr_ctx_t * invoke_context,
                                /* out */ ulong *     epoch ) {
  if( FD_FEATURE_ACTIVE( invoke_context->slot_ctx, reduce_stake_warmup_cooldown ) ) {
    fd_epoch_schedule_t epoch_schedule;
    fd_sysvar_epoch_schedule_read( invoke_context->slot_ctx, &epoch_schedule );
    ulong slot = invoke_context->epoch_ctx->features.reduce_stake_warmup_cooldown;
    *epoch     = get_epoch_from_schedule( &epoch_schedule, slot );
    return true;
  }
  return false;
}

/**********************************************************************/
/* impl MergeKind                                                     */
/**********************************************************************/

static fd_stake_meta_t const *
meta( merge_kind_t const * self ) {
  switch ( self->discriminant ) {
  case merge_kind_inactive:
    return &self->inner.inactive.meta;
  case merge_kind_activation_epoch:
    return &self->inner.activation_epoch.meta;
  case merge_kind_fully_active:
    return &self->inner.fully_active.meta;
  default:
    FD_LOG_ERR( ( "invalid merge_kind_t discriminant" ) );
  }
}

static fd_stake_t const *
active_stake( merge_kind_t const * self ) {
  switch ( self->discriminant ) {
  case merge_kind_inactive:
    return NULL;
  case merge_kind_activation_epoch:
    return &self->inner.activation_epoch.stake;
  case merge_kind_fully_active:
    return &self->inner.fully_active.stake;
  default:
    FD_LOG_ERR( ( "invalid merge_kind_t discriminant" ) );
  }
}

static int
get_if_mergeable( fd_exec_instr_ctx_t *         invoke_context,
                  fd_stake_state_v2_t const *   stake_state,
                  ulong                         stake_lamports,
                  fd_sol_sysvar_clock_t const * clock,
                  fd_stake_history_t const *    stake_history,
                  merge_kind_t *                out,
                  uint *                        custom_err ) {
  // stake_history must be non-NULL
  // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L1295
  switch ( stake_state->discriminant ) {
  case fd_stake_state_v2_enum_stake: {
    fd_stake_meta_t const *  meta        = &stake_state->inner.stake.meta;
    fd_stake_t const *       stake       = &stake_state->inner.stake.stake;
    fd_stake_flags_t const * stake_flags = &stake_state->inner.stake.stake_flags;

    ulong new_rate_activation_epoch = ULONG_MAX;
    bool  is_some = new_warmup_cooldown_rate_epoch( invoke_context, &new_rate_activation_epoch );
    fd_stake_history_entry_t status =
        stake_activating_and_deactivating( &stake->delegation,
                                           clock->epoch,
                                           stake_history,
                                           fd_ptr_if( is_some, &new_rate_activation_epoch, NULL ) );

    // FIXME FD_LIKELY
    if( status.effective == 0 && status.activating == 0 && status.deactivating == 0 ) {

      *out = ( merge_kind_t ){ .discriminant = merge_kind_inactive,
                               .inner        = { .inactive = { .meta         = *meta,
                                                               .active_stake = stake_lamports,
                                                               .stake_flags  = *stake_flags } } };
      return FD_PROGRAM_OK;
    } else if( status.effective == 0 ) {
      *out = ( merge_kind_t ){ .discriminant = merge_kind_activation_epoch,
                               .inner        = { .activation_epoch = { .meta        = *meta,
                                                                       .stake       = *stake,
                                                                       .stake_flags = *stake_flags } } };
      return FD_PROGRAM_OK;
    } else if( status.activating == 0 && status.deactivating == 0 ) {
      *out = ( merge_kind_t ){ .discriminant = merge_kind_fully_active,
                               .inner = { .fully_active = { .meta = *meta, .stake = *stake } } };
      return FD_PROGRAM_OK;
    } else {
      *custom_err = FD_STAKE_ERR_MERGE_TRANSIENT_STAKE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    break;
  }
  case fd_stake_state_v2_enum_initialized: {
    *out = ( merge_kind_t ){
        .discriminant = merge_kind_inactive,
        .inner =
            {
                    .inactive =
                    {
                        .meta         = stake_state->inner.initialized.meta,
                        .active_stake = stake_lamports,
                        .stake_flags  = { 0 }, /* StakeFlags::empty() */
                    }, },
    };
    break;
  }

  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return FD_PROGRAM_OK;
}

static int
metas_can_merge( FD_FN_UNUSED fd_exec_instr_ctx_t const * invoke_context,
                 fd_stake_meta_t const *                  stake,
                 fd_stake_meta_t const *                  source,
                 fd_sol_sysvar_clock_t const *            clock,
                 uint *                                   custom_err ) {
  bool can_merge_lockups =
      ( 0==memcmp( &stake->lockup, &source->lockup, sizeof( fd_stake_meta_t ) ) ) ||
      ( !lockup_is_in_force( &stake->lockup, clock, NULL ) &&
        !lockup_is_in_force( &source->lockup, clock, NULL ) );

  if( 0==memcmp( &stake->authorized, &source->authorized, sizeof( fd_stake_authorized_t ) ) &&
       can_merge_lockups ) {
    return FD_PROGRAM_OK;
  } else {
    FD_DEBUG( FD_LOG_WARNING(( "Unable to merge due to metadata mismatch" )) );
    *custom_err = FD_STAKE_ERR_MERGE_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
}

static int
active_delegations_can_merge( FD_FN_UNUSED fd_exec_instr_ctx_t const * invoke_context,
                              fd_delegation_t const *                  stake,
                              fd_delegation_t const *                  source,
                              uint *                                   custom_err ) {
  if( 0 != memcmp( &stake->voter_pubkey, &source->voter_pubkey, sizeof( fd_pubkey_t ) ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "Unable to merge due to voter mismatch" )) );
    *custom_err = FD_STAKE_ERR_MERGE_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  } else if( FD_LIKELY( stake->deactivation_epoch == ULONG_MAX &&
                         source->deactivation_epoch == ULONG_MAX ) ) {
    return FD_PROGRAM_OK;
  } else {
    FD_DEBUG( FD_LOG_WARNING(( "Unable to merge due to stake deactivation" )) );
    *custom_err = FD_STAKE_ERR_MERGE_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
}

static int
active_stakes_can_merge( FD_FN_UNUSED fd_exec_instr_ctx_t const * invoke_context,
                         fd_stake_t const *                       stake,
                         fd_stake_t const *                       source,
                         uint *                                   custom_err ) {
  int rc;
  rc = active_delegations_can_merge(
      invoke_context, &stake->delegation, &source->delegation, custom_err );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  if( FD_LIKELY( stake->credits_observed == source->credits_observed ) ) {
    return FD_PROGRAM_OK;
  } else {
    FD_DEBUG( FD_LOG_WARNING(( "Unable to merge due to credits observed mismatch" )) );
    *custom_err = FD_STAKE_ERR_MERGE_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
}

static bool
stake_weighted_credits_observed( fd_stake_t const * stake,
                                 ulong              absorbed_lamports,
                                 ulong              absorbed_credits_observed,
                                 ulong *            out ) {
  // int rc;

  // FIXME FD_LIKELY
  if( stake->credits_observed == absorbed_credits_observed ) {
    *out = stake->credits_observed;
    return true;
  } else {
    // TODO need to do this properly using `fd_uwide`
    ulong total_stake               = stake->delegation.stake + absorbed_lamports;
    ulong stake_weighted_credits    = stake->credits_observed * stake->delegation.stake;
    ulong absorbed_weighted_credits = absorbed_credits_observed * absorbed_lamports;
    ulong total_weighted_credits =
        stake_weighted_credits + absorbed_weighted_credits + total_stake - 1;
    *out = total_weighted_credits / total_stake;
    return true;
  }
}

// https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L1456
static int
merge_delegation_stake_and_credits_observed( fd_exec_instr_ctx_t const * invoke_context,
                                             fd_stake_t *                stake,
                                             ulong                       absorbed_lamports,
                                             ulong absorbed_credits_observed ) {
  int rc;
  if( FD_FEATURE_ACTIVE( invoke_context->slot_ctx,
                          stake_merge_with_unmatched_credits_observed ) ) {
    bool is_some = stake_weighted_credits_observed(
        stake, absorbed_lamports, absorbed_credits_observed, &stake->credits_observed );
    if( FD_UNLIKELY( !is_some ) ) return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }
  rc = fd_instr_checked_add( stake->delegation.stake, absorbed_lamports, &stake->delegation.stake );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  return FD_PROGRAM_OK;
}

static int
merge_kind_merge( merge_kind_t                  self,
                  fd_exec_instr_ctx_t const *   invoke_context,
                  merge_kind_t                  source,
                  fd_sol_sysvar_clock_t const * clock,
                  fd_stake_state_v2_t *         out,
                  bool *                        is_some,
                  uint *                        custom_err ) {
  int rc;

  rc = metas_can_merge( invoke_context, meta( &self ), meta( &source ), clock, custom_err );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  fd_stake_t const * stake   = active_stake( &self );
  fd_stake_t const * source_ = active_stake( &source );

  // FIXME FD_LIKELY
  if( stake && source_ ) {
    if( FD_FEATURE_ACTIVE( invoke_context->slot_ctx,
                            stake_merge_with_unmatched_credits_observed ) ) {
      rc = active_delegations_can_merge(
          invoke_context, &stake->delegation, &source_->delegation, custom_err );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    } else {
      rc = active_stakes_can_merge( invoke_context, stake, source_, custom_err );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    }
  }

  // FIXME FD_LIKELY
  fd_stake_state_v2_t   merged_state_ = { 0 };
  fd_stake_state_v2_t * merged_state  = &merged_state_;
  if( self.discriminant == merge_kind_inactive && source.discriminant == merge_kind_inactive ) {
    merged_state = NULL;
  } else if( self.discriminant == merge_kind_inactive &&
              source.discriminant == merge_kind_activation_epoch ) {
    merged_state = NULL;
  } else if( self.discriminant == merge_kind_activation_epoch &&
              source.discriminant == merge_kind_inactive ) {
    fd_stake_meta_t meta            = self.inner.activation_epoch.meta;
    fd_stake_t      stake           = self.inner.activation_epoch.stake;
    ulong           source_lamports = source.inner.inactive.active_stake;
    rc = fd_instr_checked_add( stake.delegation.stake, source_lamports, &stake.delegation.stake );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    *merged_state = ( fd_stake_state_v2_t ){
        .discriminant = fd_stake_state_v2_enum_stake,
        .inner        = { .stake = { .meta        = meta,
                                     .stake       = stake,
                                     .stake_flags = self.inner.activation_epoch.stake_flags } } };
  } else if( self.discriminant == merge_kind_activation_epoch &&
              source.discriminant == merge_kind_activation_epoch ) {
    fd_stake_meta_t  meta               = self.inner.activation_epoch.meta;
    fd_stake_t       stake              = self.inner.activation_epoch.stake;
    fd_stake_flags_t stake_flags        = self.inner.activation_epoch.stake_flags;
    fd_stake_meta_t  source_meta        = source.inner.activation_epoch.meta;
    fd_stake_t       source_stake       = source.inner.activation_epoch.stake;
    fd_stake_flags_t source_stake_flags = source.inner.activation_epoch.stake_flags;

    ulong source_lamports = ULONG_MAX;
    rc                    = fd_instr_checked_add(
        source_meta.rent_exempt_reserve, source_stake.delegation.stake, &source_lamports );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    rc = merge_delegation_stake_and_credits_observed(
        invoke_context, &stake, source_lamports, source_stake.credits_observed );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    *merged_state = ( fd_stake_state_v2_t ){
        .discriminant = fd_stake_state_v2_enum_stake,
        .inner        = {
                   .stake = { .meta        = meta,
                              .stake       = stake,
                              .stake_flags = { .bits = stake_flags.bits | source_stake_flags.bits } } } };
  } else if( self.discriminant == merge_kind_fully_active &&
              source.discriminant == merge_kind_fully_active ) {
    fd_stake_meta_t meta         = self.inner.fully_active.meta;
    fd_stake_t      stake        = self.inner.fully_active.stake;
    fd_stake_t      source_stake = source.inner.fully_active.stake;
    rc                           = merge_delegation_stake_and_credits_observed(
        invoke_context, &stake, source_stake.delegation.stake, source_stake.credits_observed );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    *merged_state = ( fd_stake_state_v2_t ){
        .discriminant = fd_stake_state_v2_enum_stake,
        .inner = { .stake = { .meta = meta, .stake = stake, .stake_flags = STAKE_FLAGS_EMPTY } } };
  } else {
    *custom_err = FD_STAKE_ERR_MERGE_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  if( !merged_state ) {
    *is_some = false;
    return FD_PROGRAM_OK;
  }
  *is_some = true;
  *out     = *merged_state;
  return FD_PROGRAM_OK;
}

/**********************************************************************/
/* mod stake_state                                                    */
/**********************************************************************/

static int
get_stake_status( fd_exec_instr_ctx_t *          invoke_context,
                  fd_stake_t *                   stake,
                  fd_sol_sysvar_clock_t const *  clock,
                  fd_stake_activation_status_t * out ) {
  fd_stake_history_t stake_history = { 0 };
  int                rc;
  rc = fd_sysvar_stake_history_read( invoke_context->slot_ctx, &stake_history );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  ulong new_rate_activation_epoch = ULONG_MAX;
  bool  is_some = new_warmup_cooldown_rate_epoch( invoke_context, &new_rate_activation_epoch );
  *out =
      stake_activating_and_deactivating( &stake->delegation,
                                         clock->epoch,
                                         &stake_history,
                                         fd_ptr_if( is_some, &new_rate_activation_epoch, NULL ) );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  return OK;
}

static int
redelegate_stake( fd_exec_instr_ctx_t *         invoke_context,
                  fd_stake_t *                  stake,
                  ulong                         stake_lamports,
                  fd_pubkey_t const *           voter_pubkey,
                  fd_vote_state_t const *       vote_state,
                  fd_sol_sysvar_clock_t const * clock,
                  fd_stake_history_t const *    stake_history,
                  uint *                        custom_err ) {
  ulong new_rate_activation_epoch = ULONG_MAX;
  bool  is_some = new_warmup_cooldown_rate_epoch( invoke_context, &new_rate_activation_epoch );

  // FIXME FD_LIKELY
  // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L120
  if( stake_activating_and_deactivating( &stake->delegation,
                                          clock->epoch,
                                          stake_history,
                                          fd_ptr_if( is_some, &new_rate_activation_epoch, NULL ) )
           .effective != 0 ) {
    bool stake_lamports_FD_PROGRAM_OK;
    // FIXME FD_LIKELY
    if( FD_FEATURE_ACTIVE( invoke_context->slot_ctx, stake_redelegate_instruction ) ) {
      stake_lamports_FD_PROGRAM_OK = stake_lamports >= stake->delegation.stake;
    } else {
      stake_lamports_FD_PROGRAM_OK = true;
    }

    // FIXME FD_LIKELY
    if( 0 == memcmp( &stake->delegation.voter_pubkey, voter_pubkey, sizeof( fd_pubkey_t ) ) &&
         clock->epoch == stake->delegation.deactivation_epoch && stake_lamports_FD_PROGRAM_OK ) {
      stake->delegation.deactivation_epoch = ULONG_MAX;
      return FD_PROGRAM_OK;
    } else {
      *custom_err = FD_STAKE_ERR_TOO_SOON_TO_REDELEGATE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  }

  stake->delegation.stake              = stake_lamports;
  stake->delegation.activation_epoch   = clock->epoch;
  stake->delegation.deactivation_epoch = ULONG_MAX;
  stake->delegation.voter_pubkey       = *voter_pubkey;
  stake->credits_observed =
      ( deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits )
            ? 0
            : deq_fd_vote_epoch_credits_t_peek_index(
                  vote_state->epoch_credits,
                  deq_fd_vote_epoch_credits_t_cnt( vote_state->epoch_credits ) - 1 )
                  ->credits );
  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L160
static fd_stake_t
new_stake( ulong                   stake,
           fd_pubkey_t const *     voter_pubkey,
           fd_vote_state_t const * vote_state,
           ulong                   activation_epoch ) {
  // https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/vote/state/mod.rs#L512
  ulong credits = ( deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits )
                        ? 0
                        : deq_fd_vote_epoch_credits_t_peek_index(
                              vote_state->epoch_credits,
                              deq_fd_vote_epoch_credits_t_cnt( vote_state->epoch_credits ) - 1 )
                              ->credits );
  // https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/state.rs#L438
  return ( fd_stake_t ){
      .delegation       = {.voter_pubkey         = *voter_pubkey,
                           .stake                = stake,
                           .activation_epoch     = activation_epoch,
                           .deactivation_epoch   = ULONG_MAX,
                           .warmup_cooldown_rate = DEFAULT_WARMUP_COOLDOWN_RATE},
      .credits_observed = credits,
  };
}

// https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L466
static int
initialize( fd_borrowed_account_t const * stake_account,
            fd_stake_authorized_t const * authorized,
            fd_stake_lockup_t const *     lockup,
            fd_rent_t const *             rent,
            fd_valloc_t const *           valloc ) {
  int rc;
  if( FD_UNLIKELY( stake_account->meta->dlen != stake_state_v2_size_of() ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  fd_stake_state_v2_t stake_state = { 0 };
  rc                              = get_state( stake_account, valloc, &stake_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  if( FD_LIKELY( stake_state.discriminant == fd_stake_state_v2_enum_uninitialized ) ) {
    ulong rent_exempt_reserve = fd_rent_exempt_minimum_balance2( rent, stake_account->meta->dlen );
    if( FD_LIKELY( stake_account->meta->info.lamports >= rent_exempt_reserve ) ) {
      fd_stake_state_v2_t initialized                        = { 0 };
      initialized.discriminant                               = fd_stake_state_v2_enum_initialized;
      initialized.inner.initialized.meta.rent_exempt_reserve = rent_exempt_reserve;
      initialized.inner.initialized.meta.authorized          = *authorized;
      initialized.inner.initialized.meta.lockup              = *lockup;
      return set_state( stake_account, &initialized );
    } else {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }
  } else {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
}

// https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L494
static int
authorize( fd_borrowed_account_t *       stake_account,
           fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
           fd_pubkey_t const *           new_authority,
           fd_stake_authorize_t const *  stake_authorize,
           bool                          require_custodian_for_locked_stake_authorize,
           fd_sol_sysvar_clock_t const * clock,
           fd_pubkey_t const *           custodian,
           fd_valloc_t const *           valloc,
           uint *                        custom_err ) {
  int                 rc;
  fd_stake_state_v2_t stake_state = { 0 };
  rc                              = get_state( stake_account, valloc, &stake_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  switch ( stake_state.discriminant ) {
  /* FIXME check if the compiler can optimize away branching (given the layout of `meta` in both
   * union members) and instead fallthrough */
  case fd_stake_state_v2_enum_stake: {
    fd_stake_meta_t * meta = &stake_state.inner.stake.meta;

    fd_stake_lockup_custodian_args_t lockup_custodian_args = {
        .lockup = meta->lockup, .clock = *clock, .custodian = (fd_pubkey_t *)custodian };
    rc = authorized_authorize(
        &meta->authorized, /* &mut self */
        signers,
        new_authority,
        stake_authorize,
        fd_ptr_if( require_custodian_for_locked_stake_authorize, &lockup_custodian_args, NULL ),
        custom_err );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    return set_state( stake_account, &stake_state );
  }
  case fd_stake_state_v2_enum_initialized: {
    fd_stake_meta_t * meta = &stake_state.inner.initialized.meta;

    fd_stake_lockup_custodian_args_t lockup_custodian_args = {
        .lockup = meta->lockup, .clock = *clock, .custodian = (fd_pubkey_t *)custodian };
    rc = authorized_authorize(
        &meta->authorized,
        signers,
        new_authority,
        stake_authorize,
        fd_ptr_if( require_custodian_for_locked_stake_authorize, &lockup_custodian_args, NULL ),
        custom_err );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    return set_state( stake_account, &stake_state );
  }
  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return rc;
}

// https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L535
static int
authorize_with_seed( fd_exec_txn_ctx_t *          transaction_context,
                     fd_instr_info_t const *      instruction_context,
                     fd_borrowed_account_t *      stake_account,
                     uchar                        authority_base_index,
                     char const *                 authority_seed,
                     fd_pubkey_t const *          authority_owner,
                     fd_pubkey_t const *          new_authority,
                     fd_stake_authorize_t const * stake_authorize,
                     bool                         require_custodian_for_locked_stake_authorize,
                     fd_sol_sysvar_clock_t *      clock,
                     fd_pubkey_t const *          custodian,
                     fd_valloc_t const *          valloc ) {
  int                 rc;
  fd_pubkey_t const * signers[FD_TXN_SIG_MAX] = { 0 };
  fd_pubkey_t         out                     = { 0 };
  if( FD_LIKELY( fd_instr_acc_is_signer_idx( instruction_context, authority_base_index ) ) ) {

    // https://github.com/firedancer-io/solana/blob/debug-master/programs/stake/src/stake_state.rs#L550-L553
    fd_pubkey_t base_pubkey          = { 0 };
    uchar       index_in_transaction = FD_TXN_ACCT_ADDR_MAX;
    rc                               = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
        instruction_context, authority_base_index, &index_in_transaction );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    rc = fd_txn_ctx_get_key_of_account_at_index(
        transaction_context, index_in_transaction, &base_pubkey );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    // https://github.com/firedancer-io/solana/blob/debug-master/programs/stake/src/stake_state.rs#L554-L558
    rc = fd_pubkey_create_with_seed( base_pubkey.uc,
                                     authority_seed,
                                     strlen( authority_seed ),
                                     authority_owner->uc,
                                     /* out */ out.uc );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    signers[0] = &out;
  }
  return authorize( stake_account,
                    signers,
                    new_authority,
                    stake_authorize,
                    require_custodian_for_locked_stake_authorize,
                    clock,
                    custodian,
                    valloc,
                    &transaction_context->custom_err );
}

static int
delegate( fd_exec_instr_ctx_t *                   invoke_context,
          fd_exec_txn_ctx_t const *               transaction_context,
          FD_PARAM_UNUSED fd_instr_info_t const * instruction_context,
          uchar                                   stake_account_index,
          uchar                                   vote_account_index,
          fd_sol_sysvar_clock_t const *           clock,
          fd_stake_history_t *                    stake_history,
          fd_pubkey_t const *                     signers[static FD_TXN_SIG_MAX],
          fd_valloc_t *                           valloc ) {
  int rc;

  fd_borrowed_account_t * vote_account = NULL;
  rc                                   = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, vote_account_index, &vote_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  if( FD_UNLIKELY(
           0 != memcmp( &vote_account->meta->info.owner, fd_solana_vote_program_id.key, 32UL ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
  }

  fd_pubkey_t const *       vote_pubkey = vote_account->pubkey;
  fd_vote_state_versioned_t vote_state  = { 0 };
  rc = fd_vote_get_state( vote_account, *invoke_context, &vote_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  fd_borrowed_account_t * stake_account = NULL;
  rc                                    = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, stake_account_index, &stake_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  fd_stake_state_v2_t stake_state = { 0 };
  rc                              = get_state( stake_account, valloc, &stake_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  switch ( stake_state.discriminant ) {
  case fd_stake_state_v2_enum_initialized: {
    fd_stake_meta_t meta = stake_state.inner.initialized.meta;
    rc                   = authorized_check( &meta.authorized, signers, STAKE_AUTHORIZE_STAKER );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    validated_delegated_info_t validated_delegated_info;
    rc = validate_delegated_amount( stake_account,
                                    &meta,
                                    invoke_context->slot_ctx,
                                    &validated_delegated_info,
                                    &invoke_context->txn_ctx->custom_err );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    ulong stake_amount = validated_delegated_info.stake_amount;

    fd_vote_convert_to_current( &vote_state, *invoke_context ); // FIXME
    fd_stake_t stake =
        new_stake( stake_amount, vote_pubkey, &vote_state.inner.current, clock->epoch );
    fd_stake_state_v2_t new_stake_state = { .discriminant = fd_stake_state_v2_enum_stake,
                                            .inner        = { .stake = {
                                                                  .meta        = meta,
                                                                  .stake       = stake,
                                                                  .stake_flags = STAKE_FLAGS_EMPTY,
                                                       } } };
    return set_state( stake_account, &new_stake_state );
  }
  case fd_stake_state_v2_enum_stake: {
    fd_stake_meta_t  meta        = stake_state.inner.stake.meta;
    fd_stake_t       stake       = stake_state.inner.stake.stake;
    fd_stake_flags_t stake_flags = stake_state.inner.stake.stake_flags;
    rc = authorized_check( &meta.authorized, signers, STAKE_AUTHORIZE_STAKER );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    validated_delegated_info_t validated_delegated_info;
    rc = validate_delegated_amount( stake_account,
                                    &meta,
                                    invoke_context->slot_ctx,
                                    &validated_delegated_info,
                                    &invoke_context->txn_ctx->custom_err );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    ulong stake_amount = validated_delegated_info.stake_amount;
    fd_vote_convert_to_current( &vote_state, *invoke_context );
    rc = redelegate_stake( invoke_context,
                           &stake,
                           stake_amount,
                           vote_pubkey,
                           &vote_state.inner.current,
                           clock,
                           stake_history,
                           &invoke_context->txn_ctx->custom_err );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    fd_stake_state_v2_t new_stake_state = { .discriminant = fd_stake_state_v2_enum_stake,
                                            .inner        = { .stake = {
                                                                  .meta        = meta,
                                                                  .stake       = stake,
                                                                  .stake_flags = stake_flags,
                                                       } } };
    return set_state( stake_account, &new_stake_state );
  }
  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
}

static int
deactivate( fd_borrowed_account_t *       stake_account,
            fd_sol_sysvar_clock_t const * clock,
            fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
            fd_valloc_t const *           valloc,
            uint *                        custom_err ) {
  int rc;

  fd_stake_state_v2_t state = { 0 };
  rc                        = get_state( stake_account, valloc, &state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  if( state.discriminant == fd_stake_state_v2_enum_stake ) {
    fd_stake_meta_t * meta  = &state.inner.stake.meta;
    fd_stake_t *      stake = &state.inner.stake.stake;

    rc = authorized_check( &meta->authorized, signers, STAKE_AUTHORIZE_STAKER );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    rc = stake_deactivate( stake, clock->epoch, custom_err );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    return set_state( stake_account, &state );
  } else {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
}

static int
set_lockup( fd_borrowed_account_t *       stake_account,
            fd_lockup_args_t const *      lockup,
            fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
            fd_sol_sysvar_clock_t const * clock,
            fd_valloc_t const *           valloc ) {
  int rc;

  fd_stake_state_v2_t state = { 0 };
  rc                        = get_state( stake_account, valloc, &state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  switch ( state.discriminant ) {
  case fd_stake_state_v2_enum_initialized: {
    fd_stake_meta_t * meta = &state.inner.initialized.meta;
    rc                     = set_lockup_meta( meta, lockup, signers, clock );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    return set_state( stake_account, &state );
  }
  case fd_stake_state_v2_enum_stake: {
    fd_stake_meta_t * meta = &state.inner.stake.meta;
    rc                     = set_lockup_meta( meta, lockup, signers, clock );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    return set_state( stake_account, &state );
  }
  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
}

static int
split( fd_exec_instr_ctx_t *     invoke_context,
       fd_exec_txn_ctx_t const * transaction_context,
       fd_instr_info_t const *   instruction_context,
       uchar                     stake_account_index,
       ulong                     lamports,
       uchar                     split_index,
       fd_pubkey_t const *       signers[static FD_TXN_SIG_MAX] ) {
  int rc;

  fd_borrowed_account_t * split = NULL;
  rc                            = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, split_index, &split );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  if( FD_UNLIKELY( 0 !=
                    memcmp( &split->meta->info.owner, fd_solana_stake_program_id.key, 32UL ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
  }

  if( FD_UNLIKELY( split->meta->dlen != stake_state_v2_size_of() ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  fd_stake_state_v2_t split_get_state = { 0 };
  rc = get_state( split, &invoke_context->valloc, &split_get_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  if( !FD_UNLIKELY( split_get_state.discriminant == fd_stake_state_v2_enum_uninitialized ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  ulong split_lamport_balance = split->meta->info.lamports;

  fd_borrowed_account_t * stake_account = NULL;
  rc                                    = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, stake_account_index, &stake_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  if( FD_UNLIKELY( lamports > stake_account->meta->info.lamports ) ) {
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }

  fd_stake_state_v2_t stake_state = { 0 };
  rc = get_state( stake_account, &invoke_context->valloc, &stake_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  switch ( stake_state.discriminant ) {
  case fd_stake_state_v2_enum_stake: {
    fd_stake_meta_t *  meta        = &stake_state.inner.stake.meta;
    fd_stake_t *       stake       = &stake_state.inner.stake.stake;
    fd_stake_flags_t * stake_flags = &stake_state.inner.stake.stake_flags;

    rc = authorized_check( &meta->authorized, signers, STAKE_AUTHORIZE_STAKER );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    ulong minimum_delegation = get_minimum_delegation( invoke_context->slot_ctx );
    bool  is_active;
    if( FD_UNLIKELY( FD_FEATURE_ACTIVE( invoke_context->slot_ctx,
                                         require_rent_exempt_split_destination ) ) ) {
      fd_sol_sysvar_clock_t clock = { 0 };
      rc                          = fd_sysvar_clock_read( invoke_context->slot_ctx, &clock );
      if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) {
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
      }

      fd_stake_activation_status_t status = { 0 };
      rc = get_stake_status( invoke_context, stake, &clock, &status );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      is_active = status.effective > 0;
    } else {
      is_active = false;
    }

    validated_split_info_t validated_split_info = { 0 };
    rc                                          = validate_split_amount( invoke_context,
                                transaction_context,
                                instruction_context,
                                stake_account_index,
                                split_index,
                                lamports,
                                meta,
                                minimum_delegation,
                                is_active,
                                &validated_split_info );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L710-L744
    ulong remaining_stake_delta;
    ulong split_stake_amount;
    // FIXME FD_LIKELY
    if( validated_split_info.source_remaining_balance == 0 ) {
      remaining_stake_delta = fd_ulong_sat_sub( lamports, meta->rent_exempt_reserve );
      split_stake_amount    = remaining_stake_delta;
    } else {
      if( FD_UNLIKELY( fd_ulong_sat_sub( stake->delegation.stake, lamports ) <
                        minimum_delegation ) ) {
        invoke_context->txn_ctx->custom_err = FD_STAKE_ERR_INSUFFICIENT_DELEGATION;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }

      remaining_stake_delta = lamports;
      split_stake_amount =
          fd_ulong_sat_sub( lamports,
                            fd_ulong_sat_sub( validated_split_info.destination_rent_exempt_reserve,
                                              split_lamport_balance )

          );
    }

    if( FD_UNLIKELY( split_stake_amount < minimum_delegation ) ) {
      invoke_context->txn_ctx->custom_err = FD_STAKE_ERR_INSUFFICIENT_DELEGATION;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    fd_stake_t split_stake = { 0 };
    rc                     = stake_split( stake,
                      remaining_stake_delta,
                      split_stake_amount,
                      &invoke_context->txn_ctx->custom_err,
                      &split_stake );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    fd_stake_meta_t split_meta     = *meta;
    split_meta.rent_exempt_reserve = validated_split_info.destination_rent_exempt_reserve;

    fd_borrowed_account_t * stake_account = NULL;
    rc                                    = fd_instr_ctx_try_borrow_instruction_account(
        invoke_context, transaction_context, stake_account_index, &stake_account );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    rc = set_state( stake_account, &stake_state );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_borrowed_account_t * split = NULL;
    rc                            = fd_instr_ctx_try_borrow_instruction_account(
        invoke_context, transaction_context, split_index, &split );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    fd_stake_state_v2_t temp = { .discriminant = fd_stake_state_v2_enum_stake,
                                 .inner        = { .stake = {
                                                       .meta        = split_meta,
                                                       .stake       = split_stake,
                                                       .stake_flags = *stake_flags,
                                            } } };
    rc                       = set_state( split, &temp );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    break;
  }
  case fd_stake_state_v2_enum_initialized: {
    fd_stake_meta_t * meta = &stake_state.inner.initialized.meta;
    rc                     = authorized_check( &meta->authorized, signers, STAKE_AUTHORIZE_STAKER );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    validated_split_info_t validated_split_info = { 0 };
    rc                                          = validate_split_amount( invoke_context,
                                transaction_context,
                                instruction_context,
                                stake_account_index,
                                split_index,
                                lamports,
                                meta,
                                0,
                                false,
                                &validated_split_info );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_stake_meta_t split_meta     = *meta;
    split_meta.rent_exempt_reserve = validated_split_info.destination_rent_exempt_reserve;

    fd_borrowed_account_t * split = NULL;
    rc                            = fd_instr_ctx_try_borrow_instruction_account(
        invoke_context, transaction_context, split_index, &split );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    fd_stake_state_v2_t temp = { .discriminant = fd_stake_state_v2_enum_initialized,
                                 .inner        = { .initialized = { .meta = split_meta } } };
    rc                       = set_state( split, &temp );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    break;
  }
  case fd_stake_state_v2_enum_uninitialized: {
    uchar index_in_transaction = FD_TXN_ACCT_ADDR_MAX;
    rc                         = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
        instruction_context, stake_account_index, &index_in_transaction );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    fd_pubkey_t stake_pubkey = { 0 };
    rc                       = fd_txn_ctx_get_key_of_account_at_index(
        transaction_context, index_in_transaction, &stake_pubkey );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    if( FD_UNLIKELY( !fd_instr_ctx_signers_contains( signers, &stake_pubkey ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
    break;
  }
  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L789-L794
  rc = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, stake_account_index, &stake_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  if( FD_UNLIKELY( lamports == stake_account->meta->info.lamports ) ) {
    fd_stake_state_v2_t uninitialized = { 0 };
    uninitialized.discriminant        = fd_stake_state_v2_enum_uninitialized;
    rc                                = set_state( stake_account, &uninitialized );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  };

  // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L796-L803
  rc = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, split_index, &split );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  rc = fd_borrowed_account_checked_add_lamports( split, lamports );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  rc = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, stake_account_index, &stake_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  rc = fd_borrowed_account_checked_sub_lamports( stake_account, lamports );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  return FD_PROGRAM_OK;
}

static int
merge( fd_exec_instr_ctx_t *         invoke_context,
       fd_exec_txn_ctx_t const *     transaction_context,
       fd_instr_info_t const *       instruction_context,
       uchar                         stake_account_index,
       uchar                         source_account_index,
       fd_sol_sysvar_clock_t const * clock,
       fd_stake_history_t const *    stake_history,
       fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX] ) {
  int rc;

  fd_borrowed_account_t * source_account = NULL;
  rc                                     = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, source_account_index, &source_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  if( FD_UNLIKELY( 0 != memcmp( &source_account->meta->info.owner,
                                 fd_solana_stake_program_id.key,
                                 32UL ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
  }

  uchar stake_account_i = FD_TXN_ACCT_ADDR_MAX;
  rc                    = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
      instruction_context, stake_account_index, &stake_account_i );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  uchar source_account_i = FD_TXN_ACCT_ADDR_MAX;
  rc                     = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
      instruction_context, source_account_index, &source_account_i );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  if( FD_UNLIKELY( stake_account_i == source_account_i ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  fd_borrowed_account_t * stake_account = NULL;
  rc                                    = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, stake_account_index, &stake_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  fd_stake_state_v2_t stake_account_state = { 0 };
  rc = get_state( stake_account, &invoke_context->valloc, &stake_account_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  FD_DEBUG( FD_LOG_WARNING(( "Checking if destination stake is mergeable" )) );
  merge_kind_t stake_merge_kind = { 0 };
  rc                            = get_if_mergeable( invoke_context,
                         &stake_account_state,
                         stake_account->meta->info.lamports,
                         clock,
                         stake_history,
                         &stake_merge_kind,
                         &invoke_context->txn_ctx->custom_err );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  rc = authorized_check( &meta( &stake_merge_kind )->authorized, signers, STAKE_AUTHORIZE_STAKER );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  FD_DEBUG( FD_LOG_INFO(( "Checking if source stake is mergeable" )) );
  fd_stake_state_v2_t source_account_state = { 0 };
  rc = get_state( source_account, &invoke_context->valloc, &source_account_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  merge_kind_t source_merge_kind = { 0 };
  rc                             = get_if_mergeable( invoke_context,
                         &source_account_state,
                         source_account->meta->info.lamports,
                         clock,
                         stake_history,
                         &source_merge_kind,
                         &invoke_context->txn_ctx->custom_err );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  FD_DEBUG( FD_LOG_INFO(( "Merging stake accounts" )) );

  fd_stake_state_v2_t merged_state = { 0 };
  bool                is_some      = false;
  rc                               = merge_kind_merge( stake_merge_kind,
                         invoke_context,
                         source_merge_kind,
                         clock,
                         &merged_state,
                         &is_some,
                         &invoke_context->txn_ctx->custom_err );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  // FIXME FD_LIKELY
  if( is_some ) {
    rc = set_state( stake_account, &merged_state );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  }

  fd_stake_state_v2_t uninitialized = { 0 };
  uninitialized.discriminant        = fd_stake_state_v2_enum_uninitialized;
  rc                                = set_state( source_account, &uninitialized );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  ulong lamports = source_account->meta->info.lamports;
  rc             = fd_borrowed_account_checked_sub_lamports( source_account, lamports );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  rc = fd_borrowed_account_checked_add_lamports( stake_account, lamports );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  return FD_PROGRAM_OK;
}

static int
redelegate( fd_exec_instr_ctx_t *                   invoke_context,
            fd_exec_txn_ctx_t const *               transaction_context,
            FD_PARAM_UNUSED fd_instr_info_t const * instruction_context,
            fd_borrowed_account_t *                 stake_account,
            uchar                                   uninitialized_stake_account_index,
            uchar                                   vote_account_index,
            fd_pubkey_t const *                     signers[static FD_TXN_SIG_MAX],
            uint *                                  custom_err ) {
  int rc;

  fd_sol_sysvar_clock_t clock = { 0 };
  rc                          = fd_sysvar_clock_read( invoke_context->slot_ctx, &clock );
  if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

  fd_borrowed_account_t * uninitialized_stake_account = NULL;
  rc = fd_instr_ctx_try_borrow_instruction_account( invoke_context,
                                                    transaction_context,
                                                    uninitialized_stake_account_index,
                                                    &uninitialized_stake_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  if( FD_UNLIKELY( 0 != memcmp( &uninitialized_stake_account->meta->info.owner,
                                 fd_solana_stake_program_id.key,
                                 sizeof( fd_pubkey_t ) ) ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "expected uninitialized stake account owner to be {}, not {}" )) );
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
  }

  if( FD_UNLIKELY( uninitialized_stake_account->meta->dlen != stake_state_v2_size_of() ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "expected uninitialized stake account data len to be {}, not {}" )) );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  fd_stake_state_v2_t uninitialized_stake_account_state = { 0 };
  rc                                                    = get_state(
      uninitialized_stake_account, &invoke_context->valloc, &uninitialized_stake_account_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  if( FD_UNLIKELY( uninitialized_stake_account_state.discriminant !=
                    fd_stake_state_v2_enum_uninitialized ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "expected uninitialized stake account to be uninitialized" )) );
    return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
  }

  fd_borrowed_account_t * vote_account = NULL;
  rc                                   = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, vote_account_index, &vote_account );
  if( FD_UNLIKELY(
           0 != memcmp( &vote_account->meta->info.owner, fd_solana_vote_program_id.key, 32UL ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
  }

  fd_pubkey_t const *       vote_pubkey = vote_account->pubkey;
  fd_vote_state_versioned_t vote_state  = { 0 };
  rc = fd_vote_get_state( vote_account, *invoke_context, &vote_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  fd_stake_meta_t     stake_meta          = { 0 };
  ulong               effective_stake     = ULONG_MAX;
  fd_stake_state_v2_t stake_account_state = { 0 };
  rc = get_state( stake_account, &invoke_context->valloc, &stake_account_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  if( FD_LIKELY( stake_account_state.discriminant == fd_stake_state_v2_enum_stake ) ) {
    fd_stake_meta_t meta  = stake_account_state.inner.stake.meta;
    fd_stake_t      stake = stake_account_state.inner.stake.stake;

    fd_stake_history_t stake_history = { 0 };
    rc = fd_sysvar_stake_history_read( invoke_context->slot_ctx, &stake_history );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    ulong new_rate_activation_epoch = ULONG_MAX;
    bool  is_some = new_warmup_cooldown_rate_epoch( invoke_context, &new_rate_activation_epoch );
    fd_stake_history_entry_t status =
        stake_activating_and_deactivating( &stake.delegation,
                                           clock.epoch,
                                           &stake_history,
                                           fd_ptr_if( is_some, &new_rate_activation_epoch, NULL ) );

    if( FD_UNLIKELY( status.effective == 0 || status.activating != 0 ||
                      status.deactivating != 0 ) ) {
      FD_DEBUG( FD_LOG_WARNING(( "stake is not active" )) );
      *custom_err = FD_STAKE_ERR_REDELEGATE_TRANSIENT_OR_INACTIVE_STAKE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    if( FD_UNLIKELY(
             0 == memcmp( &stake.delegation.voter_pubkey, vote_pubkey, sizeof( fd_pubkey_t ) ) ) ) {
      FD_DEBUG( FD_LOG_WARNING(( "redelegating to the same vote account not permitted" )) );
      *custom_err = FD_STAKE_ERR_REDELEGATE_TO_SAME_VOTE_ACCOUNT;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    stake_meta      = meta;
    effective_stake = status.effective;
  } else {
    FD_DEBUG( FD_LOG_WARNING(( "invalid stake account data" )) );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  rc = deactivate( stake_account,
                   &clock,
                   signers,
                   &invoke_context->valloc,
                   &invoke_context->txn_ctx->custom_err );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  rc = fd_borrowed_account_checked_sub_lamports( stake_account, effective_stake );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  rc = fd_borrowed_account_checked_add_lamports( uninitialized_stake_account, effective_stake );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  fd_rent_t rent = { 0 };
  rc             = fd_sysvar_rent_read( invoke_context->slot_ctx, &rent );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

  fd_stake_meta_t uninitialized_stake_meta = stake_meta;
  uninitialized_stake_meta.rent_exempt_reserve =
      fd_rent_exempt_minimum_balance2( &rent, uninitialized_stake_account->meta->dlen );

  validated_delegated_info_t validated_delegated_info = { 0 };
  rc = validate_delegated_amount( uninitialized_stake_account,
                                  &uninitialized_stake_meta,
                                  invoke_context->slot_ctx,
                                  &validated_delegated_info,
                                  &invoke_context->txn_ctx->custom_err );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  ulong stake_amount = validated_delegated_info.stake_amount;

  fd_vote_convert_to_current( &vote_state, *invoke_context );
  fd_stake_t new_stake_ =
      new_stake( stake_amount, vote_pubkey, &vote_state.inner.current, clock.epoch );
  fd_stake_state_v2_t new_stake_state = {
      .discriminant = fd_stake_state_v2_enum_stake,
      .inner        = { .stake = { .meta        = uninitialized_stake_meta,
                                   .stake       = new_stake_,
                                   .stake_flags = STAKE_FLAGS_MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION_IS_PERMITTED } } };
  rc = set_state( uninitialized_stake_account, &new_stake_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  return FD_PROGRAM_OK;
}

static int
withdraw( fd_exec_instr_ctx_t *         invoke_context,
          fd_exec_txn_ctx_t const *     transaction_context,
          fd_instr_info_t const *       instruction_context,
          uchar                         stake_account_index,
          ulong                         lamports,
          uchar                         to_index,
          fd_sol_sysvar_clock_t const * clock,
          fd_stake_history_t const *    stake_history,
          uchar                         withdraw_authority_index,
          uchar *                       custodian_index,
          ulong *                       new_rate_activation_epoch ) {
  int rc;

  uchar index_in_transaction = FD_TXN_ACCT_ADDR_MAX;
  rc                         = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
      instruction_context, withdraw_authority_index, &index_in_transaction );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  fd_pubkey_t withdraw_authority_pubkey = { 0 };
  rc                                    = fd_txn_ctx_get_key_of_account_at_index(
      transaction_context, index_in_transaction, &withdraw_authority_pubkey );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L1010-L1012
  bool is_signer = false;
  rc             = fd_instr_ctx_is_instruction_account_signer(
      instruction_context, withdraw_authority_index, &is_signer );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  if( FD_UNLIKELY( !is_signer ) ) return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  fd_pubkey_t const * signers[FD_TXN_SIG_MAX] = {
      &withdraw_authority_pubkey }; // TODO: This feels wrong

  fd_borrowed_account_t * stake_account = NULL;
  rc                                    = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, stake_account_index, &stake_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  fd_stake_state_v2_t stake_state = { 0 };
  rc = get_state( stake_account, &invoke_context->valloc, &stake_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  fd_stake_lockup_t lockup;
  ulong             reserve;
  bool              is_staked;

  switch ( stake_state.discriminant ) {
  case fd_stake_state_v2_enum_stake: {
    fd_stake_meta_t * meta  = &stake_state.inner.stake.meta;
    fd_stake_t *      stake = &stake_state.inner.stake.stake;

    rc = authorized_check( &meta->authorized, signers, STAKE_AUTHORIZE_WITHDRAWER );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    ulong staked = fd_ulong_if(
        clock->epoch >= stake->delegation.deactivation_epoch,
        delegation_stake(
            &stake->delegation, clock->epoch, stake_history, new_rate_activation_epoch ),
        stake->delegation.stake );

    ulong staked_and_reserve = ULONG_MAX;
    rc = fd_instr_checked_add( staked, meta->rent_exempt_reserve, &staked_and_reserve );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    lockup    = meta->lockup;
    reserve   = staked_and_reserve;
    is_staked = staked != 0;
    break;
  }
  case fd_stake_state_v2_enum_initialized: {
    fd_stake_meta_t * meta = &stake_state.inner.initialized.meta;

    rc = authorized_check( &meta->authorized, signers, STAKE_AUTHORIZE_WITHDRAWER );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    lockup    = meta->lockup;
    reserve   = meta->rent_exempt_reserve;
    is_staked = false;
    break;
  }
  case fd_stake_state_v2_enum_uninitialized: {
    if( FD_UNLIKELY( !fd_instr_ctx_signers_contains( signers, stake_account->pubkey ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
    memset( &lockup, 0, sizeof( fd_stake_lockup_t ) ); /* Lockup::default(); */
    reserve   = 0;
    is_staked = false;
    break;
  }
  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  // FIXME FD_LIKELY
  fd_pubkey_t   custodian_pubkey_ = { 0 };
  fd_pubkey_t * custodian_pubkey  = &custodian_pubkey_;
  if( custodian_index ) {
    bool is_signer = false;
    rc             = fd_instr_ctx_is_instruction_account_signer(
        instruction_context, *custodian_index, &is_signer );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    if( is_signer ) {
      uchar index_in_transaction = FD_TXN_ACCT_ADDR_MAX;
      rc                         = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
          instruction_context, *custodian_index, &index_in_transaction );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      rc = fd_txn_ctx_get_key_of_account_at_index(
          transaction_context, index_in_transaction, custodian_pubkey );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
    } else {
      custodian_pubkey = NULL;
    }
  } else {
    custodian_pubkey = NULL;
  }
  if( FD_UNLIKELY( lockup_is_in_force( &lockup, clock, custodian_pubkey ) ) ) {
    invoke_context->txn_ctx->custom_err = FD_STAKE_ERR_LOCKUP_IN_FORCE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  };

  ulong lamports_and_reserve = ULONG_MAX;
  rc                         = fd_instr_checked_add( lamports, reserve, &lamports_and_reserve );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  if( FD_UNLIKELY( is_staked && lamports_and_reserve > stake_account->meta->info.lamports ) ) {
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }

  if( FD_UNLIKELY( lamports != stake_account->meta->info.lamports &&
                    lamports_and_reserve > stake_account->meta->info.lamports ) ) {
    // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_state.rs#L1083
    FD_TEST( !is_staked );
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }

  // FIXME FD_LIKELY
  if( lamports == stake_account->meta->info.lamports ) {
    fd_stake_state_v2_t uninitialized = { 0 };
    uninitialized.discriminant        = fd_stake_state_v2_enum_uninitialized;
    rc                                = set_state( stake_account, &uninitialized );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  }

  rc = fd_borrowed_account_checked_sub_lamports( stake_account, lamports );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  fd_borrowed_account_t * to = NULL;
  rc                         = fd_instr_ctx_try_borrow_instruction_account(
      invoke_context, transaction_context, to_index, &to );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  rc = fd_borrowed_account_checked_add_lamports( to, lamports );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  return FD_PROGRAM_OK;
}

static int
deactivate_delinquent( fd_exec_txn_ctx_t *     transaction_context,
                       fd_exec_instr_ctx_t *   instruction_context,
                       fd_borrowed_account_t * stake_account,
                       uchar                   delinquent_vote_account_index,
                       uchar                   reference_vote_account_index,
                       ulong                   current_epoch,
                       fd_valloc_t *           valloc,
                       uint *                  custom_err ) {
  int rc;

  uchar index_in_transaction = FD_TXN_ACCT_ADDR_MAX;
  rc                         = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
      instruction_context->instr, delinquent_vote_account_index, &index_in_transaction );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  fd_pubkey_t delinquent_vote_account_pubkey = { 0 };
  rc                                         = fd_txn_ctx_get_key_of_account_at_index(
      transaction_context, index_in_transaction, &delinquent_vote_account_pubkey );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  fd_borrowed_account_t * delinquent_vote_account = NULL;
  rc = fd_instr_ctx_try_borrow_instruction_account( instruction_context,
                                                    transaction_context,
                                                    delinquent_vote_account_index,
                                                    &delinquent_vote_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  if( FD_UNLIKELY( 0 != memcmp( &delinquent_vote_account->meta->info.owner,
                                 fd_solana_vote_program_id.key,
                                 32UL ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
  }

  fd_vote_state_versioned_t delinquent_vote_state_versioned = { 0 };
  fd_exec_instr_ctx_t       ctx                             = *instruction_context;
  rc = fd_vote_get_state( delinquent_vote_account, ctx, &delinquent_vote_state_versioned );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  fd_vote_convert_to_current( &delinquent_vote_state_versioned, ctx );
  fd_vote_state_t delinquent_vote_state = delinquent_vote_state_versioned.inner.current;

  fd_borrowed_account_t * reference_vote_account = NULL;
  rc = fd_instr_ctx_try_borrow_instruction_account( instruction_context,
                                                    transaction_context,
                                                    reference_vote_account_index,
                                                    &reference_vote_account );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  if( FD_UNLIKELY( 0 != memcmp( &reference_vote_account->meta->info.owner,
                                 fd_solana_vote_program_id.key,
                                 32UL ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
  }

  fd_vote_state_versioned_t reference_vote_state_versioned = { 0 };
  // FIXME ctx
  rc = fd_vote_get_state( reference_vote_account, ctx, &reference_vote_state_versioned );
  fd_vote_convert_to_current( &reference_vote_state_versioned, ctx );
  fd_vote_state_t reference_vote_state = reference_vote_state_versioned.inner.current;
  (void)reference_vote_state;

  if( !acceptable_reference_epoch_credits( reference_vote_state.epoch_credits, current_epoch ) ) {
    ctx.txn_ctx->custom_err = FD_STAKE_ERR_INSUFFICIENT_REFERENCE_VOTES;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_stake_state_v2_t stake_state = { 0 };
  rc                              = get_state( stake_account, valloc, &stake_state );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  if( FD_LIKELY( stake_state.discriminant == fd_stake_state_v2_enum_stake ) ) {
    fd_stake_t * stake = &stake_state.inner.stake.stake;

    if( FD_UNLIKELY( 0 != memcmp( &stake->delegation.voter_pubkey,
                                   &delinquent_vote_account_pubkey,
                                   sizeof( fd_pubkey_t ) ) ) ) {
      *custom_err = FD_STAKE_ERR_VOTE_ADDRESS_MISMATCH;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    if( FD_LIKELY( eligible_for_deactivate_delinquent( delinquent_vote_state.epoch_credits,
                                                        current_epoch ) ) ) {
      rc = stake_deactivate( stake, current_epoch, custom_err );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      return set_state( stake_account, &stake_state );
    } else {
      *custom_err = FD_STAKE_ERR_MINIMUM_DELIQUENT_EPOCHS_FOR_DEACTIVATION_NOT_MET;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  } else {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
}

/**********************************************************************/
/* mod stake_instruction                                              */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L29
static int
get_optional_pubkey( fd_exec_instr_ctx_t            ctx,
                     uchar                          instruction_account_index,
                     bool                           should_be_signer,
                     /* out */ fd_pubkey_t const ** pubkey ) {
  if( FD_LIKELY( instruction_account_index < ctx.instr->acct_cnt ) ) {
    if( FD_UNLIKELY( should_be_signer &&
                      !fd_instr_acc_is_signer_idx( ctx.instr, instruction_account_index ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
    fd_pubkey_t const * txn_accs       = ctx.txn_ctx->accounts;
    uchar const *       instr_acc_idxs = ctx.instr->acct_txn_idxs;
    *pubkey                            = &txn_accs[instr_acc_idxs[instruction_account_index]];
  } else {
    *pubkey = NULL;
  }
  return FD_PROGRAM_OK;
}

// https://github.com/firedancer-io/solana/blob/debug-master/programs/stake/src/stake_instruction.rs#L67-L73
static int
get_stake_account( fd_exec_txn_ctx_t const * transaction_context,
                   fd_exec_instr_ctx_t *     instruction_context,
                   fd_borrowed_account_t **  out ) {
  int rc;
  rc = fd_instr_ctx_try_borrow_instruction_account(
      instruction_context, transaction_context, 0, out );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
  // https://github.com/firedancer-io/solana/blob/debug-master/programs/stake/src/stake_instruction.rs#L69-L71
  if( FD_UNLIKELY( 0 !=
                    memcmp( ( *out )->meta->info.owner, fd_solana_stake_program_id.key, 32UL ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }
  return FD_PROGRAM_OK;
}

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

void
fd_stake_program_config_init( fd_exec_slot_ctx_t * slot_ctx ) {
  /* Defaults taken from
     https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/stake/config.rs#L8-L11
   */
  fd_stake_config_t stake_config = {
      .warmup_cooldown_rate = 0.25,
      .slash_penalty        = 12,
  };
  write_stake_config( slot_ctx, &stake_config );
}

int
fd_stake_get_state( fd_borrowed_account_t const * self,
                    fd_valloc_t const *           valloc,
                    fd_stake_state_v2_t *         out ) {
  return get_state( self, valloc, out );
}

fd_stake_history_entry_t
fd_stake_activating_and_deactivating( fd_delegation_t const *    self,
                                      ulong                      target_epoch,
                                      fd_stake_history_t const * stake_history,
                                      ulong *                    new_rate_activation_epoch ) {
  return stake_activating_and_deactivating(
      self, target_epoch, stake_history, new_rate_activation_epoch );
}

int
fd_executor_stake_program_execute_instruction( fd_exec_instr_ctx_t ctx ) {
  int                      rc;
  fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.valloc };

  // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L61-L63
  fd_exec_txn_ctx_t *     transaction_context = ctx.txn_ctx;
  fd_instr_info_t const * instruction_context = ctx.instr;
  uchar *                 data                = ctx.instr->data;

  // https://github.com/firedancer-io/solana/blob/debug-master/programs/stake/src/stake_instruction.rs#L75
  fd_pubkey_t const * signers[FD_TXN_SIG_MAX] = { 0 };
  rc = fd_instr_ctx_get_signers( instruction_context, transaction_context, signers );
  if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/debug-master/programs/stake/src/stake_instruction.rs#L76
  fd_stake_instruction_t instruction;
  fd_stake_instruction_new( &instruction );
  fd_bincode_decode_ctx_t decode_ctx = {
      .data    = data,
      .dataend = &data[ctx.instr->data_sz],
      .valloc  = ctx.valloc,
  };
  if( FD_UNLIKELY( FD_EXECUTOR_INSTR_SUCCESS !=
                    fd_stake_instruction_decode( &instruction, &decode_ctx ) ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "fd_stake_instruction_decode failed" )) );
    fd_stake_instruction_destroy( &instruction, &destroy );
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* PLEASE PRESERVE SWITCH-CASE ORDERING TO MIRROR LABS IMPL:
   * https://github.com/firedancer-io/solana/blob/debug-master/programs/stake/src/stake_instruction.rs#L76
   */
  switch ( instruction.discriminant ) {

  /* Initialize
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/debug-master/sdk/program/src/stake/instruction.rs#L93
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/debug-master/programs/stake/src/stake_instruction.rs#L77
   */
  case fd_stake_instruction_enum_initialize: {
    fd_stake_authorized_t const * authorized = &instruction.inner.initialize.authorized;
    fd_stake_lockup_t const *     lockup     = &instruction.inner.initialize.lockup;

    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_rent_t rent;
    rc = fd_sysvar_rent_checked_read( &ctx, ctx.instr, 1, &rent );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    rc = initialize( me, authorized, lockup, &rent, &ctx.valloc );
    break;
  }

  /* Authorize
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/debug-master/sdk/program/src/stake/instruction.rs#L103
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/debug-master/programs/stake/src/stake_instruction.rs#L77
   */
  case fd_stake_instruction_enum_authorize: {
    fd_pubkey_t const *          authorized_pubkey = &instruction.inner.authorize.pubkey;
    fd_stake_authorize_t const * stake_authorize   = &instruction.inner.authorize.stake_authorize;

    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    bool require_custodian_for_locked_stake_authorize =
        FD_FEATURE_ACTIVE( ctx.slot_ctx, require_custodian_for_locked_stake_authorize );

    if( FD_LIKELY( require_custodian_for_locked_stake_authorize ) ) {
      fd_sol_sysvar_clock_t clock = { 0 };
      rc                          = fd_sysvar_clock_checked_read( &ctx, ctx.instr, 1, &clock );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      rc = fd_instr_ctx_check_number_of_instruction_accounts( ctx.instr, 3 );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      fd_pubkey_t const * custodian_pubkey = NULL;
      rc = get_optional_pubkey( ctx, 3, false, &custodian_pubkey );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      rc = authorize( me,
                      signers,
                      authorized_pubkey,
                      stake_authorize,
                      require_custodian_for_locked_stake_authorize,
                      &clock,
                      custodian_pubkey,
                      &ctx.valloc,
                      &ctx.txn_ctx->custom_err );
    } else {
      fd_sol_sysvar_clock_t clock_default = { 0 };

      rc = authorize( me,
                      signers,
                      authorized_pubkey,
                      stake_authorize,
                      require_custodian_for_locked_stake_authorize,
                      &clock_default,
                      NULL,
                      &ctx.valloc,
                      &ctx.txn_ctx->custom_err );
    }
    break;
  }

  /* AuthorizeWithSeed
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/debug-master/sdk/program/src/stake/instruction.rs#L194
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/debug-master/programs/stake/src/stake_instruction.rs#L120
   */
  case fd_stake_instruction_enum_authorize_with_seed: {
    fd_authorize_with_seed_args_t args = instruction.inner.authorize_with_seed;

    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    rc = fd_instr_ctx_check_number_of_instruction_accounts( ctx.instr, 2 );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    bool require_custodian_for_locked_stake_authorize =
        FD_FEATURE_ACTIVE( ctx.slot_ctx, require_custodian_for_locked_stake_authorize );

    if( FD_LIKELY( require_custodian_for_locked_stake_authorize ) ) {
      fd_sol_sysvar_clock_t clock = { 0 };
      rc                          = fd_sysvar_clock_checked_read( &ctx, ctx.instr, 2, &clock );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      fd_pubkey_t const * custodian_pubkey = NULL;
      rc = get_optional_pubkey( ctx, 3, false, &custodian_pubkey );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      rc = authorize_with_seed( ctx.txn_ctx,
                                ctx.instr,
                                me,
                                1,
                                args.authority_seed,
                                &args.authority_owner,
                                &args.new_authorized_pubkey,
                                &args.stake_authorize,
                                require_custodian_for_locked_stake_authorize,
                                &clock,
                                custodian_pubkey,
                                &ctx.valloc );
    } else {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
    break;
  }

  /* DelegateStake
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L118
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L164
   */
  case fd_stake_instruction_enum_delegate_stake: {
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    rc = fd_instr_ctx_check_number_of_instruction_accounts( ctx.instr, 2 );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_sol_sysvar_clock_t clock = { 0 };
    rc                          = fd_sysvar_clock_checked_read( &ctx, ctx.instr, 2, &clock );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_stake_history_t stake_history = { 0 };
    rc = fd_sysvar_stake_history_checked_read( &ctx, ctx.instr, 3, &stake_history );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    rc = fd_instr_ctx_check_number_of_instruction_accounts( ctx.instr, 5 );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    // FIXME FD_LIKELY
    // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L176-L188
    if( FD_UNLIKELY( !FD_FEATURE_ACTIVE( ctx.slot_ctx, reduce_stake_warmup_cooldown ) ) ) {
      fd_borrowed_account_t * config_account = NULL;
      rc                                     = fd_instr_ctx_try_borrow_instruction_account(
          &ctx, transaction_context, 4, &config_account );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      uchar index_in_transaction = FD_TXN_ACCT_ADDR_MAX;
      rc                         = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
          instruction_context, 4, &index_in_transaction );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      fd_pubkey_t config_account_key = { 0 };
      rc                             = fd_txn_ctx_get_key_of_account_at_index(
          transaction_context, index_in_transaction, &config_account_key );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      if( FD_UNLIKELY( 0 == memcmp( config_account_key.uc,
                                     fd_solana_config_program_id.key,
                                     sizeof( config_account_key.uc ) ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L442
      fd_bincode_decode_ctx_t decode_ctx;
      decode_ctx.data    = config_account->data;
      decode_ctx.dataend = config_account->data + config_account->meta->dlen;
      decode_ctx.valloc  = decode_ctx.valloc;

      fd_stake_config_t stake_config;
      rc = fd_stake_config_decode( &stake_config, &decode_ctx );
      if( FD_UNLIKELY( rc != FD_BINCODE_SUCCESS ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    rc = delegate( &ctx,
                   transaction_context,
                   instruction_context,
                   0,
                   1,
                   &clock,
                   &stake_history,
                   signers,
                   &ctx.valloc );
    break;
  }

  /* Split
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L126
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L201
   */
  case fd_stake_instruction_enum_split: {
    ulong lamports = instruction.inner.split;

    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    rc = fd_instr_ctx_check_number_of_instruction_accounts( instruction_context, 2 );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    rc = split( &ctx, transaction_context, instruction_context, 0, lamports, 1, signers );
    break;
  }

  /* Merge
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L184
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L215
   */
  case fd_stake_instruction_enum_merge: {
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    rc = fd_instr_ctx_check_number_of_instruction_accounts( instruction_context, 2 );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_sol_sysvar_clock_t clock = { 0 };
    rc                          = fd_sysvar_clock_checked_read( &ctx, ctx.instr, 2, &clock );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_stake_history_t stake_history = { 0 };
    rc = fd_sysvar_stake_history_checked_read( &ctx, ctx.instr, 3, &stake_history );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    rc = merge(
        &ctx, transaction_context, instruction_context, 0, 1, &clock, &stake_history, signers );

    break;
  }

  /* Withdraw
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L140
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L237
   */
  case fd_stake_instruction_enum_withdraw: {
    ulong lamports = instruction.inner.withdraw;

    rc = fd_instr_ctx_check_number_of_instruction_accounts( instruction_context, 2 );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_sol_sysvar_clock_t clock = { 0 };
    rc                          = fd_sysvar_clock_checked_read( &ctx, ctx.instr, 2, &clock );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_stake_history_t stake_history = { 0 };
    rc = fd_sysvar_stake_history_checked_read( &ctx, ctx.instr, 3, &stake_history );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    rc = fd_instr_ctx_check_number_of_instruction_accounts( instruction_context, 5 );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    uchar custodian_index           = 5;
    ulong new_rate_activation_epoch = ULONG_MAX;
    bool  is_some = new_warmup_cooldown_rate_epoch( &ctx, &new_rate_activation_epoch );
    rc            = withdraw(
        &ctx,
        transaction_context,
        instruction_context,
        0,
        lamports,
        1,
        &clock,
        &stake_history,
        4,
        // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L258-L262
        fd_ptr_if( instruction_context->acct_cnt >= 6, &custodian_index, NULL ),
        fd_ptr_if( is_some, &new_rate_activation_epoch, NULL ) );
    break;
  }

  /* Deactivate
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L148
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L266
   */
  case fd_stake_instruction_enum_deactivate: {
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_sol_sysvar_clock_t clock = { 0 };
    rc                          = fd_sysvar_clock_checked_read( &ctx, ctx.instr, 1, &clock );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    rc = deactivate( me, &clock, signers, &ctx.valloc, &ctx.txn_ctx->custom_err );
    break;
  }

  /* SetLockup
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L158
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L272
   */
  case fd_stake_instruction_enum_set_lockup: {
    fd_lockup_args_t * lockup = &instruction.inner.set_lockup;

    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_sol_sysvar_clock_t clock = { 0 };
    rc                          = fd_sysvar_clock_read( ctx.slot_ctx, &clock );
    if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    rc = set_lockup( me, lockup, signers, &clock, &ctx.valloc );
    break;
  }

  /* InitializeChecked
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L207
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L277
   */
  case fd_stake_instruction_enum_initialize_checked: {
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L279-L307
    if( FD_LIKELY( FD_FEATURE_ACTIVE( ctx.slot_ctx, vote_stake_checked_instructions ) ) ) {
      rc = fd_instr_ctx_check_number_of_instruction_accounts( instruction_context, 4 );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      uchar staker_txn_i = FD_TXN_ACCT_ADDR_MAX;
      rc                 = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
          instruction_context, 2, &staker_txn_i );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      fd_pubkey_t staker_pubkey = { 0 };
      rc                        = fd_txn_ctx_get_key_of_account_at_index(
          transaction_context, staker_txn_i, &staker_pubkey );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      uchar withdrawer_txn_i = FD_TXN_ACCT_ADDR_MAX;
      rc                     = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
          instruction_context, 3, &withdrawer_txn_i );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      fd_pubkey_t withdrawer_pubkey = { 0 };
      rc                            = fd_txn_ctx_get_key_of_account_at_index(
          transaction_context, withdrawer_txn_i, &withdrawer_pubkey );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      bool is_signer = false;
      rc = fd_instr_ctx_is_instruction_account_signer( instruction_context, 3, &is_signer );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      if( FD_UNLIKELY( !is_signer ) ) return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

      fd_stake_authorized_t authorized = { .staker     = staker_pubkey,
                                           .withdrawer = withdrawer_pubkey };

      fd_rent_t rent = { 0 };
      rc             = fd_sysvar_rent_checked_read( &ctx, instruction_context, 1, &rent );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      fd_stake_lockup_t lockup_default = { 0 };
      rc = initialize( me, &authorized, &lockup_default, &rent, &ctx.valloc );
    } else {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
    break;
  }

  /* AuthorizeChecked
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L221
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L309
   */
  case fd_stake_instruction_enum_authorize_checked: {
    fd_stake_authorize_t const * stake_authorize = &instruction.inner.authorize_checked;

    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    if( FD_LIKELY( FD_FEATURE_ACTIVE( ctx.slot_ctx, vote_stake_checked_instructions ) ) ) {
      fd_sol_sysvar_clock_t clock = { 0 };
      rc                          = fd_sysvar_clock_checked_read( &ctx, ctx.instr, 1, &clock );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      int rc = fd_instr_ctx_check_number_of_instruction_accounts( ctx.instr, 4 );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      uchar authorized_txn_i = FD_TXN_ACCT_ADDR_MAX;
      rc                     = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
          instruction_context, 3, &authorized_txn_i );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      fd_pubkey_t authorized_pubkey = { 0 };
      rc                            = fd_txn_ctx_get_key_of_account_at_index(
          transaction_context, authorized_txn_i, &authorized_pubkey );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      bool is_signer = false;
      rc = fd_instr_ctx_is_instruction_account_signer( instruction_context, 3, &is_signer );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      if( FD_UNLIKELY( !is_signer ) ) return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

      fd_pubkey_t const * custodian_pubkey = NULL;
      rc = get_optional_pubkey( ctx, 4, false, &custodian_pubkey );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      rc = authorize( me,
                      signers,
                      &authorized_pubkey,
                      stake_authorize,
                      true,
                      &clock,
                      custodian_pubkey,
                      &ctx.valloc,
                      &ctx.txn_ctx->custom_err );
    } else {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    break;
  }

  /* AuthorizeCheckedWithSeed
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L235
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L343
   */
  case fd_stake_instruction_enum_authorize_checked_with_seed: {
    fd_authorize_checked_with_seed_args_t const * args =
        &instruction.inner.authorize_checked_with_seed;

    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    if( FD_LIKELY( FD_FEATURE_ACTIVE( ctx.slot_ctx, vote_stake_checked_instructions ) ) ) {
      rc = fd_instr_ctx_check_number_of_instruction_accounts( ctx.instr, 2 );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      fd_sol_sysvar_clock_t clock = { 0 };
      rc                          = fd_sysvar_clock_checked_read( &ctx, ctx.instr, 2, &clock );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      rc = fd_instr_ctx_check_number_of_instruction_accounts( ctx.instr, 4 );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      uchar authorized_txn_i = FD_TXN_ACCT_ADDR_MAX;
      rc                     = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
          instruction_context, 3, &authorized_txn_i );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      fd_pubkey_t authorized_pubkey = { 0 };
      rc                            = fd_txn_ctx_get_key_of_account_at_index(
          transaction_context, authorized_txn_i, &authorized_pubkey );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      bool is_signer = false;
      rc = fd_instr_ctx_is_instruction_account_signer( instruction_context, 3, &is_signer );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
      if( FD_UNLIKELY( !is_signer ) ) return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

      fd_pubkey_t const * custodian_pubkey = NULL;
      rc = get_optional_pubkey( ctx, 4, false, &custodian_pubkey );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      rc = authorize_with_seed( ctx.txn_ctx,
                                ctx.instr,
                                me,
                                1,
                                args->authority_seed,
                                &args->authority_owner,
                                &authorized_pubkey,
                                &args->stake_authorize,
                                true,
                                &clock,
                                custodian_pubkey,
                                &ctx.valloc );
    } else {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    break;
  }

  /* SetLockupChecked
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L249
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L382
   */
  case fd_stake_instruction_enum_set_lockup_checked: {
    fd_lockup_checked_args_t * lockup_checked = &instruction.inner.set_lockup_checked;

    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    if( FD_LIKELY( FD_FEATURE_ACTIVE( ctx.slot_ctx, vote_stake_checked_instructions ) ) ) {
      fd_pubkey_t const * custodian_pubkey = NULL;
      rc                                   = get_optional_pubkey( ctx, 2, true, &custodian_pubkey );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      fd_lockup_args_t lockup = { .unix_timestamp = lockup_checked->unix_timestamp,
                                  .epoch          = lockup_checked->epoch,
                                  .custodian      = (fd_pubkey_t *)custodian_pubkey }; // FIXME

      fd_sol_sysvar_clock_t clock;
      rc = fd_sysvar_clock_read( ctx.slot_ctx, &clock );
      if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) {
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
      }

      rc = set_lockup( me, &lockup, signers, &clock, &ctx.valloc );
    } else {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
    break;
  }

  /* GetMinimumDelegation
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L261
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L402
   */
  case fd_stake_instruction_enum_get_minimum_delegation: {
    // ulong minimum_delegation = get_minimum_delegation( ctx.slot_ctx );

    /* FIXME: Fix this after CPI return data is implemented */
    break;
  }

  /* DeactivateDelinquent
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L274
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L410
   */
  case fd_stake_instruction_enum_deactivate_delinquent: {
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    rc = fd_instr_ctx_check_number_of_instruction_accounts( instruction_context, 3 );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    fd_sol_sysvar_clock_t clock;
    rc = fd_sysvar_clock_read( ctx.slot_ctx, &clock );
    if( FD_UNLIKELY( rc != FD_ACC_MGR_SUCCESS ) ) return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    rc = deactivate_delinquent(
        transaction_context, &ctx, me, 1, 2, clock.epoch, &ctx.valloc, &ctx.txn_ctx->custom_err );
    break;
  }

  /* Redelegate
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/v1.17/sdk/program/src/stake/instruction.rs#L296
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L424
   */
  case fd_stake_instruction_enum_redelegate: {
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx.txn_ctx, &ctx, &me );
    if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

    // FIXME FD_LIKELY
    if( FD_LIKELY( FD_FEATURE_ACTIVE( ctx.slot_ctx, stake_redelegate_instruction ) ) ) {
      rc = fd_instr_ctx_check_number_of_instruction_accounts( instruction_context, 3 );
      if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

      // FIXME FD_LIKELY
      if( FD_UNLIKELY( !FD_FEATURE_ACTIVE( ctx.slot_ctx, reduce_stake_warmup_cooldown ) ) ) {
        fd_borrowed_account_t * config_account = NULL;
        rc                                     = fd_instr_ctx_try_borrow_instruction_account(
            &ctx, transaction_context, 3, &config_account );
        if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;

        uchar index_in_transaction = FD_TXN_ACCT_ADDR_MAX;
        rc                         = fd_instr_ctx_get_index_of_instruction_account_in_transaction(
            instruction_context, 3, &index_in_transaction );
        if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
        fd_pubkey_t config_account_key = { 0 };
        rc                             = fd_txn_ctx_get_key_of_account_at_index(
            transaction_context, index_in_transaction, &config_account_key );
        if( FD_UNLIKELY( rc != FD_PROGRAM_OK ) ) return rc;
        if( FD_UNLIKELY( 0 != memcmp( config_account_key.uc,
                                       fd_solana_stake_program_config_id.key,
                                       sizeof( config_account_key.uc ) ) ) ) {
          return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
        }
        // https://github.com/firedancer-io/solana/blob/v1.17/programs/stake/src/stake_instruction.rs#L442
        fd_bincode_decode_ctx_t decode_ctx;
        decode_ctx.data    = config_account->data;
        decode_ctx.dataend = config_account->data + config_account->meta->dlen;
        decode_ctx.valloc  = decode_ctx.valloc;

        fd_stake_config_t stake_config;
        rc = fd_stake_config_decode( &stake_config, &decode_ctx );
        if( FD_UNLIKELY( rc != FD_BINCODE_SUCCESS ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      }

      rc = redelegate( &ctx,
                       transaction_context,
                       instruction_context,
                       me,
                       1,
                       2,
                       signers,
                       &ctx.txn_ctx->custom_err );
    } else {
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
    break;
  }
  default:
    FD_LOG_ERR( ( "unsupported stake instruction: %u", instruction.discriminant ) );
  }

  fd_stake_instruction_destroy( &instruction, &destroy );
  return rc;
}
