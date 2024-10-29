#define FD_SCRATCH_USE_HANDHOLDING 1
#include <limits.h>

#include "../../../util/bits/fd_sat.h"
#include "../../../util/bits/fd_uwide.h"
#include "../fd_account.h"
#include "../fd_executor.h"
#include "../fd_pubkey_utils.h"
#include "../fd_system_ids.h"

#include "fd_stake_program.h"
#include "fd_vote_program.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../sysvar/fd_sysvar_rent.h"

/* A note on fd_borrowed_account_acquire_write:

   The stake program uses this function to prevent aliasing of accounts.
   (When the same account is passed via multiple instruction account
   indexes.)  Internally, it acquires a transaction-wide mutex on the
   account.  If called twice on the same account while the mutex is
   still locked, it returns an "AccountBorrowFailed" error.

   There is no exact equivalent to this in Agave/Rust.

     let handle = instruction_context.try_borrow_instruction_account(...)

   The above creates the lock on the account.  However, that lock is
   **implicitly** released when 'handle' goes out of scope.  Firedancer
   releases the handle **explicitly**. */

/**********************************************************************/
/* Errors                                                             */
/**********************************************************************/

// DO NOT REORDER: https://github.com/bincode-org/bincode/blob/trunk/docs/spec.md#enums
// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L28
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
#define FD_STAKE_ERR_EPOCH_REWARDS_ACTIVE                                                   ( 16 )

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/lib.rs#L31
#define MINIMUM_DELEGATION_SOL                     ( 1 )
// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/native_token.rs#L6
#define LAMPORTS_PER_SOL                           ( 1000000000 )
// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/mod.rs#L18
#define MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION ( 5 )
// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L26-L28
#define DEFAULT_WARMUP_COOLDOWN_RATE               ( 0.25 )
#define NEW_WARMUP_COOLDOWN_RATE                   ( 0.09 )
#define DEFAULT_SLASH_PENALTY                      ( 12 )

#define STAKE_AUTHORIZE_STAKER                                                                     \
  ( ( fd_stake_authorize_t ){ .discriminant = fd_stake_authorize_enum_staker, .inner = {0} } )
#define STAKE_AUTHORIZE_WITHDRAWER                                                                 \
  ( ( fd_stake_authorize_t ){ .discriminant = fd_stake_authorize_enum_withdrawer, .inner = {0} } )

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L51
#define DEFAULT_COMPUTE_UNITS 750UL

/**********************************************************************/
/* MergeKind                                                          */
/**********************************************************************/
// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1074-L1079
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
           fd_valloc_t                   valloc,
           fd_stake_state_v2_t *         out ) {
  int rc;

  fd_bincode_decode_ctx_t bincode_ctx;
  bincode_ctx.data    = self->const_data;
  bincode_ctx.dataend = self->const_data + self->const_meta->dlen;
  bincode_ctx.valloc  = valloc;

  rc = fd_stake_state_v2_decode( out, &bincode_ctx );
  if( FD_UNLIKELY( rc!=FD_BINCODE_SUCCESS ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  return 0;
}

static int
set_state( fd_exec_instr_ctx_t const * ctx,
           ulong                       acct_idx,
           fd_stake_state_v2_t const * state ) {

  uchar * data = NULL;
  ulong   dlen = 0UL;
  
  int err = fd_account_get_data_mut( ctx, acct_idx, &data, &dlen );
  if( FD_UNLIKELY( err ) ) return err;

  ulong serialized_size = fd_stake_state_v2_size( state );
  if( FD_UNLIKELY( serialized_size>dlen ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, acct_idx, serialized_size, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  fd_bincode_encode_ctx_t encode = {
    .data    = account->data,
    .dataend = account->data + serialized_size,
  };
  do {
    int err = fd_stake_state_v2_encode( state, &encode );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_stake_state_v2_encode failed" ));
  } while(0);

  return 0;
}

/**********************************************************************/
/* mod stake                                                          */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/lib.rs#L29
static inline ulong
get_minimum_delegation( fd_exec_slot_ctx_t const * slot_ctx /* feature set */ ) {
  return fd_ulong_if( FD_FEATURE_ACTIVE( slot_ctx, stake_raise_minimum_delegation_to_1_sol ),
                      MINIMUM_DELEGATION_SOL * LAMPORTS_PER_SOL,
                      1 );
}

/**********************************************************************/
/* mod stake/state                                                    */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L30
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

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L963
static int
validate_delegated_amount( fd_borrowed_account_t *      account,
                           fd_stake_meta_t const *      meta,
                           fd_exec_slot_ctx_t const *   slot_ctx,
                           validated_delegated_info_t * out,
                           uint *                       custom_err ) {
  ulong stake_amount = fd_ulong_sat_sub( account->const_meta->info.lamports, meta->rent_exempt_reserve );

  if( FD_UNLIKELY( stake_amount<get_minimum_delegation( slot_ctx ) ) ) {
    *custom_err = FD_STAKE_ERR_INSUFFICIENT_DELEGATION;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  out->stake_amount = stake_amount;
  return 0;
}

struct validated_split_info {
  ulong source_remaining_balance;
  ulong destination_rent_exempt_reserve;
};
typedef struct validated_split_info validated_split_info_t;

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L992
static int
validate_split_amount( fd_exec_instr_ctx_t const * invoke_context,
                       uchar                       source_account_index,
                       uchar                       destination_account_index,
                       ulong                       lamports,
                       fd_stake_meta_t const *     source_meta,
                       ulong                       additional_required_lamports,
                       int                         source_is_active,
                       validated_split_info_t *    out ) {

  ulong source_lamports = 0;
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1003-L1004
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( invoke_context, source_account_index, source_account ) {

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1005
  source_lamports = source_account->const_meta->info.lamports;

  } FD_BORROWED_ACCOUNT_DROP( source_account );

  ulong destination_lamports = 0;
  ulong destination_data_len = 0;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1007-L1008
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( invoke_context, destination_account_index, destination_account ) {

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1009-1010
  destination_lamports = destination_account->const_meta->info.lamports;
  destination_data_len = destination_account->const_meta->dlen;

  } FD_BORROWED_ACCOUNT_DROP( destination_account );

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1013-L1021
  if( FD_UNLIKELY( lamports==0 ) ) return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  if( FD_UNLIKELY( lamports>source_lamports ) ) return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1027-L1040
  ulong source_minimum_balance =
      fd_ulong_sat_add( source_meta->rent_exempt_reserve, additional_required_lamports );
  ulong source_remaining_balance = fd_ulong_sat_sub( source_lamports, lamports );

  if( FD_LIKELY( source_remaining_balance==0 ) ) {
  } else if( source_remaining_balance<source_minimum_balance ) {
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  } else {
  };

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1042
  fd_rent_t const * rent = fd_sysvar_cache_rent( invoke_context->slot_ctx->sysvar_cache );
  if( FD_UNLIKELY( !rent ) )
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1043
  ulong destination_rent_exempt_reserve =
      fd_rent_exempt_minimum_balance( rent, destination_data_len );

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1048
  if( FD_UNLIKELY(
           FD_FEATURE_ACTIVE( invoke_context->slot_ctx, require_rent_exempt_split_destination ) &&
           source_is_active && source_remaining_balance!=0 &&
           destination_lamports<destination_rent_exempt_reserve ) ) {
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1059-L1066
  ulong destination_minimum_balance =
      fd_ulong_sat_add( destination_rent_exempt_reserve, additional_required_lamports );
  ulong destination_balance_deficit =
      fd_ulong_sat_sub( destination_minimum_balance, destination_lamports );
  if( FD_UNLIKELY( lamports<destination_balance_deficit ) ) {
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1067-L1071
  out->source_remaining_balance        = source_remaining_balance;
  out->destination_rent_exempt_reserve = destination_rent_exempt_reserve;
  return 0;
}

/**********************************************************************/
/* impl Lockup                                                        */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L270
static inline int
lockup_is_in_force( fd_stake_lockup_t const *     self,
                    fd_sol_sysvar_clock_t const * clock,
                    fd_pubkey_t const *           custodian ) {
  // FIXME FD_LIKELY
  if( custodian && !memcmp( custodian, &self->custodian, sizeof( fd_pubkey_t ) ) ) {
    return 0;
  }
  return self->unix_timestamp>clock->unix_timestamp || self->epoch>clock->epoch;
}

/**********************************************************************/
/* impl Authorized                                                    */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L359
static inline int
authorized_check( fd_stake_authorized_t const * self,
                  fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
                  fd_stake_authorize_t          stake_authorize ) {
  /* clang-format off */
  switch( stake_authorize.discriminant ) {
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L365
  case fd_stake_authorize_enum_staker:
    if( FD_LIKELY( fd_instr_signers_contains( signers, &self->staker ) ) ) {
      return 0;
    }
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L366
  case fd_stake_authorize_enum_withdrawer:
    if( FD_LIKELY( fd_instr_signers_contains( signers, &self->withdrawer ) ) ) {
      return 0;
    }
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  default:
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }
  /* clang-format on */
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L371
static int
authorized_authorize( fd_stake_authorized_t *                  self,
                      fd_pubkey_t const *                      signers[static FD_TXN_SIG_MAX],
                      fd_pubkey_t const *                      new_authorized,
                      fd_stake_authorize_t const *             stake_authorize,
                      fd_stake_lockup_custodian_args_t const * lockup_custodian_args,
                      /* out */ uint *                         custom_err ) {
  int rc;
  switch( stake_authorize->discriminant ) {
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L379
  case fd_stake_authorize_enum_staker:
    if( FD_UNLIKELY( !fd_instr_signers_contains( signers, &self->staker ) &&
                      !fd_instr_signers_contains( signers, &self->withdrawer ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
    self->staker = *new_authorized;
    break;
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L386
  case fd_stake_authorize_enum_withdrawer:
    if( FD_LIKELY( lockup_custodian_args ) ) {
      fd_stake_lockup_t const *     lockup    = &lockup_custodian_args->lockup;
      fd_sol_sysvar_clock_t const * clock     = &lockup_custodian_args->clock;
      fd_pubkey_t const *           custodian = lockup_custodian_args->custodian;

      // FIXME FD_LIKELY
      if( lockup_is_in_force( lockup, clock, NULL ) ) {
        // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L389-L402
        if( !custodian ) { // FIXME FD_LIKELY
          *custom_err = FD_STAKE_ERR_CUSTODIAN_MISSING;
          return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
        } else {
          if( FD_UNLIKELY( !fd_instr_signers_contains( signers, custodian ) ) ) {
            *custom_err = FD_STAKE_ERR_CUSTODIAN_SIGNATURE_MISSING;
            return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          }

          if( FD_UNLIKELY( lockup_is_in_force( lockup, clock, custodian ) ) ) {
            *custom_err = FD_STAKE_ERR_LOCKUP_IN_FORCE;
            return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
          }
        }
      }
      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L405
      rc = authorized_check( self, signers, *stake_authorize );
      if( FD_UNLIKELY( rc ) ) return rc;
      self->withdrawer = *new_authorized;
    }
  }
  return 0;
}

/**********************************************************************/
/* impl Meta                                                          */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L482
static inline int
set_lockup_meta( fd_stake_meta_t *             self,
                 fd_lockup_args_t const *      lockup,
                 fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
                 fd_sol_sysvar_clock_t const * clock ) {
  // FIXME FD_LIKELY
  if( lockup_is_in_force( &self->lockup, clock, NULL ) ) {
    if( !fd_instr_signers_contains( signers, &self->lockup.custodian ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
  } else if( !fd_instr_signers_contains( signers, &self->authorized.withdrawer ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L498-L506
  if( lockup->unix_timestamp ) self->lockup.unix_timestamp = *lockup->unix_timestamp;
  if( lockup->epoch ) self->lockup.epoch = *lockup->epoch;
  if( lockup->custodian ) self->lockup.custodian = *lockup->custodian;
  return 0;
}

/**********************************************************************/
/* impl Delegation                                                    */
/**********************************************************************/

typedef fd_stake_history_entry_t fd_stake_activation_status_t;

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L728
static effective_activating_t
stake_and_activating( fd_delegation_t const *    self,
                      ulong                      target_epoch,
                      fd_stake_history_t const * history,
                      ulong *                    new_rate_activation_epoch ) {
  ulong delegated_stake = self->stake;

  fd_stake_history_entry_t const * cluster_stake_at_activation_epoch;
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L736
  if( self->activation_epoch==ULONG_MAX ) {
    return ( effective_activating_t ){ .effective = delegated_stake, .activating = 0 };
  } else if( self->activation_epoch==self->deactivation_epoch ) {
    return ( effective_activating_t ){ .effective = 0, .activating = 0 };
  } else if( target_epoch==self->activation_epoch ) {
    return ( effective_activating_t ){ .effective = 0, .activating = delegated_stake };
  } else if( target_epoch<self->activation_epoch ) {
    return ( effective_activating_t ){ .effective = 0, .activating = 0 };
  } else if( history &&
              ( cluster_stake_at_activation_epoch = fd_stake_history_treap_ele_query_const(
                    history->treap, self->activation_epoch, history->pool ) ) ) {
    ulong                            prev_epoch         = self->activation_epoch;
    fd_stake_history_entry_t const * prev_cluster_stake = cluster_stake_at_activation_epoch;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L763
    ulong current_epoch;
    ulong current_effective_stake = 0;
    for( ;; ) {
      current_epoch = prev_epoch + 1;
      if( FD_LIKELY( prev_cluster_stake->activating==0 ) ) { // FIXME always optimize loop break?
        break;
      }

      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L775-L780
      ulong  remaining_activating_stake = delegated_stake - current_effective_stake;
      double weight = (double)remaining_activating_stake / (double)prev_cluster_stake->activating;
      double warmup_cooldown_rate_ =
          warmup_cooldown_rate( current_epoch, new_rate_activation_epoch );

      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L782-L786
      double newly_effective_cluster_stake =
          (double)prev_cluster_stake->effective * warmup_cooldown_rate_;
      ulong newly_effective_stake =
          fd_ulong_max( fd_rust_cast_double_to_ulong( weight * newly_effective_cluster_stake ), 1 );

      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L787-L792
      current_effective_stake += newly_effective_stake;
      if( FD_LIKELY( current_effective_stake>=delegated_stake ) ) {
        current_effective_stake = delegated_stake;
        break;
      }

      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L793
      if( FD_LIKELY( current_epoch>=target_epoch ||
                     current_epoch>=self->deactivation_epoch ) ) { // FIXME always optimize loop break
        break;
      }

      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L796-L801
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
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L804-L807
    return ( effective_activating_t ){ .effective  = current_effective_stake,
                                       .activating = delegated_stake - current_effective_stake };
  } else {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L810
    return ( effective_activating_t ){ .effective = delegated_stake, .activating = 0 };
  }
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L641
static fd_stake_activation_status_t
stake_activating_and_deactivating( fd_delegation_t const *    self,
                                   ulong                      target_epoch,
                                   fd_stake_history_t const * stake_history,
                                   ulong *                    new_rate_activation_epoch ) {

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L648
  effective_activating_t effective_activating =
      stake_and_activating( self, target_epoch, stake_history, new_rate_activation_epoch );

  ulong effective_stake  = effective_activating.effective;
  ulong activating_stake = effective_activating.activating;

  fd_stake_history_entry_t * cluster_stake_at_activation_epoch = NULL;

  fd_stake_history_entry_t k;
  k.epoch = self->deactivation_epoch;

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/stake/state.rs#L652
  if( target_epoch<self->deactivation_epoch ) {
    // if is bootstrap
    if( activating_stake==0 ) {
      return ( fd_stake_history_entry_t ){
          .effective = effective_stake, .deactivating = 0, .activating = 0 };
    } else {
      return ( fd_stake_history_entry_t ){
          .effective = effective_stake, .deactivating = 0, .activating = activating_stake };
    }
  } else if( target_epoch==self->deactivation_epoch ) {
    // https://github.com/anza-xyz/agave/blob/be16321eb0db3e12a57a32f59febbf54b92ebb7c/sdk/program/src/stake/state.rs#L662
    return ( fd_stake_history_entry_t ){
        .effective = effective_stake, .deactivating = effective_stake, .activating = 0 };
  } else if( stake_history!=NULL ) {
    // https://github.com/anza-xyz/agave/blob/be16321eb0db3e12a57a32f59febbf54b92ebb7c/sdk/program/src/stake/state.rs#L665
    fd_stake_history_entry_t * n =
        fd_stake_history_treap_ele_query( stake_history->treap, k.epoch, stake_history->pool );

    if( NULL!=n ) { cluster_stake_at_activation_epoch = n; }

    if( cluster_stake_at_activation_epoch==NULL ) {
      fd_stake_history_entry_t entry = { .effective = 0, .activating = 0, .deactivating = 0 };

      return entry;
    }
    ulong                      prev_epoch         = self->deactivation_epoch;
    fd_stake_history_entry_t * prev_cluster_stake = cluster_stake_at_activation_epoch;

    ulong current_epoch;
    ulong current_effective_stake = effective_stake;
    for( ;; ) {
      current_epoch = prev_epoch + 1;
      if( prev_cluster_stake->deactivating==0 ) break;

      double weight = (double)current_effective_stake / (double)prev_cluster_stake->deactivating;
      double warmup_cooldown_rate_ =
          warmup_cooldown_rate( current_epoch, new_rate_activation_epoch );

      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L697-L700
      double newly_not_effective_cluster_stake =
          (double)prev_cluster_stake->effective * warmup_cooldown_rate_;
      ulong newly_not_effective_stake =
          fd_ulong_max( fd_rust_cast_double_to_ulong( weight * newly_not_effective_cluster_stake ), 1 );

      current_effective_stake =
          fd_ulong_sat_sub( current_effective_stake, newly_not_effective_stake );
      if( current_effective_stake==0 ) break;

      if( current_epoch>=target_epoch ) break;

      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L711-L713
      fd_stake_history_entry_t * current_cluster_stake = NULL;
      if( ( current_cluster_stake = fd_stake_history_treap_ele_query(
                 stake_history->treap, current_epoch, stake_history->pool ) ) ) {
        prev_epoch         = current_epoch;
        prev_cluster_stake = current_cluster_stake;
      } else {
        break;
      }
    }
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L720
    return ( fd_stake_history_entry_t ){ .effective    = current_effective_stake,
                                         .deactivating = current_effective_stake,
                                         .activating   = 0 };
  } else {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L723C16-L723C17
    return ( fd_stake_history_entry_t ){ .effective = 0, .activating = 0, .deactivating = 0 };
  }
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L630
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

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/tools.rs#L44
static inline int
acceptable_reference_epoch_credits( fd_vote_epoch_credits_t * epoch_credits,
                                    ulong                     current_epoch ) {
  ulong len            = deq_fd_vote_epoch_credits_t_cnt( epoch_credits );
  ulong epoch_index[1] = { ULONG_MAX };
  // FIXME FD_LIKELY
  if( !__builtin_usubl_overflow( len, MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION, epoch_index ) ) {
    ulong epoch = current_epoch;
    for( ulong i = len - 1; i>=*epoch_index; i-- ) {
      ulong vote_epoch = deq_fd_vote_epoch_credits_t_peek_index( epoch_credits, i )->epoch;
      if( vote_epoch!=epoch ) { return 0; }
      epoch = fd_ulong_sat_sub( epoch, 1 );
      if( i==0 ) break;
    }
    return 1;
  } else {
    return 0;
  };
}

/* https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/tools.rs#L67-L83 */
static inline int
eligible_for_deactivate_delinquent( fd_vote_epoch_credits_t * epoch_credits, ulong current_epoch ) {
  if( FD_LIKELY( deq_fd_vote_epoch_credits_t_empty( epoch_credits ) ) ) {
    return 1;
  }

  fd_vote_epoch_credits_t * last = deq_fd_vote_epoch_credits_t_peek_tail( epoch_credits );
  if( FD_LIKELY( !last ) ) {
    return 1;
  } else {
    ulong epoch         = last->epoch;
    ulong minimum_epoch = ULONG_MAX;
    int res = fd_ulong_checked_sub( current_epoch, MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION, &minimum_epoch );
    if( FD_LIKELY( res==0 ) ) {
      return epoch<=minimum_epoch;
    } else {
      return 0;
    }
  }
}

/**********************************************************************/
/* impl StakeFlags                                                    */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/stake_flags.rs#L72
#define STAKE_FLAGS_MUST_FULLY_ACTIVATE_BEFORE_DEACTIVATION_IS_PERMITTED                           \
  ( ( fd_stake_flags_t ){ .bits = 1 } )

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/stake_flags.rs#L75
#define STAKE_FLAGS_EMPTY ( ( fd_stake_flags_t ){ .bits = 0 } )

/**********************************************************************/
/* impl Stake                                                         */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L915
static int
stake_split( fd_stake_t * self,
             ulong        remaining_stake_delta,
             ulong        split_stake_amount,
             uint *       custom_err,
             fd_stake_t * out ) {
  if( FD_UNLIKELY( remaining_stake_delta>self->delegation.stake ) ) {
    *custom_err = FD_STAKE_ERR_INSUFFICIENT_STAKE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  self->delegation.stake -= remaining_stake_delta;
  fd_stake_t new;
  new                  = *self;
  new.delegation.stake = split_stake_amount;
  *out                 = new;
  return 0;
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L934
static int
stake_deactivate( fd_stake_t * stake, ulong epoch, uint * custom_err ) {
  if( FD_UNLIKELY( stake->delegation.deactivation_epoch!=ULONG_MAX ) ) {
    *custom_err = FD_STAKE_ERR_ALREADY_DEACTIVATED;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  } else {
    stake->delegation.deactivation_epoch = epoch;
    return 0;
  }
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L62
static inline int
new_warmup_cooldown_rate_epoch( fd_exec_instr_ctx_t const * invoke_context,
                                /* out */ ulong *           epoch,
                                int *                       err ) {
  *err = 0;
  fd_epoch_schedule_t const * epoch_schedule = fd_sysvar_cache_epoch_schedule( invoke_context->slot_ctx->sysvar_cache );
  if( FD_UNLIKELY( !epoch_schedule ) ) {
    *epoch = ULONG_MAX;
    *err   = FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    return 1;
  }
  ulong slot = invoke_context->epoch_ctx->features.reduce_stake_warmup_cooldown;
  *epoch     = fd_slot_to_epoch( epoch_schedule, slot, NULL );
  return 1;
}

/**********************************************************************/
/* util                                                               */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L205
FD_FN_CONST static inline ulong
stake_state_v2_size_of( void ) {
  return 200;
}

/**********************************************************************/
/* impl MergeKind                                                     */
/**********************************************************************/

static fd_stake_meta_t const *
meta( merge_kind_t const * self ) {
  switch( self->discriminant ) {
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
  switch( self->discriminant ) {
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

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1097
static int
get_if_mergeable( fd_exec_instr_ctx_t *         invoke_context, // not const to log
                  fd_stake_state_v2_t const *   stake_state,
                  ulong                         stake_lamports,
                  fd_sol_sysvar_clock_t const * clock,
                  fd_stake_history_t const *    stake_history,
                  merge_kind_t *                out,
                  uint *                        custom_err ) {
  // stake_history must be non-NULL
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1104
  switch( stake_state->discriminant ) {
  case fd_stake_state_v2_enum_stake: {
    fd_stake_meta_t const *  meta        = &stake_state->inner.stake.meta;
    fd_stake_t const *       stake       = &stake_state->inner.stake.stake;
    fd_stake_flags_t const * stake_flags = &stake_state->inner.stake.stake_flags;

    ulong new_rate_activation_epoch = ULONG_MAX;
    int   err;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1111
    int   is_some = new_warmup_cooldown_rate_epoch( invoke_context, &new_rate_activation_epoch, &err );
    if( FD_UNLIKELY( err ) ) return err;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1108
    fd_stake_history_entry_t status =
        stake_activating_and_deactivating( &stake->delegation,
                                           clock->epoch,
                                           stake_history,
                                           fd_ptr_if( is_some, &new_rate_activation_epoch, NULL ) );

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1115
    if( status.effective==0 && status.activating==0 && status.deactivating==0 ) {

      *out = ( merge_kind_t ){ .discriminant = merge_kind_inactive,
                               .inner        = { .inactive = { .meta         = *meta,
                                                               .active_stake = stake_lamports,
                                                               .stake_flags  = *stake_flags } } };
      return 0;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1116
    } else if( status.effective==0 ) {
      *out = ( merge_kind_t ){ .discriminant = merge_kind_activation_epoch,
                               .inner        = { .activation_epoch = { .meta        = *meta,
                                                                       .stake       = *stake,
                                                                       .stake_flags = *stake_flags } } };
      return 0;
      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1117
    } else if( status.activating==0 && status.deactivating==0 ) {
      *out = ( merge_kind_t ){ .discriminant = merge_kind_fully_active,
                               .inner = { .fully_active = { .meta  = *meta, 
                                                            .stake = *stake } } };
      return 0;
    } else {
      fd_log_collector_msg_literal( invoke_context, "stake account with transient stake cannot be merged" );
      *custom_err = FD_STAKE_ERR_MERGE_TRANSIENT_STAKE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    break;
  }
  case fd_stake_state_v2_enum_initialized: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1126
    *out = ( merge_kind_t ){ .discriminant = merge_kind_inactive,
                             .inner        = { .inactive = { .meta         = stake_state->inner.initialized.meta,
                                                             .active_stake = stake_lamports,
                                                             .stake_flags  = STAKE_FLAGS_EMPTY} } };
    break;
  }
  default:
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1128
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return 0;
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1132
static int
metas_can_merge( fd_exec_instr_ctx_t *         invoke_context, // not const to log
                 fd_stake_meta_t const *       stake,
                 fd_stake_meta_t const *       source,
                 fd_sol_sysvar_clock_t const * clock,
                 uint *                        custom_err ) {
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1139
  int  can_merge_lockups =
      ( !memcmp( &stake->lockup, &source->lockup, sizeof( fd_stake_lockup_t ) ) ) ||
      ( !lockup_is_in_force( &stake->lockup, clock, NULL ) &&
        !lockup_is_in_force( &source->lockup, clock, NULL ) );

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1146
  if( FD_LIKELY( !memcmp( &stake->authorized, &source->authorized, sizeof( fd_stake_authorized_t ) ) && can_merge_lockups ) ) {
    return 0;
  } else {
    fd_log_collector_msg_literal( invoke_context, "Unable to merge due to metadata mismatch" );
    *custom_err = FD_STAKE_ERR_MERGE_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1154
static int
active_delegations_can_merge( fd_exec_instr_ctx_t *   invoke_context, // not const to log
                              fd_delegation_t const * stake,
                              fd_delegation_t const * source,
                              uint *                  custom_err ) {
  if( memcmp( &stake->voter_pubkey, &source->voter_pubkey, sizeof(fd_pubkey_t) ) ) {
    fd_log_collector_msg_literal( invoke_context, "Unable to merge due to voter mismatch" );
    *custom_err = FD_STAKE_ERR_MERGE_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  } else if( FD_LIKELY( stake->deactivation_epoch==ULONG_MAX && source->deactivation_epoch==ULONG_MAX ) ) {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1162
    return 0;
  } else {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1167
    fd_log_collector_msg_literal( invoke_context, "Unable to merge due to stake deactivation" );
    *custom_err = FD_STAKE_ERR_MERGE_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
}

static int
stake_weighted_credits_observed( fd_stake_t const * stake,
                                 ulong              absorbed_lamports,
                                 ulong              absorbed_credits_observed,
                                 ulong *            out ) {
  /* https://github.com/anza-xyz/agave/blob/dc74c22960b4f2adfc672f6dc3bfaa74ec1d5d48/programs/stake/src/stake_state.rs#L1194 */
  if( FD_LIKELY( stake->credits_observed==absorbed_credits_observed ) ) {
    *out = stake->credits_observed;
    return 1;
  } else {
    /* https://github.com/anza-xyz/agave/blob/dc74c22960b4f2adfc672f6dc3bfaa74ec1d5d48/programs/stake/src/stake_state.rs#L1197 */
    /* let total_stake = u128::from(stake.delegation.stake.checked_add(absorbed_lamports)?); */
    ulong total_stake;
    /* If there is an overflow on the ulong addition then exit */
    if( FD_UNLIKELY( fd_ulong_checked_add( stake->delegation.stake, absorbed_lamports, &total_stake ) ) ) {
      return 0;
    }

    /* https://github.com/anza-xyz/agave/blob/9489096dc5b7f0a61a981f3d0fd393d264896c2a/programs/stake/src/stake_state.rs#L1198 */
    /* The multiplication of two 64 bit integers will never overflow the 128 bits */
    ulong stake_weighted_credits_h;
    ulong stake_weighted_credits_l;
    /* let stake_weighted_credits = */
    /*     u128::from(stake.credits_observed).checked_mul(u128::from(stake.delegation.stake))?; */
    fd_uwide_mul( &stake_weighted_credits_h, &stake_weighted_credits_l,
                  stake->credits_observed, stake->delegation.stake );

    /* https://github.com/anza-xyz/agave/blob/9489096dc5b7f0a61a981f3d0fd393d264896c2a/programs/stake/src/stake_state.rs#L1200 */
    /* The multiplication of two 64 bit integers will never overflow the 128 bits */
    ulong absorbed_weighted_credits_h;
    ulong absorbed_weighted_credits_l;
    /* let absorbed_weighted_credits = */
    /*     u128::from(absorbed_credits_observed).checked_mul(u128::from(absorbed_lamports))?; */
    fd_uwide_mul( &absorbed_weighted_credits_h, &absorbed_weighted_credits_l,
                  absorbed_credits_observed, absorbed_lamports );

    /* https://github.com/anza-xyz/agave/blob/9489096dc5b7f0a61a981f3d0fd393d264896c2a/programs/stake/src/stake_state.rs#L1204 */
    /* let total_weighted_credits = stake_weighted_credits */
    /*     .checked_add(absorbed_weighted_credits)? */
    /*     .checked_add(total_stake)? */
    /*     .checked_sub(1)?; */
    ulong total_weighted_credits_partial_one_h;
    ulong total_weighted_credits_partial_one_l;
    ulong carry_out = fd_uwide_add( &total_weighted_credits_partial_one_h, &total_weighted_credits_partial_one_l,
                                    stake_weighted_credits_h, stake_weighted_credits_l,
                                    absorbed_weighted_credits_h, absorbed_weighted_credits_l, 0UL );
    /* return on overflow */
    if( FD_UNLIKELY( carry_out ) ) {
      return 0;
    }

    ulong total_weighted_credits_partial_two_h;
    ulong total_weighted_credits_partial_two_l;
    carry_out = fd_uwide_add( &total_weighted_credits_partial_two_h, &total_weighted_credits_partial_two_l,
                              total_weighted_credits_partial_one_h, total_weighted_credits_partial_one_l,
                              0UL, total_stake, 0UL );
    /* return on overflow */
    if( FD_UNLIKELY( carry_out ) ) {
      return 0;
    }

    /* The only way we can underflow the subtraction of 1 is if the value of total_weighted_credits_partial_two is zero */
    if( FD_UNLIKELY( total_weighted_credits_partial_two_h==0 && total_weighted_credits_partial_two_l==0 ) ) {
      return 0;
    }
    ulong total_weighted_credits_h;
    ulong total_weighted_credits_l;
    fd_uwide_dec( &total_weighted_credits_h, &total_weighted_credits_l,
                  total_weighted_credits_partial_two_h, total_weighted_credits_partial_two_l, 1UL );

    /* https://github.com/anza-xyz/agave/blob/8a1b2dc3fa4b85e26fbce0db06a462d4853b0652/programs/stake/src/stake_state.rs#L1208 */
    /* u64::try_from(total_weighted_credits.checked_div(total_stake)?).ok() */
    ulong res_h;
    ulong res_l;
    if( FD_UNLIKELY( fd_uwide_div( &res_h, &res_l, total_weighted_credits_h, total_weighted_credits_l, total_stake ) ) ) {
      return 0;
    }
    *out = res_l;
    return 1;
  }
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1239
static int
merge_delegation_stake_and_credits_observed( FD_FN_UNUSED fd_exec_instr_ctx_t const * invoke_context,
                                             fd_stake_t *                stake,
                                             ulong                       absorbed_lamports,
                                             ulong absorbed_credits_observed ) {
  int rc;
  int  is_some = stake_weighted_credits_observed(
      stake, absorbed_lamports, absorbed_credits_observed, &stake->credits_observed );
  if( FD_UNLIKELY( !is_some ) ) return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  rc = fd_ulong_checked_add( stake->delegation.stake, absorbed_lamports, &stake->delegation.stake );
  if( FD_UNLIKELY( rc ) ) return rc;
  return 0;
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1171
static int
merge_kind_merge( merge_kind_t                  self,
                  fd_exec_instr_ctx_t *         invoke_context, // not const to log
                  merge_kind_t                  source,
                  fd_sol_sysvar_clock_t const * clock,
                  fd_stake_state_v2_t *         out,
                  int  *                        is_some,
                  uint *                        custom_err ) {
  int rc;
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1177
  rc = metas_can_merge( invoke_context, meta( &self ), meta( &source ), clock, custom_err );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1178-L1188
  fd_stake_t const * stake   = active_stake( &self );
  fd_stake_t const * source_ = active_stake( &source );

  // FIXME FD_LIKELY
  if( stake && source_ ) {
    rc = active_delegations_can_merge(
        invoke_context, &stake->delegation, &source_->delegation, custom_err );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1188
  // FIXME FD_LIKELY
  fd_stake_state_v2_t   merged_state_ = {0};
  fd_stake_state_v2_t * merged_state  = &merged_state_;
  if( self.discriminant==merge_kind_inactive && source.discriminant==merge_kind_inactive ) {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1189
    merged_state = NULL;
  } else if( self.discriminant==merge_kind_inactive && source.discriminant==merge_kind_activation_epoch ) {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1190
    merged_state = NULL;
  } else if( self.discriminant==merge_kind_activation_epoch && source.discriminant==merge_kind_inactive ) {
    fd_stake_meta_t  meta               = self.inner.activation_epoch.meta;
    fd_stake_t       stake              = self.inner.activation_epoch.stake;
    fd_stake_flags_t stake_flags        = self.inner.activation_epoch.stake_flags;
    ulong            source_lamports    = source.inner.inactive.active_stake;
    fd_stake_flags_t source_stake_flags = source.inner.inactive.stake_flags;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1195
    rc = fd_ulong_checked_add( stake.delegation.stake, source_lamports, &stake.delegation.stake );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1196
    *merged_state = ( fd_stake_state_v2_t ){
        .discriminant = fd_stake_state_v2_enum_stake,
        .inner        = { .stake = { .meta        = meta,
                                     .stake       = stake,
                                     .stake_flags = { .bits = stake_flags.bits | source_stake_flags.bits } } } };
  } else if( self.discriminant==merge_kind_activation_epoch && source.discriminant==merge_kind_activation_epoch ) {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1203
    fd_stake_meta_t  meta               = self.inner.activation_epoch.meta;
    fd_stake_t       stake              = self.inner.activation_epoch.stake;
    fd_stake_flags_t stake_flags        = self.inner.activation_epoch.stake_flags;
    fd_stake_meta_t  source_meta        = source.inner.activation_epoch.meta;
    fd_stake_t       source_stake       = source.inner.activation_epoch.stake;
    fd_stake_flags_t source_stake_flags = source.inner.activation_epoch.stake_flags;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1206
    ulong source_lamports = ULONG_MAX;
    rc = fd_ulong_checked_add( source_meta.rent_exempt_reserve, source_stake.delegation.stake, &source_lamports );
    if( FD_UNLIKELY( rc ) ) return rc;

    // // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1210
    rc = merge_delegation_stake_and_credits_observed(invoke_context, &stake, source_lamports, source_stake.credits_observed );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1215
    *merged_state = ( fd_stake_state_v2_t ){
        .discriminant = fd_stake_state_v2_enum_stake,
        .inner        = { .stake = { .meta        = meta,
                                     .stake       = stake,
                                     .stake_flags = { .bits = stake_flags.bits | source_stake_flags.bits } } } };
  } else if( self.discriminant==merge_kind_fully_active && source.discriminant==merge_kind_fully_active ) {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1221
    fd_stake_meta_t meta         = self.inner.fully_active.meta;
    fd_stake_t      stake        = self.inner.fully_active.stake;
    fd_stake_t      source_stake = source.inner.fully_active.stake;
    rc                           = merge_delegation_stake_and_credits_observed(
        invoke_context, &stake, source_stake.delegation.stake, source_stake.credits_observed );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L1231
    *merged_state = ( fd_stake_state_v2_t ){
        .discriminant = fd_stake_state_v2_enum_stake,
        .inner = { .stake = { .meta = meta, .stake = stake, .stake_flags = STAKE_FLAGS_EMPTY } } };
  } else {
    *custom_err = FD_STAKE_ERR_MERGE_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  if( !merged_state ) {
    *is_some = 0;
    return 0;
  }
  *is_some = 1;
  *out     = *merged_state;
  return 0;
}

/**********************************************************************/
/* mod stake_state                                                    */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L72
static int
get_stake_status( fd_exec_instr_ctx_t const *    invoke_context,
                  fd_stake_t *                   stake,
                  fd_sol_sysvar_clock_t const *  clock,
                  fd_stake_activation_status_t * out ) {
  fd_stake_history_t const * stake_history = fd_sysvar_cache_stake_history( invoke_context->slot_ctx->sysvar_cache );
  if( FD_UNLIKELY( !stake_history ) )
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  ulong new_rate_activation_epoch = ULONG_MAX;
  int   err;
  int   is_some = new_warmup_cooldown_rate_epoch( invoke_context, &new_rate_activation_epoch, &err );
  if( FD_UNLIKELY( err ) ) return err;

  *out =
      stake_activating_and_deactivating( &stake->delegation,
                                         clock->epoch,
                                         stake_history,
                                         fd_ptr_if( is_some, &new_rate_activation_epoch, NULL ) );
  return 0;
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/vote/state/mod.rs#L740
static ulong
get_credits( fd_vote_state_t       const * vote_state ) {

    return ( deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits )
              ? 0
              : deq_fd_vote_epoch_credits_t_peek_index(
                    vote_state->epoch_credits,
                    deq_fd_vote_epoch_credits_t_cnt( vote_state->epoch_credits ) - 1 )
                    ->credits );
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L85
static int
redelegate_stake( fd_exec_instr_ctx_t const *   ctx,
                  fd_stake_t *                  stake,
                  ulong                         stake_lamports,
                  fd_pubkey_t const *           voter_pubkey,
                  fd_vote_state_t const *       vote_state,
                  fd_sol_sysvar_clock_t const * clock,
                  fd_stake_history_t const *    stake_history,
                  uint *                        custom_err ) {
  ulong new_rate_activation_epoch = ULONG_MAX;
  int   err;
  int   is_some = new_warmup_cooldown_rate_epoch( ctx, &new_rate_activation_epoch, &err );
  if( FD_UNLIKELY( err ) ) return err;

  // FIXME FD_LIKELY
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L96
  if( delegation_stake( &stake->delegation, clock->epoch, stake_history, fd_ptr_if( is_some, &new_rate_activation_epoch, NULL ) )!=0 ) {

    if( FD_LIKELY( !memcmp( &stake->delegation.voter_pubkey, voter_pubkey, sizeof( fd_pubkey_t ) ) ) &&
         clock->epoch==stake->delegation.deactivation_epoch ) {
      stake->delegation.deactivation_epoch = ULONG_MAX;
      return 0;
    } else {
      *custom_err = FD_STAKE_ERR_TOO_SOON_TO_REDELEGATE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  }

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L114-L118
  stake->delegation.stake              = stake_lamports;
  stake->delegation.activation_epoch   = clock->epoch;
  stake->delegation.deactivation_epoch = ULONG_MAX;
  stake->delegation.voter_pubkey       = *voter_pubkey;
  stake->credits_observed              = get_credits( vote_state );
  return 0;
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L202
static fd_stake_t
new_stake( ulong                   stake,
           fd_pubkey_t const *     voter_pubkey,
           fd_vote_state_t const * vote_state,
           ulong                   activation_epoch ) {
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L208
  return ( fd_stake_t ){
      .delegation       = {.voter_pubkey         = *voter_pubkey,
                           .stake                = stake,
                           .activation_epoch     = activation_epoch,
                           .deactivation_epoch   = ULONG_MAX,
                           .warmup_cooldown_rate = DEFAULT_WARMUP_COOLDOWN_RATE},
      .credits_observed = get_credits( vote_state ),
  };
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L214
static int
initialize( fd_exec_instr_ctx_t const *   ctx,
            fd_borrowed_account_t const * stake_account,
            ulong                         stake_acc_idx,
            fd_stake_authorized_t const * authorized,
            fd_stake_lockup_t const *     lockup,
            fd_rent_t const *             rent ) {

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L220

  if( FD_UNLIKELY( stake_account->const_meta->dlen!=stake_state_v2_size_of() ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L224
  fd_stake_state_v2_t stake_state = {0};
  do {
    int rc = get_state( stake_account, fd_scratch_virtual(), &stake_state );
    if( FD_UNLIKELY( rc ) ) return rc;
  } while(0);

  if( FD_LIKELY( stake_state.discriminant==fd_stake_state_v2_enum_uninitialized ) ) {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L225
    ulong rent_exempt_reserve = fd_rent_exempt_minimum_balance( rent, stake_account->const_meta->dlen );

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L226
    if( FD_LIKELY( stake_account->const_meta->info.lamports>=rent_exempt_reserve ) ) {
      fd_stake_state_v2_t initialized = {
        .discriminant = fd_stake_state_v2_enum_initialized,
        .inner = { .initialized = { .meta = { .rent_exempt_reserve = rent_exempt_reserve,
                                              .authorized          = *authorized,
                                              .lockup              = *lockup } } } };
      return set_state( ctx, stake_acc_idx, &initialized );
    } else {
      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L233
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

  } else {

    /// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L236
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  }
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L243
static int
authorize( fd_exec_instr_ctx_t const *   ctx,
           fd_borrowed_account_t *       stake_account,
           ulong                         stake_acc_idx,
           fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
           fd_pubkey_t const *           new_authority,
           fd_stake_authorize_t const *  stake_authorize,
           fd_sol_sysvar_clock_t const * clock,
           fd_pubkey_t const *           custodian,
           uint *                        custom_err ) {
  int                 rc;
  fd_stake_state_v2_t stake_state = {0};
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L251
  rc = get_state( stake_account, fd_scratch_virtual(), &stake_state );
  if( FD_UNLIKELY( rc ) ) return rc;
  switch( stake_state.discriminant ) {
  /* FIXME check if the compiler can optimize away branching (given the layout of `meta` in both
   * union members) and instead fallthrough */
  case fd_stake_state_v2_enum_stake: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L252
    fd_stake_meta_t * meta = &stake_state.inner.stake.meta;

    fd_stake_lockup_custodian_args_t lockup_custodian_args = {
        .lockup = meta->lockup, .clock = *clock, .custodian = (fd_pubkey_t *)custodian };
    rc = authorized_authorize(
        &meta->authorized, /* &mut self */
        signers,
        new_authority,
        stake_authorize,
        &lockup_custodian_args,
        custom_err );
    if( FD_UNLIKELY( rc ) ) return rc;

    return set_state( ctx, stake_acc_idx, &stake_state );
  }
  case fd_stake_state_v2_enum_initialized: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L261
    fd_stake_meta_t * meta = &stake_state.inner.initialized.meta;

    fd_stake_lockup_custodian_args_t lockup_custodian_args = {
        .lockup = meta->lockup, .clock = *clock, .custodian = (fd_pubkey_t *)custodian };
    rc = authorized_authorize(
        &meta->authorized,
        signers,
        new_authority,
        stake_authorize,
        &lockup_custodian_args,
        custom_err );
    if( FD_UNLIKELY( rc ) ) return rc;

    return set_state( ctx, stake_acc_idx, &stake_state );
  }
  default:
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L270
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  return rc;
}

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L275
static int
authorize_with_seed( fd_exec_instr_ctx_t const *   ctx,
                     fd_borrowed_account_t *       stake_account,
                     ulong                         stake_acc_idx,
                     uchar                         authority_base_index,
                     char const *                  authority_seed,
                     ulong                         authority_seed_len,
                     fd_pubkey_t const *           authority_owner,
                     fd_pubkey_t const *           new_authority,
                     fd_stake_authorize_t const *  stake_authorize,
                     fd_sol_sysvar_clock_t const * clock,
                     fd_pubkey_t const *           custodian ) {
  int                 rc;
  fd_pubkey_t const * signers[FD_TXN_SIG_MAX] = {0};
  fd_pubkey_t         out                     = {0};
  if( FD_LIKELY( fd_instr_acc_is_signer_idx( ctx->instr, authority_base_index ) ) ) {

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L289
    fd_pubkey_t const * base_pubkey = &ctx->instr->acct_pubkeys[authority_base_index];

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L293
    rc = fd_pubkey_create_with_seed( ctx,
                                     base_pubkey->uc,
                                     authority_seed,
                                     authority_seed_len,
                                     authority_owner->uc,
                                     /* out */ out.uc );
    if( FD_UNLIKELY( rc ) ) return rc;
    signers[0] = &out;
  }
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L299
  return authorize( ctx,
                    stake_account,
                    stake_acc_idx,
                    signers,
                    new_authority,
                    stake_authorize,
                    clock,
                    custodian,
                    &ctx->txn_ctx->custom_err );
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L310
static int
delegate( fd_exec_instr_ctx_t const *   ctx,
          uchar                         stake_account_index,
          uchar                         vote_account_index,
          fd_sol_sysvar_clock_t const * clock,
          fd_stake_history_t const *    stake_history,
          fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX] ) {
  int rc;

  fd_valloc_t scratch_valloc = fd_scratch_virtual();

  fd_pubkey_t const * vote_pubkey;
  fd_vote_state_versioned_t vote_state = {0};
  int vote_get_state_rc;
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L321
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, vote_account_index, vote_account ) {

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L323
  if( FD_UNLIKELY( memcmp( &vote_account->const_meta->info.owner, fd_solana_vote_program_id.key, 32UL ) ) )
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L3326
  vote_pubkey = vote_account->pubkey;
  // https://github.com/anza-xyz/agave/blob/a60fbc2288d626a4f1846052c8fcb98d3f9ea58d/programs/stake/src/stake_state.rs#L327
  vote_get_state_rc = fd_vote_get_state( vote_account, scratch_valloc, &vote_state );

  } FD_BORROWED_ACCOUNT_DROP( vote_account );

  fd_stake_state_v2_t stake_state = {0};
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L330
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, stake_account_index, stake_account ) {
  
  rc = get_state( stake_account, fd_scratch_virtual(), &stake_state );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L332
  switch( stake_state.discriminant ) {
  case fd_stake_state_v2_enum_initialized: {
    fd_stake_meta_t meta = stake_state.inner.initialized.meta;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L334
    rc = authorized_check( &meta.authorized, signers, STAKE_AUTHORIZE_STAKER );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L335-L336
    validated_delegated_info_t validated_delegated_info;
    rc = validate_delegated_amount( stake_account,
                                    &meta,
                                    ctx->slot_ctx,
                                    &validated_delegated_info,
                                    &ctx->txn_ctx->custom_err );
    if( FD_UNLIKELY( rc ) ) return rc;
    ulong stake_amount = validated_delegated_info.stake_amount;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L340
    if( FD_UNLIKELY( vote_get_state_rc ) ) return vote_get_state_rc;
    fd_vote_convert_to_current( &vote_state, scratch_valloc ); // FIXME
    fd_stake_t stake =
        new_stake( stake_amount, vote_pubkey, &vote_state.inner.current, clock->epoch );
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L343
    fd_stake_state_v2_t new_stake_state = { .discriminant = fd_stake_state_v2_enum_stake,
                                            .inner        = { .stake = {
                                                                  .meta        = meta,
                                                                  .stake       = stake,
                                                                  .stake_flags = STAKE_FLAGS_EMPTY } } };
    return set_state( ctx, stake_account_index, &new_stake_state );
  }
  case fd_stake_state_v2_enum_stake: {
    fd_stake_meta_t  meta        = stake_state.inner.stake.meta;
    fd_stake_t       stake       = stake_state.inner.stake.stake;
    fd_stake_flags_t stake_flags = stake_state.inner.stake.stake_flags;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L346
    rc = authorized_check( &meta.authorized, signers, STAKE_AUTHORIZE_STAKER );
    if( FD_UNLIKELY( rc ) ) return rc;
    
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L347-L348
    validated_delegated_info_t validated_delegated_info;
    rc = validate_delegated_amount( stake_account,
                                    &meta,
                                    ctx->slot_ctx,
                                    &validated_delegated_info,
                                    &ctx->txn_ctx->custom_err );
    if( FD_UNLIKELY( rc ) ) return rc;
    ulong stake_amount = validated_delegated_info.stake_amount;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L354
    if( FD_UNLIKELY( vote_get_state_rc ) ) return vote_get_state_rc;
    fd_vote_convert_to_current( &vote_state, scratch_valloc );
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L349
    rc = redelegate_stake( ctx,
                           &stake,
                           stake_amount,
                           vote_pubkey,
                           &vote_state.inner.current,
                           clock,
                           stake_history,
                           &ctx->txn_ctx->custom_err );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L358
    fd_stake_state_v2_t new_stake_state = { .discriminant = fd_stake_state_v2_enum_stake,
                                            .inner        = { .stake = {
                                                                  .meta        = meta,
                                                                  .stake       = stake,
                                                                  .stake_flags = stake_flags } } };
     
    return set_state( ctx, stake_account_index, &new_stake_state );
  }
  default:
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L360
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  } FD_BORROWED_ACCOUNT_DROP( stake_account );
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L364
static int
deactivate( fd_exec_instr_ctx_t const *   ctx,
            fd_borrowed_account_t *       stake_account,
            ulong                         stake_acc_idx,
            fd_sol_sysvar_clock_t const * clock,
            fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
            uint *                        custom_err ) {
  int rc;

  fd_stake_state_v2_t state = {0};
  rc                        = get_state( stake_account, fd_scratch_virtual(), &state );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L370
  if( state.discriminant==fd_stake_state_v2_enum_stake ) {
    fd_stake_meta_t * meta  = &state.inner.stake.meta;
    fd_stake_t *      stake = &state.inner.stake.stake;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L371
    rc = authorized_check( &meta->authorized, signers, STAKE_AUTHORIZE_STAKER );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L372
    rc = stake_deactivate( stake, clock->epoch, custom_err );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L373
    return set_state( ctx, stake_acc_idx, &state );
  } else {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L375
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L379
static int
set_lockup( fd_exec_instr_ctx_t const *   ctx,
            fd_borrowed_account_t *       stake_account,
            ulong                         stake_acc_idx,
            fd_lockup_args_t const *      lockup,
            fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX],
            fd_sol_sysvar_clock_t const * clock ) {
  int rc;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L385
  fd_stake_state_v2_t state = {0};
  rc = get_state( stake_account, fd_scratch_virtual(), &state );
  if( FD_UNLIKELY( rc ) ) return rc;

  switch( state.discriminant ) {
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L386
  case fd_stake_state_v2_enum_initialized: {
    fd_stake_meta_t * meta = &state.inner.initialized.meta;
    rc                     = set_lockup_meta( meta, lockup, signers, clock );
    if( FD_UNLIKELY( rc ) ) return rc;
    return set_state( ctx, stake_acc_idx, &state );
  }
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L390
  case fd_stake_state_v2_enum_stake: {
    fd_stake_meta_t * meta = &state.inner.stake.meta;
    rc                     = set_lockup_meta( meta, lockup, signers, clock );
    if( FD_UNLIKELY( rc ) ) return rc;
    return set_state( ctx, stake_acc_idx, &state );
  }
  default:
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L394
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L398
static int
split( fd_exec_instr_ctx_t const * ctx,
       uchar                       stake_account_index,
       ulong                       lamports,
       uchar                       split_index,
       fd_pubkey_t const *         signers[static FD_TXN_SIG_MAX] ) {
  int rc;

  ulong split_lamport_balance = 0;
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L407
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, split_index, split ) {

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L409
  if( FD_UNLIKELY( memcmp( &split->const_meta->info.owner, fd_solana_stake_program_id.key, 32UL ) ) )
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L412
  if( FD_UNLIKELY( split->const_meta->dlen!=stake_state_v2_size_of() ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L415
  fd_stake_state_v2_t split_get_state = {0};
  rc = get_state( split, fd_scratch_virtual(), &split_get_state );
  if( FD_UNLIKELY( rc ) ) return rc;
  if( FD_UNLIKELY( split_get_state.discriminant!=fd_stake_state_v2_enum_uninitialized ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L418
  split_lamport_balance = split->const_meta->info.lamports;

  } FD_BORROWED_ACCOUNT_DROP( split );

  fd_stake_state_v2_t stake_state = {0};
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L420
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, stake_account_index, stake_account) {
  
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L422
  if( FD_UNLIKELY( lamports>stake_account->const_meta->info.lamports ) )
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    
  rc = get_state( stake_account, fd_scratch_virtual(), &stake_state );
  if( FD_UNLIKELY( rc ) ) return rc;

  } FD_BORROWED_ACCOUNT_DROP( stake_account );

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L428
  switch( stake_state.discriminant ) {
  case fd_stake_state_v2_enum_stake: {
    fd_stake_meta_t *  meta        = &stake_state.inner.stake.meta;
    fd_stake_t *       stake       = &stake_state.inner.stake.stake;
    fd_stake_flags_t * stake_flags = &stake_state.inner.stake.stake_flags;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L430
    rc = authorized_check( &meta->authorized, signers, STAKE_AUTHORIZE_STAKER );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L431
    ulong minimum_delegation = get_minimum_delegation( ctx->slot_ctx );
    
    int   is_active;
    if( FD_UNLIKELY( FD_FEATURE_ACTIVE( ctx->slot_ctx,
                                         require_rent_exempt_split_destination ) ) ) {
      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L434
      fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock( ctx->slot_ctx->sysvar_cache );
      if( FD_UNLIKELY( !clock ) )
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L435
      fd_stake_activation_status_t status = {0};
      rc = get_stake_status( ctx, stake, clock, &status );
      if( FD_UNLIKELY( rc ) ) return rc;

      is_active = status.effective>0;
    } else {
      is_active = 0;
    }

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L438
    validated_split_info_t validated_split_info = {0};
    rc = validate_split_amount( ctx,
                                stake_account_index,
                                split_index,
                                lamports,
                                meta,
                                minimum_delegation,
                                is_active,
                                &validated_split_info );
    if( FD_UNLIKELY( rc ) ) return rc;

    ulong remaining_stake_delta;
    ulong split_stake_amount;
    // FIXME FD_LIKELY
    
    if( validated_split_info.source_remaining_balance==0 ) {
      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L456
      remaining_stake_delta = fd_ulong_sat_sub( lamports, meta->rent_exempt_reserve );
      split_stake_amount    = remaining_stake_delta;
    } else {
      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L469
      if( FD_UNLIKELY( fd_ulong_sat_sub( stake->delegation.stake, lamports ) <
                        minimum_delegation ) ) {
        ctx->txn_ctx->custom_err = FD_STAKE_ERR_INSUFFICIENT_DELEGATION;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }

      remaining_stake_delta = lamports;
      split_stake_amount =
          fd_ulong_sat_sub( lamports,
                            fd_ulong_sat_sub( validated_split_info.destination_rent_exempt_reserve,
                                              split_lamport_balance )

          );
    }

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L487
    if( FD_UNLIKELY( split_stake_amount<minimum_delegation ) ) {
      ctx->txn_ctx->custom_err = FD_STAKE_ERR_INSUFFICIENT_DELEGATION;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L491-L493
    fd_stake_t split_stake = {0};
    rc = stake_split( stake,
                      remaining_stake_delta,
                      split_stake_amount,
                      &ctx->txn_ctx->custom_err,
                      &split_stake );
    if( FD_UNLIKELY( rc ) ) return rc;
    fd_stake_meta_t split_meta     = *meta;
    split_meta.rent_exempt_reserve = validated_split_info.destination_rent_exempt_reserve;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L495
    FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, stake_account_index, stake_account ) {

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L497
    rc = set_state( ctx, stake_account_index, &stake_state );
    if( FD_UNLIKELY( rc ) ) return rc;

    } FD_BORROWED_ACCOUNT_DROP( stake_account );

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L499
    FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, split_index, split ) {

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L501
    fd_stake_state_v2_t temp = { .discriminant = fd_stake_state_v2_enum_stake,
                                 .inner        = { .stake = { .meta        = split_meta,
                                                              .stake       = split_stake,
                                                              .stake_flags = *stake_flags } } };
    rc = set_state( ctx, split_index, &temp );
    if( FD_UNLIKELY( rc ) ) return rc;

    } FD_BORROWED_ACCOUNT_DROP( split );
    break;
  }
  case fd_stake_state_v2_enum_initialized: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L504
    fd_stake_meta_t * meta = &stake_state.inner.initialized.meta;
    rc                     = authorized_check( &meta->authorized, signers, STAKE_AUTHORIZE_STAKER );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L505
    validated_split_info_t validated_split_info = {0};
    rc = validate_split_amount( ctx,
                                stake_account_index,
                                split_index,
                                lamports,
                                meta,
                                0,
                                0,
                                &validated_split_info );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L516
    fd_stake_meta_t split_meta     = *meta;
    split_meta.rent_exempt_reserve = validated_split_info.destination_rent_exempt_reserve;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L518
    FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, split_index, split ) {
    
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L520
    fd_stake_state_v2_t temp = { .discriminant = fd_stake_state_v2_enum_initialized,
                                 .inner        = { .initialized = { .meta = split_meta } } };
    rc = set_state( ctx, split_index, &temp );
    if( FD_UNLIKELY( rc ) ) return rc;

    } FD_BORROWED_ACCOUNT_DROP( split );
    break;
  }
  case fd_stake_state_v2_enum_uninitialized: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L523
    fd_pubkey_t const * stake_pubkey = &ctx->instr->acct_pubkeys[stake_account_index];
    if( FD_UNLIKELY( !fd_instr_signers_contains( signers, stake_pubkey ) ) ) {
      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L527
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
    break;
  }
  default:
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L531
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L535
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, stake_account_index, stake_account ) {

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L537
  if( FD_UNLIKELY( lamports==stake_account->const_meta->info.lamports ) ) {
    fd_stake_state_v2_t uninitialized = {0};
    uninitialized.discriminant        = fd_stake_state_v2_enum_uninitialized;
    rc                                = set_state( ctx, stake_account_index, &uninitialized );
    if( FD_UNLIKELY( rc ) ) return rc;
  };

  } FD_BORROWED_ACCOUNT_DROP( stake_account );

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L542
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, split_index, split ) {
  
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L544
  rc = fd_account_checked_add_lamports( ctx, split_index, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;


  } FD_BORROWED_ACCOUNT_DROP( split );

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L546
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, stake_account_index, stake_account ) {

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L548
  rc = fd_account_checked_sub_lamports( ctx, stake_account_index, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;

  } FD_BORROWED_ACCOUNT_DROP( stake_account );
  return 0;
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L552
static int
merge( fd_exec_instr_ctx_t *         ctx, // not const to log
       uchar                         stake_account_index,
       uchar                         source_account_index,
       fd_sol_sysvar_clock_t const * clock,
       fd_stake_history_t const *    stake_history,
       fd_pubkey_t const *           signers[static FD_TXN_SIG_MAX] ) {
  int rc;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L562
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, source_account_index, source_account  ) {

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L565
  if( FD_UNLIKELY( memcmp( &source_account->const_meta->info.owner, fd_solana_stake_program_id.key, 32UL ) ) )
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L569
  if( FD_UNLIKELY( !memcmp( &ctx->instr->acct_pubkeys[stake_account_index], &ctx->instr->acct_pubkeys[source_account_index], sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L575
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, stake_account_index, stake_account  ) {

  fd_stake_state_v2_t stake_account_state = {0};
  rc = get_state( stake_account, fd_scratch_virtual(), &stake_account_state );
  if( FD_UNLIKELY( rc ) ) return rc;

  merge_kind_t stake_merge_kind = {0};
  fd_log_collector_msg_literal( ctx, "Checking if destination stake is mergeable" );
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L579
  rc = get_if_mergeable( ctx,
                         &stake_account_state,
                         stake_account->const_meta->info.lamports,
                         clock,
                         stake_history,
                         &stake_merge_kind,
                         &ctx->txn_ctx->custom_err );
  if( FD_UNLIKELY( rc ) )
    return rc;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L588
  rc = authorized_check( &meta( &stake_merge_kind )->authorized, signers, STAKE_AUTHORIZE_STAKER );
  if( FD_UNLIKELY( rc ) )
    return rc;

  fd_stake_state_v2_t source_account_state = {0};
  rc = get_state( source_account, fd_scratch_virtual(), &source_account_state );
  if( FD_UNLIKELY( rc ) ) return rc;

  merge_kind_t source_merge_kind = {0};
  fd_log_collector_msg_literal( ctx, "Checking if source stake is mergeable" );
  //https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L594
  rc = get_if_mergeable( ctx,
                         &source_account_state,
                         source_account->const_meta->info.lamports,
                         clock,
                         stake_history,
                         &source_merge_kind,
                         &ctx->txn_ctx->custom_err );
  if( FD_UNLIKELY( rc ) ) return rc;

  fd_stake_state_v2_t merged_state = {0};
  int                 is_some      = 0;
  fd_log_collector_msg_literal( ctx, "Merging stake accounts" );
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L603
  rc = merge_kind_merge( stake_merge_kind,
                         ctx,
                         source_merge_kind,
                         clock,
                         &merged_state,
                         &is_some,
                         &ctx->txn_ctx->custom_err );
  if( FD_UNLIKELY( rc ) ) return rc;
  if( is_some ) {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L608
    rc = set_state( ctx, stake_account_index, &merged_state );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  //  https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L608
  fd_stake_state_v2_t uninitialized = {0};
  uninitialized.discriminant        = fd_stake_state_v2_enum_uninitialized;
  rc                                = set_state( ctx, source_account_index, &uninitialized );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L611-L613
  ulong lamports = source_account->const_meta->info.lamports;
  rc = fd_account_checked_sub_lamports( ctx, source_account_index, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;
  rc = fd_account_checked_add_lamports( ctx, stake_account_index, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;

  } FD_BORROWED_ACCOUNT_DROP( stake_account );
  } FD_BORROWED_ACCOUNT_DROP( source_account );

  return 0;
}

// https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L136
static int 
move_stake_or_lamports_shared_checks( fd_exec_instr_ctx_t *   invoke_context, // not const to log
                                      fd_borrowed_account_t * source_account,
                                      ulong                   lamports,
                                      fd_borrowed_account_t * destination_account,
                                      ulong                   stake_authority_index,
                                      merge_kind_t *          source_merge_kind,
                                      merge_kind_t *          destination_merge_kind,
                                      uint *                  custom_err ) {
    int rc;

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L145-L153
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( invoke_context->instr, stake_authority_index ) ) ) { 
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    fd_pubkey_t const * stake_authority_pubkey = &invoke_context->instr->acct_pubkeys[stake_authority_index];
    fd_pubkey_t const * signers[FD_TXN_SIG_MAX] = { stake_authority_pubkey };

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L158
    if( FD_UNLIKELY( memcmp( &source_account->const_meta->info.owner, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ||
                     memcmp( &destination_account->const_meta->info.owner, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) )
      return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L163
    if( FD_UNLIKELY( !memcmp( &source_account->pubkey, &destination_account->pubkey, sizeof(fd_pubkey_t) ) ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L168
    if( FD_UNLIKELY( !fd_instr_acc_is_writable( invoke_context->instr, source_account->pubkey ) ||
                     !fd_instr_acc_is_writable( invoke_context->instr, destination_account->pubkey ) ) )
        return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L173
    if( lamports==0 )
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    
    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L177-L180
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock( invoke_context->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !clock ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    fd_stake_history_t const * stake_history = fd_sysvar_cache_stake_history( invoke_context->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !stake_history ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L182
    fd_stake_state_v2_t source_account_state = {0};
    rc = get_state( source_account, fd_scratch_virtual(), &source_account_state );
    if( FD_UNLIKELY( rc ) ) return rc;

    rc = get_if_mergeable( invoke_context,
                         &source_account_state,
                         source_account->const_meta->info.lamports,
                         clock,
                         stake_history,
                         source_merge_kind,
                         &invoke_context->txn_ctx->custom_err );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L191
    rc = authorized_check( &meta( source_merge_kind )->authorized, signers, STAKE_AUTHORIZE_STAKER );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L197
    fd_stake_state_v2_t destination_account_state = {0};
    rc = get_state( destination_account, fd_scratch_virtual(), &destination_account_state );
    if( FD_UNLIKELY( rc ) ) return rc;

    rc = get_if_mergeable( invoke_context,
                         &destination_account_state,
                         destination_account->const_meta->info.lamports,
                         clock,
                         stake_history,
                         destination_merge_kind,
                         &invoke_context->txn_ctx->custom_err );
    if( FD_UNLIKELY( rc ) ) return rc;
    
    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L206
    rc = metas_can_merge( invoke_context, meta( source_merge_kind ), meta( destination_merge_kind ), clock, custom_err );
    if( FD_UNLIKELY( rc ) ) return rc;

  return 0;
}

// https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L789
static int
move_stake(fd_exec_instr_ctx_t * ctx, // not const to log
           ulong                 source_account_index,
           ulong                 lamports,
           ulong                 destination_account_index,
           ulong                 stake_authority_index,
           uint *                custom_err ) {
  int rc;

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L798-L804
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, source_account_index, source_account ) {
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, destination_account_index, destination_account ) {
  
  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L804
  merge_kind_t source_merge_kind = {0};
  merge_kind_t destination_merge_kind = {0};
  rc = move_stake_or_lamports_shared_checks( ctx,
                                             source_account,
                                             lamports,
                                             destination_account,
                                             stake_authority_index,
                                             &source_merge_kind,
                                             &destination_merge_kind,
                                             &ctx->txn_ctx->custom_err );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L816
  if( FD_UNLIKELY( source_account->const_meta->dlen!=stake_state_v2_size_of() ||
                   destination_account->const_meta->dlen!=stake_state_v2_size_of() ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L823
  if( source_merge_kind.discriminant!=merge_kind_fully_active )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  fd_stake_meta_t * source_meta = &source_merge_kind.inner.fully_active.meta;
  fd_stake_t * source_stake = &source_merge_kind.inner.fully_active.stake;

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L827
  ulong minimum_delegation = get_minimum_delegation( ctx->slot_ctx );  

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L831
  if( FD_UNLIKELY( source_stake->delegation.stake<lamports ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  ulong source_final_stake = source_stake->delegation.stake - lamports;

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L836 
  if( FD_UNLIKELY( source_final_stake!=0 && source_final_stake<minimum_delegation ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  
  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L841
  fd_stake_meta_t * destination_meta = NULL;
  switch( destination_merge_kind.discriminant ) {
  case merge_kind_fully_active: {
    fd_stake_t * destination_stake = &destination_merge_kind.inner.fully_active.stake;

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L844
    if( FD_UNLIKELY( memcmp( &source_stake->delegation.voter_pubkey, &destination_stake->delegation.voter_pubkey, sizeof(fd_pubkey_t) ) ) ) {
      *custom_err = FD_STAKE_ERR_VOTE_ADDRESS_MISMATCH;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L848
    ulong destination_effective_stake = 0;
    rc = fd_ulong_checked_add( destination_stake->delegation.stake, lamports, &destination_effective_stake );
    if( FD_UNLIKELY( rc ) ) return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L855
    if( FD_UNLIKELY( destination_effective_stake<minimum_delegation ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L859
    rc = merge_delegation_stake_and_credits_observed(
      ctx, destination_stake, lamports, source_stake->credits_observed );
    if( FD_UNLIKELY( rc ) ) return rc;
    destination_meta = &destination_merge_kind.inner.fully_active.meta;

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L867
    fd_stake_state_v2_t new_destination_state = {
      .discriminant = fd_stake_state_v2_enum_stake,
      .inner        = { .stake = {
                            .meta        = *destination_meta,
                            .stake       = *destination_stake,
                            .stake_flags = STAKE_FLAGS_EMPTY} } };
    rc = set_state( ctx, destination_account_index, &new_destination_state );
    if( FD_UNLIKELY( rc ) ) return rc;
  
    break;
  }
  case merge_kind_inactive: {
    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L877
    if( lamports<minimum_delegation ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L881
    fd_stake_t * destination_stake = source_stake;
    destination_stake->delegation.stake = lamports;

    destination_meta = &destination_merge_kind.inner.inactive.meta;

    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L886
    fd_stake_state_v2_t new_destination_state = {
      .discriminant = fd_stake_state_v2_enum_stake,
      .inner        = { .stake = {
                            .meta        = *destination_meta,
                            .stake       = *destination_stake,
                            .stake_flags = STAKE_FLAGS_EMPTY} } };
    rc = set_state( ctx, destination_account_index, &new_destination_state );
    if( FD_UNLIKELY( rc ) ) return rc;
    break;
  }
  default:
    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L894
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L897-L910
  if( source_final_stake==0) {
    fd_stake_state_v2_t new_source_state = { .discriminant = fd_stake_state_v2_enum_initialized,
                                 .inner        = { .initialized = { .meta =  *source_meta} } };
    rc = set_state( ctx, source_account_index, &new_source_state );
    if( FD_UNLIKELY( rc ) ) return rc;
    
  } else {
    source_stake->delegation.stake = source_final_stake;
  
    fd_stake_state_v2_t new_source_state = { .discriminant = fd_stake_state_v2_enum_stake,
                               .inner        = { .stake = { .meta = *source_meta,
                                                            .stake = *source_stake,
                                                            .stake_flags = STAKE_FLAGS_EMPTY } } };
    rc = set_state( ctx, source_account_index, &new_source_state );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L911-L914
  rc = fd_account_checked_sub_lamports( ctx, source_account_index, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;
  rc = fd_account_checked_add_lamports( ctx, destination_account_index, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L915-L923
  if( FD_UNLIKELY( fd_account_get_lamports2( ctx, source_account_index )<source_meta->rent_exempt_reserve ) ||
                   fd_account_get_lamports2( ctx, destination_account_index )<destination_meta->rent_exempt_reserve ) {
    fd_log_collector_msg_literal( ctx, "Delegation calculations violated lamport balance assumptions" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;                 
  }

  } FD_BORROWED_ACCOUNT_DROP( destination_account );
  } FD_BORROWED_ACCOUNT_DROP( source_account );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L928
static int
move_lamports(fd_exec_instr_ctx_t * ctx, // not const to log
              ulong                 source_account_index,
              ulong                 lamports,
              ulong                 destination_account_index,
              ulong                 stake_authority_index ) {
  int rc;

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L937-L942
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, source_account_index, source_account ) {
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, destination_account_index, destination_account ) {


  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L943
  merge_kind_t source_merge_kind = {0};
  merge_kind_t destination_merge_kind = {0};
  rc = move_stake_or_lamports_shared_checks( ctx,
                                             source_account,
                                             lamports,
                                             destination_account,
                                             stake_authority_index,
                                             &source_merge_kind,
                                             &destination_merge_kind,
                                             &ctx->txn_ctx->custom_err );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L953-L963
  ulong source_free_lamports;
  switch( source_merge_kind.discriminant ) {
    case merge_kind_fully_active: {
      source_free_lamports = fd_ulong_sat_sub( fd_ulong_sat_sub( source_account->const_meta->info.lamports,
                                                                 source_merge_kind.inner.fully_active.stake.delegation.stake ),
                                                source_merge_kind.inner.fully_active.meta.rent_exempt_reserve );
      
      break;
    }
    case merge_kind_inactive: {
      source_free_lamports = fd_ulong_sat_sub( source_merge_kind.inner.inactive.active_stake,
                                               source_merge_kind.inner.inactive.meta.rent_exempt_reserve );
      break;
    }
    default:
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L964
  if( FD_UNLIKELY( lamports>source_free_lamports ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_state.rs#L968-L970
  rc = fd_account_checked_sub_lamports( ctx, source_account_index, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;

  rc = fd_account_checked_add_lamports( ctx, destination_account_index, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;

  } FD_BORROWED_ACCOUNT_DROP( destination_account );
  } FD_BORROWED_ACCOUNT_DROP( source_account );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L797
static int
withdraw( fd_exec_instr_ctx_t const *   ctx,
          uchar                         stake_account_index,
          ulong                         lamports,
          uchar                         to_index,
          fd_sol_sysvar_clock_t const * clock,
          fd_stake_history_t const *    stake_history,
          uchar                         withdraw_authority_index,
          uchar *                       custodian_index,
          ulong *                       new_rate_activation_epoch ) {

  int rc;
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L809
  fd_pubkey_t const * withdraw_authority_pubkey = &ctx->instr->acct_pubkeys[withdraw_authority_index];

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L813
  int is_signer = fd_instr_acc_is_signer_idx( ctx->instr, withdraw_authority_index );
  if( FD_UNLIKELY( !is_signer ) ) return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L817
  fd_pubkey_t const * signers[FD_TXN_SIG_MAX] = { withdraw_authority_pubkey };

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L819
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, stake_account_index, stake_account ) {
  
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L821
  fd_stake_state_v2_t stake_state = {0};
  rc = get_state( stake_account, fd_scratch_virtual(), &stake_state );
  if( FD_UNLIKELY( rc ) ) return rc;

  fd_stake_lockup_t lockup;
  ulong             reserve;
  int               is_staked;

  switch( stake_state.discriminant ) {
  case fd_stake_state_v2_enum_stake: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L822
    fd_stake_meta_t * meta  = &stake_state.inner.stake.meta;
    fd_stake_t *      stake = &stake_state.inner.stake.stake;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L823
    rc = authorized_check( &meta->authorized, signers, STAKE_AUTHORIZE_WITHDRAWER );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L826
    ulong staked = fd_ulong_if(
        clock->epoch>=stake->delegation.deactivation_epoch,
        delegation_stake(
            &stake->delegation, clock->epoch, stake_history, new_rate_activation_epoch ),
        stake->delegation.stake );

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L837
    ulong staked_and_reserve = ULONG_MAX;
    rc = fd_ulong_checked_add( staked, meta->rent_exempt_reserve, &staked_and_reserve );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L838
    lockup    = meta->lockup;
    reserve   = staked_and_reserve;
    is_staked = staked!=0;
    break;
  }
  case fd_stake_state_v2_enum_initialized: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L840
    fd_stake_meta_t * meta = &stake_state.inner.initialized.meta;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L841
    rc = authorized_check( &meta->authorized, signers, STAKE_AUTHORIZE_WITHDRAWER );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L844
    lockup    = meta->lockup;
    reserve   = meta->rent_exempt_reserve;
    is_staked = 0;
    break;
  }
  case fd_stake_state_v2_enum_uninitialized: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L846
    if( FD_UNLIKELY( !fd_instr_signers_contains( signers, stake_account->pubkey ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L850
    memset( &lockup, 0, sizeof( fd_stake_lockup_t ) ); /* Lockup::default(); */
    reserve   = 0;
    is_staked = 0;
    break;
  }
  default:
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L852
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  // FIXME FD_LIKELY
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L857-L871
  fd_pubkey_t custodian_pubkey_ = {0};
  fd_pubkey_t const * custodian_pubkey  = &custodian_pubkey_;
  if( custodian_index ) {
    int is_signer = fd_instr_acc_is_signer_idx( ctx->instr, *custodian_index );
    if( is_signer ) {
      custodian_pubkey = &ctx->instr->acct_pubkeys[*custodian_index];
    } else {
      custodian_pubkey = NULL;
    }
  } else {
    custodian_pubkey = NULL;
  }
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L871
  if( FD_UNLIKELY( lockup_is_in_force( &lockup, clock, custodian_pubkey ) ) ) {
    ctx->txn_ctx->custom_err = FD_STAKE_ERR_LOCKUP_IN_FORCE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  };

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L875
  ulong lamports_and_reserve = ULONG_MAX;
  rc                         = fd_ulong_checked_add( lamports, reserve, &lamports_and_reserve );
  if( FD_UNLIKELY( rc ) ) return rc;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L877
  if( FD_UNLIKELY( is_staked && lamports_and_reserve>stake_account->const_meta->info.lamports ) ) {
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L883
  if( FD_UNLIKELY( lamports!=stake_account->const_meta->info.lamports &&
                    lamports_and_reserve>stake_account->const_meta->info.lamports ) ) {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L886
    FD_TEST( !is_staked );
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }

  // FIXME FD_LIKELY
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L891
  if( lamports==stake_account->const_meta->info.lamports ) {
    fd_stake_state_v2_t uninitialized = {0};
    uninitialized.discriminant        = fd_stake_state_v2_enum_uninitialized;
    rc                                = set_state( ctx, stake_account_index, &uninitialized );
    if( FD_UNLIKELY( rc ) ) return rc;
  }

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L895
  rc = fd_account_checked_sub_lamports( ctx, stake_account_index, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;

  } FD_BORROWED_ACCOUNT_DROP( stake_account );

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L897
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, to_index, to ) {

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L899
  rc = fd_account_checked_add_lamports( ctx, to_index, lamports );
  if( FD_UNLIKELY( rc ) ) return rc;

  } FD_BORROWED_ACCOUNT_DROP( to );
  
  return 0;
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L903
static int
deactivate_delinquent( fd_exec_instr_ctx_t *   ctx,
                       fd_borrowed_account_t * stake_account,
                       ulong                   stake_acc_index,
                       ulong                   delinquent_vote_account_index,
                       ulong                   reference_vote_account_index,
                       ulong                   current_epoch,
                       uint *                  custom_err ) {
  int rc;

  fd_valloc_t scratch_valloc = fd_scratch_virtual();

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L911
  fd_pubkey_t const * delinquent_vote_account_pubkey =
      &ctx->instr->acct_pubkeys[delinquent_vote_account_index];

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L915
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, delinquent_vote_account_index, delinquent_vote_account ) {

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L917
  if( FD_UNLIKELY( memcmp( &delinquent_vote_account->const_meta->info.owner, fd_solana_vote_program_id.key, 32UL ) ) )
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L920-L922
  fd_vote_state_versioned_t delinquent_vote_state_versioned = {0};
  rc = fd_vote_get_state( delinquent_vote_account, scratch_valloc, &delinquent_vote_state_versioned );
  if( FD_UNLIKELY( rc ) ) return rc;
  fd_vote_convert_to_current( &delinquent_vote_state_versioned, scratch_valloc );
  fd_vote_state_t delinquent_vote_state = delinquent_vote_state_versioned.inner.current;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L924
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, reference_vote_account_index, reference_vote_account ) {

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L926
  if( FD_UNLIKELY( memcmp( &reference_vote_account->const_meta->info.owner, fd_solana_vote_program_id.key, 32UL ) ) )
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L929-L932
  fd_vote_state_versioned_t reference_vote_state_versioned = {0};
  rc = fd_vote_get_state( reference_vote_account, scratch_valloc, &reference_vote_state_versioned );
  if( FD_UNLIKELY( rc ) ) return rc;
  fd_vote_convert_to_current( &reference_vote_state_versioned, scratch_valloc );
  fd_vote_state_t reference_vote_state = reference_vote_state_versioned.inner.current;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L933
  if( !acceptable_reference_epoch_credits( reference_vote_state.epoch_credits, current_epoch ) ) {
    ctx->txn_ctx->custom_err = FD_STAKE_ERR_INSUFFICIENT_REFERENCE_VOTES;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_stake_state_v2_t stake_state = {0};
  rc = get_state( stake_account, fd_scratch_virtual(), &stake_state );
  if( FD_UNLIKELY( rc ) ) return rc;
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L937
  if( FD_LIKELY( stake_state.discriminant==fd_stake_state_v2_enum_stake ) ) {
    fd_stake_t * stake = &stake_state.inner.stake.stake;

    if( FD_UNLIKELY( memcmp( &stake->delegation.voter_pubkey, delinquent_vote_account_pubkey, sizeof(fd_pubkey_t) ) ) ) {
      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L939
      *custom_err = FD_STAKE_ERR_VOTE_ADDRESS_MISMATCH;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L944 
    if( FD_LIKELY( eligible_for_deactivate_delinquent( delinquent_vote_state.epoch_credits,
                                                        current_epoch ) ) ) {
      rc = stake_deactivate( stake, current_epoch, custom_err );
      if( FD_UNLIKELY( rc ) ) return rc;
      rc = set_state( ctx, stake_acc_index, &stake_state );
    } else {
      // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L948
      *custom_err = FD_STAKE_ERR_MINIMUM_DELIQUENT_EPOCHS_FOR_DEACTIVATION_NOT_MET;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  } else {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_state.rs#L951
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  } FD_BORROWED_ACCOUNT_DROP( reference_vote_account );
  } FD_BORROWED_ACCOUNT_DROP( delinquent_vote_account );

  return rc;
}

/**********************************************************************/
/* mod stake_instruction                                              */
/**********************************************************************/

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L25
static int
get_optional_pubkey( fd_exec_instr_ctx_t *          ctx,
                     ulong                          acc_idx,
                     int                            should_be_signer,
                     /* out */ fd_pubkey_t const ** pubkey ) {
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L32
  if( FD_LIKELY( acc_idx<ctx->instr->acct_cnt ) ) {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L33
    if( FD_UNLIKELY( should_be_signer && !fd_instr_acc_is_signer_idx( ctx->instr, acc_idx ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L39
    *pubkey = &ctx->instr->acct_pubkeys[acc_idx];
  } else {
    *pubkey = NULL;
  }
  return 0;
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L60
static int
get_stake_account( fd_exec_instr_ctx_t const * ctx,
                   fd_borrowed_account_t **    out ) {

  if( FD_UNLIKELY( ctx->instr->acct_cnt<1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L61
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, 0, out );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  fd_borrowed_account_t * account = *out;
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( account ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  // https://github.com/https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L62-L65
  if( FD_UNLIKELY( memcmp( account->const_meta->info.owner, fd_solana_stake_program_id.key, 32UL ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

int
fd_stake_program_execute( fd_exec_instr_ctx_t * ctx ) {
  FD_EXEC_CU_UPDATE( ctx, DEFAULT_COMPUTE_UNITS );

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L77
  fd_pubkey_t const * signers[FD_TXN_SIG_MAX] = {0};
  fd_instr_get_signers( ctx->instr, signers );

  if( FD_UNLIKELY( ctx->instr->data==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L79
  fd_valloc_t valloc = fd_scratch_virtual();
  fd_bincode_decode_ctx_t decode =
    { .valloc  = valloc,
      .data    = ctx->instr->data,
      .dataend = ctx->instr->data + ctx->instr->data_sz };

  fd_stake_instruction_t instruction[1];
  int decode_result = fd_stake_instruction_decode( instruction, &decode );
  /* Fail if the number of bytes consumed by deserialize exceeds 1232
     (hardcoded constant by Agave limited_deserialize) */
  if( decode_result!=FD_BINCODE_SUCCESS ||
      (ulong)ctx->instr->data + 1232UL<(ulong)decode.data )
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  /* The EpochRewards sysvar only exists after partitioned epoch rewards is activated.
     If the sysvar exists, check the `active` field */
  fd_sysvar_epoch_rewards_t const * rewards = fd_sysvar_cache_epoch_rewards( ctx->slot_ctx->sysvar_cache );
  int epoch_rewards_active = (NULL != rewards) ? rewards->active : false;

  if (epoch_rewards_active && instruction->discriminant!=fd_stake_instruction_enum_get_minimum_delegation) {
    ctx->txn_ctx->custom_err = FD_STAKE_ERR_EPOCH_REWARDS_ACTIVE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Replicate stake account changes to bank caches after processing the
     transaction's instructions. */
  ctx->txn_ctx->dirty_stake_acc = 1;

  int rc;
  // PLEASE PRESERVE SWITCH-CASE ORDERING TO MIRROR AGAVE IMPL:
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L84
  switch( instruction->discriminant ) {

  /* Initialize
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L110
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L85
   */
  case fd_stake_instruction_enum_initialize: {
    fd_stake_authorized_t const * authorized = &instruction->inner.initialize.authorized;
    fd_stake_lockup_t const *     lockup     = &instruction->inner.initialize.lockup;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L86
    fd_borrowed_account_t * me = NULL;
    rc = get_stake_account( ctx, &me );  /* acquire_write */
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L87
    fd_rent_t const * rent = fd_sysvar_from_instr_acct_rent( ctx, 1, &rc );
    if( FD_UNLIKELY( !rent ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L88
    rc = initialize( ctx, me, 0, authorized, lockup, rent );

    fd_borrowed_account_release_write( me );  /* implicit drop */
    break;
  }

  /* Authorize
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L120
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L90
   */
  case fd_stake_instruction_enum_authorize: {
    fd_pubkey_t const *          authorized_pubkey = &instruction->inner.authorize.pubkey;
    fd_stake_authorize_t const * stake_authorize   = &instruction->inner.authorize.stake_authorize;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L91
    fd_borrowed_account_t * me = NULL;
    rc = get_stake_account( ctx, &me );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L92
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_from_instr_acct_clock( ctx, 1, &rc );
    if( FD_UNLIKELY( !clock ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L94
    if( FD_UNLIKELY( ctx->instr->acct_cnt<3 ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L95
    fd_pubkey_t const * custodian_pubkey = NULL;
    rc = get_optional_pubkey( ctx, 3, 0, &custodian_pubkey );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L98
    rc = authorize( ctx,
                    me,
                    0,
                    signers,
                    authorized_pubkey,
                    stake_authorize,
                    clock,
                    custodian_pubkey,
                    &ctx->txn_ctx->custom_err );

    fd_borrowed_account_release_write( me );  /* implicit drop */
    break;
  }

  /* AuthorizeWithSeed
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L211
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L107
   */
  case fd_stake_instruction_enum_authorize_with_seed: {
    fd_authorize_with_seed_args_t args = instruction->inner.authorize_with_seed;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L108
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx, &me );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L109
    if( ctx->instr->acct_cnt<2 )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L110
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_from_instr_acct_clock( ctx, 2, &rc );
    if( FD_UNLIKELY( !clock ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L112
    fd_pubkey_t const * custodian_pubkey = NULL;
    rc = get_optional_pubkey( ctx, 3, 0, &custodian_pubkey );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L115
    rc = authorize_with_seed( ctx,
                              me,
                              0,
                              1,
                              (char const *)args.authority_seed,
                              args.authority_seed_len,
                              &args.authority_owner,
                              &args.new_authorized_pubkey,
                              &args.stake_authorize,
                              clock,
                              custodian_pubkey );

    fd_borrowed_account_release_write( me );  /* implicit drop */
    break;
  }

  /* DelegateStake
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L135
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L128
   */
  case fd_stake_instruction_enum_delegate_stake: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L129
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx, &me );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L130
    if( FD_UNLIKELY( ctx->instr->acct_cnt<2 ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L131
    fd_sol_sysvar_clock_t const * clock =
      fd_sysvar_from_instr_acct_clock( ctx, 2, &rc );
    if( FD_UNLIKELY( !clock ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L133
    fd_stake_history_t const * stake_history =
      fd_sysvar_from_instr_acct_stake_history( ctx, 3, &rc );
    if( FD_UNLIKELY( !stake_history ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L138
    if( FD_UNLIKELY( ctx->instr->acct_cnt<5 ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    fd_borrowed_account_release_write( me );  /* implicit drop */

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L140
    rc = delegate( ctx,
                   0,
                   1,
                   clock,
                   stake_history,
                   signers );

    break;
  }

  /* Split
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L143
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L152
   */
  case fd_stake_instruction_enum_split: {
    ulong lamports = instruction->inner.split;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L153
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx, &me );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L154
    if( FD_UNLIKELY( ctx->instr->acct_cnt<2 ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    fd_borrowed_account_release_write( me );  /* implicit drop */

    //https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L156
    rc = split( ctx, 0, lamports, 1, signers );
    break;
  }

  /* Merge
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L201
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L166
   */
  case fd_stake_instruction_enum_merge: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L167
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx, &me );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L168
    if( FD_UNLIKELY( ctx->instr->acct_cnt<2 ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L169
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_from_instr_acct_clock( ctx, 2, &rc );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L171
    fd_stake_history_t const * stake_history = fd_sysvar_from_instr_acct_stake_history( ctx, 3, &rc );
    if( FD_UNLIKELY( rc ) ) return rc;

    fd_borrowed_account_release_write( me );  /* implicit drop */

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L177
    rc = merge( ctx, 0, 1, clock, stake_history, signers );
    break;
  }

  /* Withdraw
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L157
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L188
   */
  case fd_stake_instruction_enum_withdraw: FD_SCRATCH_SCOPE_BEGIN {
    ulong lamports = instruction->inner.withdraw;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L189
    fd_borrowed_account_t * me = NULL;
    rc = get_stake_account( ctx, &me );  /* calls acquire_write */
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L190
    if( FD_UNLIKELY( ctx->instr->acct_cnt<2 ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L191
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_from_instr_acct_clock( ctx, 2, &rc );
    if( FD_UNLIKELY( !clock ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L193
    fd_stake_history_t const * stake_history = fd_sysvar_from_instr_acct_stake_history( ctx, 3, &rc );
    if( FD_UNLIKELY( !stake_history ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L198
    if( FD_UNLIKELY( ctx->instr->acct_cnt<5 ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

    fd_borrowed_account_release_write( me );  /* implicit drop */

    uchar custodian_index           = 5;
    ulong new_rate_activation_epoch = ULONG_MAX;
    int   err;
    int   is_some = new_warmup_cooldown_rate_epoch( ctx, &new_rate_activation_epoch, &err );
    if( FD_UNLIKELY( err ) ) return err;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L200
    rc = withdraw(
        ctx,
        0,
        lamports,
        1,
        clock,
        stake_history,
        4,
        // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L209-L215
        fd_ptr_if( ctx->instr->acct_cnt>=6, &custodian_index, NULL ),
        fd_ptr_if( is_some, &new_rate_activation_epoch, NULL ) );

    } FD_SCRATCH_SCOPE_END;
    break;

  /* Deactivate
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L165
   * 
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L217
   */
  case fd_stake_instruction_enum_deactivate: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L218
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx, &me );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L219
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_from_instr_acct_clock( ctx, 1, &rc );
    if( FD_UNLIKELY( !clock ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L221
    rc = deactivate( ctx, me, 0, clock, signers, &ctx->txn_ctx->custom_err );

    fd_borrowed_account_release_write( me );  /* implicit drop */
    break;
  }

  /* SetLockup
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L175
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L223
   */
  case fd_stake_instruction_enum_set_lockup: {
    fd_lockup_args_t * lockup = &instruction->inner.set_lockup;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L224
    fd_borrowed_account_t * me = NULL;
    rc = get_stake_account( ctx, &me );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L225
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock( ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !clock ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L226
    rc = set_lockup( ctx, me, 0, lockup, signers, clock );

    fd_borrowed_account_release_write( me );  /* implicit drop */
    break;
  }

  /* InitializeChecked
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L224
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L228
   */
  case fd_stake_instruction_enum_initialize_checked: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L229
    fd_borrowed_account_t * me = NULL;
    rc = get_stake_account( ctx, &me );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L230
    if( FD_UNLIKELY( ctx->instr->acct_cnt<4 ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L231-L236
    fd_pubkey_t const * staker_pubkey     = &ctx->instr->acct_pubkeys[2];
    fd_pubkey_t const * withdrawer_pubkey = &ctx->instr->acct_pubkeys[3];
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L237
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, 3 ) ) )
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L241
    fd_stake_authorized_t authorized = { .staker     = *staker_pubkey,
                                          .withdrawer = *withdrawer_pubkey };
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L246
    fd_rent_t const * rent = fd_sysvar_from_instr_acct_rent( ctx, 1, &rc );
    if( FD_UNLIKELY( !rent ) ) return rc;

    fd_stake_lockup_t lockup_default = {0};
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L247
    rc = initialize( ctx, me, 0, &authorized, &lockup_default, rent );

    fd_borrowed_account_release_write( me );  /* implicit drop */
    break;
  }

  /* AuthorizeChecked
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L238
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L249
   */
  case fd_stake_instruction_enum_authorize_checked: {
    fd_stake_authorize_t const * stake_authorize = &instruction->inner.authorize_checked;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L250
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx, &me );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L251
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_from_instr_acct_clock( ctx, 1, &rc );
    if( FD_UNLIKELY( !clock ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L253
    if( FD_UNLIKELY( ctx->instr->acct_cnt<4 ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L254
    fd_pubkey_t const * authorized_pubkey = &ctx->instr->acct_pubkeys[3];
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L257
    int is_signer = fd_instr_acc_is_signer_idx( ctx->instr, 3 );
    if( FD_UNLIKELY( !is_signer ) ) return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L260
    fd_pubkey_t const * custodian_pubkey = NULL;
    rc = get_optional_pubkey( ctx, 4, 0, &custodian_pubkey );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L263
    rc = authorize( ctx,
                    me,
                    0,
                    signers,
                    authorized_pubkey,
                    stake_authorize,
                    clock,
                    custodian_pubkey,
                    &ctx->txn_ctx->custom_err );

    fd_borrowed_account_release_write( me );  /* implicit drop */
    break;
  }

  /* AuthorizeCheckedWithSeed
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L252
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L272
   */
  case fd_stake_instruction_enum_authorize_checked_with_seed: {
    fd_authorize_checked_with_seed_args_t const * args =
        &instruction->inner.authorize_checked_with_seed;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L273
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx, &me );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L274
    if( FD_UNLIKELY( ctx->instr->acct_cnt<2 ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L276
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_from_instr_acct_clock( ctx, 2, &rc );
    if( FD_UNLIKELY( !clock ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L277
    if( FD_UNLIKELY( ctx->instr->acct_cnt<4 ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L278
    fd_pubkey_t const * authorized_pubkey = &ctx->instr->acct_pubkeys[3];
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L281
    int is_signer = fd_instr_acc_is_signer_idx( ctx->instr, 3 );
    if( FD_UNLIKELY( !is_signer ) ) return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L284
    fd_pubkey_t const * custodian_pubkey = NULL;
    rc = get_optional_pubkey( ctx, 4, 0, &custodian_pubkey );
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L287
    rc = authorize_with_seed( ctx,
                              me,
                              0,
                              1,
                              (char const *)args->authority_seed,
                              args->authority_seed_len,
                              &args->authority_owner,
                              authorized_pubkey,
                              &args->stake_authorize,
                              clock,
                              custodian_pubkey );

    fd_borrowed_account_release_write( me );  /* implicit drop */
    break;
  }

  /* SetLockupChecked
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L266
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L300
   */
  case fd_stake_instruction_enum_set_lockup_checked: {
    fd_lockup_checked_args_t * lockup_checked = &instruction->inner.set_lockup_checked;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L301
    fd_borrowed_account_t * me = NULL;
    rc = get_stake_account( ctx, &me );  /* acquire_write */
    if( FD_UNLIKELY( rc ) ) return rc;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L302
    fd_pubkey_t const * custodian_pubkey = NULL;
    rc = get_optional_pubkey( ctx, 2, 1, &custodian_pubkey );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L305
    fd_lockup_args_t lockup = { .unix_timestamp = lockup_checked->unix_timestamp,
                                .epoch          = lockup_checked->epoch,
                                .custodian      = (fd_pubkey_t *)custodian_pubkey }; // FIXME
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L310
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock( ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !clock ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L311
    rc = set_lockup( ctx, me, 0, &lockup, signers, clock );

    fd_borrowed_account_release_write( me );  /* implicit drop */
    break;
  }

  /* GetMinimumDelegation
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L278
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L313
   */
  case fd_stake_instruction_enum_get_minimum_delegation: {
    ulong minimum_delegation = get_minimum_delegation( ctx->slot_ctx );
    fd_memcpy( &ctx->txn_ctx->return_data.program_id, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t));
    fd_memcpy(ctx->txn_ctx->return_data.data, (uchar*)(&minimum_delegation), sizeof(ulong));
    ctx->txn_ctx->return_data.len = sizeof(ulong);
    rc = 0;
    goto done;
  }

  /* DeactivateDelinquent
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/instruction.rs#L291
   *
   * Processor:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L321
   */
  case fd_stake_instruction_enum_deactivate_delinquent: {
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L322
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx, &me );
    if( FD_UNLIKELY( rc ) ) return rc;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L323
    if( FD_UNLIKELY( ctx->instr->acct_cnt<3 ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L325
    fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock( ctx->slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !clock ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L326
    rc = deactivate_delinquent( ctx, me, 0, 1, 2, clock->epoch, &ctx->txn_ctx->custom_err );

    fd_borrowed_account_release_write( me );  /* implicit drop */
    break;
  }

  /* Redelegate
   *
   * Deprecated:
   * https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/programs/stake/src/stake_instruction.rs#L336
   */
  case fd_stake_instruction_enum_redelegate: {
    fd_borrowed_account_t * me = NULL;
    rc                         = get_stake_account( ctx, &me );
    if( FD_UNLIKELY( rc ) ) return rc;

    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }
  /* MoveStake
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/sdk/program/src/stake/instruction.rs#L330 
   * 
   * Processor:
   * https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_instruction.rs#L356
   */
  case fd_stake_instruction_enum_move_stake: {
    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_instruction.rs#L359
    if( FD_LIKELY( FD_FEATURE_ACTIVE( ctx->slot_ctx, move_stake_and_move_lamports_ixs ) ) ) {
      // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_instruction.rs#L361
      if( FD_UNLIKELY( ctx->instr->acct_cnt<3 ) )
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

      ulong lamports = instruction->inner.move_stake;
      // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_instruction.rs#L362
      rc = move_stake( ctx,
                       0UL,
                       lamports,
                       1UL,
                       2UL,
                       &ctx->txn_ctx->custom_err );
    } else {
      // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_instruction.rs#L372
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
    break;
  }
  /* MoveLamports
   *
   * Instruction:
   * https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/sdk/program/src/stake/instruction.rs#L345 
   * 
   * Processor:
   * https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_instruction.rs#L375
   */
  case fd_stake_instruction_enum_move_lamports: {
    // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_instruction.rs#L378
    if( FD_LIKELY( FD_FEATURE_ACTIVE( ctx->slot_ctx, move_stake_and_move_lamports_ixs ) ) ) {
      // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_instruction.rs#L380
      if( FD_UNLIKELY( ctx->instr->acct_cnt<3 ) )
        return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

      // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_instruction.rs#L381
      ulong lamports = instruction->inner.move_lamports;

      // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_instruction.rs#L381
      rc = move_lamports( ctx,
                       0UL,
                       lamports,
                       1UL,
                       2UL );
    } else {
      // https://github.com/anza-xyz/agave/blob/cdff19c7807b006dd63429114fb1d9573bf74172/programs/stake/src/stake_instruction.rs#L391
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
    break;
  }
  default:
    FD_LOG_ERR(( "unsupported stake instruction: %u", instruction->discriminant ));
  }

done:
  return rc;
}

/* Public API *********************************************************/

static void
write_stake_config( fd_exec_slot_ctx_t * slot_ctx, fd_stake_config_t const * stake_config ) {
  ulong                   data_sz  = fd_stake_config_size( stake_config );
  fd_pubkey_t const *     acc_key  = &fd_solana_stake_program_config_id;
  fd_account_meta_t *     acc_meta = NULL;
  uchar *                 acc_data = NULL;
  FD_BORROWED_ACCOUNT_DECL(rec);
  int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, acc_key, 1, data_sz, rec );
  FD_TEST( !err );

  acc_meta                  = rec->meta;
  acc_data                  = rec->data;
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

void
fd_stake_program_config_init( fd_exec_slot_ctx_t * slot_ctx ) {
  // https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/config.rs#L26
  fd_stake_config_t stake_config = {
      .warmup_cooldown_rate = DEFAULT_WARMUP_COOLDOWN_RATE,
      .slash_penalty        = DEFAULT_SLASH_PENALTY,
  };
  write_stake_config( slot_ctx, &stake_config );
}

int
fd_stake_get_state( fd_borrowed_account_t const * self,
                    fd_valloc_t const *           valloc,
                    fd_stake_state_v2_t *         out ) {
  return get_state( self, *valloc, out );
}

fd_stake_history_entry_t
fd_stake_activating_and_deactivating( fd_delegation_t const *    self,
                                      ulong                      target_epoch,
                                      fd_stake_history_t const * stake_history,
                                      ulong *                    new_rate_activation_epoch ) {
  return stake_activating_and_deactivating(
    self, target_epoch, stake_history, new_rate_activation_epoch );
}

/* Removes stake delegation from epoch stakes and updates vote account */
static void
fd_stakes_remove_stake_delegation( fd_exec_slot_ctx_t * slot_ctx, fd_borrowed_account_t * stake_account ) {
  fd_stake_accounts_pair_t_mapnode_t key;
  fd_memcpy( key.elem.key.uc, stake_account->pubkey->uc, sizeof(fd_pubkey_t) );
  if( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool==NULL ) {
    FD_LOG_DEBUG(("Stake accounts pool does not exist"));
    return;
  }
  fd_stake_accounts_pair_t_mapnode_t * entry = fd_stake_accounts_pair_t_map_find( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root, &key );
  if (FD_UNLIKELY( entry )) {
    fd_stake_accounts_pair_t_map_remove( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, &slot_ctx->slot_bank.stake_account_keys.stake_accounts_root, entry);
    // TODO: do we need a release here?
  }
}

/* Updates stake delegation in epoch stakes */
static void
fd_stakes_upsert_stake_delegation( fd_exec_slot_ctx_t * slot_ctx, fd_borrowed_account_t * stake_account ) {
  FD_TEST( stake_account->const_meta->info.lamports!=0 );
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_stakes_t * stakes = &epoch_bank->stakes;

  fd_delegation_pair_t_mapnode_t key;
  fd_memcpy(&key.elem.account, stake_account->pubkey->uc, sizeof(fd_pubkey_t));

  if( stakes->stake_delegations_pool==NULL) {
    FD_LOG_DEBUG(("Stake delegations pool does not exist"));
    return;
  }

  fd_delegation_pair_t_mapnode_t * entry = fd_delegation_pair_t_map_find( stakes->stake_delegations_pool, stakes->stake_delegations_root, &key);
  if( FD_UNLIKELY( !entry ) ) {
    fd_stake_accounts_pair_t_mapnode_t key;
    fd_memcpy( key.elem.key.uc, stake_account->pubkey->uc, sizeof(fd_pubkey_t) );
    if( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool==NULL) {
      FD_LOG_DEBUG(("Stake accounts pool does not exist"));
      return;
    }
    fd_stake_accounts_pair_t_mapnode_t * stake_entry = fd_stake_accounts_pair_t_map_find( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root, &key );
    if( stake_entry ) {
      stake_entry->elem.exists = 1;
    } else {
      fd_stake_accounts_pair_t_mapnode_t * new_node = fd_stake_accounts_pair_t_map_acquire( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool );
      ulong size = fd_stake_accounts_pair_t_map_size( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root );
      FD_LOG_DEBUG(("Curr stake account size %lu %p", size, (void *)slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool));
      if( new_node==NULL ) {
        FD_LOG_ERR(("Stake accounts keys map full %lu", size));
      }
      new_node->elem.exists = 1;
      fd_memcpy( new_node->elem.key.uc, stake_account->pubkey->uc, sizeof(fd_pubkey_t) );
      fd_stake_accounts_pair_t_map_insert( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, &slot_ctx->slot_bank.stake_account_keys.stake_accounts_root, new_node );
    }
  }
}

void fd_store_stake_delegation( fd_exec_slot_ctx_t * slot_ctx, fd_borrowed_account_t * stake_account ) {
  fd_pubkey_t const * owner = (fd_pubkey_t const *)stake_account->const_meta->info.owner;

  if( memcmp( owner->uc, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) {
      return;
  }

  int is_empty  = stake_account->const_meta->info.lamports==0;
  int is_uninit = 1;
  if( stake_account->const_meta->dlen>=4 ) {
    uint prefix = FD_LOAD( uint, stake_account->const_data );
    is_uninit = ( prefix==fd_stake_state_v2_enum_uninitialized );
  }

  if( is_empty || is_uninit ) {
    fd_stakes_remove_stake_delegation( slot_ctx, stake_account );
  } else {
    fd_stakes_upsert_stake_delegation( slot_ctx, stake_account );
  }
}
