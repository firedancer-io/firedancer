#ifndef HEADER_fd_src_flamenco_events_fd_event_runtime_h
#define HEADER_fd_src_flamenco_events_fd_event_runtime_h

/* fd_event_runtime.h provides the shared helpers used by the
   exec-replay (execrp) and exec-leader (execle) tiles to convert
   runtime events and emit them on the tile's event link. */

#include "../runtime/fd_runtime.h"
#include "../runtime/fd_runtime_err.h"
#include "../runtime/fd_executor_err.h"
#include "../runtime/fd_bank.h"
#include "../stakes/fd_stakes.h"
#include "../../disco/events/generated/fd_event_gen.h"

FD_PROTOTYPES_BEGIN

static inline int
fd_event_txn_err_from_txn_err( int err ) {
  switch( err ) {
    case FD_RUNTIME_EXECUTE_SUCCESS:                                 return FD_EVENT_RUNTIME_TXN_TXN_ERR_SUCCESS;
    case FD_RUNTIME_TXN_ERR_ACCOUNT_LOADED_TWICE:                    return FD_EVENT_RUNTIME_TXN_TXN_ERR_ACCOUNT_LOADED_TWICE;
    case FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND:                       return FD_EVENT_RUNTIME_TXN_TXN_ERR_ACCOUNT_NOT_FOUND;
    case FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND:               return FD_EVENT_RUNTIME_TXN_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND;
    case FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE:              return FD_EVENT_RUNTIME_TXN_TXN_ERR_INSUFFICIENT_FUNDS_FOR_FEE;
    case FD_RUNTIME_TXN_ERR_INVALID_ACCOUNT_FOR_FEE:                 return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_ACCOUNT_FOR_FEE;
    case FD_RUNTIME_TXN_ERR_ALREADY_PROCESSED:                       return FD_EVENT_RUNTIME_TXN_TXN_ERR_ALREADY_PROCESSED;
    case FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND:                     return FD_EVENT_RUNTIME_TXN_TXN_ERR_BLOCKHASH_NOT_FOUND;
    case FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR:                       return FD_EVENT_RUNTIME_TXN_TXN_ERR_INSTRUCTION_ERROR;
    case FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE:                       return FD_EVENT_RUNTIME_TXN_TXN_ERR_SIGNATURE_FAILURE;
    case FD_RUNTIME_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION:           return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_PROGRAM_FOR_EXECUTION;
    case FD_RUNTIME_TXN_ERR_SANITIZE_FAILURE:                        return FD_EVENT_RUNTIME_TXN_TXN_ERR_SANITIZE_FAILURE;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_BLOCK_COST_LIMIT:       return FD_EVENT_RUNTIME_TXN_TXN_ERR_WOULD_EXCEED_MAX_BLOCK_COST_LIMIT;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT:     return FD_EVENT_RUNTIME_TXN_TXN_ERR_WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT:   return FD_EVENT_RUNTIME_TXN_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT;
    case FD_RUNTIME_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS:                  return FD_EVENT_RUNTIME_TXN_TXN_ERR_TOO_MANY_ACCOUNT_LOCKS;
    case FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND:          return FD_EVENT_RUNTIME_TXN_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND;
    case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER:      return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER;
    case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA:       return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA;
    case FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX:      return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_VOTE_COST_LIMIT:        return FD_EVENT_RUNTIME_TXN_TXN_ERR_WOULD_EXCEED_MAX_VOTE_COST_LIMIT;
    case FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT:   return FD_EVENT_RUNTIME_TXN_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT;
    case FD_RUNTIME_TXN_ERR_DUPLICATE_INSTRUCTION:                   return FD_EVENT_RUNTIME_TXN_TXN_ERR_DUPLICATE_INSTRUCTION;
    case FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT:             return FD_EVENT_RUNTIME_TXN_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT;
    case FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED:  return FD_EVENT_RUNTIME_TXN_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED;
    case FD_RUNTIME_TXN_ERR_INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT: return FD_EVENT_RUNTIME_TXN_TXN_ERR_INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT;
    case FD_RUNTIME_TXN_ERR_UNBALANCED_TRANSACTION:                  return FD_EVENT_RUNTIME_TXN_TXN_ERR_UNBALANCED_TRANSACTION;
    case FD_RUNTIME_TXN_ERR_BUNDLE_PEER:                             return FD_EVENT_RUNTIME_TXN_TXN_ERR_BUNDLE_PEER;
    case FD_RUNTIME_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED:        return FD_EVENT_RUNTIME_TXN_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED;
    case FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_ADVANCE_NONCE_INSTR:      return FD_EVENT_RUNTIME_TXN_TXN_ERR_BLOCKHASH_FAIL_ADVANCE_NONCE_INSTR;
    case FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_WRONG_NONCE:              return FD_EVENT_RUNTIME_TXN_TXN_ERR_BLOCKHASH_FAIL_WRONG_NONCE;
    case FD_RUNTIME_TXN_ERR_UNSUPPORTED_VERSION:                     return FD_EVENT_RUNTIME_TXN_TXN_ERR_UNSUPPORTED_VERSION;
    default:                                                         FD_LOG_ERR(( "unmapped runtime txn err %d", err ));
  }
}

static inline int
fd_event_exec_err_from_exec_err( int err ) {
  switch( err ) {
    case FD_EXECUTOR_INSTR_SUCCESS:                                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_SUCCESS;
    case FD_EXECUTOR_INSTR_ERR_GENERIC_ERR:                        return FD_EVENT_RUNTIME_TXN_EXEC_ERR_GENERIC_ERR;
    case FD_EXECUTOR_INSTR_ERR_INVALID_ARG:                        return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_ARG;
    case FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA:                 return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_INSTR_DATA;
    case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA:                   return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_ACC_DATA;
    case FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL:                 return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_DATA_TOO_SMALL;
    case FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS:                 return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INSUFFICIENT_FUNDS;
    case FD_EXECUTOR_INSTR_ERR_INCORRECT_PROGRAM_ID:               return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INCORRECT_PROGRAM_ID;
    case FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE:         return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MISSING_REQUIRED_SIGNATURE;
    case FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED:            return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_ALREADY_INITIALIZED;
    case FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT:              return FD_EVENT_RUNTIME_TXN_EXEC_ERR_UNINITIALIZED_ACCOUNT;
    case FD_EXECUTOR_INSTR_ERR_UNBALANCED_INSTR:                   return FD_EVENT_RUNTIME_TXN_EXEC_ERR_UNBALANCED_INSTR;
    case FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MODIFIED_PROGRAM_ID;
    case FD_EXECUTOR_INSTR_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND:     return FD_EVENT_RUNTIME_TXN_EXEC_ERR_EXTERNAL_ACCOUNT_LAMPORT_SPEND;
    case FD_EXECUTOR_INSTR_ERR_EXTERNAL_DATA_MODIFIED:             return FD_EVENT_RUNTIME_TXN_EXEC_ERR_EXTERNAL_DATA_MODIFIED;
    case FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE:            return FD_EVENT_RUNTIME_TXN_EXEC_ERR_READONLY_LAMPORT_CHANGE;
    case FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED:             return FD_EVENT_RUNTIME_TXN_EXEC_ERR_READONLY_DATA_MODIFIED;
    case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_MODIFIED:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_EXECUTABLE_MODIFIED;
    case FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_NOT_ENOUGH_ACC_KEYS;
    case FD_EXECUTOR_INSTR_ERR_ACC_DATA_SIZE_CHANGED:              return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_DATA_SIZE_CHANGED;
    case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED:                  return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_BORROW_FAILED;
    case FD_EXECUTOR_INSTR_ERR_ACC_BORROW_OUTSTANDING:             return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_BORROW_OUTSTANDING;
    case FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR:                         return FD_EVENT_RUNTIME_TXN_EXEC_ERR_CUSTOM_ERR;
    case FD_EXECUTOR_INSTR_ERR_INVALID_ERR:                        return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_ERR;
    case FD_EXECUTOR_INSTR_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT: return FD_EVENT_RUNTIME_TXN_EXEC_ERR_EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT;
    case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID:             return FD_EVENT_RUNTIME_TXN_EXEC_ERR_UNSUPPORTED_PROGRAM_ID;
    case FD_EXECUTOR_INSTR_ERR_CALL_DEPTH:                         return FD_EVENT_RUNTIME_TXN_EXEC_ERR_CALL_DEPTH;
    case FD_EXECUTOR_INSTR_ERR_MISSING_ACC:                        return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MISSING_ACC;
    case FD_EXECUTOR_INSTR_ERR_REENTRANCY_NOT_ALLOWED:             return FD_EVENT_RUNTIME_TXN_EXEC_ERR_REENTRANCY_NOT_ALLOWED;
    case FD_EXECUTOR_INSTR_ERR_MAX_SEED_LENGTH_EXCEEDED:           return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MAX_SEED_LENGTH_EXCEEDED;
    case FD_EXECUTOR_INSTR_ERR_INVALID_SEEDS:                      return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_SEEDS;
    case FD_EXECUTOR_INSTR_ERR_INVALID_REALLOC:                    return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_REALLOC;
    case FD_EXECUTOR_INSTR_ERR_COMPUTE_BUDGET_EXCEEDED:            return FD_EVENT_RUNTIME_TXN_EXEC_ERR_COMPUTE_BUDGET_EXCEEDED;
    case FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION:               return FD_EVENT_RUNTIME_TXN_EXEC_ERR_PRIVILEGE_ESCALATION;
    case FD_EXECUTOR_INSTR_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE:  return FD_EVENT_RUNTIME_TXN_EXEC_ERR_PROGRAM_ENVIRONMENT_SETUP_FAILURE;
    case FD_EXECUTOR_INSTR_ERR_PROGRAM_FAILED_TO_COMPLETE:         return FD_EVENT_RUNTIME_TXN_EXEC_ERR_PROGRAM_FAILED_TO_COMPLETE;
    case FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE:                      return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_IMMUTABLE;
    case FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INCORRECT_AUTHORITY;
    case FD_EXECUTOR_INSTR_ERR_BORSH_IO_ERROR:                     return FD_EVENT_RUNTIME_TXN_EXEC_ERR_BORSH_IO_ERROR;
    case FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ACC_NOT_RENT_EXEMPT;
    case FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER:                  return FD_EVENT_RUNTIME_TXN_EXEC_ERR_INVALID_ACC_OWNER;
    case FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW:                return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ARITHMETIC_OVERFLOW;
    case FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR:                 return FD_EVENT_RUNTIME_TXN_EXEC_ERR_UNSUPPORTED_SYSVAR;
    case FD_EXECUTOR_INSTR_ERR_ILLEGAL_OWNER:                      return FD_EVENT_RUNTIME_TXN_EXEC_ERR_ILLEGAL_OWNER;
    case FD_EXECUTOR_INSTR_ERR_MAX_ACCS_DATA_ALLOCS_EXCEEDED:      return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MAX_ACCS_DATA_ALLOCS_EXCEEDED;
    case FD_EXECUTOR_INSTR_ERR_MAX_ACCS_EXCEEDED:                  return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MAX_ACCS_EXCEEDED;
    case FD_EXECUTOR_INSTR_ERR_MAX_INSN_TRACE_LENS_EXCEEDED:       return FD_EVENT_RUNTIME_TXN_EXEC_ERR_MAX_INSN_TRACE_LENS_EXCEEDED;
    case FD_EXECUTOR_INSTR_ERR_BUILTINS_MUST_CONSUME_CUS:          return FD_EVENT_RUNTIME_TXN_EXEC_ERR_BUILTINS_MUST_CONSUME_CUS;
    default:                                                       FD_LOG_ERR(( "unmapped instruction exec err %d", err ));
  }
}

static inline int
fd_event_exec_err_kind_from_exec_err_kind( int kind ) {
  switch( kind ) {
    case FD_EXECUTOR_ERR_KIND_NONE:    return FD_EVENT_RUNTIME_TXN_EXEC_ERR_KIND_NONE;
    case FD_EXECUTOR_ERR_KIND_EBPF:    return FD_EVENT_RUNTIME_TXN_EXEC_ERR_KIND_EBPF;
    case FD_EXECUTOR_ERR_KIND_SYSCALL: return FD_EVENT_RUNTIME_TXN_EXEC_ERR_KIND_SYSCALL;
    case FD_EXECUTOR_ERR_KIND_INSTR:   return FD_EVENT_RUNTIME_TXN_EXEC_ERR_KIND_INSTR;
    default:                           FD_LOG_ERR(( "unmapped exec err kind %d", kind ));
  }
}

/* Build a runtime_txn event from (txn_in, txn_out, bank) and publish
   it on the calling tile's event link.  No-op when the tile has no
   event link. */

void
fd_event_runtime_txn_emit( fd_txn_in_t  const * txn_in,
                           fd_txn_out_t const * txn_out,
                           fd_bank_t    const * bank );

/* Build a runtime_stake_delegation event for the cache mutation the
   caller just applied (stake_state is the upserted entry's parsed
   state, or NULL for a removal) and publish it on the calling tile's
   event link.  Called by fd_stakes_update_stake_delegation.  No-op
   when the tile has no event link. */

void
fd_event_runtime_stake_delegation_emit( fd_txn_in_t      const * txn_in,
                                        fd_bank_t        const * bank,
                                        fd_pubkey_t      const * pubkey,
                                        fd_stake_state_t const * stake_state );

/* Build a runtime_stake_delegation event for a baseline stake
   delegation cache entry loaded at boot (streamed from the snapshot
   accounts by snapin, or loaded from genesis) and publish it on the
   calling tile's event link.  slot/epoch are the snapshot slot and its
   epoch (0/0 for genesis).  No-op when the tile has no event link. */

void
fd_event_runtime_stake_delegation_bootup_emit( ulong         slot,
                                               ulong         epoch,
                                               uchar const * stake_account,
                                               uchar const * vote_account,
                                               ulong         stake,
                                               ulong         activation_epoch,
                                               ulong         deactivation_epoch,
                                               ulong         credits_observed );

/* Record the StakeHistory sysvar entry for the new epoch. */

void
fd_event_runtime_epoch_stake_history( fd_stake_history_entry_t const * entry );

/* Record the EpochRewards sysvar values initialized at this boundary */

void
fd_event_runtime_epoch_rewards( fd_sysvar_epoch_rewards_t const * epoch_rewards );

/* Record the boundary vote-account counts. */

void
fd_event_runtime_epoch_votes( ulong staked_vote_accounts,
                              ulong top_votes_eligible );

/* Build a runtime_vote_account event for a vote account in the final
   boundary snapshot and publish it on the calling tile's event link.
   No-op when the tile has no event link. */

void
fd_event_runtime_vote_account_emit( fd_bank_t const *          bank,
                                    uchar const *              pubkey,
                                    uchar const *              node_account,
                                    ulong                      stake,
                                    uint                       commission_bps,
                                    int                        has_commission_t_2,
                                    uint                       commission_t_2_bps,
                                    int                        has_commission_t_3,
                                    uint                       commission_t_3_bps,
                                    uint                       reward_commission_bps,
                                    fd_epoch_credits_t const * epoch_credits );

/* Record a feature id newly activated at this boundary. */

void
fd_event_runtime_epoch_feature( uchar const * feature_id );

/* Record the per-vote-account VAT burn applied at this epoch boundary
   for the runtime_epoch event.  No-op when the tile has no event
   link. */

void
fd_event_runtime_epoch_vat_burn( ulong burn_per_vote_account );

/* Per-bank accumulator region for the runtime_block account diffs,
   owned by the replay tile (the only tile running the non-txn account
   write paths) and indexed by bank->idx.  All the fd_event_runtime_*
   functions taking a bank no-op until _init is called, so the region
   only exists when runtime diffs are enabled. */

#define FD_EVENT_RUNTIME_SLOT_DIFFS_FOOTPRINT (8192UL)

void
fd_event_runtime_slot_diffs_init( void * mem,      /* bank_max*FD_EVENT_RUNTIME_SLOT_DIFFS_FOOTPRINT bytes, 8 aligned */
                                  ulong  bank_max );

/* Reset the accumulator for a (new or recycled) bank index.  No-op
   when _init has not been called. */

void
fd_event_runtime_slot_diffs_reset( ulong bank_idx );

/* Build the runtime_epoch event from bank and publish it on the calling tile's event link. 
   No-op when the tile has no event link. */

void
fd_event_runtime_epoch_emit( fd_bank_t const * bank );

/* Discard any accumulated runtime_epoch state without emitting.  Called
   after genesis boot: initializing the bank from genesis runs the same
   vote-account refresh and feature-activation paths as an epoch
   boundary, which would otherwise pollute the first real boundary's
   summary counts. */

void
fd_event_runtime_epoch_reset( void );

/* Build a runtime_rooted event for the newly rooted bank and publish
   it on the calling tile's event link.  The delta stats cover every
   bank on (prev_root_slot, bank slot]. No-op when the tile has no event link. */

void
fd_event_runtime_rooted_emit( fd_bank_t const *                          bank,
                              ulong                                      prev_root_slot,
                              fd_stake_delegations_t const *             stake_delegations,
                              fd_stake_delegations_delta_stats_t const * stake_delegations_delta_stats );

/* Build a runtime_stake_delegation event from a reward payout
   and publish it on the calling tile's event link. No-op when the tile has no event link. */

void
fd_event_runtime_stake_delegation_payout_emit( fd_bank_t const * bank,
                                               uchar const *     stake_account,
                                               uchar const *     vote_account,
                                               ulong             stake,
                                               ulong             activation_epoch,
                                               ulong             deactivation_epoch,
                                               ulong             credits_observed );

/* Record a block-level account diff in the bank. */

void
fd_event_runtime_block_account( fd_bank_t *   bank,
                                uchar const * pubkey,
                                uchar const * prev_owner,
                                uchar const * owner,
                                ulong         prev_lamports,
                                ulong         lamports,
                                ulong         prev_data_sz,
                                ulong         data_sz,
                                int           executable );

/* Build a runtime_reward event and publish it on the calling tile's
   event link. No-op when the tile has no event link. */

void
fd_event_runtime_reward_emit( fd_bank_t const * bank,
                              int               kind,
                              uchar const *     pubkey,
                              uchar const *     owner,
                              ulong             prev_lamports,
                              ulong             lamports,
                              ulong             partition_idx,
                              ulong             credits_observed,
                              ulong             stake );

/* Build the runtime_block event for a finalized bank from the bank
   state and its accumulated diffs and publish it on the calling
   tile's event link. No-op when the tile has no event link. */

void
fd_event_runtime_block_emit( fd_bank_t const *             bank,
                             uchar const *                 block_id,
                             uchar const *                 parent_block_id,
                             uchar const *                 leader,
                             ulong                         execution_fees,
                             ulong                         priority_fees,
                             ulong                         tips,
                             fd_sol_sysvar_clock_t const * clock,
                             fd_hash_t const *             fec_mrs,
                             ulong                         fec_mr_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_events_fd_event_runtime_h */
