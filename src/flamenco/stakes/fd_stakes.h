#ifndef HEADER_fd_src_flamenco_stakes_fd_stakes_h
#define HEADER_fd_src_flamenco_stakes_fd_stakes_h

#include "fd_stake_delegations.h"
#include "fd_stake_types.h"
#include "fd_stake_weight.h"
#include "fd_vote_stakes.h"

FD_PROTOTYPES_BEGIN

fd_stake_state_t const *
fd_stakes_get_state( fd_acc_t const * acc );

ulong
fd_stake_calculate_activation_allowance( ulong                            current_epoch,
                                         ulong                            account_activating_stake,
                                         fd_stake_history_entry_t const * prev_epoch_cluster_state,
                                         ulong *                          opt_rate_change_activation_epoch );

/* https://github.com/anza-xyz/agave/blob/v4.2.0-beta.1/runtime/src/stake_delegation.rs#L27-L41 */
fd_stake_history_entry_t
fd_delegation_activation_status( fd_delegation_t const *    delegation,
                                 ulong                      target_epoch,
                                 fd_stake_history_t const * stake_history,
                                 ulong *                    new_rate_activation_epoch );

int
fd_delegation_is_inactive( fd_delegation_t const *    delegation,
                           ulong                      target_epoch,
                           fd_stake_history_t const * stake_history,
                           ulong *                    new_rate_activation_epoch );

fd_stake_history_entry_t
fd_stake_delegation_activation_status( fd_stake_delegation_t const * delegation,
                                       ulong                         target_epoch,
                                       fd_stake_history_t const *    stake_history,
                                       ulong *                       new_rate_activation_epoch );

int
fd_stake_delegation_is_inactive( fd_stake_delegation_t const * delegation,
                                 ulong                         target_epoch,
                                 fd_stake_history_t const *    stake_history,
                                 ulong *                       new_rate_activation_epoch );

/* fd_stake_weights_by_node converts Stakes (unordered list of (vote
   acc, active stake) tuples) to an ordered list of (stake, vote pubkey, node
   identity) sorted by (stake descending, vote pubkey descending).

   iter_kind selects the vote stakes set: FD_VOTE_STAKES_ITER_T_1 (next
   epoch), T_2 (current epoch), T_3 (previous epoch), T_4 (two epochs ago)
   or T_5 (three epochs ago).

   weights points to an array of MAX_STAKE_WEIGHTS items.

   Returns the number of items in weights (which is <= no of vote accs). */

ulong
fd_stake_weights_by_node( fd_vote_stakes_t *       vote_stakes,
                          ushort                   fork_id,
                          int                      iter_kind,
                          fd_vote_stake_weight_t * weights );

void
fd_stakes_activate_epoch( fd_bank_t *                    bank,
                          fd_runtime_stack_t *           runtime_stack,
                          fd_accdb_t *                   accdb,
                          fd_capture_ctx_t *             capture_ctx,
                          fd_stake_delegations_t *       stake_delegations,
                          ulong *                        new_rate_activation_epoch );

/* fd_stakes_vote_account_is_admissible returns 1 if a vote account
   with the given state passes the validator admission ticket filter
   applied at the epoch boundary */

int
fd_stakes_vote_account_is_admissible( fd_bank_t const * bank,
                                      ulong             lamports,
                                      uchar const *     owner,
                                      uchar const *     data,
                                      ulong             data_len );

/* rewarded_epoch selects the epoch whose effective delegated stakes
   should be accumulated for rewards.  ULONG_MAX disables this work. */
void
fd_refresh_vote_accounts( fd_bank_t *                    bank,
                          fd_accdb_t *                   accdb,
                          fd_runtime_stack_t *           runtime_stack,
                          fd_stake_delegations_t const * stake_delegations,
                          fd_stake_history_t const *     history,
                          ulong                          rewarded_epoch,
                          ulong *                        new_rate_activation_epoch );

/* fd_stakes_update_delegation is used to maintain the in-memory cache
   of the stake delegations that is used at the epoch boundary.  Entries
   in the cache will be inserted/updated/removed based on the state of
   the stake account.  stake_history is the bank's StakeHistory sysvar
   (may be NULL if absent). */

void
fd_stakes_update_stake_delegation( fd_pubkey_t const *        pubkey,
                                   fd_acc_t const *           acc,
                                   fd_bank_t *                bank,
                                   fd_stake_history_t const * stake_history,
                                   fd_txn_in_t const *        txn_in );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stakes_h */
