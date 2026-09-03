#ifndef HEADER_fd_src_flamenco_stakes_fd_stakes_h
#define HEADER_fd_src_flamenco_stakes_fd_stakes_h

#include "fd_stake_delegations.h"
#include "fd_stake_types.h"
#include "fd_stake_weight.h"
#include "fd_vote_stakes.h"
#include "../types/fd_cast.h"

FD_PROTOTYPES_BEGIN

fd_stake_state_t const *
fd_stakes_get_state( fd_acc_t const * acc );

fd_stake_history_entry_t
stake_activating_and_deactivating( fd_delegation_t const *    self,
                                   ulong                      target_epoch,
                                   fd_stake_history_t const * stake_history,
                                   ulong *                    new_rate_activation_epoch );

#if FD_HAS_DOUBLE
/* Caller must ensure cluster_portion is nonzero. */

static inline ulong
fd_stake_calculate_change_allowance_float( ulong   current_epoch,
                                           ulong   account_portion,
                                           ulong   cluster_portion,
                                           ulong   cluster_effective,
                                           ulong * new_rate_activation_epoch ) {
  double weight = (double)account_portion / (double)cluster_portion;
  double warmup_cooldown_rate = fd_stake_delegations_warmup_cooldown_rate_to_double( fd_stake_warmup_cooldown_rate( current_epoch, new_rate_activation_epoch ) );
  double newly_changed_cluster_stake = (double)cluster_effective * warmup_cooldown_rate;
  return fd_rust_cast_double_to_ulong( weight * newly_changed_cluster_stake );
}
#endif /* FD_HAS_DOUBLE */

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
                                 ulong *                    new_rate_activation_epoch,
                                 int                        use_fixed_point_stake_math );

int
fd_delegation_is_inactive( fd_delegation_t const *    delegation,
                           ulong                      target_epoch,
                           fd_stake_history_t const * stake_history,
                           ulong *                    new_rate_activation_epoch,
                           int                        use_fixed_point_stake_math );

fd_stake_history_entry_t
fd_stake_delegation_activation_status( fd_stake_delegation_t const * delegation,
                                       ulong                         target_epoch,
                                       fd_stake_history_t const *    stake_history,
                                       ulong *                       new_rate_activation_epoch,
                                       int                           use_fixed_point_stake_math );

int
fd_stake_delegation_is_inactive( fd_stake_delegation_t const * delegation,
                                 ulong                         target_epoch,
                                 fd_stake_history_t const *    stake_history,
                                 ulong *                       new_rate_activation_epoch,
                                 int                           use_fixed_point_stake_math );

/* fd_stake_weights_by_node converts Stakes (unordered list of (vote
   acc, active stake) tuples) to an ordered list of (stake, vote pubkey, node
   identity) sorted by (stake descending, vote pubkey descending).

   iter_kind selects the vote stakes set: FD_VOTE_STAKES_ITER_T_1 (next
   epoch), T_2 (current epoch) or T_3 (previous epoch).

   weights points to an array suitable to hold ...

     fd_vote_accounts_pair_t_map_size( accs->vote_accounts_pool,
                                       accs->vote_accounts_root )

   ... items.  On return, weights be an ordered list.

   Returns the number of items in weights (which is <= no of vote accs). */

ulong
fd_stake_weights_by_node( fd_vote_stakes_t const * vote_stakes,
                          ulong                    fork_id,
                          int                      iter_kind,
                          fd_vote_stake_weight_t * weights );

void
fd_stakes_activate_epoch( fd_bank_t *                    bank,
                          fd_runtime_stack_t *           runtime_stack,
                          fd_accdb_t *                   accdb,
                          fd_capture_ctx_t *             capture_ctx,
                          fd_stake_delegations_t *       stake_delegations,
                          ulong *                        new_rate_activation_epoch );

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
   the stake account. */

void
fd_stakes_update_stake_delegation( fd_pubkey_t const * pubkey,
                                   fd_acc_t const *    acc,
                                   fd_bank_t *         bank );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stakes_h */
