#ifndef HEADER_fd_src_flamenco_stakes_fd_stakes_h
#define HEADER_fd_src_flamenco_stakes_fd_stakes_h

#include "fd_stake_delegations.h"
#include "fd_stake_types.h"

FD_PROTOTYPES_BEGIN

fd_stake_state_t const *
fd_stakes_get_state( fd_accdb_entry_t const * entry );

fd_stake_history_entry_t
stake_activating_and_deactivating( fd_delegation_t const *    self,
                                   ulong                      target_epoch,
                                   fd_stake_history_t const * stake_history,
                                   ulong *                    new_rate_activation_epoch );

fd_stake_history_entry_t
fd_stakes_activating_and_deactivating( fd_stake_delegation_t const * self,
                                       ulong                         target_epoch,
                                       fd_stake_history_t const *    stake_history,
                                       ulong *                       new_rate_activation_epoch );

/* fd_stake_weights_by_node converts Stakes (unordered list of (vote
   acc, active stake) tuples) to an ordered list of (stake, vote pubkey, node
   identity) sorted by (stake descending, vote pubkey descending).

   weights points to an array suitable to hold ...

     fd_vote_accounts_pair_t_map_size( accs->vote_accounts_pool,
                                       accs->vote_accounts_root )

   ... items.  On return, weights be an ordered list.

   Returns the number of items in weights (which is <= no of vote accs). */

ulong
fd_stake_weights_by_node( fd_top_votes_t const *   top_votes_t_2,
                          fd_vote_stakes_t *       vote_stakes,
                          ushort                   fork_idx,
                          fd_vote_stake_weight_t * weights,
                          int                      vat_enabled );


ulong
fd_stake_weights_by_node_next( fd_top_votes_t const *   top_votes_t_1,
                               fd_vote_stakes_t *       vote_stakes,
                               ushort                   fork_idx,
                               fd_vote_stake_weight_t * weights,
                               int                      vat_enabled );

void
fd_stakes_activate_epoch( fd_bank_t *                    bank,
                          fd_runtime_stack_t *           runtime_stack,
                          fd_accdb_t *                   accdb,
                          fd_capture_ctx_t *             capture_ctx,
                          fd_stake_delegations_t const * stake_delegations,
                          ulong *                        new_rate_activation_epoch );

void
fd_refresh_vote_accounts( fd_bank_t *                    bank,
                          fd_accdb_t *                   accdb,
                          fd_runtime_stack_t *           runtime_stack,
                          fd_stake_delegations_t const * stake_delegations,
                          fd_stake_history_t const *     history,
                          ulong *                        new_rate_activation_epoch );

/* fd_stakes_update_delegation is used to maintain the in-memory cache
   of the stake delegations that is used at the epoch boundary.  Entries
   in the cache will be inserted/updated/removed based on the state of
   the stake account. */

void
fd_stakes_update_stake_delegation( fd_pubkey_t const *      pubkey,
                                   fd_accdb_entry_t const * entry,
                                   fd_bank_t *              bank );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stakes_h */
