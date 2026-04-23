#ifndef HEADER_fd_src_flamenco_stakes_fd_stakes_h
#define HEADER_fd_src_flamenco_stakes_fd_stakes_h

#include "fd_stake_delegations.h"
#include "fd_stake_types.h"
#include "../types/fd_types.h"

FD_PROTOTYPES_BEGIN

fd_stake_state_t const *
fd_stakes_get_state( fd_account_meta_t const * meta );

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

/* Epoch-boundary phase 0 (refresh_delegations): the map-reduce.

   The map: fd_refresh_delegations_partitioned is the per-worker
   function.  It iterates its partition of stake_delegations,
   accumulates into the tile's local stake_accum stash (per-worker
   dedup), and adds scalar activating/deactivating/effective totals
   into the out_* accumulators.  Returns 0 on completion; returns 1
   if the local stash filled up, in which case iterator state is
   saved in runtime_stack->refresh.local_state and the caller must
   drain the slot via fd_refresh_delegations_merge_tile_slot before
   issuing a resume.

   Replay-side reduce/bookends:
     _pre   seeds the shared stake_accum_map with zero-stake entries
            for every vote account in the parent fork's vote_stakes
            and new_votes; returns the running staked_accounts count.
     _merge_tile_slot folds one worker's local stake_accum into the
            shared stake_accum_map; resets that slot for reuse.
     _finalize writes the accumulated scalar stake totals onto the
            bank.
     _post  runs Phase B (top votes refresh) and Phase C
            (vote_stakes insertion) after the shared stake_accum_map
            has been fully populated. */

void
fd_refresh_vote_accounts_no_vat_pre( fd_bank_t *          bank,
                                     fd_runtime_stack_t * runtime_stack,
                                     ulong *              staked_accounts_out );

int
fd_refresh_delegations_partitioned( fd_bank_t *                    bank,
                                    fd_runtime_stack_t *           runtime_stack,
                                    fd_stake_delegations_t const * stake_delegations,
                                    fd_stake_history_t const *     history,
                                    ulong                          partition_idx,
                                    ulong                          total_partitions,
                                    int                            is_resume,
                                    ulong *                        new_rate_activation_epoch,
                                    ulong *                        out_effective,
                                    ulong *                        out_activating,
                                    ulong *                        out_deactivating );

void
fd_refresh_delegations_merge_tile_slot( fd_runtime_stack_t * runtime_stack,
                                        ulong                slot_idx,
                                        ulong *              staked_accounts_inout );

void
fd_refresh_delegations_finalize( fd_bank_t * bank,
                                 ulong       total_effective,
                                 ulong       total_activating,
                                 ulong       total_deactivating );

void
fd_refresh_vote_accounts_no_vat_post( fd_bank_t *               bank,
                                      fd_accdb_user_t *         accdb,
                                      fd_funk_txn_xid_t const * xid,
                                      fd_runtime_stack_t *      runtime_stack );

/* fd_refresh_vote_accounts_vat is the sequential VAT refresh path,
   used only from the serial epoch-boundary convenience.  Not yet
   parallelized; callers that want parallel refresh fall back to
   serial when validator_admission_ticket is active. */

void
fd_refresh_vote_accounts_vat( fd_bank_t *                    bank,
                              fd_accdb_user_t *              accdb,
                              fd_funk_txn_xid_t const *      xid,
                              fd_runtime_stack_t *           runtime_stack,
                              fd_stake_delegations_t const * stake_delegations,
                              fd_stake_history_t const *     history,
                              ulong *                        new_rate_activation_epoch );

/* fd_stakes_update_delegation is used to maintain the in-memory cache
   of the stake delegations that is used at the epoch boundary.  Entries
   in the cache will be inserted/updated/removed based on the state of
   the stake account. */

void
fd_stakes_update_stake_delegation( fd_pubkey_t const *       pubkey,
                                   fd_account_meta_t const * meta,
                                   fd_bank_t *               bank );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stakes_h */
