#ifndef HEADER_fd_src_flamenco_stakes_fd_stakes_h
#define HEADER_fd_src_flamenco_stakes_fd_stakes_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "fd_stake_delegations.h"
#include "fd_vote_states.h"

FD_PROTOTYPES_BEGIN

/* fd_stake_weights_by_node converts Stakes (unordered list of (vote
   acc, active stake) tuples) to an ordered list of (stake, vote pubkey, node
   identity) sorted by (stake descending, vote pubkey descending).

   weights points to an array suitable to hold ...

     fd_vote_accounts_pair_t_map_size( accs->vote_accounts_pool,
                                       accs->vote_accounts_root )

   ... items.  On return, weights be an ordered list.

   Returns the number of items in weights (which is <= no of vote accs). */
#define STAKE_ACCOUNT_SIZE ( 200 )

ulong
fd_stake_weights_by_node( fd_vote_states_t const * vote_states,
                          fd_vote_stake_weight_t * weights );

void
fd_stakes_activate_epoch( fd_exec_slot_ctx_t *           slot_ctx,
                          fd_stake_delegations_t const * stake_delegations,
                          ulong *                        new_rate_activation_epoch,
                          fd_spad_t *                    runtime_spad );

fd_stake_history_entry_t
stake_and_activating( fd_delegation_t const * delegation,
                      ulong                   target_epoch,
                      fd_stake_history_t *    stake_history,
                      ulong *                 new_rate_activation_epoch );

fd_stake_history_entry_t
stake_activating_and_deactivating( fd_delegation_t const * delegation,
                                   ulong                   target_epoch,
                                   fd_stake_history_t *    stake_history,
                                   ulong *                 new_rate_activation_epoch );

int
write_stake_state( fd_txn_account_t *    stake_acc_rec,
                   fd_stake_state_v2_t * stake_state );

void
fd_refresh_vote_accounts( fd_exec_slot_ctx_t *           slot_ctx,
                          fd_stake_delegations_t const * stake_delegations,
                          fd_stake_history_t const *     history,
                          ulong *                        new_rate_activation_epoch );

void
fd_accumulate_stake_infos( ulong                          epoch,
                           fd_stake_delegations_t const * stake_delegations,
                           fd_stake_history_t const *     history,
                           ulong *                        new_rate_activation_epoch,
                           fd_stake_history_entry_t *     accumulator );

/* fd_store_stake_delegation is used to update fd_stake_delegations_t
   based on a specific transaction account. If the account is empty or
   uninitialized, it is removed from the stake delegation map. */

void
fd_update_stake_delegation( fd_txn_account_t * stake_account,
                            fd_bank_t *        bank );

/* fd_refresh_stake_delegations is used to refresh the stake
   delegations stored in fd_stake_delegations_t which is owned by
   the bank. For a given database handle, read in the state of all
   stake accounts, decode their state, and update each stake delegation.
   This is meant to be called before any slots are executed, but after
   the snapshot has finished loading.

   Before this function is called, there are some important assumptions
   made about the state of the stake delegations:
   1. fd_stake_delegations_t is not missing any valid entries
   2. fd_stake_delegations_t may have some invalid entries that should
      be removed
   These are invariants enforced by the Agave client. However, after
   TODO:FIXME: add permalink

   fd_refresh_stake_delegations will remove all of the invalid entries
   that are detected. An entry is considered invalid if the stake
   account does not exist (e.g. zero balance or no record) or if it
   has invalid state (e.g. not a stake account or invalid bincode data).
   No new entries are added to the struct at this point. */

void
fd_refresh_stake_delegations( fd_exec_slot_ctx_t * slot_ctx,
                              fd_spad_t *          spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stakes_h */
