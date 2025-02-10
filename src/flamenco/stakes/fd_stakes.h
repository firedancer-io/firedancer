#ifndef HEADER_fd_src_flamenco_stakes_fd_stakes_h
#define HEADER_fd_src_flamenco_stakes_fd_stakes_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../runtime/fd_borrowed_account.h"

FD_PROTOTYPES_BEGIN

/* fd_stake_weights_by_node converts Stakes (unordered list of (vote
   acc, active stake) tuples) to an ordered list of (stake, node
   identity) sorted by (stake descending, node identity descending).

   weights points to an array suitable to hold ...

     fd_vote_accounts_pair_t_map_size( accs->vote_accounts_pool,
                                       accs->vote_accounts_root )

   ... items.  On return, weights be an ordered list.

   Returns the number of items in weights (which is <= no of vote accs).
   On failure returns ULONG_MAX.  Reasons for failure include not enough
   bump allocator space available. */
#define STAKE_ACCOUNT_SIZE ( 200 )

struct fd_compute_stake_delegations {
   ulong                           epoch;
   fd_stake_history_t const *      stake_history;
   ulong *                         new_rate_activation_epoch;
   fd_stake_weight_t_mapnode_t *   delegation_pool;
   fd_stake_weight_t_mapnode_t *   delegation_root;
   ulong                           vote_states_pool_sz;
   fd_spad_t * *                   spads;
};
typedef struct fd_compute_stake_delegations fd_compute_stake_delegations_t;

struct fd_accumulate_delegations_task_args {
   fd_exec_slot_ctx_t const *         slot_ctx;
   fd_stake_history_t const *         stake_history;
   ulong *                            new_rate_activation_epoch;
   fd_stake_history_entry_t *         accumulator;
   fd_epoch_info_t *                  temp_info;
   fd_spad_t * *                      spads;
   fd_delegation_pair_t_mapnode_t *   stake_delegations_pool;
   ulong                              epoch;
};
typedef struct fd_accumulate_delegations_task_args fd_accumulate_delegations_task_args_t;

ulong
fd_stake_weights_by_node( fd_vote_accounts_t const * accs,
                          fd_stake_weight_t *        weights,
                          fd_spad_t *                runtime_spad );


void
fd_stakes_activate_epoch( fd_exec_slot_ctx_t *  slot_ctx,
                          ulong *               new_rate_activation_epoch,
                          fd_epoch_info_t *     temp_info,
                          fd_tpool_t *          tpool,
                          fd_spad_t * *         exec_spads,
                          ulong                 exec_spad_cnt,
                          fd_spad_t *           runtime_spad );

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
write_stake_state( fd_borrowed_account_t * stake_acc_rec,
                   fd_stake_state_v2_t *   stake_state );

void
fd_stakes_remove_stake_delegation( fd_exec_slot_ctx_t * slot_ctx, fd_borrowed_account_t * stake_account, ulong * new_rate_activation_epoch );

void
fd_stakes_upsert_stake_delegation( fd_exec_slot_ctx_t * slot_ctx, fd_borrowed_account_t * stake_account, ulong * new_rate_activation_epoch );

void
fd_refresh_vote_accounts( fd_exec_slot_ctx_t *       slot_ctx,
                          fd_stake_history_t const * history,
                          ulong *                    new_rate_activation_epoch,
                          fd_epoch_info_t *          temp_info,
                          fd_tpool_t *               tpool,
                          fd_spad_t * *              exec_spads,
                          ulong                      exec_spad_cnt,
                          fd_spad_t *                runtime_spad );

void 
fd_accumulate_stake_infos( fd_exec_slot_ctx_t const * slot_ctx,
                           fd_stakes_t const *        stakes,
                           fd_stake_history_t const * history,
                           ulong *                    new_rate_activation_epoch,
                           fd_stake_history_entry_t * accumulator,
                           fd_epoch_info_t *          temp_info,
                           fd_tpool_t *               tpool,
                           fd_spad_t * *              exec_spads,
                           ulong                      exec_spads_cnt,
                           fd_spad_t *                runtime_spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stakes_h */
