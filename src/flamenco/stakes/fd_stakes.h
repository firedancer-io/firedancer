#ifndef HEADER_fd_src_flamenco_stakes_fd_stakes_h
#define HEADER_fd_src_flamenco_stakes_fd_stakes_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"

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

struct fd_stake_account_slim {
  ulong                        map_next;
  fd_pubkey_t                  key;
  fd_delegation_t              delegation;
};
typedef struct fd_stake_account_slim fd_stake_account_slim_t;

#define FD_STAKE_ACCOUNTS_SLIM_POOL_SZ (50000)

ulong fd_pubkey_hash( fd_pubkey_t const * key, ulong seed );

#define MAP_NAME  fd_stakes_slim
#define MAP_KEY_T fd_pubkey_t
#define MAP_ELE_T fd_stake_account_slim_t
#define MAP_KEY   key
#define MAP_KEY_EQ(a,b) fd_pubkey_eq( (a), (b) )
#define MAP_KEY_HASH(key,seed) fd_pubkey_hash( key, seed )
#define MAP_NEXT  map_next
#define MAP_IMPL_STYLE 1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_compute_stake_delegations {
   ulong                           epoch;
   fd_stake_history_t const *      stake_history;
   ulong *                         new_rate_activation_epoch;
   fd_stake_weight_t_mapnode_t *   delegation_pool;
   fd_stake_weight_t_mapnode_t *   delegation_root;
   ulong                           vote_states_pool_sz;
};
typedef struct fd_compute_stake_delegations fd_compute_stake_delegations_t;

struct fd_accumulate_delegations_task_args {
   fd_exec_slot_ctx_t const *         slot_ctx;
   fd_stake_history_t const *         stake_history;
   ulong *                            new_rate_activation_epoch;
   fd_stake_history_entry_t *         accumulator;
   fd_epoch_info_t *                  temp_info;
   fd_spad_t * *                      spads;
   ulong                              epoch;
};
typedef struct fd_accumulate_delegations_task_args fd_accumulate_delegations_task_args_t;

fd_stake_account_slim_t *
fd_stakes_slim_join_pool( fd_stakes_slim_t * stakes );

fd_stake_account_slim_t *
fd_stakes_slim_init_pool( fd_stakes_slim_t * stakes );

static inline fd_stake_account_slim_t const *
fd_stakes_slim_join_pool_const( fd_stakes_slim_t const * stakes ) {
  return (fd_stake_account_slim_t const *)( fd_stakes_slim_join_pool( (fd_stakes_slim_t *)stakes ) );
}

void
fd_stakes_import( fd_stakes_slim_t *                  dst,
                  fd_solana_manifest_global_t const * manifest );

ulong
fd_stake_weights_by_node( fd_vote_accounts_global_t const * accs,
                          fd_vote_stake_weight_t *          weights );


void
fd_stakes_activate_epoch( fd_exec_slot_ctx_t *  slot_ctx,
                          ulong *               new_rate_activation_epoch,
                          fd_epoch_info_t *     temp_info,
                          fd_spad_t *           runtime_spad );

int
write_stake_state( fd_txn_account_t *    stake_acc_rec,
                   fd_stake_state_v2_t * stake_state );

void
fd_refresh_vote_accounts( fd_exec_slot_ctx_t *       slot_ctx,
                          fd_stake_history_t const * history,
                          ulong *                    new_rate_activation_epoch,
                          fd_epoch_info_t *          temp_info,
                          fd_spad_t *                runtime_spad );

/* A workaround to mimic Agave function get_epoch_reward_calculate_param_info
   https://github.com/anza-xyz/agave/blob/v2.2.14/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L299 */
void
fd_populate_vote_accounts( fd_exec_slot_ctx_t *       slot_ctx,
                           fd_stake_history_t const * history,
                           ulong *                    new_rate_activation_epoch,
                           fd_epoch_info_t *          temp_info,
                           fd_spad_t *                runtime_spad );

void
fd_accumulate_stake_infos( fd_exec_slot_ctx_t const * slot_ctx,
                           fd_stakes_slim_t const *   stakes,
                           fd_stake_history_t const * history,
                           ulong *                    new_rate_activation_epoch,
                           fd_stake_history_entry_t * accumulator,
                           fd_epoch_info_t *          temp_info,
                           fd_spad_t *                runtime_spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_stakes_h */
