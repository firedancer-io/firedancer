#include "fd_runtime.h"

/* Initializes the stakes cache in the Bank structure.
   TODO: maybe we don't need this cache at all? */
void fd_stakes_init( fd_global_ctx_t* global, fd_stakes_t* stakes ) {
   /* TODO: handle non-zero epoch case */
   


   stakes->epoch = 0;
   fd_vec_fd_delegation_pair_t_new( &stakes->stake_delegations );

}


/* https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L169 */
void activate_epoch( fd_global_ctx_t* global, ulong next_epoch ) {

   fd_stakes_t* stakes = &global->bank.stakes;

   /* Current stake delegations: list of all current delegations in stake_delegations
      https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L180 */
   fd_pubkey_hash_pair_t* stake_delegations = stakes->stake_delegations.elems;

   /* Add a new entry to the Stake History sysvar for the previous epoch
      https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L181-L192 */

   /* Update the current epoch value */
   stakes->epoch = next_epoch;

  /* Refresh the stake distribution of vote accounts for the next epoch,
     using the updated Stake History.
     https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L194-L216 */
}

// u calculate_stake(         &self,
//         voter_pubkey: &Pubkey,
//         epoch: Epoch,
//         stake_history: &StakeHistory, )

// Sum the stakes that point to the given voter_pubkey
static int calculate_stake () {

}

static ulong vote_balance_and_staked( fd_global_ctx_t* global ) {
   ulong total = 0;
   for (int i = 0; i < global->bank.stakes.stake_delegations.cnt; ++i) {
      total += global->bank.stakes.stake_delegations.elems->delegation.stake; 
   }
   for (int i = 0; i < global->bank.stakes.vote_accounts.vote_accounts_len; ++i) {
      total += global->bank.stakes.vote_accounts.vote_accounts->stake;
   }
   return total;
}

void remove_vote_account( fd_global_ctx_t* global ) {
   
}