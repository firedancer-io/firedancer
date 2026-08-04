#ifndef HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h
#define HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h

#include "../fd_flamenco_base.h"

/* fd_stake_rewards is a fork aware structure that stores and keeps
   track of pending stake rewards for the purposes of partitioned epoch
   rewards that occurs after the epoch boundary.

   The access pattern is as follows:
   1. Insertion/Hashing: This occurs at the epoch boundary after stake
      rewards are computed before rewards are distributed.  The stake
      account along with corresponding lamports and credits observed are
      hashed into a rewards partition.  These rewards will be paid out
      later.
   2. Iteration: A partition is paid out per slot.  All of the accounts
      in the partition are iterated over and the rewards are distributed
      to the stake accounts involved.

  The protocol level guarantees is just that there can be up to 43200
  rewards slots.  There is no limit on the number of stake rewards paid
  out per slot.

  Each fork can support a window of entries at a time.  It is sized to
  support current mainnet load along with some slack, but it can support
  more.  When the rewards for a specific block are reached, the rewards
  are recalculated and the window is advanced.  In the non-degenerate
  case, rewards are only calculated once per fork.

  As a note, the structure is also only partially fork-aware.  It safely
  assumes that the epoch boundary of a second epoch will not happen
  while the stake rewards are still being paid out of a first epoch.
  The protocol guarantees this because stake rewards must be paid out
  within the first 10% of an epoch.

  It is assumed that there will not be concurrent users of the stake
  rewards structure.  The caller is expected to manage synchronization
  between threads.

  TODO: nothing reserves a fork for a bank before the bank runs, so
  this capacity is not checked when the bank is started: banks are
  admitted by fd_banks_can_start_bank, which only accounts for the bank
  pool and the fork width, and acquire their fork later while executing
  the block.  This means that under really adverse staking conditions
  and forking conditions, the pool capacity can exceed which would
  cause the validator to crash.  These conditions don't exist today. */

#define FD_STAKE_REWARDS_ALIGN          (128UL)
#define FD_STAKE_REWARDS_MAX_FORK_WIDTH (128UL)

struct fd_stake_rewards;
typedef struct fd_stake_rewards fd_stake_rewards_t;

FD_PROTOTYPES_BEGIN

/* fd_stake_rewards_align is used to get the alignment for the stake
   rewards structure. */

ulong
fd_stake_rewards_align( void );

/* fd_stake_rewards_footprint is used to get the footprint for the stake
   rewards structure given the max number of stake accounts and the max
   number of forks.  max_stake_accounts is the per fork window capacity
   in entries, not a bound on the number of rewards in an epoch. */

ulong
fd_stake_rewards_footprint( ulong max_stake_accounts,
                            ulong max_fork_width );

/* fd_stake_rewards_new creates a new stake rewards structure. */

void *
fd_stake_rewards_new( void * shmem,
                      ulong  max_stake_accounts,
                      ulong  max_fork_width );

/* fd_stake_rewards_join joins the caller to the stake rewards
   structure. */

fd_stake_rewards_t *
fd_stake_rewards_join( void * shmem );

/* fd_stake_rewards_clear resets the stake rewards structure to a
   post-new state. */

void
fd_stake_rewards_clear( fd_stake_rewards_t * stake_rewards );

/* fd_stake_rewards_purge frees all per-fork state for a given fork,
   regardless of how many references it has. */

void
fd_stake_rewards_purge( fd_stake_rewards_t * stake_rewards,
                        uchar                fork_idx );

/* Each stake rewards fork idx must be refcnt'd since they are shared
   across banks.  fd_stake_rewards_acquire increments the reference
   count and fd_stake_rewards_release decrements it.  Once the count
   reaches zero, the fork is purged via a call to _release(). */

void
fd_stake_rewards_acquire( fd_stake_rewards_t * stake_rewards,
                          uchar                fork_idx );

void
fd_stake_rewards_release( fd_stake_rewards_t * stake_rewards,
                          uchar                fork_idx );

ulong
fd_stake_rewards_refcnt( fd_stake_rewards_t const * stake_rewards,
                         uchar                      fork_idx );

/* fd_stake_rewards_free_cnt returns how many forks can still be
   acquired.  A bank needs one whenever it computes rewards it does not
   already hold: at an epoch boundary, or when the partition it has to
   distribute falls outside its window. */

ulong
fd_stake_rewards_free_cnt( fd_stake_rewards_t const * stake_rewards );

/* fd_stake_rewards_init initializes the stake rewards structure for a
   given fork.  It should be used at the start of epoch reward
   calculation or recalculation.  It returns a fork index. */

uchar
fd_stake_rewards_init( fd_stake_rewards_t * stake_rewards,
                       ulong                epoch,
                       fd_hash_t const *    parent_blockhash,
                       ulong                starting_block_height,
                       uint                 partitions_cnt,
                       ulong                max_rewards_cnt );

/* fd_stake_rewards_window_advance removes all of the entries associated
   with the current window of a specific fork and shifts the starting
   window to be win_lo.  The caller is expected to insert stake rewards
   in the same way it does when computing rewards.  parent_blockhash
   must match the one that was supplied to fd_stake_rewards_init for
   the initial rewards computation.

   A fork's window is only ever positioned before its entries are
   computed: a bank that needs a window other than the one it holds
   acquires a fork of its own, because the fork it holds is shared with
   the banks that branched off it.  When the window is advance, it must
   belong to a new fork_idx. */

void
fd_stake_rewards_window_advance( fd_stake_rewards_t * stake_rewards,
                                 uchar                fork_idx,
                                 fd_hash_t const *    parent_blockhash,
                                 uint                 win_lo );

/* fd_stake_rewards_window_{lo,hi} return the inclusive range of
   partition indices that a stake rewards fork currently holds.  If the
   requested partition is not in this window, the caller needs to
   re-derive the set of stake partitions for the next window. */

uint
fd_stake_rewards_window_lo( fd_stake_rewards_t const * stake_rewards,
                            uchar                      fork_idx );

uint
fd_stake_rewards_window_hi( fd_stake_rewards_t const * stake_rewards,
                            uchar                      fork_idx );

/* fd_stake_rewards_insert inserts a new stake reward for a given fork.
   It hashes the reward into the appropriate partition.  The reward is
   only stored if its partition falls inside the fork's window, but it
   always counts towards fd_stake_rewards_total_rewards. */

void
fd_stake_rewards_insert( fd_stake_rewards_t * stake_rewards,
                         uchar                fork_idx,
                         fd_pubkey_t const *  pubkey,
                         ulong                lamports,
                         ulong                credits_observed );

/* Iterator for iterating over the stake rewards for a given fork and
   partition.  partition_idx must lie inside the fork's window.  The
   caller should not interleave any other iteration or modification of
   the stake rewards structure while iterating.

   Example use:
   for( fd_stake_rewards_iter_init( stake_rewards, fork_idx, partition_idx );
        !fd_stake_rewards_iter_done( stake_rewards );
        fd_stake_rewards_iter_next( stake_rewards, fork_idx ) ) {
     fd_pubkey_t pubkey;
     ulong       lamports;
     ulong       credits_observed;
     fd_stake_rewards_iter_ele( stake_rewards, fork_idx, &pubkey, &lamports, &credits_observed );
   }
*/

void
fd_stake_rewards_iter_init( fd_stake_rewards_t * stake_rewards,
                            uchar                fork_idx,
                            uint                 partition_idx );

void
fd_stake_rewards_iter_next( fd_stake_rewards_t * stake_rewards,
                            uchar                fork_idx );

int
fd_stake_rewards_iter_done( fd_stake_rewards_t * stake_rewards );

void
fd_stake_rewards_iter_ele( fd_stake_rewards_t * stake_rewards,
                           uchar                fork_idx,
                           fd_pubkey_t *        pubkey_out,
                           ulong *              lamports_out,
                           ulong *              credits_observed_out );

/* Simple accessors for stake rewards information. */

ulong
fd_stake_rewards_total_rewards( fd_stake_rewards_t const * stake_rewards,
                                uchar                      fork_idx );

uint
fd_stake_rewards_num_partitions( fd_stake_rewards_t const * stake_rewards,
                                 uchar                      fork_idx );

ulong
fd_stake_rewards_starting_block_height( fd_stake_rewards_t const * stake_rewards,
                                        uchar                      fork_idx );

ulong
fd_stake_rewards_exclusive_ending_block_height( fd_stake_rewards_t const * stake_rewards,
                                                uchar                      fork_idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h */
