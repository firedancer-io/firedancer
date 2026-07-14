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

  Each fork can have a distinct worst-case set of stake rewards.  For
  each fork, we keep track of what elements are in each partition.  The
  partitions can be of unequal size, so each partition is represented as
  a singly linked list.  Each partition member stores the stake account,
  lamports, credits observed, and the linked-list pointer directly.

  As a note, the structure is also only partially fork-aware.  It safely
  assumes that the epoch boundary of a second epoch will not happen
  while the stake rewards are still being paid out of a first epoch.
  The protocol guarantees this because stake rewards must be paid out
  within the first 10% of an epoch.

  It is assumed that there will not be concurrent users of the stake
  rewards structure.  The caller is expected to manage synchronization
  between threads. */

#define FD_STAKE_REWARDS_ALIGN (128UL)

struct fd_stake_rewards;
typedef struct fd_stake_rewards fd_stake_rewards_t;

FD_PROTOTYPES_BEGIN

/* fd_stake_rewards_align is used to get the alignment for the stake
   rewards structure. */

ulong
fd_stake_rewards_align( void );

/* fd_stake_rewards_footprint is used to get the footprint for the stake
   rewards structure given the max number of stake accounts and the max
   number of forks. */

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

/* fd_stake_rewards_purge frees all per-fork state for a given fork. */

void
fd_stake_rewards_purge( fd_stake_rewards_t * stake_rewards,
                        uchar                fork_idx );

/* fd_stake_rewards_init initializes the stake rewards structure for a
   given fork.  It should be used at the start of epoch reward
   calculation or recalculation.  It returns a fork index. */

uchar
fd_stake_rewards_init( fd_stake_rewards_t * stake_rewards,
                       ulong                epoch,
                       fd_hash_t const *    parent_blockhash,
                       ulong                starting_block_height,
                       uint                 partitions_cnt );

/* fd_stake_rewards_insert inserts a new stake reward for a given
   fork.  It hashes the reward into the appropriate
   partition. */

void
fd_stake_rewards_insert( fd_stake_rewards_t * stake_rewards,
                         uchar                fork_idx,
                         fd_pubkey_t const *  pubkey,
                         ulong                lamports,
                         ulong                credits_observed );

/* Iterator for iterating over the stake rewards for a given fork and
   partition.  The caller should not interleave any other iteration or
   modification of the stake rewards structure while iterating.

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
