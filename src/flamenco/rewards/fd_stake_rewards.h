#ifndef HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h
#define HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h

#include "../fd_flamenco_base.h"

/* fd_stake_rewards tracks pending partitioned epoch rewards across
   forks.

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

  Reward entries use cache_cnt+1 equivalent buffers: up to cache_cnt
  completed windows and one window under construction.  Entries are
  built directly in the buffer that becomes resident, so finishing a
  window does not move them.  Per-bank metadata is dynamically sized
  and does not multiply reward-entry storage.  Finishing a fork when
  the completed-window cache is full evicts the least recently finished
  window, but keeps that fork's metadata.  If an evicted window is
  needed, the caller recalculates it.

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

/* fd_stake_rewards_footprint returns the footprint given the maximum
   number of stake accounts and banks.  max_stake_accounts is the
   capacity of each in-memory window, not a bound on the rewards in an
   epoch.  max_bank_cnt sizes metadata, not reward-entry buffers.
   cache_cnt is the number of completed windows retained in memory and
   must be in [1,max_bank_cnt+1].  Storage includes one additional
   construction buffer.  An ancestor bank can retain an older evicted
   generation, so there is one metadata slot per bank.  An additional
   slot allows a cached window to be replaced before its old shared
   handle is released. */

ulong
fd_stake_rewards_footprint( ulong max_stake_accounts,
                            ulong max_bank_cnt,
                            ulong cache_cnt );

/* fd_stake_rewards_new creates a new stake rewards structure. */

void *
fd_stake_rewards_new( void * shmem,
                      ulong  max_stake_accounts,
                      ulong  max_bank_cnt,
                      ulong  cache_cnt );

/* fd_stake_rewards_join joins the caller to the stake rewards
   structure. */

fd_stake_rewards_t *
fd_stake_rewards_join( void * shmem );

/* fd_stake_rewards_clear resets the stake rewards structure to a
   post-new state. */

void
fd_stake_rewards_clear( fd_stake_rewards_t * stake_rewards );

/* Each stake rewards fork idx must be refcnt'd since they are shared
   across banks.  fd_stake_rewards_acquire increments the reference
   count and fd_stake_rewards_release decrements it.  Once the count
   reaches zero, the fork is purged. */

void
fd_stake_rewards_acquire( fd_stake_rewards_t * stake_rewards,
                          ushort               fork_idx );

void
fd_stake_rewards_release( fd_stake_rewards_t * stake_rewards,
                          ushort               fork_idx );

ulong
fd_stake_rewards_refcnt( fd_stake_rewards_t const * stake_rewards,
                         ushort                     fork_idx );

/* fd_stake_rewards_free_cnt returns how many forks can still be
   acquired, including the replacement slot.  A bank needs one whenever
   it computes rewards it does not already hold: at an epoch boundary,
   or when the partition it has to distribute falls outside its
   window. */

ulong
fd_stake_rewards_free_cnt( fd_stake_rewards_t const * stake_rewards );

/* fd_stake_rewards_init starts reward calculation for a new fork and
   returns its index.  win_lo is the first partition to retain.  The
   fork claims the free construction buffer.  No other fork may be
   staged. */

ushort
fd_stake_rewards_init( fd_stake_rewards_t * stake_rewards,
                       fd_hash_t const *    parent_blockhash,
                       ulong                starting_block_height,
                       uint                 partitions_cnt,
                       uint                 win_lo,
                       ulong                max_rewards_cnt );

/* fd_stake_rewards_window_{lo,hi} return the inclusive range of
   partitions that a fork currently holds.  A staged fork reports its
   range but is not iterable until fd_stake_rewards_fini.  Both return
   UINT_MAX for an evicted fork.  The caller must recalculate a missing
   window. */

uint
fd_stake_rewards_window_lo( fd_stake_rewards_t const * stake_rewards,
                            ushort                     fork_idx );

uint
fd_stake_rewards_window_hi( fd_stake_rewards_t const * stake_rewards,
                            ushort                     fork_idx );

/* fd_stake_rewards_insert inserts a new stake reward for a given fork.
   It hashes the reward into the appropriate partition.  The reward is
   only stored if its partition falls inside the fork's window, but it
   always counts towards fd_stake_rewards_total_rewards. */

void
fd_stake_rewards_insert( fd_stake_rewards_t * stake_rewards,
                         ushort               fork_idx,
                         fd_pubkey_t const *  pubkey,
                         ulong                lamports,
                         ulong                credits_observed );

/* fd_stake_rewards_fini makes the construction buffer resident without
   moving its entries.  An empty window releases its buffer.  The oldest
   resident window is evicted when the completed-window cache is full. */

void
fd_stake_rewards_fini( fd_stake_rewards_t * stake_rewards,
                       ushort               fork_idx );

/* Iterator for the rewards in one resident fork partition.
   partition_idx must lie inside the fork's window.  The caller should
   not interleave any other iteration or modification of the stake
   rewards structure while iterating.

   Example use:
   for( fd_stake_rewards_iter_init( stake_rewards, fork_idx,
                                    partition_idx );
        !fd_stake_rewards_iter_done( stake_rewards );
        fd_stake_rewards_iter_next( stake_rewards, fork_idx ) ) {
     fd_pubkey_t pubkey;
     ulong       lamports;
     ulong       credits_observed;
     fd_stake_rewards_iter_ele( stake_rewards, fork_idx, &pubkey,
                                &lamports, &credits_observed );
   }
*/

void
fd_stake_rewards_iter_init( fd_stake_rewards_t * stake_rewards,
                            ushort               fork_idx,
                            uint                 partition_idx );

void
fd_stake_rewards_iter_next( fd_stake_rewards_t * stake_rewards,
                            ushort               fork_idx );

int
fd_stake_rewards_iter_done( fd_stake_rewards_t * stake_rewards );

void
fd_stake_rewards_iter_ele( fd_stake_rewards_t * stake_rewards,
                           ushort               fork_idx,
                           fd_pubkey_t *        pubkey_out,
                           ulong *              lamports_out,
                           ulong *              credits_observed_out );

/* Simple accessors for stake rewards information. */

ulong
fd_stake_rewards_total_rewards( fd_stake_rewards_t const * stake_rewards,
                                ushort                     fork_idx );

uint
fd_stake_rewards_num_partitions( fd_stake_rewards_t const * stake_rewards,
                                 ushort                     fork_idx );

ulong
fd_stake_rewards_starting_block_height( fd_stake_rewards_t const * stake_rewards,
                                        ushort                     fork_idx );

ulong
fd_stake_rewards_exclusive_ending_block_height( fd_stake_rewards_t const * stake_rewards,
                                                ushort                     fork_idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h */
