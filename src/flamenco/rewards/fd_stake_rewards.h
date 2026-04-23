#ifndef HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h
#define HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h

#include "../../util/fd_util_base.h"
#include "../types/fd_types_custom.h"

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
  rewards slots.  There is no gap on the number of stake rewards paid
  out per slot.

  A naive approach with a worst case number of stake accounts (assume
  ~200M) and a reasonable amount of forks across the epoch boundary
  (assume 32) would require an element of size 48 (pubkey, lamports, and
  credits observed).  So we would need a structure of size: 48 bytes *
  200M accounts * 32 forks = 307GB of memory.  This also doesn't involve
  any data to keep track of pool/map overhead.

  Instead we use the property that across forks almost every single
  stake account will have the same rewards.  So we can use a shared
  index of (pubkey, stake, credit) entries to store the rewards for all
  forks.

  For each fork, we will need to keep track of what elements are in
  each partition.  But each partition can be of unequal size so we use
  a singly linked list to store the elements in each partition.  Each
  partition member will just contain a linked-list pointer and an index
  into the aforementioned index pool.  When stake rewards are being paid
  out, the iterator will iterate through the linked list and dereference
  the index pool to get the pubkey and associated rewards.

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
   rewards structure given the max number of stake accounts, the max
   number of forks, and the expected number of stake accounts.  The
   expected number of stake accounts is used to internally size out the
   map chain for the index. */

ulong
fd_stake_rewards_footprint( ulong max_stake_accounts,
                            ulong expected_stake_accs,
                            ulong max_fork_width );

/* fd_stake_rewards_new creates a new stake rewards structure. */

void *
fd_stake_rewards_new( void * shmem,
                      ulong  max_stake_accounts,
                      ulong  expected_stake_accs,
                      ulong  max_fork_width,
                      ulong  seed );

/* fd_stake_rewards_join joins the caller to the stake rewards
   structure. */

fd_stake_rewards_t *
fd_stake_rewards_join( void * shmem );

/* fd_stake_rewards_clear resets the stake rewards structure to a
   post-new state. */

void
fd_stake_rewards_clear( fd_stake_rewards_t * stake_rewards );

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
   fork.  It adds it to the index and hashes it into the approporiate
   partition.  Concurrency-safe: multiple writers may call in
   parallel on the same (stake_rewards, fork_idx); shared counters
   are updated with atomic FAA and the index_map / partition_idxs_head
   chains are pushed via CAS-spin. */

void
fd_stake_rewards_insert( fd_stake_rewards_t * stake_rewards,
                         uchar                fork_idx,
                         fd_pubkey_t const *  pubkey,
                         ulong                lamports,
                         ulong                credits_observed );

/* Per-worker slot reservation state for
   fd_stake_rewards_insert_local_batched.  The insert path needs two
   shared counters (stake_rewards->total_ele_used and
   fork_info.ele_cnt); naively each insert would do an atomic FAA(1)
   on both, which under N-way contention costs ~100 ns each and
   causes false sharing on the per-slot arrays (index_ele[],
   partition_ele[]) because workers' slots end up interleaved.
   Instead we reserve chunks of FD_STAKE_REWARDS_RESERVATION_CHUNK
   slots at a time with a single FAA per chunk and hand them out
   locally -- per-insert path has no atomics.  A worker's reserved
   slots are also contiguous, so the writes to index_ele[] and
   partition_ele[] stay within cache lines that the worker exclusively
   owns: no coherence ping-pong with other workers.

   Initialize to all zeros for a fresh worker session.  The terminal
   over-reservation (up to CHUNK-1 slots unused by each worker) is
   harmless: consumers walk the partition linked lists and never see
   unused slots.  Callers must ensure stake_rewards->max_stake_accounts
   exceeds (actual_inserts + (CHUNK-1)*num_workers). */

#define FD_STAKE_REWARDS_RESERVATION_CHUNK (64U)

struct fd_stake_rewards_reservation {
  uint total_ele_next;  /* next slot to consume from index_ele pool reservation */
  uint total_ele_end;   /* one past last reserved index_ele slot */
  uint fork_ele_next;   /* next slot to consume from partition_ele reservation */
  uint fork_ele_end;    /* one past last reserved partition_ele slot */
};
typedef struct fd_stake_rewards_reservation fd_stake_rewards_reservation_t;

/* Local-batched insert.  Identical to fd_stake_rewards_insert except:
   (a) the per-insert CAS-spin push onto fork_info.partition_idxs_head[]
   is deferred -- caller supplies per-partition local_heads /
   local_tails scratch arrays and must later invoke
   fd_stake_rewards_splice_local to publish them;
   (b) atomic FAAs on total_ele_used and fork_info.ele_cnt are batched
   via a per-worker reservation state (see above). */

void
fd_stake_rewards_insert_local_batched( fd_stake_rewards_t *             stake_rewards,
                                       uchar                            fork_idx,
                                       fd_pubkey_t const *              pubkey,
                                       ulong                            lamports,
                                       ulong                            credits_observed,
                                       uint *                           local_heads,
                                       uint *                           local_tails,
                                       fd_stake_rewards_reservation_t * reservation );

/* fd_stake_rewards_splice_local splices per-partition local chains
   onto the shared fork_info.partition_idxs_head[] via one CAS-spin
   per non-empty partition.  The caller's local_heads / local_tails
   arrays must be sized >= fork_info.partition_cnt and populated by
   prior fd_stake_rewards_insert_local_batched calls.  On return the
   local chains are logically drained (the local arrays are not
   modified in place; the caller may reset them for reuse). */

void
fd_stake_rewards_splice_local( fd_stake_rewards_t * stake_rewards,
                               uchar                fork_idx,
                               uint const *         local_heads,
                               uint const *         local_tails );

/* Iterator for iterating over the stake rewards for a given fork and
   partition.  The caller should not interleave any other iteration or
   modification of the stake rewards structure while iterating.

   Example use:
   for( fd_stake_rewards_iter_init( stake_rewards, fork_idx, partition_idx );
        !fd_stake_rewards_iter_done( stake_rewards, fork_idx );
        fd_stake_rewards_iter_next( stake_rewards, fork_idx ) ) {
     fd_pubkey_t pubkey;
     ulong       lamports;
     ulong       credits_observed;
     fd_stake_rewards_iter_ele( iter, &pubkey, &lamports, &credits_observed );
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
