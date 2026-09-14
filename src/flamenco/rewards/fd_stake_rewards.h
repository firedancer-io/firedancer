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

  A fork's reward set is computed exactly once and is immutable after
  it is sealed.  Distribution reads back the partition that was saved,
  it never recomputes rewards.

  Storage is tiered.  Locked RAM holds:
  - one staging buffer of max_stake_accounts entries, in insert order
    and chained per partition, for the single fork being computed;
  - two sealed buffers of max_stake_accounts entries each, grouped by
    partition, for the two most recently sealed live forks.
  Disk (the well-known fd below) is the overflow tier, an arena of
  fixed-size extents of max_stake_accounts entries each:
  - when a third live fork is sealed while both sealed buffers are
    held, the oldest sealed live fork is spilled to an extent, once.  A
    fork whose last reference is dropped just gives its buffer back.
  - when a fork has more than max_stake_accounts rewards, every time
    the staging buffer fills during insertion it is flushed to the
    fork's overflow area, laid out partition-major with a fixed
    per-partition slot so that a partition is one contiguous run there.
    The remainder that fits is sealed to RAM as usual.

  On mainnet a single boundary chain is live and its rewards fit, so
  the common path never touches the disk.  The sparse file address
  space is bounded by (max_fork_width+FD_STAKE_REWARDS_OVF_EXTENTS)
  extents, and blocks are only ever allocated for what is written.

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

/* Disk extents available for overflow areas, shared by all forks, on
   top of the one spill extent every fork is guaranteed.  Each extent
   is max_stake_accounts entries of 48 bytes (about 103 MiB at the
   production capacity), so this is about 3.3 GiB of sparse file.  A
   single fork may take all of them, which bounds the rewards of one
   epoch to about 27x max_stake_accounts. */

#define FD_STAKE_REWARDS_OVF_EXTENTS (32UL)

/* The spill file lives on the well-known fd below (see
   initialize_accdb_fd; tests dup2 a memfd onto it).  123458/9 are
   Store, 123460/1 are accdb, and 123462 is reserved by XDP. */

#define FD_STAKE_REWARDS_FD (123457)

struct fd_stake_rewards;
typedef struct fd_stake_rewards fd_stake_rewards_t;

FD_PROTOTYPES_BEGIN

/* fd_stake_rewards_align is used to get the alignment for the stake
   rewards structure. */

ulong
fd_stake_rewards_align( void );

/* fd_stake_rewards_footprint is used to get the footprint for the stake
   rewards structure given the max number of stake accounts and the max
   number of forks.  max_stake_accounts is the RAM capacity in entries
   of the staging buffer and of each sealed buffer, not a bound on the
   number of rewards in an epoch. */

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
   regardless of how many references it has.  A sealed buffer or disk
   extents the fork held are returned without any I/O. */

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
   acquired.  A bank needs one whenever it computes rewards: at an
   epoch boundary, or when booting from a snapshot taken while rewards
   were being distributed. */

ulong
fd_stake_rewards_free_cnt( fd_stake_rewards_t const * stake_rewards );

/* fd_stake_rewards_init initializes the stake rewards structure for a
   given fork.  It should be used at the start of epoch reward
   calculation.  It returns a fork index.  The returned fork becomes
   the staged fork, sealing any fork that was still staged.

   max_rewards_cnt is the number of rewards the caller is about to
   insert.  It only matters when it exceeds max_stake_accounts: it then
   sizes the per-partition slot of the fork's overflow area, so it must
   not undercount. */

uchar
fd_stake_rewards_init( fd_stake_rewards_t * stake_rewards,
                       ulong                epoch,
                       fd_hash_t const *    parent_blockhash,
                       ulong                starting_block_height,
                       uint                 partitions_cnt,
                       ulong                max_rewards_cnt );

/* fd_stake_rewards_insert inserts a new stake reward for a given fork.
   It hashes the reward into the appropriate partition.  fork_idx must
   be the staged fork (the most recently init'd, not yet sealed).  When
   the staging buffer is full the staged entries are flushed to the
   fork's overflow area on disk first. */

void
fd_stake_rewards_insert( fd_stake_rewards_t * stake_rewards,
                         uchar                fork_idx,
                         fd_pubkey_t const *  pubkey,
                         ulong                lamports,
                         ulong                credits_observed );

/* fd_stake_rewards_seal finishes a fork's computation: the staged
   entries are grouped by partition into a sealed buffer, spilling the
   oldest sealed live fork to disk if both buffers are held.  Must be
   called after the last insert and before any iteration; fork_idx
   must be the staged fork.  Initializing another fork seals the staged
   one implicitly. */

void
fd_stake_rewards_seal( fd_stake_rewards_t * stake_rewards,
                       uchar                fork_idx );

/* Iterator for iterating over the stake rewards for a given fork and
   partition.  The fork must be sealed.  The caller should not
   interleave any other iteration or modification of the stake rewards
   structure while iterating.

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

/* Introspection for tests: whether a sealed fork's RAM part currently
   lives in a sealed buffer (1) or was spilled to disk (0), and how many
   disk extents the fork holds for overflow. */

int
fd_stake_rewards_is_resident( fd_stake_rewards_t const * stake_rewards,
                              uchar                      fork_idx );

ulong
fd_stake_rewards_ovf_extent_cnt( fd_stake_rewards_t const * stake_rewards,
                                 uchar                      fork_idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h */
