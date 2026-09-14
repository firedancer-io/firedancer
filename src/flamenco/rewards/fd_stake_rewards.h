#ifndef HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h
#define HEADER_fd_src_flamenco_rewards_fd_stake_rewards_h

#include "../fd_flamenco_base.h"

/* fd_stake_rewards stores partitioned epoch rewards for multiple forks.
   At an epoch boundary, the caller initializes a fork, inserts each
   reward, and finishes the fork.  Each reward is hashed into a
   partition.  During distribution, the saved partitions are read back
   one per slot.  Finished rewards are immutable and never recomputed.

   The in-memory tier holds one fork being built and two finished forks.
   Additional rewards or live forks spill to the sparse file described
   below.  The common mainnet path uses only the in-memory tier.  The
   protocol permits up to 43200 reward slots and does not limit the
   number of rewards in one slot.

   Rewards for a new epoch must not begin while rewards from the
   previous epoch are still being distributed.  The protocol guarantees
   this because distribution finishes within the first 10% of an epoch.

   This structure is not thread-safe.  The caller must synchronize
   concurrent access.

   TODO: fd_banks_can_start_bank does not reserve a rewards fork.  Under
   extreme staking and forking conditions, a bank could start and then
   exhaust this pool while executing an epoch-boundary block. */

#define FD_STAKE_REWARDS_ALIGN          (128UL)
#define FD_STAKE_REWARDS_MAX_FORK_WIDTH (128UL)

/* The spill file lives on the well-known fd below (see
   initialize_stake_rewards_fd; tests dup2 a memfd onto it).  123458/9
   are Store, 123460/1 are accdb, and 123462 is reserved by XDP. */

#define FD_STAKE_REWARDS_FD (123453)

struct fd_stake_rewards;
typedef struct fd_stake_rewards fd_stake_rewards_t;

FD_PROTOTYPES_BEGIN

/* fd_stake_rewards_align is used to get the alignment for the stake
   rewards structure. */

ulong
fd_stake_rewards_align( void );

/* fd_stake_rewards_footprint is used to get the footprint for the stake
   rewards structure given the max number of stake accounts and the max
   number of forks.  max_stake_accounts is the in-memory capacity in
   entries of the staging buffer and of each buffer, not a bound on the
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
                       fd_hash_t const *    parent_blockhash,
                       ulong                starting_block_height,
                       uint                 partitions_cnt,
                       ulong                max_rewards_cnt );

/* fd_stake_rewards_insert inserts a new stake reward for a given fork.
   It hashes the reward into the appropriate partition.  fork_idx must
   be the staged fork (the most recently init'd, not yet fini'd).  When
   the staging buffer is full the staged entries are flushed to the
   fork's overflow area on disk first. */

void
fd_stake_rewards_insert( fd_stake_rewards_t * stake_rewards,
                         uchar                fork_idx,
                         fd_pubkey_t const *  pubkey,
                         ulong                lamports,
                         ulong                credits_observed );

/* fd_stake_rewards_fini finishes building rewards for the staged fork
   and makes them ready to iterate.  If both in-memory buffers are in
   use, the oldest fork is moved to disk.  Call this after the final
   insert.  Starting a new fork finishes the staged fork
   automatically. */

void
fd_stake_rewards_fini( fd_stake_rewards_t * stake_rewards,
                       uchar                fork_idx );

/* Iterator for iterating over the stake rewards for a given fork and
   partition.  The fork must be sealed.  The caller should not
   interleave any other iteration or modification of the stake rewards
   structure while iterating.

   Example use:
   for( fd_stake_rewards_iter_init( stake_rewards, fork_idx,
                                    partition_idx );
        !fd_stake_rewards_iter_done( stake_rewards );
        fd_stake_rewards_iter_next( stake_rewards ) ) {
     fd_pubkey_t pubkey;
     ulong       lamports;
     ulong       credits_observed;
     fd_stake_rewards_iter_ele( stake_rewards, &pubkey, &lamports,
                                &credits_observed );
   }
*/

void
fd_stake_rewards_iter_init( fd_stake_rewards_t * stake_rewards,
                            uchar                fork_idx,
                            uint                 partition_idx );

void
fd_stake_rewards_iter_next( fd_stake_rewards_t * stake_rewards );

int
fd_stake_rewards_iter_done( fd_stake_rewards_t * stake_rewards );

void
fd_stake_rewards_iter_ele( fd_stake_rewards_t * stake_rewards,
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
