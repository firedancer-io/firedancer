#ifndef HEADER_fd_src_flamenco_rewards_fd_epoch_rewards_h
#define HEADER_fd_src_flamenco_rewards_fd_epoch_rewards_h

#include "../runtime/fd_runtime_const.h"
#include "fd_rewards_base.h"

FD_PROTOTYPES_BEGIN

/* fd_epoch_rewards_t is the main struct that stores the epoch rewards
   data. Specifically, the struct manages storing the stake account
   rewards which are distributed over many slots. The number of
   partitions are determined by a simple function on the number of stake
   accounts. The rewards distribution starts on the first block after
   an epoch boundary and the rewards for each partition is distributed
   during a single slot. The partitions and reward schedule are
   calculated during the epoch boundary and distributed after.

   fd_epoch_rewards_t is usually managed by the banks. It is only
   written to during the epoch boundary and is read-only after that. */

/* Some useful bounds to size out the epoch rewards struct. */

/* The max number of partitions is bounded by the the slots_per_epoch
   divided by the MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH.
   See hash_rewards_into_partitions() and
   Bank::get_reward_distribution_num_blocks().

   We can find a loose bound by assuming FD_RUNTIME_SLOTS_PER_EPOCH is the
   number of slots in an epoch, there can be:
   FD_RUNTIME_SLOTS_PER_EPOCH / MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH
   == 43200UL partitions.

   However, it is possible to find a tighter bound. If we assume that
   the max number of stake accounts is FD_RUNTIME_MAX_STAKE_ACCOUNTS,
   then the max number of partitions is
   div_ceil(FD_RUNTIME_MAX_STAKE_ACCOUNTS, STAKE_ACCOUNT_STORES_PER_BLOCK)
   == FD_RUNTIME_MAX_STAKE_ACCOUNTS / STAKE_ACCOUNT_STORES_PER_BLOCK
      + (FD_RUNTIME_MAX_STAKE_ACCOUNTS % STAKE_ACCOUNT_STORES_PER_BLOCK != 0)
   == 733UL partitions.
*/
#define FD_REWARDS_MAX_PARTITIONS ((FD_RUNTIME_MAX_STAKE_ACCOUNTS / STAKE_ACCOUNT_STORES_PER_BLOCK) + (FD_RUNTIME_MAX_STAKE_ACCOUNTS % STAKE_ACCOUNT_STORES_PER_BLOCK != 0))
FD_STATIC_ASSERT( FD_REWARDS_MAX_PARTITIONS == 733, "incorrect FD_REWARDS_MAX_PARTITIONS" );
FD_STATIC_ASSERT( FD_REWARDS_MAX_PARTITIONS <= FD_RUNTIME_SLOTS_PER_EPOCH / MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH, "incorrect FD_REWARDS_MAX_PARTITIONS" );

/* The max of footprint of fd_epoch_rewards is variable depending on the
   number of stake accounts that are supported. However, the size can be
   bounded out assuming worst case with 3M stake accounts. The total
   struct contains the top level header struct, the pool, and the dlists

   fd_epoch_rewards_t                                         = 5984 bytes

   pool's private meta:     32 bytes   + 96 bytes align       = 128 bytes
   all pool members:        64 bytes   * 3M                   = 192 MB
   total pool footprint:                                      = 192,000,128 bytes

   map footprint:           align_up( sizeof(MAP_T) + chain_cnt*sizeof(MAP_IDX_T), alignof(MAP_T) )
   chain_cnt:               2097152 chains is the largest power of 2 less than 3M.
   sizeof(MAP_T):           24 bytes
   alignof(MAP_T):          8 bytes
                            24 + 2097152 * sizeof(uint)      = 8,388,632 bytes


   each dlist:              16 bytes for sizeof(DLIST_T)      = 16 bytes
   all dlists:              16 bytes   * 733 max partitions   = 11,728 bytes

   total footprint:         5,984 bytes + 192,000,128 bytes + 8,388,632 bytes + 11,728 bytes = 200,406,472 bytes
   total footprint + align: align up to 128 bytes = 200,406,528 bytes
*/
#define FD_EPOCH_REWARDS_FOOTPRINT (200406528UL)

#define FD_EPOCH_REWARDS_ALIGN (128UL)

#define FD_EPOCH_REWARDS_MAGIC (0x122400081001UL)

struct fd_epoch_stake_reward {
  fd_pubkey_t stake_pubkey;
  ulong       credits_observed;
  ulong       lamports;
  /* Internal pointers for pool, dlist, and map. */
  uint        prev;
  uint        next;
  uint        parent;
  uint        next_map;
};
typedef struct fd_epoch_stake_reward fd_epoch_stake_reward_t;

/* TODO: Need to move the dlist into the .c file.  There needs to be a
   way to forward declare the iterator (see fd_map.h). */

#define DLIST_NAME  fd_epoch_stake_reward_dlist
#define DLIST_ELE_T fd_epoch_stake_reward_t
#define DLIST_IDX_T uint
#include "../../util/tmpl/fd_dlist.c"

struct fd_epoch_rewards_iter {
  fd_epoch_stake_reward_t *          pool;
  void *                             dlist;
  fd_epoch_stake_reward_dlist_iter_t iter;
};
typedef struct fd_epoch_rewards_iter fd_epoch_rewards_iter_t;

struct fd_epoch_rewards {
  ulong magic;

  /* Data representing the partitioned stake rewards */
  ulong stake_account_max;
  ulong starting_block_height;
  ulong num_partitions;
  ulong partitions_lengths[FD_REWARDS_MAX_PARTITIONS];

  /* Result of total rewards distribution */

  /* Total rewards for the epoch (including both vote rewards and stake
     rewards) */
  ulong total_rewards;

  /* total rewards points calculated for the current epoch, where points
     equals the sum of (delegated stake * credits observed) for all
     delegations */
  ulong distributed_rewards;

  /* Stake rewards that still need to be distributed, grouped by
     partition */
  fd_w_u128_t total_points;

  /* Total stake rewards to distribute as calculated during the epoch
     boundary */
  ulong total_stake_rewards;

  /* Total number of stake accounts that have rewards to distribute */
  ulong stake_rewards_cnt;

  /* Internal pointers for pool, dlist, and map. */
  ulong pool_offset;
  ulong map_offset;
  ulong dlists_offset;

  /* This will be followed by a pool of fd_epoch_stake_reward_t. This
     pool will be sized out to FD_RUNTIME_MAX_STAKE_ACCOUNTS. */

  /* The pool will be followed by up to FD_REWARDS_MAX_PARTITIONS
     that will all need to be joined. */

};
typedef struct fd_epoch_rewards fd_epoch_rewards_t;


/* fd_epoch_rewards_align returns the alignment of the epoch rewards
   struct. */

ulong
fd_epoch_rewards_align( void );

/* fd_epoch_rewards_footprint returns the footprint of the epoch rewards
   struct. */

ulong
fd_epoch_rewards_footprint( ulong stake_account_max );

/* fd_epoch_rewards_new initializes the epoch_rewards struct. */
void *
fd_epoch_rewards_new( void * shmem, ulong stake_account_max );

/* fd_epoch_rewards_join returns a pointer to the epoch rewards struct
   that is stored in the shared memory. */

fd_epoch_rewards_t *
fd_epoch_rewards_join( void * shmem );

/* fd_epoch_rewards_leave returns a pointer to the epoch rewards struct
   that is stored in the shared memory. */

void *
fd_epoch_rewards_leave( fd_epoch_rewards_t const * epoch_rewards );

/* fd_epoch_rewards_delete unformats the epoch rewards struct and the
   memory that the struct manages.  */

void *
fd_epoch_rewards_delete( void * epoch_rewards );

/* fd_epoch_rewards_insert stores the rewards for a given stake account
   into the data structure. */

void
fd_epoch_rewards_insert( fd_epoch_rewards_t * epoch_rewards,
                         fd_pubkey_t const *  pubkey,
                         ulong                credits,
                         ulong                lamports );

/* fd_epoch_rewards_hash_into_partitions hashes all of the stake
   accounts into the appropriate partitions. */

void
fd_epoch_rewards_hash_into_partitions( fd_epoch_rewards_t * epoch_rewards,
                                       fd_hash_t const *    parent_blockhash,
                                       ulong                num_partitions );

/* fd_epoch_rewards_get_distribution_partition_index determines the
   hash partition that the current block belongs in. */

ulong
fd_epoch_rewards_get_distribution_partition_index( fd_epoch_rewards_t const * epoch_rewards,
                                                   ulong                      curr_block_height );

/* fd_epoch_rewards_get_exclusive_ending_block_height returns the
   block height that the last partition ends at. */

static inline ulong
fd_epoch_rewards_get_exclusive_ending_block_height( fd_epoch_rewards_t const * epoch_rewards ) {
  return epoch_rewards->starting_block_height + epoch_rewards->num_partitions;
}

/* Iterator API for epoch rewards. The iterator is initialized with a
   call to fd_epoch_rewards_iter_init. The caller is responsible for
   managing the memory for the iterator. It is safe to call
   fd_epoch_rewards_iter_next if the result of
   fd_epoch_rewards_iter_done() ==0. It is safe to call
   fd_epoch_rewards_iter_ele() to get the current epoch reward.
   Elements that are iterated over are not safe to modify.

   Under the hood, the iterator is just a wrapper over the iterator used
   by the underlying dlist.
*/

fd_epoch_stake_reward_t *
fd_epoch_rewards_iter_ele( fd_epoch_rewards_iter_t * iter );

fd_epoch_rewards_iter_t *
fd_epoch_rewards_iter_init( fd_epoch_rewards_iter_t *  iter,
                            fd_epoch_rewards_t const * epoch_rewards,
                            ulong                      partition_idx );

int
fd_epoch_rewards_iter_done( fd_epoch_rewards_iter_t * iter );

void
fd_epoch_rewards_iter_next( fd_epoch_rewards_iter_t * iter );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_rewards_fd_epoch_rewards_h */
