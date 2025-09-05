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

   We can find a loose bound by assuming FD_BANKS_SLOTS_PER_EPOCH is the
   number of slots in an epoch, there can be:
   FD_BANKS_SLOTS_PER_EPOCH / MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH
   == 43200UL partitions.

   However, it is possible to find a tighter bound. If we assume that
   the max number of stake accounts is FD_BANKS_MAX_STAKE_ACCOUNTS,
   then the max number of partiitions is
   (FD_BANKS_MAX_STAKE_ACCOUNTS / (STAKE_ACCOUNT_STORES_PER_BLOCK + (FD_BANKS_MAX_STAKE_ACCOUNTS % STAKE_ACCOUNT_STORES_PER_BLOCK)))
   == 515UL partitions.
*/
#define FD_REWARDS_MAX_PARTITIONS ((FD_RUNTIME_MAX_STAKE_ACCOUNTS / STAKE_ACCOUNT_STORES_PER_BLOCK) + (FD_RUNTIME_MAX_STAKE_ACCOUNTS % STAKE_ACCOUNT_STORES_PER_BLOCK != 0))
FD_STATIC_ASSERT( FD_REWARDS_MAX_PARTITIONS == 733, "incorrect FD_REWARDS_MAX_PARTITIONS" );
FD_STATIC_ASSERT( FD_REWARDS_MAX_PARTITIONS <= FD_RUNTIME_SLOTS_PER_EPOCH / MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH, "incorrect FD_REWARDS_MAX_PARTITIONS" );

/* The max of footprint of fd_epoch_stakes is variable depending on the
   number of stake accounts that are supported. However, the size can be
   bounded out assuming worst case with 3M stake accounts. The total
   struct contains the top level header struct, the pool, and the dlists

   fd_epoch_stake_reward_t: 4192 bytes + 64 bytes align       = 4224 bytes

   pool's private meta:     32 bytes   + 96 bytes align       = 128 bytes
   each pool member:        72 bytes   + 56 bytes align       = 128 bytes
   all pool members:        128 bytes  * 3M                   = 384 MB

   each dlist:              24 bytes for sizeof(DLIST_T)      = 24 bytes
   all dlists:              24 bytes   * 733 max partitions   = 17592 bytes

   total footprint:         4224 bytes + 384 MB + 17592 bytes = 384021816 bytes
*/
#define FD_EPOCH_REWARDS_FOOTPRINT (384021816UL)

#define FD_EPOCH_REWARDS_ALIGN (128UL)

#define FD_EPOCH_REWARDS_MAGIC (0x122400081001UL)

struct fd_epoch_stake_reward {
  ulong       prev;
  ulong       next;
  ulong       parent;
  fd_pubkey_t stake_pubkey;
  ulong       credits_observed;
  ulong       lamports;
};
typedef struct fd_epoch_stake_reward fd_epoch_stake_reward_t;

#define POOL_NAME fd_epoch_stake_reward_pool
#define POOL_T    fd_epoch_stake_reward_t
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  fd_epoch_stake_reward_dlist
#define DLIST_ELE_T fd_epoch_stake_reward_t
#include "../../util/tmpl/fd_dlist.c"

struct fd_epoch_rewards {
  ulong magic;

  /* Data representing the partitioned stake rewards */
  int   is_active_;
  ulong stake_account_max_;
  ulong starting_block_height_;
  ulong num_partitions_;
  ulong partitions_lengths_[FD_REWARDS_MAX_PARTITIONS];

  /* Result of total rewards distribution */

  /* Total rewards for the epoch (including both vote rewards and stake
     rewards) */
  ulong total_rewards_;
  /* total rewards points calculated for the current epoch, where points
     equals the sum of (delegated stake * credits observed) for all
     delegations */
  ulong distributed_rewards_;
  /* Stake rewards that still need to be distributed, grouped by
     partition */
  uint128 total_points_;

  /* This will be followed by a pool of fd_epoch_stake_reward_t. This
     pool will be sized out to FD_BANKS_MAX_STAKE_ACCOUNTS. */

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

/* fd_epoch_rewards_get_partition_index returns a pointer to the dlist
   of stake rewards for the given partition index. */

fd_epoch_stake_reward_dlist_t *
fd_epoch_rewards_get_partition_index( fd_epoch_rewards_t const * epoch_rewards, ulong idx );

/* fd_epoch_rewards_get_stake_reward_pool returns a pointer to the pool
   of stake rewards. */

fd_epoch_stake_reward_t *
fd_epoch_rewards_get_stake_reward_pool( fd_epoch_rewards_t const * epoch_rewards );

/* fd_epoch_rewards_hash_and_insert determines the hash partition that
   the stake pubkey belongs in and stores the pubkey along with the
   total amount of credits and lamports. */

int
fd_epoch_rewards_hash_and_insert( fd_epoch_rewards_t * epoch_rewards,
                                  fd_hash_t const *    parent_blockhash,
                                  fd_pubkey_t const *  pubkey,
                                  ulong                credits,
                                  ulong                lamports );

/* fd_epoch_rewards_get_distribution_partition_index determines the
   hash partition that the current block belongs in. */

ulong
fd_epoch_rewards_get_distribution_partition_index( fd_epoch_rewards_t const * epoch_rewards, ulong curr_block_height );

/* Simple inline mutator functions */

static void FD_FN_UNUSED
fd_epoch_rewards_set_active( fd_epoch_rewards_t * epoch_rewards, int is_active ) {
  epoch_rewards->is_active_ = is_active;
}

static void FD_FN_UNUSED
fd_epoch_rewards_set_starting_block_height( fd_epoch_rewards_t * epoch_rewards, ulong block_height ) {
  epoch_rewards->starting_block_height_ = block_height;
}

static void FD_FN_UNUSED
fd_epoch_rewards_set_num_partitions( fd_epoch_rewards_t * epoch_rewards, ulong num_partitions ) {
  if( FD_UNLIKELY( num_partitions>FD_REWARDS_MAX_PARTITIONS ) ) {
    FD_LOG_WARNING(( "num_partitions: %lu is greater than FD_REWARDS_MAX_PARTITIONS: %lu", num_partitions, FD_REWARDS_MAX_PARTITIONS ));
    return;
  }
  epoch_rewards->num_partitions_ = num_partitions;
}

static void FD_FN_UNUSED
fd_epoch_rewards_set_distributed_rewards( fd_epoch_rewards_t * epoch_rewards, ulong distributed_rewards ) {
  epoch_rewards->distributed_rewards_ = distributed_rewards;
}

static void FD_FN_UNUSED
fd_epoch_rewards_set_total_rewards( fd_epoch_rewards_t * epoch_rewards, ulong total_rewards ) {
  epoch_rewards->total_rewards_ = total_rewards;
}

static void FD_FN_UNUSED
fd_epoch_rewards_set_total_points( fd_epoch_rewards_t * epoch_rewards, uint128 total_points ) {
  epoch_rewards->total_points_ = total_points;
}

/* Simple inline accessor functions */

static int FD_FN_UNUSED
fd_epoch_rewards_is_active( fd_epoch_rewards_t const * epoch_rewards ) {
  return epoch_rewards->is_active_;
}

static ulong FD_FN_UNUSED
fd_epoch_rewards_get_num_partitions( fd_epoch_rewards_t const * epoch_rewards ) {
  return epoch_rewards->num_partitions_;
}

static ulong FD_FN_UNUSED
fd_epoch_rewards_get_starting_block_height( fd_epoch_rewards_t const * epoch_rewards ) {
  return epoch_rewards->starting_block_height_;
}

static ulong FD_FN_UNUSED
fd_epoch_rewards_get_exclusive_ending_block_height( fd_epoch_rewards_t const * epoch_rewards ) {
  return epoch_rewards->starting_block_height_ + epoch_rewards->num_partitions_;
}

static ulong FD_FN_UNUSED
fd_epoch_rewards_get_distributed_rewards( fd_epoch_rewards_t const * epoch_rewards ) {
  return epoch_rewards->distributed_rewards_;
}

static uint128 FD_FN_UNUSED
fd_epoch_rewards_get_total_points( fd_epoch_rewards_t const * epoch_rewards ) {
  return epoch_rewards->total_points_;
}

static ulong FD_FN_UNUSED
fd_epoch_rewards_get_total_rewards( fd_epoch_rewards_t const * epoch_rewards ) {
  return epoch_rewards->total_rewards_;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_rewards_fd_epoch_rewards_h */
