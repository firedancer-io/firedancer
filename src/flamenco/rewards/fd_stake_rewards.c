#include "fd_stake_rewards.h"
#include "fd_rewards_base.h"
#include "../../ballet/siphash13/fd_siphash13.h"

#define MAX_SUPPORTED_FORKS (128UL)

#define FD_STAKE_REWARDS_MAGIC (0xF17EDA2CE757A4E0) /* FIREDANCER STAKE V0 */

/* This is an arbitrary value but it's a buffer that basically says that
   there won't be more than 2x the stake account limit of accounts that
   receive stake rewards in an epoch across forks. */
#define PUBKEY_POOL_CAPACITY_MULTIPLIER (2UL)

struct fork {
  int next;
};
typedef struct fork fork_t;

#define POOL_NAME  fork_pool
#define POOL_T     fork_t
#define POOL_NEXT  next
#define POOL_IDX_T int
#include "../../util/tmpl/fd_pool.c"

struct pubkey_ele {
  fd_pubkey_t pubkey;
  uint        next;
};
typedef struct pubkey_ele pubkey_ele_t;

#define POOL_NAME  pubkey_pool
#define POOL_T     pubkey_ele_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               pubkey_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              pubkey_ele_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

struct partition_ele {
  ulong lamports;
  ulong credits_observed;
  uint  pubkey_idx;
  uint  next;
};
typedef struct partition_ele partition_ele_t;

struct fork_info {
  uint  ele_cnt;
  uint  partition_cnt;
  uint  partition_idxs_head[MAX_PARTITIONS_PER_EPOCH];
  uint  partition_idxs_tail[MAX_PARTITIONS_PER_EPOCH];
  ulong starting_block_height;
  ulong total_stake_rewards;
};
typedef struct fork_info fork_info_t;

struct fd_stake_rewards {
  ulong       magic;
  ulong       max_stake_accounts;
  fork_info_t fork_info[MAX_SUPPORTED_FORKS];
  ulong       pubkey_pool_offset;
  ulong       pubkey_map_offset;
  ulong       fork_pool_offset;
  ulong       partitions_offset;
  ulong       epoch;

  /* Temporary storage for the current stake reward being computed. */
  fd_siphash13_t primed_hasher[ 1 ];
  uint           iter_curr_fork_idx;
  uint           pubkey_map_valid;
};
typedef struct fd_stake_rewards fd_stake_rewards_t;

static inline fork_t *
get_fork_pool( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->fork_pool_offset );
}

static inline pubkey_ele_t *
get_pubkey_pool( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->pubkey_pool_offset );
}

static inline pubkey_map_t *
get_pubkey_map( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->pubkey_map_offset );
}

static inline partition_ele_t *
get_partition_ele( fd_stake_rewards_t const * stake_rewards,
                   uchar                      fork_idx,
                   uint                       ele_cnt ) {

  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->partitions_offset +
                      (fork_idx * stake_rewards->max_stake_accounts * sizeof(partition_ele_t)) +
                      (ele_cnt * sizeof(partition_ele_t)) );
}

static void
populate_pubkey_map( fd_stake_rewards_t * stake_rewards ) {
  pubkey_ele_t * pubkey_pool = get_pubkey_pool( stake_rewards );
  pubkey_map_t * pubkey_map  = get_pubkey_map( stake_rewards );

  pubkey_map_reset( pubkey_map );
  ulong pubkey_cnt = pubkey_pool_used( pubkey_pool );
  for( ulong pubkey_idx=0UL; pubkey_idx<pubkey_cnt; pubkey_idx++ ) {
    pubkey_map_idx_insert( pubkey_map, pubkey_idx, pubkey_pool );
  }
  stake_rewards->pubkey_map_valid = 1U;
}

ulong
fd_stake_rewards_align( void ) {
  return FD_STAKE_REWARDS_ALIGN;
}

ulong
fd_stake_rewards_footprint( ulong max_stake_accounts,
                            ulong max_fork_width ) {
  ulong partition_ele_cnt = fd_ulong_sat_mul( max_fork_width, max_stake_accounts );
  ulong max_pubkeys       = fd_ulong_sat_mul( PUBKEY_POOL_CAPACITY_MULTIPLIER, max_stake_accounts );
  ulong map_chain_cnt     = pubkey_map_chain_cnt_est( max_pubkeys );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_rewards_align(), sizeof(fd_stake_rewards_t) );
  l = FD_LAYOUT_APPEND( l, pubkey_pool_align(),      pubkey_pool_footprint( max_pubkeys ) );
  l = FD_LAYOUT_APPEND( l, pubkey_map_align(),       pubkey_map_footprint( map_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, alignof(partition_ele_t), fd_ulong_sat_mul( partition_ele_cnt, sizeof(partition_ele_t) ) );
  return FD_LAYOUT_FINI( l, fd_stake_rewards_align() );
}

void *
fd_stake_rewards_new( void * shmem,
                      ulong  max_stake_accounts,
                      ulong  max_fork_width,
                      ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_stake_rewards_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_stake_accounts>(ulong)UINT_MAX/PUBKEY_POOL_CAPACITY_MULTIPLIER ) ) {
    FD_LOG_WARNING(( "max_stake_accounts is too large" ));
    return NULL;
  }
  ulong partition_ele_cnt = fd_ulong_sat_mul( max_fork_width, max_stake_accounts );
  ulong max_pubkeys        = PUBKEY_POOL_CAPACITY_MULTIPLIER * max_stake_accounts;
  ulong map_chain_cnt      = pubkey_map_chain_cnt_est( max_pubkeys );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_stake_rewards_t * stake_rewards   = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_rewards_align(), sizeof(fd_stake_rewards_t) );
  void *               pubkey_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, pubkey_pool_align(),      pubkey_pool_footprint( max_pubkeys ) );
  void *               pubkey_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, pubkey_map_align(),       pubkey_map_footprint( map_chain_cnt ) );
  void *               fork_pool_mem   = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_fork_width ) );
  void *               partitions_mem  = FD_SCRATCH_ALLOC_APPEND( l, alignof(partition_ele_t), fd_ulong_sat_mul( partition_ele_cnt, sizeof(partition_ele_t) ) );

  pubkey_ele_t * pubkey_pool = pubkey_pool_join( pubkey_pool_new( pubkey_pool_mem, max_pubkeys ) );
  if( FD_UNLIKELY( !pubkey_pool ) ) {
    FD_LOG_WARNING(( "Failed to create pubkey pool" ));
    return NULL;
  }
  stake_rewards->pubkey_pool_offset = (ulong)pubkey_pool - (ulong)shmem;

  pubkey_map_t * pubkey_map = pubkey_map_join( pubkey_map_new( pubkey_map_mem, map_chain_cnt, seed ) );
  if( FD_UNLIKELY( !pubkey_map ) ) {
    FD_LOG_WARNING(( "Failed to create pubkey map" ));
    return NULL;
  }
  stake_rewards->pubkey_map_offset = (ulong)pubkey_map - (ulong)shmem;

  fork_t * fork_pool = fork_pool_join( fork_pool_new( fork_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create fork pool" ));
    return NULL;
  }
  stake_rewards->fork_pool_offset = (ulong)fork_pool - (ulong)shmem;

  stake_rewards->partitions_offset   = (ulong)partitions_mem - (ulong)shmem;
  stake_rewards->max_stake_accounts  = max_stake_accounts;
  stake_rewards->epoch               = ULONG_MAX;
  stake_rewards->pubkey_map_valid    = 0U;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( stake_rewards->magic ) = FD_STAKE_REWARDS_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_stake_rewards_t *
fd_stake_rewards_join( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_stake_rewards_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_stake_rewards_t * stake_rewards = (fd_stake_rewards_t *)shmem;
  if( FD_UNLIKELY( stake_rewards->magic != FD_STAKE_REWARDS_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid stake rewards magic" ));
    return NULL;
  }
  return stake_rewards;
}

void
fd_stake_rewards_clear( fd_stake_rewards_t * stake_rewards ) {
  pubkey_pool_reset( get_pubkey_pool( stake_rewards ) );
  pubkey_map_reset( get_pubkey_map( stake_rewards ) );
  fork_pool_reset( get_fork_pool( stake_rewards ) );
  stake_rewards->epoch            = ULONG_MAX;
  stake_rewards->pubkey_map_valid = 0U;
}

void
fd_stake_rewards_purge( fd_stake_rewards_t * stake_rewards,
                        uchar                fork_idx ) {
  fork_pool_idx_release( get_fork_pool( stake_rewards ), (ulong)fork_idx );
  stake_rewards->fork_info[fork_idx].partition_cnt         = 0U;
  stake_rewards->fork_info[fork_idx].starting_block_height = 0UL;
  stake_rewards->fork_info[fork_idx].ele_cnt               = 0UL;
  stake_rewards->fork_info[fork_idx].total_stake_rewards   = 0UL;
  memset( stake_rewards->fork_info[fork_idx].partition_idxs_head, 0xFF, sizeof(stake_rewards->fork_info[fork_idx].partition_idxs_head) );
  memset( stake_rewards->fork_info[fork_idx].partition_idxs_tail, 0xFF, sizeof(stake_rewards->fork_info[fork_idx].partition_idxs_tail) );
}

uchar
fd_stake_rewards_init( fd_stake_rewards_t * stake_rewards,
                       ulong                epoch,
                       fd_hash_t const *    parent_blockhash,
                       ulong                starting_block_height,
                       uint                 partitions_cnt ) {
  fork_t * fork_pool = get_fork_pool( stake_rewards );

  /* The first fork of an epoch appends pubkeys directly to the shared
     pool.  If another fork reaches the same epoch, populate the map
     before processing it so that pubkeys can be shared across forks. */
  int is_new_epoch = stake_rewards->epoch!=epoch;
  if( FD_LIKELY( is_new_epoch ) ) {
    pubkey_pool_reset( get_pubkey_pool( stake_rewards ) );
    fork_pool_reset( fork_pool );
    stake_rewards->epoch            = epoch;
    stake_rewards->pubkey_map_valid = 0U;
  } else if( FD_UNLIKELY( !stake_rewards->pubkey_map_valid ) ) {
    populate_pubkey_map( stake_rewards );
  }

  uchar fork_idx = (uchar)fork_pool_idx_acquire( fork_pool );

  fd_siphash13_init( stake_rewards->primed_hasher, 0UL, 0UL );
  fd_siphash13_append( stake_rewards->primed_hasher, parent_blockhash->hash, sizeof(fd_hash_t) );

  stake_rewards->fork_info[fork_idx].partition_cnt         = partitions_cnt;
  stake_rewards->fork_info[fork_idx].starting_block_height = starting_block_height;
  stake_rewards->fork_info[fork_idx].ele_cnt               = 0UL;
  stake_rewards->fork_info[fork_idx].total_stake_rewards   = 0UL;
  memset( stake_rewards->fork_info[fork_idx].partition_idxs_head, 0xFF, sizeof(stake_rewards->fork_info[fork_idx].partition_idxs_head) );
  memset( stake_rewards->fork_info[fork_idx].partition_idxs_tail, 0xFF, sizeof(stake_rewards->fork_info[fork_idx].partition_idxs_tail) );

  return fork_idx;
}

void
fd_stake_rewards_insert( fd_stake_rewards_t * stake_rewards,
                         uchar                fork_idx,
                         fd_pubkey_t const *  pubkey,
                         ulong                lamports,
                         ulong                credits_observed ) {

  fd_siphash13_t sip[ 1 ];
  *sip = *stake_rewards->primed_hasher;
  fd_siphash13_append( sip, (uchar const *)pubkey->uc, sizeof(fd_pubkey_t) );
  ulong hash64 = fd_siphash13_fini( sip );

  ulong partition_index = (ulong)((uint128)stake_rewards->fork_info[fork_idx].partition_cnt * (uint128) hash64 / ((uint128)ULONG_MAX + 1));

  uint curr_fork_len = stake_rewards->fork_info[fork_idx].ele_cnt;
  if( FD_UNLIKELY( curr_fork_len>=stake_rewards->max_stake_accounts ) ) {
    FD_LOG_CRIT(( "invariant violation: curr_fork_len>=stake_rewards->max_stake_accounts" ));
  }

  pubkey_ele_t * pubkey_pool = get_pubkey_pool( stake_rewards );
  pubkey_map_t * pubkey_map  = get_pubkey_map( stake_rewards );
  pubkey_ele_t * pubkey_ele  = NULL;
  if( FD_UNLIKELY( stake_rewards->pubkey_map_valid ) ) {
    pubkey_ele = pubkey_map_ele_query( pubkey_map, pubkey, NULL, pubkey_pool );
  }
  if( FD_UNLIKELY( !pubkey_ele ) ) {
    if( FD_UNLIKELY( !pubkey_pool_free( pubkey_pool ) ) ) {
      FD_LOG_CRIT(( "Too many unique stake reward pubkeys in epoch (max %lu)", pubkey_pool_max( pubkey_pool ) ));
    }
    pubkey_ele         = pubkey_pool_ele_acquire( pubkey_pool );
    pubkey_ele->pubkey = *pubkey;
    if( FD_UNLIKELY( stake_rewards->pubkey_map_valid ) ) {
      FD_TEST( pubkey_map_ele_insert( pubkey_map, pubkey_ele, pubkey_pool ) );
    }
  }

  partition_ele_t * partition_ele = get_partition_ele( stake_rewards, fork_idx, curr_fork_len );
  partition_ele->lamports         = lamports;
  partition_ele->credits_observed = credits_observed;
  partition_ele->pubkey_idx       = (uint)pubkey_pool_idx( pubkey_pool, pubkey_ele );
  partition_ele->next             = UINT_MAX;

  int is_first_ele = stake_rewards->fork_info[fork_idx].partition_idxs_head[partition_index] == UINT_MAX;

  if( FD_LIKELY( !is_first_ele ) ) {
    partition_ele_t * prev_partition_ele = get_partition_ele( stake_rewards, fork_idx, stake_rewards->fork_info[fork_idx].partition_idxs_tail[partition_index] );
    prev_partition_ele->next = curr_fork_len;
    stake_rewards->fork_info[fork_idx].partition_idxs_tail[partition_index] = curr_fork_len;
  } else {
    stake_rewards->fork_info[fork_idx].partition_idxs_head[partition_index] = curr_fork_len;
    stake_rewards->fork_info[fork_idx].partition_idxs_tail[partition_index] = curr_fork_len;
  }

  stake_rewards->fork_info[fork_idx].ele_cnt++;
  stake_rewards->fork_info[fork_idx].total_stake_rewards += lamports;
}

void
fd_stake_rewards_iter_init( fd_stake_rewards_t * stake_rewards,
                            uchar                fork_idx,
                            uint                 partition_idx ) {
  uint first_fork_idx = stake_rewards->fork_info[fork_idx].partition_idxs_head[partition_idx];
  stake_rewards->iter_curr_fork_idx = first_fork_idx;
}

void
fd_stake_rewards_iter_next( fd_stake_rewards_t * stake_rewards,
                            uchar                fork_idx ) {
  partition_ele_t * partition_ele = get_partition_ele( stake_rewards, fork_idx, stake_rewards->iter_curr_fork_idx );
  stake_rewards->iter_curr_fork_idx = partition_ele->next;
}

int
fd_stake_rewards_iter_done( fd_stake_rewards_t * stake_rewards ) {
  return stake_rewards->iter_curr_fork_idx == UINT_MAX;
}

void
fd_stake_rewards_iter_ele( fd_stake_rewards_t * stake_rewards,
                           uchar                fork_idx,
                           fd_pubkey_t *        pubkey_out,
                           ulong *              lamports_out,
                           ulong *              credits_observed_out ) {
  partition_ele_t * partition_ele = get_partition_ele( stake_rewards, fork_idx, stake_rewards->iter_curr_fork_idx );
  pubkey_ele_t *    pubkey_ele    = pubkey_pool_ele( get_pubkey_pool( stake_rewards ), partition_ele->pubkey_idx );

  *pubkey_out           = pubkey_ele->pubkey;
  *lamports_out         = partition_ele->lamports;
  *credits_observed_out = partition_ele->credits_observed;
}

ulong
fd_stake_rewards_total_rewards( fd_stake_rewards_t const * stake_rewards,
                                uchar                      fork_idx ) {
  return stake_rewards->fork_info[fork_idx].total_stake_rewards;
}

uint
fd_stake_rewards_num_partitions( fd_stake_rewards_t const * stake_rewards,
                                 uchar                      fork_idx ) {
  return stake_rewards->fork_info[fork_idx].partition_cnt;
}

ulong
fd_stake_rewards_starting_block_height( fd_stake_rewards_t const * stake_rewards,
                                        uchar                      fork_idx ) {
  return stake_rewards->fork_info[fork_idx].starting_block_height;
}

ulong
fd_stake_rewards_exclusive_ending_block_height( fd_stake_rewards_t const * stake_rewards,
                                                uchar                      fork_idx ) {
  return stake_rewards->fork_info[fork_idx].starting_block_height + stake_rewards->fork_info[fork_idx].partition_cnt;
}
