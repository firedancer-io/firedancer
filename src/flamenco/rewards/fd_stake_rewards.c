#include "fd_stake_rewards.h"
#include "../../ballet/siphash13/fd_siphash13.h"

struct fd_stake_reward {
  uint  index_idx; /* position in vote account index */
  ulong lamports;
  ulong credits_observed;
};
typedef struct fd_stake_reward fd_stake_reward_t;

struct index_key {
  fd_pubkey_t pubkey;
  ulong       lamports;
  ulong       credits_observed;
};
typedef struct index_key index_key_t;

struct index_ele {
  union {
    struct {
      fd_pubkey_t pubkey;
      ulong       lamports;
      ulong       credits_observed;
    };
    index_key_t index_key;
  };
  uint next;
};
typedef struct index_ele index_ele_t;

#define POOL_NAME  index_pool
#define POOL_T     index_ele_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               index_map
#define MAP_KEY_T              index_key_t
#define MAP_ELE_T              index_ele_t
#define MAP_KEY                index_key
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(index_key_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(index_key_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

struct partition_ele  {
  uint index;
  uint next;
};
typedef struct partition_ele partition_ele_t;

struct fork_info {
  uint  ele_cnt;
  uint  partition_cnt;
  uint  partition_idxs_head[43200];
  uint  partition_idxs_tail[43200];
  ulong starting_block_height;
  ulong total_stake_rewards;

};
typedef struct fork_info fork_info_t;

struct fd_stake_rewards {
  ulong            magic;
  uint             total_ele_used;
  fork_info_t      fork_info[128];
  ulong            index_pool_offset;
  ulong            index_map_offset;
  ulong            partitions_offset;
  uchar            refcnt;

  ulong            max_stake_accounts;

  /* Temporary storage for the current stake reward being computed. */
  fd_hash_t        parent_blockhash;

  uint iter_curr_fork_idx;

};
typedef struct fd_stake_rewards fd_stake_rewards_t;

static inline index_ele_t *
get_index_pool( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->index_pool_offset );
}
static inline index_map_t *
get_index_map( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->index_map_offset );
}

static inline partition_ele_t *
get_partition_ele( fd_stake_rewards_t const * stake_rewards,
                   uchar                      fork_idx,
                   uint                       ele_cnt ) {

  /* TODO:FIXME: ALIGN HERE */
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->partitions_offset +
                      (fork_idx * stake_rewards->max_stake_accounts * sizeof(partition_ele_t)) +
                      (ele_cnt * sizeof(partition_ele_t)) );
}

ulong
fd_stake_rewards_align( void ) {
  return FD_STAKE_REWARDS_ALIGN;
}

ulong
fd_stake_rewards_footprint( ulong max_stake_accounts,
                            ulong max_fork_width,
                            ulong expected_stake_accs ) {
  ulong map_chain_cnt = index_map_chain_cnt_est( expected_stake_accs );

  ulong l = FD_LAYOUT_INIT;
  l  = FD_LAYOUT_APPEND( l, fd_stake_rewards_align(),  sizeof(fd_stake_rewards_t) );
  l  = FD_LAYOUT_APPEND( l, index_pool_align(),        index_pool_footprint( max_stake_accounts ) );
  l  = FD_LAYOUT_APPEND( l, index_map_align(),         index_map_footprint( map_chain_cnt ) );
  l  = FD_LAYOUT_APPEND( l, alignof(partition_ele_t),  max_fork_width * max_stake_accounts * sizeof(partition_ele_t) );

  /* we take advantage of the fact that the number of partitions * 8192
     is always == fd_ulong_align_up( max_stake_accounts, 8192UL ) */

  return FD_LAYOUT_FINI( l, fd_stake_rewards_align() );
}

void *
fd_stake_rewards_new( void * shmem,
                      ulong  max_stake_accounts,
                      ulong  max_fork_width FD_PARAM_UNUSED,
                      ulong  expected_stake_accs,
                      ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_stake_rewards_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong map_chain_cnt = index_map_chain_cnt_est( expected_stake_accs );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_stake_rewards_t * stake_rewards  = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_rewards_align(), sizeof(fd_stake_rewards_t) );
  void *               index_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, index_pool_align(),       index_pool_footprint( max_stake_accounts ) );
  void *               index_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, index_map_align(),        index_map_footprint( map_chain_cnt ) );
  void *               partitions_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(partition_ele_t), max_fork_width * max_stake_accounts * sizeof(partition_ele_t) );

  index_ele_t * index_pool = index_pool_join( index_pool_new( index_pool_mem, max_stake_accounts ) );
  if( FD_UNLIKELY( !index_pool ) ) {
    FD_LOG_WARNING(( "Failed to create index pool" ));
    return NULL;
  }
  stake_rewards->index_pool_offset = (ulong)index_pool - (ulong)shmem;

  index_map_t * index_map = index_map_join( index_map_new( index_map_mem, map_chain_cnt, seed ) );
  if( FD_UNLIKELY( !index_map ) ) {
    FD_LOG_WARNING(( "Failed to create index map" ));
    return NULL;
  }
  stake_rewards->index_map_offset   = (ulong)index_map - (ulong)shmem;
  stake_rewards->partitions_offset  = (ulong)partitions_mem - (ulong)shmem;
  stake_rewards->max_stake_accounts = max_stake_accounts;
  stake_rewards->refcnt             = 0;
  stake_rewards->magic              = 100UL; /* TODO:FIXME: placeholder magic */

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
  return fd_type_pun( shmem );
}

uchar
fd_stake_rewards_init( fd_stake_rewards_t * stake_rewards,
                       fd_hash_t const *    parent_blockhash,
                       ulong                starting_block_height,
                       uint                 partitions_cnt ) {
  /* 43200UL partitions is a protocol level invariant. */
  FD_TEST( partitions_cnt <= 43200UL && partitions_cnt > 0UL );

  index_map_t * index_map  = get_index_map( stake_rewards );
  index_ele_t * index_pool = get_index_pool( stake_rewards );

  /* If this is the first reference to the stake rewards, we need to
     reset the backing map and pool all the forks will share. */
  if( FD_LIKELY( stake_rewards->refcnt==0 ) ) {
    index_map_reset( index_map );
    index_pool_reset( index_pool );
  }

  uchar fork_idx = stake_rewards->refcnt;

  stake_rewards->refcnt++;
  stake_rewards->parent_blockhash = *parent_blockhash;

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
  index_ele_t * index_ele = get_index_pool( stake_rewards );
  index_map_t * index_map = get_index_map( stake_rewards );

  index_key_t index_key = {
    .pubkey           = *pubkey,
    .lamports         = lamports,
    .credits_observed = credits_observed,
  };

  uint index = (uint)index_map_idx_query( index_map, &index_key, UINT_MAX, index_ele );
  if( FD_UNLIKELY( index==UINT_MAX ) ) {
    index = (uint)index_pool_idx_acquire( index_ele );
    index_ele_t * ele = index_pool_ele( index_ele, index );
    ele->index_key = index_key;
    index_map_ele_insert( index_map, ele, index_ele );
  }

  /* We have an invariant that there can never be more than 8192 entries
     in a partition. */
  fd_siphash13_t   sip[1] = {0};
  fd_siphash13_t * hasher = fd_siphash13_init( sip, 0UL, 0UL );
  hasher = fd_siphash13_append( hasher, stake_rewards->parent_blockhash.hash, sizeof(fd_hash_t) );
  fd_siphash13_append( hasher, (uchar const *)pubkey->uc, sizeof(fd_pubkey_t) );
  ulong hash64 = fd_siphash13_fini( hasher );

  ulong partition_index = (ulong)((uint128)stake_rewards->fork_info[fork_idx].partition_cnt * (uint128) hash64 / ((uint128)ULONG_MAX + 1));

  uint curr_fork_len = stake_rewards->fork_info[fork_idx].ele_cnt;

  partition_ele_t * partition_ele = get_partition_ele( stake_rewards, fork_idx, curr_fork_len );
  partition_ele->index = index;
  partition_ele->next  = UINT_MAX;

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
fd_stake_rewards_fini( fd_stake_rewards_t * stake_rewards ) {
  stake_rewards->refcnt--;
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
  index_ele_t * index_ele = index_pool_ele( get_index_pool( stake_rewards ), partition_ele->index );
  *pubkey_out = index_ele->index_key.pubkey;
  *lamports_out = index_ele->index_key.lamports;
  *credits_observed_out = index_ele->index_key.credits_observed;
}

ulong
fd_stake_rewards_total_rewards( fd_stake_rewards_t * stake_rewards,
                                uchar                fork_idx ) {
  return stake_rewards->fork_info[fork_idx].total_stake_rewards;
}

uint
fd_stake_rewards_num_partitions( fd_stake_rewards_t * stake_rewards,
                                 uchar                fork_idx ) {
  return stake_rewards->fork_info[fork_idx].partition_cnt;
}

ulong
fd_stake_rewards_starting_block_height( fd_stake_rewards_t * stake_rewards,
                                        uchar                fork_idx ) {
  return stake_rewards->fork_info[fork_idx].starting_block_height;
}

ulong
fd_stake_rewards_exclusive_ending_block_height( fd_stake_rewards_t * stake_rewards,
                                                uchar                fork_idx ) {
  return stake_rewards->fork_info[fork_idx].starting_block_height + stake_rewards->fork_info[fork_idx].partition_cnt;
}
