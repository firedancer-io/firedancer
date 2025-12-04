#include "fd_epoch_rewards.h"
#include "../../ballet/siphash13/fd_siphash13.h"

#define POOL_NAME  fd_epoch_stake_reward_pool
#define POOL_T     fd_epoch_stake_reward_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               fd_epoch_stake_reward_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_epoch_stake_reward_t
#define MAP_KEY                stake_pubkey
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next_map
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

ulong
fd_epoch_rewards_align( void ) {
  return FD_EPOCH_REWARDS_ALIGN;
}

ulong
fd_epoch_rewards_footprint( ulong stake_account_max ) {
  ulong chain_cnt_est = fd_epoch_stake_reward_map_chain_cnt_est( stake_account_max );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_epoch_rewards_align(), sizeof(fd_epoch_rewards_t) );
  l = FD_LAYOUT_APPEND( l, fd_epoch_stake_reward_pool_align(), fd_epoch_stake_reward_pool_footprint( stake_account_max ) );
  l = FD_LAYOUT_APPEND( l, fd_epoch_stake_reward_map_align(), fd_epoch_stake_reward_map_footprint( chain_cnt_est ) );
  l = FD_LAYOUT_APPEND( l, fd_epoch_stake_reward_dlist_align(), fd_epoch_stake_reward_dlist_footprint() * FD_REWARDS_MAX_PARTITIONS );
  return FD_LAYOUT_FINI( l, fd_epoch_rewards_align() );
}

void *
fd_epoch_rewards_new( void * shmem, ulong stake_account_max ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_epoch_rewards_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_epoch_rewards_t * epoch_rewards = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_rewards_align(), sizeof(fd_epoch_rewards_t) );
  memset( epoch_rewards, 0, sizeof(fd_epoch_rewards_t) );

  void * pool = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_pool_align(), fd_epoch_stake_reward_pool_footprint( stake_account_max ) );
  epoch_rewards->pool_offset = (ulong)pool - (ulong)shmem;
  if( FD_UNLIKELY( !fd_epoch_stake_reward_pool_new( pool, stake_account_max ) ) ) {
    FD_LOG_WARNING(( "bad pool" ));
    return NULL;
  }

  ulong chain_cnt_est = fd_epoch_stake_reward_map_chain_cnt_est( stake_account_max );
  void * map = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_map_align(), fd_epoch_stake_reward_map_footprint( chain_cnt_est ) );
  epoch_rewards->map_offset = (ulong)map - (ulong)shmem;
  if( FD_UNLIKELY( !fd_epoch_stake_reward_map_new( map, chain_cnt_est, 0UL ) ) ) {
    FD_LOG_WARNING(( "bad map" ));
    return NULL;
  }

  for( ulong i=0UL; i<FD_REWARDS_MAX_PARTITIONS; i++ ) {
    void * dlist = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_dlist_align(), fd_epoch_stake_reward_dlist_footprint() );
    if( i==0UL ) epoch_rewards->dlists_offset = (ulong)dlist - (ulong)shmem;
    if( FD_UNLIKELY( !fd_epoch_stake_reward_dlist_new( dlist ) ) ) {
      FD_LOG_WARNING(( "bad dlist at idx %lu", i ));
      return NULL;
    }
  }

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_epoch_rewards_align() ) != (ulong)shmem+fd_epoch_rewards_footprint( stake_account_max ) ) ) {
    FD_LOG_WARNING(( "bad footprint" ));
    return NULL;
  }


  FD_COMPILER_MFENCE();
  epoch_rewards->magic = FD_EPOCH_REWARDS_MAGIC;
  FD_COMPILER_MFENCE();

  epoch_rewards->stake_account_max = stake_account_max;

  return shmem;
}

fd_epoch_rewards_t *
fd_epoch_rewards_join( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_epoch_rewards_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_epoch_rewards_t * epoch_rewards = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_rewards_align(), sizeof(fd_epoch_rewards_t) );
  ulong stake_account_max = epoch_rewards->stake_account_max;

  void * pool = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_pool_align(), fd_epoch_stake_reward_pool_footprint( stake_account_max ) );
  if( FD_UNLIKELY( !fd_epoch_stake_reward_pool_join( pool ) ) ) {
    FD_LOG_WARNING(( "bad pool" ));
    return NULL;
  }

  ulong chain_cnt_est = fd_epoch_stake_reward_map_chain_cnt_est( stake_account_max );
  void * map = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_map_align(), fd_epoch_stake_reward_map_footprint( chain_cnt_est ) );
  if( FD_UNLIKELY( !fd_epoch_stake_reward_map_join( map ) ) ) {
    FD_LOG_WARNING(( "bad map" ));
    return NULL;
  }

  for( ulong i=0UL; i<FD_REWARDS_MAX_PARTITIONS; i++ ) {
    void * dlist = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_dlist_align(), fd_epoch_stake_reward_dlist_footprint() );
    if( FD_UNLIKELY( !fd_epoch_stake_reward_dlist_join( dlist ) ) ) {
      FD_LOG_WARNING(( "bad dlist at idx %lu", i ));
      return NULL;
    }
  }

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_epoch_rewards_align() )!=(ulong)shmem+fd_epoch_rewards_footprint( stake_account_max ) ) ) {
    FD_LOG_WARNING(( "bad footprint" ));
    return NULL;
  }

  if( FD_UNLIKELY( epoch_rewards->magic!=FD_EPOCH_REWARDS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return epoch_rewards;
}

void *
fd_epoch_rewards_leave( fd_epoch_rewards_t const * epoch_rewards ) {
  return (void *)epoch_rewards;
}

void *
fd_epoch_rewards_delete( void * epoch_rewards_shmem ) {
  fd_epoch_rewards_t * epoch_rewards = (fd_epoch_rewards_t *)epoch_rewards_shmem;

  if( FD_UNLIKELY( !epoch_rewards ) ) {
    FD_LOG_WARNING(( "NULL epoch_rewards" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)epoch_rewards, fd_epoch_rewards_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned epoch_rewards" ));
    return NULL;
  }

  if( FD_UNLIKELY( epoch_rewards->magic != FD_EPOCH_REWARDS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  epoch_rewards->magic = 0UL;

  return epoch_rewards_shmem;
}

static inline fd_epoch_stake_reward_dlist_t *
fd_epoch_rewards_get_partition_index( fd_epoch_rewards_t const * epoch_rewards, ulong idx ) {
  if( FD_UNLIKELY( idx>=epoch_rewards->num_partitions ) ) {
    FD_LOG_WARNING(( "idx: %lu is greater than num_partitions: %lu", idx, epoch_rewards->num_partitions ));
    return NULL;
  }

  fd_epoch_stake_reward_dlist_t * dlist_idx_zero  = (fd_epoch_stake_reward_dlist_t *)((uchar *)epoch_rewards + epoch_rewards->dlists_offset);
  fd_epoch_stake_reward_dlist_t * partition_dlist = fd_epoch_stake_reward_dlist_join( dlist_idx_zero + idx );
  return partition_dlist;
}

static inline fd_epoch_stake_reward_t *
fd_epoch_rewards_get_stake_reward_pool( fd_epoch_rewards_t const * epoch_rewards ) {
  return fd_epoch_stake_reward_pool_join( (uchar *)epoch_rewards + epoch_rewards->pool_offset );
}

static inline fd_epoch_stake_reward_map_t *
fd_epoch_rewards_get_stake_reward_map( fd_epoch_rewards_t const * epoch_rewards ) {
  return fd_epoch_stake_reward_map_join( (uchar *)epoch_rewards + epoch_rewards->map_offset );
}

void
fd_epoch_rewards_insert( fd_epoch_rewards_t * epoch_rewards,
                         fd_pubkey_t const *  pubkey,
                         ulong                credits,
                         ulong                lamports ) {
  fd_epoch_stake_reward_t *     stake_reward_pool = fd_epoch_rewards_get_stake_reward_pool( epoch_rewards );
  fd_epoch_stake_reward_map_t * stake_reward_map  = fd_epoch_rewards_get_stake_reward_map( epoch_rewards );

  if( FD_UNLIKELY( fd_epoch_stake_reward_map_ele_query( stake_reward_map, pubkey, NULL, stake_reward_pool ) ) ) {
    FD_LOG_CRIT(( "invariant violation: stake reward entry already exists" ));
  }

  fd_epoch_stake_reward_t * stake_reward = fd_epoch_stake_reward_pool_ele_acquire( stake_reward_pool );

  stake_reward->stake_pubkey     = *pubkey;
  stake_reward->credits_observed = credits;
  stake_reward->lamports         = lamports;

  fd_epoch_stake_reward_map_ele_insert( stake_reward_map, stake_reward, stake_reward_pool );

  epoch_rewards->total_stake_rewards += lamports;
  epoch_rewards->stake_rewards_cnt++;

}

void
fd_epoch_rewards_hash_into_partitions( fd_epoch_rewards_t * epoch_rewards,
                                       fd_hash_t const *    parent_blockhash,
                                       ulong                num_partitions ) {

  fd_epoch_stake_reward_t *     stake_reward_pool = fd_epoch_rewards_get_stake_reward_pool( epoch_rewards );
  fd_epoch_stake_reward_map_t * stake_reward_map  = fd_epoch_rewards_get_stake_reward_map( epoch_rewards );

  epoch_rewards->num_partitions = num_partitions;

  for( fd_epoch_stake_reward_map_iter_t iter = fd_epoch_stake_reward_map_iter_init( stake_reward_map, stake_reward_pool );
       !fd_epoch_stake_reward_map_iter_done( iter, stake_reward_map, stake_reward_pool );
       iter = fd_epoch_stake_reward_map_iter_next( iter, stake_reward_map, stake_reward_pool ) ) {

    fd_epoch_stake_reward_t * stake_reward = fd_epoch_stake_reward_map_iter_ele( iter, stake_reward_map, stake_reward_pool );

    fd_siphash13_t   sip[1] = {0};
    fd_siphash13_t * hasher = fd_siphash13_init( sip, 0UL, 0UL );
    hasher = fd_siphash13_append( hasher, parent_blockhash->hash, sizeof(fd_hash_t) );
    fd_siphash13_append( hasher, (uchar const *)stake_reward->stake_pubkey.uc, sizeof(fd_pubkey_t) );
    ulong hash64 = fd_siphash13_fini( hasher );

    /* Now get the correct dlist based on the hash. */
    ulong partition_index = (ulong)((uint128)num_partitions * (uint128) hash64 / ((uint128)ULONG_MAX + 1));

    fd_epoch_stake_reward_dlist_t * partition_dlist = fd_epoch_rewards_get_partition_index( epoch_rewards, partition_index );

    fd_epoch_stake_reward_dlist_ele_push_tail( partition_dlist, stake_reward, stake_reward_pool );
  }
}

fd_epoch_stake_reward_t *
fd_epoch_rewards_iter_ele( fd_epoch_rewards_iter_t * iter ) {
  return fd_epoch_stake_reward_dlist_iter_ele( iter->iter, iter->dlist, iter->pool );
}

fd_epoch_rewards_iter_t *
fd_epoch_rewards_iter_init( fd_epoch_rewards_iter_t *  iter,
                            fd_epoch_rewards_t const * epoch_rewards,
                            ulong                      partition_idx ) {
  iter->pool  = fd_epoch_rewards_get_stake_reward_pool( epoch_rewards );
  iter->dlist = fd_epoch_rewards_get_partition_index( epoch_rewards, partition_idx );
  iter->iter  = fd_epoch_stake_reward_dlist_iter_fwd_init( iter->dlist, iter->pool );
  return iter;
}

int
fd_epoch_rewards_iter_done( fd_epoch_rewards_iter_t * iter ) {
  return fd_epoch_stake_reward_dlist_iter_done( iter->iter, iter->dlist, iter->pool );
}

void
fd_epoch_rewards_iter_next( fd_epoch_rewards_iter_t * iter ) {
  iter->iter = fd_epoch_stake_reward_dlist_iter_fwd_next( iter->iter, iter->dlist, iter->pool );
}
