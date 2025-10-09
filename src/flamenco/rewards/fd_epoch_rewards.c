#include "fd_epoch_rewards.h"
#include "../../ballet/siphash13/fd_siphash13.h"

ulong
fd_epoch_rewards_align( void ) {
  return FD_EPOCH_REWARDS_ALIGN;
}

ulong
fd_epoch_rewards_footprint( ulong stake_account_max ) {
  ulong l = FD_LAYOUT_INIT;
  ulong map_chain_cnt = fd_epoch_stake_reward_map_chain_cnt_est( stake_account_max );
  l = FD_LAYOUT_APPEND( l, fd_epoch_rewards_align(),            sizeof(fd_epoch_rewards_t) );
  l = FD_LAYOUT_APPEND( l, fd_epoch_stake_reward_pool_align(),  fd_epoch_stake_reward_pool_footprint( stake_account_max ) );
  l = FD_LAYOUT_APPEND( l, fd_epoch_stake_reward_dlist_align(), fd_epoch_stake_reward_dlist_footprint() * FD_REWARDS_MAX_PARTITIONS );
  l = FD_LAYOUT_APPEND( l, fd_epoch_stake_reward_map_align(),   fd_epoch_stake_reward_map_footprint( map_chain_cnt ) );
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

  void * pool = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_pool_align(), fd_epoch_stake_reward_pool_footprint( stake_account_max ) );
  if( FD_UNLIKELY( !fd_epoch_stake_reward_pool_new( pool, stake_account_max ) ) ) {
    FD_LOG_WARNING(( "bad pool" ));
    return NULL;
  }

  for( ulong i=0UL; i<FD_REWARDS_MAX_PARTITIONS; i++ ) {
    void * dlist = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_dlist_align(), fd_epoch_stake_reward_dlist_footprint() );
    if( FD_UNLIKELY( !fd_epoch_stake_reward_dlist_new( dlist ) ) ) {
      FD_LOG_WARNING(( "bad dlist at idx %lu", i ));
      return NULL;
    }
  }

  ulong map_chain_cnt = fd_epoch_stake_reward_map_chain_cnt_est( stake_account_max );
  void * map = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_map_align(), fd_epoch_stake_reward_map_footprint( map_chain_cnt ) );
  if( FD_UNLIKELY( !fd_epoch_stake_reward_map_new( map, map_chain_cnt, 0UL ) ) ) {
    FD_LOG_WARNING(( "bad map" ));
    return NULL;
  }

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_epoch_rewards_align() ) != (ulong)shmem+fd_epoch_rewards_footprint( stake_account_max ) ) ) {
    FD_LOG_WARNING(( "bad footprint" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( epoch_rewards->magic ) = FD_EPOCH_REWARDS_MAGIC;
  FD_COMPILER_MFENCE();

  epoch_rewards->stake_account_max_ = stake_account_max;
  epoch_rewards->map_offset_        = (ulong)map - (ulong)shmem;

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
  ulong stake_account_max = epoch_rewards->stake_account_max_;

  void * pool = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_pool_align(), fd_epoch_stake_reward_pool_footprint( stake_account_max ) );
  if( FD_UNLIKELY( !fd_epoch_stake_reward_pool_join( pool ) ) ) {
    FD_LOG_WARNING(( "bad pool" ));
    return NULL;
  }

  for( ulong i=0UL; i<FD_REWARDS_MAX_PARTITIONS; i++ ) {
    void * dlist = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_dlist_align(), fd_epoch_stake_reward_dlist_footprint() );
    if( FD_UNLIKELY( !fd_epoch_stake_reward_dlist_join( dlist ) ) ) {
      FD_LOG_WARNING(( "bad dlist at idx %lu", i ));
      return NULL;
    }
  }

  ulong map_chain_cnt = fd_epoch_stake_reward_map_chain_cnt_est( stake_account_max );
  void * map = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_map_align(), fd_epoch_stake_reward_map_footprint( map_chain_cnt ) );
  if( FD_UNLIKELY( !fd_epoch_stake_reward_map_join( map ) ) ) {
    FD_LOG_WARNING(( "bad map" ));
    return NULL;
  }

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_epoch_rewards_align() ) != (ulong)shmem+fd_epoch_rewards_footprint( stake_account_max ) ) ) {
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

fd_epoch_stake_reward_dlist_t *
fd_epoch_rewards_get_partition_index( fd_epoch_rewards_t const * epoch_rewards, ulong idx ) {
  // if( FD_UNLIKELY( idx >= epoch_rewards->num_partitions_ ) ) {
  //   FD_LOG_WARNING(( "idx: %lu is greater than num_partitions: %lu", idx, epoch_rewards->num_partitions_ ));
  //   return NULL;
  // }

  FD_SCRATCH_ALLOC_INIT( l, epoch_rewards );
  FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_rewards_align(), sizeof(fd_epoch_rewards_t) );
  FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_pool_align(), fd_epoch_stake_reward_pool_footprint( epoch_rewards->stake_account_max_ ) );
  for( ulong i=0UL; i<idx; i++ ) {
    FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_dlist_align(), fd_epoch_stake_reward_dlist_footprint() );
  }
  void * dlist = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_dlist_align(), fd_epoch_stake_reward_dlist_footprint() );

  fd_epoch_stake_reward_dlist_t * partition_dlist = fd_epoch_stake_reward_dlist_join( dlist );
  if( FD_UNLIKELY( !partition_dlist ) ) {
    FD_LOG_WARNING(( "bad dlist" ));
    return NULL;
  }
  return partition_dlist;
}

fd_epoch_stake_reward_t *
fd_epoch_rewards_get_stake_reward_pool( fd_epoch_rewards_t const * epoch_rewards ) {
  if( FD_UNLIKELY( !epoch_rewards ) ) {
    FD_LOG_WARNING(( "NULL epoch_rewards" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, epoch_rewards );
  FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_rewards_align(), sizeof(fd_epoch_rewards_t) );
  void * pool = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_stake_reward_pool_align(), fd_epoch_stake_reward_pool_footprint( epoch_rewards->stake_account_max_ ) );
  fd_epoch_stake_reward_t * stake_reward_pool = fd_epoch_stake_reward_pool_join( pool );
  if( FD_UNLIKELY( !stake_reward_pool ) ) {
    FD_LOG_WARNING(( "bad stake_reward_pool" ));
    return NULL;
  }
  return stake_reward_pool;
}

fd_epoch_stake_reward_map_t *
fd_epoch_rewards_get_stake_reward_map( fd_epoch_rewards_t const * epoch_rewards ) {
  return (fd_epoch_stake_reward_map_t *)( (ulong)epoch_rewards + epoch_rewards->map_offset_ );
}

void
fd_epoch_rewards_insert( fd_epoch_rewards_t * epoch_rewards,
                         fd_pubkey_t const *  pubkey,
                         ulong                credits,
                         ulong                lamports ) {
  /* Acquire a stake reward from the pool's free list and add it to
     the tail of the dlist. */
  fd_epoch_stake_reward_t * stake_reward_pool = fd_epoch_rewards_get_stake_reward_pool( epoch_rewards );
  if( FD_UNLIKELY( !stake_reward_pool ) ) {
    FD_LOG_CRIT(( "stake_reward_pool is not valid" ));
  }

  if( FD_UNLIKELY( !fd_epoch_stake_reward_pool_free( stake_reward_pool ) ) ) {
    FD_LOG_CRIT(( "stake_reward_pool is full" ));
  }

  fd_epoch_stake_reward_t * stake_reward = fd_epoch_stake_reward_pool_ele_acquire( stake_reward_pool );
  if( FD_UNLIKELY( !stake_reward ) ) {
    FD_LOG_CRIT(( "stake_reward is not valid" ));
  }

  stake_reward->stake_pubkey     = *pubkey;
  stake_reward->credits_observed = credits;
  stake_reward->lamports         = lamports;

  fd_epoch_stake_reward_map_t * map = fd_epoch_rewards_get_stake_reward_map( epoch_rewards );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_CRIT(( "map is not valid" ));
  }

  fd_epoch_stake_reward_map_ele_insert( map, stake_reward, stake_reward_pool );
}

void
fd_epoch_rewards_hash_all( fd_epoch_rewards_t * epoch_rewards,
                           fd_hash_t const *    parent_blockhash,
                           ulong                num_partitions ) {

  fd_epoch_stake_reward_t *     stake_reward_pool = fd_epoch_rewards_get_stake_reward_pool( epoch_rewards );
  fd_epoch_stake_reward_map_t * stake_reward_map  = fd_epoch_rewards_get_stake_reward_map( epoch_rewards );

  for( fd_epoch_stake_reward_map_iter_t iter = fd_epoch_stake_reward_map_iter_init( stake_reward_map, stake_reward_pool );
       !fd_epoch_stake_reward_map_iter_done( iter, stake_reward_map, stake_reward_pool );
       iter = fd_epoch_stake_reward_map_iter_next( iter, stake_reward_map, stake_reward_pool ) ) {
    fd_epoch_stake_reward_t * stake_reward = fd_epoch_stake_reward_map_iter_ele( iter, stake_reward_map, stake_reward_pool );

    fd_siphash13_t   sip[1] = {0};
    fd_siphash13_t * hasher = fd_siphash13_init( sip, 0UL, 0UL );
    hasher = fd_siphash13_append( hasher, parent_blockhash->hash, sizeof(fd_hash_t) );
    fd_siphash13_append( hasher, (uchar const *)&stake_reward->stake_pubkey, sizeof(fd_pubkey_t) );
    ulong hash64 = fd_siphash13_fini( hasher );

    /* Now get the correct dlist based on the hash. */
    ulong partition_index = (ulong)((uint128)num_partitions * (uint128) hash64 / ((uint128)ULONG_MAX + 1));

    fd_epoch_stake_reward_dlist_t * partition_dlist = fd_epoch_rewards_get_partition_index( epoch_rewards, partition_index );
    if( FD_UNLIKELY( !partition_dlist ) ) {
      FD_LOG_CRIT(( "bad partition_dlist" ));
    }
    fd_epoch_stake_reward_dlist_ele_push_tail( partition_dlist, stake_reward, stake_reward_pool );
  }
}

int
fd_epoch_rewards_hash_and_insert( fd_epoch_rewards_t * epoch_rewards,
                                  fd_hash_t const *    parent_blockhash,
                                  fd_pubkey_t const *  pubkey,
                                  ulong                credits,
                                  ulong                lamports ) {

  if( FD_UNLIKELY( !epoch_rewards ) ) {
    FD_LOG_WARNING(( "NULL epoch_rewards" ));
    return 1;
  }

  if( FD_UNLIKELY( !parent_blockhash ) ) {
    FD_LOG_WARNING(( "NULL parent_blockhash" ));
    return 1;
  }

  if( FD_UNLIKELY( !pubkey ) ) {
    FD_LOG_WARNING(( "NULL pubkey" ));
    return 1;
  }

  /* First figure out which partition the pubkey belongs to. */
  fd_siphash13_t   sip[1] = {0};
  fd_siphash13_t * hasher = fd_siphash13_init( sip, 0UL, 0UL );
  hasher = fd_siphash13_append( hasher, parent_blockhash->hash, sizeof(fd_hash_t) );
  fd_siphash13_append( hasher, (uchar const *)pubkey, sizeof(fd_pubkey_t) );
  ulong hash64 = fd_siphash13_fini( hasher );

  /* Now get the correct dlist based on the hash. */
  ulong partition_index = (ulong)((uint128)epoch_rewards->num_partitions_ * (uint128) hash64 / ((uint128)ULONG_MAX + 1));

  fd_epoch_stake_reward_dlist_t * partition_dlist = fd_epoch_rewards_get_partition_index( epoch_rewards, partition_index );
  if( FD_UNLIKELY( !partition_dlist ) ) {
    FD_LOG_WARNING(( "bad partition_dlist" ));
    return 1;
  }

  /* Acquire a stake reward from the pool's free list and add it to
     the tail of the dlist. */
  fd_epoch_stake_reward_t * stake_reward_pool = fd_epoch_rewards_get_stake_reward_pool( epoch_rewards );
  if( FD_UNLIKELY( !stake_reward_pool ) ) {
    FD_LOG_WARNING(( "bad stake_reward_pool" ));
    return 1;
  }

  if( FD_UNLIKELY( !fd_epoch_stake_reward_pool_free( stake_reward_pool ) ) ) {
    FD_LOG_WARNING(( "stake_reward_pool is full" ));
    return 1;
  }

  fd_epoch_stake_reward_t * stake_reward = fd_epoch_stake_reward_pool_ele_acquire( stake_reward_pool );
  if( FD_UNLIKELY( !stake_reward ) ) {
    FD_LOG_WARNING(( "bad stake_reward" ));
    return 1;
  }

  stake_reward->stake_pubkey     = *pubkey;
  stake_reward->credits_observed = credits;
  stake_reward->lamports         = lamports;

  fd_epoch_stake_reward_dlist_ele_push_tail( partition_dlist, stake_reward, stake_reward_pool );
  return 0;
}

