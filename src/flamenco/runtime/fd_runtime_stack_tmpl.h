#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_stack_tmpl_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_stack_tmpl_h

/* The fd_runtime_stack_t container instantiations and constructors.
   fd_runtime_stack.h only declares the map types; include this header
   to use the maps or to size/create a runtime stack. */

#include "fd_runtime_stack.h"
#include "../../util/fd_hash32.h"

#define MAP_NAME               fd_vote_rewards_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_vote_rewards_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash32( (key)->uc, (seed) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               fd_stake_accum_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_accum_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash32( (key)->uc, (seed) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

FD_FN_CONST static inline ulong
fd_runtime_stack_align( void ) {
  return 128UL;
}

/* stake_accum and bpf_migration share a region, see fd_runtime_stack_t */

FD_FN_CONST static inline ulong
fd_runtime_stack_private_stake_accum_align( void ) {
  return fd_ulong_max( 128UL, alignof(fd_runtime_stack_bpf_migration_t) );
}

FD_FN_CONST static inline ulong
fd_runtime_stack_private_stake_accum_footprint( ulong max_staked_vote_accounts ) {
  return fd_ulong_max( sizeof(fd_stake_accum_t) * max_staked_vote_accounts, sizeof(fd_runtime_stack_bpf_migration_t) );
}

FD_FN_PURE static inline ulong
fd_runtime_stack_footprint( ulong max_vote_accounts,
                            ulong max_staked_vote_accounts,
                            ulong max_stake_accounts ) {
  ulong vote_chain_cnt  = fd_vote_rewards_map_chain_cnt_est( max_vote_accounts );
  ulong stake_chain_cnt = fd_stake_accum_map_chain_cnt_est( max_staked_vote_accounts );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_runtime_stack_t),                     sizeof(fd_runtime_stack_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_vote_stake_weight_t),                 sizeof(fd_vote_stake_weight_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, alignof(fd_stake_weight_t),                      sizeof(fd_stake_weight_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, 128UL,                                           sizeof(fd_vote_rewards_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, fd_vote_rewards_map_align(),                     fd_vote_rewards_map_footprint( vote_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_runtime_stack_private_stake_accum_align(),    fd_runtime_stack_private_stake_accum_footprint( max_staked_vote_accounts ) );
  l = FD_LAYOUT_APPEND( l, fd_stake_accum_map_align(),                      fd_stake_accum_map_footprint( stake_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_calculated_stake_result_t),           sizeof(fd_calculated_stake_result_t) * max_stake_accounts );
  return FD_LAYOUT_FINI( l, fd_runtime_stack_align() );
}

/* fd_runtime_stack_new: max_staked_vote_accounts sizes the RAM stake
   accumulator and max_stake_accounts the points/rewards cache window.  Distinct
   voters beyond the RAM accumulator spill to stake_accum_fd (up to
   stake_accum_spill_max; fd -1 disables spilling). */

static inline void *
fd_runtime_stack_new( void * shmem,
                      ulong  max_vote_accounts,
                      ulong  max_staked_vote_accounts,
                      ulong  max_stake_accounts,
                      int    stake_accum_fd,
                      ulong  stake_accum_spill_max,
                      ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) return NULL;
  if( FD_UNLIKELY( stake_accum_spill_max>=(ulong)UINT_MAX ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: bad stake accum sizing" ));
    return NULL;
  }
  ulong vote_chain_cnt  = fd_vote_rewards_map_chain_cnt_est( max_vote_accounts );
  ulong stake_chain_cnt = fd_stake_accum_map_chain_cnt_est( max_staked_vote_accounts );
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_runtime_stack_t *            runtime_stack        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_runtime_stack_t),            sizeof(fd_runtime_stack_t) );
  fd_vote_stake_weight_t *        stake_weights        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vote_stake_weight_t),        sizeof(fd_vote_stake_weight_t) * max_vote_accounts );
  fd_stake_weight_t *             id_weights           = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stake_weight_t),             sizeof(fd_stake_weight_t) * max_vote_accounts );
  fd_vote_rewards_t *             vote_ele             = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  sizeof(fd_vote_rewards_t) * max_vote_accounts );
  void *                          vote_map_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_rewards_map_align(),            fd_vote_rewards_map_footprint( vote_chain_cnt ) );
  fd_stake_accum_t *              stake_accum          = FD_SCRATCH_ALLOC_APPEND( l, fd_runtime_stack_private_stake_accum_align(), fd_runtime_stack_private_stake_accum_footprint( max_staked_vote_accounts ) );
  void *                          stake_accum_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_accum_map_align(),             fd_stake_accum_map_footprint( stake_chain_cnt ) );
  fd_calculated_stake_result_t *  stake_results        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_calculated_stake_result_t),  sizeof(fd_calculated_stake_result_t) * max_stake_accounts );
  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_runtime_stack_align() )!=(ulong)shmem + fd_runtime_stack_footprint( max_vote_accounts, max_staked_vote_accounts, max_stake_accounts ) ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: bad layout" ));
    return NULL;
  }

  runtime_stack->max_vote_accounts           = max_vote_accounts;
  runtime_stack->max_staked_vote_accounts    = max_staked_vote_accounts;
  runtime_stack->max_stake_accounts          = max_stake_accounts;
  runtime_stack->stakes.stake_weights        = stake_weights;
  runtime_stack->stakes.id_weights           = id_weights;
  runtime_stack->stakes.vote_ele             = vote_ele;
  runtime_stack->stakes.stake_results        = stake_results;
  runtime_stack->stakes.stake_accum          = stake_accum;
  runtime_stack->bpf_migration               = (fd_runtime_stack_bpf_migration_t *)stake_accum;
  runtime_stack->stakes.stake_accum_cnt      = 0UL;

  runtime_stack->stakes.stake_accum_fd               = stake_accum_fd;
  runtime_stack->stakes.stake_accum_spill_gen        = 1U;
  runtime_stack->stakes.stake_accum_spill_max        = stake_accum_fd>=0 ? stake_accum_spill_max : 0UL;
  runtime_stack->stakes.stake_accum_spill_cnt        = 0UL;
  runtime_stack->stakes.stake_accum_spill_bucket_cnt = fd_ulong_pow2_up( stake_accum_spill_max + (stake_accum_spill_max>>1) + 1UL );

  runtime_stack->stakes.stake_accum_map = fd_stake_accum_map_join( fd_stake_accum_map_new( stake_accum_map_mem, stake_chain_cnt, seed ) );
  if( FD_UNLIKELY( !runtime_stack->stakes.stake_accum_map ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: bad map" ));
    return NULL;
  }

  runtime_stack->stakes.vote_map = fd_vote_rewards_map_join( fd_vote_rewards_map_new( vote_map_mem, vote_chain_cnt, seed ) );
  if( FD_UNLIKELY( !runtime_stack->stakes.vote_map ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: bad map" ));
    return NULL;
  }

  return shmem;
}

FD_FN_CONST static inline fd_runtime_stack_t *
fd_runtime_stack_join( void * shruntime_stack ) {
  return (fd_runtime_stack_t *)shruntime_stack;
}

/* Stake accumulator: one entry per distinct delegated-to vote account.
   RAM map first; spill table only once the RAM pool is full, so no
   disk access while nothing has spilled. */

static inline void
fd_runtime_stack_stake_accum_reset( fd_runtime_stack_t * runtime_stack ) {
  fd_stake_accum_map_reset( runtime_stack->stakes.stake_accum_map );
  runtime_stack->stakes.stake_accum_cnt = 0UL;
  if( FD_UNLIKELY( runtime_stack->stakes.stake_accum_spill_cnt ) ) {
    runtime_stack->stakes.stake_accum_spill_cnt = 0UL;
    if( FD_UNLIKELY( !++runtime_stack->stakes.stake_accum_spill_gen ) ) FD_LOG_CRIT(( "stake accum spill generation wrapped" ));
  }
}

/* Returns key's entry (spilled entries are copied into scratch) or
   NULL. */

static inline fd_stake_accum_t const *
fd_runtime_stack_stake_accum_query( fd_runtime_stack_t * runtime_stack,
                                    fd_pubkey_t const *  key,
                                    fd_stake_accum_t *   scratch ) {
  fd_stake_accum_t const * ele = fd_stake_accum_map_ele_query_const( runtime_stack->stakes.stake_accum_map, key, NULL, runtime_stack->stakes.stake_accum );
  if( FD_LIKELY( ele || !runtime_stack->stakes.stake_accum_spill_cnt ) ) return ele;
  return fd_runtime_stack_stake_accum_spill_query( runtime_stack, key, scratch );
}

/* Adds stake/reward_stake to key's entry, creating it if absent. */

static inline void
fd_runtime_stack_stake_accum_add( fd_runtime_stack_t * runtime_stack,
                                  fd_pubkey_t const *  key,
                                  ulong                stake,
                                  ulong                reward_stake ) {
  fd_stake_accum_t *     pool = runtime_stack->stakes.stake_accum;
  fd_stake_accum_map_t * map  = runtime_stack->stakes.stake_accum_map;
  fd_stake_accum_t *     ele  = fd_stake_accum_map_ele_query( map, key, NULL, pool );
  if( FD_LIKELY( ele ) ) {
    ele->stake += stake;
    FD_TEST( !__builtin_uaddl_overflow( ele->reward_stake, reward_stake, &ele->reward_stake ) );
  } else if( FD_LIKELY( runtime_stack->stakes.stake_accum_cnt<runtime_stack->max_staked_vote_accounts ) ) {
    ele               = &pool[ runtime_stack->stakes.stake_accum_cnt++ ];
    ele->pubkey       = *key;
    ele->stake        = stake;
    ele->reward_stake = reward_stake;
    fd_stake_accum_map_ele_insert( map, ele, pool );
  } else {
    fd_runtime_stack_stake_accum_spill_add( runtime_stack, key, stake, reward_stake );
  }
}

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_stack_tmpl_h */
