#include "fd_stake_rewards.h"
#include "fd_rewards_base.h"
#include "../../ballet/siphash13/fd_siphash13.h"

#define FD_STAKE_REWARDS_MAGIC (0xF17EDA2CE757A4E0) /* FIREDANCER STAKE V0 */

struct fork {
  int next;
};
typedef struct fork fork_t;

#define POOL_NAME  fork_pool
#define POOL_T     fork_t
#define POOL_NEXT  next
#define POOL_IDX_T int
#include "../../util/tmpl/fd_pool.c"

struct partition_ele {
  fd_pubkey_t pubkey;
  ulong       lamports;
  ulong       credits_observed;
  uint        next;
};
typedef struct partition_ele partition_ele_t;

struct fork_info {
  uint  ele_cnt;
  uint  partition_cnt;
  uint  win_lo;
  uint  win_hi;
  uint  win_sz;
  uint  partition_idxs_head[MAX_PARTITIONS_PER_EPOCH];
  uint  partition_idxs_tail[MAX_PARTITIONS_PER_EPOCH];
  ulong starting_block_height;
  ulong total_stake_rewards;
  ulong refcnt;
};
typedef struct fork_info fork_info_t;

struct fd_stake_rewards {
  ulong       magic;
  ulong       max_stake_accounts; /* entries a fork's storage can hold */
  fork_info_t fork_info[ FD_STAKE_REWARDS_MAX_FORK_WIDTH ];
  ulong       fork_pool_offset;
  ulong       partitions_offset;
  ulong       epoch;

  /* Temporary storage for the current stake reward being computed. */
  fd_siphash13_t primed_hasher[ 1 ];
  uint           iter_curr_fork_idx;
};
typedef struct fd_stake_rewards fd_stake_rewards_t;

static inline fork_t *
get_fork_pool( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->fork_pool_offset );
}

static inline partition_ele_t *
get_partition_ele( fd_stake_rewards_t const * stake_rewards,
                   uchar                      fork_idx,
                   uint                       ele_cnt ) {

  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->partitions_offset +
                      (fork_idx * stake_rewards->max_stake_accounts * sizeof(partition_ele_t)) +
                      (ele_cnt * sizeof(partition_ele_t)) );
}

static uint
window_sz( ulong capacity,
           uint  partitions_cnt,
           ulong max_rewards_cnt ) {

  /* Percentage of the window capacity left unused when the epoch's
     rewards do not all fit.  Rewards are scattered uniformly over the
     partitions, so the entry count of a window of W partitions has a
     mean of at most W*max_rewards_cnt/partitions_cnt and a sd of the
     square root of that mean.  Reserving a hundredth of the capacity
     puts the overflow threshold at sqrt(capacity)/100 deviations above
     the mean, which is over thirteen deviations at the production
     capacity of 2150000 stake accounts. */
  if( FD_LIKELY( max_rewards_cnt<=capacity ) ) return partitions_cnt;

  ulong usable = fd_ulong_max( fd_ulong_sat_sub( capacity, fd_ulong_max( capacity*1UL/100UL, 1UL ) ), 1UL );
  ulong sz     = fd_ulong_max( usable*(ulong)partitions_cnt/max_rewards_cnt, 1UL );
  return (uint)fd_ulong_min( sz, (ulong)partitions_cnt );
}

static void
window_reset( fd_stake_rewards_t * stake_rewards,
              uchar                fork_idx,
              uint                 win_lo ) {
  /* reset the window to start at win_lo and drop whatever the window
     used to hold.  The win_hi will either be the end of rewards or the
     end of the partition window, whichever is smaller. */

  fork_info_t * fork_info = &stake_rewards->fork_info[fork_idx];

  uint win_end                   = fd_uint_min( win_lo+fork_info->win_sz, fork_info->partition_cnt );
  fork_info->win_lo              = win_lo;
  fork_info->win_hi              = fd_uint_max( fd_uint_sat_sub( win_end, 1UL ), win_lo );
  fork_info->ele_cnt             = 0U;
  fork_info->total_stake_rewards = 0UL;
  memset( fork_info->partition_idxs_head, 0xFF, sizeof(fork_info->partition_idxs_head) );
  memset( fork_info->partition_idxs_tail, 0xFF, sizeof(fork_info->partition_idxs_tail) );
}

static void
prime_hasher( fd_stake_rewards_t * stake_rewards,
              fd_hash_t const *    parent_blockhash ) {
  fd_siphash13_init( stake_rewards->primed_hasher, 0UL, 0UL );
  fd_siphash13_append( stake_rewards->primed_hasher, parent_blockhash->hash, sizeof(fd_hash_t) );
}

ulong
fd_stake_rewards_align( void ) {
  return FD_STAKE_REWARDS_ALIGN;
}

ulong
fd_stake_rewards_footprint( ulong max_stake_accounts,
                            ulong max_fork_width ) {
  if( FD_UNLIKELY( max_stake_accounts>=(ulong)UINT_MAX ) ) return 0UL;
  if( FD_UNLIKELY( max_fork_width>FD_STAKE_REWARDS_MAX_FORK_WIDTH ) ) return 0UL;

  ulong partition_ele_cnt = fd_ulong_sat_mul( max_fork_width, max_stake_accounts );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_rewards_align(), sizeof(fd_stake_rewards_t) );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, alignof(partition_ele_t), fd_ulong_sat_mul( partition_ele_cnt, sizeof(partition_ele_t) ) );
  return FD_LAYOUT_FINI( l, fd_stake_rewards_align() );
}

void *
fd_stake_rewards_new( void * shmem,
                      ulong  max_stake_accounts,
                      ulong  max_fork_width ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_stake_rewards_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  /* Entries are addressed by uint indices within a fork's storage. */
  if( FD_UNLIKELY( max_stake_accounts>=(ulong)UINT_MAX ) ) {
    FD_LOG_WARNING(( "max_stake_accounts is too large" ));
    return NULL;
  }
  if( FD_UNLIKELY( max_fork_width>FD_STAKE_REWARDS_MAX_FORK_WIDTH ) ) {
    FD_LOG_WARNING(( "max_fork_width %lu exceeds maximum %lu",
                     max_fork_width, FD_STAKE_REWARDS_MAX_FORK_WIDTH ));
    return NULL;
  }
  ulong partition_ele_cnt = fd_ulong_sat_mul( max_fork_width, max_stake_accounts );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_stake_rewards_t * stake_rewards   = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_rewards_align(), sizeof(fd_stake_rewards_t) );
  void *               fork_pool_mem   = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_fork_width ) );
  void *               partitions_mem  = FD_SCRATCH_ALLOC_APPEND( l, alignof(partition_ele_t), fd_ulong_sat_mul( partition_ele_cnt, sizeof(partition_ele_t) ) );

  fork_t * fork_pool = fork_pool_join( fork_pool_new( fork_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create fork pool" ));
    return NULL;
  }
  stake_rewards->fork_pool_offset   = (ulong)fork_pool - (ulong)shmem;
  stake_rewards->partitions_offset  = (ulong)partitions_mem - (ulong)shmem;
  stake_rewards->max_stake_accounts = max_stake_accounts;
  stake_rewards->epoch              = ULONG_MAX;

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
  fork_pool_reset( get_fork_pool( stake_rewards ) );
  for( ulong i=0UL; i<FD_STAKE_REWARDS_MAX_FORK_WIDTH; i++ ) stake_rewards->fork_info[i].refcnt = 0UL;
  stake_rewards->epoch = ULONG_MAX;
}

void
fd_stake_rewards_purge( fd_stake_rewards_t * stake_rewards,
                        uchar                fork_idx ) {
  fork_pool_idx_release( get_fork_pool( stake_rewards ), (ulong)fork_idx );
  stake_rewards->fork_info[fork_idx].partition_cnt         = 0U;
  stake_rewards->fork_info[fork_idx].starting_block_height = 0UL;
  stake_rewards->fork_info[fork_idx].win_sz                = 0U;
  stake_rewards->fork_info[fork_idx].refcnt                = 0UL;
  window_reset( stake_rewards, fork_idx, 0U );
}

void
fd_stake_rewards_acquire( fd_stake_rewards_t * stake_rewards,
                          uchar                fork_idx ) {
  stake_rewards->fork_info[fork_idx].refcnt++;
}

void
fd_stake_rewards_release( fd_stake_rewards_t * stake_rewards,
                          uchar                fork_idx ) {
  ulong refcnt = stake_rewards->fork_info[fork_idx].refcnt;
  if( FD_UNLIKELY( !refcnt ) ) return;
  if( FD_UNLIKELY( refcnt==1UL ) ) fd_stake_rewards_purge( stake_rewards, fork_idx );
  else                             stake_rewards->fork_info[fork_idx].refcnt = refcnt-1UL;
}

ulong
fd_stake_rewards_refcnt( fd_stake_rewards_t const * stake_rewards,
                         uchar                      fork_idx ) {
  return stake_rewards->fork_info[fork_idx].refcnt;
}

ulong
fd_stake_rewards_free_cnt( fd_stake_rewards_t const * stake_rewards ) {
  return (ulong)fork_pool_free( get_fork_pool( stake_rewards ) );
}

uchar
fd_stake_rewards_init( fd_stake_rewards_t * stake_rewards,
                       ulong                epoch,
                       fd_hash_t const *    parent_blockhash,
                       ulong                starting_block_height,
                       uint                 partitions_cnt,
                       ulong                max_rewards_cnt ) {
  fork_t * fork_pool = get_fork_pool( stake_rewards );

  /* Forks are not reclaimed wholesale when the epoch changes.  Every fork
     is returned by the banks referencing it, so a new epoch has nothing
     left over to clean up. */
  stake_rewards->epoch = epoch;

  if( FD_UNLIKELY( !fork_pool_free( fork_pool ) ) ) {
    FD_LOG_ERR(( "No free forks in the stake rewards pool.  This likely occurred due to extremely degenerate "
                 "network conditions. Please report this crash to the Firedancer team." ));
  }
  uchar fork_idx = (uchar)fork_pool_idx_acquire( fork_pool );
  stake_rewards->fork_info[fork_idx].refcnt = 1UL;

  prime_hasher( stake_rewards, parent_blockhash );

  stake_rewards->fork_info[fork_idx].partition_cnt         = partitions_cnt;
  stake_rewards->fork_info[fork_idx].starting_block_height = starting_block_height;
  stake_rewards->fork_info[fork_idx].win_sz                = window_sz( stake_rewards->max_stake_accounts, partitions_cnt, max_rewards_cnt );
  window_reset( stake_rewards, fork_idx, 0U );

  return fork_idx;
}

void
fd_stake_rewards_window_advance( fd_stake_rewards_t * stake_rewards,
                                 uchar                fork_idx,
                                 fd_hash_t const *    parent_blockhash,
                                 uint                 win_lo ) {
  prime_hasher( stake_rewards, parent_blockhash );
  window_reset( stake_rewards, fork_idx, win_lo );
}

uint
fd_stake_rewards_window_lo( fd_stake_rewards_t const * stake_rewards,
                            uchar                      fork_idx ) {
  return stake_rewards->fork_info[fork_idx].win_lo;
}

uint
fd_stake_rewards_window_hi( fd_stake_rewards_t const * stake_rewards,
                            uchar                      fork_idx ) {
  return stake_rewards->fork_info[fork_idx].win_hi;
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

  fork_info_t * fork_info       = &stake_rewards->fork_info[fork_idx];
  ulong         partition_index = (ulong)((uint128)fork_info->partition_cnt * (uint128) hash64 / ((uint128)ULONG_MAX + 1));

  /* The total covers the whole epoch, not just the window, so that it
     does not depend on where the window happens to sit. */
  fork_info->total_stake_rewards += lamports;

  if( FD_UNLIKELY( partition_index<fork_info->win_lo || partition_index>fork_info->win_hi ) ) return;

  uint curr_fork_len = fork_info->ele_cnt;
  if( FD_UNLIKELY( curr_fork_len>=stake_rewards->max_stake_accounts ) ) {
    FD_LOG_CRIT(( "invariant violation: curr_fork_len>=stake_rewards->max_stake_accounts" ));
  }

  partition_ele_t * partition_ele = get_partition_ele( stake_rewards, fork_idx, curr_fork_len );
  partition_ele->pubkey           = *pubkey;
  partition_ele->lamports         = lamports;
  partition_ele->credits_observed = credits_observed;
  partition_ele->next             = UINT_MAX;

  int is_first_ele = fork_info->partition_idxs_head[partition_index] == UINT_MAX;

  if( FD_LIKELY( !is_first_ele ) ) {
    partition_ele_t * prev_partition_ele = get_partition_ele( stake_rewards, fork_idx, fork_info->partition_idxs_tail[partition_index] );
    prev_partition_ele->next = curr_fork_len;
    fork_info->partition_idxs_tail[partition_index] = curr_fork_len;
  } else {
    fork_info->partition_idxs_head[partition_index] = curr_fork_len;
    fork_info->partition_idxs_tail[partition_index] = curr_fork_len;
  }

  fork_info->ele_cnt++;
}

void
fd_stake_rewards_iter_init( fd_stake_rewards_t * stake_rewards,
                            uchar                fork_idx,
                            uint                 partition_idx ) {
  fork_info_t const * fork_info = &stake_rewards->fork_info[fork_idx];
  if( FD_UNLIKELY( partition_idx<fork_info->win_lo || partition_idx>fork_info->win_hi ) ) {
    FD_LOG_CRIT(( "partition %u is outside of the valid window [%u,%u]", partition_idx, fork_info->win_lo, fork_info->win_hi ));
  }
  stake_rewards->iter_curr_fork_idx = fork_info->partition_idxs_head[partition_idx];
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

  *pubkey_out           = partition_ele->pubkey;
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
