#include "fd_stake_rewards.h"
#include "fd_rewards_base.h"
#include "../../ballet/siphash13/fd_siphash13.h"
#include "../runtime/fd_bank.h"

#define FD_STAKE_REWARDS_MAGIC (0xF17EDA2CE757A4E0) /* FIREDANCER STAKE V0 */

FD_STATIC_ASSERT( FD_BANKS_MAX_BANKS<USHORT_MAX, fork_idx_width );

struct fork {
  int next;
};
typedef struct fork fork_t;

#define POOL_NAME  fork_pool
#define POOL_T     fork_t
#define POOL_NEXT  next
#define POOL_IDX_T int
#include "../../util/tmpl/fd_pool.c"

struct __attribute__((packed, aligned(4UL))) partition_ele {
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
  uint  buf_idx; /* UINT_MAX for empty or evicted windows */
  uint  ready;   /* finalized and cached, including empty windows */
  ulong starting_block_height;
  ulong total_stake_rewards;
  ulong refcnt;
};
typedef struct fork_info fork_info_t;

struct fd_stake_rewards {
  ulong       magic;
  ulong       max_stake_accounts; /* entries each buffer can hold */
  ulong       fork_cnt;           /* max bank count plus replacement */
  ulong       fork_info_offset;
  ulong       fork_pool_offset;
  ulong       buf_fork_offset;
  ulong       buf_seq_offset;
  ulong       buf_partition_heads_offset;
  ulong       buf_offset;
  ulong       finish_seq;

  uint  cache_cnt;
  uint  staging_fork;

  uint staging_partition_idxs_tail[ MAX_PARTITIONS_PER_EPOCH ];

  /* Temporary storage for the current stake reward being computed. */
  fd_siphash13_t primed_hasher[ 1 ];

  uint iter_fork;
  uint iter_buf;
  uint iter_idx;
};
typedef struct fd_stake_rewards fd_stake_rewards_t;

static inline fork_t *
get_fork_pool( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->fork_pool_offset );
}

static inline fork_info_t *
get_fork_info( fd_stake_rewards_t const * stake_rewards,
               ushort                     fork_idx ) {
  fork_info_t * fork_info = fd_type_pun( (uchar *)stake_rewards + stake_rewards->fork_info_offset );
  return fork_info + fork_idx;
}

static inline uint
get_buf_cnt( fd_stake_rewards_t const * stake_rewards ) {
  return stake_rewards->cache_cnt+1U;
}

static inline uint *
get_buf_forks( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->buf_fork_offset );
}

static inline ulong *
get_buf_seqs( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->buf_seq_offset );
}

static inline uint *
get_buf_partition_heads( fd_stake_rewards_t const * stake_rewards,
                         uint                       buf_idx ) {
  uint * heads = fd_type_pun(
      (uchar *)stake_rewards + stake_rewards->buf_partition_heads_offset );
  return heads + (ulong)buf_idx*MAX_PARTITIONS_PER_EPOCH;
}

static inline partition_ele_t *
get_buf( fd_stake_rewards_t const * stake_rewards,
         uint                       buf_idx ) {
  partition_ele_t * buf = fd_type_pun(
      (uchar *)stake_rewards + stake_rewards->buf_offset );
  return buf + (ulong)buf_idx*stake_rewards->max_stake_accounts;
}

static uint
window_sz( ulong capacity,
           uint  partitions_cnt,
           ulong max_rewards_cnt ) {

  /* Percentage of the window capacity left unused when the rewards do
     not all fit.  Rewards are scattered uniformly over the partitions,
     so the entry count of a window of W partitions has a mean of at
     most W*max_rewards_cnt/partitions_cnt and a sd of the square root
     of that mean.  Reserving a hundredth of the capacity puts the
     overflow threshold at sqrt(capacity)/100 deviations above the mean,
     which is over thirteen deviations at the production capacity of
     2150000 stake accounts. */
  if( FD_LIKELY( max_rewards_cnt<=capacity ) ) return partitions_cnt;

  ulong usable = fd_ulong_max( fd_ulong_sat_sub( capacity, fd_ulong_max( capacity*1UL/100UL, 1UL ) ), 1UL );
  ulong sz     = fd_ulong_max( usable*(ulong)partitions_cnt/max_rewards_cnt, 1UL );
  return (uint)fd_ulong_min( sz, (ulong)partitions_cnt );
}

static void
fork_drop_buf( fd_stake_rewards_t * stake_rewards,
               ushort               fork_idx ) {
  fork_info_t * fork_info = get_fork_info( stake_rewards, fork_idx );
  if( fork_info->buf_idx==UINT_MAX ) return;

  uint    buf_idx   = fork_info->buf_idx;
  uint *  buf_forks = get_buf_forks( stake_rewards );
  ulong * buf_seqs  = get_buf_seqs( stake_rewards );
  FD_CHECK_CRIT( buf_idx<get_buf_cnt( stake_rewards ), "invalid reward buffer" );
  FD_CHECK_CRIT( buf_forks[buf_idx]==(uint)fork_idx,
                 "reward buffer owner mismatch" );
  buf_forks[buf_idx] = UINT_MAX;
  buf_seqs[buf_idx]  = 0UL;
  fork_info->buf_idx = UINT_MAX;
}

static uint
buf_acquire( fd_stake_rewards_t * stake_rewards,
             ushort               fork_idx ) {
  uint * buf_forks = get_buf_forks( stake_rewards );
  uint   buf_cnt   = get_buf_cnt( stake_rewards );
  for( uint buf_idx=0U; buf_idx<buf_cnt; buf_idx++ ) {
    if( FD_LIKELY( buf_forks[buf_idx]==UINT_MAX ) ) {
      buf_forks[buf_idx] = (uint)fork_idx;
      get_buf_seqs( stake_rewards )[buf_idx] = 0UL;
      return buf_idx;
    }
  }
  FD_LOG_CRIT(( "invariant violation: no free stake rewards construction buffer" ));
}

static void
window_init( fd_stake_rewards_t * stake_rewards,
             ushort               fork_idx,
             uint                 win_lo,
             ulong                max_rewards_cnt ) {
  /* The win_hi is either the end of rewards or the end of the
     partition window, whichever is smaller. */

  fork_info_t * fork_info = get_fork_info( stake_rewards, fork_idx );

  uint remaining_cnt             = fd_uint_sat_sub( fork_info->partition_cnt, win_lo );
  uint win_sz                    = window_sz( stake_rewards->max_stake_accounts, remaining_cnt, max_rewards_cnt );
  uint win_end                   = fd_uint_min( win_lo+win_sz, fork_info->partition_cnt );
  fork_info->win_lo              = win_lo;
  fork_info->win_hi              = fd_uint_max( fd_uint_sat_sub( win_end, 1UL ), win_lo );
  fork_info->ele_cnt             = 0U;
  fork_info->ready               = 0U;
  fork_info->total_stake_rewards = 0UL;
  memset( get_buf_partition_heads( stake_rewards, fork_info->buf_idx ), 0xFF,
          (ulong)fork_info->partition_cnt*sizeof(uint) );
  memset( stake_rewards->staging_partition_idxs_tail, 0xFF,
          (ulong)fork_info->partition_cnt*sizeof(uint) );
  stake_rewards->staging_fork = (uint)fork_idx;
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
                            ulong max_bank_cnt,
                            ulong cache_cnt ) {
  if( FD_UNLIKELY( max_stake_accounts>=(ulong)UINT_MAX ) ) return 0UL;
  if( FD_UNLIKELY( !max_bank_cnt || max_bank_cnt>FD_BANKS_MAX_BANKS ) ) return 0UL;
  if( FD_UNLIKELY( !cache_cnt || cache_cnt>max_bank_cnt+1UL ) ) return 0UL;
  ulong fork_cnt = max_bank_cnt+1UL;
  ulong buf_cnt  = cache_cnt+1UL;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_rewards_align(), sizeof(fd_stake_rewards_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fork_info_t),      fd_ulong_sat_mul( fork_cnt, sizeof(fork_info_t) ) );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),        fork_pool_footprint( fork_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),            fd_ulong_sat_mul( buf_cnt, sizeof(uint) ) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),           fd_ulong_sat_mul( buf_cnt, sizeof(ulong) ) );
  l = FD_LAYOUT_APPEND( l, alignof(uint),            fd_ulong_sat_mul( buf_cnt*MAX_PARTITIONS_PER_EPOCH,
                                                                      sizeof(uint) ) );
  l = FD_LAYOUT_APPEND( l, alignof(partition_ele_t), fd_ulong_sat_mul( fd_ulong_sat_mul( buf_cnt, max_stake_accounts ),
                                                                      sizeof(partition_ele_t) ) );
  return FD_LAYOUT_FINI( l, fd_stake_rewards_align() );
}

void *
fd_stake_rewards_new( void * shmem,
                      ulong  max_stake_accounts,
                      ulong  max_bank_cnt,
                      ulong  cache_cnt ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_stake_rewards_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  /* Entries are addressed by uint indices within a buffer. */
  if( FD_UNLIKELY( max_stake_accounts>=(ulong)UINT_MAX ) ) {
    FD_LOG_WARNING(( "max_stake_accounts is too large" ));
    return NULL;
  }
  if( FD_UNLIKELY( !max_bank_cnt || max_bank_cnt>FD_BANKS_MAX_BANKS ) ) {
    FD_LOG_WARNING(( "max_bank_cnt must be in [1,%lu]", FD_BANKS_MAX_BANKS ));
    return NULL;
  }
  if( FD_UNLIKELY( !cache_cnt || cache_cnt>max_bank_cnt+1UL ) ) {
    FD_LOG_WARNING(( "cache_cnt must be in [1,max_bank_cnt+1]" ));
    return NULL;
  }
  ulong fork_cnt = max_bank_cnt+1UL;
  ulong buf_cnt  = cache_cnt+1UL;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_stake_rewards_t * stake_rewards = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_rewards_align(), sizeof(fd_stake_rewards_t) );
  void * fork_info_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fork_info_t), fd_ulong_sat_mul( fork_cnt, sizeof(fork_info_t) ) );
  void * fork_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(), fork_pool_footprint( fork_cnt ) );
  void * buf_fork_mem  = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint), fd_ulong_sat_mul( buf_cnt, sizeof(uint) ) );
  void * buf_seq_mem   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), fd_ulong_sat_mul( buf_cnt, sizeof(ulong) ) );
  void * buf_heads_mem = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint), fd_ulong_sat_mul( buf_cnt*MAX_PARTITIONS_PER_EPOCH,
                                                                                     sizeof(uint) ) );
  void * buf_mem       = FD_SCRATCH_ALLOC_APPEND( l, alignof(partition_ele_t), fd_ulong_sat_mul( fd_ulong_sat_mul( buf_cnt, max_stake_accounts ),
                                                                                                sizeof(partition_ele_t) ) );

  fork_t * fork_pool = fork_pool_join( fork_pool_new( fork_pool_mem, fork_cnt ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create fork pool" ));
    return NULL;
  }
  stake_rewards->fork_info_offset           = (ulong)fork_info_mem - (ulong)shmem;
  stake_rewards->fork_pool_offset           = (ulong)fork_pool - (ulong)shmem;
  stake_rewards->buf_fork_offset            = (ulong)buf_fork_mem - (ulong)shmem;
  stake_rewards->buf_seq_offset             = (ulong)buf_seq_mem - (ulong)shmem;
  stake_rewards->buf_partition_heads_offset = (ulong)buf_heads_mem - (ulong)shmem;
  stake_rewards->buf_offset                 = (ulong)buf_mem - (ulong)shmem;
  stake_rewards->max_stake_accounts         = max_stake_accounts;
  stake_rewards->fork_cnt                   = fork_cnt;
  stake_rewards->cache_cnt                  = (uint)cache_cnt;

  fd_stake_rewards_clear( stake_rewards );

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

static void
fork_reset_meta( fork_info_t * fork_info ) {
  fork_info->ele_cnt               = 0U;
  fork_info->partition_cnt         = 0U;
  fork_info->win_lo                = UINT_MAX;
  fork_info->win_hi                = UINT_MAX;
  fork_info->buf_idx               = UINT_MAX;
  fork_info->ready                 = 0U;
  fork_info->starting_block_height = 0UL;
  fork_info->total_stake_rewards   = 0UL;
  fork_info->refcnt                = 0UL;
}

void
fd_stake_rewards_clear( fd_stake_rewards_t * stake_rewards ) {
  fork_pool_reset( get_fork_pool( stake_rewards ) );
  for( ulong i=0UL; i<stake_rewards->fork_cnt; i++ )
    fork_reset_meta( get_fork_info( stake_rewards, (ushort)i ) );
  uint * buf_forks = get_buf_forks( stake_rewards );
  ulong * buf_seqs = get_buf_seqs( stake_rewards );
  for( uint i=0U; i<get_buf_cnt( stake_rewards ); i++ ) {
    buf_forks[i] = UINT_MAX;
    buf_seqs[i]  = 0UL;
  }
  stake_rewards->staging_fork = UINT_MAX;
  stake_rewards->finish_seq   = 0UL;
  stake_rewards->iter_idx     = UINT_MAX;
}

static void
fork_purge( fd_stake_rewards_t * stake_rewards,
            ushort               fork_idx ) {
  fork_info_t * fork_info = get_fork_info( stake_rewards, fork_idx );
  if( stake_rewards->staging_fork==(uint)fork_idx )
    stake_rewards->staging_fork = UINT_MAX;
  fork_drop_buf( stake_rewards, fork_idx );
  fork_reset_meta( fork_info );
  fork_pool_idx_release( get_fork_pool( stake_rewards ), (ulong)fork_idx );
}

void
fd_stake_rewards_acquire( fd_stake_rewards_t * stake_rewards,
                          ushort               fork_idx ) {
  get_fork_info( stake_rewards, fork_idx )->refcnt++;
}

void
fd_stake_rewards_release( fd_stake_rewards_t * stake_rewards,
                          ushort               fork_idx ) {
  fork_info_t * fork_info = get_fork_info( stake_rewards, fork_idx );
  ulong refcnt = fork_info->refcnt;
  FD_CHECK_CRIT( refcnt, "releasing stake rewards fork with zero refcount" );
  if( FD_UNLIKELY( refcnt==1UL ) ) fork_purge( stake_rewards, fork_idx );
  else                             fork_info->refcnt = refcnt-1UL;
}

ulong
fd_stake_rewards_refcnt( fd_stake_rewards_t const * stake_rewards,
                         ushort                     fork_idx ) {
  return get_fork_info( stake_rewards, fork_idx )->refcnt;
}

ulong
fd_stake_rewards_free_cnt( fd_stake_rewards_t const * stake_rewards ) {
  return (ulong)fork_pool_free( get_fork_pool( stake_rewards ) );
}

ushort
fd_stake_rewards_init( fd_stake_rewards_t * stake_rewards,
                       fd_hash_t const *    parent_blockhash,
                       ulong                starting_block_height,
                       uint                 partitions_cnt,
                       uint                 win_lo,
                       ulong                max_rewards_cnt ) {
  FD_CHECK_CRIT( stake_rewards->staging_fork==UINT_MAX,
                 "initializing while another fork is staged" );
  FD_CHECK_CRIT( partitions_cnt && partitions_cnt<=MAX_PARTITIONS_PER_EPOCH,
                 "invalid partition count" );
  FD_CHECK_CRIT( win_lo<partitions_cnt, "invalid window start" );
  FD_CHECK_CRIT( starting_block_height<=ULONG_MAX-(ulong)partitions_cnt,
                 "partition block height overflow" );

  fork_t * fork_pool = get_fork_pool( stake_rewards );

  if( FD_UNLIKELY( !fork_pool_free( fork_pool ) ) ) {
    FD_LOG_ERR(( "No free forks in the stake rewards pool.  This likely occurred due to extremely degenerate "
                 "network conditions. Please report this crash to the Firedancer team." ));
  }
  ushort fork_idx = (ushort)fork_pool_idx_acquire( fork_pool );
  fork_info_t * fork_info = get_fork_info( stake_rewards, fork_idx );
  fork_reset_meta( fork_info );
  fork_info->refcnt = 1UL;
  fork_info->buf_idx = buf_acquire( stake_rewards, fork_idx );

  prime_hasher( stake_rewards, parent_blockhash );

  fork_info->partition_cnt         = partitions_cnt;
  fork_info->starting_block_height = starting_block_height;
  window_init( stake_rewards, fork_idx, win_lo, max_rewards_cnt );

  return fork_idx;
}

uint
fd_stake_rewards_window_lo( fd_stake_rewards_t const * stake_rewards,
                            ushort                     fork_idx ) {
  fork_info_t const * fork_info = get_fork_info( stake_rewards, fork_idx );
  return fd_uint_if( fork_info->ready ||
                     stake_rewards->staging_fork==(uint)fork_idx,
                     fork_info->win_lo,
                     UINT_MAX );
}

uint
fd_stake_rewards_window_hi( fd_stake_rewards_t const * stake_rewards,
                            ushort                     fork_idx ) {
  fork_info_t const * fork_info = get_fork_info( stake_rewards, fork_idx );
  return fd_uint_if( fork_info->ready ||
                     stake_rewards->staging_fork==(uint)fork_idx,
                     fork_info->win_hi,
                     UINT_MAX );
}

void
fd_stake_rewards_insert( fd_stake_rewards_t * stake_rewards,
                         ushort               fork_idx,
                         fd_pubkey_t const *  pubkey,
                         ulong                lamports,
                         ulong                credits_observed ) {

  FD_STATIC_ASSERT( sizeof(fd_pubkey_t)==32UL, partition_hash_size );
  FD_CHECK_CRIT( stake_rewards->staging_fork==(uint)fork_idx,
                 "insert into a fork that is not staged" );
  ulong hash64 = fd_siphash13_fini_x32( stake_rewards->primed_hasher, pubkey->uc );

  fork_info_t * fork_info       = get_fork_info( stake_rewards, fork_idx );
  ulong         partition_index = (ulong)((uint128)fork_info->partition_cnt * (uint128) hash64 / ((uint128)ULONG_MAX + 1));

  /* The total covers the whole epoch, not just the window, so that it
     does not depend on where the window happens to sit. */
  fork_info->total_stake_rewards += lamports;

  if( FD_UNLIKELY( partition_index<fork_info->win_lo || partition_index>fork_info->win_hi ) ) return;

  uint curr_fork_len = fork_info->ele_cnt;
  if( FD_UNLIKELY( curr_fork_len>=stake_rewards->max_stake_accounts ) ) {
    FD_LOG_CRIT(( "invariant violation: curr_fork_len>=stake_rewards->max_stake_accounts" ));
  }

  partition_ele_t * buf           = get_buf( stake_rewards, fork_info->buf_idx );
  partition_ele_t * partition_ele = buf + curr_fork_len;
  partition_ele->pubkey           = *pubkey;
  partition_ele->lamports         = lamports;
  partition_ele->credits_observed = credits_observed;
  partition_ele->next             = UINT_MAX;

  uint * head = get_buf_partition_heads( stake_rewards, fork_info->buf_idx ) + partition_index;
  uint * tail = stake_rewards->staging_partition_idxs_tail + partition_index;

  if( FD_LIKELY( *head!=UINT_MAX ) ) buf[ *tail ].next = curr_fork_len;
  else                               *head             = curr_fork_len;
  *tail = curr_fork_len;

  fork_info->ele_cnt++;
}

static void
buf_trim( fd_stake_rewards_t * stake_rewards,
          uint                 keep_buf_idx ) {
  uint *  buf_forks = get_buf_forks( stake_rewards );
  ulong * buf_seqs  = get_buf_seqs( stake_rewards );
  uint    buf_cnt   = get_buf_cnt( stake_rewards );

  uint resident_cnt = 0U;
  uint victim_idx   = UINT_MAX;
  for( uint buf_idx=0U; buf_idx<buf_cnt; buf_idx++ ) {
    if( buf_forks[buf_idx]==UINT_MAX ) continue;
    resident_cnt++;
    if( buf_idx==keep_buf_idx ) continue;
    if( victim_idx==UINT_MAX || buf_seqs[buf_idx]<buf_seqs[victim_idx] )
      victim_idx = buf_idx;
  }
  if( FD_LIKELY( resident_cnt<=stake_rewards->cache_cnt ) ) return;

  FD_CHECK_CRIT( resident_cnt==stake_rewards->cache_cnt+1U,
                 "invalid resident stake rewards buffer count" );
  FD_CHECK_CRIT( victim_idx!=UINT_MAX,
                 "missing resident stake rewards buffer eviction candidate" );
  ushort victim_fork = (ushort)buf_forks[victim_idx];
  fork_info_t * fork_info = get_fork_info( stake_rewards, victim_fork );
  FD_CHECK_CRIT( fork_info->ready && fork_info->buf_idx==victim_idx,
                 "reward buffer owner mismatch" );
  fork_info->buf_idx      = UINT_MAX;
  fork_info->ready        = 0U;
  buf_forks[victim_idx]   = UINT_MAX;
  buf_seqs[victim_idx]    = 0UL;
}

void
fd_stake_rewards_fini( fd_stake_rewards_t * stake_rewards,
                       ushort               fork_idx ) {
  FD_CHECK_CRIT( stake_rewards->staging_fork==(uint)fork_idx,
                 "finishing a fork that is not staged" );

  fork_info_t * fork_info = get_fork_info( stake_rewards, fork_idx );
  if( FD_UNLIKELY( !fork_info->ele_cnt ) ) {
    fork_drop_buf( stake_rewards, fork_idx );
    fork_info->ready             = 1U;
    stake_rewards->staging_fork = UINT_MAX;
    return;
  }

  uint buf_idx = fork_info->buf_idx;
  FD_CHECK_CRIT( buf_idx<get_buf_cnt( stake_rewards ), "invalid reward buffer" );
  FD_CHECK_CRIT( get_buf_forks( stake_rewards )[buf_idx]==(uint)fork_idx,
                 "reward buffer owner mismatch" );
  get_buf_seqs( stake_rewards )[buf_idx] = stake_rewards->finish_seq++;
  fork_info->ready                       = 1U;
  stake_rewards->staging_fork            = UINT_MAX;
  buf_trim( stake_rewards, buf_idx );
}

void
fd_stake_rewards_iter_init( fd_stake_rewards_t * stake_rewards,
                            ushort               fork_idx,
                            uint                 partition_idx ) {
  fork_info_t const * fork_info = get_fork_info( stake_rewards, fork_idx );
  FD_CHECK_CRIT( fork_info->ready, "stake rewards window is not resident" );
  if( FD_UNLIKELY( partition_idx<fork_info->win_lo || partition_idx>fork_info->win_hi ) ) {
    FD_LOG_CRIT(( "partition %u is outside of the valid window [%u,%u]", partition_idx, fork_info->win_lo, fork_info->win_hi ));
  }
  if( FD_UNLIKELY( fork_info->buf_idx==UINT_MAX ) ) {
    FD_CHECK_CRIT( !fork_info->ele_cnt, "stake rewards window is not resident" );
    stake_rewards->iter_fork = (uint)fork_idx;
    stake_rewards->iter_idx  = UINT_MAX;
    return;
  }
  uint buf_idx = fork_info->buf_idx;
  FD_CHECK_CRIT( buf_idx<get_buf_cnt( stake_rewards ), "invalid reward buffer" );
  FD_CHECK_CRIT( get_buf_forks( stake_rewards )[buf_idx]==(uint)fork_idx,
                 "reward buffer owner mismatch" );
  stake_rewards->iter_fork = (uint)fork_idx;
  stake_rewards->iter_buf  = buf_idx;
  stake_rewards->iter_idx  = get_buf_partition_heads( stake_rewards, buf_idx )[partition_idx];
}

void
fd_stake_rewards_iter_next( fd_stake_rewards_t * stake_rewards,
                            ushort               fork_idx ) {
  FD_CHECK_CRIT( stake_rewards->iter_fork==(uint)fork_idx,
                 "iterator fork mismatch" );
  FD_CHECK_CRIT( stake_rewards->iter_idx!=UINT_MAX,
                 "advancing a finished iterator" );
  partition_ele_t const * buf = get_buf( stake_rewards, stake_rewards->iter_buf );
  stake_rewards->iter_idx = buf[stake_rewards->iter_idx].next;
}

int
fd_stake_rewards_iter_done( fd_stake_rewards_t * stake_rewards ) {
  return stake_rewards->iter_idx==UINT_MAX;
}

void
fd_stake_rewards_iter_ele( fd_stake_rewards_t * stake_rewards,
                           ushort               fork_idx,
                           fd_pubkey_t *        pubkey_out,
                           ulong *              lamports_out,
                           ulong *              credits_observed_out ) {
  FD_CHECK_CRIT( stake_rewards->iter_fork==(uint)fork_idx,
                 "iterator fork mismatch" );
  FD_CHECK_CRIT( stake_rewards->iter_idx!=UINT_MAX,
                 "accessing a finished iterator" );
  partition_ele_t const * ele =
      get_buf( stake_rewards, stake_rewards->iter_buf ) +
      stake_rewards->iter_idx;

  *pubkey_out           = ele->pubkey;
  *lamports_out         = ele->lamports;
  *credits_observed_out = ele->credits_observed;
}

ulong
fd_stake_rewards_total_rewards( fd_stake_rewards_t const * stake_rewards,
                                ushort                     fork_idx ) {
  return get_fork_info( stake_rewards, fork_idx )->total_stake_rewards;
}

uint
fd_stake_rewards_num_partitions( fd_stake_rewards_t const * stake_rewards,
                                 ushort                     fork_idx ) {
  return get_fork_info( stake_rewards, fork_idx )->partition_cnt;
}

ulong
fd_stake_rewards_starting_block_height( fd_stake_rewards_t const * stake_rewards,
                                        ushort                     fork_idx ) {
  return get_fork_info( stake_rewards, fork_idx )->starting_block_height;
}

ulong
fd_stake_rewards_exclusive_ending_block_height( fd_stake_rewards_t const * stake_rewards,
                                                ushort                     fork_idx ) {
  fork_info_t const * fork_info = get_fork_info( stake_rewards, fork_idx );
  return fork_info->starting_block_height + fork_info->partition_cnt;
}
