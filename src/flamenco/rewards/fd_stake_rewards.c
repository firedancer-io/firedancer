#include "fd_stake_rewards.h"
#include "fd_rewards_base.h"
#include "../../ballet/siphash13/fd_siphash13.h"

#include <errno.h>
#include <unistd.h>

/* FIREDANCER STAKE V0 */
#define FD_STAKE_REWARDS_MAGIC (0xF17EDA2CE757A4E0)

/* Entries moved through the bounce buffer per syscall: pread per refill
   while iterating a run that lives on disk, pwrite per gather while
   flushing a partition chain to the overflow area. */

#define FD_STAKE_REWARDS_IOBUF_ELE (16384UL)

/* pwrite chunk while spilling a sealed image (in entries). */

#define FD_STAKE_REWARDS_SPILL_CHUNK_ELE (131072UL)

/* In-memory sealed images. */

#define FD_STAKE_REWARDS_SEALED_BUF_CNT (2UL)

/* Disk extents available for overflow areas, shared by all forks, on
   top of the one spill extent every fork is guaranteed.  Each extent
   is max_stake_accounts entries of 48 bytes (about 103 MiB at the
   production capacity), so this is about 3.3 GiB of sparse file.  A
   single fork may take all of them, which bounds the rewards of one
   epoch to about 27x max_stake_accounts. */

#define FD_STAKE_REWARDS_OVF_EXTENTS (32UL)
#define FD_STAKE_REWARDS_MAX_EXTENTS (FD_STAKE_REWARDS_MAX_FORK_WIDTH+FD_STAKE_REWARDS_OVF_EXTENTS)

struct fork {
  int next;
};
typedef struct fork fork_t;

#define POOL_NAME  fork_pool
#define POOL_T     fork_t
#define POOL_NEXT  next
#define POOL_IDX_T int
#include "../../util/tmpl/fd_pool.c"

/* Staging entry: insert order, chained per partition. */

struct __attribute__((packed, aligned(4UL))) partition_ele {
  fd_pubkey_t pubkey;
  ulong       lamports;
  ulong       credits_observed;
  uint        next;
};
typedef struct partition_ele partition_ele_t;

/* Sealed entry: partition-grouped, chain-free.  Also the on-disk record
   in spill extents and overflow areas. */

struct disk_ele {
  fd_pubkey_t pubkey;
  ulong       lamports;
  ulong       credits_observed;
};
typedef struct disk_ele disk_ele_t;

FD_STATIC_ASSERT( sizeof(disk_ele_t)==48UL, disk_ele );

struct fork_info {
  uint  ele_cnt;        /* staged or in-memory sealed entries */
  uint  partition_cnt;
  uint  sealed;
  uint  sealed_buf;     /* buffer index; UINT_MAX if spilled/empty */
  uint  spill_extent;   /* spill extent; UINT_MAX unless spilled */
  uint  ovf_slot_cap;   /* overflow entries per partition, or 0 */
  uint  ovf_extent_cnt; /* extents allocated on first flush */
  uint  ovf_extent[ FD_STAKE_REWARDS_OVF_EXTENTS ];

  /* Before fini, head/tail index each partition's staging chain.
     After fini, head is the first entry of the partition's run in the
     sealed image.  Runs are in partition order, so p ends where p+1
     starts, or at ele_cnt for the last partition.  tail is the
     partition's entry count in the overflow area. */
  uint  partition_idxs_head[MAX_PARTITIONS_PER_EPOCH];
  uint  partition_idxs_tail[MAX_PARTITIONS_PER_EPOCH];

  ulong starting_block_height;
  ulong total_stake_rewards;
  ulong refcnt;
  ulong seal_seq;      /* seal order used to choose the spill victim */
};
typedef struct fork_info fork_info_t;

struct fd_stake_rewards {
  ulong       magic;

  /* Entries per staging buffer, sealed buffer, and disk extent. */
  ulong       max_stake_accounts;

  fork_info_t fork_info[ FD_STAKE_REWARDS_MAX_FORK_WIDTH ];

  ulong       fork_pool_offset;
  ulong       staging_offset; /* partition_ele_t staging buffer */
  ulong       sealed_offset;  /* partition-grouped disk_ele_t buffers */
  ulong       iobuf_offset;   /* disk bounce buffer */
  ulong       epoch;
  uint        staging_fork;   /* fork accepting inserts, or UINT_MAX */

  /* Owner of each sealed buffer, or UINT_MAX. */
  uint        sealed_buf_fork[ FD_STAKE_REWARDS_SEALED_BUF_CNT ];

  ulong       seal_seq;

  /* Per-partition entry count in the staged fork's overflow area.
     Moves into partition_idxs_tail when the fork is sealed. */
  uint        staging_ovf_cnt[MAX_PARTITIONS_PER_EPOCH];

  /* Disk extent free list. */
  ulong       extent_cnt;
  ulong       extent_free_cnt;
  uint        extent_free[ FD_STAKE_REWARDS_MAX_EXTENTS ];

  /* Temporary storage for the current stake reward being computed. */
  fd_siphash13_t primed_hasher[ 1 ];

  /* Partition iterator state.  A partition is read as two segments:
     its run in the overflow area (disk), then its run in the sealed
     image (in an in-memory buffer or the spill extent). */
  uint  iter_fork;
  uint  iter_partition;
  int   iter_seg;      /* -1 not started, 0 overflow, 1 image, 2 done */
  uint  iter_rem;      /* entries not yet consumed in the segment */
  int   iter_resident; /* segment is served from a sealed buffer */
  ulong iter_res_idx;  /* next in-memory entry */
  uint  iter_buf_pos;  /* disk: next entry in iobuf */
  uint  iter_buf_cnt;  /* disk: valid entries in iobuf */
  ulong iter_ele_off;  /* disk: next overflow or spill entry */
};
typedef struct fd_stake_rewards fd_stake_rewards_t;

static inline fork_t *
get_fork_pool( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->fork_pool_offset );
}

static inline partition_ele_t *
get_staging( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->staging_offset );
}

static inline disk_ele_t *
get_sealed( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->sealed_offset );
}

static inline disk_ele_t *
get_sealed_buf( fd_stake_rewards_t const * stake_rewards,
                uint                       buf ) {
  return get_sealed( stake_rewards ) + (ulong)buf*stake_rewards->max_stake_accounts;
}

static inline disk_ele_t *
get_iobuf( fd_stake_rewards_t const * stake_rewards ) {
  return fd_type_pun( (uchar *)stake_rewards + stake_rewards->iobuf_offset );
}

/* Disk layout: extent e is the max_stake_accounts entries starting at
   file byte e*max_stake_accounts*sizeof(disk_ele_t). */

static inline ulong
extent_file_off( fd_stake_rewards_t const * stake_rewards,
                 uint                       extent,
                 ulong                      ele_idx ) {
  return ( (ulong)extent*stake_rewards->max_stake_accounts + ele_idx )*sizeof(disk_ele_t);
}

static void
spill_read( void * dst,
            ulong  off,
            ulong  sz ) {
  ulong got = 0UL;
  while( got<sz ) {
    long n = pread( FD_STAKE_REWARDS_FD, (uchar *)dst+got, sz-got, (long)(off+got) );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      FD_LOG_CRIT(( "pread(stake rewards spill file, fd=%d) failed (%i-%s)", FD_STAKE_REWARDS_FD, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( !n ) ) FD_LOG_CRIT(( "unexpected EOF reading stake rewards spill file" ));
    got += (ulong)n;
  }
}

static void
spill_write( void const * src,
             ulong        off,
             ulong        sz ) {
  ulong put = 0UL;
  while( put<sz ) {
    long n = pwrite( FD_STAKE_REWARDS_FD, (uchar const *)src+put, sz-put, (long)(off+put) );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      FD_LOG_CRIT(( "pwrite(stake rewards spill file, fd=%d) failed (%i-%s)", FD_STAKE_REWARDS_FD, errno, fd_io_strerror( errno ) ));
    }
    put += (ulong)n;
  }
}

static uint
extent_acquire( fd_stake_rewards_t * stake_rewards,
                char const *         what ) {
  if( FD_UNLIKELY( !stake_rewards->extent_free_cnt ) ) {
    FD_LOG_ERR(( "No free disk extents in the stake rewards spill file for %s.  This likely occurred due to "
                 "extremely degenerate network conditions. Please report this crash to the Firedancer team.", what ));
  }
  return stake_rewards->extent_free[ --stake_rewards->extent_free_cnt ];
}

static void
extent_release( fd_stake_rewards_t * stake_rewards,
                uint                 extent ) {
  FD_CHECK_CRIT( stake_rewards->extent_free_cnt<stake_rewards->extent_cnt, "disk extent released twice" );
  stake_rewards->extent_free[ stake_rewards->extent_free_cnt++ ] = extent;
}

static void
extent_free_list_reset( fd_stake_rewards_t * stake_rewards ) {
  /* Popped from the end, so lowest extents are handed out first and
     the file stays compact. */
  for( ulong i=0UL; i<stake_rewards->extent_cnt; i++ ) {
    stake_rewards->extent_free[ i ] = (uint)(stake_rewards->extent_cnt-1UL-i);
  }
  stake_rewards->extent_free_cnt = stake_rewards->extent_cnt;
}

/* ovf_io reads or writes ele_cnt entries of a fork's overflow area
   starting at logical entry ele_off, splitting at extent boundaries. */

static void
ovf_io( fd_stake_rewards_t * stake_rewards,
        fork_info_t const *  fork_info,
        ulong                ele_off,
        void *               buf,
        ulong                ele_cnt,
        int                  is_write ) {
  ulong   capacity = stake_rewards->max_stake_accounts;
  uchar * p        = buf;
  while( ele_cnt ) {
    ulong ext_idx = ele_off / capacity;
    ulong in_ext  = ele_off % capacity;
    ulong n       = fd_ulong_min( ele_cnt, capacity-in_ext );
    FD_CHECK_CRIT( ext_idx<(ulong)fork_info->ovf_extent_cnt, "overflow area access beyond its extents" );
    ulong off = extent_file_off( stake_rewards, fork_info->ovf_extent[ ext_idx ], in_ext );
    if( is_write ) spill_write( p, off, n*sizeof(disk_ele_t) );
    else           spill_read ( p, off, n*sizeof(disk_ele_t) );
    ele_off += n;
    p       += n*sizeof(disk_ele_t);
    ele_cnt -= n;
  }
}

static ulong
isqrt( ulong x ) {
  if( FD_UNLIKELY( x<2UL ) ) return x;
  /* Initial guess is at least sqrt(x). */
  ulong r = 1UL<<( ((uint)fd_ulong_find_msb( x )/2U)+1U );
  for(;;) {
    ulong next = (r + x/r)/2UL;
    if( next>=r ) return r;
    r = next;
  }
}

/* ovf_slot_cap sizes a fork's per-partition overflow slot.  It returns
   0 when the in-memory buffer can hold all rewards. */

static uint
ovf_slot_cap( ulong capacity,
              uint  partitions_cnt,
              ulong max_rewards_cnt ) {
  if( FD_LIKELY( max_rewards_cnt<=capacity ) ) return 0U;
  if( FD_UNLIKELY( !partitions_cnt ) ) return 0U;

  /* Rewards are scattered uniformly over the partitions, so the entry
     count of a partition has a mean of max_rewards_cnt/partitions_cnt
     and a standard deviation of the square root of that mean.  Twelve
     deviations above the mean put the chance of any partition
     overflowing its slot below one in 10^25 even at the maximum
     partition count; at the production mean of 4096 entries that is
     under a fifth of the area.  The area only ever receives the full
     staging buffers flushed during insertion, never more than the
     total, so this bound is conservative. */
  ulong mean = (max_rewards_cnt+(ulong)partitions_cnt-1UL)/(ulong)partitions_cnt;
  ulong slot = mean + 12UL*(isqrt( mean )+1UL);
  return (uint)fd_ulong_min( slot, (ulong)UINT_MAX-1UL );
}

static ulong
ovf_extents_needed( fd_stake_rewards_t const * stake_rewards,
                    fork_info_t const *        fork_info ) {
  ulong area = (ulong)fork_info->partition_cnt*(ulong)fork_info->ovf_slot_cap;
  return (area+stake_rewards->max_stake_accounts-1UL)/stake_rewards->max_stake_accounts;
}

static void
fork_reset_meta( fork_info_t * fork_info ) {
  fork_info->ele_cnt               = 0U;
  fork_info->partition_cnt         = 0U;
  fork_info->sealed                = 0U;
  fork_info->sealed_buf            = UINT_MAX;
  fork_info->spill_extent          = UINT_MAX;
  fork_info->ovf_slot_cap          = 0U;
  fork_info->ovf_extent_cnt        = 0U;
  fork_info->starting_block_height = 0UL;
  fork_info->total_stake_rewards   = 0UL;
  fork_info->refcnt                = 0UL;
  fork_info->seal_seq              = 0UL;
}

static void
chains_reset( fork_info_t * fork_info ) {
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

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_rewards_align(), sizeof(fd_stake_rewards_t) );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_fork_width ) );
  l = FD_LAYOUT_APPEND( l, alignof(partition_ele_t), fd_ulong_sat_mul( max_stake_accounts, sizeof(partition_ele_t) ) );
  l = FD_LAYOUT_APPEND( l, alignof(disk_ele_t),      fd_ulong_sat_mul( FD_STAKE_REWARDS_SEALED_BUF_CNT*max_stake_accounts, sizeof(disk_ele_t) ) );
  l = FD_LAYOUT_APPEND( l, alignof(disk_ele_t),      FD_STAKE_REWARDS_IOBUF_ELE*sizeof(disk_ele_t) );
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

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_stake_rewards_t * stake_rewards = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_rewards_align(), sizeof(fd_stake_rewards_t) );
  void *               fork_pool_mem = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_fork_width ) );
  void *               staging_mem   = FD_SCRATCH_ALLOC_APPEND( l, alignof(partition_ele_t), fd_ulong_sat_mul( max_stake_accounts, sizeof(partition_ele_t) ) );
  void *               sealed_mem    = FD_SCRATCH_ALLOC_APPEND( l, alignof(disk_ele_t),      fd_ulong_sat_mul( FD_STAKE_REWARDS_SEALED_BUF_CNT*max_stake_accounts, sizeof(disk_ele_t) ) );
  void *               iobuf_mem     = FD_SCRATCH_ALLOC_APPEND( l, alignof(disk_ele_t),      FD_STAKE_REWARDS_IOBUF_ELE*sizeof(disk_ele_t) );

  fork_t * fork_pool = fork_pool_join( fork_pool_new( fork_pool_mem, max_fork_width ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create fork pool" ));
    return NULL;
  }
  stake_rewards->fork_pool_offset   = (ulong)fork_pool - (ulong)shmem;
  stake_rewards->staging_offset     = (ulong)staging_mem - (ulong)shmem;
  stake_rewards->sealed_offset      = (ulong)sealed_mem - (ulong)shmem;
  stake_rewards->iobuf_offset       = (ulong)iobuf_mem - (ulong)shmem;
  stake_rewards->max_stake_accounts = max_stake_accounts;
  stake_rewards->extent_cnt         = max_fork_width + FD_STAKE_REWARDS_OVF_EXTENTS;

  for( ulong i=0UL; i<FD_STAKE_REWARDS_MAX_FORK_WIDTH; i++ ) fork_reset_meta( &stake_rewards->fork_info[i] );
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

void
fd_stake_rewards_clear( fd_stake_rewards_t * stake_rewards ) {
  fork_pool_reset( get_fork_pool( stake_rewards ) );
  for( ulong i=0UL; i<FD_STAKE_REWARDS_MAX_FORK_WIDTH; i++ ) fork_reset_meta( &stake_rewards->fork_info[i] );
  for( ulong i=0UL; i<FD_STAKE_REWARDS_SEALED_BUF_CNT; i++ ) stake_rewards->sealed_buf_fork[i] = UINT_MAX;
  extent_free_list_reset( stake_rewards );
  stake_rewards->epoch        = ULONG_MAX;
  stake_rewards->staging_fork = UINT_MAX;
  stake_rewards->seal_seq     = 0UL;
  stake_rewards->iter_seg     = 2;
  stake_rewards->iter_rem     = 0U;
}

void
fd_stake_rewards_purge( fd_stake_rewards_t * stake_rewards,
                        uchar                fork_idx ) {
  fork_info_t * fork_info = &stake_rewards->fork_info[fork_idx];

  /* Whatever the fork held comes straight back, no I/O: a dead image is
     simply dropped and its extents are reused by later forks. */
  if( fork_info->sealed_buf!=UINT_MAX ) {
    FD_CHECK_CRIT( stake_rewards->sealed_buf_fork[ fork_info->sealed_buf ]==(uint)fork_idx, "sealed buffer owner mismatch" );
    stake_rewards->sealed_buf_fork[ fork_info->sealed_buf ] = UINT_MAX;
  }
  if( fork_info->spill_extent!=UINT_MAX ) extent_release( stake_rewards, fork_info->spill_extent );
  for( uint i=0U; i<fork_info->ovf_extent_cnt; i++ ) extent_release( stake_rewards, fork_info->ovf_extent[i] );

  fork_pool_idx_release( get_fork_pool( stake_rewards ), (ulong)fork_idx );
  fork_reset_meta( fork_info );
  if( FD_UNLIKELY( stake_rewards->staging_fork==(uint)fork_idx ) ) stake_rewards->staging_fork = UINT_MAX;
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

  FD_CHECK_CRIT( partitions_cnt<=MAX_PARTITIONS_PER_EPOCH, "too many stake reward partitions" );

  /* A previously staged fork that was never explicitly sealed gets
     sealed here: the staging buffer is single-occupancy. */
  if( FD_UNLIKELY( stake_rewards->staging_fork!=UINT_MAX &&
                   !stake_rewards->fork_info[ stake_rewards->staging_fork ].sealed ) ) {
    fd_stake_rewards_fini( stake_rewards, (uchar)stake_rewards->staging_fork );
  }

  /* Forks are not reclaimed wholesale when the epoch changes.  Every
     fork is returned by the banks referencing it, so a new epoch has
     nothing left over to clean up. */
  stake_rewards->epoch = epoch;

  if( FD_UNLIKELY( !fork_pool_free( fork_pool ) ) ) {
    FD_LOG_ERR(( "No free forks in the stake rewards pool.  This likely occurred due to extremely degenerate "
                 "network conditions. Please report this crash to the Firedancer team." ));
  }
  uchar         fork_idx  = (uchar)fork_pool_idx_acquire( fork_pool );
  fork_info_t * fork_info = &stake_rewards->fork_info[fork_idx];

  fork_reset_meta( fork_info );
  chains_reset( fork_info );
  fork_info->refcnt                = 1UL;
  fork_info->partition_cnt         = partitions_cnt;
  fork_info->starting_block_height = starting_block_height;
  fork_info->ovf_slot_cap          = ovf_slot_cap( stake_rewards->max_stake_accounts, partitions_cnt, max_rewards_cnt );

  if( FD_UNLIKELY( fork_info->ovf_slot_cap &&
                   ovf_extents_needed( stake_rewards, fork_info )>FD_STAKE_REWARDS_OVF_EXTENTS ) ) {
    FD_LOG_ERR(( "%lu stake rewards over %u partitions exceed the overflow area a fork can hold (%lu extents of %lu entries)",
                 max_rewards_cnt, partitions_cnt, FD_STAKE_REWARDS_OVF_EXTENTS, stake_rewards->max_stake_accounts ));
  }

  memset( stake_rewards->staging_ovf_cnt, 0, (ulong)partitions_cnt*sizeof(uint) );

  prime_hasher( stake_rewards, parent_blockhash );

  stake_rewards->staging_fork = (uint)fork_idx;

  return fork_idx;
}

/* staging_flush moves every staged entry of the fork to its overflow
   area, one contiguous run per partition appended to the partition's
   slot, and empties the staging buffer. */

static void
staging_flush( fd_stake_rewards_t * stake_rewards,
               uchar                fork_idx ) {
  fork_info_t * fork_info = &stake_rewards->fork_info[fork_idx];

  if( FD_UNLIKELY( !fork_info->ovf_slot_cap ) ) {
    FD_LOG_CRIT(( "stake rewards fork %u overflowed the staging buffer (%lu entries) without an overflow area: "
                  "more rewards were inserted than announced to fd_stake_rewards_init",
                  (uint)fork_idx, stake_rewards->max_stake_accounts ));
  }

  if( FD_UNLIKELY( !fork_info->ovf_extent_cnt ) ) {
    ulong need = ovf_extents_needed( stake_rewards, fork_info );
    FD_CHECK_CRIT( need<=FD_STAKE_REWARDS_OVF_EXTENTS, "overflow area too large" );
    for( ulong i=0UL; i<need; i++ ) fork_info->ovf_extent[i] = extent_acquire( stake_rewards, "an overflow area" );
    fork_info->ovf_extent_cnt = (uint)need;
  }

  partition_ele_t const * staging = get_staging( stake_rewards );
  disk_ele_t *            iobuf   = get_iobuf  ( stake_rewards );

  ulong flushed = 0UL;
  for( uint p=0U; p<fork_info->partition_cnt; p++ ) {
    uint e = fork_info->partition_idxs_head[p];
    if( FD_LIKELY( e==UINT_MAX ) ) continue;

    ulong slot_base = (ulong)p*(ulong)fork_info->ovf_slot_cap;
    ulong fill      = (ulong)stake_rewards->staging_ovf_cnt[p];
    ulong n         = 0UL;
    while( e!=UINT_MAX ) {
      iobuf[ n ].pubkey           = staging[e].pubkey;
      iobuf[ n ].lamports         = staging[e].lamports;
      iobuf[ n ].credits_observed = staging[e].credits_observed;
      n++;
      e = staging[e].next;
      if( n==FD_STAKE_REWARDS_IOBUF_ELE || e==UINT_MAX ) {
        if( FD_UNLIKELY( fill+n>(ulong)fork_info->ovf_slot_cap ) ) {
          FD_LOG_CRIT(( "stake rewards partition %u of fork %u overflowed its disk slot (%lu > %u entries)",
                        p, (uint)fork_idx, fill+n, fork_info->ovf_slot_cap ));
        }
        ovf_io( stake_rewards, fork_info, slot_base+fill, iobuf, n, 1 );
        fill    += n;
        flushed += n;
        n        = 0UL;
      }
    }
    stake_rewards->staging_ovf_cnt[p] = (uint)fill;
  }
  FD_CHECK_CRIT( flushed==(ulong)fork_info->ele_cnt, "flushed entry count does not match inserts" );

  fork_info->ele_cnt = 0U;
  chains_reset( fork_info );
}

void
fd_stake_rewards_insert( fd_stake_rewards_t * stake_rewards,
                         uchar                fork_idx,
                         fd_pubkey_t const *  pubkey,
                         ulong                lamports,
                         ulong                credits_observed ) {

  FD_STATIC_ASSERT( sizeof(fd_pubkey_t)==32UL, partition_hash_size );
  FD_CHECK_CRIT( stake_rewards->staging_fork==(uint)fork_idx, "insert into a fork that is not staged" );
  ulong hash64 = fd_siphash13_fini_x32( stake_rewards->primed_hasher, pubkey->uc );

  fork_info_t * fork_info       = &stake_rewards->fork_info[fork_idx];
  ulong         partition_index = (ulong)((uint128)fork_info->partition_cnt * (uint128) hash64 / ((uint128)ULONG_MAX + 1));

  fork_info->total_stake_rewards += lamports;

  if( FD_UNLIKELY( (ulong)fork_info->ele_cnt>=stake_rewards->max_stake_accounts ) ) staging_flush( stake_rewards, fork_idx );

  uint              curr_fork_len = fork_info->ele_cnt;
  partition_ele_t * partition_ele = get_staging( stake_rewards )+curr_fork_len;
  partition_ele->pubkey           = *pubkey;
  partition_ele->lamports         = lamports;
  partition_ele->credits_observed = credits_observed;
  partition_ele->next             = UINT_MAX;

  int is_first_ele = fork_info->partition_idxs_head[partition_index] == UINT_MAX;

  if( FD_LIKELY( !is_first_ele ) ) {
    partition_ele_t * prev_partition_ele = get_staging( stake_rewards )+fork_info->partition_idxs_tail[partition_index];
    prev_partition_ele->next = curr_fork_len;
    fork_info->partition_idxs_tail[partition_index] = curr_fork_len;
  } else {
    fork_info->partition_idxs_head[partition_index] = curr_fork_len;
    fork_info->partition_idxs_tail[partition_index] = curr_fork_len;
  }

  fork_info->ele_cnt++;
}

/* sealed_buf_spill writes the image held by a sealed buffer to a spill
   extent of its own and frees the buffer.  The fork keeps serving reads
   from the extent from then on. */

static void
sealed_buf_spill( fd_stake_rewards_t * stake_rewards,
                  uint                 buf ) {
  uint          fork_idx  = stake_rewards->sealed_buf_fork[ buf ];
  fork_info_t * fork_info = &stake_rewards->fork_info[ fork_idx ];
  FD_CHECK_CRIT( fork_info->sealed_buf==buf,          "sealed buffer owner mismatch" );
  FD_CHECK_CRIT( fork_info->spill_extent==UINT_MAX,   "spilling a fork twice" );

  uint extent = extent_acquire( stake_rewards, "spilling a sealed fork" );

  disk_ele_t const * image = get_sealed_buf( stake_rewards, buf );
  ulong              cnt   = (ulong)fork_info->ele_cnt;
  for( ulong i=0UL; i<cnt; i+=FD_STAKE_REWARDS_SPILL_CHUNK_ELE ) {
    ulong n = fd_ulong_min( FD_STAKE_REWARDS_SPILL_CHUNK_ELE, cnt-i );
    spill_write( image+i, extent_file_off( stake_rewards, extent, i ), n*sizeof(disk_ele_t) );
  }

  fork_info->spill_extent               = extent;
  fork_info->sealed_buf                 = UINT_MAX;
  stake_rewards->sealed_buf_fork[ buf ] = UINT_MAX;
}

/* sealed_buf_take returns a free sealed buffer, spilling the live fork
   sealed longest ago if both are held. */

static uint
sealed_buf_take( fd_stake_rewards_t * stake_rewards ) {
  for( uint b=0U; b<FD_STAKE_REWARDS_SEALED_BUF_CNT; b++ ) {
    if( stake_rewards->sealed_buf_fork[b]==UINT_MAX ) return b;
  }

  uint victim = 0U;
  for( uint b=1U; b<FD_STAKE_REWARDS_SEALED_BUF_CNT; b++ ) {
    ulong seq_b = stake_rewards->fork_info[ stake_rewards->sealed_buf_fork[b]      ].seal_seq;
    ulong seq_v = stake_rewards->fork_info[ stake_rewards->sealed_buf_fork[victim] ].seal_seq;
    if( seq_b<seq_v ) victim = b;
  }
  sealed_buf_spill( stake_rewards, victim );
  return victim;
}

void
fd_stake_rewards_fini( fd_stake_rewards_t * stake_rewards,
                       uchar                fork_idx ) {
  FD_CHECK_CRIT( stake_rewards->staging_fork==(uint)fork_idx, "sealing a fork that is not staged" );
  fork_info_t * fork_info = &stake_rewards->fork_info[fork_idx];
  FD_CHECK_CRIT( !fork_info->sealed, "sealing a fork twice" );

  /* Group the staged entries by partition into a sealed buffer,
     rewriting each partition's chain head as the start of its run.  An
     empty image needs no buffer at all. */

  if( FD_LIKELY( fork_info->ele_cnt ) ) {
    uint                    buf     = sealed_buf_take( stake_rewards );
    partition_ele_t const * staging = get_staging( stake_rewards );
    disk_ele_t *            image   = get_sealed_buf( stake_rewards, buf );

    ulong out = 0UL;
    for( uint p=0U; p<fork_info->partition_cnt; p++ ) {
      uint start = (uint)out;
      for( uint e=fork_info->partition_idxs_head[p]; e!=UINT_MAX; e=staging[e].next ) {
        image[ out ].pubkey           = staging[e].pubkey;
        image[ out ].lamports         = staging[e].lamports;
        image[ out ].credits_observed = staging[e].credits_observed;
        out++;
      }
      fork_info->partition_idxs_head[p] = start;
    }
    FD_CHECK_CRIT( out==(ulong)fork_info->ele_cnt, "sealed entry count does not match inserts" );

    fork_info->sealed_buf                 = buf;
    stake_rewards->sealed_buf_fork[ buf ] = (uint)fork_idx;
  } else {
    for( uint p=0U; p<fork_info->partition_cnt; p++ ) fork_info->partition_idxs_head[p] = 0U;
    fork_info->sealed_buf = UINT_MAX;
  }

  /* The chain tails are free now.  Reuse them for overflow counts. */
  for( uint p=0U; p<fork_info->partition_cnt; p++ ) {
    fork_info->partition_idxs_tail[p] = fork_info->ovf_extent_cnt ? stake_rewards->staging_ovf_cnt[p] : 0U;
  }

  fork_info->sealed           = 1U;
  fork_info->seal_seq         = stake_rewards->seal_seq++;
  stake_rewards->staging_fork = UINT_MAX;
}

/* iter_seg_start positions the iterator on the next non-empty segment
   of the partition, or marks it done. */

static void
iter_seg_start( fd_stake_rewards_t * stake_rewards ) {
  fork_info_t const * fork_info = &stake_rewards->fork_info[ stake_rewards->iter_fork ];
  uint                p         = stake_rewards->iter_partition;

  for(;;) {
    stake_rewards->iter_seg++;

    if( stake_rewards->iter_seg==0 ) {
      /* Overflow area, disk only. */
      uint cnt = fork_info->partition_idxs_tail[p];
      if( FD_LIKELY( !cnt ) ) continue;
      stake_rewards->iter_rem      = cnt;
      stake_rewards->iter_resident = 0;
      stake_rewards->iter_buf_pos  = 0U;
      stake_rewards->iter_buf_cnt  = 0U;
      stake_rewards->iter_ele_off  = (ulong)p*(ulong)fork_info->ovf_slot_cap;
      return;
    }

    if( stake_rewards->iter_seg==1 ) {
      /* Sealed image, in a buffer or in the spill extent. */
      uint start = fork_info->partition_idxs_head[p];
      uint end   = p+1U<fork_info->partition_cnt ? fork_info->partition_idxs_head[p+1U] : fork_info->ele_cnt;
      FD_CHECK_CRIT( end>=start, "sealed image runs out of order" );
      uint cnt   = end-start;
      if( FD_UNLIKELY( !cnt ) ) continue;
      stake_rewards->iter_rem = cnt;
      if( FD_LIKELY( fork_info->sealed_buf!=UINT_MAX ) ) {
        stake_rewards->iter_resident = 1;
        stake_rewards->iter_res_idx  = (ulong)fork_info->sealed_buf*stake_rewards->max_stake_accounts + (ulong)start;
      } else {
        /* Mainnet keeps a single boundary chain live, whose image is
           resident; reading an image back off its spill extent only
           happens under concurrent boundary-crossing forks. */
        FD_CHECK_CRIT( fork_info->spill_extent!=UINT_MAX, "sealed image is neither resident nor spilled" );
        stake_rewards->iter_resident = 0;
        stake_rewards->iter_buf_pos  = 0U;
        stake_rewards->iter_buf_cnt  = 0U;
        stake_rewards->iter_ele_off  = (ulong)start;
      }
      return;
    }

    stake_rewards->iter_rem = 0U;
    return;
  }
}

void
fd_stake_rewards_iter_init( fd_stake_rewards_t * stake_rewards,
                            uchar                fork_idx,
                            uint                 partition_idx ) {
  fork_info_t const * fork_info = &stake_rewards->fork_info[fork_idx];
  if( FD_UNLIKELY( partition_idx>=fork_info->partition_cnt ) ) {
    FD_LOG_CRIT(( "partition %u is outside of the fork's %u partitions", partition_idx, fork_info->partition_cnt ));
  }
  FD_CHECK_CRIT( fork_info->sealed, "iterating a stake rewards fork that was never sealed" );

  stake_rewards->iter_fork      = (uint)fork_idx;
  stake_rewards->iter_partition = partition_idx;
  stake_rewards->iter_seg       = -1;
  iter_seg_start( stake_rewards );
}

static void
iter_refill( fd_stake_rewards_t * stake_rewards ) {
  fork_info_t const * fork_info = &stake_rewards->fork_info[ stake_rewards->iter_fork ];
  ulong               n         = fd_ulong_min( FD_STAKE_REWARDS_IOBUF_ELE, (ulong)stake_rewards->iter_rem );
  if( stake_rewards->iter_seg==0 ) {
    ovf_io( stake_rewards, fork_info, stake_rewards->iter_ele_off, get_iobuf( stake_rewards ), n, 0 );
  } else {
    spill_read( get_iobuf( stake_rewards ),
                extent_file_off( stake_rewards, fork_info->spill_extent, stake_rewards->iter_ele_off ),
                n*sizeof(disk_ele_t) );
  }
  stake_rewards->iter_ele_off += n;
  stake_rewards->iter_buf_cnt  = (uint)n;
  stake_rewards->iter_buf_pos  = 0U;
}

void
fd_stake_rewards_iter_next( fd_stake_rewards_t * stake_rewards,
                            uchar                fork_idx ) {
  (void)fork_idx;
  stake_rewards->iter_rem--;
  if( FD_LIKELY( stake_rewards->iter_resident ) ) stake_rewards->iter_res_idx++;
  else                                            stake_rewards->iter_buf_pos++;
  if( FD_UNLIKELY( !stake_rewards->iter_rem ) ) iter_seg_start( stake_rewards );
}

int
fd_stake_rewards_iter_done( fd_stake_rewards_t * stake_rewards ) {
  return !stake_rewards->iter_rem;
}

void
fd_stake_rewards_iter_ele( fd_stake_rewards_t * stake_rewards,
                           uchar                fork_idx,
                           fd_pubkey_t *        pubkey_out,
                           ulong *              lamports_out,
                           ulong *              credits_observed_out ) {
  (void)fork_idx;
  disk_ele_t const * ele;
  if( FD_LIKELY( stake_rewards->iter_resident ) ) {
    ele = get_sealed( stake_rewards )+stake_rewards->iter_res_idx;
  } else {
    if( FD_UNLIKELY( stake_rewards->iter_buf_pos>=stake_rewards->iter_buf_cnt ) ) iter_refill( stake_rewards );
    ele = get_iobuf( stake_rewards )+stake_rewards->iter_buf_pos;
  }

  *pubkey_out           = ele->pubkey;
  *lamports_out         = ele->lamports;
  *credits_observed_out = ele->credits_observed;
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
