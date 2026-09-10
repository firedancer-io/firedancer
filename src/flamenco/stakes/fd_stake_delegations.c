#include "fd_stake_delegations.h"
#include "fd_stakes.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../events/fd_event_runtime.h"
#include "../../util/fd_hash32.h"

#include <errno.h>
#include <unistd.h>

#define POOL_NAME  root_pool
#define POOL_T     fd_stake_delegation_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               root_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_delegation_t
#define MAP_KEY                stake_account
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_hash32( key->uc, seed ))
#define MAP_NEXT               next_
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               fork_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_delegation_t
#define MAP_KEY                stake_account
#define MAP_KEY_EQ(k0,k1)      (fd_pubkey_eq( k0, k1 ))
#define MAP_KEY_HASH(key,seed) (fd_hash32( key->uc, seed ))
#define MAP_NEXT               next_
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME  delta_pool
#define POOL_T     fd_stake_delegation_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

struct fork_pool_ele {
  ushort next;
  uint   disk_delta_head;
};
typedef struct fork_pool_ele fork_pool_ele_t;

#define POOL_NAME  fork_pool
#define POOL_T     fork_pool_ele_t
#define POOL_IDX_T ushort
#include "../../util/tmpl/fd_pool.c"

/* Internal getters for base map + pool */

static inline fd_stake_delegation_t *
get_root_pool( fd_stake_delegations_t const * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->pool_offset_ );
}

static inline root_map_t *
get_root_map( fd_stake_delegations_t const * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->map_offset_ );
}

/* Internal getters for delta pool + fork structures */

static inline fd_stake_delegation_t *
get_delta_pool( fd_stake_delegations_t const * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->delta_pool_offset_ );
}

static inline fork_pool_ele_t *
get_fork_pool( fd_stake_delegations_t const * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->fork_pool_offset_ );
}

static inline fork_map_t *
get_fork_map( fd_stake_delegations_t const * stake_delegations,
              ushort                         fork_idx ) {
  ulong map_footprint = fork_map_footprint( FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT );
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->fork_map_offset_ + (ulong)fork_idx*map_footprint );
}

/* The spill file contains two compact open-addressed indexes followed
   by dense root and delta record arrays.  Index generations make reset
   O(1).  Root and delta indexes are separate so root mutation while
   applying a fork cannot disturb traversal of that fork's deltas. */

#define DISK_BUCKET_EMPTY     (UINT_MAX)
#define DISK_BUCKET_TOMBSTONE (UINT_MAX-1U)

struct disk_bucket {
  uint idx;
  uint gen;
};
typedef struct disk_bucket disk_bucket_t;

struct disk_delta {
  fd_stake_delegation_t delegation;
  uint                  next;
  uint                  prev;
  ushort                fork_idx;
  ushort                pad;
};
typedef struct disk_delta disk_delta_t;

FD_STATIC_ASSERT( sizeof(disk_bucket_t)==8UL, disk_bucket );
FD_STATIC_ASSERT( sizeof(disk_delta_t)==128UL, disk_delta );

static inline ulong
disk_root_bucket_off( fd_stake_delegations_t const * stake_delegations ) {
  (void)stake_delegations;
  return 0UL;
}

static inline ulong
disk_delta_bucket_off( fd_stake_delegations_t const * stake_delegations ) {
  return stake_delegations->disk_slot_cnt_*sizeof(disk_bucket_t);
}

static inline ulong
disk_root_record_off( fd_stake_delegations_t const * stake_delegations ) {
  return fd_ulong_align_up( 2UL*stake_delegations->disk_slot_cnt_*sizeof(disk_bucket_t), alignof(fd_stake_delegation_t) );
}

static inline ulong
disk_root_record_cap( fd_stake_delegations_t const * stake_delegations ) {
  return 2UL*stake_delegations->max_disk_records_ + stake_delegations->max_stake_accounts_;
}

static inline ulong
disk_delta_record_off( fd_stake_delegations_t const * stake_delegations ) {
  return fd_ulong_align_up( disk_root_record_off( stake_delegations ) +
                            disk_root_record_cap( stake_delegations )*sizeof(fd_stake_delegation_t),
                            alignof(disk_delta_t) );
}

/* Reads short at EOF zero-fill.  The spill file is sparse and is not
   required to be pre-sized. */

static void
disk_read( void * dst,
           ulong  off,
           ulong  sz ) {
  ulong got = 0UL;
  while( got<sz ) {
    long n = pread( FD_STAKE_DELEGATIONS_FD, (uchar *)dst+got, sz-got, (long)(off+got) );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      FD_LOG_CRIT(( "pread(stake delegation spill file, fd=%d) failed (%i-%s)", FD_STAKE_DELEGATIONS_FD, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( !n ) ) break;
    got += (ulong)n;
  }
  if( FD_UNLIKELY( got<sz ) ) fd_memset( (uchar *)dst+got, 0, sz-got );
}

static void
disk_write( void const * src,
            ulong        off,
            ulong        sz ) {
  ulong put = 0UL;
  while( put<sz ) {
    long n = pwrite( FD_STAKE_DELEGATIONS_FD, (uchar const *)src+put, sz-put, (long)(off+put) );
    if( FD_LIKELY( n>0L ) ) { put += (ulong)n; continue; }
    if( FD_UNLIKELY( n<0L && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( !n ) ) errno = EIO;
    FD_LOG_CRIT(( "pwrite(stake delegation spill file, fd=%d) failed (%i-%s)", FD_STAKE_DELEGATIONS_FD, errno, fd_io_strerror( errno ) ));
  }
}

static inline int
disk_bucket_is_empty( disk_bucket_t const * bucket,
                      uint                  gen ) {
  return bucket->gen!=gen || bucket->idx==DISK_BUCKET_EMPTY;
}

static inline int
disk_bucket_is_tombstone( disk_bucket_t const * bucket,
                          uint                  gen ) {
  return bucket->gen==gen && bucket->idx==DISK_BUCKET_TOMBSTONE;
}

static inline ulong
disk_bucket_off( ulong base,
                 ulong slot ) {
  return base + slot*sizeof(disk_bucket_t);
}

static void
disk_bucket_store( fd_stake_delegations_t const * stake_delegations,
                   ulong                          base,
                   ulong                          slot,
                   uint                           gen,
                   uint                           idx ) {
  (void)stake_delegations;
  disk_bucket_t bucket = {
    .idx = idx,
    .gen = gen,
  };
  disk_write( &bucket, disk_bucket_off( base, slot ), sizeof(disk_bucket_t) );
}

static void
disk_root_read( fd_stake_delegations_t const * stake_delegations,
                uint                           idx,
                fd_stake_delegation_t *        delegation ) {
  disk_read( delegation,
             disk_root_record_off( stake_delegations ) + (ulong)idx*sizeof(fd_stake_delegation_t),
             sizeof(fd_stake_delegation_t) );
}

static void
disk_root_write( fd_stake_delegations_t const * stake_delegations,
                 uint                           idx,
                 fd_stake_delegation_t const *  delegation ) {
  disk_write( delegation,
              disk_root_record_off( stake_delegations ) + (ulong)idx*sizeof(fd_stake_delegation_t),
              sizeof(fd_stake_delegation_t) );
}

static void
disk_delta_read( fd_stake_delegations_t const * stake_delegations,
                 uint                           idx,
                 disk_delta_t *                 delta ) {
  disk_read( delta,
             disk_delta_record_off( stake_delegations ) + (ulong)idx*sizeof(disk_delta_t),
             sizeof(disk_delta_t) );
}

static void
disk_delta_write( fd_stake_delegations_t const * stake_delegations,
                  uint                           idx,
                  disk_delta_t const *           delta ) {
  disk_write( delta,
              disk_delta_record_off( stake_delegations ) + (ulong)idx*sizeof(disk_delta_t),
              sizeof(disk_delta_t) );
}

static void
disk_root_find( fd_stake_delegations_t const * stake_delegations,
                fd_pubkey_t const *            stake_account,
                fd_stake_delegation_t *        delegation,
                uint *                         idx,
                ulong *                        bucket_slot,
                ulong *                        free_slot ) {
  *idx         = UINT_MAX;
  *bucket_slot = ULONG_MAX;
  *free_slot   = ULONG_MAX;
  if( FD_UNLIKELY( !stake_delegations->disk_slot_cnt_ ) ) return;

  ulong mask = stake_delegations->disk_slot_cnt_-1UL;
  ulong slot = (ulong)fd_hash32( stake_account->uc, stake_delegations->disk_seed_ ) & mask;
  ulong base = disk_root_bucket_off( stake_delegations );
  for( ulong probe=0UL; probe<stake_delegations->disk_slot_cnt_; probe++ ) {
    disk_bucket_t bucket;
    disk_read( &bucket, disk_bucket_off( base, slot ), sizeof(disk_bucket_t) );
    if( FD_UNLIKELY( disk_bucket_is_empty( &bucket, stake_delegations->disk_root_gen_ ) ) ) {
      if( *free_slot==ULONG_MAX ) *free_slot = slot;
      return;
    }
    if( FD_UNLIKELY( bucket.idx==DISK_BUCKET_TOMBSTONE ) ) {
      if( *free_slot==ULONG_MAX ) *free_slot = slot;
    } else {
      FD_CHECK_CRIT( (ulong)bucket.idx<stake_delegations->disk_root_cnt_, "corrupt stake delegation disk root index" );
      fd_stake_delegation_t candidate;
      disk_root_read( stake_delegations, bucket.idx, &candidate );
      if( FD_UNLIKELY( fd_pubkey_eq( &candidate.stake_account, stake_account ) ) ) {
        if( delegation ) *delegation = candidate;
        *idx         = bucket.idx;
        *bucket_slot = slot;
        return;
      }
    }
    slot = (slot+1UL) & mask;
  }
}

static void
disk_delta_find( fd_stake_delegations_t const * stake_delegations,
                 ushort                         fork_idx,
                 fd_pubkey_t const *            stake_account,
                 disk_delta_t *                 delta,
                 uint *                         idx,
                 ulong *                        bucket_slot,
                 ulong *                        free_slot ) {
  *idx         = UINT_MAX;
  *bucket_slot = ULONG_MAX;
  *free_slot   = ULONG_MAX;
  if( FD_UNLIKELY( !stake_delegations->disk_slot_cnt_ ) ) return;

  uint  seed = (uint)stake_delegations->disk_seed_ ^ ((uint)fork_idx*2654435761U);
  ulong mask = stake_delegations->disk_slot_cnt_-1UL;
  ulong slot = (ulong)fd_hash32( stake_account->uc, seed ) & mask;
  ulong base = disk_delta_bucket_off( stake_delegations );
  for( ulong probe=0UL; probe<stake_delegations->disk_slot_cnt_; probe++ ) {
    disk_bucket_t bucket;
    disk_read( &bucket, disk_bucket_off( base, slot ), sizeof(disk_bucket_t) );
    if( FD_UNLIKELY( disk_bucket_is_empty( &bucket, stake_delegations->disk_delta_gen_ ) ) ) {
      if( *free_slot==ULONG_MAX ) *free_slot = slot;
      return;
    }
    if( FD_UNLIKELY( bucket.idx==DISK_BUCKET_TOMBSTONE ) ) {
      if( *free_slot==ULONG_MAX ) *free_slot = slot;
    } else {
      FD_CHECK_CRIT( (ulong)bucket.idx<stake_delegations->disk_delta_cnt_, "corrupt stake delegation disk delta index" );
      disk_delta_t candidate;
      disk_delta_read( stake_delegations, bucket.idx, &candidate );
      if( FD_UNLIKELY( candidate.fork_idx==fork_idx &&
                       fd_pubkey_eq( &candidate.delegation.stake_account, stake_account ) ) ) {
        if( delta ) *delta = candidate;
        *idx         = bucket.idx;
        *bucket_slot = slot;
        return;
      }
    }
    slot = (slot+1UL) & mask;
  }
}

static inline int
disk_root_record_available( fd_stake_delegations_t const * stake_delegations ) {
  FD_CHECK_CRIT( stake_delegations->disk_temp_root_cnt_<=stake_delegations->disk_root_cnt_,
                 "corrupt stake delegation temporary root count" );
  return stake_delegations->disk_root_cnt_ - stake_delegations->disk_temp_root_cnt_ <
         stake_delegations->max_disk_records_;
}

static inline void
disk_root_record_reserve( fd_stake_delegations_t const * stake_delegations ) {
  FD_CHECK_CRIT( disk_root_record_available( stake_delegations ), "stake delegation disk root spill exhausted" );
}

static inline void
disk_delta_record_reserve( fd_stake_delegations_t const * stake_delegations ) {
  FD_CHECK_CRIT( stake_delegations->disk_delta_cnt_<stake_delegations->max_disk_records_,
                 "stake delegation disk delta spill exhausted" );
}

static inline uint
disk_gen_next( uint gen ) {
  FD_CHECK_CRIT( gen<UINT_MAX, "stake delegation disk generation exhausted" );
  return gen+1U;
}

static inline int
disk_index_needs_rebuild( ulong tombstone_cnt,
                          ulong live_cnt,
                          ulong slot_cnt ) {
  return tombstone_cnt>live_cnt || tombstone_cnt>(slot_cnt>>2);
}

static void
disk_root_rebuild( fd_stake_delegations_t * stake_delegations ) {
  stake_delegations->disk_root_gen_ = disk_gen_next( stake_delegations->disk_root_gen_ );
  stake_delegations->disk_root_tombstone_cnt_ = 0UL;

  for( uint idx=0U; (ulong)idx<stake_delegations->disk_root_cnt_; idx++ ) {
    fd_stake_delegation_t delegation;
    disk_root_read( stake_delegations, idx, &delegation );

    uint  found_idx;
    ulong bucket_slot;
    ulong free_slot;
    disk_root_find( stake_delegations, &delegation.stake_account, NULL, &found_idx, &bucket_slot, &free_slot );
    FD_CHECK_CRIT( found_idx==UINT_MAX && free_slot!=ULONG_MAX, "unable to rebuild stake delegation disk root index" );
    disk_bucket_store( stake_delegations, disk_root_bucket_off( stake_delegations ), free_slot,
                       stake_delegations->disk_root_gen_, idx );
  }
}

static void
disk_delta_rebuild( fd_stake_delegations_t * stake_delegations ) {
  stake_delegations->disk_delta_gen_ = disk_gen_next( stake_delegations->disk_delta_gen_ );
  stake_delegations->disk_delta_tombstone_cnt_ = 0UL;

  for( uint idx=0U; (ulong)idx<stake_delegations->disk_delta_cnt_; idx++ ) {
    disk_delta_t delta;
    disk_delta_read( stake_delegations, idx, &delta );

    uint  found_idx;
    ulong bucket_slot;
    ulong free_slot;
    disk_delta_find( stake_delegations, delta.fork_idx, &delta.delegation.stake_account,
                     NULL, &found_idx, &bucket_slot, &free_slot );
    FD_CHECK_CRIT( found_idx==UINT_MAX && free_slot!=ULONG_MAX, "unable to rebuild stake delegation disk delta index" );
    disk_bucket_store( stake_delegations, disk_delta_bucket_off( stake_delegations ), free_slot,
                       stake_delegations->disk_delta_gen_, idx );
  }
}

static void
disk_root_maintain( fd_stake_delegations_t * stake_delegations ) {
  if( FD_UNLIKELY( !stake_delegations->disk_root_cnt_ ) ) {
    if( FD_UNLIKELY( stake_delegations->disk_root_tombstone_cnt_ ) ) {
      stake_delegations->disk_root_gen_ = disk_gen_next( stake_delegations->disk_root_gen_ );
      stake_delegations->disk_root_tombstone_cnt_ = 0UL;
    }
    return;
  }
  if( FD_UNLIKELY( stake_delegations->frontier_query_epoch==ULONG_MAX &&
                   disk_index_needs_rebuild( stake_delegations->disk_root_tombstone_cnt_,
                                             stake_delegations->disk_root_cnt_,
                                             stake_delegations->disk_slot_cnt_ ) ) ) {
    disk_root_rebuild( stake_delegations );
  }
}

static void
disk_delta_maintain( fd_stake_delegations_t * stake_delegations ) {
  if( FD_UNLIKELY( !stake_delegations->disk_delta_cnt_ ) ) {
    if( FD_UNLIKELY( stake_delegations->disk_delta_tombstone_cnt_ ) ) {
      stake_delegations->disk_delta_gen_ = disk_gen_next( stake_delegations->disk_delta_gen_ );
      stake_delegations->disk_delta_tombstone_cnt_ = 0UL;
    }
    return;
  }
  if( FD_UNLIKELY( disk_index_needs_rebuild( stake_delegations->disk_delta_tombstone_cnt_,
                                             stake_delegations->disk_delta_cnt_,
                                             stake_delegations->disk_slot_cnt_ ) ) ) {
    disk_delta_rebuild( stake_delegations );
  }
}

static uint
disk_root_insert( fd_stake_delegations_t *      stake_delegations,
                  fd_stake_delegation_t const * delegation,
                  int                           temporary ) {
  if( FD_LIKELY( !temporary ) ) {
    disk_root_record_reserve( stake_delegations );
  } else {
    FD_CHECK_CRIT( stake_delegations->disk_root_cnt_<disk_root_record_cap( stake_delegations ),
                   "stake delegation temporary disk roots exhausted" );
  }

  uint  idx;
  ulong bucket_slot;
  ulong free_slot;
  disk_root_find( stake_delegations, &delegation->stake_account, NULL, &idx, &bucket_slot, &free_slot );
  FD_CHECK_CRIT( idx==UINT_MAX, "duplicate stake delegation disk root" );
  FD_CHECK_CRIT( free_slot!=ULONG_MAX, "stake delegation disk root index exhausted" );

  idx = (uint)stake_delegations->disk_root_cnt_;
  disk_root_write( stake_delegations, idx, delegation );
  disk_bucket_t free_bucket;
  disk_read( &free_bucket, disk_bucket_off( disk_root_bucket_off( stake_delegations ), free_slot ), sizeof(disk_bucket_t) );
  if( FD_UNLIKELY( disk_bucket_is_tombstone( &free_bucket, stake_delegations->disk_root_gen_ ) ) ) {
    FD_CHECK_CRIT( stake_delegations->disk_root_tombstone_cnt_, "corrupt stake delegation disk root tombstone count" );
    stake_delegations->disk_root_tombstone_cnt_--;
  }
  disk_bucket_store( stake_delegations, disk_root_bucket_off( stake_delegations ), free_slot,
                     stake_delegations->disk_root_gen_, idx );
  stake_delegations->disk_root_cnt_++;
  stake_delegations->disk_temp_root_cnt_ += !!temporary;
  return idx;
}

static void
disk_root_remove( fd_stake_delegations_t * stake_delegations,
                  uint                     idx,
                  ulong                    bucket_slot ) {
  FD_CHECK_CRIT( (ulong)idx<stake_delegations->disk_root_cnt_, "invalid stake delegation disk root removal" );
  fd_stake_delegation_t removed;
  disk_root_read( stake_delegations, idx, &removed );
  disk_bucket_store( stake_delegations, disk_root_bucket_off( stake_delegations ), bucket_slot,
                     stake_delegations->disk_root_gen_, DISK_BUCKET_TOMBSTONE );

  uint last = (uint)(stake_delegations->disk_root_cnt_-1UL);
  if( FD_UNLIKELY( idx!=last ) ) {
    fd_stake_delegation_t moved;
    disk_root_read( stake_delegations, last, &moved );
    disk_root_write( stake_delegations, idx, &moved );

    uint  moved_idx;
    ulong moved_slot;
    ulong free_slot;
    disk_root_find( stake_delegations, &moved.stake_account, NULL, &moved_idx, &moved_slot, &free_slot );
    FD_CHECK_CRIT( moved_idx==last, "missing moved stake delegation disk root" );
    disk_bucket_store( stake_delegations, disk_root_bucket_off( stake_delegations ), moved_slot,
                       stake_delegations->disk_root_gen_, idx );
  }
  stake_delegations->disk_root_cnt_--;
  stake_delegations->disk_root_tombstone_cnt_++;
  if( FD_UNLIKELY( removed.dne_in_root ) ) {
    FD_CHECK_CRIT( stake_delegations->disk_temp_root_cnt_, "corrupt stake delegation temporary root removal" );
    stake_delegations->disk_temp_root_cnt_--;
  }
  disk_root_maintain( stake_delegations );
}

static uint
disk_delta_insert( fd_stake_delegations_t * stake_delegations,
                   ushort                   fork_idx,
                   fd_stake_delegation_t *  delegation ) {
  disk_delta_record_reserve( stake_delegations );

  uint  idx;
  ulong bucket_slot;
  ulong free_slot;
  disk_delta_find( stake_delegations, fork_idx, &delegation->stake_account, NULL, &idx, &bucket_slot, &free_slot );
  FD_CHECK_CRIT( idx==UINT_MAX, "duplicate stake delegation disk delta" );
  FD_CHECK_CRIT( free_slot!=ULONG_MAX, "stake delegation disk delta index exhausted" );

  idx = (uint)stake_delegations->disk_delta_cnt_;
  fork_pool_ele_t * fork = get_fork_pool( stake_delegations ) + fork_idx;
  disk_delta_t delta = {
    .delegation = *delegation,
    .next       = fork->disk_delta_head,
    .prev       = UINT_MAX,
    .fork_idx   = fork_idx,
    .pad        = 0U,
  };
  disk_delta_write( stake_delegations, idx, &delta );
  if( FD_LIKELY( delta.next!=UINT_MAX ) ) {
    disk_delta_t next;
    disk_delta_read( stake_delegations, delta.next, &next );
    next.prev = idx;
    disk_delta_write( stake_delegations, delta.next, &next );
  }
  disk_bucket_t free_bucket;
  disk_read( &free_bucket, disk_bucket_off( disk_delta_bucket_off( stake_delegations ), free_slot ), sizeof(disk_bucket_t) );
  if( FD_UNLIKELY( disk_bucket_is_tombstone( &free_bucket, stake_delegations->disk_delta_gen_ ) ) ) {
    FD_CHECK_CRIT( stake_delegations->disk_delta_tombstone_cnt_, "corrupt stake delegation disk delta tombstone count" );
    stake_delegations->disk_delta_tombstone_cnt_--;
  }
  disk_bucket_store( stake_delegations, disk_delta_bucket_off( stake_delegations ), free_slot,
                     stake_delegations->disk_delta_gen_, idx );
  fork->disk_delta_head = idx;
  stake_delegations->disk_delta_cnt_++;
  return idx;
}

static void
disk_delta_remove( fd_stake_delegations_t * stake_delegations,
                   uint                     idx ) {
  FD_CHECK_CRIT( (ulong)idx<stake_delegations->disk_delta_cnt_, "invalid stake delegation disk delta removal" );
  disk_delta_t removed;
  disk_delta_read( stake_delegations, idx, &removed );

  fork_pool_ele_t * fork = get_fork_pool( stake_delegations ) + removed.fork_idx;
  if( FD_LIKELY( removed.prev!=UINT_MAX ) ) {
    disk_delta_t prev;
    disk_delta_read( stake_delegations, removed.prev, &prev );
    prev.next = removed.next;
    disk_delta_write( stake_delegations, removed.prev, &prev );
  } else {
    fork->disk_delta_head = removed.next;
  }
  if( FD_LIKELY( removed.next!=UINT_MAX ) ) {
    disk_delta_t next;
    disk_delta_read( stake_delegations, removed.next, &next );
    next.prev = removed.prev;
    disk_delta_write( stake_delegations, removed.next, &next );
  }

  uint  found_idx;
  ulong bucket_slot;
  ulong free_slot;
  disk_delta_find( stake_delegations, removed.fork_idx, &removed.delegation.stake_account,
                   NULL, &found_idx, &bucket_slot, &free_slot );
  FD_CHECK_CRIT( found_idx==idx, "missing stake delegation disk delta removal" );
  disk_bucket_store( stake_delegations, disk_delta_bucket_off( stake_delegations ), bucket_slot,
                     stake_delegations->disk_delta_gen_, DISK_BUCKET_TOMBSTONE );

  uint last = (uint)(stake_delegations->disk_delta_cnt_-1UL);
  if( FD_UNLIKELY( idx!=last ) ) {
    disk_delta_t moved;
    disk_delta_read( stake_delegations, last, &moved );
    disk_delta_write( stake_delegations, idx, &moved );

    uint  moved_idx;
    ulong moved_slot;
    disk_delta_find( stake_delegations, moved.fork_idx, &moved.delegation.stake_account,
                     NULL, &moved_idx, &moved_slot, &free_slot );
    FD_CHECK_CRIT( moved_idx==last, "missing moved stake delegation disk delta" );
    disk_bucket_store( stake_delegations, disk_delta_bucket_off( stake_delegations ), moved_slot,
                       stake_delegations->disk_delta_gen_, idx );

    fork_pool_ele_t * moved_fork = get_fork_pool( stake_delegations ) + moved.fork_idx;
    if( FD_LIKELY( moved.prev!=UINT_MAX ) ) {
      disk_delta_t prev;
      disk_delta_read( stake_delegations, moved.prev, &prev );
      prev.next = idx;
      disk_delta_write( stake_delegations, moved.prev, &prev );
    } else {
      moved_fork->disk_delta_head = idx;
    }
    if( FD_LIKELY( moved.next!=UINT_MAX ) ) {
      disk_delta_t next;
      disk_delta_read( stake_delegations, moved.next, &next );
      next.prev = idx;
      disk_delta_write( stake_delegations, moved.next, &next );
    }
  }
  stake_delegations->disk_delta_cnt_--;
  stake_delegations->disk_delta_tombstone_cnt_++;
  disk_delta_maintain( stake_delegations );
}

ulong
fd_stake_delegations_align( void ) {
  return FD_STAKE_DELEGATIONS_ALIGN;
}

ulong
fd_stake_delegations_footprint( ulong max_stake_accounts,
                                ulong max_fallback_stake_accounts,
                                ulong expected_stake_accounts,
                                ulong max_live_slots ) {
  (void)max_fallback_stake_accounts;

  ulong map_chain_cnt = root_map_chain_cnt_est( expected_stake_accounts );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t) );
  l = FD_LAYOUT_APPEND( l, root_pool_align(),            root_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, root_map_align(),             root_map_footprint( map_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, delta_pool_align(),           delta_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),            fork_pool_footprint( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, fork_map_align(),             max_live_slots*fork_map_footprint( FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT ) );

  return FD_LAYOUT_FINI( l, fd_stake_delegations_align() );
}

void *
fd_stake_delegations_new( void * mem,
                          ulong  seed,
                          ulong  max_stake_accounts,
                          ulong  max_fallback_stake_accounts,
                          ulong  expected_stake_accounts,
                          ulong  max_live_slots ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_stake_accounts ) ) {
    FD_LOG_WARNING(( "max_stake_accounts is 0" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_stake_accounts>=(ulong)FD_STAKE_DELEGATIONS_DELTA_DISK_TAG ) ) {
    FD_LOG_WARNING(( "max_stake_accounts is too large" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stake_delegations_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_live_slots>FD_STAKE_DELEGATIONS_FORK_MAX ) ) {
    FD_LOG_WARNING(( "max_live_slots is too large" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_fallback_stake_accounts>=(ulong)FD_STAKE_DELEGATIONS_DELTA_DISK_TAG ) ) {
    FD_LOG_WARNING(( "max_fallback_stake_accounts is too large" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_stake_accounts>(ulong)FD_STAKE_DELEGATIONS_DELTA_IDX_MASK ||
                   max_fallback_stake_accounts>
                   ((ulong)FD_STAKE_DELEGATIONS_DELTA_IDX_MASK-max_stake_accounts)/2UL ) ) {
    FD_LOG_WARNING(( "combined stake delegation disk root capacity is too large" ));
    return NULL;
  }

  ulong map_chain_cnt = root_map_chain_cnt_est( expected_stake_accounts );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_delegations_t * stake_delegations = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t) );
  void *                   pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, root_pool_align(),            root_pool_footprint( max_stake_accounts ) );
  void *                   map_mem           = FD_SCRATCH_ALLOC_APPEND( l, root_map_align(),             root_map_footprint( map_chain_cnt ) );
  void *                   delta_pool_mem    = FD_SCRATCH_ALLOC_APPEND( l, delta_pool_align(),           delta_pool_footprint( max_stake_accounts ) );
  void *                   fork_pool_mem     = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),            fork_pool_footprint( max_live_slots ) );
  void *                   fork_map_mem      = FD_SCRATCH_ALLOC_APPEND( l, fork_map_align(),             max_live_slots*fork_map_footprint( FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT ) );
  for( ushort i=0; i<(ushort)max_live_slots; i++ ) {
    void * fork_map_mem_i = (uchar *)fork_map_mem + (ulong)i*fork_map_footprint( FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT );
    fork_map_t * map = fork_map_join( fork_map_new( fork_map_mem_i, FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT, seed ) );
    if( FD_UNLIKELY( !map ) ) {
      FD_LOG_WARNING(( "Failed to create fork map" ));
      return NULL;
    }
  }

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_stake_delegations_align() )!=(ulong)mem+fd_stake_delegations_footprint( max_stake_accounts, max_fallback_stake_accounts, expected_stake_accounts, max_live_slots ) ) ) {
    FD_LOG_WARNING(( "fd_stake_delegations_new: bad layout" ));
    return NULL;
  }

  fd_stake_delegation_t * root_pool = root_pool_join( root_pool_new( pool_mem, max_stake_accounts ) );
  if( FD_UNLIKELY( !root_pool ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegations pool" ));
    return NULL;
  }

  root_map_t * root_map = root_map_join( root_map_new( map_mem, map_chain_cnt, seed ) );
  if( FD_UNLIKELY( !root_map ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegations map" ));
    return NULL;
  }

  fd_stake_delegation_t * delta_pool = delta_pool_join( delta_pool_new( delta_pool_mem, max_stake_accounts ) );
  if( FD_UNLIKELY( !delta_pool ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegation delta pool" ));
    return NULL;
  }

  fork_pool_ele_t * fork_pool = fork_pool_join( fork_pool_new( fork_pool_mem, max_live_slots ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create fork pool" ));
    return NULL;
  }

  stake_delegations->max_stake_accounts_      = max_stake_accounts;
  stake_delegations->expected_stake_accounts_ = expected_stake_accounts;
  stake_delegations->pool_offset_             = (ulong)root_pool - (ulong)mem;
  stake_delegations->map_offset_              = (ulong)root_map - (ulong)mem;
  stake_delegations->delta_pool_offset_       = (ulong)delta_pool - (ulong)mem;
  stake_delegations->fork_pool_offset_        = (ulong)fork_pool - (ulong)mem;
  stake_delegations->fork_map_offset_         = (ulong)fork_map_mem - (ulong)mem;
  stake_delegations->max_disk_records_        = max_fallback_stake_accounts;
  stake_delegations->disk_root_cnt_           = 0UL;
  stake_delegations->disk_temp_root_cnt_      = 0UL;
  stake_delegations->disk_delta_cnt_          = 0UL;
  ulong disk_root_cap                         = 2UL*max_fallback_stake_accounts + max_stake_accounts;
  stake_delegations->disk_slot_cnt_           = fd_ulong_pow2_up( disk_root_cap + (disk_root_cap>>1) + 1UL );
  stake_delegations->disk_seed_               = seed;
  stake_delegations->disk_root_tombstone_cnt_ = 0UL;
  stake_delegations->disk_delta_tombstone_cnt_= 0UL;
  stake_delegations->disk_root_gen_            = 1U;
  stake_delegations->disk_delta_gen_           = 1U;

  stake_delegations->effective_stake    = 0UL;
  stake_delegations->activating_stake   = 0UL;
  stake_delegations->deactivating_stake = 0UL;
  stake_delegations->frontier_query_epoch = ULONG_MAX;
  stake_delegations->pool_idx_wmk_      = 0UL;
  stake_delegations->fp_warmed_awarded  = 0;

  fd_rwlock_new( &stake_delegations->lock );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( stake_delegations->magic ) = FD_STAKE_DELEGATIONS_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_stake_delegations_t *
fd_stake_delegations_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_stake_delegations_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_stake_delegations_t * stake_delegations = (fd_stake_delegations_t *)mem;

  if( FD_UNLIKELY( stake_delegations->magic!=FD_STAKE_DELEGATIONS_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid stake delegations magic" ));
    return NULL;
  }

  return stake_delegations;
}

void
fd_stake_delegations_reset( fd_stake_delegations_t * stake_delegations ) {
  fd_rwlock_write( &stake_delegations->lock );
  root_pool_reset( get_root_pool( stake_delegations ) );
  root_map_reset( get_root_map( stake_delegations ) );
  delta_pool_reset( get_delta_pool( stake_delegations ) );
  fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
  ulong max_forks = fork_pool_max( fork_pool );
  for( ulong i=0UL; i<max_forks; i++ ) {
    fork_map_reset( get_fork_map( stake_delegations, (ushort)i ) );
    fork_pool[ i ].disk_delta_head = UINT_MAX;
  }
  fork_pool_reset( fork_pool );
  stake_delegations->disk_root_cnt_            = 0UL;
  stake_delegations->disk_temp_root_cnt_       = 0UL;
  stake_delegations->disk_delta_cnt_           = 0UL;
  stake_delegations->disk_root_tombstone_cnt_  = 0UL;
  stake_delegations->disk_delta_tombstone_cnt_ = 0UL;
  stake_delegations->disk_root_gen_            = disk_gen_next( stake_delegations->disk_root_gen_ );
  stake_delegations->disk_delta_gen_           = disk_gen_next( stake_delegations->disk_delta_gen_ );
  stake_delegations->effective_stake    = 0UL;
  stake_delegations->activating_stake   = 0UL;
  stake_delegations->deactivating_stake = 0UL;
  stake_delegations->frontier_query_epoch = ULONG_MAX;
  stake_delegations->pool_idx_wmk_      = 0UL;
  stake_delegations->fp_warmed_awarded  = 0;
  fd_rwlock_unwrite( &stake_delegations->lock );
}

struct root_ref {
  fd_stake_delegation_t * ram;
  uint                    disk_idx;
  ulong                   disk_bucket_slot;
};
typedef struct root_ref root_ref_t;

static inline root_ref_t
root_ref_none( void ) {
  root_ref_t ref = { .ram = NULL, .disk_idx = UINT_MAX, .disk_bucket_slot = ULONG_MAX };
  return ref;
}

static inline int
root_ref_is_none( root_ref_t ref ) {
  return !ref.ram && ref.disk_idx==UINT_MAX;
}

static void
delegation_set( fd_stake_delegation_t * delegation,
                fd_pubkey_t const *     stake_account,
                fd_pubkey_t const *     vote_account,
                ulong                   stake,
                ulong                   activation_epoch,
                ulong                   deactivation_epoch,
                ulong                   credits_observed,
                ulong                   lamports,
                uint                    acc_dlen,
                uchar                   warmup_cooldown_rate ) {
  FD_CHECK_ERR( (long)activation_epoch  <USHORT_MAX, "activation_epoch overflow"   );
  FD_CHECK_ERR( (long)deactivation_epoch<USHORT_MAX, "deactivation_epoch overflow" );

  delegation->stake_account        = *stake_account;
  delegation->vote_account         = *vote_account;
  delegation->stake                = stake;
  delegation->lamports             = lamports;
  delegation->credits_observed     = credits_observed;
  delegation->acc_dlen             = acc_dlen;
  delegation->delta_idx            = UINT_MAX;
  delegation->activation_epoch     = (ushort)activation_epoch;
  delegation->deactivation_epoch   = (ushort)deactivation_epoch;
  delegation->dne_in_root          = 0;
  delegation->warmup_cooldown_rate = warmup_cooldown_rate;
  delegation->in_use               = 1;
  delegation->state                = FD_STAKE_DELEGATION_STATE_UNKNOWN;
}

static root_ref_t
root_lookup( fd_stake_delegations_t * stake_delegations,
             fd_pubkey_t const *      stake_account,
             fd_stake_delegation_t *  copy ) {
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  root_map_t *            map  = get_root_map( stake_delegations );

  fd_stake_delegation_t * ram = root_map_ele_query( map, stake_account, NULL, pool );
  if( FD_LIKELY( ram ) ) {
    if( copy ) *copy = *ram;
    root_ref_t ref = { .ram = ram, .disk_idx = UINT_MAX, .disk_bucket_slot = ULONG_MAX };
    return ref;
  }

  root_ref_t ref = root_ref_none();
  if( FD_LIKELY( !stake_delegations->disk_root_cnt_ ) ) return ref;
  ulong free_slot;
  disk_root_find( stake_delegations, stake_account, copy, &ref.disk_idx, &ref.disk_bucket_slot, &free_slot );
  return ref;
}

static root_ref_t
root_insert( fd_stake_delegations_t *      stake_delegations,
             fd_stake_delegation_t const * delegation,
             int                           temporary ) {
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  if( FD_LIKELY( root_pool_free( pool ) ) ) {
    fd_stake_delegation_t * ram = root_pool_ele_acquire( pool );
    *ram = *delegation;
    stake_delegations->pool_idx_wmk_ = fd_ulong_max( stake_delegations->pool_idx_wmk_, root_pool_idx( pool, ram )+1UL );
    FD_CHECK_CRIT( root_map_ele_insert( get_root_map( stake_delegations ), ram, pool ),
                   "unable to insert stake delegation into root map" );
    root_ref_t ref = { .ram = ram, .disk_idx = UINT_MAX, .disk_bucket_slot = ULONG_MAX };
    return ref;
  }

  uint idx = disk_root_insert( stake_delegations, delegation, temporary );
  root_ref_t ref = { .ram = NULL, .disk_idx = idx, .disk_bucket_slot = ULONG_MAX };
  return ref;
}

static void
root_store( fd_stake_delegations_t *      stake_delegations,
            root_ref_t                    ref,
            fd_stake_delegation_t const * delegation ) {
  if( FD_LIKELY( ref.ram ) ) {
    uint next = ref.ram->next_;
    *ref.ram = *delegation;
    ref.ram->next_ = next;
  } else {
    disk_root_write( stake_delegations, ref.disk_idx, delegation );
  }
}

static void
root_remove( fd_stake_delegations_t * stake_delegations,
             root_ref_t               ref ) {
  if( FD_LIKELY( ref.ram ) ) {
    fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
    uint idx = (uint)root_pool_idx( pool, ref.ram );
    fd_pubkey_t stake_account = ref.ram->stake_account;
    root_map_idx_remove( get_root_map( stake_delegations ), &stake_account, idx, pool );
    ref.ram->in_use = 0;
    root_pool_idx_release( pool, idx );
  } else {
    disk_root_remove( stake_delegations, ref.disk_idx, ref.disk_bucket_slot );
  }
}

/* Unlocked root upsert used by public updates and fork rooting. */

static root_ref_t
root_update( fd_stake_delegations_t * stake_delegations,
             fd_pubkey_t const *      stake_account,
             fd_pubkey_t const *      vote_account,
             ulong                    stake,
             ulong                    activation_epoch,
             ulong                    deactivation_epoch,
             ulong                    credits_observed,
             ulong                    lamports,
             uint                     acc_dlen,
             uchar                    warmup_cooldown_rate,
             int                      allow_temporary_disk_root ) {
  fd_stake_delegation_t delegation;
  root_ref_t ref = root_lookup( stake_delegations, stake_account, &delegation );
  if( FD_UNLIKELY( root_ref_is_none( ref ) ) ) fd_memset( &delegation, 0, sizeof(delegation) );
  uchar dne_in_root = delegation.dne_in_root;

  delegation_set( &delegation, stake_account, vote_account, stake, activation_epoch,
                  deactivation_epoch, credits_observed, lamports, acc_dlen, warmup_cooldown_rate );
  delegation.dne_in_root = dne_in_root;

  if( FD_LIKELY( !root_ref_is_none( ref ) ) ) {
    root_store( stake_delegations, ref, &delegation );
    return ref;
  }

  if( FD_UNLIKELY( allow_temporary_disk_root &&
                   !root_pool_free( get_root_pool( stake_delegations ) ) &&
                   !disk_root_record_available( stake_delegations ) ) ) {
    delegation.dne_in_root = 1;
    return root_insert( stake_delegations, &delegation, 1 );
  }
  return root_insert( stake_delegations, &delegation, 0 );
}

void
fd_stake_delegations_root_update( fd_stake_delegations_t * stake_delegations,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  ulong                    lamports,
                                  uint                     acc_dlen,
                                  uchar                    warmup_cooldown_rate ) {
  fd_rwlock_write( &stake_delegations->lock );
  root_update( stake_delegations, stake_account, vote_account, stake, activation_epoch,
               deactivation_epoch, credits_observed, lamports, acc_dlen, warmup_cooldown_rate, 0 );
  fd_rwlock_unwrite( &stake_delegations->lock );
}

#if FD_HAS_DOUBLE

ulong
fd_stake_delegations_prune_inactive_root( fd_stake_delegations_t *   stake_delegations,
                                          ulong                      epoch,
                                          fd_stake_history_t const * stake_history,
                                          ulong *                    warmup_cooldown_rate_epoch,
                                          int                        use_fixed_point_stake_math,
                                          fd_bank_t const *          emit_bank ) {
  fd_rwlock_write( &stake_delegations->lock );

  root_map_t *            map        = get_root_map( stake_delegations );
  fd_stake_delegation_t * pool       = get_root_pool( stake_delegations );
  ulong                   prev_epoch = epoch ? epoch-1UL : 0UL;
  ulong                   pruned     = 0UL;

  for( ulong idx=0UL; idx<stake_delegations->pool_idx_wmk_; idx++ ) {
    fd_stake_delegation_t * delegation = pool+idx;
    if( FD_LIKELY( !delegation->in_use ) ) continue;

    if( FD_LIKELY( !fd_stake_delegation_is_inactive( delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math ) ||
                   !fd_stake_delegation_is_inactive( delegation, prev_epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math ) ) ) continue;

    if( FD_UNLIKELY( emit_bank ) ) fd_event_runtime_stake_delegation_remove_emit( emit_bank, delegation->stake_account.uc );
    pruned++;

    fd_pubkey_t stake_account = delegation->stake_account;
    root_map_idx_remove( map, &stake_account, (uint)idx, pool );
    delegation->in_use = 0;
    root_pool_idx_release( pool, (uint)idx );
  }

  for( uint idx=0U; (ulong)idx<stake_delegations->disk_root_cnt_; ) {
    fd_stake_delegation_t delegation;
    disk_root_read( stake_delegations, idx, &delegation );
    if( FD_LIKELY( !fd_stake_delegation_is_inactive( &delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math ) ||
                   !fd_stake_delegation_is_inactive( &delegation, prev_epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math ) ) ) {
      idx++;
      continue;
    }

    if( FD_UNLIKELY( emit_bank ) ) fd_event_runtime_stake_delegation_remove_emit( emit_bank, delegation.stake_account.uc );
    pruned++;

    uint  found_idx;
    ulong bucket_slot;
    ulong free_slot;
    disk_root_find( stake_delegations, &delegation.stake_account, NULL, &found_idx, &bucket_slot, &free_slot );
    FD_CHECK_CRIT( found_idx==idx, "missing inactive stake delegation disk root" );
    disk_root_remove( stake_delegations, idx, bucket_slot );
  }

  /* Keep the RAM root tier packed after pruning. */
  while( root_pool_free( pool ) && stake_delegations->disk_root_cnt_ ) {
    uint idx = (uint)(stake_delegations->disk_root_cnt_-1UL);
    fd_stake_delegation_t delegation;
    disk_root_read( stake_delegations, idx, &delegation );
    root_insert( stake_delegations, &delegation, 0 );

    uint  found_idx;
    ulong bucket_slot;
    ulong free_slot;
    disk_root_find( stake_delegations, &delegation.stake_account, NULL, &found_idx, &bucket_slot, &free_slot );
    FD_CHECK_CRIT( found_idx==idx, "missing promoted stake delegation disk root" );
    disk_root_remove( stake_delegations, idx, bucket_slot );
  }

  fd_rwlock_unwrite( &stake_delegations->lock );

  return pruned;
}

static void
refresh_remove_ram( fd_stake_delegations_t * stake_delegations,
                    uint                     idx ) {
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  fd_pubkey_t stake_account = pool[ idx ].stake_account;
  root_map_idx_remove( get_root_map( stake_delegations ), &stake_account, idx, pool );
  pool[ idx ].in_use = 0;
  root_pool_idx_release( pool, idx );
}

void
fd_stake_delegations_refresh( fd_stake_delegations_t *   stake_delegations,
                              ulong                      epoch,
                              fd_stake_history_t const * stake_history,
                              ulong *                    warmup_cooldown_rate_epoch,
                              int                        use_fixed_point_stake_math,
                              int                        remove_inactive_stakes,
                              fd_accdb_t *               accdb,
                              fd_accdb_fork_id_t         fork_id ) {
  fd_rwlock_write( &stake_delegations->lock );

  int history_contiguous = fd_sysvar_stake_history_is_contiguous( stake_history );

  stake_delegations->effective_stake    = 0UL;
  stake_delegations->activating_stake   = 0UL;
  stake_delegations->deactivating_stake = 0UL;
  stake_delegations->fp_warmed_awarded  = 0;

  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  ulong const wmk = stake_delegations->pool_idx_wmk_;

#define BATCH 64UL
  uchar const * pubkeys[ BATCH ];
  int           writable[ BATCH ];
  fd_acc_t      accs[ BATCH ];
  uint          root_idx[ BATCH ];

  ulong i = 0UL;
  while( i<wmk ) {
    ulong batch_n = 0UL;
    while( i<wmk && batch_n<BATCH ) {
      if( FD_LIKELY( pool[ i ].in_use ) ) {
        pubkeys[ batch_n ]  = pool[ i ].stake_account.uc;
        writable[ batch_n ] = 0;
        root_idx[ batch_n ] = (uint)i;
        batch_n++;
      }
      i++;
    }
    if( FD_UNLIKELY( !batch_n ) ) continue;

    fd_accdb_acquire( accdb, fork_id, batch_n, pubkeys, writable, accs );

    for( ulong j=0UL; j<batch_n; j++ ) {
      fd_pubkey_t const *      stake_account = &pool[ root_idx[ j ] ].stake_account;
      fd_stake_state_t const * stake         = accs[ j ].lamports ? fd_stakes_get_state( &accs[ j ] ) : NULL;

      if( FD_UNLIKELY( !stake || stake->stake_type!=FD_STAKE_STATE_STAKE ) ) {
        refresh_remove_ram( stake_delegations, root_idx[ j ] );
        continue;
      }

      fd_delegation_t const * account_delegation = &stake->stake.stake.delegation;
      ulong prev_epoch = epoch ? epoch-1UL : 0UL;
      if( FD_UNLIKELY( remove_inactive_stakes &&
                       fd_delegation_is_inactive( account_delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math ) &&
                       fd_delegation_is_inactive( account_delegation, prev_epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math ) ) ) {
        refresh_remove_ram( stake_delegations, root_idx[ j ] );
        continue;
      }

      root_ref_t ref = root_update(
          stake_delegations,
          stake_account,
          &stake->stake.stake.delegation.voter_pubkey,
          stake->stake.stake.delegation.stake,
          stake->stake.stake.delegation.activation_epoch,
          stake->stake.stake.delegation.deactivation_epoch,
          stake->stake.stake.credits_observed,
          accs[ j ].lamports,
          (uint)accs[ j ].data_len,
          fd_stake_warmup_cooldown_rate( epoch, warmup_cooldown_rate_epoch ),
          0 );

      fd_stake_history_entry_t history = fd_delegation_activation_status( &stake->stake.stake.delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
      stake_delegations->effective_stake    += history.effective;
      stake_delegations->activating_stake   += history.activating;
      stake_delegations->deactivating_stake += history.deactivating;

      fd_stake_delegation_t delegation = *ref.ram;
      uchar state = fd_stake_delegation_classify( &delegation, history, epoch );
      delegation.state = !history_contiguous ? FD_STAKE_DELEGATION_STATE_UNKNOWN : state;
      root_store( stake_delegations, ref, &delegation );
      if( FD_LIKELY( delegation.state==FD_STAKE_DELEGATION_STATE_WARMED && !use_fixed_point_stake_math ) ) {
        stake_delegations->fp_warmed_awarded = 1;
      }
    }

    fd_accdb_release( accdb, batch_n, accs );
  }

  /* Disk roots are dense, so removals leave the moved last record at
     the current index.  Survivors move back to RAM whenever pruning
     made a root-pool slot available. */
  uint disk_idx = 0U;
  while( (ulong)disk_idx<stake_delegations->disk_root_cnt_ ) {
    fd_stake_delegation_t old_delegation;
    disk_root_read( stake_delegations, disk_idx, &old_delegation );
    fd_pubkey_t stake_account = old_delegation.stake_account;
    pubkeys[ 0 ]  = stake_account.uc;
    writable[ 0 ] = 0;
    fd_accdb_acquire( accdb, fork_id, 1UL, pubkeys, writable, accs );

    fd_stake_state_t const * stake = accs[ 0 ].lamports ? fd_stakes_get_state( &accs[ 0 ] ) : NULL;
    int remove = !stake || stake->stake_type!=FD_STAKE_STATE_STAKE;
    if( FD_LIKELY( !remove ) && FD_UNLIKELY( remove_inactive_stakes ) ) {
      fd_delegation_t const * account_delegation = &stake->stake.stake.delegation;
      ulong prev_epoch = epoch ? epoch-1UL : 0UL;
      remove = fd_delegation_is_inactive( account_delegation, epoch,      stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math ) &&
               fd_delegation_is_inactive( account_delegation, prev_epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    }

    if( FD_UNLIKELY( remove ) ) {
      fd_accdb_release( accdb, 1UL, accs );
      uint  found_idx;
      ulong bucket_slot;
      ulong free_slot;
      disk_root_find( stake_delegations, &stake_account, NULL, &found_idx, &bucket_slot, &free_slot );
      FD_CHECK_CRIT( found_idx==disk_idx, "missing refreshed stake delegation disk root" );
      disk_root_remove( stake_delegations, disk_idx, bucket_slot );
      continue;
    }

    root_ref_t ref = root_update(
        stake_delegations,
        &stake_account,
        &stake->stake.stake.delegation.voter_pubkey,
        stake->stake.stake.delegation.stake,
        stake->stake.stake.delegation.activation_epoch,
        stake->stake.stake.delegation.deactivation_epoch,
        stake->stake.stake.credits_observed,
        accs[ 0 ].lamports,
        (uint)accs[ 0 ].data_len,
        fd_stake_warmup_cooldown_rate( epoch, warmup_cooldown_rate_epoch ),
        0 );

    fd_stake_history_entry_t history = fd_delegation_activation_status(
        &stake->stake.stake.delegation,
        epoch,
        stake_history,
        warmup_cooldown_rate_epoch,
        use_fixed_point_stake_math );
    stake_delegations->effective_stake    += history.effective;
    stake_delegations->activating_stake   += history.activating;
    stake_delegations->deactivating_stake += history.deactivating;

    fd_stake_delegation_t delegation;
    disk_root_read( stake_delegations, ref.disk_idx, &delegation );
    uchar state = fd_stake_delegation_classify( &delegation, history, epoch );
    delegation.state = !history_contiguous ? FD_STAKE_DELEGATION_STATE_UNKNOWN : state;
    root_store( stake_delegations, ref, &delegation );
    if( FD_LIKELY( delegation.state==FD_STAKE_DELEGATION_STATE_WARMED && !use_fixed_point_stake_math ) ) {
      stake_delegations->fp_warmed_awarded = 1;
    }
    fd_accdb_release( accdb, 1UL, accs );

    if( FD_UNLIKELY( root_pool_free( pool ) ) ) {
      root_insert( stake_delegations, &delegation, 0 );
      uint  found_idx;
      ulong bucket_slot;
      ulong free_slot;
      disk_root_find( stake_delegations, &stake_account, NULL, &found_idx, &bucket_slot, &free_slot );
      FD_CHECK_CRIT( found_idx==disk_idx, "missing promoted refreshed stake delegation disk root" );
      disk_root_remove( stake_delegations, disk_idx, bucket_slot );
      continue;
    }
    disk_idx++;
  }
#undef BATCH

  fd_rwlock_unwrite( &stake_delegations->lock );
}

#endif

/* Fork-aware delta operations */

ushort
fd_stake_delegations_new_fork( fd_stake_delegations_t * stake_delegations ) {
  fd_rwlock_write( &stake_delegations->lock );
  fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
  FD_CHECK_CRIT( fork_pool_free( fork_pool ), "no free forks in pool. The system has forked too wide." );
  ushort fork_idx = (ushort)fork_pool_idx_acquire( fork_pool );
  fork_map_reset( get_fork_map( stake_delegations, fork_idx ) );
  fork_pool[ fork_idx ].disk_delta_head = UINT_MAX;
  fd_rwlock_unwrite( &stake_delegations->lock );

  return fork_idx;
}

void
fd_stake_delegations_fork_update( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  ulong                    lamports,
                                  uint                     acc_dlen,
                                  uchar                    warmup_cooldown_rate ) {
  fd_rwlock_write( &stake_delegations->lock );

  fd_stake_delegation_t * delta_pool       = get_delta_pool( stake_delegations );
  fork_map_t *            map              = get_fork_map( stake_delegations, fork_idx );
  fd_stake_delegation_t * stake_delegation = fork_map_ele_query( map, stake_account, NULL, delta_pool );
  if( FD_LIKELY( stake_delegation ) ) {
    uint next = stake_delegation->next_;
    delegation_set( stake_delegation, stake_account, vote_account, stake, activation_epoch,
                    deactivation_epoch, credits_observed, lamports, acc_dlen, warmup_cooldown_rate );
    stake_delegation->next_ = next;
    fd_rwlock_unwrite( &stake_delegations->lock );
    return;
  }

  disk_delta_t disk_delta;
  uint         disk_idx = UINT_MAX;
  ulong        bucket_slot;
  ulong        free_slot;
  if( FD_UNLIKELY( stake_delegations->disk_delta_cnt_ ) )
    disk_delta_find( stake_delegations, fork_idx, stake_account, &disk_delta, &disk_idx, &bucket_slot, &free_slot );
  if( FD_UNLIKELY( disk_idx!=UINT_MAX ) ) {
    delegation_set( &disk_delta.delegation, stake_account, vote_account, stake, activation_epoch,
                    deactivation_epoch, credits_observed, lamports, acc_dlen, warmup_cooldown_rate );
    disk_delta_write( stake_delegations, disk_idx, &disk_delta );
    fd_rwlock_unwrite( &stake_delegations->lock );
    return;
  }

  fd_stake_delegation_t delegation;
  fd_memset( &delegation, 0, sizeof(delegation) );
  delegation_set( &delegation, stake_account, vote_account, stake, activation_epoch,
                  deactivation_epoch, credits_observed, lamports, acc_dlen, warmup_cooldown_rate );
  if( FD_LIKELY( delta_pool_free( delta_pool ) ) ) {
    stake_delegation = delta_pool_ele_acquire( delta_pool );
    *stake_delegation = delegation;
    FD_CHECK_CRIT( fork_map_ele_insert( map, stake_delegation, delta_pool ),
                   "unable to insert stake delegation into fork map" );
  } else {
    disk_delta_insert( stake_delegations, fork_idx, &delegation );
  }

  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_fork_remove( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  fd_pubkey_t const *      stake_account ) {
  fd_rwlock_write( &stake_delegations->lock );

  fd_stake_delegation_t * delta_pool       = get_delta_pool( stake_delegations );
  fork_map_t *            map              = get_fork_map( stake_delegations, fork_idx );
  fd_stake_delegation_t * stake_delegation = fork_map_ele_query( map, stake_account, NULL, delta_pool );
  if( FD_LIKELY( stake_delegation ) ) {
    stake_delegation->lamports     = 0UL;
    stake_delegation->acc_dlen     = 0U;
    stake_delegation->is_tombstone = 1;
    stake_delegation->state        = FD_STAKE_DELEGATION_STATE_UNKNOWN;

    FD_BASE58_ENCODE_32_BYTES( stake_delegation->stake_account.uc, stake_account_out );
    FD_LOG_DEBUG(( "fork_remove: stake_account=%s", stake_account_out ));
    fd_rwlock_unwrite( &stake_delegations->lock );
    return;
  }

  disk_delta_t disk_delta;
  uint         disk_idx = UINT_MAX;
  ulong        bucket_slot;
  ulong        free_slot;
  if( FD_UNLIKELY( stake_delegations->disk_delta_cnt_ ) )
    disk_delta_find( stake_delegations, fork_idx, stake_account, &disk_delta, &disk_idx, &bucket_slot, &free_slot );
  if( FD_UNLIKELY( disk_idx!=UINT_MAX ) ) {
    disk_delta.delegation.lamports     = 0UL;
    disk_delta.delegation.acc_dlen     = 0U;
    disk_delta.delegation.is_tombstone = 1;
    disk_delta.delegation.state        = FD_STAKE_DELEGATION_STATE_UNKNOWN;
    disk_delta_write( stake_delegations, disk_idx, &disk_delta );
    fd_rwlock_unwrite( &stake_delegations->lock );
    return;
  }

  fd_stake_delegation_t delegation;
  fd_memset( &delegation, 0, sizeof(delegation) );
  delegation.stake_account = *stake_account;
  delegation.next_         = UINT_MAX;
  delegation.delta_idx     = UINT_MAX;
  delegation.is_tombstone  = 1;
  delegation.in_use        = 1;
  delegation.state         = FD_STAKE_DELEGATION_STATE_UNKNOWN;
  if( FD_LIKELY( delta_pool_free( delta_pool ) ) ) {
    stake_delegation = delta_pool_ele_acquire( delta_pool );
    *stake_delegation = delegation;
    FD_CHECK_CRIT( fork_map_ele_insert( map, stake_delegation, delta_pool ),
                   "unable to insert stake delegation tombstone into fork map" );
  } else {
    disk_delta_insert( stake_delegations, fork_idx, &delegation );
  }

  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_evict_fork( fd_stake_delegations_t * stake_delegations,
                                 ushort                   fork_idx ) {
  if( fork_idx==USHORT_MAX ) return;

  fd_rwlock_write( &stake_delegations->lock );

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fork_map_t *            fork_map   = get_fork_map( stake_delegations, fork_idx );

  fork_map_iter_t iter = fork_map_iter_init( fork_map, delta_pool );
  while( !fork_map_iter_done( iter, fork_map, delta_pool ) ) {
    fd_stake_delegation_t * ele = fork_map_iter_ele( iter, fork_map, delta_pool );
    iter = fork_map_iter_next( iter, fork_map, delta_pool );
    delta_pool_ele_release( delta_pool, ele );
  }
  fork_map_reset( fork_map );

  fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
  while( fork_pool[ fork_idx ].disk_delta_head!=UINT_MAX ) {
    disk_delta_remove( stake_delegations, fork_pool[ fork_idx ].disk_delta_head );
  }
  fork_pool[ fork_idx ].disk_delta_head = UINT_MAX;
  fork_pool_idx_release( fork_pool, fork_idx );

  fd_rwlock_unwrite( &stake_delegations->lock );
}

static void
apply_delta( ulong                           epoch,
             fd_stake_history_t const *      stake_history,
             ulong *                         warmup_cooldown_rate_epoch,
             int                             use_fixed_point_stake_math,
             int                             history_contiguous,
             int                             allow_temporary_disk_root,
             fd_stake_delegations_t *        stake_delegations,
             fd_stake_delegation_t const *   delta ) {
  fd_stake_delegation_t old_delegation;
  root_ref_t old_ref = root_lookup( stake_delegations, &delta->stake_account, &old_delegation );

  if( FD_LIKELY( !delta->is_tombstone ) ) {
    if( FD_LIKELY( !root_ref_is_none( old_ref ) ) ) {
      fd_stake_history_entry_t old_entry = fd_stake_delegation_activation_status(
          &old_delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
      stake_delegations->effective_stake    -= old_entry.effective;
      stake_delegations->activating_stake   -= old_entry.activating;
      stake_delegations->deactivating_stake -= old_entry.deactivating;
    }

    root_ref_t new_ref = root_update(
        stake_delegations,
        &delta->stake_account,
        &delta->vote_account,
        delta->stake,
        delta->activation_epoch==(ushort)USHORT_MAX   ? ULONG_MAX : delta->activation_epoch,
        delta->deactivation_epoch==(ushort)USHORT_MAX ? ULONG_MAX : delta->deactivation_epoch,
        delta->credits_observed,
        delta->lamports,
        delta->acc_dlen,
        delta->warmup_cooldown_rate,
        allow_temporary_disk_root );

    fd_stake_history_entry_t new_entry = fd_stake_delegation_activation_status(
        delta, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    stake_delegations->effective_stake    += new_entry.effective;
    stake_delegations->activating_stake   += new_entry.activating;
    stake_delegations->deactivating_stake += new_entry.deactivating;

    fd_stake_delegation_t root_delegation;
    if( FD_LIKELY( new_ref.ram ) ) root_delegation = *new_ref.ram;
    else                           disk_root_read( stake_delegations, new_ref.disk_idx, &root_delegation );
    root_delegation.state = history_contiguous
                            ? fd_stake_delegation_classify( &root_delegation, new_entry, epoch )
                            : FD_STAKE_DELEGATION_STATE_UNKNOWN;
    root_store( stake_delegations, new_ref, &root_delegation );
    if( FD_LIKELY( root_delegation.state==FD_STAKE_DELEGATION_STATE_WARMED && !use_fixed_point_stake_math ) ) {
      stake_delegations->fp_warmed_awarded = 1;
    }
    return;
  }

  if( FD_LIKELY( !root_ref_is_none( old_ref ) ) ) {
    fd_stake_history_entry_t old_entry = fd_stake_delegation_activation_status(
        &old_delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    stake_delegations->effective_stake    -= old_entry.effective;
    stake_delegations->activating_stake   -= old_entry.activating;
    stake_delegations->deactivating_stake -= old_entry.deactivating;
    root_remove( stake_delegations, old_ref );
  }
}

static void
apply_fork_delta( ulong                                epoch,
                  fd_stake_history_t const *           stake_history,
                  ulong *                              warmup_cooldown_rate_epoch,
                  int                                  use_fixed_point_stake_math,
                  int                                  history_contiguous,
                  int                                  allow_temporary_disk_root,
                  fd_stake_delegations_t *             stake_delegations,
                  ushort                               fork_idx,
                  fd_stake_delegations_delta_stats_t * stake_delegations_delta_stats ) {
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fork_map_t *            fork_map   = get_fork_map( stake_delegations, fork_idx );
  ulong                   upserts    = 0UL;
  ulong                   removes    = 0UL;

  /* Consume disk deltas first.  This both bounds traversal by the
     occupied per-fork list and frees a disk slot before a new disk root
     might be needed. */
  fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
  while( fork_pool[ fork_idx ].disk_delta_head!=UINT_MAX ) {
    uint disk_idx = fork_pool[ fork_idx ].disk_delta_head;
    disk_delta_t disk_delta;
    disk_delta_read( stake_delegations, disk_idx, &disk_delta );
    fd_stake_delegation_t delegation = disk_delta.delegation;
    disk_delta_remove( stake_delegations, disk_idx );
    upserts += (ulong)!delegation.is_tombstone;
    removes += (ulong)!!delegation.is_tombstone;
    apply_delta( epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math,
                 history_contiguous, allow_temporary_disk_root, stake_delegations, &delegation );
  }

  /* RAM deltas do not themselves consume disk capacity.  Apply
     tombstones first so insertions cannot transiently exhaust a disk
     budget that the final rooted state fits within. */
  for( int apply_tombstones=1; apply_tombstones>=0; apply_tombstones-- ) {
    for( fork_map_iter_t iter = fork_map_iter_init( fork_map, delta_pool );
         !fork_map_iter_done( iter, fork_map, delta_pool );
         iter = fork_map_iter_next( iter, fork_map, delta_pool ) ) {
      fd_stake_delegation_t * delegation = fork_map_iter_ele( iter, fork_map, delta_pool );
      if( !!delegation->is_tombstone!=apply_tombstones ) continue;
      upserts += (ulong)!delegation->is_tombstone;
      removes += (ulong)!!delegation->is_tombstone;
      apply_delta( epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math,
                   history_contiguous, allow_temporary_disk_root, stake_delegations, delegation );
    }
  }

  if( FD_UNLIKELY( stake_delegations_delta_stats ) ) {
    stake_delegations_delta_stats->upserts += upserts;
    stake_delegations_delta_stats->removes += removes;
  }
}

static void
disk_root_commit_temporaries( fd_stake_delegations_t * stake_delegations ) {
  if( FD_LIKELY( !stake_delegations->disk_temp_root_cnt_ ) ) return;

  FD_CHECK_CRIT( stake_delegations->frontier_query_epoch==ULONG_MAX,
                 "cannot commit temporary stake delegation roots during a frontier query" );

  fd_stake_delegation_t * root_pool = get_root_pool( stake_delegations );
  while( root_pool_free( root_pool ) && stake_delegations->disk_root_cnt_ ) {
    uint idx = (uint)(stake_delegations->disk_root_cnt_-1UL);
    fd_stake_delegation_t delegation;
    disk_root_read( stake_delegations, idx, &delegation );

    fd_stake_delegation_t promoted = delegation;
    promoted.dne_in_root = 0;
    root_insert( stake_delegations, &promoted, 0 );

    uint  found_idx;
    ulong bucket_slot;
    ulong free_slot;
    disk_root_find( stake_delegations, &delegation.stake_account, NULL, &found_idx, &bucket_slot, &free_slot );
    FD_CHECK_CRIT( found_idx==idx, "missing promoted stake delegation temporary root" );
    disk_root_remove( stake_delegations, idx, bucket_slot );
  }

  if( FD_LIKELY( !stake_delegations->disk_temp_root_cnt_ ) ) return;
  FD_CHECK_CRIT( stake_delegations->disk_root_cnt_<=stake_delegations->max_disk_records_,
                 "rooted stake delegation disk root spill exhausted" );

  ulong temporary_cnt = 0UL;
  for( uint idx=0U; (ulong)idx<stake_delegations->disk_root_cnt_; idx++ ) {
    fd_stake_delegation_t delegation;
    disk_root_read( stake_delegations, idx, &delegation );
    if( FD_LIKELY( !delegation.dne_in_root ) ) continue;
    delegation.dne_in_root = 0;
    disk_root_write( stake_delegations, idx, &delegation );
    temporary_cnt++;
  }
  FD_CHECK_CRIT( temporary_cnt==stake_delegations->disk_temp_root_cnt_,
                 "corrupt stake delegation temporary root count" );
  stake_delegations->disk_temp_root_cnt_ = 0UL;
}

void
fd_stake_delegations_apply_fork_deltas( ulong                                epoch,
                                        fd_stake_history_t const *           stake_history,
                                        ulong *                              warmup_cooldown_rate_epoch,
                                        int                                  use_fixed_point_stake_math,
                                        fd_stake_delegations_t *             stake_delegations,
                                        ushort const *                       fork_ids,
                                        ulong                                fork_id_cnt,
                                        fd_stake_delegations_delta_stats_t * stake_delegations_delta_stats ) {
  fd_rwlock_write( &stake_delegations->lock );

  int history_contiguous = fd_sysvar_stake_history_is_contiguous( stake_history );
  for( ulong i=0UL; i<fork_id_cnt; i++ ) {
    apply_fork_delta( epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math,
                      history_contiguous, 1, stake_delegations, fork_ids[ i ], stake_delegations_delta_stats );
  }
  disk_root_commit_temporaries( stake_delegations );
  if( FD_UNLIKELY( stake_delegations_delta_stats ) ) {
    stake_delegations_delta_stats->root_cnt =
        root_pool_used( get_root_pool( stake_delegations ) ) + stake_delegations->disk_root_cnt_;
  }
  FD_LOG_DEBUG(( "effective_stake=%lu, activating_stake=%lu, deactivating_stake=%lu", stake_delegations->effective_stake, stake_delegations->activating_stake, stake_delegations->deactivating_stake ));

  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_iter_read_disk_delta( fd_stake_delegations_iter_t * iter,
                                           uint                          delta_idx ) {
  FD_CHECK_CRIT( (ulong)delta_idx<iter->stake_delegations->disk_delta_cnt_,
                 "invalid stake delegation iterator disk delta" );
  disk_delta_t delta;
  disk_delta_read( iter->stake_delegations, delta_idx, &delta );
  iter->disk_ele = delta.delegation;
  iter->ele = iter->disk_ele.is_tombstone ? NULL : &iter->disk_ele;
}

void
fd_stake_delegations_iter_advance_disk_root( fd_stake_delegations_iter_t * iter ) {
  fd_stake_delegations_t const * stake_delegations = iter->stake_delegations;
  while( iter->disk_idx<stake_delegations->disk_root_cnt_ ) {
    disk_root_read( stake_delegations, (uint)iter->disk_idx, &iter->disk_ele );
    iter->idx = stake_delegations->max_stake_accounts_ + iter->disk_idx;

    uint delta_idx = iter->disk_ele.delta_idx;
    if( FD_LIKELY( delta_idx==UINT_MAX ) ) {
      iter->ele = &iter->disk_ele;
      return;
    }
    if( FD_UNLIKELY( delta_idx & FD_STAKE_DELEGATIONS_DELTA_DISK_TAG ) ) {
      fd_stake_delegations_iter_read_disk_delta( iter, delta_idx & FD_STAKE_DELEGATIONS_DELTA_IDX_MASK );
      if( FD_LIKELY( iter->ele ) ) return;
    } else {
      fd_stake_delegation_t * delta = iter->delta_pool + delta_idx;
      if( FD_LIKELY( !delta->is_tombstone ) ) {
        iter->ele = delta;
        return;
      }
    }
    iter->disk_idx++;
  }
  iter->ele = NULL;
}

fd_stake_delegations_iter_t *
fd_stake_delegations_iter_init( fd_stake_delegations_iter_t *  iter,
                                fd_stake_delegations_t const * stake_delegations ) {
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "NULL stake_delegations" ));
  }

  iter->root_pool         = get_root_pool( stake_delegations );
  iter->delta_pool        = get_delta_pool( stake_delegations );
  iter->stake_delegations = stake_delegations;
  iter->idx               = 0UL;
  iter->wmk               = stake_delegations->pool_idx_wmk_;
  iter->disk_idx          = 0UL;
  fd_stake_delegations_iter_advance_private( iter );

  return iter;
}

static fd_stake_delegation_t const *
delta_ref_query( fd_stake_delegations_t const * stake_delegations,
                 uint                          delta_ref,
                 fd_stake_delegation_t *        disk_copy ) {
  if( FD_UNLIKELY( delta_ref & FD_STAKE_DELEGATIONS_DELTA_DISK_TAG ) ) {
    uint idx = delta_ref & FD_STAKE_DELEGATIONS_DELTA_IDX_MASK;
    FD_CHECK_CRIT( (ulong)idx<stake_delegations->disk_delta_cnt_, "invalid stake delegation disk delta reference" );
    disk_delta_t disk_delta;
    disk_delta_read( stake_delegations, idx, &disk_delta );
    *disk_copy = disk_delta.delegation;
    return disk_copy;
  }
  return get_delta_pool( stake_delegations ) + delta_ref;
}

static void
mark_delta_one( fd_stake_delegations_t *      stake_delegations,
                ulong                         epoch,
                fd_stake_history_t const *    stake_history,
                ulong *                       warmup_cooldown_rate_epoch,
                int                           use_fixed_point_stake_math,
                fd_stake_delegation_t const * delta,
                uint                          delta_ref ) {
  fd_stake_delegation_t base;
  root_ref_t base_ref = root_lookup( stake_delegations, &delta->stake_account, &base );
  if( FD_UNLIKELY( root_ref_is_none( base_ref ) ) ) {
    fd_memset( &base, 0, sizeof(base) );
    base.stake_account = delta->stake_account;
    base.next_         = UINT_MAX;
    base.delta_idx     = delta_ref;
    base.dne_in_root   = 1;
    base.in_use        = 1;
    base.state         = FD_STAKE_DELEGATION_STATE_UNKNOWN;
    root_insert( stake_delegations, &base, 1 );
  } else {
    fd_stake_delegation_t disk_copy;
    fd_stake_delegation_t const * old = base.delta_idx==UINT_MAX
                                        ? &base
                                        : delta_ref_query( stake_delegations, base.delta_idx, &disk_copy );
    if( FD_LIKELY( !old->is_tombstone ) ) {
      fd_stake_history_entry_t old_entry = fd_stake_delegation_activation_status(
          old, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
      stake_delegations->effective_stake    -= old_entry.effective;
      stake_delegations->activating_stake   -= old_entry.activating;
      stake_delegations->deactivating_stake -= old_entry.deactivating;
    }
    base.delta_idx = delta_ref;
    root_store( stake_delegations, base_ref, &base );
  }

  if( FD_LIKELY( !delta->is_tombstone ) ) {
    fd_stake_history_entry_t new_entry = fd_stake_delegation_activation_status(
        delta, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    stake_delegations->effective_stake    += new_entry.effective;
    stake_delegations->activating_stake   += new_entry.activating;
    stake_delegations->deactivating_stake += new_entry.deactivating;
  }
}

static void
unmark_delta_one( fd_stake_delegations_t *      stake_delegations,
                  ulong                         epoch,
                  fd_stake_history_t const *    stake_history,
                  ulong *                       warmup_cooldown_rate_epoch,
                  int                           use_fixed_point_stake_math,
                  fd_stake_delegation_t const * delta,
                  uint                          delta_ref ) {
  fd_stake_delegation_t base;
  root_ref_t base_ref = root_lookup( stake_delegations, &delta->stake_account, &base );
  if( FD_UNLIKELY( root_ref_is_none( base_ref ) || base.delta_idx!=delta_ref ) ) return;

  if( FD_LIKELY( !delta->is_tombstone ) ) {
    fd_stake_history_entry_t entry = fd_stake_delegation_activation_status(
        delta, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    stake_delegations->effective_stake    -= entry.effective;
    stake_delegations->activating_stake   -= entry.activating;
    stake_delegations->deactivating_stake -= entry.deactivating;
  }

  if( FD_UNLIKELY( base.dne_in_root ) ) {
    root_remove( stake_delegations, base_ref );
    return;
  }

  base.delta_idx = UINT_MAX;
  root_store( stake_delegations, base_ref, &base );
  fd_stake_history_entry_t entry = fd_stake_delegation_activation_status(
      &base, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
  stake_delegations->effective_stake    += entry.effective;
  stake_delegations->activating_stake   += entry.activating;
  stake_delegations->deactivating_stake += entry.deactivating;
}

static void
fd_stake_delegations_mark_delta( fd_stake_delegations_t *   stake_delegations,
                                 ulong                      epoch,
                                 fd_stake_history_t const * stake_history,
                                 ulong *                    warmup_cooldown_rate_epoch,
                                 int                        use_fixed_point_stake_math,
                                 ushort                     fork_idx ) {
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fork_map_t *            fork_map   = get_fork_map( stake_delegations, fork_idx );

  for( fork_map_iter_t iter = fork_map_iter_init( fork_map, delta_pool );
       !fork_map_iter_done( iter, fork_map, delta_pool );
       iter = fork_map_iter_next( iter, fork_map, delta_pool ) ) {
    fd_stake_delegation_t * delta_delegation = fork_map_iter_ele( iter, fork_map, delta_pool );
    uint delta_ref = (uint)delta_pool_idx( delta_pool, delta_delegation );
    mark_delta_one( stake_delegations, epoch, stake_history, warmup_cooldown_rate_epoch,
                    use_fixed_point_stake_math, delta_delegation, delta_ref );
  }

  uint disk_idx = get_fork_pool( stake_delegations )[ fork_idx ].disk_delta_head;
  while( disk_idx!=UINT_MAX ) {
    disk_delta_t disk_delta;
    disk_delta_read( stake_delegations, disk_idx, &disk_delta );
    mark_delta_one( stake_delegations, epoch, stake_history, warmup_cooldown_rate_epoch,
                    use_fixed_point_stake_math, &disk_delta.delegation,
                    disk_idx | FD_STAKE_DELEGATIONS_DELTA_DISK_TAG );
    disk_idx = disk_delta.next;
  }
}

static void
fd_stake_delegations_unmark_delta( fd_stake_delegations_t *   stake_delegations,
                                   ulong                      epoch,
                                   fd_stake_history_t const * stake_history,
                                   ulong *                    warmup_cooldown_rate_epoch,
                                   int                        use_fixed_point_stake_math,
                                   ushort                     fork_idx ) {
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fork_map_t *            fork_map   = get_fork_map( stake_delegations, fork_idx );

  for( fork_map_iter_t iter = fork_map_iter_init( fork_map, delta_pool );
       !fork_map_iter_done( iter, fork_map, delta_pool );
       iter = fork_map_iter_next( iter, fork_map, delta_pool ) ) {
    fd_stake_delegation_t * delta_delegation = fork_map_iter_ele( iter, fork_map, delta_pool );
    uint delta_ref = (uint)delta_pool_idx( delta_pool, delta_delegation );
    unmark_delta_one( stake_delegations, epoch, stake_history, warmup_cooldown_rate_epoch,
                      use_fixed_point_stake_math, delta_delegation, delta_ref );
  }

  uint disk_idx = get_fork_pool( stake_delegations )[ fork_idx ].disk_delta_head;
  while( disk_idx!=UINT_MAX ) {
    disk_delta_t disk_delta;
    disk_delta_read( stake_delegations, disk_idx, &disk_delta );
    unmark_delta_one( stake_delegations, epoch, stake_history, warmup_cooldown_rate_epoch,
                      use_fixed_point_stake_math, &disk_delta.delegation,
                      disk_idx | FD_STAKE_DELEGATIONS_DELTA_DISK_TAG );
    disk_idx = disk_delta.next;
  }
}

void
fd_stake_delegations_frontier_query_begin( fd_stake_delegations_t *   stake_delegations,
                                           ulong                      epoch,
                                           fd_stake_history_t const * stake_history,
                                           ulong *                    warmup_cooldown_rate_epoch,
                                           int                        use_fixed_point_stake_math,
                                           ushort const *             fork_ids,
                                           ulong                      fork_id_cnt ) {
  fd_rwlock_write( &stake_delegations->lock );
  stake_delegations->frontier_query_epoch = epoch;
  for( ulong i=0UL; i<fork_id_cnt; i++ ) {
    fd_stake_delegations_mark_delta( stake_delegations,
                                     epoch,
                                     stake_history,
                                     warmup_cooldown_rate_epoch,
                                     use_fixed_point_stake_math,
                                     fork_ids[ i ] );
  }
}

void
fd_stake_delegations_frontier_query_end( fd_stake_delegations_t *   stake_delegations,
                                         fd_stake_history_t const * stake_history,
                                         ulong *                    warmup_cooldown_rate_epoch,
                                         int                        use_fixed_point_stake_math,
                                         ushort const *             fork_ids,
                                         ulong                      fork_id_cnt ) {
  for( ulong i=0UL; i<fork_id_cnt; i++ ) {
    fd_stake_delegations_unmark_delta( stake_delegations,
                                       stake_delegations->frontier_query_epoch,
                                       stake_history,
                                       warmup_cooldown_rate_epoch,
                                       use_fixed_point_stake_math,
                                       fork_ids[ i ] );
  }
  stake_delegations->frontier_query_epoch = ULONG_MAX;
  disk_root_maintain( stake_delegations );
  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_invalidate_warmed( fd_stake_delegations_t * stake_delegations ) {
  fd_stake_delegation_t * root_pool = get_root_pool( stake_delegations );
  for( ulong i=0UL; i<stake_delegations->pool_idx_wmk_; i++ ) {
    fd_stake_delegation_t * delegation = &root_pool[ i ];
    if( FD_LIKELY( delegation->in_use && delegation->state==FD_STAKE_DELEGATION_STATE_WARMED ) ) {
      delegation->state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
    }
  }
  for( uint i=0U; (ulong)i<stake_delegations->disk_root_cnt_; i++ ) {
    fd_stake_delegation_t delegation;
    disk_root_read( stake_delegations, i, &delegation );
    if( FD_LIKELY( delegation.state==FD_STAKE_DELEGATION_STATE_WARMED ) ) {
      delegation.state = FD_STAKE_DELEGATION_STATE_UNKNOWN;
      disk_root_write( stake_delegations, i, &delegation );
    }
  }
  stake_delegations->fp_warmed_awarded = 0;
}
