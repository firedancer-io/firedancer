#include "fd_stake_delegations.h"
#include "../fd_rwlock.h"
#include "fd_stakes.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../events/fd_event_runtime.h"
#include "../../util/fd_hash32.h"

#include <errno.h>
#include <unistd.h>

struct fd_stake_delegations {
  ulong magic;
  ulong seed_;
  ulong max_stake_accounts_;

  /* Root map + pool */
  ulong map_offset_;
  ulong pool_offset_;
  ulong pool_idx_wmk_; /* One past the highest root pool index ever acquired.  Every index in
                          [0, wmk) has been acquired at least once, so its in_use byte is
                          well defined. */

  /* Delta map + pool and fork pool */
  ulong delta_pool_offset_;
  ulong fork_pool_offset_;
  ulong delta_map_offset_;

  /* Guards every mutating operation on the struct. */
  fd_rwlock_t lock;

  /* File descriptor number for this instance's backing file.
     Every process joining this object must map the same file at this
     descriptor number for the object's lifetime. */
  int disk_fd_;

  /* Management for stake delegations that spill to disk. */
  ulong max_disk_records_;        /* disk delta capacity; disk root capacity is derived */
  ulong disk_root_cnt_;           /* number of disk-backed root records */
  ulong disk_delta_cnt_;
  ulong disk_bucket_cnt_;         /* pow2 buckets in each disk hash index */
  ulong disk_root_tombstone_cnt_;
  ulong disk_delta_tombstone_cnt_;
  uint  disk_root_gen_;           /* buckets with an older generation are empty */
  uint  disk_delta_gen_;

  /* Stake totals for the current root. */
  ulong effective_stake;
  ulong activating_stake;
  ulong deactivating_stake;

  /* Epoch and target fork of the active frontier query. */
  ulong  frontier_query_epoch;
  ushort frontier_query_fork;

  /* Only relevant around upgrade_bpf_stake_program_to_v5_1 activation.
     See comment at consumer of this flag for why it's needed.  Remove
     after the feature activates on all clusters. */
  uchar fp_warmed_awarded;
};

/* map/pool pair to represent in-memory state */
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

/* pool/map pair to represent in-memory delta state */
#define POOL_NAME  delta_pool
#define POOL_T     fd_stake_delegation_t
#define POOL_NEXT  next_
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               delta_map
#define MAP_KEY_T              fd_stake_delegation_key_t
#define MAP_ELE_T              fd_stake_delegation_t
#define MAP_KEY                key
#define MAP_KEY_EQ(k0,k1)      ((k0)->fork_idx==(k1)->fork_idx && fd_pubkey_eq( &(k0)->stake_account, &(k1)->stake_account ))
#define MAP_KEY_HASH(key,seed) (fd_hash32( (key)->stake_account.uc, (seed) ^ (ulong)(key)->fork_idx ))
#define MAP_NEXT               next_
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

/* Pool/map pair for fork ids.  Just holds metadata. */
struct fork_pool_ele {
  ushort next;
  ushort parent;
  uint   delta_head;
  uint   disk_delta_head;
};
typedef struct fork_pool_ele fork_pool_ele_t;

FD_STATIC_ASSERT( sizeof(fork_pool_ele_t)==12UL, fork_pool_ele_size );

/* A live parent is a fork index or USHORT_MAX for the rooted state. */
#define FORK_PARENT_FREE ((ushort)FD_STAKE_DELEGATIONS_FORK_MAX)

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

static inline delta_map_t *
get_delta_map( fd_stake_delegations_t const * stake_delegations ) {
  return fd_type_pun( (uchar *)stake_delegations + stake_delegations->delta_map_offset_ );
}

/* Collect leaf to root; callers process the result in reverse order. */
static ulong
fork_ancestry( fd_stake_delegations_t const * stake_delegations,
               ushort                        fork_idx,
               ushort *                      fork_ids ) {
  fork_pool_ele_t const * fork_pool = get_fork_pool( stake_delegations );
  ulong max_forks = fork_pool_max( fork_pool );
  ulong cnt       = 0UL;
  for( ; fork_idx!=USHORT_MAX; fork_idx=fork_pool[ fork_idx ].parent ) {
    FD_CHECK_CRIT( cnt<max_forks && (ulong)fork_idx<max_forks && fork_pool[ fork_idx ].parent!=FORK_PARENT_FREE,
                   "invalid stake delegation ancestry" );
    fork_ids[ cnt++ ] = fork_idx;
  }
  return cnt;
}

/* The spill file contains two compact open-addressed indexes followed
   by dense root and delta record arrays.  Index generations make reset
   O(1).  Root and delta indexes are separate so root mutation while
   applying a fork cannot disturb traversal of that fork's deltas. */

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
};
typedef struct disk_delta disk_delta_t;

FD_STATIC_ASSERT( sizeof(disk_bucket_t)==8UL, disk_bucket );
FD_STATIC_ASSERT( sizeof(disk_delta_t)==128UL, disk_delta );
FD_STATIC_ASSERT( offsetof( disk_delta_t, delegation )==  0UL, disk_delta );
FD_STATIC_ASSERT( offsetof( disk_delta_t, next       )==112UL, disk_delta );
FD_STATIC_ASSERT( offsetof( disk_delta_t, prev       )==116UL, disk_delta );
FD_STATIC_ASSERT( offsetof( disk_delta_t, fork_idx   )==120UL, disk_delta );

static inline ulong
disk_root_record_cap( fd_stake_delegations_t const * stake_delegations ) {
  return 2UL*stake_delegations->max_disk_records_ + stake_delegations->max_stake_accounts_;
}

static inline ulong
disk_delta_bucket_off( fd_stake_delegations_t const * stake_delegations ) {
  return stake_delegations->disk_bucket_cnt_*sizeof(disk_bucket_t);
}

static inline ulong
disk_root_record_off( fd_stake_delegations_t const * stake_delegations ) {
  return fd_ulong_align_up( 2UL*stake_delegations->disk_bucket_cnt_*sizeof(disk_bucket_t), alignof(fd_stake_delegation_t) );
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
disk_read( fd_stake_delegations_t const * stake_delegations,
           void *                         dst,
           ulong                          off,
           ulong                          sz ) {
  ulong got = 0UL;
  while( got<sz ) {
    long n = pread( stake_delegations->disk_fd_, (uchar *)dst+got, sz-got, (long)(off+got) );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      FD_LOG_CRIT(( "pread(stake delegation spill file, fd=%d) failed (%i-%s)", stake_delegations->disk_fd_, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( !n ) ) break;
    got += (ulong)n;
  }
  if( FD_UNLIKELY( got<sz ) ) fd_memset( (uchar *)dst+got, 0, sz-got );
}

static void
disk_write( fd_stake_delegations_t const * stake_delegations,
            void const *                   src,
            ulong                          off,
            ulong                          sz ) {
  ulong put = 0UL;
  while( put<sz ) {
    long n = pwrite( stake_delegations->disk_fd_, (uchar const *)src+put, sz-put, (long)(off+put) );
    if( FD_LIKELY( n>0L ) ) { put += (ulong)n; continue; }
    if( FD_UNLIKELY( n<0L && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( !n ) ) errno = EIO;
    FD_LOG_CRIT(( "pwrite(stake delegation spill file, fd=%d) failed (%i-%s)", stake_delegations->disk_fd_, errno, fd_io_strerror( errno ) ));
  }
}

static inline int
disk_bucket_is_empty( disk_bucket_t const * bucket,
                      uint                  gen ) {
  return bucket->gen!=gen;
}

static inline int
disk_bucket_is_tombstone( disk_bucket_t const * bucket,
                          uint                  gen ) {
  return bucket->gen==gen && bucket->idx==DISK_BUCKET_TOMBSTONE;
}

static inline ulong
disk_bucket_off( ulong base,
                 ulong bucket_idx ) {
  return base + bucket_idx*sizeof(disk_bucket_t);
}

static void
disk_bucket_store( fd_stake_delegations_t const * stake_delegations,
                   ulong                          base,
                   ulong                          bucket_idx,
                   uint                           gen,
                   uint                           idx ) {
  disk_bucket_t bucket = {
    .idx = idx,
    .gen = gen,
  };
  disk_write( stake_delegations, &bucket, disk_bucket_off( base, bucket_idx ), sizeof(disk_bucket_t) );
}

static void
disk_root_read( fd_stake_delegations_t const * stake_delegations,
                uint                           idx,
                fd_stake_delegation_t *        delegation ) {
  disk_read( stake_delegations, delegation,
             disk_root_record_off( stake_delegations ) + (ulong)idx*sizeof(fd_stake_delegation_t),
             sizeof(fd_stake_delegation_t) );
}

static void
disk_root_write( fd_stake_delegations_t const * stake_delegations,
                 uint                           idx,
                 fd_stake_delegation_t const *  delegation ) {
  disk_write( stake_delegations, delegation,
              disk_root_record_off( stake_delegations ) + (ulong)idx*sizeof(fd_stake_delegation_t),
              sizeof(fd_stake_delegation_t) );
}

static void
disk_delta_read( fd_stake_delegations_t const * stake_delegations,
                 uint                           idx,
                 disk_delta_t *                 delta ) {
  disk_read( stake_delegations, delta,
             disk_delta_record_off( stake_delegations ) + (ulong)idx*sizeof(disk_delta_t),
             sizeof(disk_delta_t) );
}

static void
disk_delta_write( fd_stake_delegations_t const * stake_delegations,
                  uint                           idx,
                  disk_delta_t const *           delta ) {
  disk_write( stake_delegations, delta,
              disk_delta_record_off( stake_delegations ) + (ulong)idx*sizeof(disk_delta_t),
              sizeof(disk_delta_t) );
}

static void
disk_root_find( fd_stake_delegations_t const * stake_delegations,
                fd_pubkey_t const *            stake_account,
                fd_stake_delegation_t *        delegation,
                uint *                         idx,
                ulong *                        found_bucket_idx,
                ulong *                        free_bucket_idx ) {
  /* Default to not found and no reusable bucket. */
  *idx              = UINT_MAX;
  *found_bucket_idx = ULONG_MAX;
  *free_bucket_idx  = ULONG_MAX;
  ulong bucket_cnt = stake_delegations->disk_bucket_cnt_;

  /* Hash the stake account to its initial bucket. */
  ulong bucket_idx = (ulong)fd_hash32( stake_account->uc, stake_delegations->seed_ ) & (bucket_cnt-1UL);
  ulong base       = 0UL;
  for( ulong probe=0UL; probe<bucket_cnt; probe++ ) {
    disk_bucket_t bucket;
    disk_read( stake_delegations, &bucket, disk_bucket_off( base, bucket_idx ), sizeof(disk_bucket_t) );

    /* An empty bucket ends the search and can be reused for insertion. */
    if( FD_UNLIKELY( disk_bucket_is_empty( &bucket, stake_delegations->disk_root_gen_ ) ) ) {
      if( *free_bucket_idx==ULONG_MAX ) *free_bucket_idx = bucket_idx;
      return;
    }

    /* Remember the first tombstone, but keep searching past it.  If the
       record doesn't exist already, the tombstone will be used. */
    if( FD_UNLIKELY( bucket.idx==DISK_BUCKET_TOMBSTONE ) ) {
      if( *free_bucket_idx==ULONG_MAX ) *free_bucket_idx = bucket_idx;
    } else {
      /* A live bucket points to a record in the dense disk array. */
      FD_CHECK_CRIT( (ulong)bucket.idx<stake_delegations->disk_root_cnt_, "corrupt stake delegation disk root index" );
      fd_stake_delegation_t candidate;
      disk_root_read( stake_delegations, bucket.idx, &candidate );
      if( FD_UNLIKELY( fd_pubkey_eq( &candidate.stake_account, stake_account ) ) ) {
        /* Return the record and both of its disk locations. */
        if( delegation ) *delegation = candidate;
        *idx              = bucket.idx;
        *found_bucket_idx = bucket_idx;
        return;
      }
    }

    /* Resolve a collision by advancing, wrapping at the table end. */
    bucket_idx = (bucket_idx+1UL) & (bucket_cnt-1UL);
  }
}

struct disk_delta_query {
  uint  record_idx;   /* UINT_MAX if absent */
  ulong bucket_idx;   /* Matching entry or first reusable slot */
  int   is_tombstone; /* Reusable slot holds a deleted entry */
};
typedef struct disk_delta_query disk_delta_query_t;

static void
disk_delta_find( fd_stake_delegations_t const * stake_delegations,
                 ushort                         fork_idx,
                 fd_pubkey_t const *            stake_account,
                 disk_delta_t *                 delta,
                 disk_delta_query_t *           query ) {
  query->record_idx   = UINT_MAX;
  query->bucket_idx   = ULONG_MAX;
  query->is_tombstone = 0;
  ulong bucket_cnt = stake_delegations->disk_bucket_cnt_;
  ulong seed       = stake_delegations->seed_ ^ (ulong)fork_idx;
  ulong bucket_idx = (ulong)fd_hash32( stake_account->uc, seed ) & (bucket_cnt-1UL);
  ulong base       = disk_delta_bucket_off( stake_delegations );
  for( ulong probe=0UL; probe<bucket_cnt; probe++ ) {
    disk_bucket_t bucket;
    disk_read( stake_delegations, &bucket, disk_bucket_off( base, bucket_idx ), sizeof(disk_bucket_t) );
    if( FD_UNLIKELY( disk_bucket_is_empty( &bucket, stake_delegations->disk_delta_gen_ ) ) ) {
      if( query->bucket_idx==ULONG_MAX ) query->bucket_idx = bucket_idx;
      return;
    }
    if( FD_UNLIKELY( bucket.idx==DISK_BUCKET_TOMBSTONE ) ) {
      if( query->bucket_idx==ULONG_MAX ) {
        query->bucket_idx   = bucket_idx;
        query->is_tombstone = 1;
      }
    } else {
      FD_CHECK_CRIT( (ulong)bucket.idx<stake_delegations->disk_delta_cnt_, "corrupt stake delegation disk delta index" );
      disk_delta_t candidate;
      disk_delta_read( stake_delegations, bucket.idx, &candidate );
      if( FD_UNLIKELY( candidate.fork_idx==fork_idx &&
                       fd_pubkey_eq( &candidate.delegation.stake_account, stake_account ) ) ) {
        if( delta ) *delta = candidate;
        query->record_idx   = bucket.idx;
        query->bucket_idx   = bucket_idx;
        query->is_tombstone = 0;
        return;
      }
    }
    bucket_idx = (bucket_idx+1UL) & (bucket_cnt-1UL);
  }
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
                          ulong bucket_cnt ) {
  return tombstone_cnt>live_cnt || tombstone_cnt>(bucket_cnt>>2);
}

static void
disk_root_rebuild( fd_stake_delegations_t * stake_delegations ) {
  stake_delegations->disk_root_gen_ = disk_gen_next( stake_delegations->disk_root_gen_ );
  stake_delegations->disk_root_tombstone_cnt_ = 0UL;

  for( uint idx=0U; (ulong)idx<stake_delegations->disk_root_cnt_; idx++ ) {
    fd_stake_delegation_t delegation;
    disk_root_read( stake_delegations, idx, &delegation );

    uint  found_idx;
    ulong found_bucket_idx;
    ulong free_bucket_idx;
    disk_root_find( stake_delegations, &delegation.stake_account, NULL, &found_idx, &found_bucket_idx, &free_bucket_idx );
    FD_CHECK_CRIT( found_idx==UINT_MAX && free_bucket_idx!=ULONG_MAX, "unable to rebuild stake delegation disk root index" );
    disk_bucket_store( stake_delegations, 0UL, free_bucket_idx,
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

    disk_delta_query_t query;
    disk_delta_find( stake_delegations, delta.fork_idx, &delta.delegation.stake_account, NULL, &query );
    FD_CHECK_CRIT( query.record_idx==UINT_MAX && query.bucket_idx!=ULONG_MAX, "unable to rebuild stake delegation disk delta index" );
    disk_bucket_store( stake_delegations, disk_delta_bucket_off( stake_delegations ), query.bucket_idx,
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
                                             stake_delegations->disk_bucket_cnt_ ) ) ) {
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
                                             stake_delegations->disk_bucket_cnt_ ) ) ) {
    disk_delta_rebuild( stake_delegations );
  }
}

static void
disk_root_insert( fd_stake_delegations_t *      stake_delegations,
                  fd_stake_delegation_t const * delegation ) {
  FD_CHECK_CRIT( stake_delegations->disk_root_cnt_<disk_root_record_cap( stake_delegations ),
                 "stake delegation disk root spill exhausted" );

  uint  idx;
  ulong found_bucket_idx;
  ulong free_bucket_idx;
  disk_root_find( stake_delegations, &delegation->stake_account, NULL, &idx, &found_bucket_idx, &free_bucket_idx );
  FD_CHECK_CRIT( idx==UINT_MAX, "duplicate stake delegation disk root" );
  FD_CHECK_CRIT( free_bucket_idx!=ULONG_MAX, "stake delegation disk root index exhausted" );

  idx = (uint)stake_delegations->disk_root_cnt_;
  disk_root_write( stake_delegations, idx, delegation );
  disk_bucket_t free_bucket;
  disk_read( stake_delegations, &free_bucket, disk_bucket_off( 0UL, free_bucket_idx ), sizeof(disk_bucket_t) );
  if( FD_UNLIKELY( disk_bucket_is_tombstone( &free_bucket, stake_delegations->disk_root_gen_ ) ) ) {
    FD_CHECK_CRIT( stake_delegations->disk_root_tombstone_cnt_, "corrupt stake delegation disk root tombstone count" );
    stake_delegations->disk_root_tombstone_cnt_--;
  }
  disk_bucket_store( stake_delegations, 0UL, free_bucket_idx,
                     stake_delegations->disk_root_gen_, idx );
  stake_delegations->disk_root_cnt_++;
}

static void
disk_root_remove( fd_stake_delegations_t * stake_delegations,
                  uint                     idx,
                  ulong                    bucket_idx ) {
  FD_CHECK_CRIT( (ulong)idx<stake_delegations->disk_root_cnt_, "invalid stake delegation disk root removal" );
  disk_bucket_store( stake_delegations, 0UL, bucket_idx,
                     stake_delegations->disk_root_gen_, DISK_BUCKET_TOMBSTONE );

  uint last = (uint)(stake_delegations->disk_root_cnt_-1UL);
  if( FD_UNLIKELY( idx!=last ) ) {
    fd_stake_delegation_t moved;
    disk_root_read( stake_delegations, last, &moved );
    disk_root_write( stake_delegations, idx, &moved );

    uint  moved_idx;
    ulong moved_bucket_idx;
    ulong free_bucket_idx;
    disk_root_find( stake_delegations, &moved.stake_account, NULL, &moved_idx, &moved_bucket_idx, &free_bucket_idx );
    FD_CHECK_CRIT( moved_idx==last, "missing moved stake delegation disk root" );
    disk_bucket_store( stake_delegations, 0UL, moved_bucket_idx,
                       stake_delegations->disk_root_gen_, idx );
  }
  stake_delegations->disk_root_cnt_--;
  stake_delegations->disk_root_tombstone_cnt_++;
  disk_root_maintain( stake_delegations );
}

static void
disk_delta_insert( fd_stake_delegations_t *      stake_delegations,
                   ushort                        fork_idx,
                   fd_stake_delegation_t const * delegation,
                   disk_delta_query_t const *    query ) {
  disk_delta_record_reserve( stake_delegations );

  FD_CHECK_CRIT( query->bucket_idx!=ULONG_MAX, "stake delegation disk delta index exhausted" );

  uint idx = (uint)stake_delegations->disk_delta_cnt_;
  fork_pool_ele_t * fork = get_fork_pool( stake_delegations ) + fork_idx;
  disk_delta_t delta = {
    .delegation = *delegation,
    .next       = fork->disk_delta_head,
    .prev       = UINT_MAX,
    .fork_idx   = fork_idx,
  };
  disk_delta_write( stake_delegations, idx, &delta );
  if( FD_LIKELY( delta.next!=UINT_MAX ) ) {
    disk_write( stake_delegations, &idx,
                disk_delta_record_off( stake_delegations ) + (ulong)delta.next*sizeof(disk_delta_t) + offsetof(disk_delta_t, prev),
                sizeof(uint) );
  }
  if( FD_UNLIKELY( query->is_tombstone ) ) {
    FD_CHECK_CRIT( stake_delegations->disk_delta_tombstone_cnt_, "corrupt stake delegation disk delta tombstone count" );
    stake_delegations->disk_delta_tombstone_cnt_--;
  }
  disk_bucket_store( stake_delegations, disk_delta_bucket_off( stake_delegations ), query->bucket_idx,
                     stake_delegations->disk_delta_gen_, idx );
  fork->disk_delta_head = idx;
  stake_delegations->disk_delta_cnt_++;
}

static void
disk_delta_remove( fd_stake_delegations_t * stake_delegations,
                   uint                     idx,
                   disk_delta_t const *     removed ) {
  FD_CHECK_CRIT( (ulong)idx<stake_delegations->disk_delta_cnt_, "invalid stake delegation disk delta removal" );

  fork_pool_ele_t * fork = get_fork_pool( stake_delegations ) + removed->fork_idx;
  if( FD_LIKELY( removed->prev!=UINT_MAX ) ) {
    disk_write( stake_delegations, &removed->next,
                disk_delta_record_off( stake_delegations ) + (ulong)removed->prev*sizeof(disk_delta_t) + offsetof(disk_delta_t, next),
                sizeof(uint) );
  } else {
    fork->disk_delta_head = removed->next;
  }
  if( FD_LIKELY( removed->next!=UINT_MAX ) ) {
    disk_write( stake_delegations, &removed->prev,
                disk_delta_record_off( stake_delegations ) + (ulong)removed->next*sizeof(disk_delta_t) + offsetof(disk_delta_t, prev),
                sizeof(uint) );
  }

  disk_delta_query_t query;
  disk_delta_find( stake_delegations, removed->fork_idx, &removed->delegation.stake_account, NULL, &query );
  FD_CHECK_CRIT( query.record_idx==idx, "missing stake delegation disk delta removal" );
  disk_bucket_store( stake_delegations, disk_delta_bucket_off( stake_delegations ), query.bucket_idx,
                     stake_delegations->disk_delta_gen_, DISK_BUCKET_TOMBSTONE );

  uint last = (uint)(stake_delegations->disk_delta_cnt_-1UL);
  if( FD_UNLIKELY( idx!=last ) ) {
    disk_delta_t moved;
    disk_delta_read( stake_delegations, last, &moved );
    disk_delta_write( stake_delegations, idx, &moved );

    disk_delta_find( stake_delegations, moved.fork_idx, &moved.delegation.stake_account, NULL, &query );
    FD_CHECK_CRIT( query.record_idx==last, "missing moved stake delegation disk delta" );
    disk_bucket_store( stake_delegations, disk_delta_bucket_off( stake_delegations ), query.bucket_idx,
                       stake_delegations->disk_delta_gen_, idx );

    fork_pool_ele_t * moved_fork = get_fork_pool( stake_delegations ) + moved.fork_idx;
    if( FD_LIKELY( moved.prev!=UINT_MAX ) ) {
      disk_write( stake_delegations, &idx,
                  disk_delta_record_off( stake_delegations ) + (ulong)moved.prev*sizeof(disk_delta_t) + offsetof(disk_delta_t, next),
                  sizeof(uint) );
    } else {
      moved_fork->disk_delta_head = idx;
    }
    if( FD_LIKELY( moved.next!=UINT_MAX ) ) {
      disk_write( stake_delegations, &idx,
                  disk_delta_record_off( stake_delegations ) + (ulong)moved.next*sizeof(disk_delta_t) + offsetof(disk_delta_t, prev),
                  sizeof(uint) );
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

static inline ulong
fd_stake_delegations_delta_pool_ele_max( ulong root_ele_max ) {
  return fd_ulong_max( root_ele_max/FD_STAKE_DELEGATIONS_DELTA_POOL_DIVISOR, 1UL );
}

ulong
fd_stake_delegations_footprint( ulong max_stake_accounts,
                                ulong max_live_slots ) {
  ulong map_chain_cnt       = root_map_chain_cnt_est( max_stake_accounts );
  ulong delta_ele_max       = fd_stake_delegations_delta_pool_ele_max( max_stake_accounts );
  ulong delta_map_chain_cnt = delta_map_chain_cnt_est( delta_ele_max );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t) );
  l = FD_LAYOUT_APPEND( l, root_pool_align(),            root_pool_footprint( max_stake_accounts ) );
  l = FD_LAYOUT_APPEND( l, root_map_align(),             root_map_footprint( map_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, delta_pool_align(),           delta_pool_footprint( delta_ele_max ) );
  l = FD_LAYOUT_APPEND( l, fork_pool_align(),            fork_pool_footprint( max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, delta_map_align(),            delta_map_footprint( delta_map_chain_cnt ) );

  return FD_LAYOUT_FINI( l, fd_stake_delegations_align() );
}

void *
fd_stake_delegations_new( void * mem,
                          int    disk_fd,
                          ulong  seed,
                          ulong  max_stake_accounts,
                          ulong  max_disk_records,
                          ulong  max_live_slots ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( disk_fd<0 ) ) {
    FD_LOG_WARNING(( "invalid disk fd" ));
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

  if( FD_UNLIKELY( max_disk_records>=(ulong)FD_STAKE_DELEGATIONS_DELTA_DISK_TAG ) ) {
    FD_LOG_WARNING(( "max_disk_records is too large" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_stake_accounts>(ulong)FD_STAKE_DELEGATIONS_DELTA_IDX_MASK ||
                   max_disk_records>
                   ((ulong)FD_STAKE_DELEGATIONS_DELTA_IDX_MASK-max_stake_accounts)/2UL ) ) {
    FD_LOG_WARNING(( "combined stake delegation disk root capacity is too large" ));
    return NULL;
  }

  ulong map_chain_cnt       = root_map_chain_cnt_est( max_stake_accounts );
  ulong delta_ele_max       = fd_stake_delegations_delta_pool_ele_max( max_stake_accounts );
  ulong delta_map_chain_cnt = delta_map_chain_cnt_est( delta_ele_max );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_stake_delegations_t * stake_delegations = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t) );
  void *                   pool_mem          = FD_SCRATCH_ALLOC_APPEND( l, root_pool_align(),            root_pool_footprint( max_stake_accounts ) );
  void *                   map_mem           = FD_SCRATCH_ALLOC_APPEND( l, root_map_align(),             root_map_footprint( map_chain_cnt ) );
  void *                   delta_pool_mem    = FD_SCRATCH_ALLOC_APPEND( l, delta_pool_align(),           delta_pool_footprint( delta_ele_max ) );
  void *                   fork_pool_mem     = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),            fork_pool_footprint( max_live_slots ) );
  void *                   delta_map_mem     = FD_SCRATCH_ALLOC_APPEND( l, delta_map_align(),            delta_map_footprint( delta_map_chain_cnt ) );

  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_stake_delegations_align() )!=(ulong)mem+fd_stake_delegations_footprint( max_stake_accounts, max_live_slots ) ) ) {
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

  fd_stake_delegation_t * delta_pool = delta_pool_join( delta_pool_new( delta_pool_mem, delta_ele_max ) );
  if( FD_UNLIKELY( !delta_pool ) ) {
    FD_LOG_WARNING(( "Failed to create stake delegation delta pool" ));
    return NULL;
  }

  fork_pool_ele_t * fork_pool = fork_pool_join( fork_pool_new( fork_pool_mem, max_live_slots ) );
  if( FD_UNLIKELY( !fork_pool ) ) {
    FD_LOG_WARNING(( "Failed to create fork pool" ));
    return NULL;
  }

  for( ulong i=0UL; i<max_live_slots; i++ ) fork_pool[ i ].parent = FORK_PARENT_FREE;

  delta_map_t * delta_map = delta_map_join( delta_map_new( delta_map_mem, delta_map_chain_cnt, seed ) );
  if( FD_UNLIKELY( !delta_map ) ) {
    FD_LOG_WARNING(( "Failed to create delta map" ));
    return NULL;
  }

  stake_delegations->seed_                     = seed;
  stake_delegations->max_stake_accounts_       = max_stake_accounts;
  stake_delegations->pool_offset_              = (ulong)root_pool - (ulong)mem;
  stake_delegations->map_offset_               = (ulong)root_map - (ulong)mem;
  stake_delegations->delta_pool_offset_        = (ulong)delta_pool - (ulong)mem;
  stake_delegations->fork_pool_offset_         = (ulong)fork_pool - (ulong)mem;
  stake_delegations->delta_map_offset_         = (ulong)delta_map - (ulong)mem;
  stake_delegations->disk_fd_                  = disk_fd;
  stake_delegations->max_disk_records_         = max_disk_records;
  stake_delegations->disk_root_cnt_            = 0UL;
  stake_delegations->disk_delta_cnt_           = 0UL;
  ulong disk_root_cap                          = disk_root_record_cap( stake_delegations );
  stake_delegations->disk_bucket_cnt_          = fd_ulong_pow2_up( disk_root_cap + (disk_root_cap>>1) + 1UL );
  stake_delegations->disk_root_tombstone_cnt_  = 0UL;
  stake_delegations->disk_delta_tombstone_cnt_ = 0UL;
  stake_delegations->disk_root_gen_            = 1U;
  stake_delegations->disk_delta_gen_           = 1U;

  stake_delegations->effective_stake      = 0UL;
  stake_delegations->activating_stake     = 0UL;
  stake_delegations->deactivating_stake   = 0UL;
  stake_delegations->frontier_query_epoch = ULONG_MAX;
  stake_delegations->frontier_query_fork  = USHORT_MAX;
  stake_delegations->pool_idx_wmk_        = 0UL;
  stake_delegations->fp_warmed_awarded    = 0;

  fd_rwlock_new( &stake_delegations->lock );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( stake_delegations->magic ) = FD_STAKE_DELEGATIONS_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_stake_delegations_t *
fd_stake_delegations_join( void * mem,
                           int    disk_fd ) {
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

  if( FD_UNLIKELY( stake_delegations->disk_fd_!=disk_fd ) ) {
    FD_LOG_WARNING(( "stake delegations disk fd mismatch (expected %d, got %d)",
                     stake_delegations->disk_fd_, disk_fd ));
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
  delta_map_reset( get_delta_map( stake_delegations ) );
  fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
  ulong max_forks = fork_pool_max( fork_pool );
  for( ulong i=0UL; i<max_forks; i++ ) {
    fork_pool[ i ].parent          = FORK_PARENT_FREE;
    fork_pool[ i ].delta_head      = UINT_MAX;
    fork_pool[ i ].disk_delta_head = UINT_MAX;
  }
  fork_pool_reset( fork_pool );
  stake_delegations->disk_root_cnt_            = 0UL;
  stake_delegations->disk_delta_cnt_           = 0UL;
  stake_delegations->disk_root_tombstone_cnt_  = 0UL;
  stake_delegations->disk_delta_tombstone_cnt_ = 0UL;
  stake_delegations->disk_root_gen_            = disk_gen_next( stake_delegations->disk_root_gen_ );
  stake_delegations->disk_delta_gen_           = disk_gen_next( stake_delegations->disk_delta_gen_ );
  stake_delegations->effective_stake      = 0UL;
  stake_delegations->activating_stake     = 0UL;
  stake_delegations->deactivating_stake   = 0UL;
  stake_delegations->frontier_query_epoch = ULONG_MAX;
  stake_delegations->frontier_query_fork  = USHORT_MAX;
  stake_delegations->pool_idx_wmk_        = 0UL;
  stake_delegations->fp_warmed_awarded    = 0;
  fd_rwlock_unwrite( &stake_delegations->lock );
}

struct root_query {
  fd_stake_delegation_t * ele;
  ulong                   disk_bucket_idx;
  uint                    disk_idx;
  int                     is_disk;
  fd_stake_delegation_t   disk_ele;
};
typedef struct root_query root_query_t;

static int
root_query( fd_stake_delegations_t * stake_delegations,
            fd_pubkey_t const *      stake_account,
            root_query_t *           query ) {
  query->ele             = NULL;
  query->disk_bucket_idx = ULONG_MAX;
  query->disk_idx        = UINT_MAX;
  query->is_disk         = 0;

  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  root_map_t *            map  = get_root_map( stake_delegations );

  fd_stake_delegation_t * in_memory = root_map_ele_query( map, stake_account, NULL, pool );
  if( FD_LIKELY( in_memory ) ) {
    query->ele = in_memory;
    return 1;
  }

  if( FD_LIKELY( !stake_delegations->disk_root_cnt_ ) ) return 0;
  ulong free_bucket_idx;
  disk_root_find( stake_delegations, stake_account, &query->disk_ele,
                  &query->disk_idx, &query->disk_bucket_idx, &free_bucket_idx );
  if( FD_LIKELY( query->disk_idx==UINT_MAX ) ) return 0;
  query->ele     = &query->disk_ele;
  query->is_disk = 1;
  return 1;
}

static void
root_insert( fd_stake_delegations_t *      stake_delegations,
             fd_stake_delegation_t const * delegation ) {
  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  if( FD_LIKELY( root_pool_free( pool ) ) ) {
    fd_stake_delegation_t * in_memory = root_pool_ele_acquire( pool );
    *in_memory = *delegation;
    stake_delegations->pool_idx_wmk_ = fd_ulong_max( stake_delegations->pool_idx_wmk_, root_pool_idx( pool, in_memory )+1UL );
    FD_CHECK_CRIT( root_map_ele_insert( get_root_map( stake_delegations ), in_memory, pool ),
                   "unable to insert stake delegation into root map" );
    return;
  }

  disk_root_insert( stake_delegations, delegation );
}

#if FD_HAS_DOUBLE

static void
disk_root_promote( fd_stake_delegations_t *      stake_delegations,
                   uint                          disk_idx,
                   fd_stake_delegation_t const * delegation ) {
  FD_CHECK_CRIT( root_pool_free( get_root_pool( stake_delegations ) ),
                 "no in-memory slot for promoted stake delegation root" );
  root_insert( stake_delegations, delegation );

  uint  found_idx;
  ulong found_bucket_idx;
  ulong free_bucket_idx;
  disk_root_find( stake_delegations, &delegation->stake_account, NULL,
                  &found_idx, &found_bucket_idx, &free_bucket_idx );
  FD_CHECK_CRIT( found_idx==disk_idx, "missing promoted stake delegation disk root" );
  disk_root_remove( stake_delegations, disk_idx, found_bucket_idx );
}

#endif

static void
root_store( fd_stake_delegations_t *      stake_delegations,
            root_query_t const *           query,
            fd_stake_delegation_t const * delegation ) {
  if( FD_LIKELY( !query->is_disk ) ) {
    uint next = query->ele->next_;
    *query->ele = *delegation;
    query->ele->next_ = next;
  } else {
    disk_root_write( stake_delegations, query->disk_idx, delegation );
  }
}

static void
root_remove( fd_stake_delegations_t * stake_delegations,
             root_query_t const *      query ) {
  if( FD_LIKELY( !query->is_disk ) ) {
    fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
    uint idx = (uint)root_pool_idx( pool, query->ele );
    fd_pubkey_t stake_account = query->ele->stake_account;
    root_map_idx_remove( get_root_map( stake_delegations ), &stake_account, idx, pool );
    query->ele->in_use = 0;
    root_pool_idx_release( pool, idx );
  } else {
    disk_root_remove( stake_delegations, query->disk_idx, query->disk_bucket_idx );
  }
}

/* Unlocked root upsert used by public updates and fork rooting. */

static void
root_upsert( fd_stake_delegations_t * stake_delegations,
             root_query_t const *      query,
             fd_stake_delegation_t *   delegation ) {
  delegation->delta_idx = UINT_MAX;
  delegation->in_use    = 1;

  if( FD_LIKELY( query->ele ) ) {
    delegation->dne_in_root = query->ele->dne_in_root;
    root_store( stake_delegations, query, delegation );
    return;
  }

  delegation->dne_in_root = 0;
  root_insert( stake_delegations, delegation );
}

fd_stake_history_entry_t
fd_stake_delegations_totals( fd_stake_delegations_t const * stake_delegations ) {
  return (fd_stake_history_entry_t) {
    .effective    = stake_delegations->effective_stake,
    .activating   = stake_delegations->activating_stake,
    .deactivating = stake_delegations->deactivating_stake,
  };
}

void
fd_stake_delegations_set_totals( fd_stake_delegations_t * stake_delegations,
                                 ulong                    effective,
                                 ulong                    activating,
                                 ulong                    deactivating ) {
  fd_rwlock_write( &stake_delegations->lock );
  stake_delegations->effective_stake    = effective;
  stake_delegations->activating_stake   = activating;
  stake_delegations->deactivating_stake = deactivating;
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
    ulong found_bucket_idx;
    ulong free_bucket_idx;
    disk_root_find( stake_delegations, &delegation.stake_account, NULL, &found_idx, &found_bucket_idx, &free_bucket_idx );
    FD_CHECK_CRIT( found_idx==idx, "missing inactive stake delegation disk root" );
    disk_root_remove( stake_delegations, idx, found_bucket_idx );
  }

  /* Keep the in-memory root tier packed after pruning. */
  while( root_pool_free( pool ) && stake_delegations->disk_root_cnt_ ) {
    uint idx = (uint)(stake_delegations->disk_root_cnt_-1UL);
    fd_stake_delegation_t delegation;
    disk_root_read( stake_delegations, idx, &delegation );
    disk_root_promote( stake_delegations, idx, &delegation );
  }

  fd_rwlock_unwrite( &stake_delegations->lock );

  return pruned;
}

void
fd_stake_delegations_refresh( fd_stake_delegations_t *   stake_delegations,
                              ulong                      epoch,
                              fd_stake_history_t const * stake_history,
                              ulong *                    warmup_cooldown_rate_epoch,
                              int                        use_fixed_point_stake_math,
                              int                        remove_inactive_stakes ) {
  fd_rwlock_write( &stake_delegations->lock );

  int history_contiguous = fd_sysvar_stake_history_is_contiguous( stake_history );

  stake_delegations->effective_stake    = 0UL;
  stake_delegations->activating_stake   = 0UL;
  stake_delegations->deactivating_stake = 0UL;
  stake_delegations->fp_warmed_awarded  = 0;

  fd_stake_delegation_t * pool = get_root_pool( stake_delegations );
  ulong const wmk = stake_delegations->pool_idx_wmk_;
  ulong prev_epoch = epoch ? epoch-1UL : 0UL;

  for( ulong i=0UL; i<wmk; i++ ) {
    if( FD_UNLIKELY( !pool[ i ].in_use ) ) continue;
    fd_stake_delegation_t * delegation = pool+i;
    root_query_t            query      = { .ele = delegation };

    /* Tombstone left by fd_stake_delegations_fork_remove. */
    if( FD_UNLIKELY( !delegation->lamports ) ) {
      root_remove( stake_delegations, &query );
      continue;
    }

    if( FD_UNLIKELY( remove_inactive_stakes &&
                     fd_stake_delegation_is_inactive( delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math ) &&
                     fd_stake_delegation_is_inactive( delegation, prev_epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math ) ) ) {
      root_remove( stake_delegations, &query );
      continue;
    }

    fd_stake_history_entry_t history = fd_stake_delegation_activation_status( delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    stake_delegations->effective_stake    += history.effective;
    stake_delegations->activating_stake   += history.activating;
    stake_delegations->deactivating_stake += history.deactivating;

    delegation->slot  = 0U;
    delegation->state = history_contiguous
                        ? fd_stake_delegation_classify( delegation, history, epoch ) & 0x7U
                        : FD_STAKE_DELEGATION_STATE_UNKNOWN;
    if( FD_LIKELY( delegation->state==FD_STAKE_DELEGATION_STATE_WARMED && !use_fixed_point_stake_math ) ) {
      stake_delegations->fp_warmed_awarded = 1;
    }
  }

  /* Disk roots are dense, so removals leave the moved last record at
     the current index.  Survivors move back to in-memory storage
     whenever pruning made a root-pool slot available. */
  uint disk_idx = 0U;
  while( (ulong)disk_idx<stake_delegations->disk_root_cnt_ ) {
    fd_stake_delegation_t delegation;
    disk_root_read( stake_delegations, disk_idx, &delegation );

    int remove = !delegation.lamports;
    if( FD_LIKELY( !remove ) && FD_UNLIKELY( remove_inactive_stakes ) ) {
      remove = fd_stake_delegation_is_inactive( &delegation, epoch,      stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math ) &&
               fd_stake_delegation_is_inactive( &delegation, prev_epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    }

    if( FD_UNLIKELY( remove ) ) {
      uint  found_idx;
      ulong found_bucket_idx;
      ulong free_bucket_idx;
      disk_root_find( stake_delegations, &delegation.stake_account, NULL, &found_idx, &found_bucket_idx, &free_bucket_idx );
      FD_CHECK_CRIT( found_idx==disk_idx, "missing refreshed stake delegation disk root" );
      disk_root_remove( stake_delegations, disk_idx, found_bucket_idx );
      continue;
    }

    fd_stake_history_entry_t history = fd_stake_delegation_activation_status( &delegation, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    stake_delegations->effective_stake    += history.effective;
    stake_delegations->activating_stake   += history.activating;
    stake_delegations->deactivating_stake += history.deactivating;

    delegation.slot  = 0U;
    delegation.state = history_contiguous
                       ? fd_stake_delegation_classify( &delegation, history, epoch ) & 0x7U
                       : FD_STAKE_DELEGATION_STATE_UNKNOWN;
    root_query_t query = {
      .ele      = &delegation,
      .disk_idx = disk_idx,
      .is_disk  = 1,
    };
    root_upsert( stake_delegations, &query, &delegation );
    if( FD_LIKELY( delegation.state==FD_STAKE_DELEGATION_STATE_WARMED && !use_fixed_point_stake_math ) ) {
      stake_delegations->fp_warmed_awarded = 1;
    }

    if( FD_UNLIKELY( root_pool_free( pool ) ) ) {
      disk_root_promote( stake_delegations, disk_idx, &delegation );
      continue;
    }
    disk_idx++;
  }

  fd_rwlock_unwrite( &stake_delegations->lock );
}

#endif

/* Fork-aware delta operations */

ushort
fd_stake_delegations_new_fork( fd_stake_delegations_t * stake_delegations,
                                ushort                   parent_fork_idx ) {
  fd_rwlock_write( &stake_delegations->lock );
  fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
  FD_CHECK_CRIT( parent_fork_idx==USHORT_MAX ||
                 ((ulong)parent_fork_idx<fork_pool_max( fork_pool ) && fork_pool[ parent_fork_idx ].parent!=FORK_PARENT_FREE),
                 "invalid stake delegation parent fork" );
  FD_CHECK_CRIT( fork_pool_free( fork_pool ), "no free forks in pool. The system has forked too wide." );
  ushort fork_idx = (ushort)fork_pool_idx_acquire( fork_pool );
  fork_pool[ fork_idx ].parent          = parent_fork_idx;
  fork_pool[ fork_idx ].delta_head      = UINT_MAX;
  fork_pool[ fork_idx ].disk_delta_head = UINT_MAX;
  fd_rwlock_unwrite( &stake_delegations->lock );

  return fork_idx;
}

struct fork_query {
  fd_stake_delegation_t * ele;        /* in-memory delta, or NULL */
  disk_delta_query_t      disk_query; /* spilled delta, record_idx UINT_MAX if absent */
  disk_delta_t            disk_ele;
};
typedef struct fork_query fork_query_t;

/* Finds the fork's delta for stake_account in memory or on disk.
   Returns it, or NULL if the fork has none. */

static fd_stake_delegation_t const *
fork_query( fd_stake_delegations_t * stake_delegations,
            ushort                   fork_idx,
            fd_pubkey_t const *      stake_account,
            fork_query_t *           query ) {
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fd_stake_delegation_key_t key = {
    .stake_account = *stake_account,
    .fork_idx      = fork_idx
  };
  query->ele                   = delta_map_ele_query( get_delta_map( stake_delegations ), &key, NULL, delta_pool );
  query->disk_query.record_idx = UINT_MAX;
  query->disk_query.bucket_idx = ULONG_MAX;
  if( FD_LIKELY( query->ele ) ) return query->ele;
  if( FD_UNLIKELY( stake_delegations->disk_delta_cnt_ || !delta_pool_free( delta_pool ) ) ) {
    disk_delta_find( stake_delegations, fork_idx, stake_account, &query->disk_ele, &query->disk_query );
    if( FD_UNLIKELY( query->disk_query.record_idx!=UINT_MAX ) ) return &query->disk_ele.delegation;
  }
  return NULL;
}

/* Overwrites the queried delta or inserts a new one. */

static void
fork_upsert( fd_stake_delegations_t *      stake_delegations,
             ushort                        fork_idx,
             fork_query_t *                query,
             fd_stake_delegation_t const * delegation ) {
  if( FD_LIKELY( query->ele ) ) {
    fd_stake_delegation_t * in_memory = query->ele;
    uint next      = in_memory->next_;
    uint fork_next = in_memory->fork_next;
    *in_memory = *delegation;
    in_memory->next_     = next;
    in_memory->fork_next = fork_next;
    in_memory->fork_idx  = fork_idx;
    return;
  }

  if( FD_UNLIKELY( query->disk_query.record_idx!=UINT_MAX ) ) {
    query->disk_ele.delegation = *delegation;
    disk_delta_write( stake_delegations, query->disk_query.record_idx, &query->disk_ele );
    return;
  }

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  if( FD_LIKELY( delta_pool_free( delta_pool ) ) ) {
    fork_pool_ele_t * fork = get_fork_pool( stake_delegations ) + fork_idx;
    fd_stake_delegation_t * in_memory = delta_pool_ele_acquire( delta_pool );
    *in_memory = *delegation;
    uint idx = (uint)delta_pool_idx( delta_pool, in_memory );
    in_memory->fork_next = fork->delta_head;
    in_memory->fork_idx  = fork_idx;
    FD_CHECK_CRIT( delta_map_ele_insert( get_delta_map( stake_delegations ), in_memory, delta_pool ),
                   "unable to insert stake delegation into delta map" );
    fork->delta_head = idx;
  } else {
    disk_delta_insert( stake_delegations, fork_idx, delegation, &query->disk_query );
  }
}

/* Root tier: newest slot wins.  Caller holds the write lock. */

static void
root_write( fd_stake_delegations_t * stake_delegations,
            fd_stake_delegation_t *  delegation ) {
  root_query_t query;
  root_query( stake_delegations, &delegation->stake_account, &query );
  if( FD_UNLIKELY( query.ele && query.ele->slot>delegation->slot ) ) return;
  root_upsert( stake_delegations, &query, delegation );
}

/* Fork tier: newest slot wins.  Caller holds the write lock. */

static void
fork_write( fd_stake_delegations_t *      stake_delegations,
            ushort                        fork_idx,
            fd_stake_delegation_t const * delegation ) {
  fork_query_t query;
  fd_stake_delegation_t const * existing = fork_query( stake_delegations, fork_idx, &delegation->stake_account, &query );
  if( FD_UNLIKELY( existing && existing->slot>delegation->slot ) ) return;
  fork_upsert( stake_delegations, fork_idx, &query, delegation );
}

/* fork_idx USHORT_MAX writes the root, otherwise the fork.
   replacing_full_entry writes nothing unless the root holds the
   account. */

static void
delegation_write( fd_stake_delegations_t * stake_delegations,
                  ushort                   fork_idx,
                  fd_stake_delegation_t *  delegation,
                  int                      replacing_full_entry ) {
  fd_rwlock_write( &stake_delegations->lock );
  root_query_t query;
  if( FD_LIKELY( !replacing_full_entry || root_query( stake_delegations, &delegation->stake_account, &query ) ) ) {
    if( FD_LIKELY( fork_idx==USHORT_MAX ) ) root_write( stake_delegations, delegation );
    else                                    fork_write( stake_delegations, fork_idx, delegation );
  }
  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_fork_update( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  ulong                    slot,
                                  fd_pubkey_t const *      stake_account,
                                  fd_pubkey_t const *      vote_account,
                                  ulong                    stake,
                                  ulong                    activation_epoch,
                                  ulong                    deactivation_epoch,
                                  ulong                    credits_observed,
                                  ulong                    lamports,
                                  uint                     acc_dlen ) {
  FD_CHECK_ERR( (long)activation_epoch  <USHORT_MAX, "activation_epoch overflow"   );
  FD_CHECK_ERR( (long)deactivation_epoch<USHORT_MAX, "deactivation_epoch overflow" );
  FD_CHECK_CRIT( slot<=UINT_MAX, "slot exceeds 2^32-1" );
  fd_stake_delegation_t delegation = {
    .stake_account      = *stake_account,
    .vote_account       = *vote_account,
    .stake              = stake,
    .lamports           = lamports,
    .credits_observed   = credits_observed,
    .acc_dlen           = acc_dlen,
    .activation_epoch   = (ushort)activation_epoch,
    .deactivation_epoch = (ushort)deactivation_epoch,
    .slot               = (uint)slot,
  };
  delegation_write( stake_delegations, fork_idx, &delegation, 0 );
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
                                  uint                     acc_dlen ) {
  fd_stake_delegations_fork_update( stake_delegations, USHORT_MAX, 0UL, stake_account, vote_account, stake,
                                    activation_epoch, deactivation_epoch, credits_observed, lamports, acc_dlen );
}

void
fd_stake_delegations_fork_remove( fd_stake_delegations_t * stake_delegations,
                                  ushort                   fork_idx,
                                  ulong                    slot,
                                  fd_pubkey_t const *      stake_account,
                                  int                      replacing_full_entry ) {
  FD_CHECK_CRIT( slot<=UINT_MAX, "slot exceeds 2^32-1" );
  fd_stake_delegation_t tombstone = {
    .stake_account = *stake_account,
    .is_tombstone  = 1,
    .slot          = (uint)slot,
  };
  delegation_write( stake_delegations, fork_idx, &tombstone, replacing_full_entry );
}

void
fd_stake_delegations_evict_fork( fd_stake_delegations_t * stake_delegations,
                                 ushort                   fork_idx ) {
  if( fork_idx==USHORT_MAX ) return;

  fd_rwlock_write( &stake_delegations->lock );

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  delta_map_t *           delta_map  = get_delta_map( stake_delegations );
  fork_pool_ele_t *       fork_pool  = get_fork_pool( stake_delegations );
  FD_CHECK_CRIT( (ulong)fork_idx<fork_pool_max( fork_pool ) && fork_pool[ fork_idx ].parent!=FORK_PARENT_FREE,
                 "invalid stake delegation fork" );

  uint idx = fork_pool[ fork_idx ].delta_head;
  while( idx!=UINT_MAX ) {
    fd_stake_delegation_t * ele = delta_pool + idx;
    FD_CHECK_CRIT( delta_map_ele_remove( delta_map, &ele->key, NULL, delta_pool )==ele,
                   "stake delegation missing from delta map" );
    idx = ele->fork_next;
    delta_pool_ele_release( delta_pool, ele );
  }
  fork_pool[ fork_idx ].delta_head = UINT_MAX;

  while( fork_pool[ fork_idx ].disk_delta_head!=UINT_MAX ) {
    uint disk_idx = fork_pool[ fork_idx ].disk_delta_head;
    disk_delta_t disk_delta;
    disk_delta_read( stake_delegations, disk_idx, &disk_delta );
    disk_delta_remove( stake_delegations, disk_idx, &disk_delta );
  }
  fork_pool[ fork_idx ].disk_delta_head = UINT_MAX;

  fork_pool[ fork_idx ].parent = FORK_PARENT_FREE;
  fork_pool_idx_release( fork_pool, fork_idx );

  fd_rwlock_unwrite( &stake_delegations->lock );
}

/* skip_stake_math applies the delta without updating totals or
   state, for the snapshot loader; fd_stake_delegations_refresh
   recomputes them afterwards. */

static void
apply_delta( ulong                           epoch,
             fd_stake_history_t const *      stake_history,
             ulong *                         warmup_cooldown_rate_epoch,
             int                             use_fixed_point_stake_math,
             int                             history_contiguous,
             int                             skip_stake_math,
             fd_stake_delegations_t *        stake_delegations,
             fd_stake_delegation_t const *   delta ) {
  root_query_t query;
  int found = root_query( stake_delegations, &delta->stake_account, &query );

  if( FD_UNLIKELY( skip_stake_math ) ) {
    if( FD_UNLIKELY( delta->is_tombstone ) ) {
      if( FD_LIKELY( found ) ) root_remove( stake_delegations, &query );
      return;
    }
    fd_stake_delegation_t root_delegation = *delta;
    root_upsert( stake_delegations, &query, &root_delegation );
    return;
  }

  if( FD_LIKELY( found ) ) {
    fd_stake_history_entry_t old_entry = fd_stake_delegation_activation_status(
        query.ele, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    stake_delegations->effective_stake    -= old_entry.effective;
    stake_delegations->activating_stake   -= old_entry.activating;
    stake_delegations->deactivating_stake -= old_entry.deactivating;
  }

  if( FD_UNLIKELY( delta->is_tombstone ) ) {
    if( FD_LIKELY( found ) ) root_remove( stake_delegations, &query );
    return;
  }

  fd_stake_delegation_t root_delegation = *delta;
  fd_stake_history_entry_t new_entry = fd_stake_delegation_activation_status(
      delta, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
  stake_delegations->effective_stake    += new_entry.effective;
  stake_delegations->activating_stake   += new_entry.activating;
  stake_delegations->deactivating_stake += new_entry.deactivating;

  root_delegation.state = history_contiguous
                          ? fd_stake_delegation_classify( &root_delegation, new_entry, epoch ) & 0x7U
                          : FD_STAKE_DELEGATION_STATE_UNKNOWN;
  root_upsert( stake_delegations, &query, &root_delegation );
  if( FD_LIKELY( root_delegation.state==FD_STAKE_DELEGATION_STATE_WARMED && !use_fixed_point_stake_math ) ) {
    stake_delegations->fp_warmed_awarded = 1;
  }
}

static void
apply_fork_delta( ulong                                epoch,
                  fd_stake_history_t const *           stake_history,
                  ulong *                              warmup_cooldown_rate_epoch,
                  int                                  use_fixed_point_stake_math,
                  int                                  history_contiguous,
                  int                                  skip_stake_math,
                  fd_stake_delegations_t *             stake_delegations,
                  ushort                               fork_idx,
                  fd_stake_delegations_delta_stats_t * stake_delegations_delta_stats ) {
  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  ulong                   upserts    = 0UL;
  ulong                   removes    = 0UL;

  /* Apply disk deltas first. */
  fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
  while( fork_pool[ fork_idx ].disk_delta_head!=UINT_MAX ) {
    uint disk_idx = fork_pool[ fork_idx ].disk_delta_head;
    disk_delta_t disk_delta;
    disk_delta_read( stake_delegations, disk_idx, &disk_delta );
    fd_stake_delegation_t delegation = disk_delta.delegation;
    disk_delta_remove( stake_delegations, disk_idx, &disk_delta );
    upserts += (ulong)!delegation.is_tombstone;
    removes += (ulong)!!delegation.is_tombstone;
    apply_delta( epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math,
                 history_contiguous, skip_stake_math, stake_delegations, &delegation );
  }

  /* Apply in-memory deltas. */
  for( uint idx=fork_pool[ fork_idx ].delta_head; idx!=UINT_MAX; idx=delta_pool[ idx ].fork_next ) {
    fd_stake_delegation_t * delegation = delta_pool + idx;
    upserts += (ulong)!delegation->is_tombstone;
    removes += (ulong)!!delegation->is_tombstone;
    apply_delta( epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math,
                 history_contiguous, skip_stake_math, stake_delegations, delegation );
  }

  if( stake_delegations_delta_stats ) {
    stake_delegations_delta_stats->upserts += upserts;
    stake_delegations_delta_stats->removes += removes;
  }
}

void
fd_stake_delegations_advance_root( ulong                                epoch,
                                   fd_stake_history_t const *           stake_history,
                                   ulong *                              warmup_cooldown_rate_epoch,
                                   int                                  use_fixed_point_stake_math,
                                   int                                  skip_stake_math,
                                   fd_stake_delegations_t *             stake_delegations,
                                   ushort                               fork_idx,
                                   fd_stake_delegations_delta_stats_t * stake_delegations_delta_stats ) {
  fd_rwlock_write( &stake_delegations->lock );

  ushort fork_ids[ FD_STAKE_DELEGATIONS_FORK_MAX ];
  ulong fork_id_cnt       = fork_ancestry( stake_delegations, fork_idx, fork_ids );
  int history_contiguous = !skip_stake_math && fd_sysvar_stake_history_is_contiguous( stake_history );
  for( ulong i=fork_id_cnt; i; i-- ) {
    apply_fork_delta( epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math,
                      history_contiguous, skip_stake_math, stake_delegations, fork_ids[ i-1UL ], stake_delegations_delta_stats );
  }
  /* The target is now rooted.  Its children no longer need a parent
     delta layer, and its descriptor can be freed by the caller. */
  if( fork_idx!=USHORT_MAX ) {
    fork_pool_ele_t * fork_pool = get_fork_pool( stake_delegations );
    for( ulong i=0UL; i<fork_pool_max( fork_pool ); i++ ) {
      if( fork_pool[ i ].parent==fork_idx ) fork_pool[ i ].parent = USHORT_MAX;
    }
    fork_pool[ fork_idx ].parent = USHORT_MAX;
  }
  if( FD_UNLIKELY( stake_delegations_delta_stats ) ) {
    stake_delegations_delta_stats->root_cnt = root_pool_used( get_root_pool( stake_delegations ) ) + stake_delegations->disk_root_cnt_;
  }
  FD_LOG_DEBUG(( "effective_stake=%lu, activating_stake=%lu, deactivating_stake=%lu", stake_delegations->effective_stake, stake_delegations->activating_stake, stake_delegations->deactivating_stake ));

  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_iter_read_disk_delta_private( fd_stake_delegations_iter_t * iter,
                                                   uint                          delta_idx ) {
  FD_CHECK_CRIT( (ulong)delta_idx<iter->stake_delegations->disk_delta_cnt_,
                 "invalid stake delegation iterator disk delta" );
  disk_delta_t delta;
  disk_delta_read( iter->stake_delegations, delta_idx, &delta );
  iter->disk_ele = delta.delegation;
  iter->ele = iter->disk_ele.is_tombstone ? NULL : &iter->disk_ele;
}

void
fd_stake_delegations_iter_advance_disk_root_private( fd_stake_delegations_iter_t * iter ) {
  fd_stake_delegations_t const * stake_delegations = iter->stake_delegations;
  while( iter->disk_idx<stake_delegations->disk_root_cnt_ ) {
    ulong batch_idx = iter->disk_idx % FD_STAKE_DELEGATIONS_ITER_BATCH_CNT;
    if( FD_UNLIKELY( !batch_idx ) ) {
      ulong cnt = fd_ulong_min( FD_STAKE_DELEGATIONS_ITER_BATCH_CNT, stake_delegations->disk_root_cnt_-iter->disk_idx );
      disk_read( stake_delegations, iter->disk_batch,
                 disk_root_record_off( stake_delegations ) + iter->disk_idx*sizeof(fd_stake_delegation_t),
                 cnt*sizeof(fd_stake_delegation_t) );
    }
    fd_stake_delegation_t * root = iter->disk_batch + batch_idx;
    iter->idx = stake_delegations->max_stake_accounts_ + iter->disk_idx;

    uint delta_idx = root->delta_idx;
    if( FD_LIKELY( delta_idx==UINT_MAX ) ) {
      iter->ele = root;
      return;
    }
    if( FD_UNLIKELY( delta_idx & FD_STAKE_DELEGATIONS_DELTA_DISK_TAG ) ) {
      fd_stake_delegations_iter_read_disk_delta_private( iter, delta_idx & FD_STAKE_DELEGATIONS_DELTA_IDX_MASK );
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
  iter->root_max          = stake_delegations->max_stake_accounts_;
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
  root_query_t query;
  int found = root_query( stake_delegations, &delta->stake_account, &query );
  fd_stake_delegation_t base;
  if( FD_UNLIKELY( !found ) ) {
    base = (fd_stake_delegation_t) {
      .stake_account = delta->stake_account,
      .delta_idx     = delta_ref,
      .dne_in_root   = 1,
      .in_use        = 1,
    };
    root_insert( stake_delegations, &base );
  } else {
    base = *query.ele;
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
    root_store( stake_delegations, &query, &base );
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
  root_query_t query;
  if( FD_UNLIKELY( !root_query( stake_delegations, &delta->stake_account, &query ) ||
                   query.ele->delta_idx!=delta_ref ) ) return;
  fd_stake_delegation_t base = *query.ele;

  if( FD_LIKELY( !delta->is_tombstone ) ) {
    fd_stake_history_entry_t entry = fd_stake_delegation_activation_status(
        delta, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    stake_delegations->effective_stake    -= entry.effective;
    stake_delegations->activating_stake   -= entry.activating;
    stake_delegations->deactivating_stake -= entry.deactivating;
  }

  if( FD_UNLIKELY( base.dne_in_root ) ) {
    root_remove( stake_delegations, &query );
    return;
  }

  base.delta_idx = UINT_MAX;
  root_store( stake_delegations, &query, &base );
  fd_stake_history_entry_t entry = fd_stake_delegation_activation_status(
      &base, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
  stake_delegations->effective_stake    += entry.effective;
  stake_delegations->activating_stake   += entry.activating;
  stake_delegations->deactivating_stake += entry.deactivating;
}

void
fd_stake_delegations_view_begin( fd_stake_delegations_t *   stake_delegations,
                                 ulong                      epoch,
                                 fd_stake_history_t const * stake_history,
                                 ulong *                    warmup_cooldown_rate_epoch,
                                 int                        use_fixed_point_stake_math,
                                 ushort                     fork_idx ) {
  fd_rwlock_write( &stake_delegations->lock );

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fork_pool_ele_t *       fork_pool  = get_fork_pool( stake_delegations );

  ushort fork_ids[ FD_STAKE_DELEGATIONS_FORK_MAX ];
  ulong fork_id_cnt = fork_ancestry( stake_delegations, fork_idx, fork_ids );
  stake_delegations->frontier_query_epoch = epoch;
  stake_delegations->frontier_query_fork  = fork_idx;
  for( ulong i=fork_id_cnt; i; i-- ) {
    fork_pool_ele_t const * fork = fork_pool + fork_ids[ i-1UL ];
    for( uint delta_ref=fork->delta_head; delta_ref!=UINT_MAX; delta_ref=delta_pool[ delta_ref ].fork_next ) {
      fd_stake_delegation_t * delta_delegation = delta_pool + delta_ref;
      mark_delta_one( stake_delegations, epoch, stake_history, warmup_cooldown_rate_epoch,
                      use_fixed_point_stake_math, delta_delegation, delta_ref );
    }

    uint disk_idx = fork->disk_delta_head;
    while( disk_idx!=UINT_MAX ) {
      disk_delta_t disk_delta;
      disk_delta_read( stake_delegations, disk_idx, &disk_delta );
      mark_delta_one( stake_delegations, epoch, stake_history, warmup_cooldown_rate_epoch,
                      use_fixed_point_stake_math, &disk_delta.delegation,
                      disk_idx | FD_STAKE_DELEGATIONS_DELTA_DISK_TAG );
      disk_idx = disk_delta.next;
    }
  }
}

void
fd_stake_delegations_view_end( fd_stake_delegations_t *   stake_delegations,
                               fd_stake_history_t const * stake_history,
                               ulong *                    warmup_cooldown_rate_epoch,
                               int                        use_fixed_point_stake_math ) {
  ulong epoch = stake_delegations->frontier_query_epoch;

  fd_stake_delegation_t * delta_pool = get_delta_pool( stake_delegations );
  fork_pool_ele_t *       fork_pool  = get_fork_pool( stake_delegations );

  ushort fork_ids[ FD_STAKE_DELEGATIONS_FORK_MAX ];
  ulong fork_id_cnt = fork_ancestry( stake_delegations, stake_delegations->frontier_query_fork, fork_ids );
  for( ulong i=fork_id_cnt; i; i-- ) {
    fork_pool_ele_t const * fork = fork_pool + fork_ids[ i-1UL ];
    for( uint delta_ref=fork->delta_head; delta_ref!=UINT_MAX; delta_ref=delta_pool[ delta_ref ].fork_next ) {
      fd_stake_delegation_t * delta_delegation = delta_pool + delta_ref;
      unmark_delta_one( stake_delegations, epoch, stake_history, warmup_cooldown_rate_epoch,
                        use_fixed_point_stake_math, delta_delegation, delta_ref );
    }

    uint disk_idx = fork->disk_delta_head;
    while( disk_idx!=UINT_MAX ) {
      disk_delta_t disk_delta;
      disk_delta_read( stake_delegations, disk_idx, &disk_delta );
      unmark_delta_one( stake_delegations, epoch, stake_history, warmup_cooldown_rate_epoch,
                        use_fixed_point_stake_math, &disk_delta.delegation,
                        disk_idx | FD_STAKE_DELEGATIONS_DELTA_DISK_TAG );
      disk_idx = disk_delta.next;
    }
  }
  stake_delegations->frontier_query_epoch = ULONG_MAX;
  stake_delegations->frontier_query_fork  = USHORT_MAX;
  disk_root_maintain( stake_delegations );
  fd_rwlock_unwrite( &stake_delegations->lock );
}

void
fd_stake_delegations_invalidate_warmed( fd_stake_delegations_t * stake_delegations,
                                        int                      force ) {
  if( FD_LIKELY( !force && !stake_delegations->fp_warmed_awarded ) ) return;

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
