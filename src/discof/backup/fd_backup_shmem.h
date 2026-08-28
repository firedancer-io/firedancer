#ifndef HEADER_fd_src_discof_backup_fd_backup_shmem_h
#define HEADER_fd_src_discof_backup_fd_backup_shmem_h

/* fd_backup_shmem.h is a shared memory data structure tracking which
   accounts have been packed into the snapshot.  Each account is tracked by
   its position in the account index.

   For each visited account:
   - mark the account as visited (in snapmk)
   - copy and compress the account (in snapzp)
     - if the read failed recover via request from snapzp to snapmk

   Reads may fail when reading database cache that is concurrently
   evicted.  Accounts that failed to be read are added to the overrun
   queue, then retried via a later disk read.

   Data structures:
   - bit vector shadowing the account index
   - MPSC queue tracking overruns */

#include "../../util/fd_util.h"

/* Declare a bit vector */

#define SET_NAME visited_set
#include "../../util/tmpl/fd_set_dynamic.c"

static inline int
fd_backup_visited_test( visited_set_t const * set,
                        ulong                 idx ) {
  FD_DCHECK_CRIT( visited_set_valid_idx( set, idx ), "idx out of bounds" );
  return (int)( ( set[ idx>>6 ] >> (idx & 63UL) ) & 1UL );
}

static inline void
fd_backup_visited_insert( visited_set_t * set,
                          ulong           idx ) {
  FD_DCHECK_CRIT( visited_set_valid_idx( set, idx ), "idx out of bounds" );
  set[ idx>>6 ] |= 1UL << (idx & 63UL);
}

static inline int
fd_backup_visited_test_and_set( visited_set_t * set,
                                ulong           idx ) {
  FD_DCHECK_CRIT( visited_set_valid_idx( set, idx ), "idx out of bounds" );
  ulong   mask = 1UL << (idx & 63UL);
  ulong * word = &set[ idx>>6 ];
  ulong   prev = *word;
  *word = prev | mask;
  return !!( prev & mask );
}

static inline void
fd_backup_visited_remove( visited_set_t * set,
                          ulong           idx ) {
  FD_DCHECK_CRIT( visited_set_valid_idx( set, idx ), "idx out of bounds" );
  set[ idx>>6 ] &= ~(1UL << (idx & 63UL));
}

/* Declare an MPSC queue for reporting overruns */

#define FD_BACKUP_OVERRUN_DEPTH (4096U)

struct __attribute__((aligned(8))) fd_backup_overrun_slot {
  uint seq;
  uint acc_idx;
};

typedef struct fd_backup_overrun_slot fd_backup_overrun_slot_t;

struct fd_backup_overrun {
  uint head __attribute__((aligned(128)));
  uint tail __attribute__((aligned(128)));
  fd_backup_overrun_slot_t slot[ FD_BACKUP_OVERRUN_DEPTH ] __attribute__((aligned(128)));
};

typedef struct fd_backup_overrun fd_backup_overrun_t;

/* Per-snapzp statistics for the snapshot currently being produced.
   Each snapzp tile owns one cache-line-sized entry.  snapmk reads all
   entries after the final flush barrier. */

#define FD_BACKUP_STATS_MAX 64UL

struct __attribute__((aligned(128))) fd_backup_worker_stats {
  ulong account_cnt;
  ulong account_sz;
  ulong tombstone_cnt;
  ulong cached_account_cnt;
  ulong disk_account_cnt;
  ulong zstd_data_frame_cnt;
  ulong zstd_padding_sz;
  ulong uncompressed_sz;
  ulong compress_ticks;
  ulong io_blocked_ticks;
  ulong reserved[ 6 ];
};

typedef struct fd_backup_worker_stats fd_backup_worker_stats_t;

struct fd_backup_stats {
  fd_backup_worker_stats_t worker[ FD_BACKUP_STATS_MAX ];
};

typedef struct fd_backup_stats fd_backup_stats_t;

FD_PROTOTYPES_BEGIN

static inline void
fd_backup_overrun_push( fd_backup_overrun_t * q,
                        uint                  acc_idx ) {
  uint pos = __atomic_fetch_add( &q->head, 1U, __ATOMIC_RELAXED );
  fd_backup_overrun_slot_t * slot = &q->slot[ pos & (FD_BACKUP_OVERRUN_DEPTH-1U) ];
  while( FD_UNLIKELY( __atomic_load_n( &slot->seq, __ATOMIC_ACQUIRE )!=pos-1U ) ) {
    FD_SPIN_PAUSE();
  }
  slot->acc_idx = acc_idx;
  __atomic_store_n( &slot->seq, pos, __ATOMIC_RELEASE );
}

FD_FN_CONST static inline ulong
fd_backup_align( void ) {
  return fd_ulong_max( fd_ulong_max( alignof(fd_backup_overrun_t), alignof(fd_backup_stats_t) ), visited_set_align() );
}

FD_FN_PURE static inline ulong
fd_backup_footprint( ulong max_accounts ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_backup_overrun_t), sizeof(fd_backup_overrun_t)             );
  l = FD_LAYOUT_APPEND( l, alignof(fd_backup_stats_t),   sizeof(fd_backup_stats_t)               );
  l = FD_LAYOUT_APPEND( l, visited_set_align(),          visited_set_footprint( max_accounts )   );
  return FD_LAYOUT_FINI( l, fd_backup_align() );
}

static inline void *
fd_backup_new( void * mem,
               ulong  max_accounts ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_backup_align() ) ) ) return NULL;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_backup_overrun_t * q       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_backup_overrun_t), sizeof(fd_backup_overrun_t) );
  fd_backup_stats_t *   stats   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_backup_stats_t), sizeof(fd_backup_stats_t) );
  void *                set_mem = FD_SCRATCH_ALLOC_APPEND( l, visited_set_align(),      visited_set_footprint( max_accounts ) );
  FD_CHECK_CRIT( (ulong)q==(ulong)mem, "layout error" );

  q->head = 0UL;
  q->tail = 0UL;
  for( uint i=0U; i<FD_BACKUP_OVERRUN_DEPTH; i++ ) {
    q->slot[ i ].seq     = i-1U;
    q->slot[ i ].acc_idx = UINT_MAX;
  }

  fd_memset( stats, 0, sizeof(fd_backup_stats_t) );

  if( FD_UNLIKELY( !visited_set_new( set_mem, max_accounts ) ) ) return NULL;
  return mem;
}

/* fd_backup_overrun returns a pointer to the overrun queue. */

FD_FN_CONST static inline fd_backup_overrun_t *
fd_backup_overrun( void * mem ) {
  return (fd_backup_overrun_t *)mem;
}

/* fd_backup_stats returns per-worker snapshot statistics. */

static inline fd_backup_stats_t *
fd_backup_stats( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  /*                        */FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_backup_overrun_t), sizeof(fd_backup_overrun_t) );
  fd_backup_stats_t * stats = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_backup_stats_t), sizeof(fd_backup_stats_t) );
  return stats;
}

/* fd_backup_set returns a join to the visited bit set. */

static inline visited_set_t *
fd_backup_set( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  /*             */FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_backup_overrun_t), sizeof(fd_backup_overrun_t) );
  /*             */FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_backup_stats_t),   sizeof(fd_backup_stats_t)   );
  void * set_mem = FD_SCRATCH_ALLOC_APPEND( l, visited_set_align(),          visited_set_footprint( 1UL ) );
  return visited_set_join( set_mem );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_backup_shmem_h */
