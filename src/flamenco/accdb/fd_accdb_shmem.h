#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_shmem_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_shmem_h

#include "../../util/fd_util_base.h"
#include "fd_accdb_cache.h"

#define FD_ACCDB_SHMEM_ALIGN (128UL)

#define FD_ACCDB_SHMEM_MAGIC (0xF17EDA2CE7ACCDB0UL) /* FIREDANCE ACCDB V0 */

typedef struct fd_accdb_shmem_private fd_accdb_shmem_t;

struct fd_accdb_shmem_metrics {
   ulong accounts_total;
   ulong accounts_capacity;
   ulong disk_allocated_bytes;
   ulong disk_current_bytes;
   ulong disk_used_bytes;
   int   in_compaction;
   ulong compactions_requested;
   ulong compactions_completed;
   ulong accounts_relocated;
   ulong accounts_relocated_bytes;
   ulong partitions_freed;
};

typedef struct fd_accdb_shmem_metrics fd_accdb_shmem_metrics_t;

struct fd_accdb_metrics {
  ulong acquire_calls;
  ulong accounts_acquired_per_class[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong writable_accounts_acquired_per_class[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong accounts_evicted;
  ulong accounts_evicted_per_class[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong accounts_preevicted;
  ulong accounts_preevicted_per_class[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong accounts_committed_new_per_class[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong accounts_committed_overwrite_per_class[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong accounts_not_found_per_class[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong accounts_waited;
  ulong accounts_deleted;

  ulong acquire_failed;

  ulong bytes_read;
  ulong read_ops;
  ulong bytes_written;
  ulong write_ops;
  ulong copy_ops;

  ulong bytes_copied;
};

typedef struct fd_accdb_metrics fd_accdb_metrics_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_accdb_shmem_align( void );

FD_FN_CONST ulong
fd_accdb_shmem_footprint( ulong max_accounts,
                          ulong max_live_slots,
                          ulong max_account_writes_per_slot,
                          ulong partition_cnt,
                          ulong cache_footprint,
                          ulong cache_min_reserved,
                          ulong joiner_cnt );

void *
fd_accdb_shmem_new( void * shmem,
                    ulong  max_accounts,
                    ulong  max_live_slots,
                    ulong  max_account_writes_per_slot,
                    ulong  partition_cnt,
                    ulong  partition_sz,
                    ulong  cache_footprint,
                    ulong  cache_min_reserved,
                    ulong  seed,
                    ulong  joiner_cnt );

fd_accdb_shmem_t *
fd_accdb_shmem_join( void * shtc );

void
fd_accdb_shmem_bytes_freed( fd_accdb_shmem_t * accdb,
                            ulong              offset,
                            ulong              sz );

/* fd_accdb_shmem_try_enqueue_compaction checks whether the partition
   at partition_idx has crossed the compaction threshold and, if so,
   enqueues it for compaction.  The caller MUST hold partition_lock.
   This is factored out of fd_accdb_shmem_bytes_freed so that
   change_partition (which already holds the lock) can call it after
   updating the write head, avoiding a race where the old write head
   is skipped for enqueue. */

void
fd_accdb_shmem_try_enqueue_compaction( fd_accdb_shmem_t * accdb,
                                       ulong              partition_idx );

/* Per-partition snapshot for read-only consumers (GUI tile).  This is a
   the underlying per-partition state is updated with relaxed atomics by
   writers, so the snapshot is best-effort consistent. compaction_state
   is 0=idle, 1=queued, 2=compacting. */

struct fd_accdb_shmem_partition_info {
  ulong file_offset;        /* byte offset of partition start in the accdb file */
  ulong write_offset;       /* current write head within the partition          */
  ulong bytes_freed;        /* bytes marked freed within the partition          */
  ulong compaction_offset;  /* current compaction read offset within partition  */
  ulong read_ops;
  ulong bytes_read;
  ulong write_ops;
  ulong bytes_written;
  long  created_ticks;      /* fd_tickcount when the partition was opened       */
  long  filled_ticks;       /* fd_tickcount when partition closed (0 if active) */
  uchar layer;              /* compaction tier this partition belongs to        */
  uchar compaction_state;   /* 0=idle, 1=queued, 2=compacting                   */
  uchar is_write_head;      /* non-zero if this partition is the active write   */
                            /* head for any layer at the time of the snapshot   */
};

typedef struct fd_accdb_shmem_partition_info fd_accdb_shmem_partition_info_t;

ulong
fd_accdb_shmem_partition_max( fd_accdb_shmem_t const * accdb );

ulong
fd_accdb_shmem_partition_sz( fd_accdb_shmem_t const * accdb );

void
fd_accdb_shmem_partition_info( fd_accdb_shmem_t const *          accdb,
                               ulong                             partition_idx,
                               fd_accdb_shmem_partition_info_t * out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_shmem_h */
