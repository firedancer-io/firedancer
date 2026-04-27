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
  ulong accounts_acquired;
  ulong writable_accounts_acquired;
  ulong accounts_evicted;
  ulong accounts_evicted_per_class[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong accounts_preevicted;
  ulong accounts_preevicted_per_class[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong accounts_committed_new_per_class[ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong accounts_missed;
  ulong accounts_waited;
  ulong accounts_deleted;

  ulong acquire_failed;

  ulong bytes_read;
  ulong read_ops;
  ulong bytes_written;
  ulong write_ops;

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
                          ulong joiner_cnt );

void *
fd_accdb_shmem_new( void * shmem,
                    ulong  max_accounts,
                    ulong  max_live_slots,
                    ulong  max_account_writes_per_slot,
                    ulong  partition_cnt,
                    ulong  partition_sz,
                    ulong  cache_footprint,
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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_shmem_h */
