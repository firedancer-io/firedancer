#ifndef HEADER_fd_src_discof_accdb_fd_accdb_shmem_h
#define HEADER_fd_src_discof_accdb_fd_accdb_shmem_h

#include "../../util/fd_util_base.h"

#define FD_ACCDB_SHMEM_ALIGN (128UL)

#define FD_ACCDB_SHMEM_MAGIC (0xF17EDA2CE7ACCDB0UL) /* FIREDANCE ACCDB V0 */

typedef struct fd_accdb_shmem_private fd_accdb_shmem_t;

struct fd_accdb_shmem_metrics {
   ulong accounts_total;
   ulong accounts_capacity;
   ulong bytes_read;
   ulong bytes_written;
   ulong accounts_read;
   ulong accounts_written;
   ulong disk_allocated_bytes;
   ulong disk_used_bytes;
   int   in_compaction;
   ulong compactions_requested;
   ulong compactions_completed;
   ulong accounts_relocated;
   ulong accounts_relocated_bytes;
   ulong partitions_freed;
};

typedef struct fd_accdb_shmem_metrics fd_accdb_shmem_metrics_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_accdb_shmem_align( void );

FD_FN_CONST ulong
fd_accdb_shmem_footprint( ulong max_accounts,
                          ulong max_live_slots,
                          ulong max_account_writes_per_slot,
                          ulong partition_cnt,
                          ulong cache_footprint );

void *
fd_accdb_shmem_new( void * shmem,
                    ulong  max_accounts,
                    ulong  max_live_slots,
                    ulong  max_account_writes_per_slot,
                    ulong  partition_cnt,
                    ulong  partition_sz,
                    ulong  cache_footprint,
                    ulong  seed );

fd_accdb_shmem_t *
fd_accdb_shmem_join( void * shtc );

void
fd_accdb_shmem_bytes_freed( fd_accdb_shmem_t * accdb,
                            ulong              offset,
                            ulong              sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_accdb_fd_accdb_shmem_h */
