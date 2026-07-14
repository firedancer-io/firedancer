#ifndef HEADER_fd_src_flamenco_runtime_fd_txncache_shmem_h
#define HEADER_fd_src_flamenco_runtime_fd_txncache_shmem_h

#include "../../util/fd_util_base.h"

#define FD_TXNCACHE_SHMEM_ALIGN (128UL)

#define FD_TXNCACHE_SHMEM_MAGIC (0xF17EDA2CE58CC4E1UL) /* FIREDANCE SMCCHE V1 */

/* The maximum number of slot deltas an Agave snapshot can contain,
   from status_cache.rs::MAX_CACHE_ENTRIES.  Must match
   FD_SLOT_DELTA_MAX_ENTRIES in the slot delta parser.  Used to bound
   the snapshot load transient when sizing the txnpage pool. */

#define FD_TXNCACHE_SNAPSHOT_SLOT_DELTA_MAX (300UL)

typedef struct { ushort val; } fd_txncache_fork_id_t;

struct fd_txncache_shmem_private;
typedef struct fd_txncache_shmem_private fd_txncache_shmem_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_txncache_shmem_align( void );

/* larger_max_cost_per_block indicates the validator is running with
   development.bench.larger_max_cost_per_block, which raises the block
   cost limit and invalidates the tightened txnpage pool bound (which
   assumes at most FD_MAX_TXN_PER_SLOT committable transactions per
   slot).  When set, the pool is sized for every active slot
   simultaneously full at max_txn_per_slot instead. */

FD_FN_CONST ulong
fd_txncache_shmem_footprint( ulong max_live_slots,
                             ulong max_txn_per_slot,
                             int   larger_max_cost_per_block );

void *
fd_txncache_shmem_new( void * shmem,
                       ulong  max_live_slots,
                       ulong  max_txn_per_slot,
                       int    larger_max_cost_per_block,
                       ulong  seed );

fd_txncache_shmem_t *
fd_txncache_shmem_join( void * shtc );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_txncache_shmem_h */
