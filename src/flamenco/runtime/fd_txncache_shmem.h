#ifndef HEADER_fd_src_flamenco_runtime_fd_txncache_shmem_h
#define HEADER_fd_src_flamenco_runtime_fd_txncache_shmem_h

#include "../../util/fd_util_base.h"

#define FD_TXNCACHE_SHMEM_ALIGN (128UL)

#define FD_TXNCACHE_SHMEM_MAGIC (0xF17EDA2CE58CC4E1UL) /* FIREDANCE SMCCHE V1 */

/* FD_TXNCACHE_MAX_SLOT_DELTAS is the practical bound on the maximum
   number of slot deltas that can be stored into the txncache.  This
   bound is derived from the recent blockhashes sysvar. */

#define FD_TXNCACHE_MAX_SLOT_DELTAS (151UL)

/* FD_TXNCACHE_RAM_TXNPAGES is the number of txnpages resident in
   locked memory.  The remaining capacity lives in a disk file accessed
   with explicit pread/pwrite ("the disk tier").  Entries are only
   written to RAM pages; when the RAM pool runs low, the pages of the
   coldest blockhashes are migrated wholesale to the disk tier.

   Sizing: entries stay queryable for the ~151 blockhash validity
   window plus the ~151 root retention window, roughly 134 seconds of
   committed transactions.  1024 pages hold 8.4M entries, reached only
   at ~62k sustained committed TPS (~12x the mainnet all-time-high),
   so at mainnet load the disk tier is never touched.  Catchup with a
   deep unrooted backlog and adversarial max-fill regimes spill, which
   is graceful: total capacity is unchanged, only residency moves.

   If the configured capacity is at most this many pages (tests, small
   topologies), or larger_max_cost_per_block is set (bench topologies,
   which are latency experiments and must stay fully resident), no disk
   tier is created and behavior is identical to the untiered design. */

#define FD_TXNCACHE_RAM_TXNPAGES (1024UL)

/* File descriptor number where the txncache disk tier file is
   installed by the boot process (see initialize_accdb_fd), like
   FD_ACCDB_FD_RW (123461)/FD_ACCDB_FD_RO (123460).  123458/123459 are
   the stake delegation/reward spill files, 123462 is reserved by
   XDP. */

#define FD_TXNCACHE_FD (123457)

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

/* fd_txncache_disk_footprint returns the size in bytes of the disk
   tier file backing a txncache created with the given parameters, or
   0UL if the configuration has no disk tier. */

FD_FN_CONST ulong
fd_txncache_disk_footprint( ulong max_live_slots,
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
