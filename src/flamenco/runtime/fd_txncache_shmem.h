#ifndef HEADER_fd_src_flamenco_runtime_fd_txncache_shmem_h
#define HEADER_fd_src_flamenco_runtime_fd_txncache_shmem_h

#include "../../util/fd_util_base.h"

#define FD_TXNCACHE_SHMEM_ALIGN (128UL)

#define FD_TXNCACHE_SHMEM_MAGIC (0xF17EDA2CE58CC4E1UL) /* FIREDANCE SMCCHE V1 */

/* FD_TXNCACHE_MAX_SLOT_DELTAS is the practical bound on the maximum
   number of slot deltas that can be stored into the txncache.  This
   bound is derived from the recent blockhashes sysvar. */

#define FD_TXNCACHE_MAX_SLOT_DELTAS (151UL)

typedef struct { ushort val; } fd_txncache_fork_id_t;

struct fd_txncache_shmem_private;
typedef struct fd_txncache_shmem_private fd_txncache_shmem_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_txncache_shmem_align( void );

/* The txnpage pool is sized for the worst case set of simultaneously
   live transactions: a full snapshot load (151 slot deltas at
   max_txn_per_slot entries, which counts each transaction twice) plus
   every other active fork full at max_txn_per_slot/2.  Callers pass
   2*config->limits.max_txn_per_slot, so a raised [development.bench]
   block cost limit sizes the pool up through that value.

   footprint and new return 0 / NULL for zero max_live_slots or
   max_txn_per_slot, and log an error and exit if the parameters need a
   txnpage pool larger than the structure can address. */

ulong
fd_txncache_shmem_footprint( ulong max_live_slots,
                             ulong max_txn_per_slot );

void *
fd_txncache_shmem_new( void * shmem,
                       ulong  max_live_slots,
                       ulong  max_txn_per_slot,
                       ulong  seed );

fd_txncache_shmem_t *
fd_txncache_shmem_join( void * shtc );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_txncache_shmem_h */
