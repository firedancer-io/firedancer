#ifndef HEADER_fd_src_flamenco_runtime_fd_txncache_shmem_h
#define HEADER_fd_src_flamenco_runtime_fd_txncache_shmem_h

#include "../../util/fd_util_base.h"

#define FD_TXNCACHE_SHMEM_ALIGN (128UL)

#define FD_TXNCACHE_SHMEM_MAGIC (0xF17EDA2CE58CC4E0) /* FIREDANCE SMCCHE V0 */

/* The maximum distance a transaction blockhash reference can be
   (inclusive).  For example, if no slots were skipped, and the value is
   151, slot 300 is allowed to reference blockhashes from slots
   [149, 300). */
#define FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE (151UL)

typedef struct { ushort val; } fd_txncache_fork_id_t;

struct fd_txncache_shmem_private;
typedef struct fd_txncache_shmem_private fd_txncache_shmem_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_txncache_shmem_align( void );

FD_FN_CONST ulong
fd_txncache_shmem_footprint_ext( ulong max_live_slots,
                                 ulong max_blockhash_distance,
                                 ulong max_txn_per_slot );

FD_FN_CONST static inline ulong
fd_txncache_shmem_footprint( ulong max_live_slots,
                             ulong max_txn_per_slot ) {
  return fd_txncache_shmem_footprint_ext( max_live_slots, FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE, max_txn_per_slot );
}

void *
fd_txncache_shmem_new_ext( void * shmem,
                           ulong  max_live_slots,
                           ulong  max_blockhash_distance,
                           ulong  max_txn_per_slot );

static inline void *
fd_txncache_shmem_new( void * shmem,
                       ulong  max_live_slots,
                       ulong  max_txn_per_slot ) {
  return fd_txncache_shmem_new_ext( shmem, max_live_slots, FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE, max_txn_per_slot );
}

fd_txncache_shmem_t *
fd_txncache_shmem_join( void * shtc );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_txncache_shmem_h */
