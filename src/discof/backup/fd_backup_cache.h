#ifndef HEADER_fd_src_discof_backup_fd_backup_cache_h
#define HEADER_fd_src_discof_backup_fd_backup_cache_h

/* fd_backup_cache.h finds rooted accounts that are in accdb cache.

   Publishes discovered accounts (by pubkey and account index) onto
   mcache/dcache. */

#include "fd_backup.h"
#include "../../flamenco/accdb/fd_accdb_cache.h"
#include "../../flamenco/accdb/fd_accdb.h"
#define FD_ACCDB_NO_FORK_ID
#include "../../flamenco/accdb/fd_accdb_private.h"
#include "../../flamenco/runtime/fd_runtime_const.h"
#include <zstd.h>

#define SNAPZP_TILE_MAX 64

/* fd_backup_cache_t scans accdb caches for rooted accounts.
   Assumes compaction and rooting is disabled during the scan.
   Concurrent access (e.g. cache eviction) during the scan is fine.
   May produce duplicates.

   Usage like:

     fd_backup_cache_t scan[1];
     fd_backup_frag_t frag[1];
     while( fd_backup_cache_scan( scan, frag ) ) {
       for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
         fd_pubkey_t const * pubkey  = &frag->acc_cache.pubkey [ i ];
         uint                acc_idx =  frag->acc_cache.acc_idx[ i ];
         if( acc_idx==UINT_MAX ) continue;
         if( fd_backup_cache_read( ..., pubkey, acc_idx, ... ) ) {
           // ... process account ...
         }
       }
     }

   Designed to be send frags to a remote thread via IPC. */

struct fd_backup_cache {
  uchar const * cache    [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong         cache_max[ FD_ACCDB_CACHE_CLASS_CNT ];

  uint const *               acc_map;
  fd_accdb_accmeta_t const * acc_pool;
  ulong                      max_accounts;
  ulong                      acc_map_seed;
  uint                       chain_mask;

  uint root_generation;

  ulong cache_class;
  ulong cache_idx;

  /* scratch memory
     (slightly faster to use struct memory than stack) */
  ulong              chain_idx[ FD_BACKUP_CACHE_PARA ];
  fd_accdb_accmeta_t meta     [ FD_BACKUP_CACHE_PARA ];
};

typedef struct fd_backup_cache fd_backup_cache_t;

struct fd_backup_acc {
  uchar pubkey[ 32 ];
  uchar owner [ 32 ];
  ulong lamports;
  ulong data_len : 32;
  ulong executable : 1;
  uchar data[ FD_RUNTIME_ACC_SZ_MAX ];
};

typedef struct fd_backup_acc fd_backup_acc_t;

FD_PROTOTYPES_BEGIN

/* fd_backup_cache_init creates a new cache scanner object over the
   given shared memory cache size classes, and in-memory account index
   acc_map/acc_pool.  max_accounts bounds account indices found in
   cache before they are used to index acc_pool. */

fd_backup_cache_t *
fd_backup_cache_init( fd_backup_cache_t *           backup,
                      uchar const * const           cache    [ FD_ACCDB_CACHE_CLASS_CNT ],
                      ulong const                   cache_max[ FD_ACCDB_CACHE_CLASS_CNT ],
                      uint const *                  acc_map,
                      fd_accdb_accmeta_t const *    acc_pool,
                      ulong                         max_accounts,
                      ulong                         acc_map_seed,
                      ulong                         chain_mask );

/* fd_backup_cache_join is a convenience API for joining an accdb_shmem.
   epoch_fseq is the tile-owned external epoch slot that accdb scans
   during deferred reclamation. */

fd_backup_cache_t *
fd_backup_cache_join( fd_backup_cache_t * backup,
                      fd_accdb_shmem_t *  accdb_shmem );

/* fd_backup_cache_scan yields a batch of rooted accounts found in
   cache.  Returns NULL once the scan completes. */

fd_backup_frag_t *
fd_backup_cache_scan( fd_backup_cache_t * backup,
                      fd_backup_frag_t *  frag );

static inline void
fd_backup_cache_reset( fd_backup_cache_t * backup,
                       ulong               root_generation ) {
  backup->root_generation = (uint)root_generation;
  backup->cache_class     = 0;
  backup->cache_idx       = 0;
}

/* fd_backup_cache_read copy-reads a possibly cached account into a
   Zstandard compress buffer.  The account is laid out in snapshot
   storage format. */

#define FD_BACKUP_CACHE_SUCCESS   0 /* ok */
#define FD_BACKUP_CACHE_ERR_SPACE 1 /* not enough buffer space */
#define FD_BACKUP_CACHE_ERR_MISS  2 /* not in cache */

int
fd_backup_cache_read( fd_backup_cache_t * ctx,
                      fd_pubkey_t const * pubkey,
                      uint                acc_idx,
                      ZSTD_inBuffer *     out,
                      ulong               out_max );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_backup_cache_h */
