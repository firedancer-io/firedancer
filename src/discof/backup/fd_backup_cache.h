
#ifndef HEADER_fd_src_discof_backup_fd_backup_cache_h
#define HEADER_fd_src_discof_backup_fd_backup_cache_h

/* fd_backup_cache.h finds rooted accounts that are in accdb cache.
   Publishes discovered accounts (by pubkey and account index) onto
   mcache/dcache. */

#include "fd_backup.h"
#include "fd_backup_accidx.h"
#include "../../flamenco/accdb/fd_accdb_cache.h"
#include "../../flamenco/runtime/fd_runtime_const.h"

#define SNAPZP_TILE_MAX 64

/* fd_backup_cache_t scans accdb caches for rooted accounts.
   Assumes compaction and rooting is disabled during the scan.
   Concurrent access (e.g. cache eviction) during the scan is fine.
   May produce duplicates.
   Usage like:
     fd_backup_cache_t scan[1];
     fd_backup_cache_msg_t frag[1];
     while( fd_backup_cache_scan( scan, frag ) ) {
       for( ulong i=0UL; i<FD_BACKUP_CACHE_PARA; i++ ) {
         fd_pubkey_t const * pubkey  = &frag->pubkey [ i ];
         uint                acc_idx =  frag->acc_idx[ i ];
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

  fd_backup_accidx_t idx;

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
   given shared memory cache size classes and accdb account index. */

fd_backup_cache_t *
fd_backup_cache_init( fd_backup_cache_t *        backup,
                      uchar const * const        cache    [ FD_ACCDB_CACHE_CLASS_CNT ],
                      ulong const                cache_max[ FD_ACCDB_CACHE_CLASS_CNT ],
                      fd_backup_accidx_t const * idx );

/* fd_backup_cache_join is a convenience API for joining an accdb_shmem.
   epoch_fseq is the tile-owned external epoch slot that accdb scans
   during deferred reclamation. */

fd_backup_cache_t *
fd_backup_cache_join( fd_backup_cache_t * backup,
                      fd_accdb_shmem_t *  accdb_shmem,
                      ulong *             epoch_fseq );

/* fd_backup_cache_scan yields a batch of rooted accounts found in
   cache.  Returns NULL once the scan completes. */

fd_backup_cache_msg_t *
fd_backup_cache_scan( fd_backup_cache_t *     backup,
                      fd_backup_cache_msg_t * frag );

/* fd_backup_cache_reset rewinds the scanner. */

static inline void
fd_backup_cache_reset( fd_backup_cache_t * backup,
                       ulong               root_generation ) {
  backup->idx.root_generation = (uint)root_generation;
  backup->cache_class         = 0;
  backup->cache_idx           = 0;
}

/* fd_backup_cache_read copy-reads a possibly cached account into out.
   *out_sz is the current size of out and is advanced on success.  The
   account is laid out in snapshot storage format. */

#define FD_BACKUP_CACHE_SUCCESS   0 /* ok */
#define FD_BACKUP_CACHE_ERR_SPACE 1 /* not enough buffer space */
#define FD_BACKUP_CACHE_ERR_MISS  2 /* not in cache */

int
fd_backup_cache_read( fd_backup_cache_t * ctx,
                      fd_pubkey_t const * pubkey,
                      uint                acc_idx,
                      uchar *             out,
                      ulong *             out_sz,
                      ulong               out_max );

/* Metrics APIs */

/* fd_backup_cache_scanned_bytes returns the number of bytes scanned so
   far. */

FD_FN_PURE static inline ulong
fd_backup_cache_scanned_bytes( fd_backup_cache_t const * backup ) {
  ulong cur = fd_ulong_min( backup->cache_class, FD_ACCDB_CACHE_CLASS_CNT );
  ulong scanned = 0UL;
  for( ulong cls=0UL; cls<cur; cls++ ) {
    scanned += backup->cache_max[ cls ]*fd_accdb_cache_slot_sz[ cls ];
  }
  if( FD_LIKELY( cur<FD_ACCDB_CACHE_CLASS_CNT ) ) {
    scanned += backup->cache_idx*fd_accdb_cache_slot_sz[ cur ];
  }
  return scanned;
}

/* fd_backup_cache_total_bytes returns the total number of bytes that the
   accdb cache spans. */

FD_FN_PURE static inline ulong
fd_backup_cache_total_bytes( fd_backup_cache_t const * backup ) {
  ulong total = 0UL;
  for( ulong cls=0UL; cls<FD_ACCDB_CACHE_CLASS_CNT; cls++ ) {
    total += backup->cache_max[ cls ]*fd_accdb_cache_slot_sz[ cls ];
  }
  return total;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_backup_cache_h */
