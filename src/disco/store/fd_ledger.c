#include "fd_ledger.h"

#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <stdio.h>

FD_FN_UNUSED static void log_ring_entry( fd_ledger_entry_t const * entry ) {
  ulong slot = fd_ledger_key_slot( entry->key );
  uint  idx  = fd_ledger_key_shred_idx( entry->key );
  FD_LOG_NOTICE(("%s (slot=%lu, idx=%u, shred_sz=%u)", entry->occupied ? "USED" : "EMPTY", slot, idx, entry->shred_sz));
}


static inline fd_ledger_entry_t *
fd_ledger_ring( fd_ledger_t * ledger ) {
  return (fd_ledger_entry_t *)ledger->mapped;
}

static inline int
fd_ledger_lg_shred_cnt( ulong n ) {
  int lg = 1;
  while( (1UL<<lg) < 2UL*n ) lg++;
  return lg;
}

FD_FN_CONST ulong
fd_ledger_footprint( ulong max_shreds ) {
  if( FD_UNLIKELY( !max_shreds ) ) return 0UL;

  int lg_shred_cnt = fd_ledger_lg_shred_cnt( max_shreds );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_ledger_t),        sizeof(fd_ledger_t)                           );
  l = FD_LAYOUT_APPEND( l, fd_ledger_shred_map_align(), fd_ledger_shred_map_footprint( lg_shred_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_ledger_slot_map_align(),  fd_ledger_slot_map_footprint ( lg_shred_cnt ) );
  return FD_LAYOUT_FINI( l, fd_ledger_align() );
}

void *
fd_ledger_new( void       * shmem,
               ulong        max_shreds, /* TODO: rename all of these fields from max_shreds */
               char const * file_path,
               ulong        seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ledger_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !file_path ) ) {
    FD_LOG_WARNING(( "NULL file_path" ));
    return NULL;
  }

  ulong footprint = fd_ledger_footprint( max_shreds );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad max_shreds (%lu)", max_shreds ));
    return NULL;
  }

  int lg_shred_cnt = fd_ledger_lg_shred_cnt( max_shreds );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  /**/                   FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ledger_t),        sizeof(fd_ledger_t)                           );
  void * shred_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_ledger_shred_map_align(), fd_ledger_shred_map_footprint( lg_shred_cnt ) );
  void * slot_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_ledger_slot_map_align(),  fd_ledger_slot_map_footprint ( lg_shred_cnt ) );

  fd_ledger_t * ledger = (fd_ledger_t *)shmem;
  ledger->shred_map    = fd_ledger_shred_map_new( shred_map_mem, lg_shred_cnt, seed );
  ledger->slot_map     = fd_ledger_slot_map_new ( slot_map_mem,  lg_shred_cnt, seed );

  int fd = open( file_path, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600 );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "open(%s) failed (%i-%s)", file_path, errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  
  ulong mapped_sz = max_shreds * sizeof(fd_ledger_entry_t);
  if( FD_UNLIKELY( ftruncate( fd, (off_t)mapped_sz ) ) ) {
    FD_LOG_WARNING(( "ftruncate failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( fd );
    return NULL;
  }

  ledger->mapped = mmap( NULL, mapped_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
  if( FD_UNLIKELY( ledger->mapped==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap failed (%i-%s)", errno, fd_io_strerror( errno  ) ));
    close( fd );
    return NULL;
  }

  /* We don't need the descriptor open after we mmap(). */
  close( fd );

  fd_memset( ledger->mapped, 0, mapped_sz );
  ledger->max_shreds = max_shreds;
  ledger->write_head = 0UL;
  ledger->cnt        = 0UL;
  ledger->mapped_sz  = mapped_sz;
  ledger->fd         = fd;

  /* TODO: The slot map does NOT need to be the same size as the shred map,
           it can be much smaller. Think more about the logic used to decide
           the number of shreds/slots we store. */
  fd_ledger_shred_entry_t * shred_map = fd_ledger_shred_map_join( ledger->shred_map );
  fd_ledger_slot_entry_t  * slot_map  = fd_ledger_slot_map_join ( ledger->slot_map  );
  FD_TEST( fd_ulong_pow2( lg_shred_cnt )          ==fd_ledger_shred_map_slot_cnt( shred_map ) );
  FD_TEST( fd_ledger_slot_map_slot_cnt( slot_map )==fd_ledger_shred_map_slot_cnt( shred_map ) );

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_ledger_align() )==(ulong)shmem + footprint );

  return shmem;
}

fd_ledger_t *
fd_ledger_join( void * shledger ) {
  if( FD_UNLIKELY( !shledger ) ) {
    FD_LOG_WARNING(( "NULL shledger" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shledger, fd_ledger_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shledger" ));
    return NULL;
  }

  fd_ledger_t * ledger = (fd_ledger_t *)shledger;
  ledger->shred_map = fd_ledger_shred_map_join( ledger->shred_map );
  ledger->slot_map  = fd_ledger_slot_map_join ( ledger->slot_map  );

  return (fd_ledger_t *)shledger;
}

void *
fd_ledger_leave( fd_ledger_t const * ledger ) {
  if( FD_UNLIKELY( !ledger ) ) {
    FD_LOG_WARNING(( "NULL ledger" ));
    return NULL;
  }

  return (void *)ledger;
}

void *
fd_ledger_delete( void * shledger ) {
  if( FD_UNLIKELY( !shledger ) ) {
    FD_LOG_WARNING(( "NULL shledger" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shledger, fd_ledger_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shledger" ));
    return NULL;
  }

  fd_ledger_t * ledger = (fd_ledger_t *)shledger;
  if( FD_UNLIKELY( !ledger->mapped ) ) {
    FD_LOG_WARNING(( "NULL mapped" ));
    return NULL;
  }
  munmap( ledger->mapped, ledger->mapped_sz );

  return shledger;
}

static void
fd_ledger_slot_evict( fd_ledger_t * ledger,
                      ulong         slot,
                      uint          evicted_shred_idx ) {
  fd_ledger_slot_entry_t * se = fd_ledger_slot_map_query( ledger->slot_map, slot, NULL );
  FD_TEST( se );

  se->cnt--;
  if( se->cnt==0UL ) {
    fd_ledger_slot_map_remove( ledger->slot_map, se );
    return;
  }

  /* If the shred evicted was the highest in that slot, walk down and
     find the new highest that still exists in the per-shred map. */
  if( evicted_shred_idx==se->highest_shred_idx ) {
    for( uint idx = evicted_shred_idx; idx>0; idx-- ) {
      ulong key = fd_ledger_key_pack( slot, idx );
      if( fd_ledger_shred_map_query( ledger->shred_map, key, NULL ) ) {
        se->highest_shred_idx = idx;
        return;
      }
    }
    /* This shouldn't be reachable if cnt>0. */
    FD_CRIT( 0, "corrupt ledger state" ); /* TODO: remove this */
  }
}

void
fd_ledger_insert( fd_ledger_t * ledger,
                  uchar const * shred,
                  ulong         shred_sz,
                  ulong         slot,
                  uint          shred_idx ) {
  FD_TEST( shred_sz<=FD_SHRED_MAX_SZ );

  FD_LOG_DEBUG(( "inserting slot=%lu, idx=%u, shred_sz=%lu", slot, shred_idx, shred_sz ));
  ulong key = fd_ledger_key_pack( slot, shred_idx );

  /* If the key already exists, return early, thus doing nothing. */
  if( fd_ledger_shred_map_query( ledger->shred_map, key, NULL ) ) return;

  fd_ledger_entry_t * ring = fd_ledger_ring( ledger );
  fd_ledger_entry_t * entry = &ring[ ledger->write_head ];

  /* If this ring entry is occupied, evict the old entry */
  if( entry->occupied ) {
    ulong old_slot = fd_ledger_key_slot( entry->key );
    uint  old_idx  = fd_ledger_key_shred_idx( entry->key );

    fd_ledger_shred_entry_t * old = fd_ledger_shred_map_query( ledger->shred_map, entry->key, NULL );
    if( FD_LIKELY( old ) ) fd_ledger_shred_map_remove( ledger->shred_map, old );

    fd_ledger_slot_evict( ledger, old_slot, old_idx );
    ledger->cnt--;
  }

  entry->key      = key;
  entry->shred_sz = (ushort)shred_sz;
  entry->occupied = 1;
  fd_memcpy( entry->shred, shred, shred_sz );

  fd_ledger_shred_entry_t * map_entry = fd_ledger_shred_map_insert( ledger->shred_map, key );
  /* May only fail if key is already present, but we checked for that at the start of insert(). */
  FD_TEST( map_entry );
  map_entry->ring_idx = ledger->write_head;

  fd_ledger_slot_entry_t * se = fd_ledger_slot_map_query( ledger->slot_map, slot, NULL );
  if( !se ) {
    se = fd_ledger_slot_map_insert( ledger->slot_map, slot );
    /* May only fail if the key already exists, which we've just shown doesn't. */
    FD_TEST( se );
    /* This is the only shred we know of, so it'll be the highest. */
    se->highest_shred_idx = shred_idx;
    se->cnt               = 1UL;
  } else {
    se->cnt++;
    /* If this is a higher shred, indicate so. */
    se->highest_shred_idx = fd_uint_max( se->highest_shred_idx, shred_idx );
  }

  ledger->cnt++;
  ledger->write_head = (ledger->write_head + 1UL) % ledger->max_shreds;
}

int
fd_ledger_query( fd_ledger_t * ledger,
                 uchar         out[ FD_SHRED_MAX_SZ ],
                 ulong         slot,
                 uint          shred_idx ) {
  /* Fast-fail, if we have never heard of this slot, we must have no shreds for it. */
  if( !fd_ledger_slot_map_query( ledger->slot_map, slot, NULL ) ) return -1;

  ulong key = fd_ledger_key_pack( slot, shred_idx );
  fd_ledger_shred_entry_t const * map_entry = fd_ledger_shred_map_query( ledger->shred_map, key, NULL );
  if( FD_UNLIKELY( !map_entry ) ) return -1; /* No such shred. */

  fd_ledger_entry_t * ring  = fd_ledger_ring( ledger );
  fd_ledger_entry_t * entry = &ring[ map_entry->ring_idx ];
  fd_memcpy( out, entry->shred, entry->shred_sz );
  return entry->shred_sz;
}

int fd_ledger_query_highest( fd_ledger_t * ledger,
                             uchar         out[ FD_SHRED_MAX_SZ ],
                             ulong         slot,
                             uint          min_shred_idx ) {
  fd_ledger_slot_entry_t * se = fd_ledger_slot_map_query( ledger->slot_map, slot, NULL );
  if( FD_UNLIKELY( !se ) ) return -1;

  /* Check if the highest known index meets the threshold. */
  if( se->highest_shred_idx < min_shred_idx ) return -1;

  ulong key = fd_ledger_key_pack( slot, se->highest_shred_idx );
  fd_ledger_shred_entry_t const * map_entry = fd_ledger_shred_map_query( ledger->shred_map, key, NULL );
  FD_TEST( map_entry ); /* We set highest_shred_idx after an insert(), so it must still be here. */

  fd_ledger_entry_t * ring  = fd_ledger_ring( ledger );
  fd_ledger_entry_t * entry = &ring[ map_entry->ring_idx ];
  fd_memcpy( out, entry->shred, entry->shred_sz );
  return entry->shred_sz;
}
