#define _GNU_SOURCE
#include "fd_shredb.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static inline ulong
fd_shredb_max_shreds_for_gib( ulong max_size_gib ) {
  return (max_size_gib*1024UL*1024UL*1024UL) / sizeof(fd_shredb_entry_t);
}

/* We size the slot map such that it will never fill before we start
   evicting from the shred_map/ring buffer. The minimum number of shreds
   per slot is 32 (one FEC set), so it is guaranteed that in the worst case
   we will be able to represent every FEC set inserted into the database.

   Remember that we will always be inserting complete sets, consisting of
   32 data shreds at a time. */
static inline ulong
fd_shredb_max_slots_for_gib( ulong max_size_gib ) {
  return fd_shredb_max_shreds_for_gib( max_size_gib ) / 32UL;
}

FD_FN_CONST ulong
fd_shredb_footprint( ulong max_size_gib ) {
  if( FD_UNLIKELY( !max_size_gib ) ) return 0UL;

  ulong max_shreds = fd_shredb_max_shreds_for_gib( max_size_gib );
  ulong max_slots  = fd_shredb_max_slots_for_gib ( max_size_gib );

  int lg_shred_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( max_shreds ) );
  int lg_slot_cnt  = fd_ulong_find_msb( fd_ulong_pow2_up( max_slots  ) );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_shredb_t),        sizeof(fd_shredb_t)                           );
  l = FD_LAYOUT_APPEND( l, fd_shredb_shred_map_align(), fd_shredb_shred_map_footprint( lg_shred_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_shredb_slot_map_align(),  fd_shredb_slot_map_footprint ( lg_slot_cnt  ) );
  ulong bitset_words = (max_shreds + 63UL) / 64UL;
  l = FD_LAYOUT_APPEND( l, alignof(ulong),              max_shreds   * sizeof(ulong)                  ); /* evict_keys     */
  l = FD_LAYOUT_APPEND( l, alignof(ulong),              bitset_words * sizeof(ulong)                  ); /* evict_occupied */
  return FD_LAYOUT_FINI( l, fd_shredb_align() );
}

void *
fd_shredb_new( void       * shmem,
               ulong        max_size_gib,
               char const * file_path,
               ulong        seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_shredb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !file_path ) ) {
    FD_LOG_WARNING(( "NULL file_path" ));
    return NULL;
  }

  ulong footprint = fd_shredb_footprint( max_size_gib );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad max_size_gib (%lu)", max_size_gib ));
    return NULL;
  }

  ulong max_shreds = fd_shredb_max_shreds_for_gib( max_size_gib );
  ulong max_slots  = fd_shredb_max_slots_for_gib ( max_size_gib );

  int lg_shred_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( max_shreds ) );
  int lg_slot_cnt  = fd_ulong_find_msb( fd_ulong_pow2_up( max_slots  ) );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  /**/                   FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_shredb_t),        sizeof(fd_shredb_t)                           );
  void * shred_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_shredb_shred_map_align(), fd_shredb_shred_map_footprint( lg_shred_cnt ) );
  void * slot_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_shredb_slot_map_align(),  fd_shredb_slot_map_footprint ( lg_slot_cnt  ) );
  ulong bitset_words = (max_shreds + 63UL) / 64UL;
  void * evict_k_mem   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),              max_shreds   * sizeof(ulong)                  );
  void * evict_o_mem   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),              bitset_words * sizeof(ulong)                  );

  fd_shredb_t * store = (fd_shredb_t *)shmem;
  store->shred_map      = fd_shredb_shred_map_new( shred_map_mem, lg_shred_cnt, seed );
  store->slot_map       = fd_shredb_slot_map_new ( slot_map_mem,  lg_slot_cnt,  seed );
  store->evict_keys     = (ulong *)evict_k_mem;
  store->evict_occupied = (ulong *)evict_o_mem;
  fd_memset( store->evict_occupied, 0, bitset_words * sizeof(ulong) );

  int fd = open( file_path, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600 );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "open(%s) failed (%i-%s)", file_path, errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  ulong initial_shreds = 128UL;
  ulong initial_sz     = initial_shreds * sizeof(fd_shredb_entry_t);
  if( FD_UNLIKELY( fallocate( fd, 0, 0, (off_t)initial_sz ) ) ) {
    FD_LOG_WARNING(( "fallocate failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( fd );
    return NULL;
  }

  store->max_shreds  = max_shreds;
  store->write_head  = 0UL;
  store->cnt         = 0UL;
  store->fd          = fd;
  store->file_shreds = initial_shreds;

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_shredb_align() )==(ulong)shmem + footprint );

  return shmem;
}

fd_shredb_t *
fd_shredb_join( void * shstore ) {
  if( FD_UNLIKELY( !shstore ) ) {
    FD_LOG_WARNING(( "NULL shstore" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shstore, fd_shredb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shstore" ));
    return NULL;
  }

  fd_shredb_t * store = (fd_shredb_t *)shstore;
  store->shred_map     = fd_shredb_shred_map_join( store->shred_map );
  store->slot_map      = fd_shredb_slot_map_join ( store->slot_map  );

  return (fd_shredb_t *)shstore;
}

void *
fd_shredb_leave( fd_shredb_t const * store ) {
  if( FD_UNLIKELY( !store ) ) {
    FD_LOG_WARNING(( "NULL store" ));
    return NULL;
  }

  return (void *)store;
}

void *
fd_shredb_delete( void * shstore ) {
  if( FD_UNLIKELY( !shstore ) ) {
    FD_LOG_WARNING(( "NULL shstore" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shstore, fd_shredb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shstore" ));
    return NULL;
  }

  fd_shredb_t * store = (fd_shredb_t *)shstore;
  close( store->fd );

  return shstore;
}

static void
fd_shredb_slot_evict( fd_shredb_t * store,
                      ulong         slot,
                      uint          evicted_shred_idx ) {
  fd_shredb_slot_entry_t * se = fd_shredb_slot_map_query( store->slot_map, slot, NULL );
  FD_TEST( se );

  se->cnt--;
  if( FD_UNLIKELY( se->cnt==0UL ) ) {
    fd_shredb_slot_map_remove( store->slot_map, se );
    return;
  }

  /* If the shred evicted was the highest in that slot, walk down and
     find the new highest that still exists in the per-shred map. */
  if( evicted_shred_idx==se->highest_shred_idx ) {
    for( uint idx = evicted_shred_idx; ; idx-- ) {
      ulong key = fd_shredb_key_pack( slot, idx );
      if( fd_shredb_shred_map_query( store->shred_map, key, NULL ) ) {
        se->highest_shred_idx = idx;
        return;
      }
      if( FD_UNLIKELY( idx==0U ) ) break;
    }
    FD_LOG_ERR(( "corrupt store state" ));
  }
}

void
fd_shredb_insert( fd_shredb_t      * store,
                  fd_shred_t const * shred ) {
  ulong shred_sz  = fd_shred_sz( shred );
  ulong slot      = shred->slot;
  uint  shred_idx = shred->idx;

  ulong key = fd_shredb_key_pack( slot, shred_idx );
  if( fd_shredb_shred_map_query( store->shred_map, key, NULL ) ) return;

  /* Grow the backing file if the write head has reached the current
     file capacity.  Double the file size each time (superlinear growth)
     until we hit max_shreds, after which the ring simply evicts. */
  if( FD_UNLIKELY( store->write_head>=store->file_shreds ) ) {
    ulong old_file_sz     = store->file_shreds * sizeof(fd_shredb_entry_t);
    ulong new_file_shreds = fd_ulong_min( store->file_shreds * 2UL, store->max_shreds );
    ulong new_file_sz     = new_file_shreds * sizeof(fd_shredb_entry_t);
    if( FD_UNLIKELY( fallocate( store->fd, 0, (off_t)old_file_sz, (off_t)(new_file_sz - old_file_sz) ) ) ) {
      FD_LOG_ERR(( "fallocate failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    store->file_shreds = new_file_shreds;
  }

  ulong wh_word = store->write_head / 64UL;
  ulong wh_bit  = store->write_head % 64UL;
  if( FD_LIKELY( store->evict_occupied[ wh_word ] & (1UL << wh_bit) ) ) {
    ulong old_key  = store->evict_keys[ store->write_head ];
    ulong old_slot = fd_shredb_key_slot( old_key );
    uint  old_idx  = fd_shredb_key_shred_idx( old_key );

    fd_shredb_shred_entry_t * old = fd_shredb_shred_map_query( store->shred_map, old_key, NULL );
    if( FD_LIKELY( old ) ) fd_shredb_shred_map_remove( store->shred_map, old );

    fd_shredb_slot_evict( store, old_slot, old_idx );
    store->cnt--;
  }

  fd_shredb_entry_t wr_entry[1];
  wr_entry->shred_sz = (ushort)shred_sz;
  fd_memcpy( wr_entry->shred, shred, shred_sz );

  off_t off = (off_t)(store->write_head * sizeof(fd_shredb_entry_t));
  long res = pwrite( store->fd, wr_entry, sizeof(fd_shredb_entry_t), off );
  if( FD_UNLIKELY( res!=(long)sizeof(fd_shredb_entry_t) ) ) FD_LOG_ERR(( "error writing to shredb: (%d-%s)", errno, fd_io_strerror( errno ) ));

  store->evict_keys    [ store->write_head ] = key;
  store->evict_occupied[ wh_word ] |= (1UL << wh_bit);

  fd_shredb_shred_entry_t * map_entry = fd_shredb_shred_map_insert( store->shred_map, key );
  FD_TEST( map_entry );
  map_entry->ring_idx = store->write_head;

  fd_shredb_slot_entry_t * se = fd_shredb_slot_map_query( store->slot_map, slot, NULL );
  if( FD_LIKELY( se ) ) {
    se->cnt++;
    se->highest_shred_idx = fd_uint_max( se->highest_shred_idx, shred_idx );
  } else {
    se = fd_shredb_slot_map_insert( store->slot_map, slot );
    FD_TEST( se );
    se->highest_shred_idx = shred_idx;
    se->cnt               = 1UL;
  }

  store->cnt++;
  store->write_head = (store->write_head + 1UL) % store->max_shreds;
}

int
fd_shredb_query( fd_shredb_t * store,
                 ulong         slot,
                 uint          shred_idx,
                 uchar         out[ FD_SHRED_MAX_SZ ] ) {
  /* Fast-fail, if we have never heard of this slot, we must have no shreds for it. */
  if( !fd_shredb_slot_map_query( store->slot_map, slot, NULL ) ) return -1;

  ulong key = fd_shredb_key_pack( slot, shred_idx );
  fd_shredb_shred_entry_t const * map_entry = fd_shredb_shred_map_query( store->shred_map, key, NULL );
  if( FD_UNLIKELY( !map_entry ) ) return -1; /* No such shred. */

  fd_shredb_entry_t rd_entry[1];
  off_t off = (off_t)(map_entry->ring_idx * sizeof(fd_shredb_entry_t));
  long res = pread( store->fd, rd_entry, sizeof(fd_shredb_entry_t), off );
  if( FD_UNLIKELY( res!=(long)sizeof(fd_shredb_entry_t) ) ) FD_LOG_ERR(( "error reading from shredb: (%d-%s)", errno, fd_io_strerror( errno ) ));

  fd_memcpy( out, rd_entry->shred, rd_entry->shred_sz );
  return rd_entry->shred_sz;
}

int fd_shredb_query_highest( fd_shredb_t * store,
                             ulong         slot,
                             uint          min_shred_idx,
                             uchar         out[ FD_SHRED_MAX_SZ ] ) {
  fd_shredb_slot_entry_t * se = fd_shredb_slot_map_query( store->slot_map, slot, NULL );
  if( FD_UNLIKELY( !se ) ) return -1;

  /* Check if the highest known index meets the threshold. */
  if( se->highest_shred_idx < min_shred_idx ) return -1;

  ulong key = fd_shredb_key_pack( slot, se->highest_shred_idx );
  fd_shredb_shred_entry_t const * map_entry = fd_shredb_shred_map_query( store->shred_map, key, NULL );
  FD_TEST( map_entry );

  fd_shredb_entry_t rd_entry[1];
  off_t off = (off_t)(map_entry->ring_idx * sizeof(fd_shredb_entry_t));
  long res = pread( store->fd, rd_entry, sizeof(fd_shredb_entry_t), off );
  if( FD_UNLIKELY( res!=(long)sizeof(fd_shredb_entry_t) ) ) FD_LOG_ERR(( "error reading from shredb: (%d-%s)", errno, fd_io_strerror( errno ) ));

  fd_memcpy( out, rd_entry->shred, rd_entry->shred_sz );
  return rd_entry->shred_sz;
}
