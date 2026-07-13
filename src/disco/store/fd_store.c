#define _GNU_SOURCE
#include "fd_store.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>


static inline fd_shredb_shred_entry_t *
disk_shred_map_laddr( fd_store_t * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->shred_map_gaddr );
}

static inline fd_shredb_slot_entry_t *
disk_slot_map_laddr( fd_store_t * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->slot_map_gaddr );
}

static inline ulong *
disk_evict_keys_laddr( fd_store_t * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->evict_keys_gaddr );
}

static inline ulong *
disk_evict_occ_laddr( fd_store_t * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->evict_occ_gaddr );
}

static inline uchar *
cache_data_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->cache_data_gaddr );
}

static inline ulong *
cache_free_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->cache_free_gaddr );
}

static inline fd_store_fec_t *
pool_ele_laddr( fd_store_t const * store ) {
  return fd_wksp_laddr_fast( fd_store_wksp( store ), store->pool_ele_gaddr );
}

static void
disk_slot_evict( fd_store_t * store,
                 ulong        slot,
                 uint         evicted_shred_idx ) {
  fd_shredb_slot_entry_t * se = fd_shredb_slot_map_query( disk_slot_map_laddr( store ), slot, NULL );
  FD_TEST( se );

  se->cnt--;
  if( FD_UNLIKELY( se->cnt==0UL ) ) {
    fd_shredb_slot_map_remove( disk_slot_map_laddr( store ), se );
    return;
  }

  if( evicted_shred_idx==se->highest_shred_idx ) {
    for( uint idx = evicted_shred_idx; ; idx-- ) {
      ulong key = fd_shredb_key_pack( slot, idx );
      if( fd_shredb_shred_map_query( disk_shred_map_laddr( store ), key, NULL ) ) {
        se->highest_shred_idx = idx;
        return;
      }
      if( FD_UNLIKELY( idx==0U ) ) break;
    }
    FD_LOG_ERR(( "corrupt disk store state" ));
  }
}


static inline fd_store_pool_t
pool_ljoin( fd_store_t const * store ) {
  return (fd_store_pool_t){
      .pool    = fd_wksp_laddr_fast( fd_store_wksp( store ), store->pool_mem_gaddr ),
      .ele     = fd_wksp_laddr_fast( fd_store_wksp( store ), store->pool_ele_gaddr ),
      .ele_max = store->fec_max };
}

fd_store_fec_t *
fd_store_fec_acquire( fd_store_t * store ) {
  fd_store_pool_t pool = pool_ljoin( store );
  fd_store_fec_t * fec = fd_store_pool_acquire( &pool );
  if( FD_LIKELY( fec ) ) {
    fec->data_sz    = 0UL;
    fec->data_off   = 0UL;
    fec->cache_seq  = 0UL;
    fec->data_state = FD_STORE_FEC_DATA_EMPTY;
  }
  return fec;
}

void
fd_store_fec_release( fd_store_t * store, fd_store_fec_t * fec ) {
  fd_store_fec_data_consumed( store, fec );
  fd_store_pool_t pool = pool_ljoin( store );
  fd_store_pool_release( &pool, fec );
}


static int
cache_slot_release_locked( fd_store_t * store,
                           ulong        data_off ) {
  if( FD_UNLIKELY( data_off>=store->cache_slot_cnt*store->payload_slot_sz ) ) return -1;

  ulong * free = cache_free_laddr( store );
  FD_TEST( store->cache_free_cnt<store->cache_slot_cnt );
  free[ store->cache_free_cnt++ ] = data_off / store->payload_slot_sz;
  return 0;
}

static int
spill_one_locked( fd_store_t * store,
                  int          disk_fd ) {
  if( FD_UNLIKELY( disk_fd<0 ) ) return 0;

  fd_store_fec_t * fec0 = pool_ele_laddr( store );
  fd_store_fec_t * victim = NULL;
  ulong            victim_idx = ULONG_MAX;
  ulong            victim_seq = ULONG_MAX;

  for( ulong i=0UL; i<store->fec_max; i++ ) {
    fd_store_fec_t * fec = fec0 + i;
    if( FD_UNLIKELY( fec->data_state!=FD_STORE_FEC_DATA_RAM_READY ) ) continue;
    if( FD_UNLIKELY( !fec->data_sz ) ) continue;
    if( fec->cache_seq < victim_seq ) {
      victim     = fec;
      victim_idx = i;
      victim_seq = fec->cache_seq;
    }
  }

  if( FD_UNLIKELY( !victim ) ) return 0;

  ulong ram_off   = victim->data_off;
  ulong spill_off = victim_idx * store->payload_slot_sz;

  fd_store_disk_xlock_acquire( store );
  long res = pwrite( disk_fd, cache_data_laddr( store ) + ram_off, victim->data_sz, (off_t)spill_off );
  fd_store_disk_xlock_release( store );
  if( FD_UNLIKELY( res!=(long)victim->data_sz ) ) {
    FD_LOG_ERR(( "error spilling FEC payload to disk: (%d-%s)", errno, fd_io_strerror( errno ) ));
  }

  victim->data_off   = spill_off;
  victim->data_state = FD_STORE_FEC_DATA_DISK;
  store->fec_spill_cnt++;
  cache_slot_release_locked( store, ram_off );
  return 1;
}


void *
fd_store_new( void       * shmem,
              ulong        fec_max,
              ulong        fec_data_max,
              ulong        shred_storage_gib,
              ulong        shred_cache_bytes,
              ulong        fec_set_cnt,
              char const * db_path,
              ulong        seed ) {

  if( FD_UNLIKELY( !shmem ) ) { FD_LOG_WARNING(( "NULL shmem" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_store_align() ) ) ) { FD_LOG_WARNING(( "misaligned shmem" )); return NULL; }
  if( FD_UNLIKELY( !db_path || !db_path[0] ) ) { FD_LOG_WARNING(( "NULL db_path" )); return NULL; }
  if( FD_UNLIKELY( fd_cstr_nlen( db_path, 256UL )>=256UL ) ) { FD_LOG_WARNING(( "db_path too long" )); return NULL; }
  if( FD_UNLIKELY( !fec_max ) ) { FD_LOG_WARNING(( "fec_max must be non-zero" )); return NULL; }
  if( FD_UNLIKELY( !fec_data_max ) ) { FD_LOG_WARNING(( "fec_data_max must be non-zero" )); return NULL; }

  ulong footprint = fd_store_footprint( fec_max, fec_data_max, shred_storage_gib, shred_cache_bytes, fec_set_cnt );

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "shmem must be part of a workspace" )); return NULL; }

  ulong chain_cnt = fd_store_map_chain_cnt_est( fec_max );

  ulong payload_slot_sz = fd_store_payload_slot_sz( fec_data_max );
  ulong cache_slot_cnt  = shred_cache_bytes
                        ? fd_ulong_min( fec_max, fd_ulong_max( 1UL, shred_cache_bytes / payload_slot_sz ) )
                        : fec_max;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_store_t *     store     = FD_SCRATCH_ALLOC_APPEND( l, fd_store_align(),          sizeof(fd_store_t)                    );
  void *           map       = FD_SCRATCH_ALLOC_APPEND( l, fd_store_map_align(),      fd_store_map_footprint( chain_cnt )   );
  void *           shpool    = FD_SCRATCH_ALLOC_APPEND( l, fd_store_pool_align(),     fd_store_pool_footprint()             );
  void *           shele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_store_fec_t),   sizeof(fd_store_fec_t)*fec_max        );
  uchar *          cache_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_STORE_PAYLOAD_PAGE_SZ,  payload_slot_sz*cache_slot_cnt        );
  ulong *          cache_free= FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),            sizeof(ulong)*cache_slot_cnt          );
  fd_fec_set_t *   fec_sets  = NULL;
  if( fec_set_cnt ) {
    fec_sets = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_fec_set_t), sizeof(fd_fec_set_t)*fec_set_cnt );
  }

  void * shred_map_mem = NULL;
  void * slot_map_mem  = NULL;
  void * evict_k_mem   = NULL;
  void * evict_o_mem   = NULL;
  ulong  max_shreds    = 0UL;
  ulong  bitset_words  = 0UL;
  int    lg_shred_cnt  = 0;
  int    lg_slot_cnt   = 0;

  if( shred_storage_gib ) {
    max_shreds   = fd_shredb_max_shreds( shred_storage_gib );
    ulong max_slots = fd_shredb_max_slots( shred_storage_gib );
    lg_shred_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( max_shreds ) );
    lg_slot_cnt  = fd_ulong_find_msb( fd_ulong_pow2_up( max_slots  ) );
    bitset_words = (max_shreds + 63UL) / 64UL;

    shred_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_shredb_shred_map_align(), fd_shredb_shred_map_footprint( lg_shred_cnt ) );
    slot_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_shredb_slot_map_align(),  fd_shredb_slot_map_footprint ( lg_slot_cnt  ) );
    evict_k_mem   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),             max_shreds   * sizeof(ulong)                 );
    evict_o_mem   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),             bitset_words * sizeof(ulong)                 );
  }

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_store_align() )==(ulong)shmem + footprint );

  ulong payload_sz      = payload_slot_sz * fec_max;

  fd_memset( store, 0, sizeof(fd_store_t) );
  store->fec_max         = fec_max;
  store->fec_data_max    = fec_data_max;
  store->store_gaddr     = fd_wksp_gaddr_fast( wksp, store );
  store->pool_mem_gaddr  = fd_wksp_gaddr_fast( wksp, shpool );
  store->pool_ele_gaddr  = fd_wksp_gaddr_fast( wksp, shele  );
  store->payload_slot_sz = payload_slot_sz;
  store->payload_sz      = payload_sz;
  store->wire_off        = payload_sz; /* wire region begins after the payload region (page-aligned) */
  store->cache_slot_cnt  = cache_slot_cnt;
  store->cache_data_gaddr= fd_wksp_gaddr_fast( wksp, cache_mem );
  store->cache_free_gaddr= fd_wksp_gaddr_fast( wksp, cache_free );
  store->cache_free_cnt  = cache_slot_cnt;
  store->cache_seq       = 0UL;
  store->fec_set_cnt     = fec_set_cnt;
  store->fec_sets_gaddr  = fec_set_cnt ? fd_wksp_gaddr_fast( wksp, fec_sets ) : 0UL;
  fd_rwlock_new( &store->cache_lock );
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( store->db_path ), db_path, 255UL ) );

  void * shmap = fd_store_map_new( map, chain_cnt, seed );
  if( FD_UNLIKELY( !shmap ) ) { FD_LOG_WARNING(( "fd_store_map_new failed" )); return NULL; }
  store->map_gaddr = fd_wksp_gaddr_fast( wksp, shmap );

  if( FD_UNLIKELY( !fd_store_pool_new( shpool ) ) ) { FD_LOG_WARNING(( "fd_store_pool_new failed" )); return NULL; }
  fd_store_pool_t pool_ljoin;
  fd_store_pool_reset( fd_store_pool_join( &pool_ljoin, shpool, shele, fec_max ) );

  for( ulong i=0UL; i<cache_slot_cnt; i++ ) cache_free[ i ] = cache_slot_cnt - 1UL - i;

  /* FEC metadata starts without a payload location.  Writers acquire a
     RAM cache slot only when they are about to write payload bytes. */
  fd_store_fec_t * fec0 = (fd_store_fec_t *)shele;
  for( ulong i=0UL; i<fec_max; i++ ) {
    fec0[ i ].data_off   = 0UL;
    fec0[ i ].cache_seq  = 0UL;
    fec0[ i ].data_state = FD_STORE_FEC_DATA_EMPTY;
  }

  /* Create (or truncate) the single backing file.  Region [0,payload_sz)
     is the payload region, sized sparsely via ftruncate to hold all
     payload slots (only touched pages consume storage).  When the disk
     layer is enabled, the wire region [wire_off,...) is fallocated with
     an initial capacity just past wire_off. */
  {
    int fd = open( db_path, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600 );
    if( FD_UNLIKELY( fd<0 ) ) { FD_LOG_WARNING(( "open(%s) failed (%i-%s)", db_path, errno, fd_io_strerror( errno ) )); return NULL; }
    if( FD_UNLIKELY( ftruncate( fd, (off_t)payload_sz ) ) ) {
      FD_LOG_WARNING(( "ftruncate(%s,%lu) failed (%i-%s)", db_path, payload_sz, errno, fd_io_strerror( errno ) ));
      close( fd );
      return NULL;
    }

    if( shred_storage_gib ) {
      store->shred_map_gaddr  = fd_wksp_gaddr_fast( wksp, fd_shredb_shred_map_join( fd_shredb_shred_map_new( shred_map_mem, lg_shred_cnt, seed ) ) );
      store->slot_map_gaddr   = fd_wksp_gaddr_fast( wksp, fd_shredb_slot_map_join ( fd_shredb_slot_map_new ( slot_map_mem,  lg_slot_cnt,  seed ) ) );
      store->evict_keys_gaddr = fd_wksp_gaddr_fast( wksp, evict_k_mem );
      store->evict_occ_gaddr  = fd_wksp_gaddr_fast( wksp, evict_o_mem );
      fd_memset( evict_o_mem, 0, bitset_words * sizeof(ulong) );

      store->disk_max_shreds  = max_shreds;
      store->disk_write_head  = 0UL;
      store->disk_cnt         = 0UL;
      store->disk_file_shreds = 0UL;
      store->cache_shreds     = shred_cache_bytes ? shred_cache_bytes / sizeof(fd_shredb_entry_t) : 0UL;

      fd_rwlock_new( &store->disk_lock );

      ulong initial_shreds = 128UL;
      ulong initial_sz     = initial_shreds * sizeof(fd_shredb_entry_t);
      if( FD_UNLIKELY( fallocate( fd, 0, (off_t)store->wire_off, (off_t)initial_sz ) ) ) {
        FD_LOG_WARNING(( "fallocate(%s,off=%lu,%lu) failed (%i-%s)", db_path, store->wire_off, initial_sz, errno, fd_io_strerror( errno ) ));
        close( fd );
        return NULL;
      }
      store->disk_file_shreds = initial_shreds;
    }

    close( fd );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( store->magic ) = FD_STORE_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_store_t *
fd_store_join( void * shstore ) {
  if( FD_UNLIKELY( !shstore ) ) { FD_LOG_WARNING(( "NULL store" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shstore, fd_store_align() ) ) ) { FD_LOG_WARNING(( "misaligned store" )); return NULL; }

  fd_wksp_t * wksp = fd_wksp_containing( shstore );
  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "store must be part of a workspace" )); return NULL; }

  fd_store_t * store = (fd_store_t *)shstore;
  if( FD_UNLIKELY( store->magic!=FD_STORE_MAGIC ) ) { FD_LOG_WARNING(( "bad magic" )); return NULL; }

  return store;
}

void *
fd_store_leave( fd_store_t const * store ) {
  if( FD_UNLIKELY( !store ) ) { FD_LOG_WARNING(( "NULL store" )); return NULL; }
  return (void *)store;
}

void *
fd_store_delete( void * shstore ) {
  if( FD_UNLIKELY( !shstore ) ) { FD_LOG_WARNING(( "NULL store" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shstore, fd_store_align() ) ) ) { FD_LOG_WARNING(( "misaligned store" )); return NULL; }

  fd_store_t * store = (fd_store_t *)shstore;
  if( FD_UNLIKELY( store->magic!=FD_STORE_MAGIC ) ) { FD_LOG_WARNING(( "bad magic" )); return NULL; }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( store->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shstore;
}


uchar *
fd_store_fec_data_acquire( fd_store_t     * store,
                           int              disk_fd,
                           fd_store_fec_t * fec ) {
  if( FD_UNLIKELY( !store || !fec ) ) return NULL;

  fd_store_fec_t * fec0 = pool_ele_laddr( store );
  if( FD_UNLIKELY( fec<fec0 || fec>=fec0+store->fec_max ) ) return NULL;

  fd_rwlock_write( &store->cache_lock );

  if( FD_UNLIKELY( fec->data_state==FD_STORE_FEC_DATA_RAM_WRITING ||
                   fec->data_state==FD_STORE_FEC_DATA_RAM_READY ) ) {
    uchar * data = cache_data_laddr( store ) + fec->data_off;
    fd_rwlock_unwrite( &store->cache_lock );
    return data;
  }

  if( FD_UNLIKELY( fec->data_state!=FD_STORE_FEC_DATA_EMPTY &&
                   fec->data_state!=FD_STORE_FEC_DATA_CONSUMED ) ) {
    fd_rwlock_unwrite( &store->cache_lock );
    return NULL;
  }

  while( FD_UNLIKELY( !store->cache_free_cnt ) ) {
    if( FD_UNLIKELY( !spill_one_locked( store, disk_fd ) ) ) {
      fd_rwlock_unwrite( &store->cache_lock );
      return NULL;
    }
  }

  ulong * free = cache_free_laddr( store );
  ulong slot = free[ --store->cache_free_cnt ];
  fec->data_off   = slot * store->payload_slot_sz;
  fec->cache_seq  = 0UL;
  fec->data_state = FD_STORE_FEC_DATA_RAM_WRITING;

  uchar * data = cache_data_laddr( store ) + fec->data_off;
  fd_rwlock_unwrite( &store->cache_lock );
  return data;
}

void
fd_store_fec_data_publish( fd_store_t     * store,
                           fd_store_fec_t * fec ) {
  fd_rwlock_write( &store->cache_lock );
  FD_TEST( fec->data_state==FD_STORE_FEC_DATA_RAM_WRITING );
  fec->cache_seq  = ++store->cache_seq;
  fec->data_state = FD_STORE_FEC_DATA_RAM_READY;
  fd_rwlock_unwrite( &store->cache_lock );
}

int
fd_store_fec_data_view( fd_store_t *               store,
                        int                        disk_fd,
                        fd_store_fec_t *           fec,
                        uchar                      scratch[ static FD_STORE_FEC_DATA_SCRATCH_SZ ],
                        fd_store_fec_data_view_t * view ) {
  view->data = NULL;
  view->ram_lock_held = 0;

  fd_rwlock_read( &store->cache_lock );

  if( FD_LIKELY( fec->data_state==FD_STORE_FEC_DATA_RAM_READY ) ) {
    view->data = cache_data_laddr( store ) + fec->data_off;
    view->ram_lock_held = 1;
    return 0;
  }

  if( FD_LIKELY( fec->data_state==FD_STORE_FEC_DATA_DISK ) ) {
    if( FD_UNLIKELY( disk_fd<0 ) ) {
      fd_rwlock_unread( &store->cache_lock );
      return -1;
    }

    fd_store_disk_slock_acquire( store );
    long res = pread( disk_fd, scratch, fec->data_sz, (off_t)fec->data_off );
    fd_store_disk_slock_release( store );
    fd_rwlock_unread( &store->cache_lock );

    if( FD_UNLIKELY( res!=(long)fec->data_sz ) ) {
      FD_LOG_WARNING(( "error reading spilled FEC payload: (%d-%s)", errno, fd_io_strerror( errno ) ));
      return -1;
    }

    view->data = scratch;
    return 0;
  }

  fd_rwlock_unread( &store->cache_lock );
  return -1;
}

void
fd_store_fec_data_view_release( fd_store_t *                     store,
                                fd_store_fec_data_view_t const * view ) {
  if( FD_LIKELY( view->ram_lock_held ) ) fd_rwlock_unread( &store->cache_lock );
}

void
fd_store_fec_data_consumed( fd_store_t     * store,
                            fd_store_fec_t * fec ) {
  if( FD_UNLIKELY( !store || !fec ) ) return;

  fd_rwlock_write( &store->cache_lock );
  if( FD_LIKELY( fec->data_state==FD_STORE_FEC_DATA_RAM_WRITING ||
                 fec->data_state==FD_STORE_FEC_DATA_RAM_READY ) ) {
    FD_TEST( !cache_slot_release_locked( store, fec->data_off ) );
  }
  fec->data_off   = 0UL;
  fec->cache_seq  = 0UL;
  fec->data_state = FD_STORE_FEC_DATA_CONSUMED;
  fd_rwlock_unwrite( &store->cache_lock );
}


fd_store_fec_t *
fd_store_query( fd_store_map_t *  join,
                fd_hash_t const * merkle_root ) {
  fd_store_map_query_t query[1];
  int err = fd_store_map_query_try( join, merkle_root, NULL, query, 0 );
  if( FD_UNLIKELY( err ) ) return NULL;
  fd_store_fec_t * fec = fd_store_map_query_ele( query );
  if( FD_UNLIKELY( fd_store_map_query_test( query ) ) ) return NULL;
  return fec;
}

fd_store_fec_t *
fd_store_remove( fd_store_map_t *  join,
                 fd_hash_t const * merkle_root ) {
  fd_store_map_query_t query[1];
  int err = fd_store_map_remove( join, merkle_root, NULL, &query[0], FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( err ) ) return NULL;
  return fd_store_map_query_ele( &query[0] );
}


void
fd_store_disk_insert( fd_store_t       * store,
                      int                disk_fd,
                      fd_shred_t const * shred ) {
  ulong shred_sz  = fd_shred_sz( shred );
  ulong slot      = shred->slot;
  uint  shred_idx = shred->idx;

  fd_shredb_shred_entry_t * shred_map  = disk_shred_map_laddr( store );
  fd_shredb_slot_entry_t  * slot_map   = disk_slot_map_laddr( store );
  ulong                   * evict_keys = disk_evict_keys_laddr( store );
  ulong                   * evict_occ  = disk_evict_occ_laddr( store );

  ulong key = fd_shredb_key_pack( slot, shred_idx );
  if( fd_shredb_shred_map_query( shred_map, key, NULL ) ) return; /* duplicate */

  if( FD_UNLIKELY( store->disk_write_head>=store->disk_file_shreds ) ) {
    ulong old_file_sz     = store->disk_file_shreds * sizeof(fd_shredb_entry_t);
    ulong new_file_shreds = fd_ulong_min( store->disk_file_shreds * 2UL, store->disk_max_shreds );
    ulong new_file_sz     = new_file_shreds * sizeof(fd_shredb_entry_t);
    if( FD_UNLIKELY( fallocate( disk_fd, 0, (off_t)(store->wire_off + old_file_sz), (off_t)(new_file_sz - old_file_sz) ) ) ) {
      FD_LOG_ERR(( "fallocate failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    store->disk_file_shreds = new_file_shreds;
  }

  ulong wh_word = store->disk_write_head / 64UL;
  ulong wh_bit  = store->disk_write_head % 64UL;
  if( FD_LIKELY( evict_occ[ wh_word ] & (1UL << wh_bit) ) ) {
    ulong old_key  = evict_keys[ store->disk_write_head ];
    ulong old_slot = fd_shredb_key_slot( old_key );
    uint  old_idx  = fd_shredb_key_shred_idx( old_key );

    fd_shredb_shred_entry_t * old = fd_shredb_shred_map_query( shred_map, old_key, NULL );
    if( FD_LIKELY( old ) ) fd_shredb_shred_map_remove( shred_map, old );

    disk_slot_evict( store, old_slot, old_idx );
    store->disk_cnt--;
  }

  fd_shredb_entry_t wr_entry[1];
  wr_entry->shred_sz = (ushort)shred_sz;
  fd_memcpy( wr_entry->shred, shred, shred_sz );

  off_t off = (off_t)(store->wire_off + store->disk_write_head * sizeof(fd_shredb_entry_t));
  long  res = pwrite( disk_fd, wr_entry, sizeof(fd_shredb_entry_t), off );
  if( FD_UNLIKELY( res!=(long)sizeof(fd_shredb_entry_t) ) ) FD_LOG_ERR(( "error writing to disk store: (%d-%s)", errno, fd_io_strerror( errno ) ));

  /* Residency window: keep at most cache_shreds most-recently-written
     wire entries resident by releasing the page-cache for the entry
     that falls just behind the rolling window.  cache_shreds==0 leaves
     residency to the OS. */
  if( FD_LIKELY( store->cache_shreds && store->disk_cnt>=store->cache_shreds ) ) {
    ulong cold = (store->disk_write_head + store->disk_max_shreds - store->cache_shreds) % store->disk_max_shreds;
    off_t coff = (off_t)(store->wire_off + cold * sizeof(fd_shredb_entry_t));
    (void)posix_fadvise( disk_fd, coff, (off_t)sizeof(fd_shredb_entry_t), POSIX_FADV_DONTNEED );
  }

  evict_keys[ store->disk_write_head ] = key;
  evict_occ [ wh_word ] |= (1UL << wh_bit);

  fd_shredb_shred_entry_t * map_entry = fd_shredb_shred_map_insert( shred_map, key );
  FD_TEST( map_entry );
  map_entry->ring_idx = store->disk_write_head;

  fd_shredb_slot_entry_t * se = fd_shredb_slot_map_query( slot_map, slot, NULL );
  if( FD_LIKELY( se ) ) {
    se->cnt++;
    se->highest_shred_idx = fd_uint_max( se->highest_shred_idx, shred_idx );
  } else {
    se = fd_shredb_slot_map_insert( slot_map, slot );
    FD_TEST( se );
    se->highest_shred_idx = shred_idx;
    se->cnt               = 1UL;
  }

  store->disk_cnt++;
  store->disk_write_head = (store->disk_write_head + 1UL) % store->disk_max_shreds;
}

int
fd_store_disk_query( fd_store_t * store,
                     int          disk_fd,
                     ulong        slot,
                     uint         shred_idx,
                     uchar        out[ FD_SHRED_MAX_SZ ] ) {
  fd_shredb_slot_entry_t * slot_map = disk_slot_map_laddr( store );
  if( !fd_shredb_slot_map_query( slot_map, slot, NULL ) ) return -1;

  fd_shredb_shred_entry_t * shred_map = disk_shred_map_laddr( store );
  ulong key = fd_shredb_key_pack( slot, shred_idx );
  fd_shredb_shred_entry_t const * map_entry = fd_shredb_shred_map_query( shred_map, key, NULL );
  if( FD_UNLIKELY( !map_entry ) ) return -1;

  fd_shredb_entry_t rd_entry[1];
  off_t off = (off_t)(store->wire_off + map_entry->ring_idx * sizeof(fd_shredb_entry_t));
  long  res = pread( disk_fd, rd_entry, sizeof(fd_shredb_entry_t), off );
  if( FD_UNLIKELY( res!=(long)sizeof(fd_shredb_entry_t) ) ) FD_LOG_ERR(( "error reading from disk store: (%d-%s)", errno, fd_io_strerror( errno ) ));

  fd_memcpy( out, rd_entry->shred, rd_entry->shred_sz );
  return rd_entry->shred_sz;
}

int
fd_store_disk_query_highest( fd_store_t * store,
                             int          disk_fd,
                             ulong        slot,
                             uint         min_shred_idx,
                             uchar        out[ FD_SHRED_MAX_SZ ] ) {
  fd_shredb_slot_entry_t * se = fd_shredb_slot_map_query( disk_slot_map_laddr( store ), slot, NULL );
  if( FD_UNLIKELY( !se ) ) return -1;
  if( se->highest_shred_idx < min_shred_idx ) return -1;

  ulong key = fd_shredb_key_pack( slot, se->highest_shred_idx );
  fd_shredb_shred_entry_t const * map_entry = fd_shredb_shred_map_query( disk_shred_map_laddr( store ), key, NULL );
  FD_TEST( map_entry );

  fd_shredb_entry_t rd_entry[1];
  off_t off = (off_t)(store->wire_off + map_entry->ring_idx * sizeof(fd_shredb_entry_t));
  long  res = pread( disk_fd, rd_entry, sizeof(fd_shredb_entry_t), off );
  if( FD_UNLIKELY( res!=(long)sizeof(fd_shredb_entry_t) ) ) FD_LOG_ERR(( "error reading from disk store: (%d-%s)", errno, fd_io_strerror( errno ) ));

  fd_memcpy( out, rd_entry->shred, rd_entry->shred_sz );
  return rd_entry->shred_sz;
}
