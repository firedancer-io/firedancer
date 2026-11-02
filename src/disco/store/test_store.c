#define _GNU_SOURCE
#include "fd_store.h"
#include <errno.h>
#include <fcntl.h>

/* Tests interleave store operations with an in-flight spill through
   spill_hook, which runs with the store lock dropped, before the spill
   writes. */

static void (* spill_hook_fn)( fd_store_t * store );

#define FD_STORE_SPILL_TEST_HOOK( store ) do { if( spill_hook_fn ) spill_hook_fn( (store) ); } while(0)

#include "fd_store.c"

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define TEST_PAYLOAD_PATH "/tmp/test_store_fec_payload.db"


static fd_hash_t
mr_make( ulong a,
         ulong b ) {
  return (fd_hash_t){ .ul = { a, b, 0UL, 0UL } };
}

/* test_store_new creates a store with no shred ring.  cache_cnt is the
   number of RAM cache slots (0 sizes the cache for fec_max). */

static fd_store_t *
test_store_new( fd_wksp_t * wksp,
                ulong       fec_max,
                ulong       fec_data_max,
                ulong       cache_cnt,
                ulong       tile_cnt,
                ulong       max_live_slots ) {
  ulong cache_bytes = cache_cnt*fd_store_fec_slot_sz( fec_data_max );
  ulong footprint   = fd_store_footprint( fec_max, fec_data_max, 0UL, cache_bytes, 0UL, tile_cnt, max_live_slots );
  FD_TEST( footprint );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  FD_TEST( mem );
  fd_store_t * store = fd_store_join( fd_store_new( mem, fec_max, fec_data_max, 0UL, cache_bytes, 0UL,
                                                    FD_SHRED_BLK_MAX, 42UL, tile_cnt, max_live_slots ) );
  FD_TEST( store );
  FD_TEST( !cache_cnt || store->cache_max==cache_cnt );
  return store;
}

static void
test_store_delete( fd_store_t * store ) {
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

static int
test_file_open( fd_store_t * store ) {
  FD_TEST( !unlink( TEST_PAYLOAD_PATH ) || errno==ENOENT );
  int fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( fd>=0 );
  return fd;
}

/* fill_byte is the payload byte at off of a FEC filled with seed. */

static inline uchar
fill_byte( ulong seed,
           ulong off ) {
  return (uchar)( fd_ulong_hash( seed ) + off*31UL );
}

/* insert inserts the FEC mr of slot with sz payload bytes generated
   from seed.  The first tracked_cnt shreds split tracked_sz bytes
   evenly (the rest of sz is untracked overflow, as in legacy FECs).
   Returns the error of begin or commit. */

static int
insert_ex( fd_store_t *              store,
           int                       disk_fd,
           fd_hash_t const *         mr,
           ulong                     slot,
           ulong                     part,
           ulong                     sz,
           ulong                     tracked_sz,
           ulong                     tracked_cnt,
           ulong                     seed,
           fd_store_insert_stats_t * insert_stats ) {
  fd_store_insert_t ins;
  int err = fd_store_insert_begin( store, disk_fd, mr, slot, part, insert_stats, &ins );
  if( FD_UNLIKELY( err ) ) {
    FD_TEST( ins==FD_STORE_INSERT_NULL );
    return err;
  }
  FD_TEST( ins!=FD_STORE_INSERT_NULL );
  fd_store_fec_t * rec = fd_store_insert_data( store, ins );
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) FD_TEST( !rec->shred_sz[ i ] ); /* header zeroed */
  ulong off = 0UL;
  for( ulong i=0UL; i<tracked_cnt; i++ ) {
    ulong shred_sz = i+1UL<tracked_cnt ? tracked_sz/tracked_cnt : tracked_sz-off;
    rec->shred_sz[ i ] = (ushort)shred_sz;
    off += shred_sz;
  }
  for( ulong i=0UL; i<sz; i++ ) rec->payload[ i ] = fill_byte( seed, i );
  return fd_store_insert_commit( store, ins, sz );
}

static int
insert( fd_store_t *      store,
        int               disk_fd,
        fd_hash_t const * mr,
        ulong             slot,
        ulong             sz,
        ulong             seed ) {
  return insert_ex( store, disk_fd, mr, slot, 0UL, sz, sz, sz ? 1UL : 0UL, seed, NULL );
}

/* check pins mr, reads it and verifies sz bytes generated from seed
   with tracked_sz bytes in tracked_cnt shreds.  Returns whether the
   read came from disk. */

static uchar  check_buf[ FD_STORE_MAX_FEC_DATA_SZ ];
static ushort check_shred_sz[ FD_FEC_SHRED_CNT ];

static int
check_ex( fd_store_t *      store,
          int               disk_fd,
          fd_hash_t const * mr,
          ulong             sz,
          ulong             tracked_sz,
          ulong             tracked_cnt,
          ulong             seed ) {
  fd_store_view_t view = fd_store_query_acquire( store, mr, NULL );
  FD_TEST( view!=FD_STORE_VIEW_NULL );
  FD_TEST( fd_store_query_data_sz( store, view )==sz );
  int spilled = -1;
  FD_TEST( fd_store_query_read( store, disk_fd, view, check_buf, sizeof(check_buf), check_shred_sz, &spilled )==(long)sz );
  FD_TEST( spilled==fd_store_view_spilled( view ) );
  for( ulong i=0UL; i<sz; i++ ) FD_TEST( check_buf[ i ]==fill_byte( seed, i ) );
  ulong off = 0UL;
  for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) {
    ulong expect = i<tracked_cnt ? ( i+1UL<tracked_cnt ? tracked_sz/tracked_cnt : tracked_sz-off ) : 0UL;
    FD_TEST( check_shred_sz[ i ]==expect );
    off += expect;
  }
  fd_store_query_release( store, view );
  return spilled;
}

static int
check( fd_store_t *      store,
       int               disk_fd,
       fd_hash_t const * mr,
       ulong             sz,
       ulong             seed ) {
  return check_ex( store, disk_fd, mr, sz, sz, sz ? 1UL : 0UL, seed );
}

static int
is_miss( fd_store_t *      store,
         fd_hash_t const * mr ) {
  fd_store_view_t view = fd_store_query_acquire( store, mr, NULL );
  if( view==FD_STORE_VIEW_NULL ) return 1;
  fd_store_query_release( store, view );
  return 0;
}

static ulong
live_cnt( fd_store_t const * store ) {
  return atomic_load_explicit( &store->fec_live_cnt, memory_order_relaxed );
}

static ulong
cache_free( fd_store_t const * store ) {
  return atomic_load_explicit( &store->cache_free_cnt, memory_order_relaxed );
}

/* check_invariants verifies the containers agree with the counters.
   Store must be quiescent (no insert in progress, no pin). */

static void
check_invariants( fd_store_t * store ) {
  store_ljoin_t ljoin = store_ljoin( store );
  FD_TEST( store->pin_view==FD_STORE_VIEW_NULL );
  FD_TEST( !atomic_load_explicit( &store->cache_parked, memory_order_relaxed ) );
  FD_TEST( fd_store_meta_pool_free( ljoin.meta )+live_cnt( store )==store->fec_max );
  FD_TEST( fd_store_cache_pool_free( ljoin.cache )==cache_free( store ) );

  ulong lru_cnt = 0UL;
  for( fd_store_cache_lru_iter_t it = fd_store_cache_lru_iter_fwd_init( ljoin.lru, ljoin.cache );
       !fd_store_cache_lru_iter_done( it, ljoin.lru, ljoin.cache );
       it = fd_store_cache_lru_iter_fwd_next( it, ljoin.lru, ljoin.cache ) ) {
    uint cache_idx = (uint)fd_store_cache_lru_iter_idx( it, ljoin.lru, ljoin.cache );
    uint f         = ljoin.cache[ cache_idx ].meta_idx;
    FD_TEST( ljoin.meta[ f ].data==data_pack( cache_idx, FD_STORE_STATE_CACHED ) );
    lru_cnt++;
  }
  FD_TEST( lru_cnt+cache_free( store )==store->cache_max );

  ulong ring_cnt = 0UL;
  ulong disk_cnt = 0UL;
  for( ulong b=0UL; b<store->slot_ring_len; b++ ) {
    for( uint f=ljoin.slot_ring[ b ]; f!=FD_STORE_NULL; f=ljoin.meta[ f ].slot_next ) {
      FD_TEST( (ljoin.meta[ f ].slot & (store->slot_ring_len-1UL))==b );
      FD_TEST( ljoin.meta[ f ].slot>=store->min_root );
      fd_store_key_t key = ljoin.meta[ f ].key;
      FD_TEST( map_find( &ljoin, &key, NULL )==f );
      uint state = data_state( ljoin.meta[ f ].data );
      FD_TEST( state==FD_STORE_STATE_CACHED || state==FD_STORE_STATE_SPILLED );
      disk_cnt += state==FD_STORE_STATE_SPILLED;
      ring_cnt++;
    }
  }
  FD_TEST( ring_cnt==live_cnt( store ) );
  FD_TEST( disk_cnt==atomic_load_explicit( &store->disk_live_cnt, memory_order_relaxed ) );
  FD_TEST( disk_cnt+store->disk_free_cnt==atomic_load_explicit( &store->disk_bump, memory_order_relaxed ) );
}

/* expect_crash runs fn( store ) in a child process and checks that it
   fails an FD_TEST (FD_LOG_ERR exits with status 1).  glibc's fork
   walks the thread descriptors of every tile, whose stacks are not
   mapped in the child (MADV_DONTFORK), so fork with the raw syscall.
   The child must then exit without running atexit handlers. */

static void
expect_crash( fd_store_t * store,
              void      (* fn)( fd_store_t * ) ) {
  long pid = syscall( SYS_fork );
  FD_TEST( pid>=0L );
  if( !pid ) {
    fd_log_level_stderr_set( 5 ); /* the expected failure is noise */
    fd_log_enable_unclean_exit();
    fn( store );
    syscall( SYS_exit_group, 0 );
  }
  int status;
  FD_TEST( waitpid( (pid_t)pid, &status, 0 )==(pid_t)pid );
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );
}


void
test_footprint( void ) {
  FD_TEST( fd_store_fec_slot_sz( 31840UL )==32768UL );
  FD_TEST( fd_store_fec_slot_sz( 63985UL )==65536UL );
  FD_TEST( fd_store_fec_slot_sz( 4096UL-FD_STORE_FEC_HDR_SZ )==4096UL );
  FD_TEST( fd_store_fec_slot_sz( 4096UL-FD_STORE_FEC_HDR_SZ+1UL )==8192UL );
  FD_TEST( !fd_store_fec_slot_sz( ULONG_MAX ) );

  FD_TEST(  fd_store_footprint( 8UL, 31840UL,                      0UL, 0UL, 0UL,  1UL, 1UL ) );
  FD_TEST( !fd_store_footprint( 0UL, 31840UL,                      0UL, 0UL, 0UL,  1UL, 1UL ) );
  FD_TEST( !fd_store_footprint( FD_STORE_IDX_MAX+1UL, 31840UL,     0UL, 0UL, 0UL,  1UL, 1UL ) );
  FD_TEST( !fd_store_footprint( 8UL, 0UL,                          0UL, 0UL, 0UL,  1UL, 1UL ) );
  FD_TEST( !fd_store_footprint( 8UL, FD_STORE_MAX_FEC_DATA_SZ+1UL, 0UL, 0UL, 0UL,  1UL, 1UL ) );
  FD_TEST( !fd_store_footprint( 8UL, ULONG_MAX,                    0UL, 0UL, 0UL,  1UL, 1UL ) );
  FD_TEST( !fd_store_footprint( 8UL, 31840UL,                      0UL, 0UL, 0UL,  0UL, 1UL ) );
  FD_TEST( !fd_store_footprint( 8UL, 31840UL,                      0UL, 0UL, 0UL, 65UL, 1UL ) );
  FD_TEST( !fd_store_footprint( 8UL, 31840UL,                      0UL, 0UL, 0UL,  1UL, 0UL ) );
  FD_TEST( !fd_store_footprint( 8UL, 31840UL,                      0UL, 0UL, ULONG_MAX, 1UL, 1UL ) );
  FD_TEST(  fd_store_footprint( 8UL, 31840UL,                      0UL, 0UL, 0UL, 64UL, 1UL ) );

  /* The cache is sized in whole slots, at least one, at most fec_max. */
  ulong fec_slot_sz = fd_store_fec_slot_sz( 31840UL );
  FD_TEST( fd_store_footprint( 8UL, 31840UL, 0UL, 0UL,               0UL, 1UL, 1UL )==
           fd_store_footprint( 8UL, 31840UL, 0UL, 8UL*fec_slot_sz,   0UL, 1UL, 1UL ) );
  FD_TEST( fd_store_footprint( 8UL, 31840UL, 0UL, 100UL*fec_slot_sz, 0UL, 1UL, 1UL )==
           fd_store_footprint( 8UL, 31840UL, 0UL, 8UL*fec_slot_sz,   0UL, 1UL, 1UL ) );
  FD_TEST( fd_store_footprint( 8UL, 31840UL, 0UL, 1UL,               0UL, 1UL, 1UL )==
           fd_store_footprint( 8UL, 31840UL, 0UL, fec_slot_sz,       0UL, 1UL, 1UL ) );
  FD_TEST( fd_store_footprint( 8UL, 31840UL, 0UL, 2UL*fec_slot_sz,   0UL, 1UL, 1UL )<
           fd_store_footprint( 8UL, 31840UL, 0UL, 3UL*fec_slot_sz,   0UL, 1UL, 1UL ) );

  /* max_live_slots sizes the slot ring, rounded up to a power of 2. */
  FD_TEST( fd_store_footprint( 8UL, 31840UL, 0UL, 0UL, 0UL, 1UL, 5UL )==
           fd_store_footprint( 8UL, 31840UL, 0UL, 0UL, 0UL, 1UL, 8UL ) );
}

void
test_new( fd_wksp_t * wksp ) {
  ulong  footprint = fd_store_footprint( 8UL, 63985UL, 0UL, 0UL, 0UL, 1UL, 5UL );
  void * mem       = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  FD_TEST( mem );
  FD_TEST( !fd_store_new( mem, 8UL, FD_STORE_MAX_FEC_DATA_SZ+1UL, 0UL, 0UL, 0UL, FD_SHRED_BLK_MAX, 42UL, 1UL, 5UL ) );
  FD_TEST( !fd_store_new( mem, 8UL, 63985UL, 0UL, 0UL, 0UL, FD_SHRED_BLK_MAX, 42UL, 0UL, 5UL ) );
  FD_TEST( !fd_store_new( mem, 8UL, 63985UL, 0UL, 0UL, 0UL, FD_SHRED_BLK_MAX, 42UL, 1UL, 0UL ) );
  FD_TEST( !fd_store_join( mem ) );

  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 63985UL, 0UL, 0UL, 0UL, FD_SHRED_BLK_MAX, 42UL, 1UL, 5UL ) );
  FD_TEST( store );
  FD_TEST( store->magic==FD_STORE_MAGIC );
  FD_TEST( store->fec_slot_sz==65536UL );
  FD_TEST( store->cache_max==8UL && store->disk_max==8UL );
  FD_TEST( store->slot_ring_len==8UL );
  FD_TEST( store->wire_off==8UL*65536UL && store->payload_sz==store->wire_off );
  FD_TEST( store->min_root==0UL && store->pin_view==FD_STORE_VIEW_NULL );
  FD_TEST( cache_free( store )==8UL && !live_cnt( store ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)cache_data_laddr( store ), FD_STORE_PAYLOAD_PAGE_SZ ) );

  fd_store_fec_cache_stats_t stats[1];
  fd_store_fec_cache_stats_query( store, stats );
  FD_TEST( stats->free_cnt==8UL && stats->max==8UL );
  FD_TEST( stats->low_water>=1UL && stats->low_water<=stats->target && stats->target<=8UL );
  check_invariants( store );

  test_store_delete( store );
}

/* Basic insert, query, read, release and publish without a disk. */

void
test_basic( fd_wksp_t * wksp ) {
  fd_store_t * store = test_store_new( wksp, 8UL, 31840UL, 0UL, 1UL, 16UL );

  fd_hash_t mr0 = mr_make( 1UL, 0UL );
  fd_hash_t mr1 = mr_make( 1UL, 32UL );
  fd_hash_t mr2 = mr_make( 2UL, 0UL );
  FD_TEST( is_miss( store, &mr0 ) );

  fd_store_insert_stats_t stats[1];
  FD_TEST( !insert_ex( store, -1, &mr0, 1UL, 0UL, 31840UL, 31840UL, 32UL, 0UL, stats ) );
  FD_TEST( !stats->park_cnt && !stats->spill.write_ticks && !stats->spill.spilled_cnt );
  FD_TEST( !insert( store, -1, &mr1, 1UL, 1000UL, 1UL ) );
  FD_TEST( !insert( store, -1, &mr2, 2UL, 0UL,    2UL ) ); /* empty payload */
  FD_TEST( live_cnt( store )==3UL && cache_free( store )==5UL );
  FD_TEST( atomic_load_explicit( &store->fec_live_peak, memory_order_relaxed )==3UL );

  FD_TEST( !check_ex( store, -1, &mr0, 31840UL, 31840UL, 32UL, 0UL ) );
  FD_TEST( !check   ( store, -1, &mr1, 1000UL, 1UL ) );
  FD_TEST( !check   ( store, -1, &mr2, 0UL,    2UL ) );
  FD_TEST( !check_ex( store, -1, &mr0, 31840UL, 31840UL, 32UL, 0UL ) ); /* reads are repeatable across pins */
  check_invariants( store );

  /* The view packs meta idx, data idx and the spilled bit. */
  fd_store_view_t view = fd_store_query_acquire( store, &mr1, NULL );
  FD_TEST( view!=FD_STORE_VIEW_NULL && store->pin_view==view );
  FD_TEST( !fd_store_view_spilled( view ) && !(view>>61) );
  store_ljoin_t ljoin = store_ljoin( store );
  FD_TEST( ljoin.meta[ fd_store_view_meta_idx( view ) ].data==data_pack( fd_store_view_data_idx( view ), FD_STORE_STATE_PINNED ) );
  fd_store_query_release( store, view );
  FD_TEST( store->pin_view==FD_STORE_VIEW_NULL );

  /* Publishing slot 2 frees the slot 1 FECs only. */
  fd_store_publish_stats_t pub[1];
  fd_store_publish( store, 2UL, pub );
  FD_TEST( pub->removed_cnt==2UL );
  FD_TEST( is_miss( store, &mr0 ) && is_miss( store, &mr1 ) && !is_miss( store, &mr2 ) );
  FD_TEST( live_cnt( store )==1UL && cache_free( store )==7UL );
  check_invariants( store );

  /* Publishing the same or an older root is a no-op. */
  fd_store_publish( store, 2UL, pub ); FD_TEST( !pub->removed_cnt );
  fd_store_publish( store, 1UL, pub ); FD_TEST( !pub->removed_cnt );
  FD_TEST( store->min_root==2UL );

  /* A freed key can be inserted again at or above the root. */
  FD_TEST( !insert( store, -1, &mr0, 2UL, 10UL, 3UL ) );
  FD_TEST( !check( store, -1, &mr0, 10UL, 3UL ) );

  fd_store_publish( store, 3UL, NULL );
  FD_TEST( !live_cnt( store ) && cache_free( store )==8UL );
  check_invariants( store );
  test_store_delete( store );
}

/* Every insert_begin error leaves nothing held. */

void
test_insert_errors( fd_wksp_t * wksp ) {
  fd_store_t * store = test_store_new( wksp, 2UL, 31840UL, 1UL, 2UL, 16UL );
  store_ljoin_t ljoin = store_ljoin( store );

  fd_hash_t mr0 = mr_make( 10UL, 0UL );
  fd_hash_t mr1 = mr_make( 10UL, 32UL );
  fd_hash_t mr2 = mr_make( 10UL, 64UL );
  fd_store_insert_t ins = 0U;

  /* ERR_EXPIRED is checked before anything is taken. */
  fd_store_publish( store, 10UL, NULL );
  FD_TEST( fd_store_insert_begin( store, -1, &mr0, 9UL, 0UL, NULL, &ins )==FD_STORE_ERR_EXPIRED );
  FD_TEST( ins==FD_STORE_INSERT_NULL );
  FD_TEST( !live_cnt( store ) && cache_free( store )==1UL && fd_store_meta_pool_free( ljoin.meta )==2UL );

  /* ERR_CACHE_FULL: one cache slot, no disk. */
  FD_TEST( !insert( store, -1, &mr0, 10UL, 100UL, 0UL ) );
  FD_TEST( insert( store, -1, &mr1, 10UL, 100UL, 1UL )==FD_STORE_ERR_CACHE_FULL );
  FD_TEST( live_cnt( store )==1UL && !cache_free( store ) && fd_store_meta_pool_free( ljoin.meta )==1UL );
  FD_TEST( is_miss( store, &mr1 ) );
  { fd_store_key_t key = store_key( &mr1 ); FD_TEST( map_find( &ljoin, &key, NULL )==FD_STORE_NULL ); }

  /* ERR_DUP: committed FEC, from either partition. */
  FD_TEST( fd_store_insert_begin( store, -1, &mr0, 10UL, 1UL, NULL, &ins )==FD_STORE_ERR_DUP );
  FD_TEST( ins==FD_STORE_INSERT_NULL );
  FD_TEST( live_cnt( store )==1UL && !cache_free( store ) );
  FD_TEST( !check( store, -1, &mr0, 100UL, 0UL ) );

  /* ERR_PENDING_DUP: a FEC still being inserted is a query miss;
     another tile must not notify replay until the inserter commits. */
  fd_store_publish( store, 11UL, NULL );
  FD_TEST( fd_store_insert_begin( store, -1, &mr1, 11UL, 0UL, NULL, &ins )==FD_STORE_SUCCESS );
  fd_store_insert_t ins2;
  FD_TEST( fd_store_insert_begin( store, -1, &mr1, 11UL, 1UL, NULL, &ins2 )==FD_STORE_ERR_PENDING_DUP );
  FD_TEST( ins2==FD_STORE_INSERT_NULL );
  FD_TEST( is_miss( store, &mr1 ) );

  /* Once committed, the same key is queryable and a committed duplicate. */
  FD_TEST( !fd_store_insert_commit( store, ins, 0UL ) );
  FD_TEST( fd_store_insert_begin( store, -1, &mr1, 11UL, 1UL, NULL, &ins2 )==FD_STORE_ERR_DUP );
  FD_TEST( ins2==FD_STORE_INSERT_NULL );
  FD_TEST( !check( store, -1, &mr1, 0UL, 0UL ) );

  /* ERR_CACHE_FULL releases the meta it took. */
  FD_TEST( fd_store_insert_begin( store, -1, &mr2, 11UL, 0UL, NULL, &ins )==FD_STORE_ERR_CACHE_FULL );
  FD_TEST( ins==FD_STORE_INSERT_NULL );
  FD_TEST( live_cnt( store )==1UL && fd_store_meta_pool_free( ljoin.meta )==1UL );
  { fd_store_key_t key = store_key( &mr2 ); FD_TEST( map_find( &ljoin, &key, NULL )==FD_STORE_NULL ); }
  fd_store_publish( store, 12UL, NULL );
  FD_TEST( !insert( store, -1, &mr2, 12UL, 0UL, 0UL ) );
  FD_TEST( live_cnt( store )==1UL && !cache_free( store ) );
  check_invariants( store );
  test_store_delete( store );

  /* ERR_FEC_FULL is checked before the cache: fill the metas, one of
     them with an in-flight insert. */
  store = test_store_new( wksp, 2UL, 31840UL, 0UL, 2UL, 16UL );
  ljoin = store_ljoin( store );
  fd_store_insert_t a, b;
  FD_TEST( fd_store_insert_begin( store, -1, &mr0, 1UL, 0UL, NULL, &a )==FD_STORE_SUCCESS );
  FD_TEST( !fd_store_insert_commit( store, a, 0UL ) );
  FD_TEST( fd_store_insert_begin( store, -1, &mr1, 1UL, 1UL, NULL, &b )==FD_STORE_SUCCESS );
  FD_TEST( !cache_free( store ) && !fd_store_meta_pool_free( ljoin.meta ) );
  FD_TEST( fd_store_insert_begin( store, -1, &mr2, 1UL, 0UL, NULL, &ins )==FD_STORE_ERR_FEC_FULL );
  FD_TEST( ins==FD_STORE_INSERT_NULL && live_cnt( store )==2UL );
  FD_TEST( !fd_store_insert_commit( store, b, 0UL ) );
  fd_store_publish( store, 2UL, NULL );
  FD_TEST( fd_store_insert_begin( store, -1, &mr2, 2UL, 0UL, NULL, &ins )==FD_STORE_SUCCESS );
  FD_TEST( !fd_store_insert_commit( store, ins, 0UL ) );
  check_invariants( store );
  test_store_delete( store );
}

/* A publish between begin and commit expires the FEC at commit. */

void
test_commit_expired( fd_wksp_t * wksp ) {
  fd_store_t * store = test_store_new( wksp, 4UL, 31840UL, 0UL, 1UL, 16UL );

  fd_hash_t mr = mr_make( 5UL, 0UL );
  fd_store_insert_t ins;
  FD_TEST( fd_store_insert_begin( store, -1, &mr, 5UL, 0UL, NULL, &ins )==FD_STORE_SUCCESS );
  fd_store_fec_t * rec = fd_store_insert_data( store, ins );
  rec->shred_sz[ 0 ] = 10; fd_memset( rec->payload, 0x5a, 10UL );

  fd_store_publish_stats_t pub[1];
  fd_store_publish( store, 6UL, pub );
  FD_TEST( !pub->removed_cnt );                     /* not in slot_ring yet */
  FD_TEST( live_cnt( store )==1UL );
  fd_store_insert_t dup;
  FD_TEST( fd_store_insert_begin( store, -1, &mr, 6UL, 0UL, NULL, &dup )==FD_STORE_ERR_PENDING_DUP );
  FD_TEST( dup==FD_STORE_INSERT_NULL );
  FD_TEST( fd_store_insert_commit( store, ins, 10UL )==FD_STORE_ERR_EXPIRED );
  FD_TEST( !live_cnt( store ) && cache_free( store )==4UL );
  FD_TEST( is_miss( store, &mr ) );
  FD_TEST( insert( store, -1, &mr, 5UL, 0UL, 0UL )==FD_STORE_ERR_EXPIRED );
  FD_TEST( !insert( store, -1, &mr, 6UL, 10UL, 0UL ) );   /* the key is free again */
  check_invariants( store );
  test_store_delete( store );
}

/* The key is the first 20 bytes of the merkle root. */

void
test_key_20( fd_wksp_t * wksp ) {
  fd_store_t * store = test_store_new( wksp, 4UL, 31840UL, 0UL, 1UL, 16UL );

  fd_hash_t mr = mr_make( 0x1111111111111111UL, 0x2222222222222222UL );
  mr.ul[ 2 ] = 0x3333333333333333UL;
  mr.ul[ 3 ] = 0x4444444444444444UL;
  FD_TEST( !insert( store, -1, &mr, 1UL, 64UL, 7UL ) );

  /* Bytes 20-31 are not part of the key. */
  fd_hash_t same = mr;
  for( ulong i=20UL; i<32UL; i++ ) same.uc[ i ] ^= 0xffU;
  FD_TEST( insert( store, -1, &same, 1UL, 64UL, 8UL )==FD_STORE_ERR_DUP );
  FD_TEST( !check( store, -1, &same, 64UL, 7UL ) );

  /* Bytes 16-19 are. */
  for( ulong i=16UL; i<20UL; i++ ) {
    fd_hash_t other = mr;
    other.uc[ i ] ^= 0x01U;
    FD_TEST( is_miss( store, &other ) );
    if( i==19UL ) {
      FD_TEST( !insert( store, -1, &other, 1UL, 32UL, 9UL ) );
      FD_TEST( !check( store, -1, &other, 32UL, 9UL ) );
      FD_TEST( !check( store, -1, &mr,    64UL, 7UL ) );
    }
  }

  /* Hashing and comparing reads no byte past the key: put a root's
     20 key bytes at the very end of a page followed by an unmapped
     page. */
  long   page_sz = sysconf( _SC_PAGESIZE );
  uchar * pages  = mmap( NULL, 2UL*(ulong)page_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( pages!=MAP_FAILED );
  FD_TEST( !mprotect( pages+page_sz, (ulong)page_sz, PROT_NONE ) );
  fd_hash_t const * edge = (fd_hash_t const *)( pages + page_sz - FD_SHRED_MERKLE_NODE_SZ );
  memcpy( (uchar *)edge, mr.uc, FD_SHRED_MERKLE_NODE_SZ );
  FD_TEST( !check( store, -1, edge, 64UL, 7UL ) );
  FD_TEST( insert( store, -1, edge, 1UL, 1UL, 0UL )==FD_STORE_ERR_DUP );
  FD_TEST( !munmap( pages, 2UL*(ulong)page_sz ) );

  check_invariants( store );
  test_store_delete( store );
}

/* Lookups report fec_map chain hops. */

void
test_probe_cnt( fd_wksp_t * wksp ) {
  fd_store_t * store = test_store_new( wksp, 8UL, 31840UL, 0UL, 1UL, 16UL );

  /* Reformat the empty map with one chain so every key collides. */
  fd_store_fec_map_t * map = fd_wksp_laddr_fast( wksp, store->fec_map_gaddr );
  FD_TEST( fd_store_fec_map_join( fd_store_fec_map_new( fd_store_fec_map_leave( map ), 1UL, 42UL ) )==map );

  ulong const k = 5UL;
  fd_store_insert_stats_t stats[1];
  for( ulong i=0UL; i<k; i++ ) {
    fd_hash_t mr = mr_make( 1UL, i );
    FD_TEST( !insert_ex( store, -1, &mr, 1UL, 0UL, 0UL, 0UL, 0UL, 0UL, stats ) );
    FD_TEST( stats->lookup.probe_cnt==i ); /* a miss walks the whole chain */
  }

  /* Insert pushes at the chain head, so key i is at position k-i. */
  for( ulong i=0UL; i<k; i++ ) {
    fd_hash_t mr = mr_make( 1UL, i );
    fd_store_lookup_stats_t lookup[1];
    fd_store_view_t view = fd_store_query_acquire( store, &mr, lookup );
    FD_TEST( view!=FD_STORE_VIEW_NULL );
    FD_TEST( lookup->probe_cnt==k-i );
    fd_store_query_release( store, view );
  }
  fd_hash_t missing = mr_make( 1UL, k );
  fd_store_lookup_stats_t lookup[1];
  FD_TEST( fd_store_query_acquire( store, &missing, lookup )==FD_STORE_VIEW_NULL );
  FD_TEST( lookup->probe_cnt==k );

  fd_hash_t dup = mr_make( 1UL, 0UL );
  FD_TEST( insert_ex( store, -1, &dup, 1UL, 0UL, 0UL, 0UL, 0UL, 0UL, stats )==FD_STORE_ERR_DUP );
  FD_TEST( stats->lookup.probe_cnt==k );

  check_invariants( store );
  test_store_delete( store );
}

/* Publish walks min(root-old,len) slot ring buckets and keeps aliased
   later slots. */

void
test_publish_ring( fd_wksp_t * wksp ) {
  fd_store_t * store = test_store_new( wksp, 16UL, 31840UL, 0UL, 1UL, 4UL );
  FD_TEST( store->slot_ring_len==4UL );

  ulong slots[] = { 1UL, 5UL, 9UL, 2UL, 6UL, 3UL, 7UL, 4UL };
  ulong slot_cnt = sizeof(slots)/sizeof(slots[0]);
  for( ulong i=0UL; i<slot_cnt; i++ ) {
    fd_hash_t mr = mr_make( slots[ i ], 0UL );
    FD_TEST( !insert( store, -1, &mr, slots[ i ], 8UL, slots[ i ] ) );
  }
  check_invariants( store );

  /* Root 3 frees slots 1 and 2; 5, 9 and 6 alias their buckets. */
  fd_store_publish_stats_t pub[1];
  fd_store_publish( store, 3UL, pub );
  FD_TEST( pub->removed_cnt==2UL );
  for( ulong i=0UL; i<slot_cnt; i++ ) {
    fd_hash_t mr = mr_make( slots[ i ], 0UL );
    FD_TEST( is_miss( store, &mr )==(slots[ i ]<3UL) );
  }
  check_invariants( store );

  /* A jump past the ring length walks each bucket once. */
  fd_store_publish( store, 1000UL, pub );
  FD_TEST( pub->removed_cnt==6UL );
  FD_TEST( !live_cnt( store ) );
  check_invariants( store );

  for( ulong b=0UL; b<store->slot_ring_len; b++ ) FD_TEST( store_ljoin( store ).slot_ring[ b ]==FD_STORE_NULL );
  test_store_delete( store );

  /* Jump from 0 to a large root on a fresh store. */
  store = test_store_new( wksp, 16UL, 31840UL, 0UL, 1UL, 4UL );
  for( ulong i=0UL; i<8UL; i++ ) {
    fd_hash_t mr = mr_make( 100UL+i, 1UL );
    FD_TEST( !insert( store, -1, &mr, 100UL+i, 8UL, i ) );
  }
  fd_store_publish( store, 104UL, pub );
  FD_TEST( pub->removed_cnt==4UL && live_cnt( store )==4UL );
  check_invariants( store );
  fd_store_publish( store, (ulong)UINT_MAX, pub );
  FD_TEST( pub->removed_cnt==4UL && !live_cnt( store ) );
  check_invariants( store );
  test_store_delete( store );
}

/* Legacy FECs carry untracked overflow bytes past the 32 tracked
   shreds; they survive cache and spilled reads. */

void
test_legacy_overflow( fd_wksp_t * wksp ) {
  fd_store_t * store = test_store_new( wksp, 4UL, 63985UL, 1UL, 1UL, 16UL );
  int fd = test_file_open( store );

  fd_hash_t mr0 = mr_make( 1UL, 0UL );
  fd_hash_t mr1 = mr_make( 1UL, 32UL );
  FD_TEST( !insert_ex( store, fd, &mr0, 1UL, 0UL, 63985UL, 32UL*955UL, 32UL, 11UL, NULL ) );
  FD_TEST( !check_ex( store, fd, &mr0, 63985UL, 32UL*955UL, 32UL, 11UL ) ); /* cache */
  FD_TEST( !insert( store, fd, &mr1, 1UL, 5UL, 12UL ) );                     /* spills mr0 */
  FD_TEST( check_ex( store, fd, &mr0, 63985UL, 32UL*955UL, 32UL, 11UL ) );  /* disk */
  FD_TEST( atomic_load_explicit( &store->spill_read_bytes, memory_order_relaxed )==63985UL );

  check_invariants( store );
  close( fd );
  test_store_delete( store );
}

/* Spill on a full cache, spilled reads, ERR_TOO_BIG and disk slot
   reuse. */

void
test_spill( fd_wksp_t * wksp ) {
  fd_store_t * store = test_store_new( wksp, 8UL, 31840UL, 2UL, 1UL, 16UL );
  int fd = test_file_open( store );

  fd_hash_t mr0 = mr_make( 1UL, 0UL );
  fd_hash_t mr1 = mr_make( 1UL, 32UL );
  fd_hash_t mr2 = mr_make( 1UL, 64UL );
  fd_store_insert_stats_t stats[1];
  FD_TEST( !insert_ex( store, fd, &mr0, 1UL, 0UL, 31840UL, 31840UL, 32UL, 0UL, stats ) );
  FD_TEST( !insert_ex( store, fd, &mr1, 1UL, 0UL, 5000UL,  5000UL,  3UL,  1UL, stats ) );
  FD_TEST( !stats->spill.write_ticks && !stats->spill.spilled_cnt );

  /* The cache is full: the LRU head (mr0) is spilled synchronously. */
  FD_TEST( !insert_ex( store, fd, &mr2, 1UL, 0UL, 100UL, 100UL, 1UL, 2UL, stats ) );
  FD_TEST( stats->spill.write_ticks && stats->spill.spilled_cnt==1UL && stats->spill.spilled_bytes==31840UL );
  FD_TEST( atomic_load_explicit( &store->spill_cnt,   memory_order_relaxed )==1UL );
  FD_TEST( atomic_load_explicit( &store->spill_bytes, memory_order_relaxed )==31840UL );
  FD_TEST( atomic_load_explicit( &store->disk_live_cnt, memory_order_relaxed )==1UL );
  FD_TEST( atomic_load_explicit( &store->disk_bump,     memory_order_relaxed )==1UL );
  check_invariants( store );

  /* Spilled reads recover the header and exactly data_sz bytes. */
  FD_TEST(  check_ex( store, fd, &mr0, 31840UL, 31840UL, 32UL, 0UL ) );
  FD_TEST( !check_ex( store, fd, &mr1, 5000UL,  5000UL,  3UL,  1UL ) );
  FD_TEST( atomic_load_explicit( &store->spill_read_cnt,   memory_order_relaxed )==1UL );
  FD_TEST( atomic_load_explicit( &store->spill_read_bytes, memory_order_relaxed )==31840UL );

  /* ERR_TOO_BIG leaves the caller's buffers untouched, on both paths. */
  for( int spilled=0; spilled<2; spilled++ ) {
    fd_hash_t const * mr  = spilled ? &mr0 : &mr1;
    ulong             sz  = spilled ? 31840UL : 5000UL;
    fd_store_view_t view = fd_store_query_acquire( store, mr, NULL );
    FD_TEST( view!=FD_STORE_VIEW_NULL && fd_store_view_spilled( view )==spilled );
    FD_TEST( fd_store_query_data_sz( store, view )==sz );
    fd_memset( check_buf,      0xee, sizeof(check_buf)      );
    fd_memset( check_shred_sz, 0xee, sizeof(check_shred_sz) );
    int was_spilled = -1;
    FD_TEST( fd_store_query_read( store, fd, view, check_buf, sz-1UL, check_shred_sz, &was_spilled )==FD_STORE_ERR_TOO_BIG );
    FD_TEST( was_spilled==spilled );
    for( ulong i=0UL; i<sizeof(check_buf); i++ ) FD_TEST( check_buf[ i ]==0xee );
    for( ulong i=0UL; i<FD_FEC_SHRED_CNT; i++ ) FD_TEST( check_shred_sz[ i ]==0xeeee );
    FD_TEST( fd_store_query_read( store, fd, view, check_buf, sz, check_shred_sz, NULL )==(long)sz );
    fd_store_query_release( store, view );
  }

  /* Releasing a consumed cache FEC puts it at the LRU head, so it is
     the next victim. */
  FD_TEST( !check( store, fd, &mr2, 100UL, 2UL ) );
  fd_hash_t mr3 = mr_make( 2UL, 0UL );
  FD_TEST( !insert( store, fd, &mr3, 2UL, 10UL, 3UL ) );
  FD_TEST(  check( store, fd, &mr2, 100UL, 2UL ) );
  FD_TEST( !check_ex( store, fd, &mr1, 5000UL, 5000UL, 3UL, 1UL ) );
  check_invariants( store );

  /* Disk slot reuse: free slot 1 FECs (two disk slots), then spill a
     small FEC into a reused slot.  Only the page-rounded record is
     written; the stale tail of the larger FEC is never read. */
  ulong bump = atomic_load_explicit( &store->disk_bump, memory_order_relaxed );
  FD_TEST( bump==2UL );
  fd_store_publish( store, 2UL, NULL );
  FD_TEST( !atomic_load_explicit( &store->disk_live_cnt, memory_order_relaxed ) && store->disk_free_cnt==2U );
  fd_hash_t mr4 = mr_make( 2UL, 32UL );
  fd_hash_t mr5 = mr_make( 2UL, 64UL );
  FD_TEST( !insert( store, fd, &mr4, 2UL, 7UL, 4UL ) ); /* fills the cache */
  FD_TEST( !insert( store, fd, &mr5, 2UL, 9UL, 5UL ) ); /* spills mr3 */
  FD_TEST( atomic_load_explicit( &store->disk_bump, memory_order_relaxed )==bump );
  FD_TEST( check( store, fd, &mr3, 10UL, 3UL ) );
  check_invariants( store );

  close( fd );
  test_store_delete( store );
}

void
test_preevict( fd_wksp_t * wksp ) {
  fd_store_t * store = test_store_new( wksp, 32UL, 31840UL, 20UL, 1UL, 16UL );
  int fd = test_file_open( store );
  ulong low    = store->cache_free_low_water;
  ulong target = store->cache_free_target;
  FD_TEST( low>=1UL && low<target && target<=20UL );

  int active = 0;
  fd_store_spill_stats_t spill[1];
  FD_TEST( !fd_store_preevict( store, -1, &active, spill ) && !active ); /* no disk */
  FD_TEST( !fd_store_preevict( store, fd, &active, spill ) && !active ); /* plenty free */

  /* Preevict does nothing until the free count drops below the low
     water mark. */
  ulong i = 0UL;
  while( cache_free( store )>=low ) {
    FD_TEST( !fd_store_preevict( store, fd, &active, spill ) && !active && !spill->write_ticks && !spill->spilled_cnt );
    fd_hash_t mr = mr_make( 1UL, i );
    FD_TEST( !insert( store, fd, &mr, 1UL, 1000UL, i ) );
    i++;
  }
  FD_TEST( cache_free( store )==low-1UL );

  /* Preevict spills one FEC per call until the free count reaches the
     target, then deactivates. */
  ulong spilled = 0UL;
  while( fd_store_preevict( store, fd, &active, spill ) ) {
    FD_TEST( spill->write_ticks && spill->spilled_cnt==1UL && spill->spilled_bytes==1000UL );
    spilled++;
    FD_TEST( active==(cache_free( store )<target) );
  }
  FD_TEST( !active && cache_free( store )==target );
  FD_TEST( spilled==target-(low-1UL) );
  FD_TEST( atomic_load_explicit( &store->spill_cnt, memory_order_relaxed )==spilled );
  FD_TEST( atomic_load_explicit( &store->spill_bytes, memory_order_relaxed )==spilled*1000UL );
  FD_TEST( !fd_store_preevict( store, fd, &active, spill ) && !active );

  /* The oldest FECs were spilled. */
  for( ulong k=0UL; k<i; k++ ) {
    fd_hash_t mr = mr_make( 1UL, k );
    FD_TEST( check( store, fd, &mr, 1000UL, k )==(k<spilled) );
  }

  check_invariants( store );
  close( fd );
  test_store_delete( store );
}

/* Interleaving with an in-flight spill, driven by spill_hook. */

static fd_hash_t       hook_mr;
static int             hook_action;
static fd_store_view_t hook_view;

#define HOOK_PUBLISH        (1)
#define HOOK_PIN            (2)
#define HOOK_PIN_RELEASE    (3)

static void
spill_hook( fd_store_t * store ) {
  switch( hook_action ) {
  case HOOK_PUBLISH: {
    /* Publish does not wait for the spill; the victim is a query miss
       but still a duplicate until the spiller frees it. */
    fd_store_publish_stats_t pub[1];
    fd_store_publish( store, 2UL, pub );
    FD_TEST( pub->removed_cnt==1UL );
    FD_TEST( is_miss( store, &hook_mr ) );
    FD_TEST( insert( store, -1, &hook_mr, 2UL, 0UL, 0UL )==FD_STORE_ERR_DUP );
    break;
  }
  case HOOK_PIN:
  case HOOK_PIN_RELEASE: {
    /* Pinning the victim mid-spill reads the cache copy. */
    hook_view = fd_store_query_acquire( store, &hook_mr, NULL );
    FD_TEST( hook_view!=FD_STORE_VIEW_NULL && !fd_store_view_spilled( hook_view ) );
    FD_TEST( fd_store_query_read( store, -1, hook_view, check_buf, sizeof(check_buf), check_shred_sz, NULL )==100L );
    for( ulong i=0UL; i<100UL; i++ ) FD_TEST( check_buf[ i ]==fill_byte( 0UL, i ) );
    if( hook_action==HOOK_PIN_RELEASE ) fd_store_query_release( store, hook_view );
    break;
  }
  default: break;
  }
  hook_action = 0;
}

void
test_spill_races( fd_wksp_t * wksp ) {
  spill_hook_fn = spill_hook;
  fd_store_t * store = test_store_new( wksp, 4UL, 31840UL, 1UL, 1UL, 16UL );
  int fd = test_file_open( store );
  int active;
  fd_store_spill_stats_t spill[1];

  /* Publish during a spill: SPILLING -> SPILLING_DEAD -> FREE by the
     spiller. */
  hook_mr = mr_make( 1UL, 0UL );
  FD_TEST( !insert( store, fd, &hook_mr, 1UL, 100UL, 0UL ) );
  hook_action = HOOK_PUBLISH;
  active = 1;
  FD_TEST( !fd_store_preevict( store, fd, &active, spill ) ); /* a slot freed, but no live FEC reached disk */
  FD_TEST( !hook_action );
  FD_TEST( !live_cnt( store ) && cache_free( store )==1UL );
  FD_TEST( !atomic_load_explicit( &store->disk_live_cnt, memory_order_relaxed ) );
  FD_TEST( !atomic_load_explicit( &store->spill_cnt, memory_order_relaxed ) );
  FD_TEST( spill->write_ticks && !spill->spilled_cnt && !spill->spilled_bytes );
  FD_TEST( !insert( store, fd, &hook_mr, 2UL, 100UL, 0UL ) ); /* the key is free again */
  check_invariants( store );

  /* Pin during a spill: PINNED_SPILLING -> PINNED, the spill is
     cancelled and the disk slot freed. */
  hook_action = HOOK_PIN;
  active = 1;
  FD_TEST( !fd_store_preevict( store, fd, &active, spill ) );
  FD_TEST( spill->write_ticks && !spill->spilled_cnt && !spill->spilled_bytes );
  FD_TEST( atomic_load_explicit( &store->spill_cancel_cnt, memory_order_relaxed )==1UL );
  FD_TEST( !atomic_load_explicit( &store->disk_live_cnt, memory_order_relaxed ) );
  store_ljoin_t ljoin = store_ljoin( store );
  FD_TEST( data_state( ljoin.meta[ fd_store_view_meta_idx( hook_view ) ].data )==FD_STORE_STATE_PINNED );
  fd_store_query_release( store, hook_view );
  check_invariants( store );

  /* Pin and release during a spill: PINNED_SPILLING -> SPILLING ->
     SPILLED, the spill completes. */
  hook_action = HOOK_PIN_RELEASE;
  active = 1;
  FD_TEST( fd_store_preevict( store, fd, &active, spill ) );
  FD_TEST( atomic_load_explicit( &store->spill_cnt, memory_order_relaxed )==1UL );
  FD_TEST( atomic_load_explicit( &store->spill_cancel_cnt, memory_order_relaxed )==1UL );
  FD_TEST( check( store, fd, &hook_mr, 100UL, 0UL ) );
  check_invariants( store );

  /* A cancelled synchronous spill frees no cache slot; insert_begin
     retries and spills again once released.  The cache has one slot:
     pin mr0 mid-spill, release it, and the inserter's retry spills it. */
  fd_store_publish( store, 3UL, NULL );
  hook_mr = mr_make( 3UL, 0UL );
  FD_TEST( !insert( store, fd, &hook_mr, 3UL, 100UL, 0UL ) );
  hook_action = HOOK_PIN_RELEASE;
  fd_hash_t mr1 = mr_make( 3UL, 32UL );
  fd_store_insert_stats_t stats[1];
  FD_TEST( !insert_ex( store, fd, &mr1, 3UL, 0UL, 10UL, 10UL, 1UL, 1UL, stats ) );
  FD_TEST( stats->spill.write_ticks && stats->spill.spilled_cnt==1UL ); /* completed: the pin was released before the write finished */
  FD_TEST( check( store, fd, &hook_mr, 100UL, 0UL ) );
  check_invariants( store );

  spill_hook_fn = NULL;
  close( fd );
  test_store_delete( store );
}

/* Contract violations fail an FD_TEST rather than corrupting state. */

static fd_hash_t crash_mr;

static void
crash_publish_pinned( fd_store_t * store ) {
  FD_TEST( fd_store_query_acquire( store, &crash_mr, NULL )!=FD_STORE_VIEW_NULL );
  fd_store_publish( store, 100UL, NULL );
}

static void
crash_read_released( fd_store_t * store ) {
  fd_store_view_t view = fd_store_query_acquire( store, &crash_mr, NULL );
  FD_TEST( view!=FD_STORE_VIEW_NULL );
  fd_store_query_release( store, view );
  fd_store_query_read( store, -1, view, check_buf, sizeof(check_buf), check_shred_sz, NULL );
}

static void
crash_data_sz_released( fd_store_t * store ) {
  fd_store_view_t view = fd_store_query_acquire( store, &crash_mr, NULL );
  FD_TEST( view!=FD_STORE_VIEW_NULL );
  fd_store_query_release( store, view );
  fd_store_query_data_sz( store, view );
}

static void
crash_double_pin( fd_store_t * store ) {
  FD_TEST( fd_store_query_acquire( store, &crash_mr, NULL )!=FD_STORE_VIEW_NULL );
  fd_store_query_acquire( store, &crash_mr, NULL );
}

static void
crash_commit_too_big( fd_store_t * store ) {
  fd_hash_t mr = mr_make( 99UL, 99UL );
  fd_store_insert_t ins;
  FD_TEST( fd_store_insert_begin( store, -1, &mr, 1UL, 0UL, NULL, &ins )==FD_STORE_SUCCESS );
  fd_store_insert_commit( store, ins, store->fec_data_max+1UL );
}

static void
crash_commit_tracked( fd_store_t * store ) {
  fd_hash_t mr = mr_make( 99UL, 99UL );
  fd_store_insert_t ins;
  FD_TEST( fd_store_insert_begin( store, -1, &mr, 1UL, 0UL, NULL, &ins )==FD_STORE_SUCCESS );
  fd_store_insert_data( store, ins )->shred_sz[ 3 ] = 11;
  fd_store_insert_commit( store, ins, 10UL );
}

void
test_contracts( void ) {
  /* The children write to the store, so use normal pages: copy on
     write of a private huge page can fail in the child. */
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 1024UL, fd_shmem_cpu_idx( fd_shmem_numa_idx( 0UL ) ), "contracts", 0UL );
  FD_TEST( wksp );
  fd_store_t * store = test_store_new( wksp, 4UL, 31840UL, 0UL, 1UL, 16UL );
  crash_mr = mr_make( 1UL, 0UL );
  FD_TEST( !insert( store, -1, &crash_mr, 1UL, 10UL, 0UL ) );

  expect_crash( store, crash_publish_pinned   );
  expect_crash( store, crash_read_released    );
  expect_crash( store, crash_data_sz_released );
  expect_crash( store, crash_double_pin       );
  expect_crash( store, crash_commit_too_big   );
  expect_crash( store, crash_commit_tracked   );

  /* The parent's store is untouched. */
  FD_TEST( !check( store, -1, &crash_mr, 10UL, 0UL ) );
  check_invariants( store );
  test_store_delete( store );  fd_wksp_delete_anonymous( wksp );
}

/* Random churn across inserts, pins, spills, preevicts and publishes,
   checked against a shadow model. */

#define CHURN_FEC_MAX (64UL)

struct churn_ent {
  fd_hash_t mr;
  ulong     slot;
  ulong     sz;
  ulong     seed;
  int       live;
};
typedef struct churn_ent churn_ent_t;

void
test_churn( fd_wksp_t * wksp ) {
  fd_store_t * store = test_store_new( wksp, CHURN_FEC_MAX, 31840UL, 8UL, 1UL, 8UL );
  int fd = test_file_open( store );
  fd_rng_t rng_[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_, 1234U, 0UL ) );

  static churn_ent_t ent[ 4096 ];
  ulong ent_cnt = 0UL;
  ulong root    = 0UL;
  ulong slot    = 1UL;
  int   active  = 0;

  for( ulong iter=0UL; iter<20000UL; iter++ ) {
    uint r = fd_rng_uint_roll( rng, 100U );
    if( r<50U && ent_cnt<4096UL ) {
      if( fd_rng_uint_roll( rng, 8U )==0U ) slot++;
      churn_ent_t * e = ent + ent_cnt;
      e->mr   = mr_make( slot, ent_cnt );
      e->slot = slot;
      e->sz   = fd_rng_ulong_roll( rng, 31841UL );
      e->seed = iter;
      int err = insert( store, fd, &e->mr, slot, e->sz, e->seed );
      if( err==FD_STORE_ERR_FEC_FULL ) {
        FD_TEST( live_cnt( store )==CHURN_FEC_MAX );
        fd_store_publish( store, ++root>slot ? (root=slot) : root, NULL );
        continue;
      }
      FD_TEST( !err );
      e->live = 1;
      ent_cnt++;
    } else if( r<80U && ent_cnt ) {
      churn_ent_t * e = ent + fd_rng_ulong_roll( rng, ent_cnt );
      if( e->live && e->slot>=root ) check( store, fd, &e->mr, e->sz, e->seed );
      else                           FD_TEST( is_miss( store, &e->mr ) );
    } else if( r<95U ) {
      fd_store_spill_stats_t spill[1];
      fd_store_preevict( store, fd, &active, spill );
    } else {
      ulong new_root = root + fd_rng_ulong_roll( rng, 3UL );
      if( new_root>slot ) new_root = slot;
      fd_store_publish( store, new_root, NULL );
      if( new_root>root ) root = new_root;
    }
    if( !(iter%1024UL) ) check_invariants( store );
  }
  check_invariants( store );

  /* Every surviving FEC still reads back, then publish frees all. */
  for( ulong i=0UL; i<ent_cnt; i++ ) {
    if( ent[ i ].slot>=root ) check( store, fd, &ent[ i ].mr, ent[ i ].sz, ent[ i ].seed );
    else                      FD_TEST( is_miss( store, &ent[ i ].mr ) );
  }
  fd_store_publish( store, slot+1UL, NULL );
  FD_TEST( !live_cnt( store ) && cache_free( store )==store->cache_max );
  FD_TEST( !atomic_load_explicit( &store->disk_live_cnt, memory_order_relaxed ) );
  check_invariants( store );

  fd_rng_delete( fd_rng_leave( rng ) );
  close( fd );
  test_store_delete( store );
}

void
test_file_create( fd_wksp_t * wksp ) {
  FD_TEST( !unlink( TEST_PAYLOAD_PATH ) || errno==ENOENT );

  ulong footprint = fd_store_footprint( 2UL, 31840UL, 1UL, 0UL, 0UL, 1UL, 4UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 2UL, 31840UL, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX,
                                                    0UL, 1UL, 4UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 16UL;
  FD_TEST( access( TEST_PAYLOAD_PATH, F_OK ) && errno==ENOENT );

  int fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( fd>=0 );
  struct stat st[1];
  FD_TEST( !fstat( fd, st ) );
  FD_TEST( (ulong)st->st_size==store->wire_off + store->disk_max_shreds*sizeof(fd_shredb_entry_t) );
  FD_TEST( (ulong)st->st_blocks*512UL<store->disk_max_shreds*sizeof(fd_shredb_entry_t) );

  uchar value = 0xa5U;
  FD_TEST( pwrite( fd, &value, 1UL, 0 )==1L );

  char proc_path[ 64 ];
  FD_TEST( fd_cstr_printf_check( proc_path, sizeof(proc_path), NULL, "/proc/self/fd/%d", fd ) );
  int ro_fd = open( proc_path, O_RDONLY );
  FD_TEST( ro_fd>=0 );
  uchar observed = 0U;
  FD_TEST( pread( ro_fd, &observed, 1UL, 0 )==1L );
  FD_TEST( observed==value );
  errno = 0;
  FD_TEST( pwrite( ro_fd, &value, 1UL, 0 )<0L && errno==EBADF );
  close( ro_fd );
  close( fd );

  /* Reopening keeps the previous contents and resizes to the new ring. */
  store->disk_max_shreds = 32UL;
  fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( fd>=0 );
  FD_TEST( !fstat( fd, st ) );
  FD_TEST( (ulong)st->st_size==store->wire_off + store->disk_max_shreds*sizeof(fd_shredb_entry_t) );
  observed = 0U;
  FD_TEST( pread( fd, &observed, 1UL, 0 )==1L && observed==value );
  close( fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_pread_all( void ) {
  int fd = open( TEST_PAYLOAD_PATH, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600 );
  FD_TEST( fd>=0 );

  uchar src[ 32 ];
  uchar dst[ 33 ];
  for( ulong i=0UL; i<sizeof(src); i++ ) src[ i ] = (uchar)i;
  FD_TEST( !store_pwrite_all( fd, src, sizeof(src), 0 ) );
  FD_TEST( !store_pread_all ( fd, dst, sizeof(src), 0 ) );
  FD_TEST( !memcmp( src, dst, sizeof(src) ) );

  close( fd );
}

void
test_disk_index_footprint( void ) {
  ulong fp_no_disk = fd_store_footprint( 8UL, 31840UL,  0UL, 0UL, 0UL, 1UL, 4UL );
  ulong fp_50_gib  = fd_store_footprint( 8UL, 31840UL, 50UL, 0UL, 0UL, 1UL, 4UL );
  /* 44B ring pool + two fd_map_chain bucket arrays (max_shreds/8
     rounded up to 2^23 heads each) + per-slot hints; the +4096 is
     the slot map's header. */
  FD_TEST( fd_shredb_disk_chain_cnt( fd_shredb_max_shreds( 50UL ) )==(1UL<<23) );
  FD_TEST( fp_50_gib-fp_no_disk==(1834UL<<20)+4096UL );

  /* A 4 TiB ring fits the 32-bit index and 54-bit ticket limits. */
  ulong ring_4_tib = fd_shredb_max_shreds( 4096UL );
  FD_TEST( ring_4_tib==3435973836UL && ring_4_tib<UINT_MAX && ring_4_tib<FD_SHREDB_TAG_SEQ_MASK );
  FD_TEST( fd_store_footprint( 8UL, 31840UL, 4096UL, 0UL, 0UL, 1UL, 4UL )>0UL );
}

void
test_fec_sets_arena( fd_wksp_t * wksp ) {
  ulong fec_max     = 4UL;
  ulong fec_set_cnt = 5UL;

  ulong fp_without = fd_store_footprint( fec_max, 31840UL, 0UL, 0UL, 0UL, 1UL, 4UL );
  ulong fp_with    = fd_store_footprint( fec_max, 31840UL, 0UL, 0UL, fec_set_cnt, 1UL, 4UL );
  FD_TEST( fp_with > fp_without );

  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), fp_with, 1UL );
  fd_store_t * st = fd_store_join( fd_store_new( mem, fec_max, 31840UL, 0UL, 0UL, fec_set_cnt, FD_SHRED_BLK_MAX, 0UL, 1UL, 4UL ) );
  FD_TEST( st );
  FD_TEST( st->fec_set_cnt==fec_set_cnt );

  fd_fec_set_t * fec_sets = fd_store_fec_sets( st );
  FD_TEST( fec_sets );
  FD_TEST( fd_ulong_is_aligned( (ulong)fec_sets, alignof(fd_fec_set_t) ) );

  fec_sets[ 0 ].data_shred_rcvd = 0x12345678U;
  fec_sets[ 4 ].parity_shred_rcvd = 0x87654321U;
  FD_TEST( fec_sets[ 0 ].data_shred_rcvd==0x12345678U );
  FD_TEST( fec_sets[ 4 ].parity_shred_rcvd==0x87654321U );

  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( st ) ) );
}

/* disk_root returns a merkle root for shred's FEC set, derived from
   (slot, idx/FD_FEC_SHRED_CNT) so re-inserting a (slot,idx) repeats its
   (root,idx). */

static fd_hash_t
disk_root( ulong slot,
           uint  fec_idx ) {
  fd_hash_t root;
  for( ulong i=0UL; i<4UL; i++ ) root.ul[ i ] = fd_ulong_hash( (slot<<20) ^ ((ulong)fec_idx<<2) ^ i );
  return root;
}

static int
disk_insert( fd_store_t *       store,
             int                disk_fd,
             fd_shred_t const * shred ) {
  fd_hash_t root = disk_root( shred->slot, shred->idx/FD_FEC_SHRED_CNT );
  return fd_store_disk_insert( store, disk_fd, shred, &root );
}

static fd_store_t * disk_concurrent_store;
static int          disk_concurrent_fd;
static uchar        disk_concurrent_shred[ FD_TILE_MAX ][ FD_SHRED_MAX_SZ ];
static int          disk_concurrent_result[ FD_TILE_MAX ];
static atomic_ulong disk_concurrent_go;

static fd_shred_t *
disk_make_shred( uchar buf[ FD_SHRED_MAX_SZ ],
                 ulong slot,
                 uint  idx,
                 uchar marker ) {
  fd_memset( buf, 0, FD_SHRED_MAX_SZ );
  fd_shred_t * shred = fd_type_pun( buf );
  shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
  shred->slot      = slot;
  shred->idx       = idx;
  shred->data.size = (ushort)(FD_SHRED_DATA_HEADER_SZ+1UL);
  buf[ FD_SHRED_DATA_HEADER_SZ ] = marker;
  return shred;
}

static int
disk_tile_insert_concurrent( int argc FD_PARAM_UNUSED,
                             char ** argv FD_PARAM_UNUSED ) {
  ulong tile_idx = fd_tile_idx();
  while( !atomic_load_explicit( &disk_concurrent_go, memory_order_acquire ) ) FD_SPIN_PAUSE();
  disk_concurrent_result[ tile_idx ] = disk_insert(
      disk_concurrent_store, disk_concurrent_fd,
      (fd_shred_t const *)fd_type_pun_const( disk_concurrent_shred[ tile_idx ] ) );
  return 0;
}

void
test_disk_query_highest( fd_wksp_t * wksp ) {
  ulong fec_max      = 8UL;
  ulong fec_data_max = 31840UL;
  ulong footprint    = fd_store_footprint( fec_max, fec_data_max, 1UL, 0UL, 0UL, 1UL, 4UL );
  void * mem         = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, fec_max, fec_data_max, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX,
                                                    42UL, 1UL, 4UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 64UL;

  int disk_fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( disk_fd>=0 );

  struct stat file_stat[1];
  FD_TEST( !fstat( disk_fd, file_stat ) );
  FD_TEST( (ulong)file_stat->st_size==store->wire_off + store->disk_max_shreds*sizeof(fd_shredb_entry_t) );
  FD_TEST( (ulong)file_stat->st_blocks*512UL<store->disk_max_shreds*sizeof(fd_shredb_entry_t) );
  FD_TEST( (ulong)file_stat->st_blocks*512UL<(ulong)file_stat->st_size );

  uchar buf[ FD_SHRED_MAX_SZ ];
  fd_memset( buf, 0, sizeof(buf) );
  fd_shred_t * shred = (fd_shred_t *)fd_type_pun( buf );
  shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
  shred->slot      = 42UL;
  shred->idx       = 3U;
  shred->data.size = (ushort)FD_SHRED_DATA_HEADER_SZ;

  FD_TEST( disk_insert( store, disk_fd, shred )==FD_STORE_DISK_INSERT_SUCCESS );

  uchar out[ FD_SHRED_MAX_SZ ];
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, 42UL, 3U, out )>0 );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, 42UL, 4U, out )==FD_STORE_DISK_QUERY_MISS );

  fd_store_disk_stats_t stats[1];
  FD_TEST( !fd_store_disk_stats_query( store, stats ) );
  FD_TEST( stats->shred_cnt==1UL );
  FD_TEST( stats->current_bytes==sizeof(fd_shredb_entry_t) );
  FD_TEST( stats->allocated_bytes==sizeof(fd_shredb_entry_t) );
  FD_TEST( stats->insert_cnt==1UL );
  FD_TEST( stats->write_bytes==sizeof(fd_shredb_entry_t) );

  fd_shredb_entry_t raw_entry[1];
  FD_TEST( pread( disk_fd, raw_entry, sizeof(fd_shredb_entry_t), (off_t)store->wire_off )==(long)sizeof(fd_shredb_entry_t) );
  ulong first_shred_sz = fd_shred_sz( shred );
  FD_TEST( first_shred_sz<FD_SHRED_MAX_SZ );
  FD_TEST( raw_entry->shred_sz==first_shred_sz );
  /* Every byte past the shred is zero through the end of the struct
     (the writer only zeroes that tail, not the whole entry). */
  for( ulong i=__builtin_offsetof( fd_shredb_entry_t, shred )+first_shred_sz; i<sizeof(fd_shredb_entry_t); i++ ) {
    FD_TEST( !((uchar const *)raw_entry)[ i ] );
  }
  ulong first_tag = raw_entry->tag;

  fd_memset( buf, 0, sizeof(buf) );
  shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
  shred->slot      = 43UL;
  shred->idx       = 3U;
  shred->data.size = (ushort)FD_SHRED_DATA_HEADER_SZ;
  shred->data.flags = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;

  FD_TEST( disk_insert( store, disk_fd, shred )==FD_STORE_DISK_INSERT_SUCCESS );
  /* An unrelated metadata update does not invalidate this binding. */
  FD_TEST( pread( disk_fd, raw_entry, sizeof(fd_shredb_entry_t), (off_t)store->wire_off )==(long)sizeof(fd_shredb_entry_t) );
  FD_TEST( raw_entry->tag==first_tag );

  FD_TEST( fd_store_disk_query_highest( store, disk_fd, 43UL, 4U, out )>0 );
  fd_shred_t const * result = (fd_shred_t const *)fd_type_pun_const( out );
  FD_TEST( result->slot==43UL );
  FD_TEST( result->idx==3U );
  FD_TEST( result->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_disk_many_wraps( fd_wksp_t * wksp ) {
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL, 1UL, 4UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX,
                                                    42UL, 1UL, 4UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 16UL;

  /* Start just before the 54-bit ticket wrap. */
  ulong first_ticket = (1UL<<54)-80UL;
  atomic_store_explicit( &store->disk_reservation_head, first_ticket, memory_order_relaxed );

  int disk_fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( disk_fd>=0 );

  uchar buf[ FD_SHRED_MAX_SZ ];
  uchar out[ FD_SHRED_MAX_SZ ];

  /* Cross the ticket wrap and overwrite the 16-cell ring repeatedly.
     Just before the wrap, query a shred whose tag uses all three high bytes. */
  for( ulong i=0UL; i<160UL; i++ ) {
    FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, i/4UL, (uint)(i%4UL), (uchar)i ) )==FD_STORE_DISK_INSERT_SUCCESS );
    if( i==79UL ) FD_TEST( fd_store_disk_query( store, disk_fd, 19UL, 3U, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==79U );
  }

  /* Only the last ringful remains readable. */
  FD_TEST( atomic_load_explicit( &store->disk_cnt, memory_order_relaxed )==16UL );
  for( ulong i=144UL; i<160UL; i++ ) {
    int sz = fd_store_disk_query( store, disk_fd, i/4UL, (uint)(i%4UL), out );
    FD_TEST( sz>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==(uchar)i );
  }
  FD_TEST( fd_store_disk_query( store, disk_fd, 35UL, 3U, out )==FD_STORE_DISK_QUERY_MISS );

  /* Snapshot a live cell before replacing it. */
  disk_view_t stale;
  fd_rwlock_read( &store->disk_lock );
  FD_TEST( !disk_query_prepare_read_locked( store, fd_shredb_key_pack( 39UL, 3U ), NULL, 3U, &stale ) );
  fd_rwlock_unread( &store->disk_lock );

  /* Recreate the old 32-bit tag's ABA case: after 2^30 tickets the
     ring index and low tag repeat, but the high tag must differ. */
  ulong next_ticket = first_ticket+159UL+(1UL<<30);
  FD_TEST( (uint)disk_cell_tag( stale.ticket, FD_SHREDB_CELL_READY )==(uint)disk_cell_tag( next_ticket, FD_SHREDB_CELL_READY ) );
  FD_TEST( (ulong)stale.ring_idx==next_ticket%store->disk_max_shreds );
  atomic_store_explicit( &store->disk_reservation_head, next_ticket, memory_order_relaxed );
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, 1000UL, 0U, 0xe0U ) )==FD_STORE_DISK_INSERT_SUCCESS );

  /* The high tag bits reject the stale view; the new shred is readable. */
  fd_rwlock_read( &store->disk_lock );
  FD_TEST( disk_query_finish_read_locked( store, stale )==FD_STORE_DISK_QUERY_BUSY );
  fd_rwlock_unread( &store->disk_lock );
  FD_TEST( fd_store_disk_query( store, disk_fd, 1000UL, 0U, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xe0U );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

/* Several versions of one (slot,idx): the slot map serves the first
   stored, the root map serves each, and both follow ring eviction. */

void
test_disk_versions( fd_wksp_t * wksp ) {
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL, 1UL, 4UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX,
                                                    42UL, 1UL, 4UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 4UL;

  int disk_fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( disk_fd>=0 );

  ulong const slot = 50UL;
  uint  const idx  = 3U;
  fd_hash_t root_a = disk_root( 1000UL, 0U );
  fd_hash_t root_b = disk_root( 1001UL, 0U );
  fd_hash_t root_c = disk_root( 1002UL, 0U );
  uchar buf[ FD_SHRED_MAX_SZ ];
  uchar out[ FD_SHRED_MAX_SZ ];

  /* Two versions are both stored and addressable by root; (slot,idx)
     keeps the first. */
  FD_TEST( fd_store_disk_insert( store, disk_fd, disk_make_shred( buf, slot, idx, 0xa0U ), &root_a )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_insert( store, disk_fd, disk_make_shred( buf, slot, idx, 0xb0U ), &root_b )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( atomic_load_explicit( &store->disk_cnt, memory_order_relaxed )==2UL );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot, idx, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xa0U );
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_a.uc, idx, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xa0U );
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_b.uc, idx, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xb0U );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot, 0U, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xa0U );

  /* Only the root prefix is keyed and checked */
  fd_hash_t root_b_tail = root_b; root_b_tail.uc[ 31 ] ^= 1;
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_b_tail.uc, idx, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xb0U );

  /* Wrong idx or unknown root misses */
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_a.uc, idx+1U, out )==FD_STORE_DISK_QUERY_MISS );
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_c.uc, idx,    out )==FD_STORE_DISK_QUERY_MISS );
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_a.uc, FD_SHRED_BLK_MAX, out )==FD_STORE_DISK_QUERY_MISS );

  /* The key holds the offset in the FEC set, so the same offset in the
     next FEC set maps to the same key.  The read checks the full idx on
     disk and misses. */
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_a.uc, idx+FD_FEC_SHRED_CNT, out )==FD_STORE_DISK_QUERY_MISS );

  /* Re-inserting a stored (root,idx) does not take a ring cell */
  ulong head = atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed );
  FD_TEST( fd_store_disk_insert( store, disk_fd, disk_make_shred( buf, slot, idx, 0xb1U ), &root_b )==FD_STORE_DISK_INSERT_DUP );
  FD_TEST( atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed )==head );
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_b.uc, idx, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xb0U );

  /* Fill the four-cell ring, then overwrite version A's cell.  (slot,idx)
     misses even though version B is still stored under its root. */
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, slot+1UL, 0U, 0xc0U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, slot+1UL, 1U, 0xc1U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, slot+1UL, 2U, 0xc2U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_a.uc, idx, out )==FD_STORE_DISK_QUERY_MISS );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot, idx, out )==FD_STORE_DISK_QUERY_MISS );
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_b.uc, idx, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xb0U );
  FD_TEST( atomic_load_explicit( &store->disk_cnt, memory_order_relaxed )==4UL );

  /* With (slot,idx) free again, the next new version takes it */
  FD_TEST( fd_store_disk_insert( store, disk_fd, disk_make_shred( buf, slot, idx, 0xd0U ), &root_c )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot, idx, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xd0U );
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_c.uc, idx, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xd0U );

  /* That insert overwrote version B's cell */
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_b.uc, idx, out )==FD_STORE_DISK_QUERY_MISS );
  FD_TEST( atomic_load_explicit( &store->disk_cnt, memory_order_relaxed )==4UL );

  /* An evicted (root,idx) can be stored again */
  FD_TEST( fd_store_disk_insert( store, disk_fd, disk_make_shred( buf, slot, idx, 0xa1U ), &root_a )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root_a.uc, idx, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xa1U );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot, idx, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xd0U );

  /* A root is required */
  FD_TEST( fd_store_disk_insert( store, disk_fd, disk_make_shred( buf, slot, idx, 0U ), NULL )==FD_STORE_DISK_INSERT_ERR );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

/* Reformat the empty disk maps with a tiny bucket count so distinct
   keys collide in one chain.  Call after fd_store_new and before any
   disk insertion. */
static void
test_force_disk_chain_cnt( fd_wksp_t *  wksp,
                           fd_store_t * store,
                           ulong        chain_cnt ) {
  FD_TEST( fd_shredb_slot_map_new( fd_wksp_laddr_fast( wksp, store->shred_map_gaddr ), chain_cnt, 42UL ) );
  FD_TEST( fd_shredb_root_map_new( fd_wksp_laddr_fast( wksp, store->root_map_gaddr ), chain_cnt, 42UL ) );
}

/* The root-map key aliases full indices separated by 32.  The first
   stored shred wins; later aliases and exact repeats take no ticket. */
void
test_disk_root_offset_alias( fd_wksp_t * wksp ) {
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL, 1UL, 4UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX,
                                                    42UL, 1UL, 4UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 4UL;

  /* Exercise collisions in both map chains as well as logical root-key
     aliasing. */
  test_force_disk_chain_cnt( wksp, store, 1UL );
  int disk_fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( disk_fd>=0 );

  fd_hash_t root = disk_root( 500UL, 0U );
  uchar     buf[ FD_SHRED_MAX_SZ ];
  uchar     out[ FD_SHRED_MAX_SZ ];

  /* Seed an unrelated cell and the first owner of the root key. */
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, 10UL, 0U, 0xa0U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_insert( store, disk_fd, disk_make_shred( buf, 11UL, 3U, 0xb0U ), &root )==FD_STORE_DISK_INSERT_SUCCESS );

  /* Index 35 aliases index 3 in the root map; it takes no ring cell. */
  ulong head = atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed );
  FD_TEST( fd_store_disk_insert( store, disk_fd, disk_make_shred( buf, 11UL, 35U, 0xc0U ), &root )==FD_STORE_DISK_INSERT_DUP );
  FD_TEST( atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed )==head );

  /* The original owner remains readable; the alias misses. */
  FD_TEST( atomic_load_explicit( &store->disk_cnt, memory_order_relaxed )==2UL );
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root.uc, 3U, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xb0U );
  FD_TEST( fd_store_disk_query( store, disk_fd, 11UL, 3U, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xb0U );
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root.uc, 35U, out )==FD_STORE_DISK_QUERY_MISS );
  FD_TEST( fd_store_disk_query( store, disk_fd, 11UL, 35U, out )==FD_STORE_DISK_QUERY_MISS );
  FD_TEST( fd_store_disk_query( store, disk_fd, 10UL, 0U, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xa0U );

  /* An exact repeat is also a no-op. */
  FD_TEST( fd_store_disk_insert( store, disk_fd, disk_make_shred( buf, 11UL, 3U, 0xd0U ), &root )==FD_STORE_DISK_INSERT_DUP );
  FD_TEST( atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed )==head );
  FD_TEST( fd_store_disk_query_root( store, disk_fd, root.uc, 3U, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xb0U );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_disk_concurrent_writes( fd_wksp_t * wksp ) {
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL, 1UL, 4UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX,
                                                    42UL, 1UL, 4UL ) );
  FD_TEST( store );
  store->disk_max_shreds = fd_ulong_max( 16UL, 2UL*fd_tile_cnt() );
  int disk_fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( disk_fd>=0 );

  ulong tile_cnt = fd_tile_cnt();
  for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
    fd_memset( disk_concurrent_shred[ tile_idx ], 0, FD_SHRED_MAX_SZ );
    fd_shred_t * shred = fd_type_pun( disk_concurrent_shred[ tile_idx ] );
    shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
    shred->slot      = 100UL + tile_idx;
    shred->idx       = 0U;
    shred->data.size = (ushort)FD_SHRED_DATA_HEADER_SZ;
    disk_concurrent_result[ tile_idx ] = FD_STORE_DISK_INSERT_ERR;
  }

  disk_concurrent_store = store;
  disk_concurrent_fd    = disk_fd;
  atomic_store_explicit( &disk_concurrent_go, 0UL, memory_order_relaxed );
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
    fd_tile_exec_new( tile_idx, disk_tile_insert_concurrent, 0, NULL );
  atomic_store_explicit( &disk_concurrent_go, 1UL, memory_order_release );
  FD_TEST( !disk_tile_insert_concurrent( 0, NULL ) );
  for( ulong tile_idx=1UL; tile_idx<tile_cnt; tile_idx++ )
    fd_tile_exec_delete( fd_tile_exec( tile_idx ), NULL );

  uchar out[ FD_SHRED_MAX_SZ ];
  for( ulong tile_idx=0UL; tile_idx<tile_cnt; tile_idx++ ) {
    FD_TEST( disk_concurrent_result[ tile_idx ]==FD_STORE_DISK_INSERT_SUCCESS );
    FD_TEST( fd_store_disk_query( store, disk_fd, 100UL+tile_idx, 0U, out )>0 );
  }
  FD_TEST( atomic_load_explicit( &store->disk_cnt, memory_order_relaxed )==tile_cnt );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_disk_slot_hint( fd_wksp_t * wksp ) {
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL, 1UL, 4UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX,
                                                    42UL, 1UL, 4UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 4UL;

  int disk_fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( disk_fd>=0 );

  ulong const stride = store->disk_max_slots;
  ulong const slot_a = 17UL;
  ulong const slot_b = slot_a + stride;
  ulong const slot_c = slot_b + stride;
  ulong const slot_d = slot_c + stride;
  FD_TEST( stride>8UL && slot_d<FD_SHREDB_KEY_SLOT_MAX );
  FD_TEST( slot_a%stride==slot_b%stride && slot_b%stride==slot_c%stride && slot_c%stride==slot_d%stride );

  uchar buf[ FD_SHRED_MAX_SZ ];
  uchar out[ FD_SHRED_MAX_SZ ];

  /* A newer slot that wraps onto this bucket replaces the stale owner
     even when its shred index is lower. */
  FD_TEST( disk_insert( store, disk_fd,
                                 disk_make_shred( buf, slot_a, 10U, 0xa1U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( disk_insert( store, disk_fd,
                                 disk_make_shred( buf, slot_b, 5U, 0xb1U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot_b, 5U, out )>0 );
  FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==0xb1U );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_b, 0U, out )>0 );
  FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==0xb1U );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_a, 0U, out )==FD_STORE_DISK_QUERY_BUSY );

  /* Monotonicity still applies within one slot. */
  FD_TEST( disk_insert( store, disk_fd,
                                 disk_make_shred( buf, slot_b, 3U, 0xb2U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_b, 0U, out )>0 );
  FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==0xb1U );

  /* The next modulo generation can take ownership in the same way. */
  FD_TEST( disk_insert( store, disk_fd,
                                 disk_make_shred( buf, slot_c, 11U, 0xc1U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_c, 0U, out )>0 );
  FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==0xc1U );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_a, 0U, out )==FD_STORE_DISK_QUERY_BUSY );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot_a, 10U, out )>0 );

  /* Advance the four-cell ring until slot_c:11 is evicted.  The hint is
     intentionally never lowered or removed, so a missing hinted exact
     key must return SCAN_LIMIT rather than a false lower result. */
  for( ulong i=0UL; i<4UL; i++ )
    FD_TEST( disk_insert( store, disk_fd,
                                   disk_make_shred( buf, slot_a+1UL+i, 0U, (uchar)(0xd0U+i) ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot_c, 11U, out )==FD_STORE_DISK_QUERY_MISS );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_c, 0U, out )==FD_STORE_DISK_QUERY_SCAN_LIMIT );

  FD_TEST( disk_insert( store, disk_fd,
                                 disk_make_shred( buf, slot_c, 3U, 0xc2U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot_c, 3U, out )>0 );
  FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==0xc2U );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_c, 0U, out )==FD_STORE_DISK_QUERY_SCAN_LIMIT );
  FD_TEST( disk_insert( store, disk_fd,
                                 disk_make_shred( buf, slot_c, FD_SHRED_BLK_MAX, 0xc3U ) )==FD_STORE_DISK_INSERT_ERR );

  /* A fresh modulo generation must be serviceable from shred zero; it
     must not wait to exceed slot_c's stale index 11 watermark. */
  FD_TEST( disk_insert( store, disk_fd,
                                 disk_make_shred( buf, slot_d, 0U, 0xe0U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_d, 0U, out )>0 );
  FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==0xe0U );

  /* A root-only version must not replace another slot's hint. */
  ulong const slot_e = slot_d + stride;
  ulong const slot_f = slot_e + stride;
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, slot_e, 0U, 0xf0U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, slot_f, 0U, 0xf1U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  fd_hash_t other_root = disk_root( slot_e+1UL, 0U );
  FD_TEST( fd_store_disk_insert( store, disk_fd, disk_make_shred( buf, slot_e, 0U, 0xf2U ), &other_root )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_f, 0U, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0xf1U );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

/* The probe must never say miss when the query would hit, return
   BUSY or return SCAN_LIMIT; it may say maybe when the query misses. */

void
test_disk_probe( fd_wksp_t * wksp ) {
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL, 1UL, 4UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX,
                                                    42UL, 1UL, 4UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 4UL;

  int disk_fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( disk_fd>=0 );

  ulong const stride = store->disk_max_slots;
  ulong const slot_a = 17UL;
  ulong const slot_b = slot_a + stride;
  ulong const slot_z = slot_a + 1UL; /* never inserted, own bucket */

  uchar buf[ FD_SHRED_MAX_SZ ];
  uchar out[ FD_SHRED_MAX_SZ ];

  /* Empty store: everything is a certain miss. */
  FD_TEST( !fd_store_disk_probe( store, slot_a, 0U ) );
  FD_TEST( !fd_store_disk_probe( store, slot_a, UINT_MAX ) );
  FD_TEST( !fd_store_disk_probe( store, slot_a, (uint)store->max_shreds_per_block ) );
  FD_TEST( !fd_store_disk_probe( store, FD_SHREDB_KEY_SLOT_MAX, 0U ) );
  FD_TEST( !fd_store_disk_probe( NULL, slot_a, 0U ) );

  /* Exact hit and highest hit; other shreds of the slot still miss. */
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, slot_a, 10U, 0xa1U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST(  fd_store_disk_probe( store, slot_a, 10U ) );
  FD_TEST(  fd_store_disk_probe( store, slot_a, UINT_MAX ) );
  FD_TEST( !fd_store_disk_probe( store, slot_a, 9U ) );
  FD_TEST( !fd_store_disk_probe( store, slot_z, UINT_MAX ) );
  FD_TEST( !fd_store_disk_probe( store, slot_z, 10U ) );

  /* A colliding slot takes the hint: the query for slot_a now returns
     BUSY, so the probe must still say maybe. */
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, slot_b, 5U, 0xb1U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_a, 0U, out )==FD_STORE_DISK_QUERY_BUSY );
  FD_TEST( fd_store_disk_probe( store, slot_a, UINT_MAX ) );
  FD_TEST( fd_store_disk_probe( store, slot_b, UINT_MAX ) );
  FD_TEST( fd_store_disk_probe( store, slot_a, 10U ) );
  FD_TEST( fd_store_disk_probe( store, slot_b, 5U ) );

  /* Evict slot_a:10 through the four-cell ring.  The exact probe now
     misses for certain; the hint is never lowered, so the highest
     query returns SCAN_LIMIT and the probe keeps saying maybe. */
  for( ulong i=0UL; i<4UL; i++ )
    FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, slot_a+2UL+i, 0U, (uchar)(0xd0U+i) ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot_b, 5U, out )==FD_STORE_DISK_QUERY_MISS );
  FD_TEST( !fd_store_disk_probe( store, slot_b, 5U ) );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot_b, 0U, out )==FD_STORE_DISK_QUERY_SCAN_LIMIT );
  FD_TEST( fd_store_disk_probe( store, slot_b, UINT_MAX ) );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_disk_lazy_highest( fd_wksp_t * wksp ) {
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL, 1UL, 4UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX,
                                                    42UL, 1UL, 4UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 2UL;

  int disk_fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( disk_fd>=0 );
  uchar buf[ FD_SHRED_MAX_SZ ];
  uint idxs[3] = { 15000U, 0U, 0U };
  ulong slots[3] = { 7UL, 7UL, 8UL };
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( buf, 0, sizeof(buf) );
    fd_shred_t * shred = fd_type_pun( buf );
    shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
    shred->slot      = slots[i];
    shred->idx       = idxs[i];
    shred->data.size = (ushort)FD_SHRED_DATA_HEADER_SZ;
    FD_TEST( disk_insert( store, disk_fd, shred )==FD_STORE_DISK_INSERT_SUCCESS );
  }

  uchar out[ FD_SHRED_MAX_SZ ];
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, 7UL, 0U, out )==FD_STORE_DISK_QUERY_SCAN_LIMIT );
  FD_TEST( fd_store_disk_query( store, disk_fd, 7UL, 0U, out )>0 );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

void
test_disk_collision_eviction( fd_wksp_t * wksp ) {
  ulong const seed = 42UL;
  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL, 1UL, 4UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX,
                                                    seed, 1UL, 4UL ) );
  FD_TEST( store );
  store->disk_max_shreds = 2UL;
  test_force_disk_chain_cnt( wksp, store, 1UL );

  int disk_fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( disk_fd>=0 );

  /* Force both maps' keys into a single bucket, then wrap after two
     entries to exercise removal in the middle of each chain. */
  ulong keys[ 3 ] = { fd_shredb_key_pack( 7UL, 1U ),
                      fd_shredb_key_pack( 8UL, 1U ),
                      fd_shredb_key_pack( 9UL, 1U ) };

  uchar payloads[ 3 ] = { 1U, 2U, 3U };
  uchar buf[ FD_SHRED_MAX_SZ ];
  uchar out[ FD_SHRED_MAX_SZ ];
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( buf, 0, sizeof(buf) );
    fd_shred_t * shred = (fd_shred_t *)fd_type_pun( buf );
    shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
    shred->slot      = fd_shredb_key_slot( keys[ i ] );
    shred->idx       = fd_shredb_key_shred_idx( keys[ i ] );
    shred->data.size = (ushort)(FD_SHRED_DATA_HEADER_SZ+1UL);
    buf[ FD_SHRED_DATA_HEADER_SZ ] = payloads[ i ];

    FD_TEST( disk_insert( store, disk_fd, shred )==FD_STORE_DISK_INSERT_SUCCESS );
  }

  FD_TEST( fd_store_disk_query( store, disk_fd, fd_shredb_key_slot( keys[ 0 ] ), fd_shredb_key_shred_idx( keys[ 0 ] ), out )==FD_STORE_DISK_QUERY_MISS );
  for( ulong i=1UL; i<3UL; i++ ) {
    FD_TEST( fd_store_disk_query( store, disk_fd, fd_shredb_key_slot( keys[ i ] ), fd_shredb_key_shred_idx( keys[ i ] ), out )>0 );
    FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==payloads[ i ] );
  }

  /* A malformed in-memory header must not make the fixed-size disk
     entry copy past either its source or destination buffer. */
  fd_memset( buf, 0, sizeof(buf) );
  fd_shred_t * oversized = (fd_shred_t *)fd_type_pun( buf );
  oversized->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
  oversized->slot      = 9UL;
  oversized->idx       = 0U;
  oversized->data.size = USHRT_MAX;
  FD_TEST( disk_insert( store, disk_fd, oversized )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query( store, disk_fd, 9UL, 0U, out )==(int)FD_SHRED_MAX_SZ );

  /* A busy ring cell consumes a ticket so the next insert can try a
     different cell. */
  fd_shredb_ring_entry_t * pool = disk_ring_pool_laddr( store );
  fd_rwlock_write( &store->disk_lock );
  uint tag = pool[ 0 ].tag;
  pool[ 0 ].tag = (tag & ~(uint)FD_SHREDB_CELL_STATE_MASK) | (uint)FD_SHREDB_CELL_WRITING;
  fd_rwlock_unwrite( &store->disk_lock );
  ulong head = atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed );
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, 10UL, 0U, 4U ) )==FD_STORE_DISK_INSERT_ERR );
  FD_TEST( atomic_load_explicit( &store->disk_reservation_head, memory_order_relaxed )==head+1UL );

  fd_rwlock_write( &store->disk_lock );
  pool[ 0 ].tag = tag;
  fd_rwlock_unwrite( &store->disk_lock );
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, 10UL, 0U, 4U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query( store, disk_fd, 9UL, 1U, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==3U );

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

/* max_shreds_per_block is a runtime value: a store sized for 4x
   FD_SHRED_BLK_MAX round-trips shred idxs above the production bound
   through the exact index and the per-slot highest hint, and rejects
   idxs at or beyond its own bound.  Also pins the key encoding. */

void
test_disk_max_shreds_per_block( fd_wksp_t * wksp ) {
  ulong const shred_max = 4UL*FD_SHRED_BLK_MAX;
  FD_TEST( fd_shredb_key_pack( 5UL, (uint)shred_max-1U )==((5UL<<32)|(shred_max-1UL)) );
  FD_TEST( fd_shredb_key_slot( fd_shredb_key_pack( FD_SHREDB_KEY_SLOT_MAX-1UL, 7U ) )==FD_SHREDB_KEY_SLOT_MAX-1UL );
  FD_TEST( fd_shredb_key_shred_idx( fd_shredb_key_pack( FD_SHREDB_KEY_SLOT_MAX-1UL, 7U ) )==7U );

  ulong footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL, 1UL, 4UL );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  FD_TEST( !fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL, 0UL,                      42UL, 1UL, 4UL ) );
  FD_TEST( !fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL, FD_SHREDB_HINT_VALID+1UL, 42UL, 1UL, 4UL ) );
  FD_TEST( !fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX,        42UL, 0UL, 4UL ) ); /* no insert partition */
  fd_store_t * store = fd_store_join( fd_store_new( mem, 8UL, 31840UL, 1UL, 0UL, 0UL, shred_max,
                                                    42UL, 1UL, 4UL ) );
  FD_TEST( store && store->max_shreds_per_block==shred_max );
  store->disk_max_shreds = 8UL;

  int disk_fd = fd_store_file_create( TEST_PAYLOAD_PATH, store->wire_off, store->disk_max_shreds );
  FD_TEST( disk_fd>=0 );

  uchar buf[ FD_SHRED_MAX_SZ ];
  uchar out[ FD_SHRED_MAX_SZ ];
  ulong const slot = 21UL;
  uint  const lo   = FD_SHRED_BLK_MAX-1U; /* highest production idx */
  uint  const hi   = (uint)shred_max-1U;  /* highest bench idx, bit 15 set */

  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, slot, lo, 0x10U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, slot, hi, 0x20U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, slot, (uint)shred_max, 0x30U ) )==FD_STORE_DISK_INSERT_ERR );
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, FD_SHREDB_KEY_SLOT_MAX, 0U, 0x40U ) )==FD_STORE_DISK_INSERT_ERR );

  FD_TEST( fd_store_disk_query( store, disk_fd, slot, lo, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0x10U );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot, hi, out )>0 && out[ FD_SHRED_DATA_HEADER_SZ ]==0x20U );
  FD_TEST( fd_store_disk_query( store, disk_fd, slot, (uint)shred_max, out )==FD_STORE_DISK_QUERY_MISS );
  FD_TEST( fd_store_disk_query( store, disk_fd, FD_SHREDB_KEY_SLOT_MAX, 0U, out )==FD_STORE_DISK_QUERY_MISS );

  /* The hint tracks hi, which a 15-bit hint field would have folded. */
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot, 0U, out )>0 );
  FD_TEST( ((fd_shred_t const *)fd_type_pun_const( out ))->idx==hi );
  FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==0x20U );
  FD_TEST( disk_insert( store, disk_fd, disk_make_shred( buf, slot, lo+1U, 0x11U ) )==FD_STORE_DISK_INSERT_SUCCESS );
  FD_TEST( fd_store_disk_query_highest( store, disk_fd, slot, 0U, out )>0 );
  FD_TEST( ((fd_shred_t const *)fd_type_pun_const( out ))->idx==hi ); /* never lowered */

  close( disk_fd );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( store ) ) );
}

/* Park and wake: with one cache slot pinned by replay, inserters park
   until the release pushes the slot back onto the LRU.  The first
   woken inserter spills it, and its commit's LRU push wakes the
   next. */

static fd_store_t *            park_store;
static int                     park_fd;
static fd_store_insert_stats_t park_stats[ FD_TILE_MAX ];
static atomic_ulong            park_done;

static int
park_tile( int     argc,
           char ** argv FD_PARAM_UNUSED ) {
  ulong part = (ulong)argc;
  fd_hash_t mr = mr_make( 2UL, part );
  FD_TEST( !insert_ex( park_store, park_fd, &mr, 2UL, part, 100UL, 100UL, 1UL, part, park_stats+part ) );
  atomic_fetch_add_explicit( &park_done, 1UL, memory_order_release );
  return 0;
}

void
test_park( fd_wksp_t * wksp ) {
  ulong tile_cnt = fd_tile_cnt();
  ulong park_cnt = fd_ulong_min( tile_cnt-1UL, 2UL );
  if( FD_UNLIKELY( !park_cnt ) ) { FD_LOG_WARNING(( "skip test_park: needs at least 2 tiles" )); return; }

  park_store = test_store_new( wksp, 8UL, 31840UL, 1UL, 1UL+park_cnt, 16UL );
  park_fd    = test_file_open( park_store );
  atomic_store_explicit( &park_done, 0UL, memory_order_relaxed );

  fd_hash_t mr0 = mr_make( 1UL, 0UL );
  FD_TEST( !insert( park_store, park_fd, &mr0, 1UL, 100UL, 0UL ) );
  fd_store_view_t view = fd_store_query_acquire( park_store, &mr0, NULL );
  FD_TEST( view!=FD_STORE_VIEW_NULL );

  for( ulong i=1UL; i<=park_cnt; i++ ) FD_TEST( fd_tile_exec_new( i, park_tile, (int)i, NULL ) );

  /* Wait for every inserter to park, then wake them with the release. */
  ulong all = ((1UL<<park_cnt)-1UL)<<1;
  while( atomic_load_explicit( &park_store->cache_parked, memory_order_relaxed )!=all ) FD_SPIN_PAUSE();
  FD_TEST( !atomic_load_explicit( &park_done, memory_order_acquire ) );
  fd_store_query_release( park_store, view );

  for( ulong i=1UL; i<=park_cnt; i++ ) fd_tile_exec_delete( fd_tile_exec( i ), NULL );
  FD_TEST( atomic_load_explicit( &park_done, memory_order_acquire )==park_cnt );

  for( ulong i=1UL; i<=park_cnt; i++ ) {
    FD_TEST( park_stats[ i ].park_cnt==1UL && park_stats[ i ].park_ticks );
    FD_TEST( park_stats[ i ].spill.spilled_cnt==1UL );
  }
  FD_TEST( atomic_load_explicit( &park_store->spill_cnt, memory_order_relaxed )==park_cnt );

  /* The last inserter's FEC is cached, everything before it spilled. */
  FD_TEST( check( park_store, park_fd, &mr0, 100UL, 0UL ) );
  ulong cached = 0UL;
  for( ulong i=1UL; i<=park_cnt; i++ ) {
    fd_hash_t mr = mr_make( 2UL, i );
    cached += !check_ex( park_store, park_fd, &mr, 100UL, 100UL, 1UL, i );
  }
  FD_TEST( cached==1UL );
  check_invariants( park_store );

  close( park_fd );
  test_store_delete( park_store );
}

/* Concurrent inserts from every tile into a small cache, with the main
   thread preevicting and reading counters as rserve and replay do, then
   a race on one key: exactly one insert succeeds. */

#define CONC_INSERT_CNT (256UL)

static fd_store_t * conc_store;
static int          conc_fd;
static atomic_ulong conc_go;
static atomic_ulong conc_done;
static atomic_ulong conc_same_success;
static atomic_ulong conc_same_dup;

static int
conc_tile_insert( int     argc FD_PARAM_UNUSED,
                  char ** argv FD_PARAM_UNUSED ) {
  ulong part = fd_tile_idx();
  while( !atomic_load_explicit( &conc_go, memory_order_acquire ) ) FD_SPIN_PAUSE();
  for( ulong i=0UL; i<CONC_INSERT_CNT; i++ ) {
    fd_hash_t mr = mr_make( 1UL+part, i );
    FD_TEST( !insert_ex( conc_store, conc_fd, &mr, 1UL, part, 1000UL+i, 1000UL+i, 1UL, (part<<32)|i, NULL ) );
  }
  atomic_fetch_add_explicit( &conc_done, 1UL, memory_order_release );
  return 0;
}

static int
conc_tile_insert_same_part( int     argc FD_PARAM_UNUSED,
                            char ** argv FD_PARAM_UNUSED ) {
  ulong part = fd_tile_idx();
  while( !atomic_load_explicit( &conc_go, memory_order_acquire ) ) FD_SPIN_PAUSE();
  fd_hash_t mr = mr_make( 0xdeadbeefUL, 0UL );
  int err = insert_ex( conc_store, conc_fd, &mr, 2UL, part, 64UL, 64UL, 1UL, 77UL, NULL );
  if( !err ) atomic_fetch_add_explicit( &conc_same_success, 1UL, memory_order_relaxed );
  else {
    /* The winner may still be filling its payload on another tile. */
    FD_TEST( err==FD_STORE_ERR_DUP || err==FD_STORE_ERR_PENDING_DUP );
    atomic_fetch_add_explicit( &conc_same_dup, 1UL, memory_order_relaxed );
  }
  return 0;
}

void
test_concurrent( fd_wksp_t * wksp ) {
  ulong tile_cnt = fd_tile_cnt();
  if( FD_UNLIKELY( tile_cnt<2UL ) ) { FD_LOG_WARNING(( "skip test_concurrent: needs at least 2 tiles" )); return; }
  ulong part_cnt = fd_ulong_min( tile_cnt, 64UL );
  ulong fec_max  = part_cnt*CONC_INSERT_CNT + 16UL;

  conc_store = test_store_new( wksp, fec_max, 31840UL, 4UL, part_cnt, 16UL );
  conc_fd    = test_file_open( conc_store );
  atomic_store_explicit( &conc_go,   0UL, memory_order_relaxed );
  atomic_store_explicit( &conc_done, 0UL, memory_order_relaxed );

  for( ulong i=1UL; i<part_cnt; i++ ) FD_TEST( fd_tile_exec_new( i, conc_tile_insert, 0, NULL ) );
  atomic_store_explicit( &conc_go, 1UL, memory_order_release );

  /* Preevict and sample counters while the inserters run.  Counters
     never decrease and the gauges stay within capacity. */
  int   active     = 0;
  ulong last_spill = 0UL;
  ulong last_peak  = 0UL;
  while( atomic_load_explicit( &conc_done, memory_order_acquire )<part_cnt-1UL ) {
    fd_store_preevict( conc_store, conc_fd, &active, NULL );
    ulong spill = atomic_load_explicit( &conc_store->spill_cnt,     memory_order_relaxed );
    ulong peak  = atomic_load_explicit( &conc_store->fec_live_peak, memory_order_relaxed );
    FD_TEST( spill>=last_spill && peak>=last_peak );
    FD_TEST( atomic_load_explicit( &conc_store->fec_live_cnt,   memory_order_relaxed )<=fec_max );
    FD_TEST( atomic_load_explicit( &conc_store->cache_free_cnt, memory_order_relaxed )<=conc_store->cache_max );
    FD_TEST( atomic_load_explicit( &conc_store->disk_live_cnt,  memory_order_relaxed )<=conc_store->disk_max );
    last_spill = spill;
    last_peak  = peak;
  }
  for( ulong i=1UL; i<part_cnt; i++ ) fd_tile_exec_delete( fd_tile_exec( i ), NULL );

  ulong fec_cnt = (part_cnt-1UL)*CONC_INSERT_CNT;
  FD_TEST( live_cnt( conc_store )==fec_cnt );
  FD_TEST( atomic_load_explicit( &conc_store->fec_live_peak, memory_order_relaxed )==fec_cnt );
  check_invariants( conc_store );
  for( ulong part=1UL; part<part_cnt; part++ ) {
    for( ulong i=0UL; i<CONC_INSERT_CNT; i++ ) {
      fd_hash_t mr = mr_make( 1UL+part, i );
      check_ex( conc_store, conc_fd, &mr, 1000UL+i, 1000UL+i, 1UL, (part<<32)|i );
    }
  }
  check_invariants( conc_store );

  /* Every tile, including main, races to insert one key. */
  atomic_store_explicit( &conc_go,           0UL, memory_order_relaxed );
  atomic_store_explicit( &conc_same_success, 0UL, memory_order_relaxed );
  atomic_store_explicit( &conc_same_dup,     0UL, memory_order_relaxed );
  for( ulong i=1UL; i<part_cnt; i++ ) FD_TEST( fd_tile_exec_new( i, conc_tile_insert_same_part, 0, NULL ) );
  atomic_store_explicit( &conc_go, 1UL, memory_order_release );
  FD_TEST( !conc_tile_insert_same_part( 0, NULL ) );
  for( ulong i=1UL; i<part_cnt; i++ ) fd_tile_exec_delete( fd_tile_exec( i ), NULL );
  FD_TEST( atomic_load_explicit( &conc_same_success, memory_order_relaxed )==1UL );
  FD_TEST( atomic_load_explicit( &conc_same_dup,     memory_order_relaxed )==part_cnt-1UL );
  fd_hash_t same = mr_make( 0xdeadbeefUL, 0UL );
  check( conc_store, conc_fd, &same, 64UL, 77UL );
  check_invariants( conc_store );

  fd_store_publish( conc_store, 3UL, NULL );
  FD_TEST( !live_cnt( conc_store ) && cache_free( conc_store )==conc_store->cache_max );
  FD_TEST( !atomic_load_explicit( &conc_store->disk_live_cnt, memory_order_relaxed ) );
  check_invariants( conc_store );

  close( conc_fd );
  test_store_delete( conc_store );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_footprint();
  test_disk_index_footprint();

  int require_multitile = fd_env_strip_cmdline_contains( &argc, &argv, "--require-multitile" );
  if( FD_UNLIKELY( require_multitile && fd_tile_cnt()<2UL ) )
    FD_LOG_ERR(( "--require-multitile needs at least two tile CPUs" ));

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"              );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                     );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_new            ( wksp );
  test_basic          ( wksp );
  test_insert_errors  ( wksp );
  test_commit_expired ( wksp );
  test_key_20         ( wksp );
  test_probe_cnt      ( wksp );
  test_publish_ring   ( wksp );
  test_legacy_overflow( wksp );
  test_spill          ( wksp );
  test_preevict       ( wksp );
  test_spill_races    ( wksp );
  test_contracts      ();
  test_churn          ( wksp );
  test_park           ( wksp );
  test_concurrent     ( wksp );

  test_file_create    ( wksp );
  test_pread_all      ();
  test_fec_sets_arena ( wksp );
  test_disk_query_highest       ( wksp );
  test_disk_collision_eviction  ( wksp );
  test_disk_many_wraps          ( wksp );
  test_disk_versions            ( wksp );
  test_disk_root_offset_alias   ( wksp );
  test_disk_concurrent_writes   ( wksp );
  test_disk_slot_hint           ( wksp );
  test_disk_lazy_highest        ( wksp );
  test_disk_probe               ( wksp );
  test_disk_max_shreds_per_block( wksp );

  FD_TEST( !unlink( TEST_PAYLOAD_PATH ) || errno==ENOENT );
  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
