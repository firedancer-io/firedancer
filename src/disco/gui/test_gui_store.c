#define _GNU_SOURCE   /* pwritev (see fd_gui_store_tmpl.c) */

#include "../fd_disco.h"

#include <sys/mman.h> /* memfd_create                             */
#include <unistd.h>   /* ftruncate / close                        */

struct myrec_key {
  ulong slot;
  ulong block_id;
};
typedef struct myrec_key myrec_key_t;

#define GUI_STORE_NAME             myrec_store
#define GUI_STORE_KEY_T            myrec_key_t
#define GUI_STORE_KEY_HASH(k,seed) fd_ulong_hash( (k)->slot ^ \
                                     fd_ulong_rotate_left( (k)->block_id, 32 ) ^ (seed) )
#define GUI_STORE_KEY_EQ(k0,k1)    ( ((k0)->slot==(k1)->slot) & \
                                     ((k0)->block_id==(k1)->block_id) )
#include "fd_gui_store_tmpl.c"

#define TEST_IDX_LOAD_FACTOR   (50UL)
#define TEST_IDX_EVICT_PCT     (20UL)
#define TEST_DISK_LOAD_FACTOR  (95UL)
#define TEST_DISK_EVICT_PCT    (5UL)

/* TEST_ELE_MAX is sized generously so the index never becomes the
   binding constraint in the tier/eviction-mechanics tests below (max ~64
   distinct keys << 256).  Index slow-path (minimum-fit) eviction and
   watermark pre-eviction are exercised by their own dedicated tests,
   which size ele_max small. */
#define TEST_ELE_MAX  (256UL)
#define TEST_CIRCQ_SZ (4096UL)

#if FD_TMPL_USE_HANDHOLDING
#define VERIFY( store ) FD_TEST( !myrec_store_verify( (store) ) )
#else
#define VERIFY( store ) do { (void)(store); } while(0)
#endif

static uchar shmem [ 1UL<<20 ] __attribute__((aligned(4096UL)));
static uchar shmem2[ 1UL<<20 ] __attribute__((aligned(4096UL)));

/* fill/check writes/validates a hash derived from key+sz in buf */
static void
fill( uchar *             buf,
      myrec_key_t const * key,
      ulong               sz ) {
  for( ulong i=0UL; i<sz; i++ ) {
    buf[ i ] = (uchar)fd_ulong_hash( key->slot ^ fd_ulong_rotate_left( key->block_id, 32 ) ^ i );
  }
}

static int
check( uchar const *       buf,
       myrec_key_t const * key,
       ulong               sz ) {
  for( ulong i=0UL; i<sz; i++ ) {
    if( buf[ i ]!=(uchar)fd_ulong_hash( key->slot ^ fd_ulong_rotate_left( key->block_id, 32 ) ^ i ) ) return 0;
  }
  return 1;
}

/* tmpfile_fd creates an anonymous in-memory file. */
static int
tmpfile_fd( ulong len ) {
  int fd = memfd_create( "test_gui_store", 0U );
  FD_TEST( fd>=0 );
  FD_TEST( !ftruncate( fd, (long)len ) );
  return fd;
}

static void
test_lifecycle( void ) {
  ulong align     = myrec_store_align();
  ulong footprint = myrec_store_footprint( TEST_ELE_MAX, TEST_CIRCQ_SZ, 0UL );

  FD_TEST( align>0UL );
  FD_TEST( fd_ulong_is_pow2( align ) );
  FD_TEST( footprint>0UL );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );
  FD_TEST( footprint<=sizeof(shmem) );

  void * shstore = myrec_store_new( shmem, TEST_ELE_MAX, TEST_CIRCQ_SZ, 1234UL, 0UL, 0UL );
  FD_TEST( shstore==shmem );

  myrec_store_t * store = myrec_store_join( shstore, -1 );
  FD_TEST( store );

  VERIFY( store ); /* a freshly joined store is consistent */

  FD_TEST( myrec_store_leave( store )==(void *)store );
  FD_TEST( myrec_store_delete( shstore )==shstore );
}

static void
test_append_get_ro( void ) {
  myrec_store_t * store = myrec_store_join( myrec_store_new( shmem, TEST_ELE_MAX, TEST_CIRCQ_SZ, 7UL, 0UL, 0UL ), -1 );

  myrec_key_t keys[] = {
    { .slot = 10UL, .block_id = 0UL },
    { .slot = 11UL, .block_id = 1UL },
    { .slot = 12UL, .block_id = 2UL },
  };
  ulong szs[] = { 1UL, 17UL, 64UL };

  for( ulong i=0UL; i<3UL; i++ ) {
    uchar * v = myrec_store_append( store, &keys[ i ], 8UL, szs[ i ] );
    FD_TEST( v );
    fill( v, &keys[ i ], szs[ i ] );
  }

  VERIFY( store );

  for( ulong i=0UL; i<3UL; i++ ) {
    ulong out_sz = 0UL;
    uchar const * v = myrec_store_get_ro( store, &keys[ i ], &out_sz );
    FD_TEST( v );
    FD_TEST( out_sz==szs[ i ] );
    FD_TEST( check( v, &keys[ i ], szs[ i ] ) );
  }

  /* A key never appended is absent. */
  myrec_key_t absent = { .slot = 99UL, .block_id = 99UL };
  FD_TEST( !myrec_store_get_ro( store, &absent, NULL ) );

  VERIFY( store );

  myrec_store_leave( store );
}

static void
test_duplicate_key( void ) {
  myrec_store_t * store = myrec_store_join( myrec_store_new( shmem, TEST_ELE_MAX, TEST_CIRCQ_SZ, 2UL, 0UL, 0UL ), -1 );

  myrec_key_t key = { .slot = 5UL, .block_id = 6UL };

  uchar * v = myrec_store_append( store, &key, 8UL, 32UL );
  FD_TEST( v );
  fill( v, &key, 32UL );

  /* Duplicate append rejected. */
  FD_TEST( !myrec_store_append( store, &key, 8UL, 8UL ) );

  VERIFY( store ); /* the rejected append must not corrupt the store */

  /* Original still retrievable and unchanged. */
  ulong out_sz = 0UL;
  uchar const * got = myrec_store_get_ro( store, &key, &out_sz );
  FD_TEST( got );
  FD_TEST( out_sz==32UL );
  FD_TEST( check( got, &key, 32UL ) );

  VERIFY( store );

  myrec_store_leave( store );
}

static void
test_get_mut( void ) {
  myrec_store_t * store = myrec_store_join( myrec_store_new( shmem, TEST_ELE_MAX, TEST_CIRCQ_SZ, 8UL, 0UL, 0UL ), -1 );

  myrec_key_t key = { .slot = 13UL, .block_id = 14UL };

  uchar * v = myrec_store_append( store, &key, 8UL, 32UL );
  FD_TEST( v );
  fill( v, &key, 32UL );

  /* Initially retrievable with the appended bytes. */
  ulong sz = 0UL;
  uchar const * ro = myrec_store_get_ro( store, &key, &sz );
  FD_TEST( ro && sz==32UL && check( ro, &key, 32UL ) );

  /* Edit in place through get_mut using a different key's pattern so the
     change is unambiguous. */
  myrec_key_t alt = { .slot = 77UL, .block_id = 88UL };
  ulong msz = 0UL;
  uchar * mut = myrec_store_get_mut( store, &key, &msz );
  FD_TEST( mut && msz==32UL );
  fill( mut, &alt, 32UL );

  VERIFY( store ); /* an in-place edit leaves the store consistent */

  /* The new bytes are visible via get_ro. */
  ulong rsz = 0UL;
  uchar const * ro2 = myrec_store_get_ro( store, &key, &rsz );
  FD_TEST( ro2 && rsz==32UL );
  FD_TEST( check( ro2, &alt, 32UL ) );          /* new pattern present  */
  FD_TEST( !check( ro2, &key, 32UL ) );         /* old pattern gone     */

  VERIFY( store );

  myrec_store_leave( store );
}

static void
test_tiny_cache( void ) {
  /* Small circq so a handful of fixed-size values exceeds capacity. */
  ulong circq_sz = 1024UL;
  myrec_store_t * store = myrec_store_join( myrec_store_new( shmem, TEST_ELE_MAX, circq_sz, 5UL, 0UL, 0UL ), -1 );

  ulong const N      = 64UL;
  ulong const val_sz = 96UL; /* header (16) + pad + value (96) + circq meta */

  for( ulong i=0UL; i<N; i++ ) {
    myrec_key_t key = { .slot = 0UL, .block_id = i };
    uchar * v = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( v );
    fill( v, &key, val_sz );

    VERIFY( store ); /* invariants hold through every eviction step */

    ulong live = store->circq->cnt;
    ulong seen = 0UL;
    for( ulong j=0UL; j<=i; j++ ) {
      myrec_key_t k = { .slot = 0UL, .block_id = j };
      if( myrec_store_get_ro( store, &k, NULL ) ) seen++;
    }
    FD_TEST( seen==live );

    for( ulong j=0UL; j<=i; j++ ) {
      myrec_key_t k  = { .slot = 0UL, .block_id = j };
      ulong       sz = 0UL;
      uchar const * g = myrec_store_get_ro( store, &k, &sz );
      if( j+live > i ) { /* j in the newest `live` window */
        FD_TEST( g && sz==val_sz && check( g, &k, val_sz ) );
      } else {           /* evicted */
        FD_TEST( !g );
      }
    }
  }

  /* Eviction must have happened (otherwise the test proves nothing). */
  FD_TEST( store->circq->cnt<N );

  ulong live = store->circq->cnt;
  for( ulong i=0UL; i<N-live; i++ ) {
    myrec_key_t key = { .slot = 0UL, .block_id = i };
    FD_TEST( !myrec_store_get_ro( store, &key, NULL ) );
  }

  ulong seen = 0UL;
  for( ulong i=N-live; i<N; i++ ) {
    myrec_key_t key = { .slot = 0UL, .block_id = i };
    ulong sz = 0UL;
    uchar const * v = myrec_store_get_ro( store, &key, &sz );
    FD_TEST( v );
    FD_TEST( sz==val_sz );
    FD_TEST( check( v, &key, val_sz ) );
    seen++;
  }
  FD_TEST( seen==live );

  VERIFY( store );

  myrec_store_leave( store );
}

static void
test_oversized_append( void ) {
  ulong circq_sz = 1024UL;
  myrec_store_t * store = myrec_store_join( myrec_store_new( shmem, TEST_ELE_MAX, circq_sz, 6UL, 0UL, 0UL ), -1 );

  /* A value clearly larger than the whole circq can never fit. */
  myrec_key_t big = { .slot = 7UL, .block_id = 0UL };
  FD_TEST( !myrec_store_append( store, &big, 8UL, circq_sz*2UL ) );

  /* The rejected append must not have inserted an index slot. */
  FD_TEST( !myrec_store_get_ro( store, &big, NULL ) );

  VERIFY( store ); /* the rejected oversize append left no debris */

  /* Store remains usable: a reasonable value still appends and reads. */
  myrec_key_t ok = { .slot = 7UL, .block_id = 1UL };
  uchar * v = myrec_store_append( store, &ok, 8UL, 64UL );
  FD_TEST( v );
  fill( v, &ok, 64UL );

  ulong sz = 0UL;
  uchar const * got = myrec_store_get_ro( store, &ok, &sz );
  FD_TEST( got );
  FD_TEST( sz==64UL );
  FD_TEST( check( got, &ok, 64UL ) );

  VERIFY( store );

  myrec_store_leave( store );
}

static void
test_write_back_on_eviction( void ) {
  ulong circq_sz = 1024UL;
  ulong file_len = 1UL<<16; /* ample disk ring (no true eviction) */
  int   fd       = tmpfile_fd( file_len );

  myrec_store_t * store = myrec_store_join(
      myrec_store_new( shmem, TEST_ELE_MAX, circq_sz, 11UL, 0UL, file_len ), fd );

  ulong const N      = 40UL;
  ulong const val_sz = 96UL;

  for( ulong i=0UL; i<N; i++ ) {
    myrec_key_t key = { .slot = 1UL, .block_id = i };
    uchar * v = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( v );
    fill( v, &key, val_sz );
  }

  /* The circq cannot hold all N values, so some were evicted to disk. */
  FD_TEST( store->circq->cnt<N );

  VERIFY( store ); /* index/cache/disk-ring/superblock all consistent */

  /* Every key remains retrievable with correct bytes (RAM hits and FILE
     warms both serve correctly). */
  for( ulong i=0UL; i<N; i++ ) {
    myrec_key_t key = { .slot = 1UL, .block_id = i };
    ulong sz = 0UL;
    uchar const * v = myrec_store_get_ro( store, &key, &sz );
    FD_TEST( v );
    FD_TEST( sz==val_sz );
    FD_TEST( check( v, &key, val_sz ) );
  }

  VERIFY( store );

  myrec_store_leave( store );
  FD_TEST( !close( fd ) );
}

/* test_warm_then_edit will evict a value to FILE, get_mut it (warms
   + dirties), write new bytes, force eviction again (more appends),
   get_ro it back, assert the EDITED bytes are returned. */

static void
test_warm_then_edit( void ) {
  ulong circq_sz = 1024UL;
  ulong file_len = 1UL<<16;
  int   fd       = tmpfile_fd( file_len );

  myrec_store_t * store = myrec_store_join(
      myrec_store_new( shmem, TEST_ELE_MAX, circq_sz, 12UL, 0UL, file_len ), fd );

  ulong const val_sz = 96UL;

  myrec_key_t target = { .slot = 2UL, .block_id = 0UL };
  uchar * v = myrec_store_append( store, &target, 8UL, val_sz );
  FD_TEST( v );
  fill( v, &target, val_sz );

  /* Append more to evict target to FILE. */
  for( ulong i=1UL; i<20UL; i++ ) {
    myrec_key_t key = { .slot = 2UL, .block_id = i };
    uchar * w = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( w );
    fill( w, &key, val_sz );
  }

  /* get_mut target: warms it (clean) then marks dirty.  Edit it with a
     distinct pattern. */
  myrec_key_t alt = { .slot = 222UL, .block_id = 333UL };
  ulong msz = 0UL;
  uchar * mut = myrec_store_get_mut( store, &target, &msz );
  FD_TEST( mut && msz==val_sz );
  fill( mut, &alt, val_sz );

  VERIFY( store ); /* warmed-then-dirtied element (MEM + existing disk copy) */

  /* Force eviction again: the dirty edit must be written back. */
  for( ulong i=20UL; i<40UL; i++ ) {
    myrec_key_t key = { .slot = 2UL, .block_id = i };
    uchar * w = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( w );
    fill( w, &key, val_sz );
  }

  /* The edited bytes come back. */
  ulong rsz = 0UL;
  uchar const * ro = myrec_store_get_ro( store, &target, &rsz );
  FD_TEST( ro && rsz==val_sz );
  FD_TEST( check( ro, &alt, val_sz ) );  /* edited pattern present */
  FD_TEST( !check( ro, &target, val_sz ) );

  VERIFY( store );

  myrec_store_leave( store );
  FD_TEST( !close( fd ) );
}

/* test_clean_evict will get_ro a FILE value (warms clean), then force
   eviction; get_ro again; assert original bytes still returned (clean
   eviction did not corrupt value on disk). */

static void
test_clean_evict( void ) {
  ulong circq_sz = 1024UL;
  ulong file_len = 1UL<<16;
  int   fd       = tmpfile_fd( file_len );

  myrec_store_t * store = myrec_store_join(
      myrec_store_new( shmem, TEST_ELE_MAX, circq_sz, 13UL, 0UL, file_len ), fd );

  ulong const val_sz = 96UL;

  myrec_key_t target = { .slot = 3UL, .block_id = 0UL };
  uchar * v = myrec_store_append( store, &target, 8UL, val_sz );
  FD_TEST( v );
  fill( v, &target, val_sz );

  /* Evict target to FILE. */
  for( ulong i=1UL; i<20UL; i++ ) {
    myrec_key_t key = { .slot = 3UL, .block_id = i };
    uchar * w = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( w );
    fill( w, &key, val_sz );
  }

  /* get_ro warms it CLEAN (no dirty). */
  ulong sz = 0UL;
  uchar const * ro = myrec_store_get_ro( store, &target, &sz );
  FD_TEST( ro && sz==val_sz && check( ro, &target, val_sz ) );

  VERIFY( store ); /* warmed-clean element (MEM, dirty==0, has_disk==1) */

  /* Force eviction again: a CLEAN eviction must NOT rewrite; it demotes
     to the existing disk record. */
  for( ulong i=20UL; i<40UL; i++ ) {
    myrec_key_t key = { .slot = 3UL, .block_id = i };
    uchar * w = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( w );
    fill( w, &key, val_sz );
  }

  /* Original bytes still come back. */
  ulong rsz = 0UL;
  uchar const * ro2 = myrec_store_get_ro( store, &target, &rsz );
  FD_TEST( ro2 && rsz==val_sz && check( ro2, &target, val_sz ) );

  VERIFY( store );

  myrec_store_leave( store );
  FD_TEST( !close( fd ) );
}

/* test_warm_cascade warms a FILE value triggering eviction/write-back
   of other dirty RAM values; all involved keys should remain
   retrievable with correct bytes. */

static void
test_warm_cascade( void ) {
  ulong circq_sz = 1024UL;
  ulong file_len = 1UL<<16;
  int   fd       = tmpfile_fd( file_len );

  myrec_store_t * store = myrec_store_join(
      myrec_store_new( shmem, TEST_ELE_MAX, circq_sz, 14UL, 0UL, file_len ), fd );

  ulong const N      = 50UL;
  ulong const val_sz = 96UL;

  /* Many dirty appends.  Some live in the circq, the rest on disk. */
  for( ulong i=0UL; i<N; i++ ) {
    myrec_key_t key = { .slot = 4UL, .block_id = i };
    uchar * v = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( v );
    fill( v, &key, val_sz );
  }

  VERIFY( store );

  /* Interleave warms of old (FILE) keys with the resident set so each
     warm push_back evicts and writes back currently-dirty RAM entries.
     Every key must remain correct throughout. */
  for( ulong pass=0UL; pass<3UL; pass++ ) {
    for( ulong i=0UL; i<N; i++ ) {
      myrec_key_t key = { .slot = 4UL, .block_id = i };
      ulong sz = 0UL;
      uchar const * v = myrec_store_get_ro( store, &key, &sz );
      FD_TEST( v );
      FD_TEST( sz==val_sz );
      FD_TEST( check( v, &key, val_sz ) );
    }
    VERIFY( store ); /* re-entrant warm/write-back cascades stay consistent */
  }

  myrec_store_leave( store );
  FD_TEST( !close( fd ) );
}

static void
test_disk_ring_drop( void ) {
  ulong circq_sz = 1024UL;
  ulong val_sz   = 96UL;

  /* Disk ring sized to the precondition minimum (superblock + room for
     one max record).  The internal superblock / record-header sizes are
     private, so use a conservative upper bound here: the key is 16 bytes
     so the record header is at most 64 bytes and the superblock is at
     most 256 bytes.  This gives a small data region (>= circq_sz) that a
     long run of distinct appends wraps over its own live records,
     forcing true eviction. */
  ulong file_len = 256UL + 64UL + fd_ulong_align_up( circq_sz, 8UL );
  int   fd       = tmpfile_fd( file_len );

  myrec_store_t * store = myrec_store_join(
      myrec_store_new( shmem, TEST_ELE_MAX, circq_sz, 15UL, 0UL, file_len ), fd );

  ulong const N = 40UL;
  for( ulong i=0UL; i<N; i++ ) {
    myrec_key_t key = { .slot = 5UL, .block_id = i };
    uchar * v = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( v );
    fill( v, &key, val_sz );
  }

  VERIFY( store ); /* ring wrapped + true-evicted oldest records */

  /* Census: count how many of the N keys are still live, and verify the
     ones that survive read back correctly.  Because the disk ring (plus
     the circq) cannot hold all N, the oldest keys must have been truly
     evicted (slot removed).  We scan newest-first so reads do not
     themselves disturb the survivors via warm cascades before we have
     observed them.

     A surviving set must be a contiguous suffix: once a key reads NULL,
     every older key must also be NULL (the disk ring evicts strictly
     oldest-first). */
  ulong live    = 0UL;
  int   saw_gap = 0;
  for( ulong ii=0UL; ii<N; ii++ ) {
    ulong i = N-1UL-ii;
    myrec_key_t key = { .slot = 5UL, .block_id = i };
    ulong sz = 0UL;
    uchar const * v = myrec_store_get_ro( store, &key, &sz );
    if( v ) {
      FD_TEST( !saw_gap ); /* survivors form a contiguous newest suffix */
      FD_TEST( sz==val_sz && check( v, &key, val_sz ) );
      live++;
    } else {
      saw_gap = 1;
    }
  }

  /* True eviction happened (not all N retained) and the oldest is gone. */
  FD_TEST( live<N );
  FD_TEST( saw_gap );
  {
    myrec_key_t oldest = { .slot = 5UL, .block_id = 0UL };
    FD_TEST( !myrec_store_get_ro( store, &oldest, NULL ) );
  }

  VERIFY( store );

  myrec_store_leave( store );
  FD_TEST( !close( fd ) );
}

/* test_multi_store_one_file tests two file-enabled stores on disjoint
   [base,len) regions of one fd; interleave appends / evictions; assert
   isolation (each returns only its own correct values). */

static void
test_multi_store_one_file( void ) {
  ulong circq_sz = 1024UL;
  ulong val_sz   = 96UL;
  ulong region   = 1UL<<16;
  ulong file_len = region*2UL;
  int   fd       = tmpfile_fd( file_len );

  myrec_store_t * sa = myrec_store_join(
      myrec_store_new( shmem,  TEST_ELE_MAX, circq_sz, 16UL, 0UL,    region ), fd );
  myrec_store_t * sb = myrec_store_join(
      myrec_store_new( shmem2, TEST_ELE_MAX, circq_sz, 17UL, region, region ), fd );

  ulong const N = 40UL;

  /* Store A uses slot 6, store B uses slot 7 (distinct key spaces). */
  for( ulong i=0UL; i<N; i++ ) {
    myrec_key_t ka = { .slot = 6UL, .block_id = i };
    myrec_key_t kb = { .slot = 7UL, .block_id = i };
    uchar * a = myrec_store_append( sa, &ka, 8UL, val_sz ); FD_TEST( a ); fill( a, &ka, val_sz );
    uchar * b = myrec_store_append( sb, &kb, 8UL, val_sz ); FD_TEST( b ); fill( b, &kb, val_sz );
  }

  VERIFY( sa );
  VERIFY( sb ); /* store B lives at a non-zero file_base_off */

  /* Each store serves only its own keys with correct bytes, and never
     the other store's keys. */
  for( ulong i=0UL; i<N; i++ ) {
    myrec_key_t ka = { .slot = 6UL, .block_id = i };
    myrec_key_t kb = { .slot = 7UL, .block_id = i };

    ulong sz = 0UL;
    uchar const * a = myrec_store_get_ro( sa, &ka, &sz );
    FD_TEST( a && sz==val_sz && check( a, &ka, val_sz ) );
    /* Store A must not know store B's key. */
    FD_TEST( !myrec_store_get_ro( sa, &kb, NULL ) );

    sz = 0UL;
    uchar const * b = myrec_store_get_ro( sb, &kb, &sz );
    FD_TEST( b && sz==val_sz && check( b, &kb, val_sz ) );
    FD_TEST( !myrec_store_get_ro( sb, &ka, NULL ) );
  }

  VERIFY( sa );
  VERIFY( sb );

  myrec_store_leave( sa );
  myrec_store_leave( sb );
  FD_TEST( !close( fd ) );
}

static void
test_eviction_idx( void ) {
  ulong ele_max  = 16UL;
  ulong circq_sz = 64UL*1024UL;   /* ample: never the binding constraint */

  myrec_store_t * store = myrec_store_join(
      myrec_store_new( shmem, ele_max, circq_sz, 21UL, 0UL, 0UL ), -1 );

  ulong const N      = 200UL;
  ulong const val_sz = 24UL;

  for( ulong i=0UL; i<N; i++ ) {
    myrec_key_t key = { .slot = 9UL, .block_id = i };
    uchar * v = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( v );                        /* never wedges */
    fill( v, &key, val_sz );
    FD_TEST( store->live_cnt<=ele_max ); /* index capacity respected */
    VERIFY( store );                     /* index slow-path drop is consistent */
  }

  /* Survivors form a contiguous newest suffix; older keys were dropped. */
  ulong live    = 0UL;
  int   saw_gap = 0;
  for( ulong ii=0UL; ii<N; ii++ ) {
    ulong i = N-1UL-ii;
    myrec_key_t key = { .slot = 9UL, .block_id = i };
    ulong sz = 0UL;
    uchar const * v = myrec_store_get_ro( store, &key, &sz );
    if( v ) {
      FD_TEST( !saw_gap );
      FD_TEST( sz==val_sz && check( v, &key, val_sz ) );
      live++;
    } else {
      saw_gap = 1;
    }
  }

  FD_TEST( live<=ele_max );
  FD_TEST( live>=1UL );
  FD_TEST( saw_gap );   /* oldest keys were truly evicted */

  VERIFY( store );

  myrec_store_leave( store );
}

static void
test_pre_evict_idx( void ) {
  ulong ele_max  = 16UL;
  ulong circq_sz = 64UL*1024UL;
  ulong hi       = (ele_max*TEST_IDX_LOAD_FACTOR)/100UL;
  ulong lo       = hi-(ele_max*TEST_IDX_EVICT_PCT)/100UL;

  myrec_store_t * store = myrec_store_join(
      myrec_store_new( shmem, ele_max, circq_sz, 24UL, 0UL, 0UL ), -1 );

  ulong const val_sz = 24UL;
  for( ulong i=0UL; i<ele_max; i++ ) {
    myrec_key_t key = { .slot = 9UL, .block_id = i };
    uchar * v = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( v );
    fill( v, &key, val_sz );
  }
  FD_TEST( store->live_cnt==ele_max );

  VERIFY( store ); /* index full */

  myrec_store_pre_evict( store );

  FD_TEST( store->live_cnt>=lo && store->live_cnt<=hi );

  VERIFY( store ); /* index drained to its low watermark */

  /* The newest lo keys must still be live and correct. */
  for( ulong k=0UL; k<store->live_cnt; k++ ) {
    ulong i = ele_max-1UL-k;
    myrec_key_t key = { .slot = 9UL, .block_id = i };
    ulong sz = 0UL;
    uchar const * v = myrec_store_get_ro( store, &key, &sz );
    FD_TEST( v && sz==val_sz && check( v, &key, val_sz ) );
  }

  VERIFY( store );

  myrec_store_leave( store );
}

static void
test_pre_evict_disk( void ) {
  ulong ele_max  = 256UL;        /* big: index never the binding constraint */
  ulong circq_sz = 1024UL;       /* small: forces demotion to disk          */
  ulong file_len = 1UL<<14;      /* modest disk ring so it fills             */
  int   fd       = tmpfile_fd( file_len );

  ulong data_sz = file_len - 64UL; /* SUPERBLOCK_SZ is private; 64 is exact  */
  ulong hi      = (data_sz*TEST_DISK_LOAD_FACTOR)/100UL;

  myrec_store_t * store = myrec_store_join(
      myrec_store_new( shmem, ele_max, circq_sz, 25UL, 0UL, file_len ), fd );

  ulong const N      = 120UL;
  ulong const val_sz = 96UL;
  for( ulong i=0UL; i<N; i++ ) {
    myrec_key_t key = { .slot = 3UL, .block_id = i };
    uchar * v = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( v );
    fill( v, &key, val_sz );
  }

  VERIFY( store );

  /* Drive cache->disk demotion so the disk ring is loaded, then drain. */
  myrec_store_pre_evict( store );
  FD_TEST( store->fbytes<=hi ); /* disk drained to/below its high watermark */

  VERIFY( store ); /* disk ring drained to its low watermark */

  /* Survivors (whatever remains) read back correctly and form a newest
     suffix. */
  int saw_gap = 0;
  for( ulong ii=0UL; ii<N; ii++ ) {
    ulong i = N-1UL-ii;
    myrec_key_t key = { .slot = 3UL, .block_id = i };
    ulong sz = 0UL;
    uchar const * v = myrec_store_get_ro( store, &key, &sz );
    if( v ) {
      FD_TEST( !saw_gap );
      FD_TEST( sz==val_sz && check( v, &key, val_sz ) );
    } else {
      saw_gap = 1;
    }
  }

  VERIFY( store );

  myrec_store_leave( store );
  FD_TEST( !close( fd ) );
}

static void
test_tiny_idx( void ) {
  ulong ele_max  = 1UL;
  ulong circq_sz = 64UL*1024UL;

  myrec_store_t * store = myrec_store_join(
      myrec_store_new( shmem, ele_max, circq_sz, 23UL, 0UL, 0UL ), -1 );

  ulong const val_sz = 8UL;
  for( ulong i=0UL; i<32UL; i++ ) {
    myrec_key_t key = { .slot = 1UL, .block_id = i };
    uchar * v = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( v );                        /* append must never wedge */
    fill( v, &key, val_sz );
    FD_TEST( store->live_cnt<=ele_max ); /* capacity respected */
    VERIFY( store );                     /* capacity-1 evict-then-insert is consistent */
  }

  /* Only the newest key can be live in a capacity-1 store. */
  myrec_key_t newest = { .slot = 1UL, .block_id = 31UL };
  ulong sz = 0UL;
  uchar const * v = myrec_store_get_ro( store, &newest, &sz );
  FD_TEST( v && sz==val_sz && check( v, &newest, val_sz ) );

  VERIFY( store );

  myrec_store_leave( store );
}

static void
test_disk_writeback_wrap( void ) {
  ulong const val_szs[] = { 32UL, 96UL, 17UL, 200UL, 64UL, 9UL, 128UL, 48UL };
  ulong const n_szs     = sizeof(val_szs)/sizeof(val_szs[0]);

  /* ---- Case A: no wrap.  One big contiguous demotion run. ---- */
  {
    ulong circq_sz = 1024UL;     /* small: forces demotion to disk        */
    ulong file_len = 1UL<<16;    /* ample: the demotion run never wraps   */
    int   fd       = tmpfile_fd( file_len );

    myrec_store_t * store = myrec_store_join(
        myrec_store_new( shmem, 256UL, circq_sz, 31UL, 0UL, file_len ), fd );

    ulong const N = 60UL;
    for( ulong i=0UL; i<N; i++ ) {
      ulong       sz  = val_szs[ i % n_szs ];
      myrec_key_t key = { .slot = 6UL, .block_id = i };
      uchar * v = myrec_store_append( store, &key, 8UL, sz );
      FD_TEST( v );
      fill( v, &key, sz );
    }

    VERIFY( store );

    /* Demote the resident cache to disk in one shot. */
    myrec_store_pre_evict( store );
    FD_TEST( store->fcnt>1UL ); /* a real multi-record run was written back */

    VERIFY( store ); /* coalesced multi-record write-back is consistent */

    /* Every survivor reads back with its own (size-specific) bytes. */
    int saw_gap = 0;
    for( ulong ii=0UL; ii<N; ii++ ) {
      ulong i  = N-1UL-ii;
      ulong sz = val_szs[ i % n_szs ];
      myrec_key_t key = { .slot = 6UL, .block_id = i };
      ulong out_sz = 0UL;
      uchar const * v = myrec_store_get_ro( store, &key, &out_sz );
      if( v ) {
        FD_TEST( !saw_gap );
        FD_TEST( out_sz==sz && check( v, &key, sz ) );
      } else {
        saw_gap = 1;
      }
    }

    VERIFY( store );

    myrec_store_leave( store );
    FD_TEST( !close( fd ) );
  }

  /* ---- Case B: ring wraps + drops mid-demotion, forcing a
     discontinuity flush in the middle of a batch. ---- */
  {
    ulong circq_sz = 1024UL;
    ulong val_sz   = 96UL;
    ulong file_len = 256UL + 64UL + fd_ulong_align_up( 4UL*circq_sz, 8UL );
    int   fd       = tmpfile_fd( file_len );

    myrec_store_t * store = myrec_store_join(
        myrec_store_new( shmem, 256UL, circq_sz, 32UL, 0UL, file_len ), fd );

    ulong const N = 120UL;
    for( ulong i=0UL; i<N; i++ ) {
      myrec_key_t key = { .slot = 7UL, .block_id = i };
      uchar * v = myrec_store_append( store, &key, 8UL, val_sz );
      FD_TEST( v );
      fill( v, &key, val_sz );
      myrec_store_pre_evict( store ); /* keep the disk ring churning/wrapping */
      VERIFY( store ); /* split-pwritev write-back across a ring wrap is consistent */
    }

    /* Drop must have occurred (ring too small for all N) and
       survivors form a newest-suffix that reads back correctly. */
    int   saw_gap = 0;
    ulong live    = 0UL;
    for( ulong ii=0UL; ii<N; ii++ ) {
      ulong i = N-1UL-ii;
      myrec_key_t key = { .slot = 7UL, .block_id = i };
      ulong sz = 0UL;
      uchar const * v = myrec_store_get_ro( store, &key, &sz );
      if( v ) {
        FD_TEST( !saw_gap );
        FD_TEST( sz==val_sz && check( v, &key, val_sz ) );
        live++;
      } else {
        saw_gap = 1;
      }
    }
    FD_TEST( live<N );
    FD_TEST( saw_gap );

    VERIFY( store );

    myrec_store_leave( store );
    FD_TEST( !close( fd ) );
  }
}

/* Direct unit test of the partial-write bookkeeping (iov_advance).  A
   regular file never short-writes a pwritev, so this branch is otherwise
   never exercised; drive it explicitly with crafted byte counts that
   land on iovec boundaries, mid-iovec, span several iovecs, and consume
   nothing / everything. */

static void
test_iov_advance( void ) {
  uchar a[ 10 ], b[ 20 ], c[ 30 ];

  /* Helper to (re)build a fresh 3-iovec array each case. */
# define RESET() do {                                  \
    iov[ 0 ].iov_base = a; iov[ 0 ].iov_len = 10UL;     \
    iov[ 1 ].iov_base = b; iov[ 1 ].iov_len = 20UL;     \
    iov[ 2 ].iov_base = c; iov[ 2 ].iov_len = 30UL;     \
  } while(0)
  struct iovec iov[ 3 ];

  /* Consume 0 bytes: nothing moves. */
  RESET();
  { int i = 0; myrec_store_iov_advance( iov, 3, &i, 0UL );
    FD_TEST( i==0 );
    FD_TEST( iov[ 0 ].iov_base==a && iov[ 0 ].iov_len==10UL ); }

  /* Consume exactly the first iovec: advance to index 1, untouched len. */
  RESET();
  { int i = 0; myrec_store_iov_advance( iov, 3, &i, 10UL );
    FD_TEST( i==1 );
    FD_TEST( iov[ 1 ].iov_base==b && iov[ 1 ].iov_len==20UL ); }

  /* Consume part of the first iovec: stay at 0, trimmed base/len. */
  RESET();
  { int i = 0; myrec_store_iov_advance( iov, 3, &i, 4UL );
    FD_TEST( i==0 );
    FD_TEST( iov[ 0 ].iov_base==a+4 && iov[ 0 ].iov_len==6UL ); }

  /* Span the first iovec and part of the second. */
  RESET();
  { int i = 0; myrec_store_iov_advance( iov, 3, &i, 15UL ); /* 10 + 5 */
    FD_TEST( i==1 );
    FD_TEST( iov[ 1 ].iov_base==b+5 && iov[ 1 ].iov_len==15UL ); }

  /* Span the first two iovecs exactly, leaving the third intact. */
  RESET();
  { int i = 0; myrec_store_iov_advance( iov, 3, &i, 30UL ); /* 10 + 20 */
    FD_TEST( i==2 );
    FD_TEST( iov[ 2 ].iov_base==c && iov[ 2 ].iov_len==30UL ); }

  /* Resume from a mid-array index (simulates a second short write after a
     first one already advanced i to 1 and trimmed iov[1]). */
  RESET();
  iov[ 1 ].iov_base = b+5; iov[ 1 ].iov_len = 15UL;
  { int i = 1; myrec_store_iov_advance( iov, 3, &i, 15UL ); /* finish iov[1] */
    FD_TEST( i==2 );
    FD_TEST( iov[ 2 ].iov_base==c && iov[ 2 ].iov_len==30UL ); }

  /* Consume everything remaining: index walks off the end. */
  RESET();
  { int i = 0; myrec_store_iov_advance( iov, 3, &i, 60UL ); /* 10 + 20 + 30 */
    FD_TEST( i==3 ); }

# undef RESET
}

static void
test_over_aligned_append( void ) {
  myrec_store_t * store = myrec_store_join( myrec_store_new( shmem, TEST_ELE_MAX, TEST_CIRCQ_SZ, 99UL, 0UL, 0UL ), -1 );

  ulong const aligns[] = { 16UL, 32UL, 64UL };
  for( ulong i=0UL; i<sizeof(aligns)/sizeof(aligns[0]); i++ ) {
    ulong       align = aligns[ i ];
    myrec_key_t key   = { .slot = 70UL, .block_id = align };
    ulong       sz    = 48UL;

    uchar * v = myrec_store_append( store, &key, align, sz );
    FD_TEST( v );
    FD_TEST( fd_ulong_is_aligned( (ulong)v, align ) );
    fill( v, &key, sz );

    ulong         got_sz = 0UL;
    uchar const * g      = myrec_store_get_ro( store, &key, &got_sz );
    FD_TEST( g );
    FD_TEST( fd_ulong_is_aligned( (ulong)g, align ) );
    FD_TEST( got_sz==sz );
    FD_TEST( check( g, &key, sz ) );
  }

  VERIFY( store );

  myrec_store_leave( store );
}

/* test_append_past_orphan test a full map whose oldest cache message
   is a stale orphan. append() must keep evicting until a live slot is
   actually reclaimed. */
static void
test_append_past_orphan( void ) {
  ulong ele_max  = 4UL;        /* power of two: map capacity is exactly this */
  ulong circq_sz = 4096UL;     /* ample: holds every message in this test */
  ulong val_sz   = 16UL;
  ulong file_len = 1UL<<16;    /* file-backed, but we keep the disk ring empty */
  int   fd       = tmpfile_fd( file_len );

  myrec_store_t * store = myrec_store_join(
      myrec_store_new( shmem, ele_max, circq_sz, 24UL, 0UL, file_len ), fd );

  /* 1) Append the soon-to-be orphan; it is the oldest cache message. */
  myrec_key_t orphan = { .slot = 9UL, .block_id = 0UL };
  uchar * vo = myrec_store_append( store, &orphan, 8UL, val_sz );
  FD_TEST( vo ); fill( vo, &orphan, val_sz );

  /* Turn it into a stale orphan: drop the index entry directly, leaving
     its cache message behind with no live element to match.  fcnt stays
     0 (nothing was demoted to disk). */
  myrec_store_ele_t * oe = myrec_store_map_update( store->map, &orphan );
  FD_TEST( oe );
  myrec_store_map_remove( store->map, oe );
  store->live_cnt--;
  FD_TEST( store->fcnt==0UL );
  FD_TEST( !myrec_store_get_ro( store, &orphan, NULL ) ); /* gone from index */

  /* 2) Append live MEM keys (each newer than the orphan in the cache)
     until the map saturates and the next insert must evict to seat the
     key -- i.e. live_cnt stops growing.  Every append must succeed: the
     orphan sits at the cache head, so the index slow path is forced to
     skip past it and reclaim a live slot.  We stop the moment a slot is
     recycled, which is exactly the wedge-prone case the report
     describes (full map, fcnt==0, oldest cache message is the orphan). */
  ulong i        = 0UL;
  int   recycled = 0;
  for( ; i<64UL; i++ ) {
    myrec_key_t key = { .slot = 9UL, .block_id = 100UL+i };
    ulong before = store->live_cnt;

    uchar * v = myrec_store_append( store, &key, 8UL, val_sz );
    FD_TEST( v ); /* before the fix this wedged and returned NULL */
    fill( v, &key, val_sz );

    FD_TEST( store->live_cnt<=ele_max );
    VERIFY( store );

    if( store->live_cnt==before ) { recycled = 1; break; } /* slow path reclaimed a slot */
  }
  FD_TEST( recycled ); /* the saturating append really exercised the slow path */

  /* The just-appended key reads back correctly. */
  myrec_key_t last = { .slot = 9UL, .block_id = 100UL+i };
  ulong sz = 0UL;
  uchar const * g = myrec_store_get_ro( store, &last, &sz );
  FD_TEST( g && sz==val_sz && check( g, &last, val_sz ) );

  VERIFY( store );

  myrec_store_leave( store );
  FD_TEST( !close( fd ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_lifecycle();              FD_LOG_NOTICE(( "pass: lifecycle"              ));
  test_append_get_ro();          FD_LOG_NOTICE(( "pass: append_get_ro"          ));
  test_duplicate_key();          FD_LOG_NOTICE(( "pass: duplicate_key"          ));
  test_get_mut();                FD_LOG_NOTICE(( "pass: get_mut"                ));
  test_tiny_cache();             FD_LOG_NOTICE(( "pass: tiny_cache"             ));
  test_oversized_append();       FD_LOG_NOTICE(( "pass: oversized_append"       ));
  test_over_aligned_append();    FD_LOG_NOTICE(( "pass: over_aligned_append"    ));

  test_write_back_on_eviction(); FD_LOG_NOTICE(( "pass: write_back_on_eviction" ));
  test_warm_then_edit();         FD_LOG_NOTICE(( "pass: warm_then_edit"         ));
  test_clean_evict();            FD_LOG_NOTICE(( "pass: clean_evict"            ));
  test_warm_cascade();           FD_LOG_NOTICE(( "pass: warm_cascade"           ));
  test_disk_ring_drop();         FD_LOG_NOTICE(( "pass: disk_ring_drop"         ));
  test_disk_writeback_wrap();    FD_LOG_NOTICE(( "pass: disk_writeback_wrap"    ));
  test_multi_store_one_file();   FD_LOG_NOTICE(( "pass: multi_store_one_file"   ));

  test_eviction_idx();           FD_LOG_NOTICE(( "pass: eviction_idx"           ));
  test_pre_evict_idx();          FD_LOG_NOTICE(( "pass: pre_evict_idx"          ));
  test_pre_evict_disk();         FD_LOG_NOTICE(( "pass: pre_evict_disk"         ));
  test_tiny_idx();               FD_LOG_NOTICE(( "pass: tiny_idx"               ));
  test_append_past_orphan();     FD_LOG_NOTICE(( "pass: append_past_orphan"     ));
  test_iov_advance();            FD_LOG_NOTICE(( "pass: iov_advance"            ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
