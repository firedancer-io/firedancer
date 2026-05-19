#include "../../util/fd_util.h"
#include "fd_shredb.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_FILE "/tmp/test_shredb.bin"
#define TEST_SEED 42UL

static fd_shred_t *
make_shred( uchar buf[ FD_SHRED_MAX_SZ ],
            ulong slot,
            uint  idx,
            uchar const * payload,
            ulong         payload_sz ) {
  memset( buf, 0, FD_SHRED_MAX_SZ );
  fd_shred_t * shred = (fd_shred_t *)buf;
  shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
  shred->slot      = slot;
  shred->idx       = idx;
  shred->data.size = (ushort)(FD_SHRED_DATA_HEADER_SZ + payload_sz);
  if( payload_sz ) memcpy( buf + FD_SHRED_DATA_HEADER_SZ, payload, payload_sz );
  return shred;
}

static inline void
fill_payload( uchar * payload,
              ulong   payload_sz,
              ulong   slot,
              uint    idx ) {
  for( ulong i=0; i<payload_sz; i++ ) {
    payload[i] = (uchar)( (slot*31UL + (ulong)idx*17UL + i) & 0xFFUL );
  }
}

static fd_shredb_t *
setup_store( void ** out_mem, ulong max_size_gib ) {
  ulong footprint = fd_shredb_footprint( max_size_gib );
  FD_TEST( footprint );
  void * mem = aligned_alloc( fd_shredb_align(), footprint );
  FD_TEST( mem );
  fd_memset( mem, 0, footprint );

  void * shmem = fd_shredb_new( mem, max_size_gib, TEST_FILE, TEST_SEED );
  FD_TEST( shmem );

  fd_shredb_t * store = fd_shredb_join( shmem );
  FD_TEST( store );

  *out_mem = mem;
  return store;
}

static void
teardown_store( fd_shredb_t * store, void * mem ) {
  fd_shredb_leave( store );
  fd_shredb_delete( mem );
  free( mem );
  unlink( TEST_FILE );
}

static void
insert_shred( fd_shredb_t * store,
              ulong         slot,
              uint          idx,
              uchar const * payload,
              ulong         payload_sz ) {
  uchar buf[ FD_SHRED_MAX_SZ ];
  fd_shred_t * shred = make_shred( buf, slot, idx, payload, payload_sz );
  fd_shredb_insert( store, shred, fd_shred_sz( shred ) );
}

/* For eviction tests we create a store and then shrink max_shreds. */
static fd_shredb_t *
setup_small_store( void ** out_mem, ulong max_shreds ) {
  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );
  store->max_shreds  = max_shreds;
  store->file_shreds = max_shreds;
  *out_mem = mem;
  return store;
}

static void
test_key_pack( void ) {
  FD_LOG_NOTICE(( "TEST key pack/unpack" ));

  ulong slot = 12345UL;
  uint  idx  = 678U;
  ulong key  = fd_shredb_key_pack( slot, idx );
  FD_TEST( fd_shredb_key_slot( key )==slot );
  FD_TEST( fd_shredb_key_shred_idx( key )==idx );

  key = fd_shredb_key_pack( 0UL, 0U );
  FD_TEST( fd_shredb_key_slot( key )==0UL );
  FD_TEST( fd_shredb_key_shred_idx( key )==0U );

  key = fd_shredb_key_pack( 1UL, 65535U );
  FD_TEST( fd_shredb_key_slot( key )==1UL );
  FD_TEST( fd_shredb_key_shred_idx( key )==65535U );

  ulong big_slot = (1UL<<48)-1UL;
  key = fd_shredb_key_pack( big_slot, 100U );
  FD_TEST( fd_shredb_key_slot( key )==big_slot );
  FD_TEST( fd_shredb_key_shred_idx( key )==100U );

  /* idx truncation to 16 bits */
  key = fd_shredb_key_pack( 5UL, 0x10001U );
  FD_TEST( fd_shredb_key_shred_idx( key )==1U );
}

static void
test_footprint( void ) {
  FD_LOG_NOTICE(( "TEST footprint" ));

  FD_TEST( fd_shredb_footprint( 0UL )==0UL );
  FD_TEST( fd_shredb_footprint( 1UL )>0UL );
  FD_TEST( fd_shredb_footprint( 2UL )>fd_shredb_footprint( 1UL ) );
}

static void
test_lifecycle( void ) {
  FD_LOG_NOTICE(( "TEST lifecycle (new/join/leave/delete)" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  FD_TEST( store->max_shreds > 0UL );
  FD_TEST( store->write_head == 0UL );
  FD_TEST( store->cnt == 0UL );

  teardown_store( store, mem );
}

static void
test_query_nonexistent( void ) {
  FD_LOG_NOTICE(( "TEST query nonexistent shred" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  uchar out[ FD_SHRED_MAX_SZ ];
  FD_TEST( fd_shredb_query( store, 1UL, 0U, out )==-1 );
  FD_TEST( fd_shredb_query( store, 0UL, 0U, out )==-1 );

  uchar payload[16];
  fill_payload( payload, sizeof(payload), 10UL, 0U );
  insert_shred( store, 10UL, 0U, payload, sizeof(payload) );

  FD_TEST( fd_shredb_query( store, 10UL, 1U, out )==-1 );
  FD_TEST( fd_shredb_query( store, 11UL, 0U, out )==-1 );

  teardown_store( store, mem );
}

static void
test_multiple_shreds_same_slot( void ) {
  FD_LOG_NOTICE(( "TEST multiple shreds in the same slot" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  ulong slot = 200UL;
  ulong payload_sz = 32UL;
  uchar payload[ FD_SHRED_DATA_PAYLOAD_MAX ];

  for( uint i=0; i<32; i++ ) {
    fill_payload( payload, payload_sz, slot, i );
    insert_shred( store, slot, i, payload, payload_sz );
  }

  FD_TEST( store->cnt==32UL );

  uchar out[ FD_SHRED_MAX_SZ ];
  for( uint i=0; i<32; i++ ) {
    fill_payload( payload, payload_sz, slot, i );
    int ret = fd_shredb_query( store, slot, i, out );
    FD_TEST( ret>0 );
    FD_TEST( (ulong)ret==(payload_sz + FD_SHRED_DATA_HEADER_SZ) );
    FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, payload_sz )==0 );
  }

  teardown_store( store, mem );
}

static void
test_multiple_slots( void ) {
  FD_LOG_NOTICE(( "TEST multiple slots" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  ulong payload_sz = 20UL;
  uchar payload[ FD_SHRED_DATA_PAYLOAD_MAX ];

  for( ulong s=0; s<10; s++ ) {
    for( uint i=0; i<4; i++ ) {
      fill_payload( payload, payload_sz, s, i );
      insert_shred( store, s, i, payload, payload_sz );
    }
  }

  FD_TEST( store->cnt==40UL );

  uchar out[ FD_SHRED_MAX_SZ ];
  for( ulong s=0; s<10; s++ ) {
    for( uint i=0; i<4; i++ ) {
      fill_payload( payload, payload_sz, s, i );
      int ret = fd_shredb_query( store, s, i, out );
      FD_TEST( ret>0 );
      FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, payload_sz )==0 );
    }
  }

  teardown_store( store, mem );
}

static void
test_many_wraps( void ) {
  FD_LOG_NOTICE(( "TEST many ring wraps" ));

  void * mem;
  ulong cap = 16UL;
  fd_shredb_t * store = setup_small_store( &mem, cap );

  uchar payload[16];
  uchar out[ FD_SHRED_MAX_SZ ];

  ulong total = cap * 10;
  for( ulong i=0; i<total; i++ ) {
    ulong slot = i / 4;
    uint  idx  = (uint)(i % 4);
    fill_payload( payload, sizeof(payload), slot, idx );
    insert_shred( store, slot, idx, payload, sizeof(payload) );
  }

  FD_TEST( store->cnt==cap );

  ulong first_surviving = total - cap;
  for( ulong i=first_surviving; i<total; i++ ) {
    ulong slot = i / 4;
    uint  idx  = (uint)(i % 4);
    fill_payload( payload, sizeof(payload), slot, idx );
    int ret = fd_shredb_query( store, slot, idx, out );
    FD_TEST( ret>0 );
    FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, sizeof(payload) )==0 );
  }

  ulong gone = first_surviving - 1;
  FD_TEST( fd_shredb_query( store, gone/4, (uint)(gone%4), out )==-1 );

  teardown_store( store, mem );
}

static void
bench_insert( void ) {
  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  uchar payload[64];
  memset( payload, 0xAA, sizeof(payload) );

  ulong n = 1000000UL;

  uchar buf[ FD_SHRED_MAX_SZ ];

  long t0 = fd_log_wallclock();
  for( ulong i=0; i<n; i++ ) {
    ulong slot = i / 32;
    uint  idx  = (uint)(i % 32);
    fd_shred_t * shred = make_shred( buf, slot, idx, payload, sizeof(payload) );
    fd_shredb_insert( store, shred, fd_shred_sz( shred ) );
  }
  long t1 = fd_log_wallclock();

  double ns_per = (double)(t1 - t0) / (double)n;
  FD_LOG_NOTICE(( "BENCH insert: %.1f ns/op (%lu ops)", ns_per, n ));

  teardown_store( store, mem );
}

static void
bench_query_hit( void ) {
  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  uchar payload[64];
  memset( payload, 0xBB, sizeof(payload) );
  ulong n = 10000UL;

  for( ulong i=0; i<n; i++ ) {
    ulong slot = i / 32;
    uint  idx  = (uint)(i % 32);
    insert_shred( store, slot, idx, payload, sizeof(payload) );
  }

  uchar out[ FD_SHRED_MAX_SZ ];
  long t0 = fd_log_wallclock();
  for( ulong i=0; i<n; i++ ) {
    ulong slot = i / 32;
    uint  idx  = (uint)(i % 32);
    FD_TEST( fd_shredb_query( store, slot, idx, out )>0 );
  }
  long t1 = fd_log_wallclock();

  double ns_per = (double)(t1 - t0) / (double)n;
  FD_LOG_NOTICE(( "BENCH query_hit: %.1f ns/op (%lu ops)", ns_per, n ));

  teardown_store( store, mem );
}

static void
bench_query_miss( void ) {
  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  uchar out[ FD_SHRED_MAX_SZ ];
  ulong n = 10000UL;

  long t0 = fd_log_wallclock();
  for( ulong i=0; i<n; i++ ) {
    fd_shredb_query( store, i, 0U, out );
  }
  long t1 = fd_log_wallclock();

  double ns_per = (double)(t1 - t0) / (double)n;
  FD_LOG_NOTICE(( "BENCH query_miss: %.1f ns/op (%lu ops)", ns_per, n ));

  teardown_store( store, mem );
}

static void
bench_mixed( void ) {
  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  uchar payload[64];
  memset( payload, 0xCC, sizeof(payload) );
  uchar out[ FD_SHRED_MAX_SZ ];
  ulong n = 10000UL;

  long t0 = fd_log_wallclock();
  for( ulong i=0; i<n; i++ ) {
    ulong slot = i / 32;
    uint  idx  = (uint)(i % 32);
    insert_shred( store, slot, idx, payload, sizeof(payload) );
    fd_shredb_query( store, slot, idx, out );
  }
  long t1 = fd_log_wallclock();

  double ns_per = (double)(t1 - t0) / (double)n;
  FD_LOG_NOTICE(( "BENCH mixed (insert+query): %.1f ns/op (%lu ops)", ns_per, n ));

  teardown_store( store, mem );
}

/* ======================================================================== */

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_key_pack();
  test_footprint();
  test_lifecycle();
  test_query_nonexistent();
  test_multiple_shreds_same_slot();
  test_multiple_slots();
  test_many_wraps();

  bench_insert();
  bench_query_hit();
  bench_query_miss();
  bench_mixed();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
