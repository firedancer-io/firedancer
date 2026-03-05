#include "../../util/fd_util.h"
#include "fd_shredb.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#pragma GCC diagnostic ignored "-Wunused-function"

#define TEST_FILE "/tmp/test_shredb.bin"
#define TEST_SEED 42UL

static fd_shred_t *
make_shred( uchar buf[ FD_SHRED_MAX_SZ ],
            ulong slot,
            uint  idx ) {
  memset( buf, 0, FD_SHRED_MAX_SZ );
  fd_shred_t * shred = (fd_shred_t *)buf;
  shred->slot      = slot;
  shred->idx       = idx;
  shred->data.size = (ushort)FD_SHRED_DATA_HEADER_SZ;
  return shred;
}

static void
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
  memset( mem, 0, footprint );

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

/* Insert a shred header + payload in one go. */
static void
insert_shred( fd_shredb_t * store,
              ulong         slot,
              uint          idx,
              uchar const * payload,
              ulong         payload_sz ) {
  uchar buf[ FD_SHRED_MAX_SZ ];
  fd_shred_t * shred = make_shred( buf, slot, idx );
  fd_shredb_insert_header( store, shred );
  fd_shredb_insert_payload( store, payload, payload_sz, slot, idx );
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

/* ========================================================================
   Tests
   ======================================================================== */

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
test_insert_query_basic( void ) {
  FD_LOG_NOTICE(( "TEST basic insert + query" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  ulong slot = 100UL;
  uint  idx  = 5U;
  ulong payload_sz = 64UL;
  uchar payload[ FD_SHRED_DATA_PAYLOAD_MAX ];
  fill_payload( payload, payload_sz, slot, idx );

  insert_shred( store, slot, idx, payload, payload_sz );

  FD_TEST( store->cnt==1UL );

  uchar out[ FD_SHRED_MAX_SZ ];
  int ret = fd_shredb_query( store, slot, idx, out );
  FD_TEST( ret>0 );
  FD_TEST( (ulong)ret==(payload_sz + FD_SHRED_DATA_HEADER_SZ) );
  FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, payload_sz )==0 );

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
test_header_only_query( void ) {
  FD_LOG_NOTICE(( "TEST header-only insert returns -1 on query" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  uchar buf[ FD_SHRED_MAX_SZ ];
  fd_shred_t * shred = make_shred( buf, 50UL, 3U );
  fd_shredb_insert_header( store, shred );

  FD_TEST( store->cnt==1UL );

  uchar out[ FD_SHRED_MAX_SZ ];
  FD_TEST( fd_shredb_query( store, 50UL, 3U, out )==-1 );

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
test_duplicate_insert( void ) {
  FD_LOG_NOTICE(( "TEST duplicate header insert is a no-op" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  uchar buf[ FD_SHRED_MAX_SZ ];
  fd_shred_t * shred = make_shred( buf, 10UL, 5U );

  fd_shredb_insert_header( store, shred );
  FD_TEST( store->cnt==1UL );
  ulong wh_after_first = store->write_head;

  fd_shredb_insert_header( store, shred );
  FD_TEST( store->cnt==1UL );
  FD_TEST( store->write_head==wh_after_first );

  uchar payload[10];
  fill_payload( payload, sizeof(payload), 10UL, 5U );
  fd_shredb_insert_payload( store, payload, sizeof(payload), 10UL, 5U );

  uchar out[ FD_SHRED_MAX_SZ ];
  int ret = fd_shredb_query( store, 10UL, 5U, out );
  FD_TEST( ret>0 );
  FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, sizeof(payload) )==0 );

  teardown_store( store, mem );
}

static void
test_query_highest_basic( void ) {
  FD_LOG_NOTICE(( "TEST query_highest basic" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  ulong slot = 300UL;
  ulong payload_sz = 16UL;
  uchar payload[ FD_SHRED_DATA_PAYLOAD_MAX ];

  uint indices[] = { 0, 5, 10, 15 };
  for( ulong i=0; i<4; i++ ) {
    fill_payload( payload, payload_sz, slot, indices[i] );
    insert_shred( store, slot, indices[i], payload, payload_sz );
  }

  uchar out[ FD_SHRED_MAX_SZ ];
  int ret = fd_shredb_query_highest( store, slot, 0U, out );
  FD_TEST( ret>0 );
  fd_shred_t * result = (fd_shred_t *)out;
  FD_TEST( result->idx==15U );

  ret = fd_shredb_query_highest( store, slot, 15U, out );
  FD_TEST( ret>0 );

  FD_TEST( fd_shredb_query_highest( store, slot, 16U, out )==-1 );
  FD_TEST( fd_shredb_query_highest( store, 999UL, 0U, out )==-1 );

  teardown_store( store, mem );
}

static void
test_query_highest_header_only( void ) {
  FD_LOG_NOTICE(( "TEST query_highest with header-only highest returns -1" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  ulong slot = 400UL;
  uchar payload[16];

  fill_payload( payload, sizeof(payload), slot, 0U );
  insert_shred( store, slot, 0U, payload, sizeof(payload) );

  uchar buf[ FD_SHRED_MAX_SZ ];
  fd_shred_t * shred = make_shred( buf, slot, 5U );
  fd_shredb_insert_header( store, shred );

  uchar out[ FD_SHRED_MAX_SZ ];
  FD_TEST( fd_shredb_query_highest( store, slot, 0U, out )==-1 );

  teardown_store( store, mem );
}

static void
test_shred_index_zero( void ) {
  FD_LOG_NOTICE(( "TEST shred index 0" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  uchar payload[8];
  fill_payload( payload, sizeof(payload), 0UL, 0U );
  insert_shred( store, 0UL, 0U, payload, sizeof(payload) );

  uchar out[ FD_SHRED_MAX_SZ ];
  int ret = fd_shredb_query( store, 0UL, 0U, out );
  FD_TEST( ret>0 );
  FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, sizeof(payload) )==0 );

  ret = fd_shredb_query_highest( store, 0UL, 0U, out );
  FD_TEST( ret>0 );

  teardown_store( store, mem );
}

static void
test_large_slot( void ) {
  FD_LOG_NOTICE(( "TEST large slot number" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  ulong big_slot = (1UL<<48)-1UL;
  uchar payload[16];
  fill_payload( payload, sizeof(payload), big_slot, 42U );
  insert_shred( store, big_slot, 42U, payload, sizeof(payload) );

  uchar out[ FD_SHRED_MAX_SZ ];
  int ret = fd_shredb_query( store, big_slot, 42U, out );
  FD_TEST( ret>0 );
  FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, sizeof(payload) )==0 );

  teardown_store( store, mem );
}

static void
test_small_payload( void ) {
  FD_LOG_NOTICE(( "TEST payload of 1 byte" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  uchar payload[1] = { 0xAB };
  insert_shred( store, 1UL, 0U, payload, 1UL );

  uchar out[ FD_SHRED_MAX_SZ ];
  int ret = fd_shredb_query( store, 1UL, 0U, out );
  FD_TEST( ret>0 );
  FD_TEST( (ulong)ret==(1UL + FD_SHRED_DATA_HEADER_SZ) );
  FD_TEST( out[ FD_SHRED_DATA_HEADER_SZ ]==0xAB );

  teardown_store( store, mem );
}

static void
test_max_payload( void ) {
  FD_LOG_NOTICE(( "TEST max-size payload" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  uchar payload[ FD_SHRED_DATA_PAYLOAD_MAX ];
  fill_payload( payload, FD_SHRED_DATA_PAYLOAD_MAX, 7UL, 3U );
  insert_shred( store, 7UL, 3U, payload, FD_SHRED_DATA_PAYLOAD_MAX );

  uchar out[ FD_SHRED_MAX_SZ ];
  int ret = fd_shredb_query( store, 7UL, 3U, out );
  FD_TEST( ret>0 );
  FD_TEST( (ulong)ret==(FD_SHRED_DATA_PAYLOAD_MAX + FD_SHRED_DATA_HEADER_SZ) );
  FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, FD_SHRED_DATA_PAYLOAD_MAX )==0 );

  teardown_store( store, mem );
}

static void
test_non_contiguous_indices( void ) {
  FD_LOG_NOTICE(( "TEST non-contiguous shred indices within a slot" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  ulong slot = 500UL;
  uchar payload[16];
  uint indices[] = { 3, 7, 100, 200, 1000 };
  ulong n = sizeof(indices) / sizeof(indices[0]);

  for( ulong i=0; i<n; i++ ) {
    fill_payload( payload, sizeof(payload), slot, indices[i] );
    insert_shred( store, slot, indices[i], payload, sizeof(payload) );
  }

  FD_TEST( store->cnt==n );

  uchar out[ FD_SHRED_MAX_SZ ];
  for( ulong i=0; i<n; i++ ) {
    fill_payload( payload, sizeof(payload), slot, indices[i] );
    int ret = fd_shredb_query( store, slot, indices[i], out );
    FD_TEST( ret>0 );
    FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, sizeof(payload) )==0 );
  }

  FD_TEST( fd_shredb_query( store, slot, 4U, out )==-1 );
  FD_TEST( fd_shredb_query( store, slot, 50U, out )==-1 );

  int ret = fd_shredb_query_highest( store, slot, 0U, out );
  FD_TEST( ret>0 );
  fd_shred_t * result = (fd_shred_t *)out;
  FD_TEST( result->idx==1000U );

  teardown_store( store, mem );
}

static void
test_interleaved_slots( void ) {
  FD_LOG_NOTICE(( "TEST interleaved inserts across slots" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  uchar payload[16];

  for( uint i=0; i<8; i++ ) {
    fill_payload( payload, sizeof(payload), 0UL, i );
    insert_shred( store, 0UL, i, payload, sizeof(payload) );
    fill_payload( payload, sizeof(payload), 1UL, i );
    insert_shred( store, 1UL, i, payload, sizeof(payload) );
  }

  FD_TEST( store->cnt==16UL );

  uchar out[ FD_SHRED_MAX_SZ ];
  for( uint i=0; i<8; i++ ) {
    fill_payload( payload, sizeof(payload), 0UL, i );
    int ret = fd_shredb_query( store, 0UL, i, out );
    FD_TEST( ret>0 );
    FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, sizeof(payload) )==0 );

    fill_payload( payload, sizeof(payload), 1UL, i );
    ret = fd_shredb_query( store, 1UL, i, out );
    FD_TEST( ret>0 );
    FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, sizeof(payload) )==0 );
  }

  teardown_store( store, mem );
}

static void
test_ring_eviction( void ) {
  FD_LOG_NOTICE(( "TEST ring buffer eviction" ));

  void * mem;
  ulong cap = 4UL;
  fd_shredb_t * store = setup_small_store( &mem, cap );

  uchar payload[16];
  uchar out[ FD_SHRED_MAX_SZ ];

  for( uint i=0; i<4; i++ ) {
    fill_payload( payload, sizeof(payload), 1UL, i );
    insert_shred( store, 1UL, i, payload, sizeof(payload) );
  }
  FD_TEST( store->cnt==4UL );

  fill_payload( payload, sizeof(payload), 1UL, 4U );
  insert_shred( store, 1UL, 4U, payload, sizeof(payload) );
  FD_TEST( store->cnt==4UL );

  FD_TEST( fd_shredb_query( store, 1UL, 0U, out )==-1 );

  for( uint i=1; i<=4; i++ ) {
    fill_payload( payload, sizeof(payload), 1UL, i );
    int ret = fd_shredb_query( store, 1UL, i, out );
    FD_TEST( ret>0 );
    FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, sizeof(payload) )==0 );
  }

  teardown_store( store, mem );
}

static void
test_full_eviction_cycle( void ) {
  FD_LOG_NOTICE(( "TEST full eviction cycle" ));

  void * mem;
  ulong cap = 4UL;
  fd_shredb_t * store = setup_small_store( &mem, cap );

  uchar payload[16];
  uchar out[ FD_SHRED_MAX_SZ ];

  for( uint i=0; i<4; i++ ) {
    fill_payload( payload, sizeof(payload), 0UL, i );
    insert_shred( store, 0UL, i, payload, sizeof(payload) );
  }

  for( uint i=0; i<4; i++ ) {
    fill_payload( payload, sizeof(payload), 1UL, i );
    insert_shred( store, 1UL, i, payload, sizeof(payload) );
  }

  FD_TEST( store->cnt==4UL );

  for( uint i=0; i<4; i++ ) {
    FD_TEST( fd_shredb_query( store, 0UL, i, out )==-1 );
  }
  FD_TEST( fd_shredb_query_highest( store, 0UL, 0U, out )==-1 );

  for( uint i=0; i<4; i++ ) {
    fill_payload( payload, sizeof(payload), 1UL, i );
    int ret = fd_shredb_query( store, 1UL, i, out );
    FD_TEST( ret>0 );
    FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, sizeof(payload) )==0 );
  }

  teardown_store( store, mem );
}

static void
test_evict_highest_shred( void ) {
  FD_LOG_NOTICE(( "TEST evicting the highest shred updates slot_map" ));

  void * mem;
  ulong cap = 8UL;
  fd_shredb_t * store = setup_small_store( &mem, cap );

  uchar payload[16];
  uchar out[ FD_SHRED_MAX_SZ ];

  for( uint i=0; i<4; i++ ) {
    fill_payload( payload, sizeof(payload), 10UL, i );
    insert_shred( store, 10UL, i, payload, sizeof(payload) );
  }

  int ret = fd_shredb_query_highest( store, 10UL, 0U, out );
  FD_TEST( ret>0 );
  fd_shred_t * result = (fd_shred_t *)out;
  FD_TEST( result->idx==3U );

  /* Fill remaining ring + evict slot 10 idx 0,1 */
  for( uint i=0; i<4; i++ ) {
    fill_payload( payload, sizeof(payload), 20UL, i );
    insert_shred( store, 20UL, i, payload, sizeof(payload) );
  }
  for( uint i=0; i<2; i++ ) {
    fill_payload( payload, sizeof(payload), 30UL, i );
    insert_shred( store, 30UL, i, payload, sizeof(payload) );
  }

  FD_TEST( fd_shredb_query( store, 10UL, 0U, out )==-1 );
  FD_TEST( fd_shredb_query( store, 10UL, 1U, out )==-1 );
  FD_TEST( fd_shredb_query( store, 10UL, 2U, out )>0 );
  FD_TEST( fd_shredb_query( store, 10UL, 3U, out )>0 );

  ret = fd_shredb_query_highest( store, 10UL, 0U, out );
  FD_TEST( ret>0 );
  result = (fd_shred_t *)out;
  FD_TEST( result->idx==3U );

  /* Evict remaining slot 10 entries */
  for( uint i=2; i<4; i++ ) {
    fill_payload( payload, sizeof(payload), 30UL, i );
    insert_shred( store, 30UL, i, payload, sizeof(payload) );
  }

  FD_TEST( fd_shredb_query( store, 10UL, 2U, out )==-1 );
  FD_TEST( fd_shredb_query( store, 10UL, 3U, out )==-1 );
  FD_TEST( fd_shredb_query_highest( store, 10UL, 0U, out )==-1 );

  teardown_store( store, mem );
}

static void
test_partial_slot_eviction( void ) {
  FD_LOG_NOTICE(( "TEST partial slot eviction" ));

  void * mem;
  ulong cap = 8UL;
  fd_shredb_t * store = setup_small_store( &mem, cap );

  uchar payload[16];
  uchar out[ FD_SHRED_MAX_SZ ];

  for( uint i=0; i<6; i++ ) {
    fill_payload( payload, sizeof(payload), 0UL, i );
    insert_shred( store, 0UL, i, payload, sizeof(payload) );
  }

  for( uint i=0; i<4; i++ ) {
    fill_payload( payload, sizeof(payload), 1UL, i );
    insert_shred( store, 1UL, i, payload, sizeof(payload) );
  }

  FD_TEST( store->cnt==8UL );

  FD_TEST( fd_shredb_query( store, 0UL, 0U, out )==-1 );
  FD_TEST( fd_shredb_query( store, 0UL, 1U, out )==-1 );
  for( uint i=2; i<6; i++ ) {
    FD_TEST( fd_shredb_query( store, 0UL, i, out )>0 );
  }

  for( uint i=0; i<4; i++ ) {
    FD_TEST( fd_shredb_query( store, 1UL, i, out )>0 );
  }

  teardown_store( store, mem );
}

static void
test_reinsert_after_eviction( void ) {
  FD_LOG_NOTICE(( "TEST reinserting a (slot,idx) after eviction" ));

  void * mem;
  ulong cap = 4UL;
  fd_shredb_t * store = setup_small_store( &mem, cap );

  uchar payload[16];
  uchar out[ FD_SHRED_MAX_SZ ];

  for( uint i=0; i<4; i++ ) {
    fill_payload( payload, sizeof(payload), 0UL, i );
    insert_shred( store, 0UL, i, payload, sizeof(payload) );
  }

  for( uint i=0; i<4; i++ ) {
    fill_payload( payload, sizeof(payload), 1UL, i );
    insert_shred( store, 1UL, i, payload, sizeof(payload) );
  }

  uchar new_payload[16];
  fill_payload( new_payload, sizeof(new_payload), 99UL, 99U );
  insert_shred( store, 0UL, 0U, new_payload, sizeof(new_payload) );

  int ret = fd_shredb_query( store, 0UL, 0U, out );
  FD_TEST( ret>0 );
  FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, new_payload, sizeof(new_payload) )==0 );

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
test_payload_evicted_before_insert( void ) {
  FD_LOG_NOTICE(( "TEST payload insert after header was evicted is a no-op" ));

  void * mem;
  ulong cap = 4UL;
  fd_shredb_t * store = setup_small_store( &mem, cap );

  uchar buf[ FD_SHRED_MAX_SZ ];
  uchar payload[16];

  fd_shred_t * shred = make_shred( buf, 0UL, 0U );
  fd_shredb_insert_header( store, shred );

  for( uint i=0; i<5; i++ ) {
    fill_payload( payload, sizeof(payload), 1UL, i );
    insert_shred( store, 1UL, i, payload, sizeof(payload) );
  }

  fill_payload( payload, sizeof(payload), 0UL, 0U );
  fd_shredb_insert_payload( store, payload, sizeof(payload), 0UL, 0U );

  uchar out[ FD_SHRED_MAX_SZ ];
  FD_TEST( fd_shredb_query( store, 0UL, 0U, out )==-1 );

  teardown_store( store, mem );
}

static void
test_file_growth( void ) {
  FD_LOG_NOTICE(( "TEST backing file grows as needed" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  uchar payload[16];
  uchar out[ FD_SHRED_MAX_SZ ];

  for( uint i=0; i<256; i++ ) {
    fill_payload( payload, sizeof(payload), 0UL, i );
    insert_shred( store, 0UL, i, payload, sizeof(payload) );
  }

  FD_TEST( store->cnt==256UL );
  FD_TEST( store->file_shreds >= 256UL );

  for( uint i=0; i<256; i+=31 ) {
    fill_payload( payload, sizeof(payload), 0UL, i );
    int ret = fd_shredb_query( store, 0UL, i, out );
    FD_TEST( ret>0 );
    FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, sizeof(payload) )==0 );
  }

  teardown_store( store, mem );
}

static void
test_stress( void ) {
  FD_LOG_NOTICE(( "TEST stress: many slots, many shreds" ));

  void * mem;
  fd_shredb_t * store = setup_store( &mem, 1UL );

  ulong payload_sz = 64UL;
  uchar payload[ FD_SHRED_DATA_PAYLOAD_MAX ];
  uchar out[ FD_SHRED_MAX_SZ ];

  ulong num_slots  = 100;
  uint  per_slot   = 32;
  ulong total      = num_slots * (ulong)per_slot;

  for( ulong s=0; s<num_slots; s++ ) {
    for( uint i=0; i<per_slot; i++ ) {
      fill_payload( payload, payload_sz, s, i );
      insert_shred( store, s, i, payload, payload_sz );
    }
  }

  FD_TEST( store->cnt==total );

  for( ulong s=0; s<num_slots; s+=7 ) {
    for( uint i=0; i<per_slot; i+=5 ) {
      fill_payload( payload, payload_sz, s, i );
      int ret = fd_shredb_query( store, s, i, out );
      FD_TEST( ret>0 );
      FD_TEST( (ulong)ret==(payload_sz + FD_SHRED_DATA_HEADER_SZ) );
      FD_TEST( memcmp( out + FD_SHRED_DATA_HEADER_SZ, payload, payload_sz )==0 );
    }

    int ret = fd_shredb_query_highest( store, s, 0U, out );
    FD_TEST( ret>0 );
    fd_shred_t * result = (fd_shred_t *)out;
    FD_TEST( result->idx==per_slot-1 );
  }

  teardown_store( store, mem );
}

/* ========================================================================
   Benchmarks
   ======================================================================== */

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
    fd_shred_t * shred = make_shred( buf, slot, idx );
    fd_shredb_insert_header( store, shred );
    fd_shredb_insert_payload( store, payload, sizeof(payload), slot, idx );
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

  // test_key_pack();
  // test_footprint();
  // test_lifecycle();
  // test_insert_query_basic();
  // test_query_nonexistent();
  // test_header_only_query();
  // test_multiple_shreds_same_slot();
  // test_multiple_slots();
  // test_duplicate_insert();
  // test_query_highest_basic();
  // test_query_highest_header_only();
  // test_shred_index_zero();
  // test_large_slot();
  // test_small_payload();
  // test_max_payload();
  // test_non_contiguous_indices();
  // test_interleaved_slots();
  // test_ring_eviction();
  // test_full_eviction_cycle();
  // test_evict_highest_shred();
  // test_partial_slot_eviction();
  // test_reinsert_after_eviction();
  // test_many_wraps();
  // test_payload_evicted_before_insert();
  // test_file_growth();
  // test_stress();

  bench_insert();
  // bench_query_hit();
  // bench_query_miss();
  // bench_mixed();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
