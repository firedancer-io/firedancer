#include "../../util/fd_util.h"
#include "fd_ledger.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char TEST_FILE[] = "/tmp/test_ledger.db";

/* Helper: create a deterministic shred payload from slot and shred_idx.
   Fills the first 8 bytes with slot and the next 4 with shred_idx so
   we can verify the contents after a query. */
static void
make_shred( uchar buf[ FD_SHRED_MAX_SZ ],
            ulong slot,
            uint  shred_idx ) {
  fd_memset( buf, 0, FD_SHRED_MAX_SZ );
  FD_STORE( ulong, buf,   slot      );
  FD_STORE( uint,  buf+8, shred_idx );
}

static void
verify_shred( uchar const buf[ FD_SHRED_MAX_SZ ],
              ulong        slot,
              uint         shred_idx ) {
  FD_TEST( FD_LOAD( ulong, buf   )==slot      );
  FD_TEST( FD_LOAD( uint,  buf+8 )==shred_idx );
}

/* Helper: create, join, and return a ledger.  Caller must delete. */
static fd_ledger_t *
ledger_create( void ** mem_out, ulong max_shreds ) {
  ulong footprint = fd_ledger_footprint( max_shreds );
  FD_TEST( footprint );
  void * mem = aligned_alloc( fd_ledger_align(), footprint );
  FD_TEST( mem );
  void * shmem = fd_ledger_new( mem, max_shreds, TEST_FILE, 42UL );
  FD_TEST( shmem );
  fd_ledger_t * ledger = fd_ledger_join( shmem );
  FD_TEST( ledger );
  *mem_out = mem;
  return ledger;
}

static void
ledger_destroy( fd_ledger_t * ledger, void * mem ) {
  fd_ledger_delete( fd_ledger_leave( ledger ) );
  free( mem );
  unlink( TEST_FILE );
}

/* ---- Key packing tests ------------------------------------------- */

static void
test_key_pack( void ) {
  /* Basic round-trip */
  FD_TEST( fd_ledger_key_slot     ( fd_ledger_key_pack( 42UL, 7U ) )==42UL );
  FD_TEST( fd_ledger_key_shred_idx( fd_ledger_key_pack( 42UL, 7U ) )==7U   );

  /* Zero slot and index */
  FD_TEST( fd_ledger_key_slot     ( fd_ledger_key_pack( 0UL, 0U ) )==0UL );
  FD_TEST( fd_ledger_key_shred_idx( fd_ledger_key_pack( 0UL, 0U ) )==0U  );

  /* Max 16-bit shred index */
  FD_TEST( fd_ledger_key_slot     ( fd_ledger_key_pack( 100UL, 0xFFFFU ) )==100UL    );
  FD_TEST( fd_ledger_key_shred_idx( fd_ledger_key_pack( 100UL, 0xFFFFU ) )==0xFFFFU  );

  /* Large slot */
  ulong big_slot = (1UL<<48) - 1UL;
  FD_TEST( fd_ledger_key_slot     ( fd_ledger_key_pack( big_slot, 1U ) )==big_slot );
  FD_TEST( fd_ledger_key_shred_idx( fd_ledger_key_pack( big_slot, 1U ) )==1U       );

  /* Shred index truncates to 16 bits */
  FD_TEST( fd_ledger_key_shred_idx( fd_ledger_key_pack( 0UL, 0x10001U ) )==1U );
}

/* ---- Footprint tests --------------------------------------------- */

static void
test_footprint( void ) {
  FD_TEST( fd_ledger_footprint( 0UL )==0UL );

  /* Non-zero values must return non-zero */
  FD_TEST( fd_ledger_footprint( 1UL   ) );
  FD_TEST( fd_ledger_footprint( 2UL   ) );
  FD_TEST( fd_ledger_footprint( 16UL  ) );
  FD_TEST( fd_ledger_footprint( 100UL ) );

  /* Monotonically increasing */
  FD_TEST( fd_ledger_footprint( 16UL )<=fd_ledger_footprint( 32UL ) );
  FD_TEST( fd_ledger_footprint( 32UL )<=fd_ledger_footprint( 64UL ) );

  /* Alignment */
  for( ulong n=1UL; n<=128UL; n++ ) {
    ulong fp = fd_ledger_footprint( n );
    FD_TEST( fd_ulong_is_aligned( fp, fd_ledger_align() ) );
  }
}

/* ---- Lifecycle (new / join / leave / delete) --------------------- */

static void
test_lifecycle( void ) {
  ulong max_shreds = 64UL;
  ulong footprint  = fd_ledger_footprint( max_shreds );
  void * mem = aligned_alloc( fd_ledger_align(), footprint );
  FD_TEST( mem );

  /* new with NULL shmem returns NULL */
  FD_TEST( !fd_ledger_new( NULL, max_shreds, TEST_FILE, 0UL ) );

  /* new with zero max_shreds returns NULL */
  FD_TEST( !fd_ledger_new( mem, 0UL, TEST_FILE, 0UL ) );

  /* new with NULL file_path returns NULL */
  FD_TEST( !fd_ledger_new( mem, max_shreds, NULL, 0UL ) );

  /* Successful new */
  void * shmem = fd_ledger_new( mem, max_shreds, TEST_FILE, 0UL );
  FD_TEST( shmem==mem );

  /* join with NULL returns NULL */
  FD_TEST( !fd_ledger_join( NULL ) );

  /* Successful join */
  fd_ledger_t * ledger = fd_ledger_join( shmem );
  FD_TEST( ledger );

  /* leave with NULL returns NULL */
  FD_TEST( !fd_ledger_leave( NULL ) );

  /* Successful leave */
  void * left = fd_ledger_leave( ledger );
  FD_TEST( left==shmem );

  /* delete with NULL returns NULL */
  FD_TEST( !fd_ledger_delete( NULL ) );

  /* Successful delete */
  void * deleted = fd_ledger_delete( left );
  FD_TEST( deleted==mem );

  free( mem );
  unlink( TEST_FILE );
}

/* ---- Insert + query basic ---------------------------------------- */

static void
test_insert_query_basic( void ) {
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, 64UL );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  /* Query on empty ledger returns -1 */
  FD_TEST( fd_ledger_query( ledger, out, 0UL, 0U )==-1 );
  FD_TEST( fd_ledger_query( ledger, out, 999UL, 0U )==-1 );

  /* Insert one shred and query it back */
  make_shred( shred, 10UL, 5U );
  fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 10UL, 5U );
  int ret = fd_ledger_query( ledger, out, 10UL, 5U );
  FD_TEST( ret==(int)FD_SHRED_MAX_SZ );
  verify_shred( out, 10UL, 5U );

  /* Query non-existent index in known slot */
  FD_TEST( fd_ledger_query( ledger, out, 10UL, 6U )==-1 );

  /* Query non-existent slot */
  FD_TEST( fd_ledger_query( ledger, out, 11UL, 5U )==-1 );

  ledger_destroy( ledger, mem );
}

/* ---- Multiple shreds in the same slot ---------------------------- */

static void
test_multiple_shreds_same_slot( void ) {
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, 64UL );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  ulong slot = 42UL;
  for( uint idx=0U; idx<10U; idx++ ) {
    make_shred( shred, slot, idx );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, slot, idx );
  }

  /* All 10 should be queryable */
  for( uint idx=0U; idx<10U; idx++ ) {
    int ret = fd_ledger_query( ledger, out, slot, idx );
    FD_TEST( ret==(int)FD_SHRED_MAX_SZ );
    verify_shred( out, slot, idx );
  }

  /* Non-existent index in the same slot */
  FD_TEST( fd_ledger_query( ledger, out, slot, 10U )==-1 );

  ledger_destroy( ledger, mem );
}

/* ---- Multiple slots ---------------------------------------------- */

static void
test_multiple_slots( void ) {
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, 128UL );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  /* Insert 3 shreds each in 5 different slots */
  for( ulong slot=100UL; slot<105UL; slot++ ) {
    for( uint idx=0U; idx<3U; idx++ ) {
      make_shred( shred, slot, idx );
      fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, slot, idx );
    }
  }

  /* Query all */
  for( ulong slot=100UL; slot<105UL; slot++ ) {
    for( uint idx=0U; idx<3U; idx++ ) {
      int ret = fd_ledger_query( ledger, out, slot, idx );
      FD_TEST( ret==(int)FD_SHRED_MAX_SZ );
      verify_shred( out, slot, idx );
    }
    FD_TEST( fd_ledger_query( ledger, out, slot, 3U )==-1 );
  }

  /* Unknown slot */
  FD_TEST( fd_ledger_query( ledger, out, 200UL, 0U )==-1 );

  ledger_destroy( ledger, mem );
}

/* ---- Duplicate insert is a no-op --------------------------------- */

static void
test_duplicate_insert( void ) {
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, 64UL );

  uchar shred1[ FD_SHRED_MAX_SZ ];
  uchar shred2[ FD_SHRED_MAX_SZ ];
  uchar out   [ FD_SHRED_MAX_SZ ];

  make_shred( shred1, 5UL, 3U );
  fd_ledger_insert( ledger, shred1, FD_SHRED_MAX_SZ, 5UL, 3U );

  /* Insert with same (slot, shred_idx) but different payload */
  fd_memset( shred2, 0xAB, FD_SHRED_MAX_SZ );
  fd_ledger_insert( ledger, shred2, FD_SHRED_MAX_SZ, 5UL, 3U );

  /* Should still have the original payload */
  int ret = fd_ledger_query( ledger, out, 5UL, 3U );
  FD_TEST( ret==(int)FD_SHRED_MAX_SZ );
  verify_shred( out, 5UL, 3U );

  ledger_destroy( ledger, mem );
}

/* ---- Ring buffer wrap-around / FIFO eviction --------------------- */

static void
test_ring_eviction( void ) {
  ulong max_shreds = 8UL;
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, max_shreds );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  /* Fill the ring buffer completely (8 entries) */
  for( uint idx=0U; idx<(uint)max_shreds; idx++ ) {
    make_shred( shred, 1UL, idx );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 1UL, idx );
  }

  /* All 8 should be queryable */
  for( uint idx=0U; idx<(uint)max_shreds; idx++ ) {
    FD_TEST( fd_ledger_query( ledger, out, 1UL, idx )>0 );
  }

  /* Insert one more in a different slot => evicts slot 1 idx 0 */
  make_shred( shred, 2UL, 0U );
  fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 2UL, 0U );

  FD_TEST( fd_ledger_query( ledger, out, 1UL, 0U )==-1 ); /* evicted */
  FD_TEST( fd_ledger_query( ledger, out, 1UL, 1U )>0 );   /* still there */
  FD_TEST( fd_ledger_query( ledger, out, 2UL, 0U )>0 );   /* newly inserted */
  verify_shred( out, 2UL, 0U );

  ledger_destroy( ledger, mem );
}

/* ---- Full eviction cycle: evict everything ----------------------- */

static void
test_full_eviction_cycle( void ) {
  ulong max_shreds = 4UL;
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, max_shreds );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  /* Fill with slot 1 shreds 0..3 */
  for( uint idx=0U; idx<4U; idx++ ) {
    make_shred( shred, 1UL, idx );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 1UL, idx );
  }

  /* Now overwrite all of them with slot 2 shreds 0..3 */
  for( uint idx=0U; idx<4U; idx++ ) {
    make_shred( shred, 2UL, idx );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 2UL, idx );
  }

  /* Slot 1 should be entirely gone */
  for( uint idx=0U; idx<4U; idx++ ) {
    FD_TEST( fd_ledger_query( ledger, out, 1UL, idx )==-1 );
  }

  /* Slot 2 should all be present */
  for( uint idx=0U; idx<4U; idx++ ) {
    int ret = fd_ledger_query( ledger, out, 2UL, idx );
    FD_TEST( ret>0 );
    verify_shred( out, 2UL, idx );
  }

  ledger_destroy( ledger, mem );
}

/* ---- Eviction of the highest shred updates slot metadata --------- */

static void
test_evict_highest_shred( void ) {
  ulong max_shreds = 4UL;
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, max_shreds );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  /* Insert shreds at indices 1, 2, 3 in slot 10.  Fills 3 of 4 ring
     slots.  Highest is 3. */
  for( uint idx=1U; idx<=3U; idx++ ) {
    make_shred( shred, 10UL, idx );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 10UL, idx );
  }

  /* Insert a 4th entry to fill the ring */
  make_shred( shred, 20UL, 0U );
  fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 20UL, 0U );

  /* Now insert one more => evicts slot 10 idx 1 (the oldest).
     Slot 10 still has idx 2 and 3. */
  make_shred( shred, 20UL, 1U );
  fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 20UL, 1U );
  FD_TEST( fd_ledger_query( ledger, out, 10UL, 1U )==-1 );
  FD_TEST( fd_ledger_query( ledger, out, 10UL, 2U )>0 );
  FD_TEST( fd_ledger_query( ledger, out, 10UL, 3U )>0 );

  /* Evict idx 2 => only idx 3 remains */
  make_shred( shred, 20UL, 2U );
  fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 20UL, 2U );
  FD_TEST( fd_ledger_query( ledger, out, 10UL, 2U )==-1 );
  FD_TEST( fd_ledger_query( ledger, out, 10UL, 3U )>0 );

  /* Evict idx 3 => slot 10 entirely gone */
  make_shred( shred, 20UL, 3U );
  fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 20UL, 3U );
  FD_TEST( fd_ledger_query( ledger, out, 10UL, 3U )==-1 );

  ledger_destroy( ledger, mem );
}

/* ---- Small payload (not full FD_SHRED_MAX_SZ) -------------------- */

static void
test_small_payload( void ) {
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, 16UL );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  fd_memset( shred, 0xCD, 64 );
  fd_ledger_insert( ledger, shred, 64UL, 1UL, 0U );

  int ret = fd_ledger_query( ledger, out, 1UL, 0U );
  FD_TEST( ret==64 );
  FD_TEST( !memcmp( out, shred, 64 ) );

  ledger_destroy( ledger, mem );
}

/* ---- Minimum capacity (max_shreds == 1) -------------------------- */

static void
test_capacity_one( void ) {
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, 1UL );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  make_shred( shred, 1UL, 0U );
  fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 1UL, 0U );
  FD_TEST( fd_ledger_query( ledger, out, 1UL, 0U )>0 );
  verify_shred( out, 1UL, 0U );

  /* Inserting a second evicts the first */
  make_shred( shred, 2UL, 0U );
  fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 2UL, 0U );
  FD_TEST( fd_ledger_query( ledger, out, 1UL, 0U )==-1 );
  FD_TEST( fd_ledger_query( ledger, out, 2UL, 0U )>0 );
  verify_shred( out, 2UL, 0U );

  ledger_destroy( ledger, mem );
}

/* ---- Many wraps around the ring ---------------------------------- */

static void
test_many_wraps( void ) {
  ulong max_shreds = 16UL;
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, max_shreds );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  /* Insert 10x the capacity, each in a different slot with idx 0 */
  ulong total = max_shreds * 10UL;
  for( ulong i=0UL; i<total; i++ ) {
    make_shred( shred, i, 0U );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, i, 0U );
  }

  /* Only the last max_shreds entries should survive */
  for( ulong i=0UL; i<total - max_shreds; i++ ) {
    FD_TEST( fd_ledger_query( ledger, out, i, 0U )==-1 );
  }
  for( ulong i=total - max_shreds; i<total; i++ ) {
    int ret = fd_ledger_query( ledger, out, i, 0U );
    FD_TEST( ret>0 );
    verify_shred( out, i, 0U );
  }

  ledger_destroy( ledger, mem );
}

/* ---- Interleaved slots ------------------------------------------- */

static void
test_interleaved_slots( void ) {
  ulong max_shreds = 32UL;
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, max_shreds );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  /* Insert shreds from 4 slots in round-robin order */
  for( uint round=0U; round<8U; round++ ) {
    for( ulong slot=0UL; slot<4UL; slot++ ) {
      make_shred( shred, slot, round );
      fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, slot, round );
    }
  }

  /* All 32 should be queryable (exactly at capacity) */
  for( ulong slot=0UL; slot<4UL; slot++ ) {
    for( uint round=0U; round<8U; round++ ) {
      int ret = fd_ledger_query( ledger, out, slot, round );
      FD_TEST( ret>0 );
      verify_shred( out, slot, round );
    }
  }

  ledger_destroy( ledger, mem );
}

/* ---- Shred index 0 edge case ------------------------------------- */

static void
test_shred_index_zero( void ) {
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, 16UL );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  make_shred( shred, 0UL, 0U );
  fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 0UL, 0U );

  int ret = fd_ledger_query( ledger, out, 0UL, 0U );
  FD_TEST( ret>0 );
  verify_shred( out, 0UL, 0U );

  ledger_destroy( ledger, mem );
}

/* ---- Large slot numbers ------------------------------------------ */

static void
test_large_slot( void ) {
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, 16UL );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  ulong big_slot = (1UL<<48) - 2UL;
  make_shred( shred, big_slot, 100U );
  fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, big_slot, 100U );

  int ret = fd_ledger_query( ledger, out, big_slot, 100U );
  FD_TEST( ret>0 );
  verify_shred( out, big_slot, 100U );

  ledger_destroy( ledger, mem );
}

/* ---- Partial eviction across slots ------------------------------- */

static void
test_partial_slot_eviction( void ) {
  ulong max_shreds = 8UL;
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, max_shreds );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  /* Insert 4 shreds in slot A (indices 0..3), 4 in slot B (indices 0..3).
     Ring is now full.  Then insert 2 more in slot C which evicts
     slot A indices 0 and 1 but leaves 2 and 3. */
  for( uint idx=0U; idx<4U; idx++ ) {
    make_shred( shred, 100UL, idx );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 100UL, idx );
  }
  for( uint idx=0U; idx<4U; idx++ ) {
    make_shred( shred, 200UL, idx );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 200UL, idx );
  }

  /* Evict 2 from slot A */
  make_shred( shred, 300UL, 0U );
  fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 300UL, 0U );
  make_shred( shred, 300UL, 1U );
  fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 300UL, 1U );

  FD_TEST( fd_ledger_query( ledger, out, 100UL, 0U )==-1 ); /* evicted */
  FD_TEST( fd_ledger_query( ledger, out, 100UL, 1U )==-1 ); /* evicted */
  FD_TEST( fd_ledger_query( ledger, out, 100UL, 2U )>0 );   /* still here */
  FD_TEST( fd_ledger_query( ledger, out, 100UL, 3U )>0 );   /* still here */

  /* Slot B untouched */
  for( uint idx=0U; idx<4U; idx++ ) {
    FD_TEST( fd_ledger_query( ledger, out, 200UL, idx )>0 );
  }

  ledger_destroy( ledger, mem );
}

/* ---- Re-insert after eviction ------------------------------------ */

static void
test_reinsert_after_eviction( void ) {
  ulong max_shreds = 4UL;
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, max_shreds );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  /* Fill ring */
  for( uint idx=0U; idx<4U; idx++ ) {
    make_shred( shred, 1UL, idx );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 1UL, idx );
  }

  /* Evict all of slot 1 */
  for( uint idx=0U; idx<4U; idx++ ) {
    make_shred( shred, 2UL, idx );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 2UL, idx );
  }
  FD_TEST( fd_ledger_query( ledger, out, 1UL, 0U )==-1 );

  /* Evict all of slot 2, re-inserting slot 1 entries */
  for( uint idx=0U; idx<4U; idx++ ) {
    make_shred( shred, 1UL, idx );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 1UL, idx );
  }

  /* Slot 1 is back */
  for( uint idx=0U; idx<4U; idx++ ) {
    int ret = fd_ledger_query( ledger, out, 1UL, idx );
    FD_TEST( ret>0 );
    verify_shred( out, 1UL, idx );
  }

  /* Slot 2 is gone */
  for( uint idx=0U; idx<4U; idx++ ) {
    FD_TEST( fd_ledger_query( ledger, out, 2UL, idx )==-1 );
  }

  ledger_destroy( ledger, mem );
}

/* ---- Non-contiguous shred indices -------------------------------- */

static void
test_non_contiguous_indices( void ) {
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, 64UL );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  /* Insert shreds with gaps in the index */
  uint indices[] = { 0, 5, 10, 100, 500, 1000 };
  ulong n = sizeof(indices)/sizeof(indices[0]);

  for( ulong i=0; i<n; i++ ) {
    make_shred( shred, 77UL, indices[i] );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, 77UL, indices[i] );
  }

  for( ulong i=0; i<n; i++ ) {
    int ret = fd_ledger_query( ledger, out, 77UL, indices[i] );
    FD_TEST( ret>0 );
    verify_shred( out, 77UL, indices[i] );
  }

  /* Gaps should return -1 */
  FD_TEST( fd_ledger_query( ledger, out, 77UL, 1U   )==-1 );
  FD_TEST( fd_ledger_query( ledger, out, 77UL, 50U  )==-1 );
  FD_TEST( fd_ledger_query( ledger, out, 77UL, 999U )==-1 );

  ledger_destroy( ledger, mem );
}

/* ---- Stress: high volume with evictions -------------------------- */

static void
test_stress( void ) {
  ulong max_shreds = 256UL;
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, max_shreds );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];

  /* Insert 10k shreds across many slots */
  ulong total = 10000UL;
  for( ulong i=0UL; i<total; i++ ) {
    ulong slot = i / 10UL;
    uint  idx  = (uint)(i % 10UL);
    make_shred( shred, slot, idx );
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, slot, idx );
  }

  /* The last max_shreds entries should be retrievable.
     total=10000, max_shreds=256 => entries [9744..9999] survive.
     That's slots [974..999], but slot 974 only has indices [4..9]
     (6 entries). */
  ulong first_surviving = total - max_shreds; /* 9744 */
  ulong first_full_slot = first_surviving / 10UL + 1UL; /* 975 */
  ulong last_slot       = (total - 1UL) / 10UL;        /* 999 */

  /* All of these full slots should be queryable */
  for( ulong slot=first_full_slot; slot<=last_slot; slot++ ) {
    for( uint idx=0U; idx<10U; idx++ ) {
      int ret = fd_ledger_query( ledger, out, slot, idx );
      FD_TEST( ret>0 );
      verify_shred( out, slot, idx );
    }
  }

  /* Much earlier slots must be gone */
  FD_TEST( fd_ledger_query( ledger, out, 0UL, 0U )==-1 );
  FD_TEST( fd_ledger_query( ledger, out, 100UL, 0U )==-1 );

  ledger_destroy( ledger, mem );
}

/* ==== Benchmarks =================================================== */

static void
bench_insert( void ) {
  ulong max_shreds = 1UL<<16;
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, max_shreds );

  uchar shred[ FD_SHRED_MAX_SZ ];
  fd_memset( shred, 0xAB, FD_SHRED_MAX_SZ );

  ulong iter = max_shreds * 4UL;

  /* Warm up */
  for( ulong i=0UL; i<max_shreds; i++ ) {
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, i, 0U );
  }

  /* Benchmark: insert with eviction (steady state) */
  long dt = -fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) {
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, max_shreds + i, 0U );
  }
  dt += fd_log_wallclock();

  double rate = (double)iter / ( (double)dt / 1e9 );
  double ns   = (double)dt / (double)iter;
  FD_LOG_NOTICE(( "bench_insert: %lu iters in %.3fs  (%.0f ops/s, %.1f ns/op)",
                  iter, (double)dt/1e9, rate, ns ));

  ledger_destroy( ledger, mem );
}

static void
bench_query_hit( void ) {
  ulong max_shreds = 1UL<<16;
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, max_shreds );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];
  fd_memset( shred, 0xAB, FD_SHRED_MAX_SZ );

  /* Fill */
  for( ulong i=0UL; i<max_shreds; i++ ) {
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, i, 0U );
  }

  ulong iter = max_shreds * 4UL;

  /* Benchmark: query hits (uniform random over populated entries) */
  long dt = -fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) {
    ulong slot = i % max_shreds;
    fd_ledger_query( ledger, out, slot, 0U );
  }
  dt += fd_log_wallclock();

  double rate = (double)iter / ( (double)dt / 1e9 );
  double ns   = (double)dt / (double)iter;
  FD_LOG_NOTICE(( "bench_query_hit: %lu iters in %.3fs  (%.0f ops/s, %.1f ns/op)",
                  iter, (double)dt/1e9, rate, ns ));

  ledger_destroy( ledger, mem );
}

static void
bench_query_miss( void ) {
  ulong max_shreds = 1UL<<16;
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, max_shreds );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];
  fd_memset( shred, 0xAB, FD_SHRED_MAX_SZ );

  /* Fill with slot 0..max_shreds-1 */
  for( ulong i=0UL; i<max_shreds; i++ ) {
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, i, 0U );
  }

  ulong iter = max_shreds * 4UL;

  /* Benchmark: query misses (unknown slots) */
  long dt = -fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) {
    fd_ledger_query( ledger, out, max_shreds + i, 0U );
  }
  dt += fd_log_wallclock();

  double rate = (double)iter / ( (double)dt / 1e9 );
  double ns   = (double)dt / (double)iter;
  FD_LOG_NOTICE(( "bench_query_miss: %lu iters in %.3fs  (%.0f ops/s, %.1f ns/op)",
                  iter, (double)dt/1e9, rate, ns ));

  ledger_destroy( ledger, mem );
}

static void
bench_mixed( void ) {
  ulong max_shreds = 1UL<<16;
  void * mem;
  fd_ledger_t * ledger = ledger_create( &mem, max_shreds );

  uchar shred[ FD_SHRED_MAX_SZ ];
  uchar out  [ FD_SHRED_MAX_SZ ];
  fd_memset( shred, 0xAB, FD_SHRED_MAX_SZ );

  /* Pre-fill half */
  for( ulong i=0UL; i<max_shreds/2UL; i++ ) {
    fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, i, 0U );
  }

  ulong iter    = max_shreds * 4UL;
  ulong next_slot = max_shreds / 2UL;

  /* Benchmark: interleaved insert + query */
  long dt = -fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) {
    if( i & 1UL ) {
      /* query a populated entry */
      ulong slot = i % (max_shreds/2UL);
      fd_ledger_query( ledger, out, slot, 0U );
    } else {
      fd_ledger_insert( ledger, shred, FD_SHRED_MAX_SZ, next_slot++, 0U );
    }
  }
  dt += fd_log_wallclock();

  double rate = (double)iter / ( (double)dt / 1e9 );
  double ns   = (double)dt / (double)iter;
  FD_LOG_NOTICE(( "bench_mixed: %lu iters in %.3fs  (%.0f ops/s, %.1f ns/op)",
                  iter, (double)dt/1e9, rate, ns ));

  ledger_destroy( ledger, mem );
}

/* ==== Main ========================================================= */

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  /* Unit tests */
  test_key_pack();
  test_footprint();
  test_lifecycle();
  test_insert_query_basic();
  test_multiple_shreds_same_slot();
  test_multiple_slots();
  test_duplicate_insert();
  test_ring_eviction();
  test_full_eviction_cycle();
  test_evict_highest_shred();
  test_small_payload();
  test_capacity_one();
  test_many_wraps();
  test_interleaved_slots();
  test_shred_index_zero();
  test_large_slot();
  test_partial_slot_eviction();
  test_reinsert_after_eviction();
  test_non_contiguous_indices();
  test_stress();

  /* Benchmarks */
  bench_insert();
  bench_query_hit();
  bench_query_miss();
  bench_mixed();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
