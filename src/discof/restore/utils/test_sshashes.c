#include "../../../util/fd_util.h"
#include "fd_sshashes.h"

static int
update_sshashes( fd_sshashes_t * sshashes,
                 ulong           full_slot,
                 ulong           inc_slot,
                 char *          pubkey,
                 char *          full_hash,
                 char *          inc_hash ) {
  fd_gossip_upd_snapshot_hashes_t snapshot_hashes_msg;
  snapshot_hashes_msg.full->slot = full_slot;
  fd_memcpy( snapshot_hashes_msg.full->hash, full_hash, FD_HASH_FOOTPRINT );
  snapshot_hashes_msg.inc_len = 1UL;
  snapshot_hashes_msg.inc[ 0 ].slot = inc_slot;
  fd_memcpy( snapshot_hashes_msg.inc[ 0 ].hash, inc_hash, FD_HASH_FOOTPRINT );

  uchar msg_pubkey[ FD_HASH_FOOTPRINT ];
  fd_memcpy( msg_pubkey, pubkey, FD_HASH_FOOTPRINT );

  int err = fd_sshashes_update( sshashes, msg_pubkey, &snapshot_hashes_msg );
  return err;
}

/* Test that a basic insert followed by a query is successful */
static void
test_basic_insert( fd_sshashes_t * sshashes ) {
  FD_TEST( update_sshashes( sshashes, 1UL, 2UL, "1", "1", "1" )==FD_SSHASHES_SUCCESS );

  fd_sshashes_entry_t full_entry;
  full_entry.slot = 1UL;
  fd_memcpy( full_entry.hash, "1", FD_HASH_FOOTPRINT );

  fd_sshashes_entry_t inc_entry;
  inc_entry.slot = 2UL;
  fd_memcpy( inc_entry.hash, "1", FD_HASH_FOOTPRINT );

  int res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( res );

  fd_sshashes_reset( sshashes );
}

/* Test that only a query with the correct slots and hashes succeeds */
static void
test_basic_query( fd_sshashes_t * sshashes ) {
  FD_TEST( update_sshashes( sshashes, 1UL, 4UL, "1", "1", "1" )==FD_SSHASHES_SUCCESS );

  fd_sshashes_entry_t full_entry;
  full_entry.slot = 1UL;
  fd_memcpy( full_entry.hash, "1", FD_HASH_FOOTPRINT );

  fd_sshashes_entry_t inc_entry;
  inc_entry.slot = 4UL;
  fd_memcpy( inc_entry.hash, "1", FD_HASH_FOOTPRINT );

  int res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( res );

  full_entry.slot = 1UL;
  fd_memcpy( full_entry.hash, "2", FD_HASH_FOOTPRINT );

  inc_entry.slot = 4UL;
  fd_memcpy( inc_entry.hash, "1", FD_HASH_FOOTPRINT );

  res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( !res ); /* wrong full hash */

  full_entry.slot = 1UL;
  fd_memcpy( full_entry.hash, "1", FD_HASH_FOOTPRINT );

  inc_entry.slot = 4UL;
  fd_memcpy( inc_entry.hash, "2", FD_HASH_FOOTPRINT );

  res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( !res ); /* wrong inc hash */

  fd_sshashes_reset( sshashes );
}

/* Test that a previously inserted SnapshotHashes message is replaced
   by a more recent SnapshotHashes message from the same validator. */
static void
test_basic_replace( fd_sshashes_t * sshashes ) {
  FD_TEST( update_sshashes( sshashes, 1UL, 2UL, "1", "1", "1" )==FD_SSHASHES_SUCCESS );
  FD_TEST( update_sshashes( sshashes, 1UL, 3UL, "1", "1", "2" )==FD_SSHASHES_SUCCESS );

  fd_sshashes_entry_t full_entry;
  full_entry.slot = 1UL;
  fd_memcpy( full_entry.hash, "1", FD_HASH_FOOTPRINT );

  fd_sshashes_entry_t inc_entry;
  inc_entry.slot = 2UL;
  fd_memcpy( inc_entry.hash, "1", FD_HASH_FOOTPRINT );

  /* Querying for the old snapshothashes message should fail */
  int res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( !res );

  /* Querying for the new snapshothashes message should succeed */
  inc_entry.slot = 3UL;
  fd_memcpy( inc_entry.hash, "2", FD_HASH_FOOTPRINT );
  res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( res );

  fd_sshashes_reset( sshashes );
}

static void
test_multi_validator( fd_sshashes_t * sshashes ) {
  FD_TEST( update_sshashes( sshashes, 1UL, 2UL, "10", "1", "1" )==FD_SSHASHES_SUCCESS );
  FD_TEST( update_sshashes( sshashes, 1UL, 3UL, "11", "1", "2" )==FD_SSHASHES_SUCCESS );
  FD_TEST( update_sshashes( sshashes, 1UL, 4UL, "12", "1", "3" )==FD_SSHASHES_SUCCESS );

  /* Test that all three snapshot hashes messages are queryable */
  fd_sshashes_entry_t full_entry;
  full_entry.slot = 1UL;
  fd_memcpy( full_entry.hash, "1", FD_HASH_FOOTPRINT );

  fd_sshashes_entry_t inc_entry;
  inc_entry.slot = 2UL;
  fd_memcpy( inc_entry.hash, "1", FD_HASH_FOOTPRINT );
  int res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( res );

  inc_entry.slot = 3UL;
  fd_memcpy( inc_entry.hash, "2", FD_HASH_FOOTPRINT );
  res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( res );

  inc_entry.slot = 4UL;
  fd_memcpy( inc_entry.hash, "3", FD_HASH_FOOTPRINT );
  res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( res );

  /* Update validator 10 */
  FD_TEST( update_sshashes( sshashes, 1UL, 4UL, "10", "1", "3" )==FD_SSHASHES_SUCCESS );

  /* Test that incremental slot of 2 is no longer queryable */
  inc_entry.slot = 2UL;
  fd_memcpy( inc_entry.hash, "1", FD_HASH_FOOTPRINT );
  res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( !res );

  /* Test that incremental slot of 4 is queryable */
  inc_entry.slot = 4UL;
  fd_memcpy( inc_entry.hash, "3", FD_HASH_FOOTPRINT );
  res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( res );

  /* update validator 10 to incremental slot 5 */
  FD_TEST( update_sshashes( sshashes, 1UL, 5UL, "10", "1", "4" )==FD_SSHASHES_SUCCESS );

  /* Test that incremental slot of 4 is queryable (via validator 12)*/
  inc_entry.slot = 4UL;
  fd_memcpy( inc_entry.hash, "3", FD_HASH_FOOTPRINT );
  res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( res );

  /* Test that incremental slot of 5 is queryable */
  inc_entry.slot = 5UL;
  fd_memcpy( inc_entry.hash, "4", FD_HASH_FOOTPRINT );
  res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( res );

  FD_TEST( update_sshashes( sshashes, 1UL, 5UL, "12", "1", "4" )==FD_SSHASHES_SUCCESS );

  /* Test that incremental slot of 3 is queryable (via validator 11)*/
  inc_entry.slot = 3UL;
  fd_memcpy( inc_entry.hash, "2", FD_HASH_FOOTPRINT );
  res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( res );

  /* Test that incremental slot of 4 no longer queryable */
  inc_entry.slot = 4UL;
  fd_memcpy( inc_entry.hash, "3", FD_HASH_FOOTPRINT );
  res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( !res );

  /* Test that incremental slot of 5 is queryable */
  inc_entry.slot = 5UL;
  fd_memcpy( inc_entry.hash, "4", FD_HASH_FOOTPRINT );
  res = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( res );

  fd_sshashes_reset( sshashes );
}

static void
test_limits( fd_sshashes_t * sshashes ) {
  /* Test that we can't insert more than FD_SSHASHES_MAP_KEY_MAX
     full SnapshotHashes entries */
  char pubkey[ FD_HASH_FOOTPRINT ];
  for( ulong i=0UL; i<FD_SSHASHES_MAP_KEY_MAX; i++ ) {
    fd_memset( pubkey, (char)(i), FD_HASH_FOOTPRINT );
    FD_TEST( update_sshashes( sshashes, i, 2000UL, pubkey, "1", "1" )==FD_SSHASHES_SUCCESS );
  }

  fd_memset( pubkey, (char)(33UL), FD_HASH_FOOTPRINT );
  FD_TEST( update_sshashes( sshashes, 33UL, 2000UL, pubkey, "1", "1" )==FD_SSHASHES_ERROR );

  fd_sshashes_reset( sshashes );

  /* Test that we can't insert more than FD_SSHASHES_MAP_KEY_MAX
     incremental SnapshotHashes entries */
  fd_memset( pubkey, (char)(0), FD_HASH_FOOTPRINT );
  FD_TEST( update_sshashes( sshashes, 1UL, 2UL, pubkey, "1", "1" )==FD_SSHASHES_SUCCESS );

  for( ulong i=1UL; i<FD_SSHASHES_MAP_KEY_MAX; i++ ) {
    fd_memset( pubkey, (char)(i), FD_HASH_FOOTPRINT );
    FD_TEST( update_sshashes( sshashes, 1UL, i+2UL, pubkey, "1", "1" )==FD_SSHASHES_SUCCESS );
  }

  fd_memset( pubkey, (char)(32UL), FD_HASH_FOOTPRINT );
  FD_TEST( update_sshashes( sshashes, 1UL, 34UL, pubkey, "1", "1" )==FD_SSHASHES_ERROR );

  fd_sshashes_reset( sshashes );
}

int
main( int argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );

  FD_TEST( wksp );
  void * sshashes_mem      = fd_wksp_alloc_laddr( wksp, fd_sshashes_align(), fd_sshashes_footprint(), 1UL );
  fd_sshashes_t * sshashes = fd_sshashes_join( fd_sshashes_new( sshashes_mem ) );

  test_basic_insert( sshashes );

  test_basic_query( sshashes );

  test_basic_replace( sshashes );

  test_multi_validator( sshashes );

  test_limits( sshashes );

  fd_wksp_free_laddr( fd_sshashes_delete( fd_sshashes_leave( sshashes ) ) );

  return 0;
}
