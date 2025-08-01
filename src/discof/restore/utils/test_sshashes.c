#include "../../../util/fd_util.h"
#include "fd_sshashes.h"

static int
update_sshashes( fd_sshashes_t * sshashes,
                 ulong           full_slot,
                 ulong           inc_slot,
                 char *          pubkey,
                 ulong           pubkey_len,
                 char *          full_hash,
                 ulong           full_hash_len,
                 char *          inc_hash,
                 ulong           inc_hash_len ) {
  fd_gossip_upd_snapshot_hashes_t snapshot_hashes_msg;
  snapshot_hashes_msg.full->slot = full_slot;
  fd_memset( snapshot_hashes_msg.full->hash, 0, FD_HASH_FOOTPRINT );
  fd_memcpy( snapshot_hashes_msg.full->hash, full_hash, full_hash_len );
  snapshot_hashes_msg.inc_len         = 1UL;
  snapshot_hashes_msg.inc[ 0UL ].slot = inc_slot;
  fd_memset( snapshot_hashes_msg.inc[ 0UL ].hash, 0, FD_HASH_FOOTPRINT );
  fd_memcpy( snapshot_hashes_msg.inc[ 0UL ].hash, inc_hash, inc_hash_len );

  uchar msg_pubkey[ FD_HASH_FOOTPRINT ];
  fd_memset( msg_pubkey, 0, FD_HASH_FOOTPRINT );
  fd_memcpy( msg_pubkey, pubkey, pubkey_len );

  return fd_sshashes_update( sshashes, msg_pubkey, &snapshot_hashes_msg );
}

static int
query_sshashes( fd_sshashes_t * sshashes,
                ulong           full_slot,
                ulong           inc_slot,
                char *          full_hash,
                ulong           full_hash_len,
                char *          inc_hash,
                ulong           inc_hash_len ) {
  fd_sshashes_entry_t full_entry;
  full_entry.slot = full_slot;
  fd_memset( full_entry.hash, 0, FD_HASH_FOOTPRINT );
  fd_memcpy( full_entry.hash, full_hash, full_hash_len );

  fd_sshashes_entry_t inc_entry;
  inc_entry.slot = inc_slot;
  fd_memset( inc_entry.hash, 0, FD_HASH_FOOTPRINT );
  fd_memcpy( inc_entry.hash, inc_hash, inc_hash_len );

  return fd_sshashes_query( sshashes, &full_entry, &inc_entry );
}

/* Test that a basic insert followed by a query is successful */
static void
test_basic_insert( fd_sshashes_t * sshashes ) {
  char known_validators_pubkeys[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_BASE58_ENCODED_32_SZ ];
  uchar known_validators[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_HASH_FOOTPRINT ] = {
    "1",
  };
  for( ulong i=0UL; i<1UL; i++ ) {
    fd_base58_encode_32( known_validators[ i ], NULL, known_validators_pubkeys[ i ] );
  }

  fd_sshashes_init( sshashes, known_validators_pubkeys, 1UL );

  
  FD_TEST( update_sshashes( sshashes, 1UL, 2UL, "1", 1UL, "1", 1UL, "1", 1UL )==FD_SSHASHES_SUCCESS );
  FD_TEST( query_sshashes( sshashes, 1UL, 2UL, "1", 1UL, "1", 1UL ) );

  fd_sshashes_reset( sshashes );
}

/* Test that only a query with the correct slots and hashes succeeds */
static void
test_basic_query( fd_sshashes_t * sshashes ) {
  char known_validators_pubkeys[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_BASE58_ENCODED_32_SZ ];
  uchar known_validators[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_HASH_FOOTPRINT ] = {
    "1",
  };
  for( ulong i=0UL; i<1UL; i++ ) {
    fd_base58_encode_32( known_validators[ i ], NULL, known_validators_pubkeys[ i ] );
  }

  fd_sshashes_init( sshashes, known_validators_pubkeys, 1UL );

  FD_TEST( update_sshashes( sshashes, 1UL, 4UL, "1", 1UL, "1", 1UL, "1", 1UL )==FD_SSHASHES_SUCCESS );

  FD_TEST( query_sshashes( sshashes, 1UL, 4UL, "1", 1UL, "1", 1UL ) ); /* success */

  FD_TEST( !query_sshashes( sshashes, 2UL, 4UL, "1", 1UL, "1", 1UL ) ); /* wrong full slot */
  FD_TEST( !query_sshashes( sshashes, 2UL, 5UL, "1", 1UL, "1", 1UL ) ); /* wrong inc slot */
  FD_TEST( !query_sshashes( sshashes, 1UL, 4UL, "2", 1UL, "1", 1UL ) ); /* wrong full hash */
  FD_TEST( !query_sshashes( sshashes, 1UL, 4UL, "1", 1UL, "2", 1UL ) ); /* wrong inc hash */

  fd_sshashes_reset( sshashes );
}

/* Test that a previously inserted SnapshotHashes message is replaced
   by a more recent SnapshotHashes message from the same validator. */
static void
test_basic_replace( fd_sshashes_t * sshashes ) {
  char known_validators_pubkeys[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_BASE58_ENCODED_32_SZ ];
  uchar known_validators[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_HASH_FOOTPRINT ] = {
    "1",
  };
  for( ulong i=0UL; i<1UL; i++ ) {
    fd_base58_encode_32( known_validators[ i ], NULL, known_validators_pubkeys[ i ] );
  }
  fd_sshashes_init( sshashes, known_validators_pubkeys, 1UL );

  FD_TEST( update_sshashes( sshashes, 1UL, 2UL, "1", 1UL,  "1", 1UL,  "1", 1UL )==FD_SSHASHES_SUCCESS );
  FD_TEST( update_sshashes( sshashes, 1UL, 3UL, "1", 1UL, "1", 1UL, "2", 1UL )==FD_SSHASHES_SUCCESS );

  /* Querying for the old snapshothashes message should fail */
  FD_TEST( !query_sshashes( sshashes, 1UL, 2UL, "1", 1UL, "1", 1UL ) );

  /* Querying for the new snapshothashes message should succeed */
  FD_TEST( query_sshashes( sshashes, 1UL, 3UL, "1", 1UL, "2", 1UL ) );

  fd_sshashes_reset( sshashes );
}

/* Test that a known validator is blacklisted when its SnapshotHashes
   message contains the same slot but a differing hash than a previously
   received SnapshotHashes message from a known validator. */
static void
test_validator_blacklist( fd_sshashes_t * sshashes ) {
  char known_validators_pubkeys[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_BASE58_ENCODED_32_SZ ];
  uchar known_validators[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_HASH_FOOTPRINT ] = {
    "10",
    "11",
  };
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_base58_encode_32( known_validators[ i ], NULL, known_validators_pubkeys[ i ] );
  }

  fd_sshashes_init( sshashes, known_validators_pubkeys, 2UL );

  FD_TEST( update_sshashes( sshashes, 1UL, 2UL, "10", 2UL, "1", 1UL, "1", 1UL )==FD_SSHASHES_SUCCESS );
  FD_TEST( update_sshashes( sshashes, 1UL, 3UL, "11", 2UL, "1", 1UL, "2", 1UL )==FD_SSHASHES_SUCCESS );

  /* Test that snapshot hashes messages are queryable */
  FD_TEST( query_sshashes( sshashes, 1UL, 2UL, "1", 1UL, "1", 1UL ) );
  FD_TEST( query_sshashes( sshashes, 1UL, 3UL, "1", 1UL, "2", 1UL ) );

  /* Test that a snapshot hash with same slot but different hash is rejected */
  FD_TEST( update_sshashes( sshashes, 1UL, 3UL, "10", 2UL, "1", 1UL, "1", 1UL )==FD_SSHASHES_REJECT );

  /* Test that incremental slot of 2 is no longer queryable */
  FD_TEST( !query_sshashes( sshashes, 1UL, 2UL, "1", 1UL, "1", 1UL ) );

  /* Test that validator 10 is blacklisted */
  FD_TEST( update_sshashes( sshashes, 1UL, 4UL, "10", 2UL, "1", 1UL, "3", 1UL )==FD_SSHASHES_REJECT );
  FD_TEST( update_sshashes( sshashes, 1UL, 4UL, "11", 2UL, "1", 1UL, "3", 1UL )==FD_SSHASHES_SUCCESS );

  fd_sshashes_reset( sshashes );
}

static void
test_multi_validator( fd_sshashes_t * sshashes ) {
  char known_validators_pubkeys[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_BASE58_ENCODED_32_SZ ];
  uchar known_validators[ FD_SSHASHES_KNOWN_VALIDATORS_MAX ][ FD_HASH_FOOTPRINT ] = {
    "10",
    "11",
    "12"
  };
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_base58_encode_32( known_validators[ i ], NULL, known_validators_pubkeys[ i ] );
  }

  fd_sshashes_init( sshashes, known_validators_pubkeys, 3UL );

  FD_TEST( update_sshashes( sshashes, 1UL, 2UL, "10", 2UL, "1", 1UL, "1", 1UL )==FD_SSHASHES_SUCCESS );
  FD_TEST( update_sshashes( sshashes, 1UL, 3UL, "11", 2UL, "1", 1UL, "2", 1UL )==FD_SSHASHES_SUCCESS );
  FD_TEST( update_sshashes( sshashes, 1UL, 4UL, "12", 2UL, "1", 1UL, "3", 1UL )==FD_SSHASHES_SUCCESS );
  fd_sshashes_print( sshashes );

  /* Test that snapshot hashes messages are queryable */
  FD_TEST( query_sshashes( sshashes, 1UL, 2UL, "1", 1UL, "1", 1UL ) );
  FD_TEST( query_sshashes( sshashes, 1UL, 3UL, "1", 1UL, "2", 1UL ) );
  FD_TEST( query_sshashes( sshashes, 1UL, 4UL, "1", 1UL, "3", 1UL ) );

  /* Update validator 10 */
  FD_TEST( update_sshashes( sshashes, 1UL, 4UL, "10", 2UL, "1", 1UL, "3", 1UL )==FD_SSHASHES_SUCCESS );
  fd_sshashes_print( sshashes );

  /* Test that incremental slot of 2 is no longer queryable */
  FD_TEST( !query_sshashes( sshashes, 1UL, 2UL, "1", 1UL, "1", 1UL ) );

  /* Test that incremental slot of 4 is queryable */
  FD_TEST( query_sshashes( sshashes, 1UL, 4UL, "1", 1UL, "3", 1UL ) );

  /* update validator 10 to incremental slot 5 */
  FD_TEST( update_sshashes( sshashes, 1UL, 5UL, "10", 2UL, "1", 1UL, "4", 1UL )==FD_SSHASHES_SUCCESS );
  fd_sshashes_print( sshashes );

  /* Test that incremental slot of 4 is queryable (via validator 12)*/
  FD_TEST( query_sshashes( sshashes, 1UL, 4UL, "1", 1UL, "3", 1UL ) );

  /* Test that incremental slot of 5 is queryable */
  FD_TEST( query_sshashes( sshashes, 1UL, 5UL, "1", 1UL, "4", 1UL ) );

  FD_TEST( update_sshashes( sshashes, 1UL, 5UL, "12", 2UL, "1", 1UL, "4", 1UL )==FD_SSHASHES_SUCCESS );
  fd_sshashes_print( sshashes );

  /* Test that incremental slot of 3 is queryable (via validator 11)*/
  FD_TEST( query_sshashes( sshashes, 1UL, 3UL, "1", 1UL, "2", 1UL ) );

  /* Test that incremental slot of 4 no longer queryable */
  FD_TEST( !query_sshashes( sshashes, 1UL, 4UL, "1", 1UL, "3", 1UL ) );

  /* Test that incremental slot of 5 is queryable */
  FD_TEST( query_sshashes( sshashes, 1UL, 5UL, "1", 1UL, "4", 1UL ) );

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
  fd_sshashes_t * sshashes = fd_sshashes_join( fd_sshashes_new( sshashes_mem, NULL, 0UL ) );

  test_basic_insert( sshashes );

  test_basic_query( sshashes );

  test_basic_replace( sshashes );

  test_validator_blacklist( sshashes );

  test_multi_validator( sshashes );

  fd_wksp_free_laddr( fd_sshashes_delete( fd_sshashes_leave( sshashes ) ) );

  return 0;
}
