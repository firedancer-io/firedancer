#include "../../../util/fd_util.h"
#include "fd_sshashes.h"

static uchar pubkey1[] = "1111111111111111111111111111111";
static uchar pubkey2[] = "2222222222222222222222222222222";
static uchar pubkey3[] = "3333333333333333333333333333333";

static void
basic_update( fd_sshashes_t * sshashes,
              ulong           full_slot,
              ulong           inc_slot,
              uchar *         pubkey ) {
  fd_gossip_upd_snapshot_hashes_t snapshot_hashes_msg;
  snapshot_hashes_msg.full->slot = full_slot;
  fd_memcpy( snapshot_hashes_msg.full->hash, pubkey1, FD_HASH_FOOTPRINT );
  snapshot_hashes_msg.inc_len = 1UL;
  snapshot_hashes_msg.inc[ 0 ].slot = inc_slot;
  fd_memcpy( snapshot_hashes_msg.inc[ 0 ].hash, pubkey2, FD_HASH_FOOTPRINT );

  uchar msg_pubkey[ FD_HASH_FOOTPRINT ];
  fd_memcpy( msg_pubkey, pubkey, FD_HASH_FOOTPRINT );

  int err = fd_sshashes_update( sshashes, msg_pubkey, &snapshot_hashes_msg );
  FD_TEST( err==FD_SSHASHES_SUCCESS );
}

static void
test_basic_insert( fd_sshashes_t * sshashes ) {
  /* test basic insert */
  basic_update( sshashes, 1UL, 2UL, pubkey3 );

  fd_sshashes_entry_t full_entry;
  full_entry.slot = 1UL;
  fd_memcpy( full_entry.sshash, pubkey1, FD_HASH_FOOTPRINT );

  fd_sshashes_entry_t inc_entry;
  inc_entry.slot = 2UL;
  fd_memcpy( inc_entry.sshash, pubkey2, FD_HASH_FOOTPRINT );

  int err = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( err==FD_SSHASHES_SUCCESS );
}

static void
test_basic_update( fd_sshashes_t * sshashes ) {
  basic_update( sshashes, 1UL, 3UL, pubkey3 );

  fd_sshashes_entry_t full_entry;
  full_entry.slot = 1UL;
  fd_memcpy( full_entry.sshash, pubkey1, FD_HASH_FOOTPRINT );

  fd_sshashes_entry_t inc_entry;
  inc_entry.slot = 2UL;
  fd_memcpy( inc_entry.sshash, pubkey2, FD_HASH_FOOTPRINT );

  int err = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( err==FD_SSHASHES_ERROR );

  inc_entry.slot = 3UL;
  err = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( err==FD_SSHASHES_SUCCESS );
}

static void
test_basic_query( fd_sshashes_t * sshashes ) {
  basic_update( sshashes, 1UL, 4UL, pubkey2 );

  fd_sshashes_entry_t full_entry;
  full_entry.slot = 1UL;
  fd_memcpy( full_entry.sshash, pubkey1, FD_HASH_FOOTPRINT );

  fd_sshashes_entry_t inc_entry;
  inc_entry.slot = 4UL;
  fd_memcpy( inc_entry.sshash, pubkey2, FD_HASH_FOOTPRINT );

  int err = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( err==FD_SSHASHES_SUCCESS );

  full_entry.slot = 1UL;
  fd_memcpy( full_entry.sshash, pubkey2, FD_HASH_FOOTPRINT );

  inc_entry.slot = 4UL;
  fd_memcpy( inc_entry.sshash, pubkey2, FD_HASH_FOOTPRINT );

  err = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( err==FD_SSHASHES_ERROR ); /* wrong full hash */

  full_entry.slot = 1UL;
  fd_memcpy( full_entry.sshash, pubkey1, FD_HASH_FOOTPRINT );

  inc_entry.slot = 4UL;
  fd_memcpy( inc_entry.sshash, pubkey1, FD_HASH_FOOTPRINT );

  err = fd_sshashes_query( sshashes, &full_entry, &inc_entry );
  FD_TEST( err==FD_SSHASHES_ERROR ); /* wrong inc hash */
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

  /* test basic insert */
  test_basic_insert( sshashes );

  /* test basic update (remove then insert) */
  test_basic_update( sshashes );

  test_basic_query( sshashes );
  return 0;
}
