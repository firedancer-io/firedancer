#include "fd_blockstore.h"

int
test_query_missing_shreds( fd_blockstore_t * blockstore ) {
  fd_blockstore_missing_shreds_t missing_shreds = { 0 };

  fd_slot_meta_t slot_meta = {
      .slot                  = 1,
      .consumed              = 0,
      .received              = 7,
      .first_shred_timestamp = 0,
  };

  fd_shred_t shred = { 0 };
  shred.slot       = 42;
  shred.idx        = 7;
  shred.data.flags = 3; // reference tick = 3

  (void)blockstore;
  (void)slot_meta;
  (void)missing_shreds;
  (void)shred;
  return 0;

  // fd_blockstore_upsert_shred(blockstore,  );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  if( FD_UNLIKELY( argc > 1 ) ) FD_LOG_ERR( ( "unrecognized argument: %s", argv[1] ) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      FD_SHMEM_HUGE_PAGE_SZ, 1, fd_shmem_cpu_idx( fd_shmem_numa_idx( 0 ) ), "wksp", 0UL );
  FD_TEST( wksp );

  ulong   blockstore_shred_footprint = fd_blockstore_shred_footprint( FD_SHRED_MAX_PER_SLOT );
  uchar * blockstore_shred_mem       = (uchar *)fd_wksp_alloc_laddr(
      wksp, fd_blockstore_shred_align(), blockstore_shred_footprint, 1UL );
  FD_TEST( blockstore_shred_mem );
  fd_blockstore_shred_t * shreds = fd_blockstore_shred_join(
      fd_blockstore_shred_new( blockstore_shred_mem, FD_SHRED_MAX_PER_SLOT, 42UL ) );
  FD_TEST( shreds );

  fd_blockstore_t blockstore = { .shreds = shreds, .slot_metas = NULL }; // TODO

  for( ulong i = 0; i < FD_SHRED_MAX_PER_SLOT; i++ ) {
    for( uint j = 0; j < FD_SHRED_MAX_PER_SLOT; j++ ) {
      fd_shred_t shred = { 0 };
      shred.slot       = i;
      shred.idx        = j;
      FD_TEST( fd_blockstore_upsert_shred( &blockstore, &shred, 0 ) == FD_BLOCKSTORE_OK );
    }
  }

  for( ulong i = 0; i < FD_SHRED_MAX_PER_SLOT; i++ ) {
    for( uint j = 0; j < FD_SHRED_MAX_PER_SLOT; j++ ) {
      fd_blockstore_key_t     key   = { .slot = i, .shred_idx = j };
      fd_blockstore_shred_t * shred = fd_blockstore_shred_query( shreds, &key, NULL );
      FD_TEST( shred );
      // FD_TEST( shred->shred.slot == i );
      // FD_TEST( shred->shred.idx == j );
    }
  }

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
