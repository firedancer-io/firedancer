#include "fd_blockstore.h"

/*
         slot 0
           |
         slot 1
         /    \
    slot 2    |
       |    slot 3
    slot 4    |
            slot 5
              |
            slot 6
*/
void
setup_blockstore( fd_blockstore_t * blockstore ) {
  fd_blockstore_clear( blockstore );

  fd_blockstore_slot_map_t * slot_map = fd_blockstore_slot_map( blockstore );
  FD_TEST( slot_map );

  ulong slots[7] = { 0, 1, 2, 3, 4, 5, 6 };
  for( ulong i = 0; i < 7; i++ ) {
    fd_blockstore_slot_map_t * insert = fd_blockstore_slot_map_insert( slot_map, slots[i] );
    FD_TEST( insert );
    insert->block.data_gaddr = slots[i]; /* necessary to fake the block */
  }

  for( ulong i = 0; i < 7; i++ ) {
    fd_block_t * query = fd_blockstore_block_query( blockstore, i );
    FD_TEST( query );
  }
}

void
test_blockstore_smr_update( fd_blockstore_t * blockstore,
                            ulong             smr,
                            ulong *           s,
                            ulong             s_cnt,
                            ulong *           sc,
                            ulong             sc_cnt ) {
  int rc;
  setup_blockstore( blockstore );

  FD_TEST( s_cnt + sc_cnt == 7 );

  rc = fd_blockstore_prune( blockstore, smr );
  FD_TEST( rc == FD_BLOCKSTORE_OK );

  for( ulong i = 0; i < s_cnt; i++ ) {
    FD_TEST( fd_blockstore_block_query( blockstore, s[i] ) );
  }

  for( ulong i = 0; i < sc_cnt; i++ ) {
    FD_TEST( !fd_blockstore_block_query( blockstore, sc[i] ) );
  }
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   page_cnt,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  void * blockstore_mem =
      fd_wksp_alloc_laddr( wksp, fd_blockstore_align(), fd_blockstore_footprint(), 42UL );
  fd_blockstore_t * blockstore = fd_blockstore_join(
      fd_blockstore_new( blockstore_mem, 42UL, FD_BLOCKSTORE_MAGIC, 1024, 1024, 10 ) );
  FD_TEST( blockstore );

  {
    ulong               smr   = 0;
    ulong               s[7]  = { 0, 1, 2, 3, 4, 5, 6 };
    __extension__ ulong sc[0] = {};
    test_blockstore_smr_update(
        blockstore, smr, s, sizeof( s ) / sizeof( ulong ), sc, sizeof( sc ) / sizeof( ulong ) );
  }

  {
    ulong smr   = 1;
    ulong s[6]  = { 1, 2, 4, 3, 5, 6 };
    ulong sc[1] = { 0 };
    test_blockstore_smr_update(
        blockstore, smr, s, sizeof( s ) / sizeof( ulong ), sc, sizeof( sc ) / sizeof( ulong ) );
  }

  {
    ulong smr   = 2;
    ulong s[2]  = { 2, 4 };
    ulong sc[4] = { 1, 3, 5, 6 };
    test_blockstore_smr_update(
        blockstore, smr, s, sizeof( s ) / sizeof( ulong ), sc, sizeof( sc ) / sizeof( ulong ) );
  }

  {
    ulong smr   = 4;
    ulong s[2]  = { 4 };
    ulong sc[5] = { 1, 3, 5, 6, 2 };
    test_blockstore_smr_update(
        blockstore, smr, s, sizeof( s ) / sizeof( ulong ), sc, sizeof( sc ) / sizeof( ulong ) );
  }

  {
    ulong smr   = 3;
    ulong s[3]  = { 3, 5, 6 };
    ulong sc[4] = { 0, 1, 2, 4 };
    test_blockstore_smr_update(
        blockstore, smr, s, sizeof( s ) / sizeof( ulong ), sc, sizeof( sc ) / sizeof( ulong ) );
  }

  {
    ulong smr   = 5;
    ulong s[2]  = { 5, 6 };
    ulong sc[5] = { 0, 1, 2, 4, 3 };
    test_blockstore_smr_update(
        blockstore, smr, s, sizeof( s ) / sizeof( ulong ), sc, sizeof( sc ) / sizeof( ulong ) );
  }

  {
    ulong smr   = 6;
    ulong s[1]  = { 6 };
    ulong sc[6] = { 0, 1, 2, 4, 3, 5 };
    test_blockstore_smr_update(
        blockstore, smr, s, sizeof( s ) / sizeof( ulong ), sc, sizeof( sc ) / sizeof( ulong ) );
  }

  FD_TEST( fd_blockstore_prune( blockstore, 7 ) == FD_BLOCKSTORE_ERR_SLOT_MISSING );

  fd_halt();
  return 0;
}
