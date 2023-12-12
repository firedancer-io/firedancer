/* This file tests the ability of the blockstore to ingest shreds from RocksDB and piece them
 * together into blocks. */

#define _GNU_SOURCE /* See feature_test_macros(7) */

#define FD_TVU_TILE_SLOT_DELAY 32

#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../flamenco/runtime/fd_snapshot_loader.h"
#include "../../flamenco/types/fd_types.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../fd_flamenco.h"
#include "../gossip/fd_gossip.h"
#include "../repair/fd_repair.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );
  fd_valloc_t valloc = fd_libc_alloc_virtual();

  ulong  page_cnt = 10;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   page_cnt,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_blockstore_t blockstore = { 0 };

  void *       alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  fd_alloc_t * alloc     = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 0UL );
  blockstore.alloc       = alloc;

  ulong   blockstore_shred_max = 1 << 16; // 64kb
  uchar * blockstore_shred_mem =
      (uchar *)fd_wksp_alloc_laddr( wksp,
                                    fd_blockstore_shred_map_align(),
                                    fd_blockstore_shred_map_footprint( blockstore_shred_max ),
                                    1UL );
  FD_TEST( blockstore_shred_mem );
  fd_blockstore_shred_map_t * shred_map = fd_blockstore_shred_map_join(
      fd_blockstore_shred_map_new( blockstore_shred_mem, blockstore_shred_max, 42UL ) );
  FD_TEST( shred_map );
  blockstore.shred_map = shred_map;

  uchar * blockstore_slot_meta_mem = (uchar *)fd_wksp_alloc_laddr(
      wksp, fd_blockstore_slot_meta_map_align(), fd_blockstore_slot_meta_map_footprint( 5 ), 1UL );
  fd_blockstore_slot_meta_map_t * slot_meta_map = fd_blockstore_slot_meta_map_join(
      fd_blockstore_slot_meta_map_new( blockstore_slot_meta_mem, 5 ) );
  FD_TEST( slot_meta_map );
  blockstore.slot_meta_map = slot_meta_map;

  uchar * blockstore_block_mem = (uchar *)fd_wksp_alloc_laddr(
      wksp, fd_blockstore_block_map_align(), fd_blockstore_block_map_footprint( 5 ), 1UL );
  fd_blockstore_block_map_t * block_map =
      fd_blockstore_block_map_join( fd_blockstore_block_map_new( blockstore_block_mem, 5 ) );
  FD_TEST( block_map );
  blockstore.block_map = block_map;

  fd_rocksdb_t rocks_db;
  char * err = fd_rocksdb_init( &rocks_db, "/home/chali/projects/solana/test-ledger/rocksdb" );
  if( err != NULL ) { FD_LOG_ERR( ( "fd_rocksdb_init returned %s", err ) ); }

  fd_rocksdb_root_iter_t root_iter;
  fd_rocksdb_root_iter_new( &root_iter );

  fd_slot_meta_t m;
  fd_memset( &m, 0, sizeof( m ) );

  int rc = fd_rocksdb_root_iter_seek( &root_iter, &rocks_db, 0, &m, valloc );
  if( rc < 0 ) FD_LOG_ERR( ( "fd_rocksdb_root_iter_seek returned %d", rc ) );

  // FD_LOG_NOTICE( ( "m %lu %lu %lu", m.consumed, m.received, m.last_index ) );

  rc = fd_rocksdb_root_iter_next( &root_iter, &m, valloc );
  if( rc < 0 ) FD_LOG_ERR( ( "fd_rocksdb_root_iter_seek returned %d", rc ) );

  FD_LOG_NOTICE( ( "m %lu %lu %lu", m.consumed, m.received, m.last_index ) );

  rocksdb_iterator_t * iter =
      rocksdb_create_iterator_cf( rocks_db.db, rocks_db.ro, rocks_db.cf_handles[3] );

  ulong slot      = m.slot;
  ulong start_idx = 0;
  ulong end_idx   = m.received;

  char k[16];
  *( (ulong *)&k[0] ) = fd_ulong_bswap( slot );
  *( (ulong *)&k[8] ) = fd_ulong_bswap( start_idx );

  rocksdb_iter_seek( iter, (const char *)k, sizeof( k ) );

  for( ulong i = start_idx; i < end_idx; i++ ) {
    ulong cur_slot, index;
    uchar valid = rocksdb_iter_valid( iter );

    if( valid ) {
      size_t       klen = 0;
      const char * key  = rocksdb_iter_key( iter, &klen ); // There is no need to free key
      if( klen != 16 )                                     // invalid key
        continue;
      cur_slot = fd_ulong_bswap( *( (ulong *)&key[0] ) );
      index    = fd_ulong_bswap( *( (ulong *)&key[8] ) );
    }

    if( !valid || cur_slot != slot ) {
      FD_LOG_WARNING( ( "missing shreds for slot %ld", slot ) );
      rocksdb_iter_destroy( iter );
      return 1;
    }

    if( index != i ) {
      FD_LOG_WARNING( ( "missing shred %ld at index %ld for slot %ld", i, index, slot ) );
      rocksdb_iter_destroy( iter );
      return 1;
    }

    size_t dlen = 0;
    // Data was first copied from disk into memory to make it available to this API
    const unsigned char * data = (const unsigned char *)rocksdb_iter_value( iter, &dlen );
    if( data == NULL ) {
      FD_LOG_WARNING( ( "failed to read shred %ld/%ld", slot, i ) );
      rocksdb_iter_destroy( iter );
      return 1;
    }

    // This just correctly selects from inside the data pointer to the
    // actual data without a memory copy
    fd_shred_t const * shred = fd_shred_parse( data, (ulong)dlen );
    FD_LOG_HEXDUMP_NOTICE( ( "shred data", shred, fd_shred_sz( shred ) ) );

    // rc = fd_blockstore_shred_insert( &blockstore, shred );
    // FD_TEST( rc == FD_BLOCKSTORE_OK );

    rocksdb_iter_next( iter );
  }

  // fd_blockstore_shred_insert( blockstore, valloc);
  (void)blockstore;

  return 0;
}
