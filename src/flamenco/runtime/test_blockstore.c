#include "fd_blockstore.h"

#include <unistd.h>
#include <stdio.h>

struct __attribute__((packed)) fd_shred_cap_file_hdr {
  ushort magic;
  ushort shred_cap_hdr_sz;
};
typedef struct fd_shred_cap_file_hdr fd_shred_cap_file_hdr_t;

struct __attribute__((packed)) fd_shred_cap_hdr {
  ulong sz;
  uchar flags;
};
typedef struct fd_shred_cap_hdr fd_shred_cap_hdr_t;

// static const uchar shred_bytes[FD_SHRED_MIN_SZ] = { 12, 20, 88, 140, 221, 68, 111, 148, 187, 119, 30, 22, 42, 221, 65, 43, 93, 170, 201, 121, 37, 87, 253, 68, 228, 161, 159, 159, 149, 93, 96, 134, 155, 92, 2, 73, 33, 46, 100, 22, 245, 94, 0, 144, 43, 171, 120, 101, 93, 222, 110, 116, 17, 96, 149, 145, 33, 119, 0, 163, 70, 166, 206, 6, 149, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 1, 0, 42, 47, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 247, 131, 90, 55, 245, 41, 73, 211, 141, 173, 29, 87, 159, 58, 136, 18, 205, 115, 200, 64, 195, 242, 252, 120, 220, 58, 254, 31, 67, 199, 42, 81, 109, 14, 250, 128, 50, 24, 176, 41, 132, 8, 60, 164, 149, 81, 6, 236, 49, 238, 200, 131, 75, 27, 146, 57, 2, 85, 228, 37, 131, 223, 245, 89, 100, 51, 148, 245, 134, 194, 194, 110, 240, 25, 201, 234, 239, 3, 62, 134, 94, 74, 139, 131, 28, 116, 160, 239, 153, 61, 58, 57, 122, 55, 56, 220, 88, 16, 105, 185 };

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( "gigantic" ),
                                            50,
                                            fd_shmem_cpu_idx( fd_shmem_numa_idx( 0 ) ),
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );

  void * mem = fd_wksp_alloc_laddr( wksp, fd_blockstore_align(), fd_blockstore_footprint( 1048576, 4096, 4096, 1048576 ), 1UL );
  FD_TEST( mem );
  void * shblockstore = fd_blockstore_new( mem, 1UL, 42UL, 1048576, 4096, 4096, 1048576 );
  FD_TEST( shblockstore );
  fd_blockstore_t   blockstore_ljoin;
  fd_blockstore_t * blockstore = fd_blockstore_join( &blockstore_ljoin, shblockstore );
  fd_buf_shred_pool_reset( blockstore->shred_pool, 0 );

  blockstore->shmem->smr = 315134140;

  FILE * shred_cap = fopen( "/data/chali/testnet.shredcap", "rb" );
  FD_TEST( shred_cap );

  ulong cnt = 0;
  ulong dup_cnt = 0;
  ulong filter_cnt = 0;
  for( ;; ) {
    fd_shred_cap_hdr_t header;
    ulong nshredcap_hdr = fread( &header, sizeof( fd_shred_cap_hdr_t ), 1, shred_cap );
    // FD_LOG_NOTICE(( "nshredcap_hdr: %lu", header.sz ));
    if ( nshredcap_hdr != 1 ) break;

    uchar buffer[FD_SHRED_MAX_SZ];
    ulong shred_len = header.sz;
    ulong bytes_read = fread( buffer, sizeof( uchar ), shred_len, shred_cap );
    if ( bytes_read != shred_len ) break;

    fd_shred_t const * shred      = fd_shred_parse( buffer, shred_len );
    uchar              shred_type = fd_shred_type( shred->variant );
    if( shred_type == FD_SHRED_TYPE_LEGACY_DATA ||
        shred_type == FD_SHRED_TYPE_MERKLE_DATA ||
        shred_type == FD_SHRED_TYPE_MERKLE_DATA_CHAINED ||
        shred_type == FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED ) {
      if( !fd_blockstore_shreds_complete( blockstore, shred->slot ) ) {
        fd_blockstore_shred_insert( blockstore, shred );
        cnt++;
      } else {
        dup_cnt++;
      }
    } else {
      // FD_LOG_HEXDUMP_NOTICE(( "filtering", &shred_type, 1 ));
      filter_cnt++;
    }
    /*
    if ( FD_SHRED_CAP_FLAG_IS_TURBINE(header.flags) ) {
      fd_replay_turbine_rx( replay, shred, fd_shred_sz( shred ));
    } else {
      fd_replay_repair_rx( replay, shred );
    }
    */
  }
  FD_LOG_NOTICE(("inserted %lu %lu %lu shreds", cnt, dup_cnt, filter_cnt));

  // fd_shred_t * shred = (fd_shred_t *)fd_type_pun_const( shred_bytes );
  // ulong        slot  = shred->slot;
  // uint         idx   = shred->idx;
  // fd_blockstore_shred_insert( blockstore, shred );

  // fd_shred_key_t key = { slot, idx };
  // fd_buf_shred_map_query_t query;
  // int err = fd_buf_shred_map_query_try( blockstore->shred_map, &key, NULL, &query );
  // FD_TEST( err != FD_MAP_ERR_INVAL && err != FD_MAP_ERR_CORRUPT && err != FD_MAP_ERR_KEY );
  // err = fd_buf_shred_map_query_test( &query );
  // FD_TEST( err == FD_MAP_SUCCESS );

  fd_halt();
  return 0;
}
