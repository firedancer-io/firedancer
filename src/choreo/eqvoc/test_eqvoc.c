#include "fd_eqvoc.h"
#include <stdlib.h>

void
test_eqvoc_test( fd_eqvoc_t * eqvoc ) {

  /* Insert 13-15, 15-20 */

  fd_shred_t shred13 = { .variant     = 0x60,
                         .slot        = 42,
                         .idx         = 1,
                         .fec_set_idx = 13,
                         .signature   = { 13 },
                         .code        = { .data_cnt = 3 } };
  fd_eqvoc_insert( eqvoc, &shred13 );
  fd_shred_t shred15 = { .variant     = 96,
                         .slot        = 42,
                         .idx         = 1,
                         .fec_set_idx = 15,
                         .signature   = { 15 },
                         .code        = { .data_cnt = 6 } };
  FD_TEST( !fd_eqvoc_test( eqvoc, &shred15 ) );
}

void
test_eqvoc_from_chunks( fd_eqvoc_t * eqvoc,
                        fd_alloc_t * alloc,
                        ulong        shred1_sz,
                        ulong        shred2_sz,
                        ulong        chunk_len ) {
  uchar *      shred1_bytes = fd_alloc_malloc( alloc, 1, shred1_sz );
  fd_shred_t * shred1_out   = (fd_shred_t *)fd_type_pun( shred1_bytes );
  uchar *      shred2_bytes = fd_alloc_malloc( alloc, 1, shred2_sz );
  fd_shred_t * shred2_out   = (fd_shred_t *)fd_type_pun( shred2_bytes );

  ulong sz        = ( shred1_sz + shred2_sz );
  uchar chunk_cnt = (uchar)( sz / chunk_len );
  chunk_cnt       = fd_uchar_if( (int)( sz % chunk_len ), chunk_cnt + 1, chunk_cnt );

  fd_gossip_duplicate_shred_t duplicate_shreds[chunk_cnt];
  for( uchar chunk_idx = 0; chunk_idx < chunk_cnt; chunk_idx++ ) {
    duplicate_shreds[chunk_idx].chunk_cnt = chunk_cnt;
    duplicate_shreds[chunk_idx].chunk_idx = chunk_idx;
    duplicate_shreds[chunk_idx].chunk_len = chunk_len;
    duplicate_shreds[chunk_idx].chunk     = fd_alloc_malloc( alloc, 1, chunk_len );
  }

  uchar shred1_ascii[6] = { 0x73, 0x68, 0x72, 0x65, 0x64, 0x31 };
  for( ulong i = 0; i < shred1_sz; i++ ) {
    if( FD_UNLIKELY( i == FD_SHRED_VARIANT_OFF ) ) {
      uchar variant = fd_uchar_if( shred1_sz == FD_SHRED_MIN_SZ,
                                   FD_SHRED_TYPE_MERKLE_DATA_CHAINED,
                                   FD_SHRED_TYPE_MERKLE_CODE_CHAINED );
      duplicate_shreds[i / chunk_len].chunk[i % chunk_len] = variant;
    } else {
      duplicate_shreds[i / chunk_len].chunk[i % chunk_len] = shred1_ascii[i % 6];
    }
  }

  uchar shred2_ascii[6] = { 0x73, 0x68, 0x72, 0x65, 0x64, 0x32 };
  for( ulong i = shred1_sz; i < shred1_sz + shred2_sz; i++ ) {
    if( FD_UNLIKELY( i == FD_SHRED_VARIANT_OFF ) ) {
      uchar variant = fd_uchar_if( shred2_sz == FD_SHRED_MIN_SZ,
                                   FD_SHRED_TYPE_MERKLE_DATA_CHAINED,
                                   FD_SHRED_TYPE_MERKLE_CODE_CHAINED );
      duplicate_shreds[i / chunk_len].chunk[i % chunk_len] = variant;
    } else {
      duplicate_shreds[i / chunk_len].chunk[i % chunk_len] = shred2_ascii[i % 6];
    }
  }

  fd_eqvoc_from_chunks( eqvoc, duplicate_shreds, shred1_out, shred2_out );

  /* Check the shred1 chunks */

  ulong k = shred1_sz / chunk_len;
  for( ulong i = 0; i < k; i++ ) {
    FD_TEST( 0 == memcmp( duplicate_shreds[i].chunk, shred1_bytes + i * chunk_len, chunk_len ) );
  }

  /* Check the kth chunk contains both shred1 and shred2 */

  ulong rem = shred1_sz - ( k * chunk_len );
  FD_TEST( 0 == memcmp( duplicate_shreds[k].chunk, shred1_bytes + ( k * chunk_len ), rem ) );
  ulong off = chunk_len - rem;
  FD_TEST( 0 == memcmp( duplicate_shreds[k].chunk + rem, shred2_bytes, off ) );

  /* Check the shred2 chunks */

  for( ulong i = k + 1; i < chunk_cnt; i++ ) {
    FD_TEST( 0 == memcmp( duplicate_shreds[i].chunk,
                          shred2_bytes + off,
                          fd_ulong_min( chunk_len, shred2_sz - off ) ) );
    off += chunk_len;
  }

  // for (ulong i = 0; i < k; i ++) {
  //   FD_TEST( 0 == memcmp( duplicate_shreds[2].chunk, shred2_bytes + len, shred2_sz - len ) );
  // }

  // FD_TEST( 0 == memcmp( duplicate_shreds[0].chunk, shred1_bytes, chunk_len ) );
  // ulong rem = shred1_sz - chunk_len;
  // FD_TEST( 0 == memcmp( duplicate_shreds[1].chunk, shred1_bytes + chunk_len, rem ) );
  // ulong len = chunk_len - rem;
  // FD_TEST( 0 == memcmp( duplicate_shreds[1].chunk + rem, shred2_bytes, len ) );
  // FD_TEST( 0 == memcmp( duplicate_shreds[2].chunk, shred2_bytes + len, shred2_sz - len ) );
}

void
test_eqvoc_to_chunks( fd_eqvoc_t * eqvoc,
                      fd_alloc_t * alloc,
                      ulong        shred1_sz,
                      ulong        shred2_sz,
                      ulong        chunk_len ) {
  uchar * shred1_bytes = fd_alloc_malloc( alloc, 1, shred1_sz );
  uchar * shred2_bytes = fd_alloc_malloc( alloc, 1, shred2_sz );

  uchar shred1_ascii[6] = { 0x73, 0x68, 0x72, 0x65, 0x64, 0x31 };
  uchar shred2_ascii[6] = { 0x73, 0x68, 0x72, 0x65, 0x64, 0x32 };

  for( ulong i = 0; i < shred1_sz; i++ ) {
    shred1_bytes[i] = shred1_ascii[i % 6];
  }
  for( ulong i = 0; i < shred2_sz; i++ ) {
    shred2_bytes[i] = shred2_ascii[i % 6];
  }

  fd_shred_t * shred1 = (fd_shred_t *)fd_type_pun( shred1_bytes );
  shred1->variant     = fd_uchar_if( shred1_sz == FD_SHRED_MIN_SZ,
                                 FD_SHRED_TYPE_MERKLE_DATA_CHAINED,
                                 FD_SHRED_TYPE_MERKLE_CODE_CHAINED );
  fd_shred_t * shred2 = (fd_shred_t *)fd_type_pun( shred2_bytes );
  shred2->variant     = fd_uchar_if( shred2_sz == FD_SHRED_MIN_SZ,
                                 FD_SHRED_TYPE_MERKLE_DATA_CHAINED,
                                 FD_SHRED_TYPE_MERKLE_CODE_CHAINED );

  ulong sz        = ( shred1_sz + shred2_sz );
  ulong chunk_cnt = sz / chunk_len;
  chunk_cnt       = fd_ulong_if( (int)( sz % chunk_len ), chunk_cnt + 1, chunk_cnt );

  fd_gossip_duplicate_shred_t duplicate_shreds[chunk_cnt];
  for( ulong i = 0; i < chunk_cnt; i++ ) {
    duplicate_shreds[i].chunk = fd_alloc_malloc( alloc, 1, chunk_len );
  }

  fd_eqvoc_to_chunks( eqvoc, shred1, shred2, chunk_len, duplicate_shreds );

  /* Check the shred1 chunks */

  ulong k = shred1_sz / chunk_len;
  for( ulong i = 0; i < k; i++ ) {
    FD_TEST( 0 == memcmp( duplicate_shreds[i].chunk, shred1_bytes + i * chunk_len, chunk_len ) );
  }

  /* Check the kth chunk contains both shred1 and shred2 */

  ulong rem = shred1_sz - ( k * chunk_len );
  FD_TEST( 0 == memcmp( duplicate_shreds[k].chunk, shred1_bytes + ( k * chunk_len ), rem ) );
  ulong off = chunk_len - rem;
  FD_TEST( 0 == memcmp( duplicate_shreds[k].chunk + rem, shred2_bytes, off ) );

  /* Check the shred2 chunks */

  for( ulong i = k + 1; i < chunk_cnt; i++ ) {
    FD_TEST( 0 == memcmp( duplicate_shreds[i].chunk,
                          shred2_bytes + off,
                          fd_ulong_min( chunk_len, shred2_sz - off ) ) );
    off += chunk_len;
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
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                            page_cnt,
                                            fd_shmem_cpu_idx( numa_idx ),
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );

  ulong  key_max   = 1 << 10UL;
  void * eqvoc_mem = fd_wksp_alloc_laddr( wksp,
                                          fd_eqvoc_align(),
                                          fd_eqvoc_footprint( key_max ),
                                          1UL );
  FD_TEST( eqvoc_mem );
  fd_eqvoc_t * eqvoc = fd_eqvoc_join( fd_eqvoc_new( eqvoc_mem, key_max, 0UL ) );

  void *       alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  fd_alloc_t * alloc     = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 1UL );

  test_eqvoc_test( eqvoc );

  // test_eqvoc_to_chunks( eqvoc, FD_SHRED_MAX_SZ, FD_SHRED_MAX_SZ, FD_EQVOC_CHUNK_MAX );

  ulong shred_szs[2]  = { FD_SHRED_MIN_SZ, FD_SHRED_MAX_SZ };
  ulong chunk_lens[4] = { FD_EQVOC_CHUNK_MAX, 117, 42, 10 };

  for( ulong i = 0; i < sizeof( shred_szs ) / sizeof( ulong ); i++ ) {
    for( ulong j = 0; j < sizeof( shred_szs ) / sizeof( ulong ); j++ ) {
      for( ulong k = 0; k < sizeof( chunk_lens ) / sizeof( ulong ); k++ ) {
        test_eqvoc_from_chunks( eqvoc, alloc, shred_szs[i], shred_szs[j], chunk_lens[k] );
        test_eqvoc_to_chunks( eqvoc, alloc, shred_szs[i], shred_szs[j], chunk_lens[k] );
      }
    }
  }

  fd_wksp_free_laddr( eqvoc_mem );

  fd_halt();
  return 0;
}
