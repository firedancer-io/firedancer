#include "fd_alpen.c"

void
test_insert_votes( fd_wksp_t * wksp ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_alpen_slot_votes_map_align(), fd_alpen_slot_votes_map_footprint(), 1UL );
  FD_TEST( mem );
  fd_alpen_slot_votes_t * slot_votes = fd_alpen_slot_votes_map_join( fd_alpen_slot_votes_map_new( mem ) );
  FD_TEST( slot_votes );

  ulong slot = 1;
  ulong validator_id = 0;
  fd_hash_t blockid0 = {{0}};
  fd_hash_t blockid1 = {{1}};
  fd_hash_t blockid2 = {{2}};

  notar_insert( slot_votes, &blockid0, slot, validator_id );
  skip_insert( slot_votes, slot, validator_id );

  for( ulong i = 0; i < 3; i++ ) {
    fd_hash_t blockid = {{(uchar)i}};
    notar_fallback_insert( slot_votes, &blockid, slot, validator_id );
  }

  skip_fallback_insert( slot_votes, slot, validator_id );
  finalize_insert( slot_votes, slot, validator_id );

  fd_alpen_slot_votes_t * notar_map = fd_alpen_slot_votes_query( slot_votes, slot );
  FD_TEST( notar_map->notar[validator_id].kind.type == FD_ALPEN_VOTE_NOTARIZE );
  FD_TEST( notar_map->notar[validator_id].kind.notar.slot == slot );

  FD_TEST( notar_map->skip[validator_id].kind.type == FD_ALPEN_VOTE_SKIP );
  FD_TEST( notar_map->skip[validator_id].kind.skip.slot == slot );

  FD_TEST( notar_map->notar_fallback[0][validator_id].kind.type == FD_ALPEN_VOTE_NOTARIZE_FALLBACK );
  FD_TEST( !memcmp( &notar_map->notar_fallback[0][validator_id].kind.notar_fallback.block_hash, &blockid0, sizeof(fd_hash_t) ) );
  FD_TEST( notar_map->notar_fallback[1][validator_id].kind.type == FD_ALPEN_VOTE_NOTARIZE_FALLBACK );
  FD_TEST( !memcmp( &notar_map->notar_fallback[1][validator_id].kind.notar_fallback.block_hash, &blockid1, sizeof(fd_hash_t) ) );
  FD_TEST( notar_map->notar_fallback[2][validator_id].kind.type == FD_ALPEN_VOTE_NOTARIZE_FALLBACK );
  FD_TEST( !memcmp( &notar_map->notar_fallback[2][validator_id].kind.notar_fallback.block_hash, &blockid2, sizeof(fd_hash_t) ) );

  FD_TEST( notar_map->skip_fallback[validator_id].kind.type == FD_ALPEN_VOTE_SKIP_FALLBACK );
  FD_TEST( notar_map->skip_fallback[validator_id].kind.skip_fallback.slot == slot );

  FD_TEST( notar_map->finalizes[validator_id].kind.type == FD_ALPEN_VOTE_FINALIZE );
  FD_TEST( notar_map->finalizes[validator_id].kind.final.slot == slot );

} // test_insert_votes

void
test_cert_insert_simple( fd_wksp_t * wksp ) {
  void * certmem = fd_wksp_alloc_laddr( wksp, fd_alpen_slot_certificates_map_align(), fd_alpen_slot_certificates_map_footprint(), 1UL );
  void * dequmem = fd_wksp_alloc_laddr( wksp, fd_alpen_parent_ready_deque_align(), fd_alpen_parent_ready_deque_footprint(), 1UL );
  FD_TEST( certmem );
  FD_TEST( dequmem );
  fd_alpen_slot_certificates_t * cert_pool = fd_alpen_slot_certificates_map_join( fd_alpen_slot_certificates_map_new( certmem ) );
  FD_TEST( cert_pool );
  fd_alpen_parent_ready_t * parent_ready_deque = fd_alpen_parent_ready_deque_join( fd_alpen_parent_ready_deque_new( dequmem ) );
  FD_TEST( parent_ready_deque );

  for( ulong i = 0; i < 2*FD_ALPEN_WINDOW_SZ; i++ ) {
      ulong next_window_slot = (i / FD_ALPEN_WINDOW_SZ + 1) * FD_ALPEN_WINDOW_SZ;
      fd_alpen_cert_t nf = {
          .type = FD_ALPEN_CERT_NOTAR_FALLBACK,
          .slot = i,
          .notar = {
              .block_id = {{(uchar)i}},
              .agg_sig_notar = {0}
          }
      };
      FD_LOG_NOTICE(( "Inserting notar fallback cert for slot %lu", i ));
      FD_TEST( notar_fallback_cert_insert( cert_pool, &nf ) == FD_ALPEN_CERT_SUCCESS );
      check_parent_ready( cert_pool, &nf, parent_ready_deque );
      if ( i % FD_ALPEN_WINDOW_SZ == FD_ALPEN_WINDOW_SZ - 1 ) {
          FD_TEST( !fd_alpen_parent_ready_deque_empty( parent_ready_deque ) );
          fd_alpen_parent_ready_t pr = fd_alpen_parent_ready_deque_pop_head( parent_ready_deque );
          FD_LOG_NOTICE(( "parent ready for slot %lu, parent slot: %lu", pr.slot, pr.parent_slot ));
          FD_TEST( pr.slot == next_window_slot );
      } else {
          FD_TEST( fd_alpen_parent_ready_deque_empty( parent_ready_deque ) );
      }
  }
}

void
test_cert_insert_skips( fd_wksp_t * wksp ) {
  void * certmem = fd_wksp_alloc_laddr( wksp, fd_alpen_slot_certificates_map_align(), fd_alpen_slot_certificates_map_footprint(), 1UL );
  void * dequmem = fd_wksp_alloc_laddr( wksp, fd_alpen_parent_ready_deque_align(), fd_alpen_parent_ready_deque_footprint(), 1UL );
  FD_TEST( certmem );
  FD_TEST( dequmem );
  fd_alpen_slot_certificates_t * cert_pool = fd_alpen_slot_certificates_map_join( fd_alpen_slot_certificates_map_new( certmem ) );
  FD_TEST( cert_pool );
  fd_alpen_parent_ready_t * parent_ready_deque = fd_alpen_parent_ready_deque_join( fd_alpen_parent_ready_deque_new( dequmem ) );
  FD_TEST( parent_ready_deque );

  /* For the window 4, 5, 6, 7 */

  ulong window_slot = 4;
  ulong window_end = 8;

  fd_alpen_cert_t notar = {
    .type = FD_ALPEN_CERT_NOTAR,
    .slot = window_slot,
    .notar = {
        .block_id = {{0}},
        .agg_sig_notar = {0}
    }
  };

  FD_TEST( notar_cert_insert( cert_pool, &notar ) == FD_ALPEN_CERT_SUCCESS );
  check_parent_ready( cert_pool, &notar, parent_ready_deque );
  FD_TEST( fd_alpen_parent_ready_deque_empty( parent_ready_deque ) );

  for( ulong i = window_slot + 1; i < window_end; i++ ) {
    fd_alpen_cert_t nf = {
        .type = FD_ALPEN_CERT_SKIP,
        .slot = i,
        .notar = {
            .block_id = {{(uchar)i}},
            .agg_sig_notar = {0}
        }
    };
    FD_LOG_NOTICE(( "Inserting skip cert for slot %lu", i ));
    FD_TEST( skip_cert_insert( cert_pool, &nf ) == FD_ALPEN_CERT_SUCCESS );
    check_parent_ready( cert_pool, &nf, parent_ready_deque );
    // last skip cert should enable parent ready
    if( i == window_end - 1 ) {
      FD_TEST( !fd_alpen_parent_ready_deque_empty( parent_ready_deque ) );
      fd_alpen_parent_ready_t pr = fd_alpen_parent_ready_deque_pop_head( parent_ready_deque );
      FD_LOG_NOTICE(( "parent ready for slot %lu, parent slot: %lu", pr.slot, pr.parent_slot ));
      FD_TEST( pr.slot == i + 1 );
    } else {
      FD_TEST( fd_alpen_parent_ready_deque_empty( parent_ready_deque ) );
    }
  }
}

void
test_cert_insert_ooo( fd_wksp_t * wksp ) {
  void * certmem = fd_wksp_alloc_laddr( wksp, fd_alpen_slot_certificates_map_align(), fd_alpen_slot_certificates_map_footprint(), 1UL );
  void * dequmem = fd_wksp_alloc_laddr( wksp, fd_alpen_parent_ready_deque_align(), fd_alpen_parent_ready_deque_footprint(), 1UL );
  FD_TEST( certmem );
  FD_TEST( dequmem );
  fd_alpen_slot_certificates_t * cert_pool = fd_alpen_slot_certificates_map_join( fd_alpen_slot_certificates_map_new( certmem ) );
  fd_alpen_parent_ready_t * parent_ready_deque = fd_alpen_parent_ready_deque_join( fd_alpen_parent_ready_deque_new( dequmem ) );
  FD_TEST( cert_pool );
  FD_TEST( parent_ready_deque );

  /* For the window 4, 5, 6, 7 */

  ulong window_slot = 4;
  ulong window_end  = 8;

  for( ulong i = window_slot + 1; i < window_end; i++ ) {
    fd_alpen_cert_t nf = {
        .type = FD_ALPEN_CERT_SKIP,
        .slot = i,
        .notar = {
            .block_id = {{(uchar)i}},
            .agg_sig_notar = {0}
        }
    };
    FD_LOG_NOTICE(( "Inserting skip cert for slot %lu", i ));
    FD_TEST( skip_cert_insert( cert_pool, &nf ) == FD_ALPEN_CERT_SUCCESS );
    check_parent_ready( cert_pool, &nf, parent_ready_deque );
    // no notars, so no parent ready
    FD_TEST( fd_alpen_parent_ready_deque_empty( parent_ready_deque ) );
  }

  fd_alpen_cert_t notar = {
    .type = FD_ALPEN_CERT_NOTAR_FALLBACK,
    .slot = window_slot,
    .notar = {
        .block_id = {{0}},
        .agg_sig_notar = {0}
    }
  };
  FD_TEST( notar_fallback_cert_insert( cert_pool, &notar ) == FD_ALPEN_CERT_SUCCESS );
  check_parent_ready( cert_pool, &notar, parent_ready_deque );

  FD_TEST( !fd_alpen_parent_ready_deque_empty( parent_ready_deque ) );
  fd_alpen_parent_ready_t pr = fd_alpen_parent_ready_deque_pop_head( parent_ready_deque );
  FD_TEST( pr.slot        == window_end );
  FD_TEST( pr.parent_slot == window_slot );
  FD_TEST( !memcmp( &pr.parent_hash, &notar.notar.block_id, sizeof(fd_hash_t) ) );
  FD_TEST( fd_alpen_parent_ready_deque_empty( parent_ready_deque ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 10;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_insert_votes( wksp );
  test_cert_insert_simple( wksp );
  test_cert_insert_skips( wksp );
  test_cert_insert_ooo( wksp );

  fd_halt();
  return 0;
}
