#include "../fd_tango.h"
#include "fd_lru.h"

#if FD_HAS_HOSTED

FD_STATIC_ASSERT( FD_LRU_ALIGN == 128UL, unit_test );

FD_STATIC_ASSERT( FD_LRU_TAG_NULL == 0UL, unit_test );

FD_STATIC_ASSERT( FD_LRU_SPARSE_DEFAULT == 2, unit_test );

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t   _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_lru_align() == FD_LRU_ALIGN );
  FD_TEST( !fd_lru_footprint( ULONG_MAX, 4UL ) );
  FD_TEST( !fd_lru_footprint( 1UL, ULONG_MAX ) );
  FD_TEST( fd_lru_map_cnt_default( 0UL ) == 0UL );
  FD_TEST( fd_lru_map_cnt_default( 1UL ) == 8UL );
  FD_TEST( fd_lru_map_cnt_default( 2UL ) == 8UL );
  FD_TEST( fd_lru_map_cnt_default( 3UL ) == 16UL );
  FD_TEST( fd_lru_map_cnt_default( 6UL ) == 16UL );
  FD_TEST( fd_lru_map_cnt_default( 7UL ) == 32UL );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if ( cpu_idx > fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

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

  ulong depth     = 1UL << 16;
  ulong map_cnt   = 0UL;
  ulong align     = fd_lru_align();
  ulong footprint = fd_lru_footprint( depth, map_cnt );
  if ( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR( ( "bad depth / map_cnt" ) );
  FD_LOG_NOTICE( ( "Creating lru (--depth %lu, --map-cnt %lu, align %lu, footprint %lu)",
                   depth,
                   map_cnt,
                   align,
                   footprint ) );
  void * mem = fd_wksp_alloc_laddr( wksp, align, footprint, 1UL );
  FD_TEST( mem );
  void * _lru = fd_lru_new( mem, depth, map_cnt );
  FD_TEST( _lru );
  fd_lru_t * lru = fd_lru_join( _lru );
  FD_TEST( lru );

  if ( !map_cnt ) {
    map_cnt = fd_lru_map_cnt_default( depth );
    FD_LOG_NOTICE( ( "default map_cnt %lu used", map_cnt ) );
  }
  FD_LOG_NOTICE(
      ( "[LRU cache] depth: %lu, map_cnt: %lu, footprint: %lu", depth, map_cnt, footprint ) );

  FD_TEST( fd_lru_depth( lru ) == depth );
  FD_TEST( fd_lru_free_top( lru ) == 1UL );
  FD_TEST( fd_lru_map_cnt( lru ) == map_cnt );
  FD_TEST( fd_lru_list_laddr( lru ) );
  FD_TEST( fd_lru_map_laddr( lru ) );

  fd_list_t ** map = fd_lru_map_laddr( lru );
  for ( ulong tag = 1; tag <= depth; tag++ ) {
    FD_TEST( fd_lru_free_top( lru ) == tag );
    int         dup;
    fd_list_t * upsert = fd_lru_upsert( lru, tag, &dup );
    int         found;
    ulong       map_idx;
    FD_LRU_QUERY( found, map_idx, map, map_cnt, tag );
    FD_TEST( found );
    FD_TEST( found == ( upsert == NULL ) );
    FD_TEST( map[map_idx] );
    FD_TEST( map[map_idx]->tag == tag );
    FD_TEST( map[map_idx]->curr );
    FD_TEST( fd_lru_list_head( lru )->tag == 1 );
  }
  for ( ulong tag = 1; tag <= depth; tag++ ) {
    int   found;
    ulong map_idx;
    FD_LRU_QUERY( found, map_idx, map, map_cnt, tag );
    FD_TEST( found );
    FD_TEST( map[map_idx] );
    FD_TEST( map[map_idx]->tag == tag );
    FD_TEST( map[map_idx]->curr );
    FD_TEST( fd_lru_list_head( lru )->tag == 1 );
  }

  for ( ulong tag = depth + 1; tag <= 2 * depth; tag++ ) {
    int   found;
    ulong map_idx;
    FD_LRU_QUERY( found, map_idx, map, map_cnt, tag );
    FD_TEST( !found );
    int dup;
    fd_lru_upsert( lru, tag, &dup );
    FD_LRU_QUERY( found, map_idx, map, map_cnt, tag );
    FD_TEST( found );
    FD_TEST( map[map_idx] );
    FD_TEST( map[map_idx]->tag == tag );
    FD_TEST( map[map_idx]->curr );
    FD_TEST( fd_lru_list_tail( lru )->tag == tag );
    FD_TEST( fd_lru_list_head( lru )->tag == tag - depth + 1 );
  }

  /* already present */
  do {
    int dup;
    fd_lru_upsert( lru, depth + 1, &dup );
    int   found;
    ulong map_idx;
    ulong tag = depth + 1;
    FD_LRU_QUERY( found, map_idx, map, map_cnt, tag );
    FD_TEST( found );
    FD_TEST( map[map_idx] );
    FD_TEST( map[map_idx]->tag == tag );
    FD_TEST( fd_lru_list_tail( lru )->tag == tag );
    FD_TEST( fd_lru_list_head( lru )->tag == depth + 2UL );
  } while ( 0 );

  /* update every element */
  for( ulong tag = depth + 1; tag <= 2 * depth; tag++ ) {
    int   found = 0;
    ulong map_idx = 0UL;
    FD_LRU_QUERY( found, map_idx, map, map_cnt, tag );
    FD_TEST( found );
    int dup = 0;
    fd_lru_upsert( lru, tag, &dup );
    FD_LRU_QUERY( found, map_idx, map, map_cnt, tag );
    FD_TEST( found );
    FD_TEST( map[map_idx] );
    FD_TEST( map[map_idx]->tag == tag );
    FD_TEST( fd_lru_list_tail( lru )->tag == tag );
  }

  for ( ulong i = 1; i < depth; i++ ) {
    ushort n = fd_rng_ushort( rng ); /* assumes depth = USHORT_MAX */
    int    found;
    ulong  map_idx;
    int    dup;
    if ( n < ( fd_rng_uchar( rng ) >= ( 1 << 7 ) ) ) {
      ulong tag = (ulong)n + depth + 1;
      FD_LRU_QUERY( found, map_idx, map, lru->map_cnt, tag );
      fd_list_t * evicted = fd_lru_upsert( lru, tag, &dup );
      FD_TEST( found );
      FD_TEST( evicted == NULL );
      FD_TEST( dup );
    } else {
      ulong tag = (ulong)n;
      FD_LRU_QUERY( found, map_idx, map, lru->map_cnt, tag );
      (void)map_idx;
      FD_TEST( !found );
    }
  }

  FD_LOG_NOTICE( ( "Cleaning up" ) );

  FD_TEST( fd_lru_leave( lru ) == _lru );
  FD_TEST( fd_lru_delete( _lru ) == mem );
  fd_wksp_free_laddr( mem );
  fd_wksp_delete_anonymous( wksp );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}

#else

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  // FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED capabilities" ));
  fd_halt();
  return 0;
}

#endif
