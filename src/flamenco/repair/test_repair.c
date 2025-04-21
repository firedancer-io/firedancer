#include "fd_repair.c"

void
test_repair_tcache( fd_wksp_t * wksp ){
  ulong needed_max = 128;
  void * mem = fd_wksp_alloc_laddr( wksp, fd_repair_align(), fd_repair_footprint(needed_max), 1UL );
  FD_TEST( mem );
  fd_repair_t * repair = fd_repair_join( fd_repair_new( mem, 128, 42 ) );
  FD_TEST( repair );

  fd_repair_need_orphan( repair, 1 );

  /* verify oldest in tcache is orphan req for 1 */
  ulong oldest = fd_tcache_oldest_laddr( repair->needed )[0];
  ulong * ring = fd_tcache_ring_laddr( repair->needed );
  ulong * map  = fd_tcache_map_laddr ( repair->needed );
  ulong map_cnt = fd_tcache_map_cnt( repair->needed );
  ulong depth = fd_tcache_depth( repair->needed );

  FD_LOG_NOTICE(("depth %lu map_cnt %lu", depth, map_cnt));

  FD_LOG_WARNING(("oldest %lu val: %lx | slot : %lu, idx %u",
    oldest,
    ring[oldest],
    fd_repair_req_tag_slot( ring[oldest] ),
    fd_repair_req_tag_shred_idx( ring[oldest] )));

  FD_TEST( fd_tcache_tag_is_null( ring[oldest] ) );
  int   found;
  ulong map_idx;
  FD_TCACHE_QUERY( found, map_idx, map, map_cnt, fd_repair_req_tag( 1, FD_SHRED_IDX_MAX, fd_needed_orphan )  );
  FD_TEST( found );
  (void)map_idx;

  fd_repair_need_orphan( repair, 2 );

  /* verify oldest in tcache is orphan req for 1 */
  oldest = fd_tcache_oldest_laddr( repair->needed )[0];

  FD_LOG_WARNING(("oldest %lu val: %lx | slot : %lu, idx %u",
                      oldest,
                      ring[oldest],
                      fd_repair_req_tag_slot( ring[oldest] ),
                      fd_repair_req_tag_shred_idx( ring[oldest] )));

  FD_TCACHE_QUERY( found, map_idx, map, map_cnt, fd_repair_req_tag( 1, FD_SHRED_IDX_MAX, fd_needed_orphan )  );
  FD_TEST( found );
  (void)map_idx;

  for( ulong i=0UL; i<needed_max ; i++ ) {
    fd_repair_need_orphan( repair, i );
  }

  oldest = fd_tcache_oldest_laddr( repair->needed )[0];
  FD_LOG_WARNING(("oldest %lu val: %lx | slot : %lu, idx %u",
    oldest,
    ring[oldest],
    fd_repair_req_tag_slot( ring[oldest] ),
    fd_repair_req_tag_shred_idx( ring[oldest] )));

  FD_TEST( ring[oldest] == fd_repair_req_tag( 1, FD_SHRED_IDX_MAX, fd_needed_orphan ) );

  fd_repair_need_orphan( repair, needed_max );
  FD_TCACHE_QUERY( found, map_idx, map, map_cnt, fd_repair_req_tag( 1, FD_SHRED_IDX_MAX, fd_needed_orphan )  );
  FD_TEST( !found );

  oldest = fd_tcache_oldest_laddr( repair->needed )[0];
  FD_LOG_WARNING(("oldest %lu val: %lx | slot : %lu, idx %u",
    oldest,
    ring[oldest],
    fd_repair_req_tag_slot( ring[oldest] ),
    fd_repair_req_tag_shred_idx( ring[oldest] )));

  FD_TEST( ring[oldest] == fd_repair_req_tag( 2, FD_SHRED_IDX_MAX, fd_needed_orphan ) );

  fd_wksp_free_laddr( fd_repair_delete( fd_repair_leave( repair ) ) );
}


int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_repair_tcache( wksp );

  fd_halt();
  return 0;
}
