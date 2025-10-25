#include "fd_sspeer_selector.h"

#include "../../../util/fd_util.h"

static ulong
add_peer( fd_sspeer_selector_t * selector,
          fd_ip4_port_t          addr,
          ulong                  full_slot,
          ulong                  incremental_slot,
          ulong                  latency ) {
  if( FD_LIKELY( full_slot!=ULONG_MAX ) ) {
    fd_ssinfo_t ssinfo = {
      .full = { .slot = full_slot },
      .incremental = { .base_slot = full_slot, .slot = incremental_slot }
    };
    return fd_sspeer_selector_add( selector, addr, latency, &ssinfo );
  } else {
    return fd_sspeer_selector_add( selector, addr, latency, NULL );
  }
}

static void
test_basic_peer_selection( fd_sspeer_selector_t * selector ) {
  fd_ssinfo_t cluster_ssinfo = {
    .full = { .slot = 1000UL },
    .incremental = { .base_slot = 1000UL, .slot = 1500UL }
  };
  fd_sspeer_selector_process_cluster_slot( selector, cluster_ssinfo.full.slot, cluster_ssinfo.incremental.slot );
  /* Add a peer and it should be the best peer */
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 35, 123, 172, 227 ), .port = 8899 };
  FD_TEST( add_peer( selector, addr, 1000UL, 1500UL, 5L*1000L*1000L )==5UL*1000UL*1000UL );
  fd_sspeer_t best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr.l );
  FD_TEST( best.ssinfo.full.slot==1000UL );
  FD_TEST( best.ssinfo.incremental.slot==1500UL );
  FD_TEST( best.ssinfo.incremental.base_slot==1000UL );
  FD_TEST( best.score==5L*1000L*1000L );

  /* Add a peer with better latency at the same slot and it should be
     the best peer */
  fd_ip4_port_t addr2 = { .addr = FD_IP4_ADDR( 35, 123, 172, 228 ), .port = 8899 };
  FD_TEST( add_peer( selector, addr2, 1000UL, 1500UL, 3L*1000L*1000L )==3UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr2.l );
  FD_TEST( best.ssinfo.full.slot==1000UL );
  FD_TEST( best.ssinfo.incremental.slot==1500UL );
  FD_TEST( best.ssinfo.incremental.base_slot==1000UL );
  FD_TEST( best.score==3L*1000L*1000L );

  /* Add a peer with the same latency but lagging slots behind */
  fd_ip4_port_t addr3 = { .addr = FD_IP4_ADDR( 35, 123, 172, 229 ), .port = 8899 };
  FD_TEST( add_peer( selector, addr3, 1000UL, 1400UL, 3L*1000L*1000L )==3UL*1000UL*1000UL + 100UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX);
  FD_TEST( best.addr.l==addr2.l );
  FD_TEST( best.ssinfo.full.slot==1000UL );
  FD_TEST( best.ssinfo.incremental.slot==1500UL );
  FD_TEST( best.ssinfo.incremental.base_slot==1000UL );
  FD_TEST( best.score==3L*1000L*1000L );

  cluster_ssinfo.incremental.slot = 1600UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_ssinfo.full.slot, cluster_ssinfo.incremental.slot );

  /* Add a peer that is slightly slower but caught up in slots */
  fd_ip4_port_t addr4 = { .addr = FD_IP4_ADDR( 35, 123, 172, 230 ), .port = 8899 };
  FD_TEST( add_peer( selector, addr4, 1000UL, 1600UL, 3L*1000L*1000L + 75L*1000L )==3UL*1000UL*1000UL + 75UL*1000UL );
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX );
  FD_TEST( best.addr.l==addr4.l );
  FD_TEST( best.ssinfo.full.slot==1000UL );
  FD_TEST( best.ssinfo.incremental.slot==1600UL );
  FD_TEST( best.ssinfo.incremental.base_slot==1000UL );
  FD_TEST( best.score==3L*1000L*1000L + 75L*1000L );

  /* Add a fast peer that doesn't have resolved slots */
  fd_ip4_port_t addr5 = { .addr = FD_IP4_ADDR( 35, 123, 172, 231 ), .port = 8899 };
  FD_TEST( add_peer( selector, addr5, ULONG_MAX, ULONG_MAX, 2L*1000L*1000L )==2UL*1000UL*1000UL + 1000UL*1000UL*1000UL);
  best = fd_sspeer_selector_best( selector, 0, ULONG_MAX );
  FD_TEST( best.addr.l==addr4.l );
  FD_TEST( best.ssinfo.full.slot==1000UL );
  FD_TEST( best.ssinfo.incremental.slot==1600UL );
  FD_TEST( best.ssinfo.incremental.base_slot==1000UL );
  FD_TEST( best.score==3L*1000L*1000L + 75L*1000L );

  /* Test incremental peer selection */
  best = fd_sspeer_selector_best( selector, 1, 1000UL );
  FD_TEST( best.addr.l==addr4.l );
  FD_TEST( best.ssinfo.full.slot==1000UL );
  FD_TEST( best.ssinfo.incremental.slot==1600UL );
  FD_TEST( best.ssinfo.incremental.base_slot==1000UL );
  FD_TEST( best.score==3L*1000L*1000L + 75L*1000L );

  cluster_ssinfo.incremental.slot = 1700UL;
  fd_sspeer_selector_process_cluster_slot( selector, cluster_ssinfo.full.slot, cluster_ssinfo.incremental.slot );

  /* Add a peer that is fast and at the highest slot but not building
     off full slot, which makes it invalid an incremental peer */
  fd_ip4_port_t addr6 = { .addr = FD_IP4_ADDR( 35, 123, 172, 232 ), .port = 8899 };
  FD_TEST( add_peer( selector, addr6, 900UL, 1700UL, 2L*1000L*1000L )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 1, 1000UL );
  FD_TEST( best.addr.l==addr4.l );
  FD_TEST( best.ssinfo.full.slot==1000UL );
  FD_TEST( best.ssinfo.incremental.slot==1600UL );
  FD_TEST( best.ssinfo.incremental.base_slot==1000UL );
  FD_TEST( best.score==3L*1000L*1000L + 75L*1000L + 100UL*1000UL );

  /* Add a fast incremental peer that is caught up to the cluster slot */
  fd_ip4_port_t addr7 = { .addr = FD_IP4_ADDR( 35, 123, 172, 233 ), .port = 8899 };
  FD_TEST( add_peer( selector, addr7, 1000UL, 1700UL, 2L*1000L*1000L )==2UL*1000UL*1000UL );
  best = fd_sspeer_selector_best( selector, 1, 1000UL );
  FD_TEST( best.addr.l==addr7.l );
  FD_TEST( best.ssinfo.full.slot==1000UL );
  FD_TEST( best.ssinfo.incremental.slot==1700UL );
  FD_TEST( best.ssinfo.incremental.base_slot==1000UL );
  FD_TEST( best.score==2L*1000L*1000L );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );

  FD_TEST( wksp );
  void *                 shmem    = fd_wksp_alloc_laddr( wksp, fd_sspeer_selector_align(), fd_sspeer_selector_footprint( 65535UL ), 1UL );
  fd_sspeer_selector_t * selector = fd_sspeer_selector_join( fd_sspeer_selector_new( shmem, 65535UL, 1, 0UL ) );
  FD_TEST( selector );

  test_basic_peer_selection( selector );

  fd_wksp_free_laddr( fd_sspeer_selector_delete( fd_sspeer_selector_leave( selector ) ) );
  return 0;
}
