#define FD_TILE_TEST 1
#include "fd_iavf_tile.c"

static void
test_invalid_inputs( void ) {
  char const * invalid_pci[] = {
    "", "01:00.0", "0000:01:00.8", "0000:01:20.0", "0000:01:0g.0",
    "0000:01:00.0/", "0000/01:00.0"
  };
  fd_iavf_pci_info_t info;
  for( ulong i=0UL; i<sizeof(invalid_pci)/sizeof(invalid_pci[0]); i++ ) {
    fd_memset( &info, 0xff, sizeof(info) );
    FD_TEST( fd_iavf_pci_probe( &info, invalid_pci[i] )==-1 && errno==EINVAL );
    fd_iavf_pci_info_t empty = {0};
    FD_TEST( !memcmp( &info, &empty, sizeof(info) ) );
  }
  FD_TEST( fd_iavf_pci_probe( NULL, "0000:01:00.0" )==-1 && errno==EINVAL );
  FD_TEST( fd_iavf_pci_probe( &info, NULL )==-1 && errno==EINVAL );

  fd_iavf_vfio_t vfio = { .container_fd=-1, .iova_pgsizes=4096UL };
  FD_TEST( fd_iavf_vfio_dma_map( &vfio, (void *)4096UL, 4096UL, 4096UL )==-1 && errno==EINVAL );
  vfio.container_fd = -2;
  FD_TEST( fd_iavf_vfio_dma_map( &vfio, NULL, 4096UL, 4096UL )==-1 && errno==EINVAL );
  vfio.container_fd = 0;
  FD_TEST( fd_iavf_vfio_dma_map( &vfio, (void *)4097UL, 4096UL, 4096UL )==-1 && errno==EINVAL );
  FD_TEST( fd_iavf_vfio_dma_map( &vfio, (void *)4096UL, 4097UL, 4096UL )==-1 && errno==EINVAL );
  FD_TEST( fd_iavf_vfio_dma_map( &vfio, (void *)4096UL, 4096UL, ULONG_MAX-4095UL )==-1 && errno==EINVAL );

  FD_TEST( !fd_iavf_queue_footprint( 0U, 64U ) );
  FD_TEST( !fd_iavf_queue_footprint( 63U, 64U ) );
  FD_TEST( !fd_iavf_queue_footprint( 65U, 64U ) );
  FD_TEST( !fd_iavf_queue_footprint( 64U, 8192U ) );
  for( uint depth=64U; depth<=4096U; depth*=2U ) {
    ulong footprint = fd_iavf_queue_footprint( depth, depth );
    FD_TEST( footprint>=(ulong)depth*56UL );
    FD_TEST( fd_ulong_is_aligned( footprint, 4096UL ) );
  }

  fd_iavf_adminq_t adminq = {0};
  fd_iavf_vf_info_t resources = { .queue_pair_cnt=1U, .rss_key_sz=52U, .rss_lut_sz=64U };
  FD_TEST( fd_iavf_configure_rss( &vfio, &adminq, &resources, 0U )==-1 && errno==EINVAL );
  FD_TEST( fd_iavf_configure_rss( &vfio, &adminq, &resources, 2U )==-1 && errno==EINVAL );
  FD_TEST( fd_iavf_add_mac( &vfio, &adminq, NULL )==-1 && errno==EINVAL );
  FD_TEST( fd_iavf_add_mac( &vfio, &adminq, &resources )==-1 && errno==EINVAL );
}

static fd_iavf_tile_t test_tile;
static fd_netdev_tbl_hdr_t test_netdev_hdr;
static fd_netdev_t test_netdevs[ 4 ];

static void
test_members_init( void ) {
  fd_memset( &test_tile, 0, sizeof(test_tile) );
  test_netdev_hdr = (fd_netdev_tbl_hdr_t) { .dev_cnt=4U };
  test_tile.router.netdev_tbl = (fd_netdev_tbl_join_t) { .hdr=&test_netdev_hdr, .dev_tbl=test_netdevs };
  test_tile.router.if_virt = 4U;
  test_tile.net.tile_cnt = 1UL;
  test_tile.member_cnt = 2UL;
  test_netdevs[0] = (fd_netdev_t) {
    .if_idx=4U, .dev_type=ARPHRD_ETHER, .oper_status=FD_OPER_STATUS_UP, .mtu=1500U,
    .bond_mode=BOND_MODE_8023AD, .bond_aggregator_id=513U, .mac_addr={ 2,3,4,5,6,7 }
  };
  for( ulong i=0UL; i<2UL; i++ ) {
    test_netdevs[i+1UL] = (fd_netdev_t) {
      .if_idx=(uint)i+2U, .dev_type=ARPHRD_ETHER, .oper_status=FD_OPER_STATUS_UP,
      .master_idx=4, .bond_aggregator_id=513U,
      .bond_actor_state=LACP_STATE_COLLECTING | LACP_STATE_DISTRIBUTING
    };
    test_tile.members[i].if_idx = (uint)i+2U;
    test_tile.members[i].vf_info.link_state_valid = 1;
    test_tile.members[i].vf_info.link_up = 1;
    test_tile.members[i].queue.tx_depth = 64U;
  }
  test_netdevs[3] = (fd_netdev_t) { .if_idx=7U, .dev_type=ARPHRD_ETHER, .oper_status=FD_OPER_STATUS_UP };
}

static void
test_member_selection( void ) {
  test_members_init();
  for( ulong i=0UL; i<64UL; i++ ) {
    FD_TEST( fd_iavf_tile_tx_member( &test_tile, i)==i%2UL );
    FD_TEST( fd_iavf_tile_tx_member( &test_tile, i)==i%2UL );
  }
  test_netdevs[1].bond_actor_state = LACP_STATE_COLLECTING;
  FD_TEST( fd_iavf_tile_member_active( &test_tile, &test_tile.members[0], LACP_STATE_COLLECTING ) );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( fd_iavf_tile_tx_member( &test_tile, i)==1UL );
  test_netdevs[1].bond_actor_state = LACP_STATE_DISTRIBUTING;
  FD_TEST( !fd_iavf_tile_member_active( &test_tile, &test_tile.members[0], LACP_STATE_COLLECTING ) );
  test_netdevs[1].bond_aggregator_id = 514U;
  FD_TEST( fd_iavf_tile_tx_member( &test_tile, 0UL )==1UL );
  test_netdevs[1].bond_aggregator_id = 513U;
  test_netdevs[1].master_idx = 7;
  FD_TEST( fd_iavf_tile_tx_member( &test_tile, 0UL )==1UL );
  test_netdevs[1].master_idx = 4;
  test_tile.members[0].vf_info.link_state_valid = 0;
  FD_TEST( fd_iavf_tile_tx_member( &test_tile, 0UL )==1UL );
  test_tile.members[0].vf_info.link_state_valid = 1;
  test_tile.members[0].vf_info.link_up = 0;
  FD_TEST( fd_iavf_tile_tx_member( &test_tile, 0UL )==1UL );
  test_tile.members[0].vf_info.link_up = 1;
  test_netdevs[1].oper_status = FD_OPER_STATUS_DOWN;
  FD_TEST( fd_iavf_tile_tx_member( &test_tile, 0UL )==1UL );
  test_netdevs[2].oper_status = FD_OPER_STATUS_DOWN;
  FD_TEST( fd_iavf_tile_tx_member( &test_tile, 0UL )==ULONG_MAX );
  test_netdevs[1].oper_status = test_netdevs[2].oper_status = FD_OPER_STATUS_UP;
  test_netdevs[0].bond_aggregator_id = 0U;
  FD_TEST( fd_iavf_tile_tx_member( &test_tile, 0UL )==ULONG_MAX );
  test_netdevs[0].bond_aggregator_id = 513U;
  test_netdevs[0].bond_mode = BOND_MODE_ACTIVEBACKUP;
  FD_TEST( fd_iavf_tile_tx_member( &test_tile, 0UL )==ULONG_MAX );
  test_netdevs[0].bond_mode = BOND_MODE_8023AD;
  test_netdevs[0].oper_status = FD_OPER_STATUS_DOWN;
  FD_TEST( fd_iavf_tile_tx_member( &test_tile, 0UL )==ULONG_MAX );
  test_netdevs[0].oper_status = FD_OPER_STATUS_UP;
  FD_TEST( fd_iavf_tile_tx_member( &test_tile, 0UL )==0UL );

  test_tile.router.if_virt = 2U;
  test_tile.member_cnt = 1UL;
  test_netdevs[1].master_idx = -1;
  test_netdevs[1].bond_actor_state = 0U;
  FD_TEST( fd_iavf_tile_tx_member( &test_tile, 0UL )==0UL );
  FD_TEST( fd_iavf_tile_member_active( &test_tile, &test_tile.members[0], LACP_STATE_COLLECTING ) );
  test_tile.members[0].vf_info.link_up = 0;
  FD_TEST( fd_iavf_tile_tx_member( &test_tile, 0UL )==ULONG_MAX );
}

static void
test_bond_route( void ) {
  static uchar fib_local[ 262144 ] __attribute__((aligned(FD_FIB4_ALIGN)));
  static uchar fib_main [ 262144 ] __attribute__((aligned(FD_FIB4_ALIGN)));
  static fd_neigh4_entry_t neigh[ 256 ] __attribute__((aligned(128)));
  test_members_init();
  FD_TEST( fd_fib4_join( test_tile.router.fib_local, fd_fib4_new( fib_local, 16UL, 16UL, 1UL ) ) );
  FD_TEST( fd_fib4_join( test_tile.router.fib_main, fd_fib4_new( fib_main, 16UL, 16UL, 1UL ) ) );
  FD_TEST( fd_neigh4_hmap_footprint( 16UL )<=sizeof(neigh) );
  FD_TEST( fd_neigh4_hmap_new( neigh, 16UL, 1 ) );
  FD_TEST( fd_neigh4_hmap_join( test_tile.router.neigh4, neigh, 16UL, 8UL, 1UL ) );
  uint gw = FD_IP4_ADDR( 10,0,0,1 );
  fd_neigh4_entry_t * entry = fd_neigh4_hmap_upsert( test_tile.router.neigh4, &gw );
  FD_TEST( entry );
  fd_neigh4_entry_t neighbor = { .ip4_addr=gw, .state=FD_NEIGH4_STATE_ACTIVE, .mac_addr={ 2,7,6,5,4,3 } };
  fd_neigh4_entry_atomic_st( entry, &neighbor );
  fd_fib4_hop_t hop = { .rtype=FD_FIB4_RTYPE_UNICAST, .if_idx=4U, .ip4_gw=gw, .ip4_src=FD_IP4_ADDR( 10,0,0,2 ) };
  FD_TEST( fd_fib4_insert( test_tile.router.fib_main, 0U, 0, 0U, &hop ) );
  uint dst = FD_IP4_ADDR( 10,181,80,14 );
  ulong sig = fd_disco_netmux_sig( dst, 9000U, dst, DST_PROTO_OUTGOING, 0UL );
  FD_TEST( !before_frag( &test_tile, 0UL, 0UL, sig ) );
  FD_TEST( test_tile.net.tx_route.if_idx==4U );
  FD_TEST( !memcmp( test_tile.net.tx_route.mac_addrs, neighbor.mac_addr, 6UL ) );
  FD_TEST( !memcmp( test_tile.net.tx_route.mac_addrs+6UL, test_netdevs[0].mac_addr, 6UL ) );
  ulong chosen = test_tile.tx_member;
  FD_TEST( !before_frag( &test_tile, 0UL, 0UL, sig ) && test_tile.tx_member==chosen );
  test_tile.members[chosen].vf_info.link_up = 0;
  FD_TEST( !before_frag( &test_tile, 0UL, 0UL, sig ) && test_tile.tx_member==1UL-chosen );
  test_tile.members[1UL-chosen].vf_info.link_up = 0;
  FD_TEST( before_frag( &test_tile, 0UL, 0UL, sig ) );
  FD_TEST( test_tile.metrics.tx_no_link_cnt==1UL );
  hop.if_idx = 7U;
  FD_TEST( fd_fib4_insert( test_tile.router.fib_main, dst, 32, 0U, &hop ) );
  FD_TEST( before_frag( &test_tile, 0UL, 0UL, sig ) );
  FD_TEST( test_tile.net.metrics.tx_route_fail_cnt[ FD_METRICS_ENUM_ROUTE_FAIL_V_UNSUPPORTED_INTERFACE_IDX ]==1UL );
  FD_TEST( test_tile.metrics.tx_no_link_cnt==1UL );
}

static void
test_inactive_rx( void ) {
  test_members_init();
  fd_iavf_rx_desc_t desc[ 2 ][ 128 ] = {0};
  uint chunks[ 128 ] = { 1U };
  uint tail = 0U;
  test_tile.batch_size = 1U;
  test_tile.net.pkt_buf_chunk0 = 1UL;
  test_tile.net.pkt_buf_wmark = 64UL;
  for( ulong i=0UL; i<2UL; i++ ) {
    test_tile.members[i].queue = (fd_iavf_queue_t) { .rx_ring=desc[i], .rx_depth=128U, .enabled=1 };
  }
  fd_iavf_tile_member_t * member = &test_tile.members[0];
  member->queue.rx_prod = member->queue.rx_posted = 1UL;
  member->queue.rx_tail = &tail;
  member->rx_desc_chunk = chunks;
  member->packet_iova0 = 0x200000000UL;
  member->vf_info.link_up = 0;
  desc[0][0].qword[1] = 3UL | (64UL<<38);
  FD_TEST( fd_iavf_tile_poll_rx( &test_tile, NULL ) );
  FD_TEST( test_tile.metrics.rx_no_link_cnt==1UL && !test_tile.net.metrics.rx_pkt_cnt );
  FD_TEST( member->queue.rx_cons==1UL && member->queue.rx_prod==2UL && tail==2U );
  FD_TEST( chunks[1]==1U && desc[0][1].qword[0]==member->packet_iova0 );
  FD_TEST( !fd_iavf_tile_poll_rx( &test_tile, NULL ) );
}

static void
test_tx_ring( void ) {
  fd_iavf_tx_desc_t desc[ 64 ] = {0};
  ulong endpoints[ 64 ] = {0};
  uint tail = 0U;
  fd_iavf_queue_t queue = {
    .tx_ring=desc, .tx_comp_ring=endpoints, .tx_depth=64U, .tx_tail=&tail,
    .tx_prod=65598UL, .tx_posted=65598UL, .tx_cons=65598UL,
    .tx_comp_prod=63UL, .tx_comp_cons=63UL, .enabled=1
  };
  for( uint cycle=0U; cycle<256U; cycle++ ) {
    ulong start = queue.tx_prod;
    for( ulong i=0UL; i<63UL; i++ ) {
      FD_TEST( !fd_iavf_hw_tx_submit( &queue, 0x200000000UL+i*2048UL, 60UL+i ) );
      fd_iavf_tx_desc_t const * entry = &desc[ (start+i) & 63UL ];
      FD_TEST( entry->buffer_iova==0x200000000UL+i*2048UL );
      FD_TEST( (entry->cmd_type_offset_buffer_sz & 0xffUL)==0x50UL );
      FD_TEST( (entry->cmd_type_offset_buffer_sz>>34)==60UL+i );
      if( i==30UL ) fd_iavf_hw_tx_flush( &queue );
    }
    FD_TEST( fd_iavf_hw_tx_submit( &queue, 0x200000000UL, 64UL )==-1 );
    fd_iavf_hw_tx_flush( &queue );
    FD_TEST( tail==(queue.tx_prod & 63UL) );
    FD_TEST( fd_iavf_hw_tx_complete( &queue )==0UL );
    desc[ (start+30UL) & 63UL ].cmd_type_offset_buffer_sz = 0xfUL;
    FD_TEST( fd_iavf_hw_tx_complete( &queue )==31UL );
    FD_TEST( queue.tx_cons==start+31UL );
    desc[ (start+62UL) & 63UL ].cmd_type_offset_buffer_sz = 0xfUL;
    FD_TEST( fd_iavf_hw_tx_complete( &queue )==32UL );
    FD_TEST( queue.tx_cons==queue.tx_prod );
    FD_TEST( queue.tx_comp_cons==queue.tx_comp_prod );
    FD_TEST( fd_iavf_hw_tx_complete( &queue )==0UL );
  }
}

static void
test_rx_ring( void ) {
  fd_iavf_rx_desc_t desc[ 128 ] = {0};
  uint tail = 0U;
  fd_iavf_queue_t queue = {
    .rx_ring=desc, .rx_depth=128U, .rx_tail=&tail, .enabled=1,
    .rx_prod=65535UL, .rx_posted=65535UL, .rx_cons=65535UL
  };
  fd_iavf_hw_rx_comp_t comp[ 64 ];
  for( uint cycle=0U; cycle<256U; cycle++ ) {
    ulong start = queue.rx_prod;
    for( ulong i=0UL; i<127UL; i++ ) {
      uint desc_idx = UINT_MAX;
      FD_TEST( !fd_iavf_hw_rx_post( &queue, 0x200000000UL+i*2048UL, &desc_idx ) );
      FD_TEST( desc_idx==((start+i) & 127UL) );
      FD_TEST( !desc[ desc_idx ].qword[1] );
    }
    if( !cycle ) FD_TEST( fd_iavf_hw_rx_post( &queue, 0x200000000UL, NULL )==-1 );
    fd_iavf_hw_rx_flush( &queue );
    FD_TEST( tail==(queue.rx_prod & 127UL) );
    FD_TEST( !fd_iavf_hw_rx_poll( &queue, comp, 64U ) );
    for( ulong i=0UL; i<127UL; i++ ) {
      desc[ (start+i) & 127UL ].qword[1] = 3UL | ((60UL+i)<<38);
    }
    ulong complete_cnt = 0UL;
    while( complete_cnt<127UL ) {
      int count = fd_iavf_hw_rx_poll( &queue, comp, 64U );
      FD_TEST( count>0 && count<=64 );
      for( int i=0; i<count; i++ ) {
        FD_TEST( comp[i].desc_idx==((start+complete_cnt) & 127UL) );
        FD_TEST( comp[i].frame_sz==60UL+complete_cnt && !comp[i].error_flags );
        complete_cnt++;
      }
    }
    FD_TEST( queue.rx_cons==queue.rx_prod );
  }

  ulong start = queue.rx_prod;
  for( uint i=0U; i<5U; i++ ) FD_TEST( !fd_iavf_hw_rx_post( &queue, 0x200000000UL+(ulong)i*2048UL, NULL ) );
  fd_iavf_hw_rx_flush( &queue );
  desc[ (start+0UL) & 127UL ].qword[1] = 3UL | (1UL<<20) | (64UL<<38);
  desc[ (start+1UL) & 127UL ].qword[1] = 3UL | (1UL<<19) | (64UL<<38);
  desc[ (start+2UL) & 127UL ].qword[1] = 1UL | (2048UL<<38);
  desc[ (start+3UL) & 127UL ].qword[1] = 3UL | (64UL<<38);
  desc[ (start+4UL) & 127UL ].qword[1] = 3UL | (64UL<<38);
  FD_TEST( fd_iavf_hw_rx_poll( &queue, comp, 3U )==3 );
  FD_TEST( !comp[0].error_flags && comp[1].error_flags && comp[2].error_flags );
  FD_TEST( fd_iavf_hw_rx_poll( &queue, comp, 3U )==2 );
  FD_TEST( comp[0].error_flags && !comp[1].error_flags );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_invalid_inputs();
  test_tx_ring();
  test_rx_ring();
  test_member_selection();
  test_bond_route();
  test_inactive_rx();
  if( argc==2 ) {
    fd_iavf_pci_info_t pci;
    fd_iavf_vfio_t vfio;
    fd_iavf_adminq_t adminq;
    fd_iavf_vf_info_t info;
    FD_TEST( !fd_iavf_pci_probe( &pci, argv[1] ) );
    FD_TEST( !fd_iavf_vfio_init( &vfio, &pci ) );
    void * memory = NULL;
    FD_TEST( !posix_memalign( &memory, 4096UL, fd_iavf_adminq_footprint() ) );
    FD_TEST( !fd_iavf_adminq_init( &vfio, &adminq, memory, fd_iavf_adminq_footprint(), 0x100000000UL ) );
    FD_TEST( !fd_iavf_virtchnl_version( &vfio, &adminq ) );
    FD_TEST( !fd_iavf_get_vf_resources( &vfio, &adminq, &info ) );
    FD_LOG_NOTICE(( "VF %s, VSI %hu, queue pairs %hu, vectors %hu, RSS key %u, RSS table %u",
                    pci.pci_addr, info.vsi_id, info.queue_pair_cnt, info.vector_cnt,
                    info.rss_key_sz, info.rss_lut_sz ));

    fd_iavf_queue_t queue;
    ulong queue_sz = fd_iavf_queue_footprint( 64U, 64U );
    void * queue_memory = NULL;
    void * rx_memory = NULL;
    FD_TEST( !posix_memalign( &queue_memory, 4096UL, queue_sz ) );
    FD_TEST( !posix_memalign( &rx_memory, 4096UL, 64UL*2048UL ) );
    FD_TEST( !fd_iavf_configure_queue( &vfio, &adminq, &info, &queue, queue_memory,
                                      queue_sz, 0x100100000UL, 64U, 64U, 2048U, 2048U ) );
    FD_TEST( !fd_iavf_add_mac( &vfio, &adminq, &info ) );
    FD_TEST( !fd_iavf_configure_rss( &vfio, &adminq, &info, 1U ) );
    FD_TEST( !fd_iavf_vfio_dma_map( &vfio, rx_memory, 64UL*2048UL, 0x200000000UL ) );
    fd_iavf_rx_desc_t * rx_ring = queue.rx_ring;
    for( uint i=0U; i<63U; i++ ) rx_ring[i].qword[0] = 0x200000000UL + (ulong)i*2048UL;
    FD_COMPILER_MFENCE();
    __atomic_thread_fence( __ATOMIC_RELEASE );
    queue.rx_prod = queue.rx_posted = 63UL;
    *queue.rx_tail = 63U;
    FD_TEST( !fd_iavf_enable_queue( &vfio, &adminq, &info, &queue ) );
    FD_LOG_NOTICE(( "queue 0 enabled with RSS delivery and the PF-assigned MAC" ));

    FD_TEST( !munmap( (void *)vfio.bar0, FD_IAVF_BAR0_MAP_SZ ) );
    FD_TEST( !close( vfio.device_fd ) );
    FD_TEST( !close( vfio.group_fd ) );
    FD_TEST( !close( vfio.container_fd ) );
    free( rx_memory );
    free( queue_memory );
    free( memory );
  }
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
