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

  fd_iavf_adminq_t  adminq    = {0};
  fd_iavf_vf_info_t resources = { .queue_pair_cnt=1U, .rss_key_sz=52U, .rss_lut_sz=64U };
  FD_TEST( fd_iavf_virtchnl_configure_rss( &vfio, &adminq, &resources, 0U )==-1 && errno==EINVAL );
  FD_TEST( fd_iavf_virtchnl_configure_rss( &vfio, &adminq, &resources, 2U )==-1 && errno==EINVAL );
  FD_TEST( fd_iavf_virtchnl_add_mac( &vfio, &adminq, NULL )==-1 && errno==EINVAL );
  FD_TEST( fd_iavf_virtchnl_add_mac( &vfio, &adminq, &resources )==-1 && errno==EINVAL );
}

static void
test_tx_ring( void ) {
  fd_iavf_tx_desc_t desc[ 64 ] = {0};
  ulong endpoints[ 64 ]        = {0};
  uint tail                    = 0U;
  fd_iavf_queue_t queue        = {
    .tx_ring      = desc, .tx_comp_ring=endpoints, .tx_depth=64U, .tx_tail=&tail,
    .tx_prod      = 65598UL, .tx_posted=65598UL, .tx_cons=65598UL,
    .tx_comp_prod = 63UL, .tx_comp_cons=63UL, .enabled=1
  };
  for( uint cycle=0U; cycle<256U; cycle++ ) {
    ulong start = queue.tx_prod;
    for( ulong i=0UL; i<63UL; i++ ) {
      FD_TEST( !fd_iavf_hw_tx_enqueue( &queue, 0x200000000UL+i*2048UL, 60UL+i ) );
      fd_iavf_tx_desc_t const * entry = &desc[ (start+i) & 63UL ];
      FD_TEST( entry->buffer_iova==0x200000000UL+i*2048UL );
      FD_TEST( (entry->cmd_type_offset_buffer_sz & 0xffUL)==0x50UL );
      FD_TEST( (entry->cmd_type_offset_buffer_sz>>34)==60UL+i );
      if( i==30UL ) fd_iavf_hw_tx_flush( &queue );
    }
    FD_TEST( fd_iavf_hw_tx_enqueue( &queue, 0x200000000UL, 64UL )==-1 );
    fd_iavf_hw_tx_flush( &queue );
    FD_TEST( tail==(queue.tx_prod & 63UL) );
    FD_TEST( fd_iavf_hw_poll_tx( &queue )==0UL );
    desc[ (start+30UL) & 63UL ].cmd_type_offset_buffer_sz = 0xfUL;
    FD_TEST( fd_iavf_hw_poll_tx( &queue )==31UL );
    FD_TEST( queue.tx_cons==start+31UL );
    desc[ (start+62UL) & 63UL ].cmd_type_offset_buffer_sz = 0xfUL;
    FD_TEST( fd_iavf_hw_poll_tx( &queue )==32UL );
    FD_TEST( queue.tx_cons==queue.tx_prod );
    FD_TEST( queue.tx_comp_cons==queue.tx_comp_prod );
    FD_TEST( fd_iavf_hw_poll_tx( &queue )==0UL );
  }
}

static void
test_rx_ring( void ) {
  fd_iavf_rx_desc_t desc[ 128 ] = {0};
  uint tail                     = 0U;
  fd_iavf_queue_t queue         = {
    .rx_ring = desc, .rx_depth=128U, .rx_tail=&tail, .enabled=1,
    .rx_prod = 65535UL, .rx_posted=65535UL, .rx_cons=65535UL
  };
  fd_iavf_hw_rx_comp_t comp[ 64 ];
  for( uint cycle=0U; cycle<256U; cycle++ ) {
    ulong start = queue.rx_prod;
    for( ulong i=0UL; i<127UL; i++ ) {
      uint desc_idx = UINT_MAX;
      FD_TEST( !fd_iavf_hw_rx_enqueue( &queue, 0x200000000UL+i*2048UL, &desc_idx ) );
      FD_TEST( desc_idx==((start+i) & 127UL) );
      FD_TEST( !desc[ desc_idx ].qword[1] );
    }
    if( !cycle ) FD_TEST( fd_iavf_hw_rx_enqueue( &queue, 0x200000000UL, NULL )==-1 );
    fd_iavf_hw_rx_flush( &queue );
    FD_TEST( tail==(queue.rx_prod & 127UL) );
    FD_TEST( !fd_iavf_hw_poll_rx( &queue, comp, 64U ) );
    for( ulong i=0UL; i<127UL; i++ ) {
      desc[ (start+i) & 127UL ].qword[1] = 3UL | ((60UL+i)<<38);
    }
    ulong comp_cnt = 0UL;
    while( comp_cnt<127UL ) {
      int count = fd_iavf_hw_poll_rx( &queue, comp, 64U );
      FD_TEST( count>0 && count<=64 );
      for( int i=0; i<count; i++ ) {
        FD_TEST( comp[i].desc_idx==((start+comp_cnt) & 127UL) );
        FD_TEST( comp[i].frame_sz==60UL+comp_cnt && !comp[i].error_flags );
        comp_cnt++;
      }
    }
    FD_TEST( queue.rx_cons==queue.rx_prod );
  }

  ulong start = queue.rx_prod;
  for( uint i=0U; i<5U; i++ ) FD_TEST( !fd_iavf_hw_rx_enqueue( &queue, 0x200000000UL+(ulong)i*2048UL, NULL ) );
  fd_iavf_hw_rx_flush( &queue );
  desc[ (start+0UL) & 127UL ].qword[1] = 3UL | (1UL<<20) | (64UL<<38);
  desc[ (start+1UL) & 127UL ].qword[1] = 3UL | (1UL<<19) | (64UL<<38);
  desc[ (start+2UL) & 127UL ].qword[1] = 1UL | (2048UL<<38);
  desc[ (start+3UL) & 127UL ].qword[1] = 3UL | (64UL<<38);
  desc[ (start+4UL) & 127UL ].qword[1] = 3UL | (64UL<<38);
  FD_TEST( fd_iavf_hw_poll_rx( &queue, comp, 3U )==3 );
  FD_TEST( !comp[0].error_flags && comp[1].error_flags && comp[2].error_flags );
  FD_TEST( fd_iavf_hw_poll_rx( &queue, comp, 3U )==2 );
  FD_TEST( comp[0].error_flags && !comp[1].error_flags );
}

static void
test_hardware( char const * pci_addr ) {
  fd_iavf_pci_info_t pci;
  fd_iavf_vfio_t     vfio;
  fd_iavf_adminq_t   adminq;
  fd_iavf_vf_info_t  info;
  FD_TEST( !fd_iavf_pci_probe( &pci, pci_addr ) );
  FD_TEST( !fd_iavf_vfio_init( &vfio, &pci ) );
  void * memory = NULL;
  FD_TEST( !posix_memalign( &memory, 4096UL, fd_iavf_adminq_footprint() ) );
  FD_TEST( !fd_iavf_adminq_init( &vfio, &adminq, memory, fd_iavf_adminq_footprint(), 0x100000000UL ) );
  FD_TEST( !fd_iavf_virtchnl_version( &vfio, &adminq ) );
  FD_TEST( !fd_iavf_virtchnl_get_resources( &vfio, &adminq, &info ) );
  FD_LOG_NOTICE(( "VF %s, VSI %hu, queue pairs %hu, vectors %hu, RSS key %u, RSS table %u",
                  pci.pci_addr, info.vsi_id, info.queue_pair_cnt, info.vector_cnt,
                  info.rss_key_sz, info.rss_lut_sz ));

  fd_iavf_queue_t queue;
  ulong  queue_sz     = fd_iavf_queue_footprint( 64U, 64U );
  void * queue_memory = NULL;
  void * rx_memory    = NULL;
  FD_TEST( !posix_memalign( &queue_memory, 4096UL, queue_sz ) );
  FD_TEST( !posix_memalign( &rx_memory, 4096UL, 64UL*2048UL ) );
  FD_TEST( !fd_iavf_virtchnl_configure_queue( &vfio, &adminq, &info, &queue, queue_memory,
                                              queue_sz, 0x100100000UL, 64U, 64U, 2048U, 2048U ) );
  FD_TEST( !fd_iavf_virtchnl_add_mac( &vfio, &adminq, &info ) );
  FD_TEST( !fd_iavf_virtchnl_configure_rss( &vfio, &adminq, &info, 1U ) );
  FD_TEST( !fd_iavf_vfio_dma_map( &vfio, rx_memory, 64UL*2048UL, 0x200000000UL ) );
  for( uint i=0U; i<63U; i++ ) {
    FD_TEST( !fd_iavf_hw_rx_enqueue( &queue, 0x200000000UL+(ulong)i*2048UL, NULL ) );
  }
  fd_iavf_hw_rx_flush( &queue );
  FD_TEST( !fd_iavf_virtchnl_enable_queue( &vfio, &adminq, &info, &queue ) );
  FD_LOG_NOTICE(( "queue 0 enabled with RSS delivery and the PF-assigned MAC" ));

  FD_TEST( !munmap( (void *)vfio.bar0, FD_IAVF_BAR0_MAP_SZ ) );
  FD_TEST( !close( vfio.device_fd ) );
  FD_TEST( !close( vfio.group_fd ) );
  FD_TEST( !close( vfio.container_fd ) );
  free( rx_memory );
  free( queue_memory );
  free( memory );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_invalid_inputs();
  test_tx_ring();
  test_rx_ring();
  if( argc==2 ) test_hardware( argv[1] );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
