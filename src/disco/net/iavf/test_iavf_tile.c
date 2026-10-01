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

static fd_iavf_tile_t test_tile;
static void
test_tx_ring( void ) {
  fd_iavf_tx_desc_t desc[ 64 ] = {0};
  ulong endpoints[ 64 ]        = {0};
  uint chunks[ 64 ]            = {0};
  ushort frame_sz[ 64 ]        = {0};
  uint tail                    = 0U;
  fd_memset( &test_tile, 0, sizeof(test_tile) );
  test_tile.net.pkt_buf_chunk0 = 1UL;
  fd_iavf_tile_vf_t * vf = &test_tile.vfs[0];
  vf->packet_iova0           = 0x200000000UL;
  vf->tx_desc_buf_chunk      = chunks;
  vf->tx_desc_frame_sz       = frame_sz;
  vf->queue = (fd_iavf_queue_t) {
    .tx_ring      = desc, .tx_comp_ring=endpoints, .tx_depth=64U, .tx_tail=&tail,
    .tx_prod      = 65598UL, .tx_posted=65598UL, .tx_cons=65598UL,
    .tx_comp_prod = 63UL, .tx_comp_cons=63UL, .enabled=1
  };
  fd_iavf_queue_t * queue = &vf->queue;
  for( uint cycle=0U; cycle<256U; cycle++ ) {
    ulong start = queue->tx_prod;
    uint old_tail = tail;
    for( ulong i=0UL; i<63UL; i++ ) {
      chunks[ (start+i) & 63UL ] = (uint)(1UL+((i*2048UL)>>FD_CHUNK_LG_SZ));
      fd_iavf_hw_tx_enqueue( &test_tile, vf, 60UL+i );
      fd_iavf_tx_desc_t const * entry = &desc[ (start+i) & 63UL ];
      FD_TEST( entry->buffer_iova==0x200000000UL+i*2048UL );
      FD_TEST( (entry->cmd_type_offset_buffer_sz & 0xffUL)==0x50UL );
      FD_TEST( (entry->cmd_type_offset_buffer_sz>>34)==60UL+i );
      FD_TEST( frame_sz[ (start+i) & 63UL ]==60UL+i );
      if( i==30UL ) {
        FD_TEST( queue->tx_posted==start && tail==old_tail );
        fd_iavf_hw_tx_flush( queue );
        FD_TEST( tail==((start+31UL) & 63UL) );
      }
    }
    fd_iavf_hw_tx_flush( queue );
    FD_TEST( tail==(queue->tx_prod & 63UL) );
    FD_TEST( (desc[ (start+30UL) & 63UL ].cmd_type_offset_buffer_sz & 0xffUL)==0x70UL );
    FD_TEST( (desc[ (start+62UL) & 63UL ].cmd_type_offset_buffer_sz & 0xffUL)==0x70UL );
    ulong comp_bytes = ULONG_MAX;
    FD_TEST( fd_iavf_hw_poll_tx( vf, &comp_bytes )==0UL && !comp_bytes );
    desc[ (start+30UL) & 63UL ].cmd_type_offset_buffer_sz = 0xfUL;
    FD_TEST( fd_iavf_hw_poll_tx( vf, &comp_bytes )==31UL && comp_bytes==2325UL );
    FD_TEST( queue->tx_cons==start+31UL );
    desc[ (start+62UL) & 63UL ].cmd_type_offset_buffer_sz = 0xfUL;
    FD_TEST( fd_iavf_hw_poll_tx( vf, &comp_bytes )==32UL && comp_bytes==3408UL );
    FD_TEST( queue->tx_cons==queue->tx_prod );
    FD_TEST( queue->tx_comp_cons==queue->tx_comp_prod );
    FD_TEST( fd_iavf_hw_poll_tx( vf, &comp_bytes )==0UL && !comp_bytes );
  }
}

static void
test_rx_ring( void ) {
  fd_iavf_rx_desc_t desc[ 128 ] = {0};
  uint chunks[ 128 ]             = {0};
  uint tail                     = 0U;
  fd_memset( &test_tile, 0, sizeof(test_tile) );
  test_tile.net.pkt_buf_chunk0 = 1UL;
  test_tile.batch_size         = FD_IAVF_BATCH_SIZE;
  fd_iavf_tile_vf_t * vf = &test_tile.vfs[0];
  vf->packet_iova0           = 0x200000000UL;
  vf->rx_desc_buf_chunk      = chunks;
  vf->queue = (fd_iavf_queue_t) {
    .rx_ring = desc, .rx_depth=128U, .rx_tail=&tail, .enabled=1,
    .rx_prod = 65535UL, .rx_posted=65535UL, .rx_cons=65535UL
  };
  fd_iavf_queue_t * queue = &vf->queue;
  fd_iavf_hw_rx_comp_t comp[ 64 ];
  for( uint cycle=0U; cycle<256U; cycle++ ) {
    ulong start = queue->rx_prod;
    uint old_tail = tail;
    for( ulong i=0UL; i<127UL; i++ ) {
      fd_iavf_tile_rx_recycle( &test_tile, vf, 1UL+((i*2048UL)>>FD_CHUNK_LG_SZ) );
      if( i==62UL ) FD_TEST( queue->rx_prod==start && tail==old_tail && vf->rx_pending_cnt==63U );
      if( i==63UL ) FD_TEST( queue->rx_prod==start+64UL && tail==((start+64UL) & 127UL) && !vf->rx_pending_cnt );
    }
    FD_TEST( queue->rx_prod==start+64UL && vf->rx_pending_cnt==63U );
    FD_TEST( !fd_iavf_hw_rx_enqueue( &test_tile, vf, vf->rx_pending_cnt ) );
    vf->rx_pending_cnt = 0U;
    FD_TEST( tail==(queue->rx_prod & 127UL) && queue->rx_posted==start+127UL );
    fd_iavf_rx_desc_t unused = desc[ (start+127UL) & 127UL ];
    uint unused_chunk = chunks[ (start+127UL) & 127UL ];
    FD_TEST( fd_iavf_hw_rx_enqueue( &test_tile, vf, 1U )==-1 && errno==ENOSPC );
    FD_TEST( queue->rx_prod==start+127UL && queue->rx_posted==start+127UL && tail==((start+127UL) & 127UL) );
    FD_TEST( !memcmp( &unused, &desc[ (start+127UL) & 127UL ], sizeof(unused) ) );
    FD_TEST( chunks[ (start+127UL) & 127UL ]==unused_chunk );
    FD_TEST( !fd_iavf_hw_poll_rx( vf, comp, 64U ) );
    for( ulong i=0UL; i<127UL; i++ ) {
      uint desc_idx = (uint)((start+i) & 127UL);
      FD_TEST( desc[desc_idx].qword[0]==0x200000000UL+i*2048UL );
      FD_TEST( !desc[desc_idx].qword[1] && !desc[desc_idx].qword[2] && !desc[desc_idx].qword[3] );
      FD_TEST( chunks[desc_idx]==1UL+((i*2048UL)>>FD_CHUNK_LG_SZ) );
      desc[ (start+i) & 127UL ].qword[1] = 3UL | ((60UL+i)<<38);
    }
    ulong comp_cnt = 0UL;
    while( comp_cnt<127UL ) {
      int count = fd_iavf_hw_poll_rx( vf, comp, 64U );
      FD_TEST( count>0 && count<=64 );
      for( int i=0; i<count; i++ ) {
        FD_TEST( comp[i].chunk==1UL+((comp_cnt*2048UL)>>FD_CHUNK_LG_SZ) );
        FD_TEST( comp[i].frame_sz==60UL+comp_cnt && !comp[i].error_flags );
        comp_cnt++;
      }
    }
    FD_TEST( queue->rx_cons==queue->rx_prod );
  }

  ulong start = queue->rx_prod;
  for( uint i=0U; i<5U; i++ ) vf->rx_pending_chunk[i] = (uint)(1UL+(((ulong)i*2048UL)>>FD_CHUNK_LG_SZ));
  FD_TEST( !fd_iavf_hw_rx_enqueue( &test_tile, vf, 5U ) );
  desc[ (start+0UL) & 127UL ].qword[1] = 3UL | (1UL<<20) | (64UL<<38);
  desc[ (start+1UL) & 127UL ].qword[1] = 3UL | (1UL<<19) | (64UL<<38);
  desc[ (start+2UL) & 127UL ].qword[1] = 1UL | (2048UL<<38);
  desc[ (start+3UL) & 127UL ].qword[1] = 3UL | (64UL<<38);
  desc[ (start+4UL) & 127UL ].qword[1] = 3UL | (64UL<<38);
  FD_TEST( fd_iavf_hw_poll_rx( vf, comp, 3U )==3 );
  FD_TEST( !comp[0].error_flags && comp[1].error_flags && comp[2].error_flags );
  FD_TEST( fd_iavf_hw_poll_rx( vf, comp, 3U )==2 );
  FD_TEST( comp[0].error_flags && !comp[1].error_flags );
}

static void
test_vf_batches( void ) {
  fd_iavf_rx_desc_t desc[ 2 ][ 128 ] = {0};
  uint chunks[ 2 ][ 128 ]            = {0};
  uint tail[ 2 ]                     = {0};
  fd_memset( &test_tile, 0, sizeof(test_tile) );
  test_tile.net.pkt_buf_chunk0 = 1UL;
  test_tile.batch_size         = FD_IAVF_BATCH_SIZE;
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_iavf_tile_vf_t * vf = &test_tile.vfs[i];
    vf->packet_iova0           = 0x200000000UL+i*0x100000000UL;
    vf->rx_desc_buf_chunk      = chunks[i];
    vf->queue = (fd_iavf_queue_t) { .rx_ring=desc[i], .rx_depth=128U, .rx_tail=&tail[i] };
    for( ulong j=0UL; j<63UL; j++ ) {
      fd_iavf_tile_rx_recycle( &test_tile, vf, 1UL+((j*2048UL)>>FD_CHUNK_LG_SZ) );
    }
    FD_TEST( vf->rx_pending_cnt==63U && !tail[i] && !vf->queue.rx_prod );
  }
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_iavf_tile_vf_t * vf = &test_tile.vfs[i];
    fd_iavf_tile_rx_recycle( &test_tile, vf, 1UL+((63UL*2048UL)>>FD_CHUNK_LG_SZ) );
    FD_TEST( !vf->rx_pending_cnt && tail[i]==64U && vf->queue.rx_posted==64UL );
    FD_TEST( desc[i][0].qword[0]==vf->packet_iova0 );
    FD_TEST( desc[i][63].qword[0]==vf->packet_iova0+63UL*2048UL );
    if( !i ) FD_TEST( !tail[1] && test_tile.vfs[1].rx_pending_cnt==63U );
  }
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

  fd_memset( &test_tile, 0, sizeof(test_tile) );
  test_tile.net.pkt_buf_chunk0 = 1UL;
  uint chunks[ 64 ];
  fd_iavf_tile_vf_t * vf = &test_tile.vfs[0];
  vf->packet_iova0           = 0x200000000UL;
  vf->rx_desc_buf_chunk      = chunks;
  ulong  queue_sz     = fd_iavf_queue_footprint( 64U, 64U );
  void * queue_memory = NULL;
  void * rx_memory    = NULL;
  FD_TEST( !posix_memalign( &queue_memory, 4096UL, queue_sz ) );
  FD_TEST( !posix_memalign( &rx_memory, 4096UL, 64UL*2048UL ) );
  FD_TEST( !fd_iavf_virtchnl_configure_queue( &vfio, &adminq, &info, &vf->queue, queue_memory,
                                              queue_sz, 0x100100000UL, 64U, 64U, 2048U, 2048U ) );
  FD_TEST( !fd_iavf_virtchnl_add_mac( &vfio, &adminq, &info ) );
  FD_TEST( !fd_iavf_virtchnl_configure_rss( &vfio, &adminq, &info, 1U ) );
  FD_TEST( !fd_iavf_vfio_dma_map( &vfio, rx_memory, 64UL*2048UL, 0x200000000UL ) );
  for( uint i=0U; i<63U; i++ ) {
    vf->rx_pending_chunk[i] = (uint)(1UL+(((ulong)i*2048UL)>>FD_CHUNK_LG_SZ));
  }
  FD_TEST( !fd_iavf_hw_rx_enqueue( &test_tile, vf, 63U ) );
  FD_TEST( !fd_iavf_virtchnl_enable_queue( &vfio, &adminq, &info, &vf->queue ) );
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
  test_vf_batches();
  if( argc==2 ) test_hardware( argv[1] );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
