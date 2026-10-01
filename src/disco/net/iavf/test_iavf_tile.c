#define FD_TILE_TEST 1
#include "fd_iavf_tile.c"

/* test_adminq_memory uses Intel's descriptor pages followed by per-entry buffers. */
static struct {
  uint  send_desc[ FD_IAVF_PAGE_SZ/sizeof(uint) ];
  uint  recv_desc[ FD_IAVF_PAGE_SZ/sizeof(uint) ];
  uchar send_buf[ 32 ][ 4096 ];
  uchar recv_buf[ 32 ][ 4096 ];
} test_adminq_memory __attribute__((aligned(FD_IAVF_PAGE_SZ)));
static uint test_adminq_regs[ FD_IAVF_BAR0_MAP_SZ/sizeof(uint) ];

static void
test_adminq_init( fd_iavf_vfio_t *   vfio,
                  fd_iavf_adminq_t * adminq ) {
  FD_TEST( sizeof(test_adminq_memory)==fd_iavf_adminq_footprint() );
  fd_memset( &test_adminq_memory, 0, sizeof(test_adminq_memory) );
  fd_memset( test_adminq_regs, 0, sizeof(test_adminq_regs) );
  *vfio   = (fd_iavf_vfio_t) { .bar0=(volatile uchar *)test_adminq_regs };
  *adminq = (fd_iavf_adminq_t) { .dma_memory=&test_adminq_memory };
  test_adminq_regs[ 0x8800UL/sizeof(uint) ] = 2U;      /* IAVF_VFGEN_RSTAT, VIRTCHNL_VFR_VFACTIVE */
  test_adminq_regs[ 0x6800UL/sizeof(uint) ] = 1U<<31;  /* IAVF_VF_ATQLEN1_ATQENABLE_MASK */
  test_adminq_regs[ 0x8000UL/sizeof(uint) ] = 1U<<31;  /* IAVF_VF_ARQLEN1_ARQENABLE_MASK */
  test_adminq_regs[ 0x6400UL/sizeof(uint) ] = 1U;      /* IAVF_VF_ATQH1 */
}

static void
test_adminq_reply( uint         op,
                   int          status,
                   void const * message,
                   ulong        message_sz ) {
  uint * head = &test_adminq_regs[ 0x7400UL/sizeof(uint) ]; /* IAVF_VF_ARQH1 */
  FD_TEST( *head<31U && message_sz<=sizeof(test_adminq_memory.recv_buf[0]) );
  uint * desc = test_adminq_memory.recv_desc+8UL*(*head);
  desc[0] = 0x08020000U; /* iavf_aqc_opc_send_msg_to_vf */
  desc[1] = (uint)message_sz;
  desc[2] = op;
  desc[3] = (uint)status;
  if( message_sz ) fd_memcpy( test_adminq_memory.recv_buf[*head], message, message_sz );
  (*head)++;
}

static void
test_adminq_resources( int legacy ) {
  /* Linux virtchnl_vf_resource and one SR-IOV virtchnl_vsi_resource.
     The legacy length includes a second zero VSI entry. */
  uint resources[ 13 ] = {
    0x00010001U, (2048U<<16)|2U, 1U|(1U<<5)|(1U<<19), 52U, 64U,
    0x00010001U, 6U, 0x00020000U, 0U
  };
  test_adminq_reply( 3U, 0, resources, legacy ? 52UL : 36UL ); /* VIRTCHNL_OP_GET_VF_RESOURCES */
}

static void
test_virtchnl_setup( void ) {
  fd_iavf_vfio_t   vfio;
  fd_iavf_adminq_t adminq;
  fd_iavf_vf_info_t info;
  uint event[4] = { 1U, 100000U, 1U, 0U }; /* virtchnl_pf_event */
  uint version[2] = {1U,1U};

  /* A link report arriving during negotiation must survive resource discovery. */
  test_adminq_init( &vfio, &adminq );
  test_adminq_reply( 17U, 0, event, 16UL ); /* VIRTCHNL_OP_EVENT */
  test_adminq_reply( 1U, 0, version, sizeof(version) ); /* VIRTCHNL_OP_VERSION */
  FD_TEST( !fd_iavf_virtchnl_version( &vfio, &adminq ) );
  uint requested_version[2];
  fd_memcpy( requested_version, test_adminq_memory.send_buf[0], sizeof(requested_version) );
  FD_TEST( requested_version[0]==1U && requested_version[1]==1U );
  test_adminq_regs[ 0x6400UL/sizeof(uint) ] = 2U;
  test_adminq_resources( 0 );
  FD_TEST( !fd_iavf_virtchnl_get_resources( &vfio, &adminq, &info ) );
  FD_TEST( info.link_usable );
  FD_TEST( info.vsi_id==1U && info.queue_pair_cnt==1U && info.vector_cnt==2U && info.max_mtu==2048U );
  FD_TEST( info.rss_key_sz==52U && info.rss_lut_sz==64U && info.mac_addr[0]==2U );
  FD_TEST( info.wb_on_itr );
  uint requested_caps;
  fd_memcpy( &requested_caps, test_adminq_memory.send_buf[1], sizeof(requested_caps) );
  FD_TEST( requested_caps==(1U|(1U<<5)|(1U<<19)) );

  int changed = -1;
  event[2] = 0U;
  test_adminq_reply( 17U, 0, event, 16UL );
  FD_TEST( !fd_iavf_virtchnl_poll_link( &vfio, &adminq, &info, &changed ) );
  FD_TEST( changed && !info.link_usable );
  event[2] = 1U;
  test_adminq_reply( 17U, 0, event, 16UL );
  FD_TEST( !fd_iavf_virtchnl_poll_link( &vfio, &adminq, &info, &changed ) );
  FD_TEST( changed && info.link_usable );
  FD_TEST( !fd_iavf_virtchnl_poll_link( &vfio, &adminq, &info, &changed ) && !changed && info.link_usable );

  /* WB_ON_ITR is optional when the PF provides L2 and RSS. */
  test_adminq_init( &vfio, &adminq );
  test_adminq_resources( 0 );
  uint const unsupported_caps = 1U|(1U<<19);
  fd_memcpy( test_adminq_memory.recv_buf[0]+8UL, &unsupported_caps, sizeof(unsupported_caps) );
  FD_TEST( !fd_iavf_virtchnl_get_resources( &vfio, &adminq, &info ) );
  FD_TEST( !info.wb_on_itr );

  test_adminq_init( &vfio, &adminq );
  version[1] = 0U;
  test_adminq_reply( 1U, 0, version, sizeof(version) );
  FD_TEST( fd_iavf_virtchnl_version( &vfio, &adminq )==-1 && errno==EPROTONOSUPPORT );
}

static void
test_virtchnl_initial_link( void ) {
  fd_iavf_vfio_t    vfio;
  fd_iavf_adminq_t  adminq;
  fd_iavf_vf_info_t info;
  uint const down[4] = { 1U, 0U, 0U, 0U }; /* virtchnl_pf_event */
  uint const up[4]   = { 1U, 0U, 1U, 0U };
  int changed;

  /* An initial down report must leave the later up report for runtime polling. */
  for( int legacy=0; legacy<2; legacy++ ) {
    test_adminq_init( &vfio, &adminq );
    test_adminq_resources( legacy );
    test_adminq_reply( 17U, 0, down, sizeof(down) );
    test_adminq_reply( 17U, 0, up, sizeof(up) );
    FD_TEST( !fd_iavf_virtchnl_get_resources( &vfio, &adminq, &info ) );
    FD_TEST( !info.link_usable );
    FD_TEST( !fd_iavf_virtchnl_poll_link( &vfio, &adminq, &info, &changed ) );
    FD_TEST( changed && info.link_usable );
  }

  /* Resource discovery succeeds without a link event, leaving the VF unusable. */
  test_adminq_init( &vfio, &adminq );
  test_adminq_resources( 0 );
  FD_TEST( !fd_iavf_virtchnl_get_resources( &vfio, &adminq, &info ) && !info.link_usable );
}

static void
test_virtchnl_shutdown( void ) {
  fd_iavf_vfio_t    vfio;
  fd_iavf_adminq_t  adminq;
  fd_iavf_vf_info_t info = {0};
  uint const version[2] = {1U,1U};
  uint event[4] = { 2U, 0U, 0U, 0U }; /* VIRTCHNL_EVENT_RESET_IMPENDING */

  /* A reset must abort the request even when a successful reply follows it. */
  test_adminq_init( &vfio, &adminq );
  test_adminq_reply( 17U, 0, event, sizeof(event) );
  test_adminq_reply( 1U, 0, version, sizeof(version) );
  FD_TEST( fd_iavf_virtchnl_version( &vfio, &adminq )==-1 && errno==ECONNRESET );

  /* A later link-up report must not hide the PF driver closing. */
  test_adminq_init( &vfio, &adminq );
  event[0] = 3U; /* VIRTCHNL_EVENT_PF_DRIVER_CLOSE */
  test_adminq_reply( 17U, 0, event, sizeof(event) );
  event[0] = 1U;
  event[2] = 1U;
  test_adminq_reply( 17U, 0, event, sizeof(event) );
  int changed;
  FD_TEST( fd_iavf_virtchnl_poll_link( &vfio, &adminq, &info, &changed )==-1 && errno==ESHUTDOWN );
  FD_TEST( !info.link_usable );
}

static void
test_queue_mapping_failure( void ) {
  static uchar memory[ 3UL*FD_IAVF_PAGE_SZ ] __attribute__((aligned(FD_IAVF_PAGE_SZ)));
  fd_iavf_vfio_t vfio = {
    .container_fd = INT_MAX,
    .bar0         = (volatile uchar *)test_adminq_regs,
    .iova_pgsizes = FD_IAVF_PAGE_SZ
  };
  fd_iavf_adminq_t  adminq    = {0};
  fd_iavf_vf_info_t resources = { .queue_pair_cnt=1U, .vector_cnt=2U, .max_mtu=2048U };
  fd_iavf_queue_t tx_queue = { .depth=64U };
  fd_iavf_queue_t rx_queue = { .depth=64U };
  fd_iavf_vfio_tile_t tile = {
    .tx_queue        = &tx_queue,
    .rx_queue        = &rx_queue,
    .queue_memory    = memory,
    .queue_memory_sz = sizeof(memory)
  };
  /* A mapping failure must leave descriptor memory and queue state untouched. */
  fd_memset( memory, 0xa5, sizeof(memory) );
  FD_TEST( fd_iavf_virtchnl_configure_queue( &vfio, &adminq, &resources, &tile,
                                            4096UL, 2048U, 2048U )==-1 && errno==EBADF );
  for( ulong i=0UL; i<sizeof(memory); i++ ) FD_TEST( memory[i]==0xa5 );
  FD_TEST( !tx_queue.ring && !rx_queue.ring );
}

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
}

static fd_iavf_tile_t test_tile;
static fd_netdev_tbl_hdr_t test_netdev_hdr;
static fd_netdev_t test_netdevs[ 4 ];

static void
test_vfs_init( void ) {
  fd_memset( &test_tile, 0, sizeof(test_tile) );
  test_netdev_hdr = (fd_netdev_tbl_hdr_t) { .dev_cnt=1U };
  test_tile.router.netdev_tbl = (fd_netdev_tbl_join_t) { .hdr=&test_netdev_hdr, .dev_tbl=test_netdevs };
  test_tile.router.if_virt = 2U;
  test_tile.net.tile_cnt = 1UL;
  test_tile.vf_cnt = 1UL;
  test_netdevs[0] = (fd_netdev_t) { .if_idx=2U, .dev_type=ARPHRD_ETHER, .oper_status=FD_OPER_STATUS_UP, .mtu=1500U };
  test_tile.vfs[0].if_idx = 2U;
  test_tile.vfs[0].vf_info.link_usable = 1;
  test_tile.vfs[0].tx_queue.depth = 64U;
}

static void
test_inactive_rx( void ) {
  test_vfs_init();
  fd_iavf_hw_rx_desc_t desc[ 2 ][ 128 ] = {0};
  uint chunks[ 128 ]                    = { 1U, 2U };
  uint tail                             = 0U;
  test_tile.batch_size               = 1U;
  test_tile.net.pkt_buf_chunk0       = 1UL;
  test_tile.net.pkt_buf_wmark        = 64UL;
  for( ulong i=0UL; i<2UL; i++ ) {
    test_tile.vfs[i].rx_queue = (fd_iavf_queue_t) { .ring=desc[i], .depth=128U, .enabled=1 };
  }
  fd_iavf_tile_vf_t * vf = &test_tile.vfs[0];
  vf->rx_queue.prod          = vf->rx_queue.posted = 2UL;
  vf->rx_queue.tail          = &tail;
  vf->rx_desc_buf_chunk      = chunks;
  vf->vf_info.link_usable    = 0;
  desc[0][0].qword[1]        = FD_IAVF_RX_DESC_DONE | (2048UL<<FD_IAVF_RX_DESC_LENGTH_SHIFT);
  desc[0][1].qword[1]        = FD_IAVF_RX_DESC_DONE | FD_IAVF_RX_DESC_END_OF_PACKET | (64UL<<FD_IAVF_RX_DESC_LENGTH_SHIFT);
  FD_TEST( fd_iavf_tile_poll_rx( &test_tile, NULL ) );
  FD_TEST( !test_tile.metrics.rx_no_link_cnt && vf->rx_queue.cons==1UL );
  FD_TEST( fd_iavf_tile_poll_rx( &test_tile, NULL ) );
  FD_TEST( test_tile.metrics.rx_no_link_cnt==1UL && !test_tile.net.metrics.rx_pkt_cnt );
  FD_TEST( vf->rx_queue.cons==2UL && vf->rx_queue.prod==4UL && tail==4U );
  FD_TEST( chunks[2]==1U && chunks[3]==2U );
  FD_TEST( desc[0][2].qword[0]==64UL && desc[0][3].qword[0]==128UL );
  FD_TEST( !fd_iavf_tile_poll_rx( &test_tile, NULL ) );
}

static void
test_tx_ring( void ) {
  fd_iavf_tx_desc_t desc[ 64 ] = {0};
  ulong endpoints[ 64 ]        = {0};
  uint chunks[ 64 ]            = {0};
  ushort frame_sz[ 64 ]        = {0};
  uint tail                    = 0U;
  fd_memset( &test_tile, 0, sizeof(test_tile) );
  ulong const packet_iova = 0x100001000UL;
  fd_iavf_tile_vf_t * vf = &test_tile.vfs[0];
  vf->tx_desc_buf_chunk      = chunks;
  vf->tx_desc_frame_sz       = frame_sz;
  vf->tx_queue = (fd_iavf_queue_t) {
    .ring      = desc, .comp_ring=endpoints, .depth=64U, .tail=&tail,
    .prod      = 65598UL, .posted=65598UL, .cons=65598UL,
    .comp_prod = 63UL, .comp_cons=63UL, .enabled=1
  };
  fd_iavf_queue_t * tx_queue = &vf->tx_queue;
  for( uint cycle=0U; cycle<256U; cycle++ ) {
    ulong start = tx_queue->prod;
    uint old_tail = tail;
    for( ulong i=0UL; i<63UL; i++ ) {
      chunks[ (start+i) & 63UL ] = (uint)((packet_iova+i*2048UL)>>FD_CHUNK_LG_SZ);
      fd_iavf_hw_tx_enqueue( vf, 60UL+i );
      fd_iavf_tx_desc_t const * entry = &desc[ (start+i) & 63UL ];
      FD_TEST( entry->buffer_iova==packet_iova+i*2048UL );
      FD_TEST( (entry->cmd_type_offset_buffer_sz & 0xffUL)==0x50UL );
      FD_TEST( (entry->cmd_type_offset_buffer_sz>>34)==60UL+i );
      FD_TEST( frame_sz[ (start+i) & 63UL ]==60UL+i );
      if( i==30UL ) {
        FD_TEST( tx_queue->posted==start && tail==old_tail );
        fd_iavf_hw_tx_flush( tx_queue );
        FD_TEST( tail==((start+31UL) & 63UL) );
      }
    }
    fd_iavf_hw_tx_flush( tx_queue );
    FD_TEST( tail==(tx_queue->prod & 63UL) );
    FD_TEST( (desc[ (start+30UL) & 63UL ].cmd_type_offset_buffer_sz & 0xffUL)==0x70UL );
    FD_TEST( (desc[ (start+62UL) & 63UL ].cmd_type_offset_buffer_sz & 0xffUL)==0x70UL );
    ulong comp_bytes = ULONG_MAX;
    FD_TEST( fd_iavf_hw_poll_tx( vf, &comp_bytes )==0UL && !comp_bytes );
    desc[ (start+62UL) & 63UL ].cmd_type_offset_buffer_sz = 0xfUL;
    FD_TEST( fd_iavf_hw_poll_tx( vf, &comp_bytes )==0UL && !comp_bytes );
    FD_TEST( tx_queue->cons==start );
    desc[ (start+30UL) & 63UL ].cmd_type_offset_buffer_sz = 0xfUL;
    FD_TEST( fd_iavf_hw_poll_tx( vf, &comp_bytes )==31UL && comp_bytes==2325UL );
    FD_TEST( tx_queue->cons==start+31UL );
    FD_TEST( tx_queue->comp_cons+1UL==tx_queue->comp_prod );
    FD_TEST( fd_iavf_hw_poll_tx( vf, &comp_bytes )==32UL && comp_bytes==3408UL );
    FD_TEST( tx_queue->cons==tx_queue->prod );
    FD_TEST( tx_queue->comp_cons==tx_queue->comp_prod );
    FD_TEST( fd_iavf_hw_poll_tx( vf, &comp_bytes )==0UL && !comp_bytes );
  }
}

static void
test_tx_poll( void ) {
  fd_iavf_tx_desc_t desc[ 64 ] = {0};
  ulong endpoints[ 64 ]        = {0};
  uint chunks[ 64 ]            = {0};
  ushort frame_sz[ 64 ]        = {0};
  uint tail                    = 0U;
  fd_memset( &test_tile, 0, sizeof(test_tile) );
  test_tile.batch_size                 = FD_IAVF_BATCH_SIZE;
  test_tile.net.metrics.tx_pkt_cnt     = 10UL;
  test_tile.net.metrics.tx_bytes_total = 100UL;
  fd_iavf_tile_vf_t * vf = &test_tile.vfs[0];
  vf->tx_desc_buf_chunk = chunks;
  vf->tx_desc_frame_sz  = frame_sz;
  vf->tx_queue = (fd_iavf_queue_t) { .ring=desc, .comp_ring=endpoints, .depth=64U, .tail=&tail, .enabled=1 };
  fd_iavf_queue_t * tx_queue = &vf->tx_queue;
  FD_TEST( !fd_iavf_tile_poll_tx( &test_tile, vf ) );
  FD_TEST( test_tile.net.metrics.tx_pkt_cnt==10UL && test_tile.net.metrics.tx_bytes_total==100UL );
  for( uint batch_idx=0U; batch_idx<3U; batch_idx++ ) {
    for( uint i=0U; i<3U; i++ ) fd_iavf_hw_tx_enqueue( vf, 64UL );
    fd_iavf_hw_tx_flush( tx_queue );
    desc[ tx_queue->prod-1UL ].cmd_type_offset_buffer_sz = FD_IAVF_TX_DESC_DONE;
  }

  FD_TEST( fd_iavf_tile_poll_tx( &test_tile, vf ) );
  FD_TEST( tx_queue->cons==3UL && tx_queue->comp_cons==1UL && tx_queue->comp_prod==3UL );
  FD_TEST( test_tile.net.metrics.tx_pkt_cnt==13UL && test_tile.net.metrics.tx_bytes_total==100UL+3UL*64UL );
  FD_TEST( fd_iavf_tile_poll_tx( &test_tile, vf ) );
  FD_TEST( tx_queue->cons==6UL && tx_queue->comp_cons==2UL && tx_queue->comp_prod==3UL );
  FD_TEST( test_tile.net.metrics.tx_pkt_cnt==16UL && test_tile.net.metrics.tx_bytes_total==100UL+6UL*64UL );
  FD_TEST( fd_iavf_tile_poll_tx( &test_tile, vf ) );
  FD_TEST( tx_queue->cons==9UL && tx_queue->comp_cons==tx_queue->comp_prod );
  FD_TEST( test_tile.net.metrics.tx_pkt_cnt==19UL && test_tile.net.metrics.tx_bytes_total==100UL+9UL*64UL );
  FD_TEST( !fd_iavf_tile_poll_tx( &test_tile, vf ) );
  FD_TEST( test_tile.net.metrics.tx_pkt_cnt==19UL && test_tile.net.metrics.tx_bytes_total==100UL+9UL*64UL );
}

static void
test_loopback_send( void ) {
  fd_memset( &test_tile, 0, sizeof(test_tile) );
  int sockets[2];
  FD_TEST( !socketpair( AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, sockets ) );
  uchar data = 0x5a;
  for( uint i=0U; i<3U; i++ ) {
    test_tile.lo_tx_iov[i] = (struct iovec) { .iov_base=i==1U ? NULL : &data, .iov_len=1UL };
    test_tile.lo_tx_msg[i].msg_hdr = (struct msghdr) { .msg_iov=&test_tile.lo_tx_iov[i], .msg_iovlen=1UL };
  }
  /* A bad second buffer makes sendmmsg accept only the first packet */
  test_tile.lo_tx_sock = sockets[0];
  test_tile.lo_tx_cnt  = 3U;
  fd_iavf_tile_lo_tx_flush( &test_tile );
  FD_TEST( !test_tile.lo_tx_cnt && test_tile.metrics.tx_loopback_fail_cnt==2UL );
  FD_TEST( test_tile.net.metrics.tx_pkt_cnt==1UL && test_tile.net.metrics.tx_bytes_total==sizeof(fd_eth_hdr_t)+1UL );
  uchar received;
  FD_TEST( recv( sockets[1], &received, 1UL, MSG_DONTWAIT )==1L && received==data );
  FD_TEST( recv( sockets[1], &received, 1UL, MSG_DONTWAIT )==-1L && errno==EAGAIN );

  test_tile.lo_tx_sock = -1;
  test_tile.lo_tx_cnt  = 3U;
  fd_iavf_tile_lo_tx_flush( &test_tile );
  FD_TEST( !test_tile.lo_tx_cnt && test_tile.metrics.tx_loopback_fail_cnt==5UL );
  FD_TEST( test_tile.net.metrics.tx_pkt_cnt==1UL && test_tile.net.metrics.tx_bytes_total==sizeof(fd_eth_hdr_t)+1UL );
  FD_TEST( !close( sockets[0] ) && !close( sockets[1] ) );
}

static void
test_rx_ring( void ) {
  fd_iavf_hw_rx_desc_t desc[ 128 ] = {0};
  uint chunks[ 128 ]               = {0};
  uint tail                        = 0U;
  fd_memset( &test_tile, 0, sizeof(test_tile) );
  ulong const packet_iova = 0x200001000UL;
  test_tile.net.pkt_buf_chunk0 = packet_iova>>FD_CHUNK_LG_SZ;
  test_tile.batch_size         = FD_IAVF_BATCH_SIZE;
  fd_iavf_tile_vf_t * vf = &test_tile.vfs[0];
  vf->rx_desc_buf_chunk      = chunks;
  vf->rx_queue = (fd_iavf_queue_t) {
    .ring = desc, .depth=128U, .tail=&tail, .enabled=1,
    .prod = 65535UL, .posted=65535UL, .cons=65535UL
  };
  fd_iavf_queue_t * rx_queue = &vf->rx_queue;
  fd_iavf_tile_rx_comp_t comp[ 64 ];
  for( uint cycle=0U; cycle<256U; cycle++ ) {
    ulong start = rx_queue->prod;
    uint old_tail = tail;
    for( ulong i=0UL; i<127UL; i++ ) {
      fd_iavf_tile_rx_recycle( &test_tile, vf, (packet_iova+i*2048UL)>>FD_CHUNK_LG_SZ );
      if( i==62UL ) FD_TEST( rx_queue->prod==start && tail==old_tail && vf->rx_pending_cnt==63U );
      if( i==63UL ) FD_TEST( rx_queue->prod==start+64UL && tail==((start+64UL) & 127UL) && !vf->rx_pending_cnt );
    }
    FD_TEST( rx_queue->prod==start+64UL && vf->rx_pending_cnt==63U );
    FD_TEST( !fd_iavf_hw_rx_enqueue( vf, vf->rx_pending_cnt ) );
    vf->rx_pending_cnt = 0U;
    FD_TEST( tail==(rx_queue->prod & 127UL) && rx_queue->posted==start+127UL );
    fd_iavf_hw_rx_desc_t unused = desc[ (start+127UL) & 127UL ];
    uint unused_chunk = chunks[ (start+127UL) & 127UL ];
    FD_TEST( fd_iavf_hw_rx_enqueue( vf, 1U )==-1 && errno==ENOSPC );
    FD_TEST( rx_queue->prod==start+127UL && rx_queue->posted==start+127UL && tail==((start+127UL) & 127UL) );
    FD_TEST( !memcmp( &unused, &desc[ (start+127UL) & 127UL ], sizeof(unused) ) );
    FD_TEST( chunks[ (start+127UL) & 127UL ]==unused_chunk );
    FD_TEST( !fd_iavf_hw_poll_rx( vf, comp, 64U ) );
    for( ulong i=0UL; i<127UL; i++ ) {
      uint desc_idx = (uint)((start+i) & 127UL);
      FD_TEST( desc[desc_idx].qword[0]==packet_iova+i*2048UL );
      FD_TEST( !desc[desc_idx].qword[1] && !desc[desc_idx].qword[2] && !desc[desc_idx].qword[3] );
      FD_TEST( chunks[desc_idx]==(packet_iova+i*2048UL)>>FD_CHUNK_LG_SZ );
      desc[ (start+i) & 127UL ].qword[1] = 3UL | ((60UL+i)<<38);
    }
    ulong comp_cnt = 0UL;
    while( comp_cnt<127UL ) {
      int count = fd_iavf_hw_poll_rx( vf, comp, 64U );
      FD_TEST( count>0 && count<=64 );
      for( int i=0; i<count; i++ ) {
        FD_TEST( comp[i].chunk==(packet_iova+comp_cnt*2048UL)>>FD_CHUNK_LG_SZ );
        FD_TEST( comp[i].frame_sz==60UL+comp_cnt && !comp[i].discard );
        comp_cnt++;
      }
    }
    FD_TEST( rx_queue->cons==rx_queue->prod );
  }

  ulong start = rx_queue->prod;
  for( uint i=0U; i<5U; i++ ) vf->rx_pending_chunk[i] = (uint)((packet_iova+(ulong)i*2048UL)>>FD_CHUNK_LG_SZ);
  FD_TEST( !fd_iavf_hw_rx_enqueue( vf, 5U ) );
  desc[ (start+0UL) & 127UL ].qword[1] = 3UL | (1UL<<20) | (64UL<<38);
  desc[ (start+1UL) & 127UL ].qword[1] = 3UL | (1UL<<19) | (64UL<<38);
  desc[ (start+2UL) & 127UL ].qword[1] = 1UL | (2048UL<<38);
  desc[ (start+3UL) & 127UL ].qword[1] = 3UL | (64UL<<38);
  desc[ (start+4UL) & 127UL ].qword[1] = 3UL | (64UL<<38);
  FD_TEST( fd_iavf_hw_poll_rx( vf, comp, 3U )==3 );
  FD_TEST( !comp[0].discard && comp[1].discard && comp[2].discard );
  FD_TEST( fd_iavf_hw_poll_rx( vf, comp, 3U )==2 );
  FD_TEST( comp[0].discard && !comp[1].discard );
}

static void
test_packet_memory( void ) {
  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 512UL, cpu_idx, "iavf-packets", 0UL );
  FD_TEST( wksp );
  static fd_topo_t topo;
  fd_memset( &topo, 0, sizeof(topo) );
  topo.workspaces[0].wksp = wksp;

  ulong packet_end = 0UL;
  for( ulong i=0UL; i<1UL; i++ ) {
    ulong const data_sz = (65UL+2UL*i)*FD_NET_MTU+17UL;
    ulong const footprint = fd_dcache_footprint( data_sz, 0UL );
    void * packet_dcache_memory = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), footprint, 1UL );
    FD_TEST( packet_dcache_memory );
    void * packet_dcache = fd_dcache_join( fd_dcache_new( packet_dcache_memory, data_sz, 0UL ) );
    FD_TEST( packet_dcache );
    topo.objs[i] = (fd_topo_obj_t) { .id=i, .wksp_id=0UL, .offset=(ulong)packet_dcache_memory-(ulong)wksp };
    topo.tiles[i].net.umem_dcache_obj_id = i;
    fd_memset( &test_tile, 0, sizeof(test_tile) );

    void * packet_memory;
    ulong packet_memory_sz;
    ulong packet_iova;
    fd_iavf_tile_join_pkt_bufs( &topo, &topo.tiles[i], &test_tile, &packet_memory, &packet_memory_sz, &packet_iova );
    FD_TEST( packet_memory==packet_dcache );
    FD_TEST( fd_ulong_is_aligned( packet_iova, FD_IAVF_PAGE_SZ ) );
    FD_TEST( fd_ulong_is_aligned( packet_memory_sz, FD_IAVF_PAGE_SZ ) );
    FD_TEST( (ulong)packet_memory+packet_memory_sz<=(ulong)packet_dcache_memory+footprint );
    FD_TEST( packet_iova>=packet_end );
    packet_end = packet_iova+packet_memory_sz;

    for( ulong member=0UL; member<1UL; member++ ) {
      fd_iavf_hw_rx_desc_t rx_desc[4] = {0};
      fd_iavf_tx_desc_t tx_desc[4]    = {0};
      uint rx_chunks[4]               = {0};
      uint tx_chunks[4]               = { (uint)test_tile.net.pkt_buf_chunk0, (uint)test_tile.net.pkt_buf_wmark };
      ushort frame_sz[4]              = {0};
      uint tail                       = 0U;
      fd_iavf_tile_vf_t * vf = &test_tile.vfs[member];
      vf->rx_queue = (fd_iavf_queue_t) { .ring=rx_desc, .depth=4U, .tail=&tail };
      vf->tx_queue = (fd_iavf_queue_t) { .ring=tx_desc, .depth=4U };
      vf->rx_desc_buf_chunk = rx_chunks;
      vf->tx_desc_buf_chunk = tx_chunks;
      vf->tx_desc_frame_sz  = frame_sz;
      vf->rx_pending_chunk[0] = tx_chunks[0];
      vf->rx_pending_chunk[1] = tx_chunks[1];
      FD_TEST( !fd_iavf_hw_rx_enqueue( vf, 2U ) );
      FD_TEST( !vf->tx_queue.prod && !vf->tx_queue.posted && !vf->tx_queue.cons );
      for( uint j=0U; j<2U; j++ ) {
        fd_iavf_hw_tx_enqueue( vf, FD_NET_MTU );
        ulong const frame_iova = tx_desc[j].buffer_iova;
        FD_TEST( rx_desc[j].qword[0]==frame_iova );
        FD_TEST( frame_iova>=packet_iova && frame_iova+FD_NET_MTU<=packet_end );
        FD_TEST( (uchar *)packet_memory+(frame_iova-packet_iova)==fd_chunk_to_laddr( wksp, tx_chunks[j] ) );
      }
      FD_TEST( vf->rx_queue.prod==2UL && vf->rx_queue.posted==2UL && !vf->rx_queue.cons && tail==2U );
      FD_TEST( vf->tx_queue.prod==2UL && !vf->tx_queue.posted && !vf->tx_queue.cons );
    }
    fd_iavf_tile_join_pkt_bufs( &topo, &topo.tiles[i], &test_tile, NULL, NULL, NULL );
    FD_TEST( test_tile.net.pkt_buf_wksp_base==wksp );
  }
  fd_wksp_delete_anonymous( wksp );
}

static void
test_queue_join( void ) {
  fd_topo_tile_t tile = {0};
  tile.iavf.member_cnt     = 1UL;
  tile.iavf.tx_queue_size  = 64U;
  tile.iavf.rx_queue_size  = 128U;
  tile.iavf.route_max      = 16UL;
  tile.iavf.route_peer_max = 16UL;
  for( ulong kind_id=0UL; kind_id<1UL; kind_id++ ) {
    tile.kind_id = kind_id;
    ulong footprint = scratch_footprint( &tile );
    void * memory;
    FD_TEST( footprint && !posix_memalign( &memory, scratch_align(), footprint ) );
    fd_memset( memory, 0, footprint );
    fd_iavf_tile_t * ctx = memory;
    void * end = fd_iavf_hw_join_queues( ctx, &tile );
    FD_TEST( (ulong)end<=(ulong)memory+footprint );
    for( ulong i=0UL; i<tile.iavf.member_cnt; i++ ) {
      fd_iavf_tile_vf_t * vf = &ctx->vfs[i];
      FD_TEST( !!vf->adminq.dma_memory==!kind_id );
      FD_TEST( vf->tx_queue.ring==vf->queue_memory );
      FD_TEST( (ulong)vf->rx_queue.ring>=(ulong)vf->tx_queue.ring+64UL*sizeof(fd_iavf_tx_desc_t) );
      FD_TEST( (ulong)vf->tx_queue.comp_ring>=(ulong)vf->rx_queue.ring+128UL*sizeof(fd_iavf_hw_rx_desc_t) );
      FD_TEST( (ulong)(vf->tx_queue.comp_ring+64UL)<=(ulong)vf->queue_memory+fd_iavf_queue_footprint( 64U, 128U ) );
      FD_TEST( vf->rx_queue.depth==128U && vf->tx_queue.depth==64U );
      vf->rx_queue.prod      = 127UL;
      vf->rx_queue.posted    = 127UL;
      vf->rx_queue.enabled   = 1;
      vf->tx_queue.prod      = 31UL;
      vf->tx_queue.posted    = 31UL;
      vf->tx_queue.comp_prod = 1UL;
      vf->tx_queue.enabled   = 1;
    }
    FD_TEST( fd_iavf_hw_join_queues( ctx, &tile )==end );
    for( ulong i=0UL; i<tile.iavf.member_cnt; i++ ) {
      fd_iavf_tile_vf_t const * vf = &ctx->vfs[i];
      FD_TEST( vf->rx_queue.depth==128U && vf->rx_queue.prod==127UL && vf->rx_queue.posted==127UL && vf->rx_queue.enabled );
      FD_TEST( vf->tx_queue.depth==64U && vf->tx_queue.prod==31UL && vf->tx_queue.posted==31UL && vf->tx_queue.comp_prod==1UL && vf->tx_queue.enabled );
    }
    free( memory );
  }
}

static void
test_hardware( char const * pci_addr,
                uint         queue_cnt ) {
  fd_iavf_vfio_t     vfio;
  fd_iavf_adminq_t   adminq = {0};
  fd_iavf_vf_info_t  info;
  FD_TEST( queue_cnt && queue_cnt<=1UL );
  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 512UL, cpu_idx, "iavf-hardware", 0UL );
  FD_TEST( wksp );
  static fd_topo_t topo;
  fd_memset( &topo, 0, sizeof(topo) );
  topo.workspaces[0].wksp = wksp;
  static fd_iavf_tile_t tiles[ 1UL ];
  fd_iavf_vfio_tile_t queues[ 1UL ];
  uint chunks[ 1UL ][ 64 ];
  ulong const queue_sz = fd_iavf_queue_footprint( 64U, 64U );
  for( uint i=0U; i<queue_cnt; i++ ) {
    fd_memset( &tiles[i], 0, sizeof(tiles[i]) );
    ulong data_sz = 64UL*FD_NET_MTU;
    void * packet_dcache_memory = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL );
    FD_TEST( fd_dcache_new( packet_dcache_memory, data_sz, 0UL ) );
    topo.objs[i] = (fd_topo_obj_t) { .id=i, .wksp_id=0UL, .offset=(ulong)packet_dcache_memory-(ulong)wksp };
    topo.tiles[i].net.umem_dcache_obj_id = i;
    fd_iavf_tile_vf_t * vf = &tiles[i].vfs[0];
    vf->tx_queue.depth    = 64U;
    vf->rx_queue.depth    = 64U;
    vf->rx_desc_buf_chunk = chunks[i];
    void * queue_memory;
    FD_TEST( !posix_memalign( &queue_memory, FD_IAVF_PAGE_SZ, queue_sz ) );
    queues[i] = (fd_iavf_vfio_tile_t) {
      .tx_queue        = &vf->tx_queue,
      .rx_queue        = &vf->rx_queue,
      .queue_memory    = queue_memory,
      .queue_memory_sz = queue_sz
    };
    fd_iavf_tile_join_pkt_bufs( &topo, &topo.tiles[i], &tiles[i],
                                &queues[i].packet_memory, &queues[i].packet_memory_sz, &queues[i].packet_iova );
  }
  FD_TEST( !posix_memalign( &adminq.dma_memory, FD_IAVF_PAGE_SZ, fd_iavf_adminq_footprint() ) );
  FD_TEST( !fd_iavf_init( &vfio, &adminq, &info, queues, pci_addr, 2048U, 2048U ) );
  FD_LOG_NOTICE(( "VF %s, VSI %hu, queue pairs %hu, vectors %hu, RSS key %u, RSS table %u",
                  pci_addr, info.vsi_id, info.queue_pair_cnt, info.vector_cnt,
                  info.rss_key_sz, info.rss_lut_sz ));

  for( uint i=0U; i<queue_cnt; i++ ) {
    fd_iavf_tile_vf_t * vf = &tiles[i].vfs[0];
    for( uint j=0U; j<63U; j++ ) {
      vf->rx_pending_chunk[j] = (uint)(tiles[i].net.pkt_buf_chunk0+(((ulong)j*2048UL)>>FD_CHUNK_LG_SZ));
    }
    FD_TEST( !fd_iavf_hw_rx_enqueue( vf, 63U ) );
    FD_LOG_NOTICE(( "queue %u packet IOVA %#lx, size %lu, first descriptor %#lx",
                    i, queues[i].packet_iova, queues[i].packet_memory_sz, ((fd_iavf_hw_rx_desc_t *)vf->rx_queue.ring)[0].qword[0] ));
  }
  FD_TEST( !fd_iavf_virtchnl_enable_queue( &vfio, &adminq, &info, queues ) );
  FD_LOG_NOTICE(( "%u queues enabled with RSS delivery and the PF-assigned MAC", queue_cnt ));

  FD_TEST( !fd_iavf_vfio_unmap_bar( &vfio ) );
  FD_TEST( !close( vfio.device_fd ) );
  FD_TEST( !close( vfio.group_fd ) );
  FD_TEST( !close( vfio.container_fd ) );
  for( uint i=0U; i<queue_cnt; i++ ) {
    free( queues[i].queue_memory );
  }
  free( adminq.dma_memory );
  fd_wksp_delete_anonymous( wksp );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_invalid_inputs();
  test_virtchnl_setup();
  test_virtchnl_initial_link();
  test_virtchnl_shutdown();
  test_queue_mapping_failure();
  test_tx_ring();
  test_tx_poll();
  test_loopback_send();
  test_rx_ring();
  test_inactive_rx();
  test_packet_memory();
  test_queue_join();
  if( argc>=2 ) {
    uint queue_cnt = 1U;
    if( argc==3 ) {
      char * end;
      ulong count = strtoul( argv[2], &end, 10 );
      FD_TEST( !*end && count && count<=1UL );
      queue_cnt = (uint)count;
    }
    FD_TEST( argc<=3 );
    test_hardware( argv[1], queue_cnt );
  }
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
