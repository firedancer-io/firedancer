#define _GNU_SOURCE

#define FD_TILE_TEST 1
#include "fd_iavf_tile.c"

#include <sys/mman.h>
#include <time.h>

#define TEST_IAVF_TX_REPORT_STATUS (2UL<<4)

static void
test_queue_init_errors( void ) {
  FD_TEST( fd_iavf_hw_init_queue( NULL, NULL, NULL, NULL, NULL, 0UL, 0UL,
                                 0U, 0U, 0U, 0U )==-1 );
  FD_TEST( errno==EINVAL );

  fd_iavf_hw_vfio_t vfio[1] = { { .container_fd=-1 } };
  fd_iavf_hw_adminq_t adminq[1] = {0};
  fd_iavf_hw_vf_info_t info[1] = { { .queue_pair_cnt=1U, .vector_cnt=2U, .max_mtu=2048U } };
  fd_iavf_hw_queue_t queue[1] = {0};
  uchar memory[16384] __attribute__((aligned(4096)));
  ulong const footprint = fd_iavf_hw_queue_footprint( 64U, 64U );
  FD_TEST( footprint<=sizeof(memory) );
  FD_TEST( fd_iavf_hw_init_queue( vfio, adminq, info, queue, memory, footprint,
                                 0x100100000UL, 64U, 64U, 2048U, 2048U )==-1 );
  FD_TEST( errno==EINVAL );

  fd_iavf_hw_vf_info_t unsupported[1] = {0};
  FD_TEST( fd_iavf_hw_add_udp_flow( vfio, adminq, unsupported, 0U, 9001U )==-1 );
  FD_TEST( errno==EPROTONOSUPPORT );
}

static void
test_tx_and_arp( void ) {
  fd_iavf_tile_t ctx[1];
  fd_memset( ctx, 0, sizeof(ctx) );
  uchar packet_memory[ 8192 ] __attribute__((aligned(64)));
  ulong tx_ring[ 64 ][ 2 ] __attribute__((aligned(64)));
  uint tx_chunks[ 64 ] = {0};
  ushort tx_sizes[ 64 ] = {0};
  ulong tx_comp[ 64 ] = {0};
  uint tx_tail = 0U;

  fd_memset( packet_memory, 0, sizeof(packet_memory) );
  fd_memset( tx_ring, 0, sizeof(tx_ring) );
  ctx->pkt_buf_wksp_base = packet_memory;
  ctx->pkt_buf_chunk0    = 1U;
  ctx->pkt_buf_wmark     = 64U;
  ctx->pkt_buf_iova0     = 0x200000000UL;
  ctx->tx_desc_chunk     = tx_chunks;
  ctx->tx_desc_sz        = tx_sizes;
  tx_chunks[0]           = 1U;
  ctx->queue.tx_ring     = tx_ring;
  ctx->queue.tx_comp_ring = tx_comp;
  ctx->queue.tx_depth    = 64U;
  ctx->queue.tx_tail     = &tx_tail;
  ctx->queue.enabled     = 1;
  ctx->router.default_address = FD_IP4_ADDR( 192,0,2,10 );
  uchar const vf_mac[6] = { 0x52U,0x14U,0xb4U,0x4aU,0x43U,0x27U };
  fd_memcpy( ctx->vf_info.mac_addr, vf_mac, 6UL );

  uchar request[60] = {0};
  fd_eth_hdr_t * request_eth = (fd_eth_hdr_t *)request;
  fd_iavf_tile_arp_t * request_arp = (fd_iavf_tile_arp_t *)(request_eth+1);
  uchar const peer_mac[6] = { 0x02U,0U,0U,0U,0U,0x77U };
  fd_memset( request_eth->dst, 0xff, 6UL );
  fd_memcpy( request_eth->src, peer_mac, 6UL );
  request_eth->net_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_ARP );
  request_arp->net_hardware_type = fd_ushort_bswap( ARPHRD_ETHER );
  request_arp->net_protocol_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );
  request_arp->hardware_addr_sz = 6U;
  request_arp->protocol_addr_sz = 4U;
  request_arp->net_operation = fd_ushort_bswap( 1U );
  fd_memcpy( request_arp->sender_hardware_addr, peer_mac, 6UL );
  request_arp->sender_protocol_addr = FD_IP4_ADDR( 192,0,2,77 );
  request_arp->target_protocol_addr = ctx->router.default_address;

  FD_TEST( fd_iavf_tile_arp_reply( ctx, request, sizeof(request) ) );
  FD_TEST( ctx->queue.tx_prod==1UL );
  FD_TEST( ctx->queue.tx_posted==0UL );
  FD_TEST( tx_tail==0U );
  FD_TEST( ctx->metrics.rx_arp_cnt==1UL );
  FD_TEST( ctx->metrics.tx_arp_cnt==1UL );
  FD_TEST( tx_sizes[0]==60U );
  FD_TEST( tx_ring[0][0]==ctx->pkt_buf_iova0 );
  FD_TEST( !(tx_ring[0][1] & TEST_IAVF_TX_REPORT_STATUS) );

  uchar const * reply = packet_memory+(1UL<<FD_CHUNK_LG_SZ);
  fd_eth_hdr_t const * reply_eth = (fd_eth_hdr_t const *)reply;
  fd_iavf_tile_arp_t const * reply_arp = (fd_iavf_tile_arp_t const *)(reply_eth+1);
  FD_TEST( !memcmp( reply_eth->dst, peer_mac, 6UL ) );
  FD_TEST( !memcmp( reply_eth->src, vf_mac, 6UL ) );
  FD_TEST( reply_eth->net_type==fd_ushort_bswap( FD_ETH_HDR_TYPE_ARP ) );
  FD_TEST( reply_arp->net_operation==fd_ushort_bswap( 2U ) );
  FD_TEST( !memcmp( reply_arp->sender_hardware_addr, vf_mac, 6UL ) );
  FD_TEST( reply_arp->sender_protocol_addr==ctx->router.default_address );
  FD_TEST( !memcmp( reply_arp->target_hardware_addr, peer_mac, 6UL ) );
  FD_TEST( reply_arp->target_protocol_addr==request_arp->sender_protocol_addr );

  ctx->tx_flush_deadline_ticks = 0L;
  int charge_busy = 0;
  before_credit( ctx, NULL, &charge_busy );
  FD_TEST( charge_busy );
  FD_TEST( ctx->queue.tx_posted==1UL );
  FD_TEST( tx_tail==1U );
  FD_TEST( ctx->queue.tx_comp_prod==1UL );
  FD_TEST( tx_comp[0]==1UL );
  FD_TEST( tx_ring[0][1] & TEST_IAVF_TX_REPORT_STATUS );
  FD_TEST( ctx->queue.tx_cons==0UL );

  tx_ring[0][1] = (tx_ring[0][1] & ~0xfUL) | 0xfUL;
  FD_TEST( fd_iavf_tile_poll_tx( ctx ) );
  FD_TEST( ctx->queue.tx_cons==1UL );
  FD_TEST( ctx->queue.tx_comp_cons==1UL );
  FD_TEST( ctx->metrics.tx_pkt_cnt==1UL );
  FD_TEST( ctx->metrics.tx_bytes_total==60UL );

  request_arp->target_protocol_addr = FD_IP4_ADDR( 192,0,2,11 );
  FD_TEST( !fd_iavf_tile_arp_reply( ctx, request, sizeof(request) ) );
  FD_TEST( ctx->queue.tx_prod==1UL );
}

static void
test_tx_batch( void ) {
  fd_iavf_tile_t ctx[1];
  fd_memset( ctx, 0, sizeof(ctx) );
  ulong tx_ring[ 128 ][ 2 ] __attribute__((aligned(64)));
  uint tx_chunks[ 128 ] = {0};
  ushort tx_sizes[ 128 ] = {0};
  ulong tx_comp[ 128 ] = {0};
  uint tx_tail = 0U;

  fd_memset( tx_ring, 0, sizeof(tx_ring) );
  for( uint i=0U; i<128U; i++ ) tx_chunks[i] = i+1U;
  ctx->pkt_buf_chunk0 = 1U;
  ctx->pkt_buf_iova0 = 0x200000000UL;
  ctx->tx_desc_chunk = tx_chunks;
  ctx->tx_desc_sz = tx_sizes;
  ctx->queue.tx_ring = tx_ring;
  ctx->queue.tx_comp_ring = tx_comp;
  ctx->queue.tx_depth = 128U;
  ctx->queue.tx_tail = &tx_tail;
  ctx->queue.enabled = 1;

  for( ulong i=0UL; i<FD_IAVF_BATCH_SIZE-1U; i++ ) {
    FD_TEST( !fd_iavf_tile_tx_submit( ctx, 64UL ) );
  }
  FD_TEST( ctx->queue.tx_prod==FD_IAVF_BATCH_SIZE-1U );
  FD_TEST( ctx->queue.tx_posted==0UL );
  FD_TEST( tx_tail==0U );

  FD_TEST( !fd_iavf_tile_tx_submit( ctx, 64UL ) );
  FD_TEST( ctx->queue.tx_prod==FD_IAVF_BATCH_SIZE );
  FD_TEST( ctx->queue.tx_posted==FD_IAVF_BATCH_SIZE );
  FD_TEST( tx_tail==FD_IAVF_BATCH_SIZE );
  FD_TEST( ctx->queue.tx_comp_prod==1UL );
  FD_TEST( tx_comp[0]==FD_IAVF_BATCH_SIZE );
  for( ulong i=0UL; i<FD_IAVF_BATCH_SIZE; i++ ) {
    ulong const report = tx_ring[i][1] & TEST_IAVF_TX_REPORT_STATUS;
    FD_TEST( !!report==(i==FD_IAVF_BATCH_SIZE-1U) );
  }

  for( ulong i=FD_IAVF_BATCH_SIZE; i<127UL; i++ ) FD_TEST( !fd_iavf_tile_tx_submit( ctx, 64UL ) );
  FD_TEST( ctx->queue.tx_prod==127UL );
  FD_TEST( ctx->queue.tx_posted==127UL );
  FD_TEST( tx_tail==127U );
  FD_TEST( ctx->queue.tx_comp_prod==2UL );
  FD_TEST( tx_comp[1]==127UL );

  tx_ring[126][1] = (tx_ring[126][1] & ~0xfUL) | 0xfUL;
  FD_TEST( !fd_iavf_tile_poll_tx( ctx ) );
  tx_ring[FD_IAVF_BATCH_SIZE-1U][1] = (tx_ring[FD_IAVF_BATCH_SIZE-1U][1] & ~0xfUL) | 0xfUL;
  FD_TEST( fd_iavf_tile_poll_tx( ctx ) );
  FD_TEST( ctx->queue.tx_cons==127UL );
  FD_TEST( ctx->queue.tx_comp_cons==2UL );
  FD_TEST( ctx->metrics.tx_pkt_cnt==127UL );
  FD_TEST( ctx->metrics.tx_bytes_total==64UL*127UL );

  for( ulong i=0UL; i<FD_IAVF_BATCH_SIZE; i++ ) FD_TEST( !fd_iavf_tile_tx_submit( ctx, 64UL ) );
  FD_TEST( ctx->queue.tx_prod==191UL );
  FD_TEST( ctx->queue.tx_posted==191UL );
  FD_TEST( tx_tail==63U );
  FD_TEST( ctx->queue.tx_comp_prod==3UL );
  FD_TEST( tx_comp[2]==191UL );
  tx_ring[62][1] = (tx_ring[62][1] & ~0xfUL) | 0xfUL;
  FD_TEST( fd_iavf_tile_poll_tx( ctx ) );
  FD_TEST( ctx->queue.tx_cons==191UL );
  FD_TEST( ctx->queue.tx_comp_cons==3UL );
  FD_TEST( ctx->metrics.tx_pkt_cnt==191UL );
  FD_TEST( ctx->metrics.tx_bytes_total==64UL*191UL );
}

static void
test_rx_ring_wrap( void ) {
  fd_iavf_tile_t ctx[1];
  fd_memset( ctx, 0, sizeof(ctx) );
  ulong rx_ring[128][4] __attribute__((aligned(64)));
  uint rx_chunks[128] = {0};
  uint rx_tail = 64U;
  fd_memset( rx_ring, 0, sizeof(rx_ring) );

  ctx->pkt_buf_chunk0 = 1U;
  ulong const frame_chunks = FD_NET_MTU>>FD_CHUNK_LG_SZ;
  ulong const last_chunk = 65UL+(FD_IAVF_BATCH_SIZE-1U)*frame_chunks;
  ctx->pkt_buf_wmark  = (uint)last_chunk;
  ctx->pkt_buf_iova0  = 0x200000000UL;
  ctx->rx_desc_chunk  = rx_chunks;
  ctx->queue.rx_ring  = rx_ring;
  ctx->queue.rx_depth = 128U;
  ctx->queue.rx_prod  = 64UL;
  ctx->queue.rx_posted = 64UL;
  ctx->queue.rx_tail  = &rx_tail;
  ctx->queue.enabled  = 1;

  for( uint i=0U; i<FD_IAVF_BATCH_SIZE; i++ ) {
    rx_chunks[i] = i+1U;
    rx_ring[i][1] = 1UL | 2UL | (60UL<<38);
  }
  fd_iavf_hw_rx_comp_t comp[ FD_IAVF_BATCH_SIZE ];
  FD_TEST( fd_iavf_hw_rx_poll( &ctx->queue, comp, FD_IAVF_BATCH_SIZE )==(int)FD_IAVF_BATCH_SIZE );
  FD_TEST( comp[ 0 ].desc_idx==0U && comp[ 0 ].frame_sz==60UL && !comp[ 0 ].error_flags );
  FD_TEST( comp[ FD_IAVF_BATCH_SIZE-1U ].desc_idx==FD_IAVF_BATCH_SIZE-1U );
  FD_TEST( ctx->queue.rx_cons==FD_IAVF_BATCH_SIZE );

  for( ulong i=0UL; i<FD_IAVF_BATCH_SIZE-1U; i++ ) fd_iavf_tile_rx_recycle( ctx, 65UL+i*frame_chunks );
  FD_TEST( ctx->rx_pending_cnt==FD_IAVF_BATCH_SIZE-1U );
  FD_TEST( ctx->queue.rx_prod==64UL );
  FD_TEST( ctx->queue.rx_posted==64UL );
  FD_TEST( rx_tail==64U );

  fd_iavf_tile_rx_recycle( ctx, last_chunk );
  FD_TEST( !ctx->rx_pending_cnt );
  FD_TEST( ctx->queue.rx_prod==128UL );
  FD_TEST( ctx->queue.rx_posted==128UL );
  FD_TEST( rx_tail==0U );
  FD_TEST( rx_chunks[64]==65U && rx_chunks[127]==last_chunk );
  FD_TEST( rx_ring[64][0]==ctx->pkt_buf_iova0+(64UL<<FD_CHUNK_LG_SZ) );
  FD_TEST( rx_ring[127][0]==ctx->pkt_buf_iova0+((last_chunk-1UL)<<FD_CHUNK_LG_SZ) );
}

static void
test_dst_port_lookup( void ) {
  fd_iavf_tile_t ctx[1];
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->rx_out_cnt = 3U;
  ctx->repair_out_idx = 2U;
  ctx->dst_port_cnt = 1U;
  ctx->dst_ports[0] = 9001U;
  ctx->dst_protos[0] = DST_PROTO_REPAIR;
  ctx->dst_out_idx[0] = 1U;

  ulong out_idx;
  ulong dst_proto;
  FD_TEST( fd_iavf_tile_rx_dst_port_lookup( ctx, 9001U, 64UL, &out_idx, &dst_proto ) );
  FD_TEST( out_idx==2UL );
  FD_TEST( dst_proto==DST_PROTO_REPAIR );
  FD_TEST( !fd_iavf_tile_rx_dst_port_lookup( ctx, 9002U, 64UL, &out_idx, &dst_proto ) );
}

static void
test_hardware( char const * pci_addr ) {
  fd_iavf_hw_pci_info_t info[1];
  if( FD_UNLIKELY( fd_iavf_hw_pci_probe( info, pci_addr ) ) ) {
    FD_LOG_ERR(( "invalid IAVF device %s (%i-%s)", pci_addr, errno, fd_io_strerror( errno ) ));
  }

  fd_iavf_hw_vfio_t vfio[1];
  if( FD_UNLIKELY( fd_iavf_hw_init_vfio( vfio, info ) ) ) {
    FD_LOG_ERR(( "VFIO initialization failed for %s (%i-%s)", pci_addr, errno, fd_io_strerror( errno ) ));
  }

  ulong page_sz = vfio->iova_pgsizes & -vfio->iova_pgsizes;
  void * dma_memory = mmap( NULL, page_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( dma_memory==MAP_FAILED ) ) {
    FD_LOG_ERR(( "DMA memory allocation failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ulong const dma_iova = 1UL<<32;
  if( FD_UNLIKELY( fd_iavf_hw_dma_map( vfio, dma_memory, page_sz, dma_iova ) ) ) {
    FD_LOG_ERR(( "VFIO DMA mapping failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  ulong adminq_footprint = fd_iavf_hw_adminq_footprint();
  void * adminq_memory = mmap( NULL, adminq_footprint, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( adminq_memory==MAP_FAILED ) ) {
    FD_LOG_ERR(( "Admin Queue memory allocation failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ulong const adminq_iova = 0x100010000UL;
  fd_iavf_hw_adminq_t adminq[1];
  if( FD_UNLIKELY( fd_iavf_hw_init_adminq( vfio, adminq, adminq_memory, adminq_footprint, adminq_iova ) ) ) {
    FD_LOG_ERR(( "Admin Queue initialization failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( fd_iavf_hw_virtchnl_version( vfio, adminq ) ) ) {
    int err = errno;
    fd_iavf_hw_adminq_regs_t regs[1];
    fd_iavf_hw_adminq_regs( vfio, regs );
    FD_LOG_ERR(( "virtchnl version exchange failed (%i-%s), ATQ head %u tail %u len 0x%08x, ARQ head %u tail %u len 0x%08x",
                 err, fd_io_strerror( err ), regs->atq_head, regs->atq_tail, regs->atq_len,
                 regs->arq_head, regs->arq_tail, regs->arq_len ));
  }

  fd_iavf_hw_vf_info_t vf_info[1];
  if( FD_UNLIKELY( fd_iavf_hw_get_vf_resources( vfio, adminq, vf_info ) ) ) {
    FD_LOG_ERR(( "virtchnl resource discovery failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  uint const tx_depth = 256U;
  uint const rx_depth = 256U;
  ulong queue_footprint = fd_iavf_hw_queue_footprint( tx_depth, rx_depth );
  void * queue_memory = mmap( NULL, queue_footprint, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( queue_memory==MAP_FAILED ) ) {
    FD_LOG_ERR(( "queue memory allocation failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ulong const queue_iova = 0x100100000UL;
  fd_iavf_hw_queue_t queue[1];
  if( FD_UNLIKELY( fd_iavf_hw_init_queue( vfio, adminq, vf_info, queue,
                                          queue_memory, queue_footprint, queue_iova,
                                          tx_depth, rx_depth, 2048U, 2048U ) ) ) {
    FD_LOG_ERR(( "queue setup failed" ));
  }

  ulong const packet_memory_sz = (ulong)rx_depth*2048UL;
  void * packet_memory = mmap( NULL, packet_memory_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( packet_memory==MAP_FAILED ) ) {
    FD_LOG_ERR(( "packet memory allocation failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  ulong const packet_iova = 0x100200000UL;
  if( FD_UNLIKELY( fd_iavf_hw_dma_map( vfio, packet_memory, packet_memory_sz, packet_iova ) ) ) {
    FD_LOG_ERR(( "packet DMA mapping failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  for( uint idx=0U; idx<rx_depth-1U; idx++ ) {
    if( FD_UNLIKELY( fd_iavf_hw_rx_post( queue, packet_iova+(ulong)idx*2048UL, NULL ) ) ) {
      FD_LOG_ERR(( "receive buffer post failed at %u (%i-%s)", idx, errno, fd_io_strerror( errno ) ));
    }
  }
  fd_iavf_hw_rx_flush( queue );
  if( FD_UNLIKELY( fd_iavf_hw_enable_queue( vfio, adminq, vf_info, queue ) ) ) {
    FD_LOG_ERR(( "queue enable failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  fd_iavf_hw_stats_t stats_before[1];
  if( FD_UNLIKELY( fd_iavf_hw_get_stats( vfio, adminq, vf_info, stats_before ) ) ) {
    FD_LOG_ERR(( "initial VF statistics failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  uchar * tx_frame = (uchar *)packet_memory + (ulong)(rx_depth-1U)*2048UL;
  fd_memset( tx_frame, 0xa5, 64UL );
  fd_memset( tx_frame, 0xff, 6UL );
  fd_memcpy( tx_frame+6UL, vf_info->mac_addr, 6UL );
  tx_frame[12] = 0x88U;
  tx_frame[13] = 0xb5U;
  ulong const tx_frame_iova = packet_iova + (ulong)(rx_depth-1U)*2048UL;
  if( FD_UNLIKELY( fd_iavf_hw_tx_submit( queue, tx_frame_iova, 64UL ) ) ) {
    FD_LOG_ERR(( "test frame submission failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  fd_iavf_hw_tx_flush( queue );

  struct timespec one_ms = { .tv_sec=0L, .tv_nsec=1000000L };
  ulong tx_complete = 0UL;
  for( ulong retry=0UL; retry<2000UL && !tx_complete; retry++ ) {
    tx_complete = fd_iavf_hw_tx_complete( queue );
    if( !tx_complete && FD_UNLIKELY( nanosleep( &one_ms, NULL ) && errno!=EINTR ) ) {
      FD_LOG_ERR(( "TX completion wait failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }
  if( FD_UNLIKELY( tx_complete!=1UL ) ) FD_LOG_ERR(( "test frame did not complete" ));

  fd_iavf_hw_stats_t stats_after[1];
  struct timespec fifty_ms = { .tv_sec=0L, .tv_nsec=50000000L };
  for( ulong retry=0UL;; retry++ ) {
    if( FD_UNLIKELY( fd_iavf_hw_get_stats( vfio, adminq, vf_info, stats_after ) ) ) {
      FD_LOG_ERR(( "final VF statistics failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( stats_after->tx_broadcast>stats_before->tx_broadcast &&
        stats_after->tx_bytes>=stats_before->tx_bytes+64UL ) break;
    if( FD_UNLIKELY( retry==19UL ) ) {
      FD_LOG_ERR(( "test frame completed without a VF hardware-counter increase" ));
    }
    if( FD_UNLIKELY( nanosleep( &fifty_ms, NULL ) && errno!=EINTR ) ) {
      FD_LOG_ERR(( "VF statistics wait failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }

  FD_LOG_NOTICE(( "IAVF VF %s device 0x%04x PF %s IOMMU group %u driver %s BAR0 size 0x%lx reset state %u DMA page %lu IOVA 0x%lx virtchnl %u.%u VSI %u queues %u vectors %u MTU %u MAC %02x:%02x:%02x:%02x:%02x:%02x link %s speed %u Mbps TX packets %lu bytes %lu",
                  info->pci_addr, (uint)info->device_id, info->pf_pci_addr, info->iommu_group,
                  info->driver, vfio->bar0_sz, vfio->reset_state, page_sz, dma_iova,
                  adminq->version_major, adminq->version_minor, (uint)vf_info->vsi_id,
                  (uint)vf_info->queue_pair_cnt, (uint)vf_info->vector_cnt, (uint)vf_info->max_mtu,
                  (uint)vf_info->mac_addr[0], (uint)vf_info->mac_addr[1], (uint)vf_info->mac_addr[2],
                  (uint)vf_info->mac_addr[3], (uint)vf_info->mac_addr[4], (uint)vf_info->mac_addr[5],
                  vf_info->link_state_valid ? (vf_info->link_up ? "up" : "down") : "unknown",
                  vf_info->link_speed_mbps,
                  stats_after->tx_broadcast-stats_before->tx_broadcast,
                  stats_after->tx_bytes-stats_before->tx_bytes ));
}

int
main( int argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  if( FD_UNLIKELY( argc!=1 && argc!=2 ) ) FD_LOG_ERR(( "usage: %s [PCI_ADDRESS]", argv[0] ));
  if( argc==2 ) {
    test_hardware( argv[1] );
  } else {
    test_queue_init_errors();
    test_tx_and_arp();
    test_tx_batch();
    test_rx_ring_wrap();
    test_dst_port_lookup();
  }
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
