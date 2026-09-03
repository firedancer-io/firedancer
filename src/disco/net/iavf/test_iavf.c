#define _GNU_SOURCE

#include "fd_iavf.h"
#include "../../../util/fd_util.h"

#include <errno.h>
#include <sys/mman.h>
#include <time.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if( FD_UNLIKELY( argc!=2 ) ) FD_LOG_ERR(( "usage: %s <PCI_ADDRESS>", argv[0] ));

  fd_iavf_hw_pci_info_t info[1];
  if( FD_UNLIKELY( fd_iavf_hw_pci_probe( info, argv[1] ) ) ) {
    FD_LOG_ERR(( "invalid IAVF device %s (%i-%s)", argv[1], errno, fd_io_strerror( errno ) ));
  }

  fd_iavf_hw_vfio_t vfio[1];
  if( FD_UNLIKELY( fd_iavf_hw_init_vfio( vfio, info ) ) ) {
    FD_LOG_ERR(( "VFIO initialization failed for %s (%i-%s)", argv[1], errno, fd_io_strerror( errno ) ));
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
    FD_LOG_ERR(( "queue initialization failed (%i-%s), virtchnl operation %u status %i",
                 errno, fd_io_strerror( errno ), adminq->last_operation, adminq->last_status ));
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
  fd_halt();
  return 0;
}
