#include "fd_iavf_private.h"
#include "../../../util/fd_util.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

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

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_invalid_inputs();
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
    FD_TEST( !fd_iavf_virtchnl_get_resources( &vfio, &adminq, &info ) );
    FD_LOG_NOTICE(( "VF %s, VSI %hu, queue pairs %hu, vectors %hu, RSS key %u, RSS table %u",
                    pci.pci_addr, info.vsi_id, info.queue_pair_cnt, info.vector_cnt,
                    info.rss_key_sz, info.rss_lut_sz ));

    fd_iavf_queue_t queue;
    ulong queue_sz = fd_iavf_queue_footprint( 64U, 64U );
    void * queue_memory = NULL;
    void * rx_memory = NULL;
    FD_TEST( !posix_memalign( &queue_memory, 4096UL, queue_sz ) );
    FD_TEST( !posix_memalign( &rx_memory, 4096UL, 64UL*2048UL ) );
    FD_TEST( !fd_iavf_virtchnl_configure_queue( &vfio, &adminq, &info, &queue, queue_memory,
                                      queue_sz, 0x100100000UL, 64U, 64U, 2048U, 2048U ) );
    FD_TEST( !fd_iavf_virtchnl_add_mac( &vfio, &adminq, &info ) );
    FD_TEST( !fd_iavf_virtchnl_configure_rss( &vfio, &adminq, &info, 1U ) );
    FD_TEST( !fd_iavf_vfio_dma_map( &vfio, rx_memory, 64UL*2048UL, 0x200000000UL ) );
    fd_iavf_rx_desc_t * rx_ring = queue.rx_ring;
    for( uint i=0U; i<63U; i++ ) rx_ring[i].qword[0] = 0x200000000UL + (ulong)i*2048UL;
    FD_COMPILER_MFENCE();
    __atomic_thread_fence( __ATOMIC_RELEASE );
    queue.rx_prod = queue.rx_posted = 63UL;
    *queue.rx_tail = 63U;
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
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
