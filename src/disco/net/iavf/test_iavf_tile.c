#include "fd_iavf_private.h"
#include "../../../util/fd_util.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

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

static void
test_hardware( char const * pci_addr ) {
  fd_iavf_vfio_t vfio;
  fd_iavf_adminq_t adminq = {0};
  fd_iavf_vf_info_t info;
  fd_iavf_queue_t tx_queue = { .depth=64U };
  fd_iavf_queue_t rx_queue = { .depth=64U };
  ulong const queue_sz = fd_iavf_queue_footprint( 64U, 64U );
  void * queue_memory;
  void * rx_memory;
  FD_TEST( !posix_memalign( &queue_memory, 4096UL, queue_sz ) );
  FD_TEST( !posix_memalign( &rx_memory, 4096UL, 64UL*2048UL ) );
  FD_TEST( !posix_memalign( &adminq.dma_memory, 4096UL, fd_iavf_adminq_footprint() ) );
  fd_iavf_vfio_tile_t tile = {
    .tx_queue=&tx_queue, .rx_queue=&rx_queue,
    .queue_memory=queue_memory, .queue_memory_sz=queue_sz,
    .packet_memory=rx_memory, .packet_memory_sz=64UL*2048UL, .packet_iova=0x200000000UL
  };
  FD_TEST( !fd_iavf_init( &vfio, &adminq, &info, &tile, pci_addr, 2048U, 2048U ) );
  fd_iavf_hw_rx_desc_t * rx_ring = rx_queue.ring;
  for( uint i=0U; i<63U; i++ ) rx_ring[i].qword[0] = tile.packet_iova+(ulong)i*2048UL;
  fd_iavf_hw_dma_to_device();
  rx_queue.prod = rx_queue.posted = 63UL;
  *rx_queue.tail = 63U;
  FD_TEST( !fd_iavf_virtchnl_enable_queue( &vfio, &adminq, &info, &tile ) );
  FD_LOG_NOTICE(( "queue 0 enabled with RSS delivery and the PF-assigned MAC" ));
  FD_TEST( !fd_iavf_vfio_unmap_bar( &vfio ) );
  FD_TEST( !close( vfio.device_fd ) );
  FD_TEST( !close( vfio.group_fd ) );
  FD_TEST( !close( vfio.container_fd ) );
  free( rx_memory );
  free( queue_memory );
  free( adminq.dma_memory );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_invalid_inputs();
  test_virtchnl_setup();
  test_virtchnl_initial_link();
  test_virtchnl_shutdown();
  test_queue_mapping_failure();
  if( argc==2 ) test_hardware( argv[1] );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
