#ifndef HEADER_fd_src_disco_net_iavf_fd_iavf_private_h
#define HEADER_fd_src_disco_net_iavf_fd_iavf_private_h

#include "fd_iavf.h"
#if defined(__linux__)

#define FD_IAVF_BAR0_MAP_SZ (0x9000UL)
#define FD_IAVF_PAGE_SZ     (4096UL)

/* Intel IAVF_QTX_TAIL and IAVF_QRX_TAIL registers. */
#define FD_IAVF_TX_TAIL(queue_id) (0x0000UL + 4UL*(queue_id))
#define FD_IAVF_RX_TAIL(queue_id) (0x2000UL + 4UL*(queue_id))

static inline void
fd_iavf_hw_dma_to_device( void ) {
#if FD_HAS_X86
  FD_COMPILER_MFENCE();
#elif FD_HAS_ARM
  __asm__ __volatile__( "dmb oshst" ::: "memory" );
#else
  FD_HW_MFENCE_ST();
#endif
}

static inline void
fd_iavf_hw_dma_from_device( void ) {
#if FD_HAS_X86
  __asm__ __volatile__( "lfence" ::: "memory" );
#elif FD_HAS_ARM
  __asm__ __volatile__( "dmb oshld" ::: "memory" );
#else
  FD_HW_MFENCE();
#endif
}

/* fd_iavf_vfio owns the Linux VFIO descriptors and mapped BAR0 registers. */
struct fd_iavf_vfio {
  int              container_fd;
  int              group_fd;
  int              device_fd;
  volatile uchar * bar0;
  ulong            bar0_sz;
  ulong            iova_pgsizes;
};
typedef struct fd_iavf_vfio fd_iavf_vfio_t;

/* fd_iavf_adminq owns the Intel Admin Transmit and Receive Queues. */
struct fd_iavf_adminq {
  void * dma_memory;
  ulong  dma_iova;
  uint   atq_prod;
  uint   arq_cons;
  uint   version_major;
  uchar  pending_event[ 16 ];
  ulong  pending_event_sz;
};
typedef struct fd_iavf_adminq fd_iavf_adminq_t;

/* fd_iavf_vf_info contains resources assigned by the Physical Function. */
struct fd_iavf_vf_info {
  ushort vsi_id;
  ushort queue_pair_cnt;
  ushort vector_cnt;
  ushort max_mtu;
  uint   capability_flags;
  uint   rss_key_sz;
  uint   rss_lut_sz;
  uchar  mac_addr[ 6 ];
  int    link_state_valid;
  int    link_up;
  uint   link_speed_mbps;
};
typedef struct fd_iavf_vf_info fd_iavf_vf_info_t;

struct fd_iavf_tx_desc {
  ulong buffer_iova;
  ulong cmd_type_offset_buffer_sz;
};

typedef struct fd_iavf_tx_desc fd_iavf_tx_desc_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_tx_desc_t)==16UL, iavf_tx_desc_sz );

/* fd_iavf_rx_desc is the Intel 32-byte receive descriptor. */
struct fd_iavf_rx_desc {
  ulong qword[ 4 ];
};

typedef struct fd_iavf_rx_desc fd_iavf_rx_desc_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_rx_desc_t)==32UL, iavf_rx_desc_sz );

/* fd_iavf_queue owns one Intel transmit and receive descriptor ring. */
struct fd_iavf_queue {
  void *             dma_memory;
  fd_iavf_tx_desc_t * tx_ring;
  fd_iavf_rx_desc_t * rx_ring;
  /* tx_comp_ring records the producer endpoint of each Report Status batch. */
  ulong *            tx_comp_ring;
  uint               tx_depth;
  uint               rx_depth;
  ulong              tx_prod;
  ulong              tx_posted;
  ulong              tx_cons;
  ulong              tx_comp_prod;
  ulong              tx_comp_cons;
  ulong              rx_prod;
  ulong              rx_posted;
  ulong              rx_cons;
  uint               rx_discard;
  volatile uint *    tx_tail;
  volatile uint *    rx_tail;
  int                enabled;
};
typedef struct fd_iavf_queue fd_iavf_queue_t;

FD_PROTOTYPES_BEGIN

/* fd_iavf_vfio_map_bar maps the existing device FD without resetting the VF. */
int
fd_iavf_vfio_map_bar( fd_iavf_vfio_t * vfio );

/* fd_iavf_vfio_init opens a VF bound to vfio-pci, attaches its isolated
   IOMMU group to a Type 1 version 2 container, maps the required BAR0 register
   window, resets the VF, and waits for the VF to become active.  It returns 0
   on success.  On failure, it closes all acquired resources and sets errno. */
int
fd_iavf_vfio_init( fd_iavf_vfio_t *           vfio,
                   fd_iavf_pci_info_t const * info );

/* fd_iavf_vfio_dma_map pins memory and maps it at iova, the address visible to
   the VF.  The memory, size, and I/O virtual address must be aligned to a page
   size supported by the VFIO IOMMU.  It returns 0 on success and -1 on failure. */
int
fd_iavf_vfio_dma_map( fd_iavf_vfio_t * vfio,
                      void *           memory,
                      ulong            memory_sz,
                      ulong            iova );

ulong
fd_iavf_adminq_footprint( void );

/* fd_iavf_adminq_init maps and initializes Intel's Admin Transmit Queue and
   Admin Receive Queue.  It returns 0 on success and -1 on failure. */
int
fd_iavf_adminq_init( fd_iavf_vfio_t *   vfio,
                     fd_iavf_adminq_t * adminq,
                     void *             dma_memory,
                     ulong              dma_memory_sz,
                     ulong              dma_iova );

/* fd_iavf_virtchnl_version exchanges the supported virtchnl version with
   the Physical Function.  It returns 0 on success and -1 on failure. */
int
fd_iavf_virtchnl_version( fd_iavf_vfio_t *   vfio,
                          fd_iavf_adminq_t * adminq );

/* fd_iavf_virtchnl_get_resources discovers the Ethernet resources assigned to
   this Virtual Function.  It returns 0 on success and -1 on failure. */
int
fd_iavf_virtchnl_get_resources( fd_iavf_vfio_t *    vfio,
                                fd_iavf_adminq_t *  adminq,
                                fd_iavf_vf_info_t * info );

/* fd_iavf_virtchnl_poll_link drains unsolicited virtchnl events and updates
   info.  changed is set when the reported link state or speed changed. */
int
fd_iavf_virtchnl_poll_link( fd_iavf_vfio_t *    vfio,
                            fd_iavf_adminq_t *  adminq,
                            fd_iavf_vf_info_t * info,
                            int *               changed );

ulong
fd_iavf_queue_footprint( uint tx_depth,
                         uint rx_depth );

/* fd_iavf_virtchnl_configure_queue maps and configures one queue pair.
   It remains disabled until fd_iavf_virtchnl_enable_queue succeeds. */
int
fd_iavf_virtchnl_configure_queue( fd_iavf_vfio_t *          vfio,
                                  fd_iavf_adminq_t *        adminq,
                                  fd_iavf_vf_info_t const * info,
                                  fd_iavf_queue_t *         queue,
                                  void *                    dma_memory,
                                  ulong                     dma_memory_sz,
                                  ulong                     dma_iova,
                                  uint                      tx_depth,
                                  uint                      rx_depth,
                                  uint                      rx_buffer_sz,
                                  uint                      max_frame_sz );

int
fd_iavf_virtchnl_enable_queue( fd_iavf_vfio_t *    vfio,
                               fd_iavf_adminq_t *  adminq,
                               fd_iavf_vf_info_t * info,
                               fd_iavf_queue_t *   queue );

int
fd_iavf_virtchnl_add_mac( fd_iavf_vfio_t *          vfio,
                          fd_iavf_adminq_t *        adminq,
                          fd_iavf_vf_info_t const * info );

/* fd_iavf_virtchnl_configure_rss maps every table entry to a configured queue.
   All queue_cnt queues must be configured before reception is enabled. */
int
fd_iavf_virtchnl_configure_rss( fd_iavf_vfio_t *          vfio,
                                fd_iavf_adminq_t *        adminq,
                                fd_iavf_vf_info_t const * info,
                                uint                      queue_cnt );

FD_PROTOTYPES_END
#endif
#endif
