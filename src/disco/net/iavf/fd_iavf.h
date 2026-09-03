#ifndef HEADER_fd_src_disco_net_iavf_fd_iavf_h
#define HEADER_fd_src_disco_net_iavf_fd_iavf_h

#if defined(__linux__)

#include "../../../util/bits/fd_bits.h"

#define FD_IAVF_PCI_ADDR_SZ     (13UL)
#define FD_IAVF_DRIVER_NAME_MAX (32UL)

/* fd_iavf_hw_pci_info describes a validated Intel Ethernet Virtual Function. */
struct fd_iavf_hw_pci_info {
  char   pci_addr[ FD_IAVF_PCI_ADDR_SZ ];
  char   pf_pci_addr[ FD_IAVF_PCI_ADDR_SZ ];
  char   driver[ FD_IAVF_DRIVER_NAME_MAX ];
  uint   iommu_group;
  ushort device_id;
};
typedef struct fd_iavf_hw_pci_info fd_iavf_hw_pci_info_t;

/* fd_iavf_hw_vfio owns the Linux VFIO descriptors and mapped BAR0 registers. */
struct fd_iavf_hw_vfio {
  int              container_fd;
  int              group_fd;
  int              device_fd;
  volatile uchar * bar0;
  ulong            bar0_sz;
  ulong            iova_pgsizes;
  uint             reset_state;
};
typedef struct fd_iavf_hw_vfio fd_iavf_hw_vfio_t;

/* fd_iavf_hw_adminq owns the Intel Admin Transmit and Receive Queues. */
struct fd_iavf_hw_adminq {
  void * dma_memory;
  ulong  dma_memory_sz;
  ulong  dma_iova;
  uint   atq_prod;
  uint   arq_cons;
  uint   version_major;
  uint   version_minor;
  uchar  pending_event[ 16 ];
  ulong  pending_event_sz;
  uint   last_operation;
  int    last_status;
  int    last_fdir_status;
};
typedef struct fd_iavf_hw_adminq fd_iavf_hw_adminq_t;

/* fd_iavf_hw_adminq_regs contains the Intel Admin Queue register state. */
struct fd_iavf_hw_adminq_regs {
  uint atq_head;
  uint atq_tail;
  uint atq_len;
  uint arq_head;
  uint arq_tail;
  uint arq_len;
};
typedef struct fd_iavf_hw_adminq_regs fd_iavf_hw_adminq_regs_t;

/* fd_iavf_hw_vf_info contains resources assigned by the Physical Function. */
struct fd_iavf_hw_vf_info {
  ushort vsi_id;
  ushort queue_pair_cnt;
  ushort vector_cnt;
  ushort max_mtu;
  uint   capability_flags;
  uchar  mac_addr[ 6 ];
  int    link_state_valid;
  int    link_up;
  uint   link_speed_mbps;
};
typedef struct fd_iavf_hw_vf_info fd_iavf_hw_vf_info_t;

/* fd_iavf_hw_rx_comp describes one completed receive descriptor. */
struct fd_iavf_hw_rx_comp {
  uint  desc_idx;
  uint  error_flags;
  ulong frame_sz;
};
typedef struct fd_iavf_hw_rx_comp fd_iavf_hw_rx_comp_t;

/* fd_iavf_hw_queue owns one Intel transmit and receive descriptor ring. */
struct fd_iavf_hw_queue {
  void *          dma_memory;
  ulong           dma_memory_sz;
  ulong           dma_iova;
  void *          tx_ring;
  void *          rx_ring;
  /* tx_comp_ring records the producer endpoint of each Report Status batch. */
  ulong *         tx_comp_ring;
  ulong           tx_ring_iova;
  ulong           rx_ring_iova;
  uint            tx_depth;
  uint            rx_depth;
  ulong           tx_prod;
  ulong           tx_posted;
  ulong           tx_cons;
  ulong           tx_comp_prod;
  ulong           tx_comp_cons;
  ulong           rx_prod;
  ulong           rx_posted;
  ulong           rx_cons;
  volatile uint * tx_tail;
  volatile uint * rx_tail;
  int             enabled;
};
typedef struct fd_iavf_hw_queue fd_iavf_hw_queue_t;

/* fd_iavf_hw_stats contains Ethernet counters reported for the VF VSI. */
struct fd_iavf_hw_stats {
  ulong rx_bytes;
  ulong rx_unicast;
  ulong rx_multicast;
  ulong rx_broadcast;
  ulong rx_discards;
  ulong rx_unknown_protocol;
  ulong tx_bytes;
  ulong tx_unicast;
  ulong tx_multicast;
  ulong tx_broadcast;
  ulong tx_discards;
  ulong tx_errors;
};
typedef struct fd_iavf_hw_stats fd_iavf_hw_stats_t;

FD_PROTOTYPES_BEGIN

/* fd_iavf_hw_pci_probe verifies that pci_addr names an Intel Ethernet
   Virtual Function in an isolated IOMMU group.  The driver field is empty
   when the device is unbound.  It returns 0 on success.  On failure, it
   returns -1, clears info, and sets errno. */
int
fd_iavf_hw_pci_probe( fd_iavf_hw_pci_info_t * info,
                      char const *            pci_addr );

/* fd_iavf_hw_init_vfio opens a VF bound to vfio-pci, attaches its isolated
   IOMMU group to a Type 1 version 2 container, maps the required BAR0 register
   window, resets the VF, and waits for the VF to become active.  It returns 0
   on success.  On failure, it closes all acquired resources and sets errno. */
int
fd_iavf_hw_init_vfio( fd_iavf_hw_vfio_t *           vfio,
                      fd_iavf_hw_pci_info_t const * info );

/* fd_iavf_hw_dma_map pins memory and maps it at iova, the address visible to
   the VF.  The memory, size, and I/O virtual address must be aligned to a page
   size supported by the VFIO IOMMU.  It returns 0 on success and -1 on failure. */
int
fd_iavf_hw_dma_map( fd_iavf_hw_vfio_t * vfio,
                    void *              memory,
                    ulong               memory_sz,
                    ulong               iova );

ulong
fd_iavf_hw_adminq_footprint( void );

/* fd_iavf_hw_init_adminq maps and initializes Intel's Admin Transmit Queue and
   Admin Receive Queue.  It returns 0 on success and -1 on failure. */
int
fd_iavf_hw_init_adminq( fd_iavf_hw_vfio_t *   vfio,
                        fd_iavf_hw_adminq_t * adminq,
                        void *                dma_memory,
                        ulong                 dma_memory_sz,
                        ulong                 dma_iova );

/* fd_iavf_hw_virtchnl_version exchanges the supported virtchnl version with
   the Physical Function.  It returns 0 on success and -1 on failure. */
int
fd_iavf_hw_virtchnl_version( fd_iavf_hw_vfio_t *  vfio,
                            fd_iavf_hw_adminq_t * adminq );

/* fd_iavf_hw_get_vf_resources discovers the Ethernet resources assigned to
   this Virtual Function.  It returns 0 on success and -1 on failure. */
int
fd_iavf_hw_get_vf_resources( fd_iavf_hw_vfio_t *    vfio,
                             fd_iavf_hw_adminq_t *  adminq,
                             fd_iavf_hw_vf_info_t * info );

ulong
fd_iavf_hw_queue_footprint( uint tx_depth,
                            uint rx_depth );

/* fd_iavf_hw_init_queue maps and configures one transmit and receive queue.
   The queues remain disabled until fd_iavf_hw_enable_queue succeeds. */
int
fd_iavf_hw_init_queue( fd_iavf_hw_vfio_t *          vfio,
                       fd_iavf_hw_adminq_t *        adminq,
                       fd_iavf_hw_vf_info_t const * info,
                       fd_iavf_hw_queue_t *         queue,
                       void *                       dma_memory,
                       ulong                        dma_memory_sz,
                       ulong                        dma_iova,
                       uint                         tx_depth,
                       uint                         rx_depth,
                       uint                         rx_buffer_sz,
                       uint                         max_frame_sz );

int
fd_iavf_hw_rx_post( fd_iavf_hw_queue_t * queue,
                    ulong                buffer_iova,
                    uint *               desc_idx );

void
fd_iavf_hw_rx_flush( fd_iavf_hw_queue_t * queue );

int
fd_iavf_hw_enable_queue( fd_iavf_hw_vfio_t *    vfio,
                         fd_iavf_hw_adminq_t *  adminq,
                         fd_iavf_hw_vf_info_t * info,
                         fd_iavf_hw_queue_t *   queue );

/* fd_iavf_hw_add_udp_flow installs one Intel Flow Director rule matching an
   IPv4 UDP destination address and port and steering it to queue 0. */
int
fd_iavf_hw_add_udp_flow( fd_iavf_hw_vfio_t *          vfio,
                         fd_iavf_hw_adminq_t *        adminq,
                         fd_iavf_hw_vf_info_t const * info,
                         uint                         dst_ip,
                         ushort                       dst_port );

/* fd_iavf_hw_add_gre_udp_flow installs the equivalent Flow Director rule for
   an IPv4 UDP packet encapsulated in outer IPv4 GRE. */
int
fd_iavf_hw_add_gre_udp_flow( fd_iavf_hw_vfio_t *          vfio,
                             fd_iavf_hw_adminq_t *        adminq,
                             fd_iavf_hw_vf_info_t const * info,
                             uint                         inner_dst_ip,
                             ushort                       inner_dst_port );

int
fd_iavf_hw_tx_submit( fd_iavf_hw_queue_t * queue,
                      ulong                frame_iova,
                      ulong                frame_sz );

void
fd_iavf_hw_tx_flush( fd_iavf_hw_queue_t * queue );

ulong
fd_iavf_hw_tx_complete( fd_iavf_hw_queue_t * queue );

int
fd_iavf_hw_rx_poll( fd_iavf_hw_queue_t *   queue,
                    fd_iavf_hw_rx_comp_t * comp,
                    uint                   comp_capacity );

int
fd_iavf_hw_get_stats( fd_iavf_hw_vfio_t *          vfio,
                      fd_iavf_hw_adminq_t *        adminq,
                      fd_iavf_hw_vf_info_t const * info,
                      fd_iavf_hw_stats_t *         stats );

/* fd_iavf_hw_poll_link drains unsolicited virtchnl events and updates
   info.  changed is set when the reported link state or speed changed. */
int
fd_iavf_hw_poll_link( fd_iavf_hw_vfio_t *    vfio,
                      fd_iavf_hw_adminq_t *  adminq,
                      fd_iavf_hw_vf_info_t * info,
                      int *                  changed );

void
fd_iavf_hw_adminq_regs( fd_iavf_hw_vfio_t const *  vfio,
                        fd_iavf_hw_adminq_regs_t * regs );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_disco_net_iavf_fd_iavf_h */
