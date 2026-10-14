#ifndef HEADER_fd_src_disco_net_iavf_fd_iavf_private_h
#define HEADER_fd_src_disco_net_iavf_fd_iavf_private_h

#include "fd_iavf.h"
#if defined(__linux__)

#define FD_IAVF_BAR0_MAP_SZ (0x9000UL)
#define FD_IAVF_PAGE_SZ     (4096UL)

#define FD_IAVF_TX_TAIL(queue_id) (0x0000UL + 4UL*(queue_id)) /* IAVF_QTX_TAIL1 */
#define FD_IAVF_RX_TAIL(queue_id) (0x2000UL + 4UL*(queue_id)) /* IAVF_QRX_TAIL1 */

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
  ulong            iova_pgsizes;
};
typedef struct fd_iavf_vfio fd_iavf_vfio_t;

/* fd_iavf_adminq holds the command channel to the PF driver, separate
   from the rings carrying packet traffic. */
struct fd_iavf_adminq {
  void * dma_memory;
  ulong  dma_iova;
  uint   atq_prod;
  uint   arq_cons;
  /* PF events can arrive before the resource reply populates vf_info. */
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
  uint   rss_key_sz;
  uint   rss_lut_sz;
  uchar  mac_addr[ 6 ];
  /* link_usable is false until the PF reports an up link. */
  int    link_usable;
};
typedef struct fd_iavf_vf_info fd_iavf_vf_info_t;

struct fd_iavf_tx_desc {
  ulong buffer_iova;
  ulong cmd_type_offset_buffer_sz;
};

typedef struct fd_iavf_tx_desc fd_iavf_tx_desc_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_tx_desc_t)==16UL, iavf_tx_desc_sz );

/* fd_iavf_hw_rx_desc is the Intel 32-byte receive descriptor. */
struct fd_iavf_hw_rx_desc {
  ulong qword[ 4 ];
};

typedef struct fd_iavf_hw_rx_desc fd_iavf_hw_rx_desc_t;

FD_STATIC_ASSERT( sizeof(fd_iavf_hw_rx_desc_t)==32UL, iavf_rx_desc_sz );

/* fd_iavf_queue owns one Intel transmit or receive descriptor ring. */
struct fd_iavf_queue {
  void *          ring;
  uint            depth;
  ulong           prod;
  ulong           posted;
  ulong           cons;
  volatile uint * tail;
  int             enabled;
  /* The NIC reports TX completion in the descriptor ring itself. Track
     Report Status batch endpoints so we only poll each batch's last descriptor. */
  ulong *         comp_ring;
  ulong           comp_prod;
  ulong           comp_cons;
  uint            discard;
};
typedef struct fd_iavf_queue fd_iavf_queue_t;

/* fd_iavf_vfio_tile identifies one tile's queues and packet memory during
   shared VF initialization. Queue depths must be set before initialization. */
struct fd_iavf_vfio_tile {
  fd_iavf_queue_t * tx_queue;
  fd_iavf_queue_t * rx_queue;
  void *            queue_memory;
  ulong             queue_memory_sz;
  void *            packet_memory;
  ulong             packet_memory_sz;
  ulong             packet_iova;
};
typedef struct fd_iavf_vfio_tile fd_iavf_vfio_tile_t;

FD_PROTOTYPES_BEGIN

/* fd_iavf_init opens and resets a VF, negotiates PF resources, maps each
   tile's memory and configures queues, MAC delivery and RSS. adminq->dma_memory
   must hold fd_iavf_adminq_footprint() bytes. Queues remain disabled so callers
   can post RX buffers before fd_iavf_virtchnl_enable_queues. Returns 0 on
   success or -1 with errno set. After failure, the caller must exit. */
int
fd_iavf_init( fd_iavf_vfio_t *            vfio,
              fd_iavf_adminq_t *          adminq,
              fd_iavf_vf_info_t *         info,
              fd_iavf_vfio_tile_t const * tiles,
              uint                        tile_cnt,
              char const *                pci_addr,
              uint                        rx_buffer_sz,
              uint                        max_frame_sz );

/* fd_iavf_vfio_map_bar restores register access in each tile through the
   inherited device FD, preserving the VF configuration prepared before launch. */
int
fd_iavf_vfio_map_bar( fd_iavf_vfio_t * vfio );

/* fd_iavf_vfio_unmap_bar releases the launcher's register mapping
   VFIO descriptors stay open for the tiles to inherit and remap */
int
fd_iavf_vfio_unmap_bar( fd_iavf_vfio_t * vfio );

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

/* fd_iavf_virtchnl_version requires virtchnl 1.1 so resource discovery can
   request Ethernet and PF-managed RSS capabilities. Returns 0 on success
   or -1 on failure. */
int
fd_iavf_virtchnl_version( fd_iavf_vfio_t *   vfio,
                          fd_iavf_adminq_t * adminq );

/* fd_iavf_virtchnl_get_resources obtains and validates the PF-assigned MAC
   and limits used to configure packet queues and RSS. Requires initialized
   VFIO and Admin Queue state after fd_iavf_virtchnl_version succeeds.
   Returns 0 on success or -1 on failure. */
int
fd_iavf_virtchnl_get_resources( fd_iavf_vfio_t *    vfio,
                                fd_iavf_adminq_t *  adminq,
                                fd_iavf_vf_info_t * info );

/* fd_iavf_virtchnl_poll_link updates link usability for VF selection and detects
   resets that invalidate the configured queues. Sets changed when link
   usability changes. Returns 0 on success or -1 on failure. */
int
fd_iavf_virtchnl_poll_link( fd_iavf_vfio_t *    vfio,
                            fd_iavf_adminq_t *  adminq,
                            fd_iavf_vf_info_t * info,
                            int *               changed );

ulong
fd_iavf_queue_footprint( uint tx_depth,
                         uint rx_depth );

/* fd_iavf_virtchnl_configure_queues prepares queue pairs 0 through queue_cnt-1
   for independent tile ownership. Requires initialized VFIO and Admin Queue
   state, validated info and queue_cnt in [1,FD_IAVF_TILE_MAX].
   Each tile must provide distinct queue memory and queue state.
   Maps pairs at consecutive IOVAs starting at dma_iova and
   leaves them disabled until fd_iavf_virtchnl_enable_queues. */
int
fd_iavf_virtchnl_configure_queues( fd_iavf_vfio_t *            vfio,
                                   fd_iavf_adminq_t *          adminq,
                                   fd_iavf_vf_info_t const *   info,
                                   fd_iavf_vfio_tile_t const * tiles,
                                   uint                        queue_cnt,
                                   ulong                       dma_iova,
                                   uint                        rx_buffer_sz,
                                   uint                        max_frame_sz );

int
fd_iavf_virtchnl_enable_queues( fd_iavf_vfio_t *            vfio,
                                fd_iavf_adminq_t *          adminq,
                                fd_iavf_vf_info_t *         info,
                                fd_iavf_vfio_tile_t const * tiles,
                                uint                        queue_cnt );

FD_PROTOTYPES_END
#endif
#endif
