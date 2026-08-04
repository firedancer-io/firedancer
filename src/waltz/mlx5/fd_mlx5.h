#ifndef HEADER_fd_src_waltz_mlx5_fd_mlx5_h
#define HEADER_fd_src_waltz_mlx5_fd_mlx5_h

#if defined(__linux__)

#include "../../util/bits/fd_bits.h"

/* mlx5 queue entries use big-endian fields regardless of host byte
   order.  SQ WQEs occupy one 64-byte basic block.  RQ WQEs contain a
   single data segment. */

#define FD_MLX5_WQEBB_SZ        (64UL)
#define FD_MLX5_RQ_WQE_SZ       (16UL)
#define FD_MLX5_CQE_SZ          (64UL)
#define FD_MLX5_ETH_INLINE_SZ   (18UL)
#define FD_MLX5_PAGE_SZ         (4096UL)
#define FD_MLX5_BF_OFFSET       (0x800UL)
#define FD_MLX5_DBREC_SZ        (8UL)

#define FD_MLX5_RDMA_NAME_MAX   (64UL)
#define FD_MLX5_UVERBS_NAME_MAX (32UL)

#define FD_MLX5_CORE_ABI        (6U)
#define FD_MLX5_PROVIDER_ABI    (1U)

#define FD_MLX5_LINK_LAYER_ETHERNET (2U)

#define FD_MLX5_OPCODE_NOP      (0x00U)
#define FD_MLX5_OPCODE_SEND     (0x0aU)

#define FD_MLX5_WQE_CTRL_CQ_UPDATE (0x08U)

#define FD_MLX5_CQE_REQ         (0U)
#define FD_MLX5_CQE_RESP_SEND   (2U)
#define FD_MLX5_CQE_REQ_ERR     (13U)
#define FD_MLX5_CQE_RESP_ERR    (14U)
#define FD_MLX5_CQE_INVALID     (15U)

struct __attribute__((aligned(FD_MLX5_WQEBB_SZ))) fd_mlx5_tx_wqe {
  uchar bytes[ FD_MLX5_WQEBB_SZ ];
};
typedef struct fd_mlx5_tx_wqe fd_mlx5_tx_wqe_t;

struct __attribute__((aligned(FD_MLX5_RQ_WQE_SZ))) fd_mlx5_rx_wqe {
  uchar bytes[ FD_MLX5_RQ_WQE_SZ ];
};
typedef struct fd_mlx5_rx_wqe fd_mlx5_rx_wqe_t;

struct __attribute__((aligned(FD_MLX5_CQE_SZ))) fd_mlx5_cqe {
  uchar bytes[ FD_MLX5_CQE_SZ ];
};
typedef struct fd_mlx5_cqe fd_mlx5_cqe_t;

FD_STATIC_ASSERT( sizeof(fd_mlx5_tx_wqe_t)==FD_MLX5_WQEBB_SZ,  mlx5_tx_wqe_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_rx_wqe_t)==FD_MLX5_RQ_WQE_SZ, mlx5_rx_wqe_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_cqe_t   )==FD_MLX5_CQE_SZ,    mlx5_cqe_sz    );

/* fd_mlx5_context_t owns a uverbs command descriptor and the async
   event descriptor returned with it.  The remaining fields are a
   normalized subset of the capabilities needed to create raw-packet
   mlx5 resources in later stages. */

struct fd_mlx5_context {
  int cmd_fd;
  int async_fd;

  char rdma_name   [ FD_MLX5_RDMA_NAME_MAX   ];
  char uverbs_name[ FD_MLX5_UVERBS_NAME_MAX ];

  uint core_abi;
  uint provider_abi;
  uint port_num;
  uint num_comp_vectors;

  uint   qp_tab_size;
  uint   bf_reg_size;
  uint   tot_bfregs;
  uint   cache_line_size;
  ushort max_sq_desc_sz;
  ushort max_rq_desc_sz;
  uint   max_send_wqebb;
  uint   max_recv_wr;
  ushort num_ports;
  uchar  cqe_version;
  uchar  eth_min_inline_mode;
  uchar  eth_min_inline_sz;
  uint   log_uar_size;
  uint   num_uars_per_page;
  uint   num_dyn_bfregs;

  ulong max_mr_size;
  ulong page_size_cap;
  uint  vendor_id;
  uint  vendor_part_id;
  uint  max_qp_wr;
  uint  max_sge;
  uint  max_cqe;
  uchar phys_port_cnt;

  uint  port_cap_flags;
  uint  gid_tbl_len;
  uchar port_state;
  uchar max_mtu;
  uchar active_mtu;
  uchar phys_state;
  uchar link_layer;
};
typedef struct fd_mlx5_context fd_mlx5_context_t;

/* Protection domains own device resource handles.  Memory regions
   refer to their parent protection domain and describe caller-owned
   memory registered for local device writes. */

struct fd_mlx5_pd {
  fd_mlx5_context_t * ctx;
  uint                 handle;
  uint                 pdn;
};
typedef struct fd_mlx5_pd fd_mlx5_pd_t;

struct fd_mlx5_mr {
  fd_mlx5_pd_t * pd;
  void *          memory;
  ulong           memory_sz;
  uint            handle;
  uint            lkey;
  uint            rkey;
};
typedef struct fd_mlx5_mr fd_mlx5_mr_t;

struct fd_mlx5_uar {
  fd_mlx5_context_t * ctx;
  void *               map;
  ulong                map_sz;
  ulong                mmap_offset;
  volatile uchar *     reg;
  uint                 handle;
  uint                 page_id;
};
typedef struct fd_mlx5_uar fd_mlx5_uar_t;

struct fd_mlx5_cq {
  fd_mlx5_context_t * ctx;
  fd_mlx5_uar_t *     uar;
  fd_mlx5_cqe_t *     entries;
  uint *               dbrec;
  uint                 depth;
  uint                 handle;
  uint                 cqn;
  uint                 cons_idx;
};
typedef struct fd_mlx5_cq fd_mlx5_cq_t;

#define FD_MLX5_QPS_RESET (0U)
#define FD_MLX5_QPS_INIT  (1U)
#define FD_MLX5_QPS_RTR   (2U)
#define FD_MLX5_QPS_RTS   (3U)

#define FD_MLX5_QP_ALLOW_SELF_LOOPBACK_UC (1U)

struct fd_mlx5_qp {
  fd_mlx5_context_t * ctx;
  fd_mlx5_pd_t *      pd;
  fd_mlx5_cq_t *      rx_cq;
  fd_mlx5_cq_t *      tx_cq;
  fd_mlx5_uar_t *     uar;
  fd_mlx5_rx_wqe_t *  rq;
  fd_mlx5_tx_wqe_t *  sq;
  ulong *              rx_user_data;
  ulong *              tx_user_data;
  uint *               dbrec;
  uint                 rx_depth;
  uint                 tx_depth;
  uint                 handle;
  uint                 qpn;
  uint                 state;
  uint                 bfreg_index;
  uint                 rqn;
  uint                 sqn;
  uint                 tirn;
  uint                 tisn;
  uint                 sq_prod;
  uint                 sq_cons;
  uint                 rq_prod;
  uint                 rq_cons;
  uint                 bf_offset;
};
typedef struct fd_mlx5_qp fd_mlx5_qp_t;

struct fd_mlx5_send {
  void const * frame;
  ulong        frame_sz;
  ulong        user_data;
  uint         lkey;
  ulong        tx_inline_sz;
};
typedef struct fd_mlx5_send fd_mlx5_send_t;

struct fd_mlx5_recv {
  void * frame;
  ulong  frame_sz;
  ulong  user_data;
  uint   lkey;
};
typedef struct fd_mlx5_recv fd_mlx5_recv_t;

struct fd_mlx5_rx_comp {
  ulong user_data;
  uint  byte_len;
  uint  opcode;
};
typedef struct fd_mlx5_rx_comp fd_mlx5_rx_comp_t;

struct fd_mlx5_tx_comp {
  ulong user_data;
  uint  opcode;
};
typedef struct fd_mlx5_tx_comp fd_mlx5_tx_comp_t;

struct fd_mlx5_flow {
  fd_mlx5_qp_t * qp;
  uint            handle;
};
typedef struct fd_mlx5_flow fd_mlx5_flow_t;

struct fd_mlx5_queue_layout {
  uint rx_depth;
  uint tx_depth;

  ulong rx_cq_off;
  ulong rx_cq_sz;
  ulong tx_cq_off;
  ulong tx_cq_sz;
  ulong rq_off;
  ulong rq_sz;
  ulong sq_off;
  ulong sq_sz;

  ulong rx_cq_db_off;
  ulong tx_cq_db_off;
  ulong qp_db_off;
  ulong footprint;
};
typedef struct fd_mlx5_queue_layout fd_mlx5_queue_layout_t;

/* fd_mlx5_cqe_ready checks the CQ owner bit for the given monotonic
   consumer index and power-of-two depth.  A caller polling DMA memory
   must execute an appropriate DMA acquire barrier before reading the
   remaining CQE. */

int
fd_mlx5_cqe_ready( fd_mlx5_cqe_t const * cqe,
                   uint                  cons_idx,
                   uint                  depth );

uint
fd_mlx5_cqe_opcode( fd_mlx5_cqe_t const * cqe );

uint
fd_mlx5_cqe_byte_cnt( fd_mlx5_cqe_t const * cqe );

ushort
fd_mlx5_cqe_wqe_counter( fd_mlx5_cqe_t const * cqe );

uchar
fd_mlx5_cqe_vendor_err( fd_mlx5_cqe_t const * cqe );

uchar
fd_mlx5_cqe_syndrome( fd_mlx5_cqe_t const * cqe );

uint
fd_mlx5_cqe_sq_opcode( fd_mlx5_cqe_t const * cqe );

FD_PROTOTYPES_BEGIN

/* fd_mlx5_context_init resolves rdma_name through sysfs, validates the
   uverbs and mlx5 ABI versions, opens one device context, and queries
   device and port_num capabilities.  It does not create queue
   resources, map a UAR, install steering, or transmit traffic.  On
   success, returns ctx.  On failure, returns NULL, preserves errno,
   and releases all partially acquired descriptors.

   fd_mlx5_context_fini closes the async and command descriptors and
   returns ctx in an initialized, descriptor-free state. */

fd_mlx5_context_t *
fd_mlx5_context_init( fd_mlx5_context_t * ctx,
                      char const *         rdma_name,
                      uint                 port_num );

fd_mlx5_context_t *
fd_mlx5_context_fini( fd_mlx5_context_t * ctx );

/* fd_mlx5_pd_init allocates one protection domain in ctx.
   fd_mlx5_mr_init registers [memory,memory+memory_sz) for local device
   writes.  It does not allocate or map memory.  Callers must destroy
   all memory regions before their protection domain, and the domain
   before its context.

   Each init returns its first argument on success.  On failure, it
   returns NULL, preserves errno, and leaves the object unowned.  Each
   fini is a no-op on an unowned object.  A failed fini returns NULL
   and retains ownership so that teardown can be retried. */

fd_mlx5_pd_t *
fd_mlx5_pd_init( fd_mlx5_pd_t *      pd,
                 fd_mlx5_context_t * ctx );

fd_mlx5_pd_t *
fd_mlx5_pd_fini( fd_mlx5_pd_t * pd );

fd_mlx5_mr_t *
fd_mlx5_mr_init( fd_mlx5_mr_t * mr,
                 fd_mlx5_pd_t * pd,
                 void *          memory,
                 ulong           memory_sz );

fd_mlx5_mr_t *
fd_mlx5_mr_fini( fd_mlx5_mr_t * mr );

/* fd_mlx5_uar_init allocates one dynamic BlueFlame UAR through the
   mlx5 ioctl ABI and maps it with the kernel's explicit WC mapping.
   The returned reg points at the first BlueFlame register.  It does
   not write the mapping.  fd_mlx5_uar_fini unmaps and destroys it. */

fd_mlx5_uar_t *
fd_mlx5_uar_init( fd_mlx5_uar_t *     uar,
                  fd_mlx5_context_t * ctx );

fd_mlx5_uar_t *
fd_mlx5_uar_fini( fd_mlx5_uar_t * uar );

/* fd_mlx5_cq_init creates one 64-byte-entry completion queue over
   caller-owned, page-aligned entries and an eight-byte doorbell record.
   depth must be a supported power of two.  The CQ refers to uar but
   does not own the UAR or either memory region.  Destroy all CQs before
   their UAR and context. */

fd_mlx5_cq_t *
fd_mlx5_cq_init( fd_mlx5_cq_t *      cq,
                 fd_mlx5_context_t * ctx,
                 fd_mlx5_uar_t *     uar,
                 void *               entries,
                 uint *               dbrec,
                 uint                 depth );

fd_mlx5_cq_t *
fd_mlx5_cq_fini( fd_mlx5_cq_t * cq );

/* fd_mlx5_cq_poll_batch copies up to cqe_max device-owned CQEs and
   advances the consumer doorbell once.  It returns the number copied or
   minus one for invalid arguments.  fd_mlx5_cq_poll is the one-CQE
   convenience form. */

int
fd_mlx5_cq_poll_batch( fd_mlx5_cq_t *  cq,
                       fd_mlx5_cqe_t * cqe,
                       uint            cqe_max );

int
fd_mlx5_cq_poll( fd_mlx5_cq_t *  cq,
                 fd_mlx5_cqe_t * cqe );

fd_mlx5_qp_t *
fd_mlx5_qp_init( fd_mlx5_qp_t * qp,
                 fd_mlx5_pd_t * pd,
                 fd_mlx5_cq_t * rx_cq,
                 fd_mlx5_cq_t * tx_cq,
                 fd_mlx5_uar_t * uar,
                 void *          rq,
                 void *          sq,
                 ulong *         rx_user_data,
                 ulong *         tx_user_data,
                 uint *          dbrec,
                 uint            flags );

fd_mlx5_qp_t *
fd_mlx5_qp_start( fd_mlx5_qp_t * qp );

fd_mlx5_qp_t *
fd_mlx5_qp_fini( fd_mlx5_qp_t * qp );

/* fd_mlx5_qp_post_nop submits one signaled NOP WQE.  It writes no packet
   data but exercises the SQ doorbell record, WC BlueFlame register, and
   TX completion path.  fd_mlx5_qp_post_send submits one raw Ethernet
   frame and copies its complete WQE into the BlueFlame register.
   fd_mlx5_qp_tx_reclaim releases all SQ WQEBBs up to the completion's
   WQE counter. */

int
fd_mlx5_qp_post_nop( fd_mlx5_qp_t * qp );

int
fd_mlx5_qp_post_send( fd_mlx5_qp_t * qp,
                      void const *    frame,
                      ulong           frame_sz,
                      ulong           user_data,
                      uint            lkey,
                      ulong           tx_inline_sz,
                      int             request_cqe );

int
fd_mlx5_qp_post_send_batch( fd_mlx5_qp_t *         qp,
                            fd_mlx5_send_t const * send,
                            uint                    send_cnt );

int
fd_mlx5_qp_post_recv( fd_mlx5_qp_t * qp,
                      void *          frame,
                      ulong           frame_sz,
                      ulong           user_data,
                      uint            lkey );

int
fd_mlx5_qp_post_recv_batch( fd_mlx5_qp_t *         qp,
                            fd_mlx5_recv_t const * recv,
                            uint                    recv_cnt );

int
fd_mlx5_qp_tx_reclaim( fd_mlx5_qp_t *        qp,
                       fd_mlx5_cqe_t const * cqe );

int
fd_mlx5_qp_rx_reclaim( fd_mlx5_qp_t *        qp,
                       fd_mlx5_cqe_t const * cqe );

int
fd_mlx5_qp_poll_rx( fd_mlx5_qp_t *      qp,
                    fd_mlx5_rx_comp_t * comp,
                    uint                 comp_max );

int
fd_mlx5_qp_poll_tx( fd_mlx5_qp_t *      qp,
                    fd_mlx5_tx_comp_t * comp,
                    uint                 comp_max );

/* fd_mlx5_flow_init_eth installs one exact Ethernet destination and
   EtherType rule on qp.  The flow must be destroyed before its QP. */

fd_mlx5_flow_t *
fd_mlx5_flow_init_eth( fd_mlx5_flow_t * flow,
                       fd_mlx5_qp_t *   qp,
                       uchar const      dst_mac[6],
                       ushort           ether_type );

fd_mlx5_flow_t *
fd_mlx5_flow_init_udp( fd_mlx5_flow_t * flow,
                       fd_mlx5_qp_t *   qp,
                       uint             dst_ip,
                       ushort           dst_port );

fd_mlx5_flow_t *
fd_mlx5_flow_fini( fd_mlx5_flow_t * flow );

/* fd_mlx5_queue_layout_init describes page-separated RX CQ, TX CQ,
   RQ, SQ, and doorbell regions.  rx_depth and tx_depth are power-of-two
   queue entry counts and are shared by each direction's CQ and work
   queue.  fd_mlx5_queue_mem_init clears caller-owned, page-aligned
   memory and marks every CQE invalid before device creation. */

fd_mlx5_queue_layout_t *
fd_mlx5_queue_layout_init( fd_mlx5_queue_layout_t * layout,
                           fd_mlx5_context_t const * ctx,
                           uint                      rx_depth,
                           uint                      tx_depth );

ulong
fd_mlx5_queue_footprint( uint rx_depth,
                         uint tx_depth );

void *
fd_mlx5_queue_mem_init( void *                         memory,
                        fd_mlx5_queue_layout_t const * layout );

/* fd_mlx5_{tx,rx}_wqe_init construct queue entries but do not publish
   them to a device.  tx_inline_sz must be either zero or 18 bytes, as
   selected by the eth_min_inline capability returned by mlx5. */

fd_mlx5_tx_wqe_t *
fd_mlx5_tx_wqe_init( fd_mlx5_tx_wqe_t * wqe,
                     uint                sq_idx,
                     uint                qpn,
                     void const *        frame,
                     ulong               frame_sz,
                     uint                lkey,
                     ulong               tx_inline_sz,
                     int                 request_cqe );

fd_mlx5_tx_wqe_t *
fd_mlx5_nop_wqe_init( fd_mlx5_tx_wqe_t * wqe,
                      uint                sq_idx,
                      uint                qpn );

fd_mlx5_rx_wqe_t *
fd_mlx5_rx_wqe_init( fd_mlx5_rx_wqe_t * wqe,
                     void *              frame,
                     ulong               frame_sz,
                     uint                lkey );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_waltz_mlx5_fd_mlx5_h */
