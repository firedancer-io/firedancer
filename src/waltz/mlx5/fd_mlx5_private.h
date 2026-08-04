#ifndef HEADER_fd_src_waltz_mlx5_fd_mlx5_private_h
#define HEADER_fd_src_waltz_mlx5_fd_mlx5_private_h

#include "fd_mlx5.h"

#include <stddef.h>

#include <rdma/ib_user_ioctl_verbs.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/mlx5-abi.h>
#include <rdma/mlx5_user_ioctl_cmds.h>
#include <rdma/mlx5_user_ioctl_verbs.h>
#include <rdma/rdma_user_ioctl_cmds.h>

struct __attribute__((packed)) fd_mlx5_wqe_ctrl_wire {
  uint  opmod_idx_opcode;
  uint  qpn_ds;
  uchar signature;
  uchar reserved[2];
  uchar flags;
  uint  imm;
};
typedef struct fd_mlx5_wqe_ctrl_wire fd_mlx5_wqe_ctrl_wire_t;

struct __attribute__((packed)) fd_mlx5_wqe_eth_wire {
  uchar  reserved[12];
  ushort inline_hdr_sz;
  uchar  inline_hdr[2];
};
typedef struct fd_mlx5_wqe_eth_wire fd_mlx5_wqe_eth_wire_t;

struct __attribute__((packed)) fd_mlx5_wqe_data_wire {
  uint  byte_cnt;
  uint  lkey;
  ulong addr;
};
typedef struct fd_mlx5_wqe_data_wire fd_mlx5_wqe_data_wire_t;

struct __attribute__((packed)) fd_mlx5_cqe_wire {
  uchar  reserved0[44];
  uint   byte_cnt;
  uchar  reserved1[6];
  uchar  vendor_err;
  uchar  syndrome;
  uint   sop_drop_qpn;
  ushort wqe_counter;
  uchar  signature;
  uchar  op_own;
};
typedef struct fd_mlx5_cqe_wire fd_mlx5_cqe_wire_t;

FD_STATIC_ASSERT( sizeof(fd_mlx5_wqe_ctrl_wire_t)==16UL, mlx5_wqe_ctrl_wire_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_wqe_eth_wire_t )==16UL, mlx5_wqe_eth_wire_sz  );
FD_STATIC_ASSERT( sizeof(fd_mlx5_wqe_data_wire_t)==16UL, mlx5_wqe_data_wire_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_cqe_wire_t    )==64UL, mlx5_cqe_wire_sz      );
FD_STATIC_ASSERT( offsetof(fd_mlx5_wqe_ctrl_wire_t, flags       )==11UL, mlx5_wqe_ctrl_flags_off );
FD_STATIC_ASSERT( offsetof(fd_mlx5_wqe_eth_wire_t,  inline_hdr_sz)==12UL, mlx5_wqe_eth_inline_off );
FD_STATIC_ASSERT( offsetof(fd_mlx5_cqe_wire_t, byte_cnt   )==44UL, mlx5_cqe_byte_cnt_off );
FD_STATIC_ASSERT( offsetof(fd_mlx5_cqe_wire_t, vendor_err )==54UL, mlx5_cqe_vendor_off   );
FD_STATIC_ASSERT( offsetof(fd_mlx5_cqe_wire_t, syndrome   )==55UL, mlx5_cqe_syndrome_off );
FD_STATIC_ASSERT( offsetof(fd_mlx5_cqe_wire_t, sop_drop_qpn)==56UL, mlx5_cqe_sop_off      );
FD_STATIC_ASSERT( offsetof(fd_mlx5_cqe_wire_t, wqe_counter)==60UL, mlx5_cqe_counter_off  );
FD_STATIC_ASSERT( offsetof(fd_mlx5_cqe_wire_t, op_own     )==63UL, mlx5_cqe_op_own_off   );

struct fd_mlx5_uverbs_ex_hdr {
  struct ib_uverbs_cmd_hdr    cmd;
  struct ib_uverbs_ex_cmd_hdr ex;
};
typedef struct fd_mlx5_uverbs_ex_hdr fd_mlx5_uverbs_ex_hdr_t;

FD_STATIC_ASSERT( sizeof(struct ib_uverbs_cmd_hdr   )== 8UL, uverbs_cmd_hdr_sz );
FD_STATIC_ASSERT( sizeof(struct ib_uverbs_ex_cmd_hdr)==16UL, uverbs_ex_hdr_sz  );
FD_STATIC_ASSERT( sizeof(fd_mlx5_uverbs_ex_hdr_t    )==24UL, mlx5_ex_hdr_sz    );

struct fd_mlx5_get_context_req {
  struct ib_uverbs_cmd_hdr             hdr;
  ulong                                response;
  struct mlx5_ib_alloc_ucontext_req_v2 mlx5;
};
typedef struct fd_mlx5_get_context_req fd_mlx5_get_context_req_t;

struct fd_mlx5_get_context_resp {
  uint                                  async_fd;
  uint                                  num_comp_vectors;
  struct mlx5_ib_alloc_ucontext_resp    mlx5;
};
typedef struct fd_mlx5_get_context_resp fd_mlx5_get_context_resp_t;

struct fd_mlx5_query_device_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
};
typedef struct fd_mlx5_query_device_req fd_mlx5_query_device_req_t;

struct fd_mlx5_query_port_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
  uchar                    port_num;
  uchar                    reserved[ 7 ];
};
typedef struct fd_mlx5_query_port_req fd_mlx5_query_port_req_t;

struct fd_mlx5_alloc_pd_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
};
typedef struct fd_mlx5_alloc_pd_req fd_mlx5_alloc_pd_req_t;

struct fd_mlx5_alloc_pd_resp {
  uint                         pd_handle;
  struct mlx5_ib_alloc_pd_resp mlx5;
};
typedef struct fd_mlx5_alloc_pd_resp fd_mlx5_alloc_pd_resp_t;

struct fd_mlx5_dealloc_pd_req {
  struct ib_uverbs_cmd_hdr hdr;
  uint                     pd_handle;
};
typedef struct fd_mlx5_dealloc_pd_req fd_mlx5_dealloc_pd_req_t;

struct fd_mlx5_reg_mr_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
  ulong                    start;
  ulong                    length;
  ulong                    hca_va;
  uint                     pd_handle;
  uint                     access_flags;
};
typedef struct fd_mlx5_reg_mr_req fd_mlx5_reg_mr_req_t;

struct fd_mlx5_reg_mr_resp {
  uint mr_handle;
  uint lkey;
  uint rkey;
};
typedef struct fd_mlx5_reg_mr_resp fd_mlx5_reg_mr_resp_t;

struct fd_mlx5_dereg_mr_req {
  struct ib_uverbs_cmd_hdr hdr;
  uint                     mr_handle;
};
typedef struct fd_mlx5_dereg_mr_req fd_mlx5_dereg_mr_req_t;

struct fd_mlx5_ioctl_hdr {
  ushort length;
  ushort object_id;
  ushort method_id;
  ushort num_attrs;
  ulong  reserved1;
  uint   driver_id;
  uint   reserved2;
};
typedef struct fd_mlx5_ioctl_hdr fd_mlx5_ioctl_hdr_t;

struct fd_mlx5_uar_alloc_req {
  fd_mlx5_ioctl_hdr_t       hdr;
  struct ib_uverbs_attr     attrs[ 5 ];
};
typedef struct fd_mlx5_uar_alloc_req fd_mlx5_uar_alloc_req_t;

struct fd_mlx5_uar_destroy_req {
  fd_mlx5_ioctl_hdr_t       hdr;
  struct ib_uverbs_attr     attrs[ 1 ];
};
typedef struct fd_mlx5_uar_destroy_req fd_mlx5_uar_destroy_req_t;

struct fd_mlx5_create_cq_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
  ulong                    user_handle;
  uint                     cqe;
  uint                     comp_vector;
  int                      comp_channel;
  uint                     reserved;
  struct mlx5_ib_create_cq mlx5;
};
typedef struct fd_mlx5_create_cq_req fd_mlx5_create_cq_req_t;

struct fd_mlx5_create_cq_resp {
  uint                          cq_handle;
  uint                          cqe;
  struct mlx5_ib_create_cq_resp mlx5;
};
typedef struct fd_mlx5_create_cq_resp fd_mlx5_create_cq_resp_t;

struct fd_mlx5_destroy_cq_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
  uint                     cq_handle;
  uint                     reserved;
};
typedef struct fd_mlx5_destroy_cq_req fd_mlx5_destroy_cq_req_t;

struct fd_mlx5_create_qp_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
  ulong                    user_handle;
  uint                     pd_handle;
  uint                     send_cq_handle;
  uint                     recv_cq_handle;
  uint                     srq_handle;
  uint                     max_send_wr;
  uint                     max_recv_wr;
  uint                     max_send_sge;
  uint                     max_recv_sge;
  uint                     max_inline_data;
  uchar                    sq_sig_all;
  uchar                    qp_type;
  uchar                    is_srq;
  uchar                    reserved;
  struct mlx5_ib_create_qp mlx5;
};
typedef struct fd_mlx5_create_qp_req fd_mlx5_create_qp_req_t;

struct fd_mlx5_create_qp_resp {
  struct ib_uverbs_create_qp_resp core;
  struct mlx5_ib_create_qp_resp   mlx5;
};
typedef struct fd_mlx5_create_qp_resp fd_mlx5_create_qp_resp_t;

struct fd_mlx5_modify_qp_req {
  struct ib_uverbs_cmd_hdr hdr;
  struct ib_uverbs_modify_qp core;
};
typedef struct fd_mlx5_modify_qp_req fd_mlx5_modify_qp_req_t;

struct fd_mlx5_destroy_qp_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
  uint                     qp_handle;
  uint                     reserved;
};
typedef struct fd_mlx5_destroy_qp_req fd_mlx5_destroy_qp_req_t;

struct fd_mlx5_create_flow_req {
  fd_mlx5_uverbs_ex_hdr_t      hdr;
  uint                         comp_mask;
  uint                         qp_handle;
  uint                         type;
  ushort                       size;
  ushort                       priority;
  uchar                        num_of_specs;
  uchar                        reserved[2];
  uchar                        port;
  uint                         flags;
  struct ib_uverbs_flow_spec_eth eth;
  uint                           mlx5_ncounters_data;
  uint                           mlx5_reserved;
};
typedef struct fd_mlx5_create_flow_req fd_mlx5_create_flow_req_t;

struct fd_mlx5_create_udp_flow_req {
  fd_mlx5_uverbs_ex_hdr_t          hdr;
  uint                             comp_mask;
  uint                             qp_handle;
  uint                             type;
  ushort                           size;
  ushort                           priority;
  uchar                            num_of_specs;
  uchar                            reserved[2];
  uchar                            port;
  uint                             flags;
  struct ib_uverbs_flow_spec_eth   eth;
  struct ib_uverbs_flow_spec_ipv4  ipv4;
  struct ib_uverbs_flow_spec_tcp_udp udp;
  uint                             mlx5_ncounters_data;
  uint                             mlx5_reserved;
};
typedef struct fd_mlx5_create_udp_flow_req fd_mlx5_create_udp_flow_req_t;

struct fd_mlx5_destroy_flow_req {
  fd_mlx5_uverbs_ex_hdr_t hdr;
  uint                    comp_mask;
  uint                    flow_handle;
};
typedef struct fd_mlx5_destroy_flow_req fd_mlx5_destroy_flow_req_t;

FD_STATIC_ASSERT( sizeof(fd_mlx5_get_context_req_t )==48UL, mlx5_get_context_req_sz  );
FD_STATIC_ASSERT( sizeof(fd_mlx5_get_context_resp_t)==80UL, mlx5_get_context_resp_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_query_device_req_t)==16UL, mlx5_query_device_req_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_query_port_req_t  )==24UL, mlx5_query_port_req_sz   );
FD_STATIC_ASSERT( sizeof(fd_mlx5_alloc_pd_req_t    )==16UL, mlx5_alloc_pd_req_sz     );
FD_STATIC_ASSERT( sizeof(fd_mlx5_alloc_pd_resp_t   )== 8UL, mlx5_alloc_pd_resp_sz    );
FD_STATIC_ASSERT( sizeof(fd_mlx5_dealloc_pd_req_t  )==12UL, mlx5_dealloc_pd_req_sz   );
FD_STATIC_ASSERT( sizeof(fd_mlx5_reg_mr_req_t      )==48UL, mlx5_reg_mr_req_sz       );
FD_STATIC_ASSERT( sizeof(fd_mlx5_reg_mr_resp_t     )==12UL, mlx5_reg_mr_resp_sz      );
FD_STATIC_ASSERT( sizeof(fd_mlx5_dereg_mr_req_t    )==12UL, mlx5_dereg_mr_req_sz     );
FD_STATIC_ASSERT( sizeof(struct ib_uverbs_ioctl_hdr)==24UL, uverbs_ioctl_hdr_sz       );
FD_STATIC_ASSERT( sizeof(struct ib_uverbs_attr     )==16UL, uverbs_ioctl_attr_sz      );
FD_STATIC_ASSERT( sizeof(fd_mlx5_ioctl_hdr_t       )==24UL, mlx5_ioctl_hdr_sz         );
FD_STATIC_ASSERT( sizeof(fd_mlx5_uar_alloc_req_t   )==104UL, mlx5_uar_alloc_req_sz    );
FD_STATIC_ASSERT( sizeof(fd_mlx5_uar_destroy_req_t )== 40UL, mlx5_uar_destroy_req_sz  );
FD_STATIC_ASSERT( sizeof(fd_mlx5_create_cq_req_t   )== 72UL, mlx5_create_cq_req_sz    );
FD_STATIC_ASSERT( sizeof(fd_mlx5_create_cq_resp_t  )== 16UL, mlx5_create_cq_resp_sz   );
FD_STATIC_ASSERT( sizeof(fd_mlx5_destroy_cq_req_t  )== 24UL, mlx5_destroy_cq_req_sz   );
FD_STATIC_ASSERT( sizeof(fd_mlx5_create_qp_req_t   )==120UL, mlx5_create_qp_req_sz    );
FD_STATIC_ASSERT( sizeof(fd_mlx5_create_qp_resp_t  )== 72UL, mlx5_create_qp_resp_sz   );
FD_STATIC_ASSERT( sizeof(fd_mlx5_modify_qp_req_t   )==120UL, mlx5_modify_qp_req_sz    );
FD_STATIC_ASSERT( sizeof(fd_mlx5_destroy_qp_req_t  )== 24UL, mlx5_destroy_qp_req_sz   );
FD_STATIC_ASSERT( sizeof(fd_mlx5_create_flow_req_t )== 96UL, mlx5_create_flow_req_sz  );
FD_STATIC_ASSERT( sizeof(fd_mlx5_create_udp_flow_req_t)==144UL, mlx5_create_udp_flow_req_sz );
FD_STATIC_ASSERT( sizeof(fd_mlx5_destroy_flow_req_t)== 32UL, mlx5_destroy_flow_req_sz );

#define FD_MLX5_SUCCESS   (0)
#define FD_MLX5_ERR_INVAL (-1)

FD_PROTOTYPES_BEGIN

/* These helpers only marshal command headers.  Resource creation and
   write(2) execution belong to the control-plane layer built on top. */

int
fd_mlx5_uverbs_cmd_hdr_init( struct ib_uverbs_cmd_hdr * hdr,
                             uint                        command,
                             ulong                       request_sz,
                             ulong                       response_sz );

int
fd_mlx5_uverbs_ex_hdr_init( fd_mlx5_uverbs_ex_hdr_t * hdr,
                            uint                       command,
                            ulong                      core_request_sz,
                            ulong                      request_sz,
                            void *                     response,
                            ulong                      core_response_sz,
                            ulong                      response_sz );

int
fd_mlx5_uar_alloc_req_init( fd_mlx5_uar_alloc_req_t * req,
                            ulong *                    mmap_offset,
                            uint *                     mmap_sz,
                            uint *                     page_id );

int
fd_mlx5_uar_destroy_req_init( fd_mlx5_uar_destroy_req_t * req,
                              uint                        handle );

int
fd_mlx5_create_flow_req_init( fd_mlx5_create_flow_req_t *        req,
                              struct ib_uverbs_create_flow_resp * resp,
                              uint                               qp_handle,
                              uint                               port_num,
                              uchar const                         dst_mac[6],
                              ushort                              ether_type );

int
fd_mlx5_create_udp_flow_req_init( fd_mlx5_create_udp_flow_req_t * req,
                                  struct ib_uverbs_create_flow_resp * resp,
                                  uint                              qp_handle,
                                  uint                              port_num,
                                  uint                              dst_ip,
                                  ushort                            dst_port );

int
fd_mlx5_destroy_flow_req_init( fd_mlx5_destroy_flow_req_t * req,
                               uint                         handle );

/* fd_mlx5_uar_mmap_offset returns the byte offset expected by mmap(2)
   for an mlx5 UAR command and index.  ULONG_MAX indicates invalid or
   overflowing input. */

ulong
fd_mlx5_uar_mmap_offset( uint  command,
                         uint  index,
                         ulong page_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_mlx5_fd_mlx5_private_h */
