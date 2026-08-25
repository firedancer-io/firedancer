#include "fd_mlx5_private.h"
#include "../fd_linux_bond.h"
#include "../../../util/log/fd_log.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/mlx5-abi.h>
#include <rdma/mlx5_user_ioctl_cmds.h>
#include <rdma/mlx5_user_ioctl_verbs.h>
#include <rdma/rdma_netlink.h>
#include <rdma/rdma_user_ioctl_cmds.h>

/* Provide uverbs and mlx5 UAPI definitions missing from older Linux headers. */
#ifndef IB_UVERBS_ACCESS_LOCAL_WRITE
#define IB_UVERBS_ACCESS_LOCAL_WRITE (1U)
#endif
#ifndef IB_UVERBS_QPT_RAW_PACKET
#define IB_UVERBS_QPT_RAW_PACKET (8U)
#endif
#ifndef MLX5_LIB_CAP_DYN_UAR
#define MLX5_LIB_CAP_DYN_UAR (2UL)
#endif
#ifndef MLX5_IB_OBJECT_UAR
#define MLX5_IB_OBJECT_UAR (4104U)
#endif
#ifndef MLX5_IB_METHOD_UAR_OBJ_ALLOC
#define MLX5_IB_METHOD_UAR_OBJ_ALLOC (4096U)
#endif
#ifndef MLX5_IB_METHOD_UAR_OBJ_DESTROY
#define MLX5_IB_METHOD_UAR_OBJ_DESTROY (4097U)
#endif
#ifndef MLX5_IB_ATTR_UAR_OBJ_ALLOC_HANDLE
#define MLX5_IB_ATTR_UAR_OBJ_ALLOC_HANDLE (4096U)
#endif
#ifndef MLX5_IB_ATTR_UAR_OBJ_ALLOC_TYPE
#define MLX5_IB_ATTR_UAR_OBJ_ALLOC_TYPE (4097U)
#endif
#ifndef MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_OFFSET
#define MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_OFFSET (4098U)
#endif
#ifndef MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_LENGTH
#define MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_LENGTH (4099U)
#endif
#ifndef MLX5_IB_ATTR_UAR_OBJ_ALLOC_PAGE_ID
#define MLX5_IB_ATTR_UAR_OBJ_ALLOC_PAGE_ID (4100U)
#endif
#ifndef MLX5_IB_ATTR_UAR_OBJ_DESTROY_HANDLE
#define MLX5_IB_ATTR_UAR_OBJ_DESTROY_HANDLE (4096U)
#endif
#ifndef MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC
#define MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC (1U)
#endif
#ifndef MLX5_IB_CREATE_CQ_FLAGS_UAR_PAGE_INDEX
#define MLX5_IB_CREATE_CQ_FLAGS_UAR_PAGE_INDEX (2U)
#endif
#ifndef MLX5_QP_FLAG_UAR_PAGE_INDEX
#define MLX5_QP_FLAG_UAR_PAGE_INDEX (1024U)
#endif
#ifndef RDMA_NLDEV_CMD_STAT_SET
#define RDMA_NLDEV_CMD_STAT_SET (16U)
#endif
#ifndef RDMA_NLDEV_CMD_STAT_GET
#define RDMA_NLDEV_CMD_STAT_GET (17U)
#endif
#ifndef RDMA_NLDEV_ATTR_STAT_MODE
#define RDMA_NLDEV_ATTR_STAT_MODE (74U)
#endif
#ifndef RDMA_NLDEV_ATTR_STAT_RES
#define RDMA_NLDEV_ATTR_STAT_RES (75U)
#endif
#ifndef RDMA_NLDEV_ATTR_STAT_COUNTER
#define RDMA_NLDEV_ATTR_STAT_COUNTER (77U)
#endif
#ifndef RDMA_NLDEV_ATTR_STAT_COUNTER_ENTRY
#define RDMA_NLDEV_ATTR_STAT_COUNTER_ENTRY (78U)
#endif
#ifndef RDMA_NLDEV_ATTR_STAT_COUNTER_ID
#define RDMA_NLDEV_ATTR_STAT_COUNTER_ID (79U)
#endif
#ifndef RDMA_NLDEV_ATTR_STAT_HWCOUNTERS
#define RDMA_NLDEV_ATTR_STAT_HWCOUNTERS (80U)
#endif
#ifndef RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY
#define RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY (81U)
#endif
#ifndef RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY_NAME
#define RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY_NAME (82U)
#endif
#ifndef RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY_VALUE
#define RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY_VALUE (83U)
#endif
#ifndef RDMA_COUNTER_MODE_MANUAL
#define RDMA_COUNTER_MODE_MANUAL (2U)
#endif

/* FD_MLX5_UAR_DB_OFFSET is SQ doorbell register offset */
#define FD_MLX5_UAR_DB_OFFSET       (0x800UL) /* MLX5_BF_OFFSET */
#define FD_MLX5_ETH_INLINE_HDR_SZ   (18UL)    /* MLX5_ETH_L2_INLINE_HEADER_SIZE */
#define FD_MLX5_LINK_LAYER_ETHERNET (2U)      /* IB_LINK_LAYER_ETHERNET */
#define FD_UVERBS_NAME_MAX          (32UL)

#define FD_MLX5_QPS_INIT (1U) /* IB_QPS_INIT */
#define FD_MLX5_QPS_RTR  (2U) /* IB_QPS_RTR */
#define FD_MLX5_QPS_RTS  (3U) /* IB_QPS_RTS */

#define FD_MLX5_QP_ATTR_STATE (1U)    /* IB_QP_STATE */
#define FD_MLX5_QP_ATTR_PORT  (1U<<5) /* IB_QP_PORT */

#define FD_MLX5_WQS_RDY       (1U)    /* IB_WQS_RDY */
#define FD_MLX5_WQ_ATTR_STATE (1U)    /* IB_WQ_STATE */

#define FD_MLX5_RSS_HASH_FIELDS \
  ( MLX5_RX_HASH_SRC_IPV4     | \
    MLX5_RX_HASH_DST_IPV4     | \
    MLX5_RX_HASH_SRC_PORT_UDP | \
    MLX5_RX_HASH_DST_PORT_UDP )

/* common Toeplitz hash key */
static uchar const fd_mlx5_rss_key[ FD_MLX5_RSS_KEY_SZ ] = {
  0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
  0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
  0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
  0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
  0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa
};

struct fd_mlx5_pd {
  fd_uverbs_ctx_t * ctx;    /* uverbs context */
  uint              handle; /* protection domain handle */
};
typedef struct fd_mlx5_pd fd_mlx5_pd_t;

/* fd_uverbs_* types define Linux uverbs requests and responses */
struct fd_uverbs_ex_hdr {
  struct ib_uverbs_cmd_hdr    cmd;
  struct ib_uverbs_ex_cmd_hdr ex;
};
typedef struct fd_uverbs_ex_hdr fd_uverbs_ex_hdr_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_ex_hdr_t)==24UL, uverbs_ex_hdr_sz );

struct fd_uverbs_get_context_req {
  struct ib_uverbs_cmd_hdr             hdr;
  ulong                                response;
  struct mlx5_ib_alloc_ucontext_req_v2 mlx5;
};
typedef struct fd_uverbs_get_context_req fd_uverbs_get_context_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_get_context_req_t)==48UL, uverbs_get_context_req_sz );

struct fd_uverbs_get_context_resp {
  uint                               async_fd;
  uint                               num_comp_vectors;
  struct mlx5_ib_alloc_ucontext_resp mlx5;
};
typedef struct fd_uverbs_get_context_resp fd_uverbs_get_context_resp_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_get_context_resp_t)==80UL, uverbs_get_context_resp_sz );

struct fd_uverbs_query_device_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
};
typedef struct fd_uverbs_query_device_req fd_uverbs_query_device_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_query_device_req_t)==16UL, uverbs_query_device_req_sz );

struct fd_uverbs_query_port_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
  uchar                    port_num;
  uchar                    reserved[ 7 ];
};
typedef struct fd_uverbs_query_port_req fd_uverbs_query_port_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_query_port_req_t)==24UL, uverbs_query_port_req_sz );

struct fd_uverbs_alloc_pd_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
};
typedef struct fd_uverbs_alloc_pd_req fd_uverbs_alloc_pd_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_alloc_pd_req_t)==16UL, uverbs_alloc_pd_req_sz );

struct fd_uverbs_alloc_pd_resp {
  uint                         pd_handle;
  struct mlx5_ib_alloc_pd_resp mlx5;
};
typedef struct fd_uverbs_alloc_pd_resp fd_uverbs_alloc_pd_resp_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_alloc_pd_resp_t)==8UL, uverbs_alloc_pd_resp_sz );

struct fd_uverbs_reg_mr_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
  ulong                    start;
  ulong                    length;
  ulong                    hca_va;
  uint                     pd_handle;
  uint                     access_flags;
};
typedef struct fd_uverbs_reg_mr_req fd_uverbs_reg_mr_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_reg_mr_req_t)==48UL, uverbs_reg_mr_req_sz );

struct fd_uverbs_reg_mr_resp {
  uint mr_handle;
  uint lkey;
  uint rkey;
};
typedef struct fd_uverbs_reg_mr_resp fd_uverbs_reg_mr_resp_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_reg_mr_resp_t)==12UL, uverbs_reg_mr_resp_sz );

struct fd_uverbs_ioctl_hdr {
  ushort length;
  ushort object_id;
  ushort method_id;
  ushort num_attrs;
  ulong  reserved1;
  uint   driver_id;
  uint   reserved2;
};
typedef struct fd_uverbs_ioctl_hdr fd_uverbs_ioctl_hdr_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_ioctl_hdr_t)==24UL, uverbs_ioctl_hdr_sz );

struct fd_uverbs_alloc_uar_req {
  fd_uverbs_ioctl_hdr_t hdr;
  struct ib_uverbs_attr attrs[ 5 ];
};
typedef struct fd_uverbs_alloc_uar_req fd_uverbs_alloc_uar_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_alloc_uar_req_t)==104UL, uverbs_alloc_uar_req_sz );

struct fd_uverbs_destroy_uar_req {
  fd_uverbs_ioctl_hdr_t hdr;
  struct ib_uverbs_attr attrs[ 1 ];
};
typedef struct fd_uverbs_destroy_uar_req fd_uverbs_destroy_uar_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_destroy_uar_req_t)==40UL, uverbs_destroy_uar_req_sz );

struct fd_uverbs_create_cq_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
  ulong                    user_handle;
  uint                     cqe;
  uint                     comp_vector;
  int                      comp_channel;
  uint                     reserved;
  /* mlx5_ib_create_cq gained uar_page_index in Linux 5.7 */
  union {
    struct mlx5_ib_create_cq fields;
    struct {
      uchar  prefix[ 24 ];
      ushort uar_page_index;
    } uar;
  } mlx5;
};
typedef struct fd_uverbs_create_cq_req fd_uverbs_create_cq_req_t;

struct fd_uverbs_create_cq_resp {
  uint                          cq_handle;
  uint                          cqe;
  struct mlx5_ib_create_cq_resp mlx5;
};
typedef struct fd_uverbs_create_cq_resp fd_uverbs_create_cq_resp_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_create_cq_resp_t)==16UL, uverbs_create_cq_resp_sz );

struct fd_uverbs_destroy_cq_req {
  struct ib_uverbs_cmd_hdr hdr;
  ulong                    response;
  uint                     cq_handle;
  uint                     reserved;
};
typedef struct fd_uverbs_destroy_cq_req fd_uverbs_destroy_cq_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_destroy_cq_req_t)==24UL, uverbs_destroy_cq_req_sz );

struct fd_uverbs_create_qp_req {
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
typedef struct fd_uverbs_create_qp_req fd_uverbs_create_qp_req_t;

struct fd_uverbs_create_qp_resp {
  struct ib_uverbs_create_qp_resp core;
  struct mlx5_ib_create_qp_resp   mlx5;
};
typedef struct fd_uverbs_create_qp_resp fd_uverbs_create_qp_resp_t;

struct fd_uverbs_modify_qp_req {
  struct ib_uverbs_cmd_hdr   hdr;
  struct ib_uverbs_modify_qp core;
};
typedef struct fd_uverbs_modify_qp_req fd_uverbs_modify_qp_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_modify_qp_req_t)==120UL, uverbs_modify_qp_req_sz );

struct fd_uverbs_create_wq_req {
  fd_uverbs_ex_hdr_t            hdr;
  struct ib_uverbs_ex_create_wq core;
  struct mlx5_ib_create_wq      mlx5;
};
typedef struct fd_uverbs_create_wq_req fd_uverbs_create_wq_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_create_wq_req_t)==112UL, uverbs_create_wq_req_sz );

struct fd_uverbs_create_wq_resp {
  struct ib_uverbs_ex_create_wq_resp core;
  struct mlx5_ib_create_wq_resp      mlx5;
};
typedef struct fd_uverbs_create_wq_resp fd_uverbs_create_wq_resp_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_create_wq_resp_t)==32UL, uverbs_create_wq_resp_sz );

struct fd_uverbs_modify_wq_req {
  fd_uverbs_ex_hdr_t            hdr;
  struct ib_uverbs_ex_modify_wq core;
  struct mlx5_ib_modify_wq      mlx5;
};
typedef struct fd_uverbs_modify_wq_req fd_uverbs_modify_wq_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_modify_wq_req_t)==56UL, uverbs_modify_wq_req_sz );

struct fd_uverbs_create_rqt_req {
  fd_uverbs_ex_hdr_t hdr;
  uint               comp_mask;
  uint               log_ind_tbl_size;
  uint               wq_handle[ FD_MLX5_RQT_SZ ];
};
typedef struct fd_uverbs_create_rqt_req fd_uverbs_create_rqt_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_create_rqt_req_t)==544UL, uverbs_create_rqt_req_sz );

struct fd_uverbs_create_rqt_resp {
  struct ib_uverbs_ex_create_rwq_ind_table_resp core;
  struct mlx5_ib_create_rwq_ind_tbl_resp        mlx5;
};
typedef struct fd_uverbs_create_rqt_resp fd_uverbs_create_rqt_resp_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_create_rqt_resp_t)==24UL, uverbs_create_rqt_resp_sz );

struct fd_uverbs_create_rss_qp_req {
  fd_uverbs_ex_hdr_t            hdr;
  struct ib_uverbs_ex_create_qp core;
  struct mlx5_ib_create_qp_rss  mlx5;
};
typedef struct fd_uverbs_create_rss_qp_req fd_uverbs_create_rss_qp_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_create_rss_qp_req_t)==240UL, uverbs_create_rss_qp_req_sz );

struct fd_uverbs_create_rss_qp_resp {
  struct ib_uverbs_ex_create_qp_resp core;
  struct mlx5_ib_create_qp_resp      mlx5;
};
typedef struct fd_uverbs_create_rss_qp_resp fd_uverbs_create_rss_qp_resp_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_create_rss_qp_resp_t)==80UL, uverbs_create_rss_qp_resp_sz );

struct fd_uverbs_create_udp_flow_req {
  fd_uverbs_ex_hdr_t                 hdr;
  uint                               comp_mask;
  uint                               qp_handle;
  uint                               type;
  ushort                             size;
  ushort                             priority;
  uchar                              num_of_specs;
  uchar                              reserved[2];
  uchar                              port;
  uint                               flags;
  struct ib_uverbs_flow_spec_eth     eth;
  struct ib_uverbs_flow_spec_ipv4    ipv4;
  struct ib_uverbs_flow_spec_tcp_udp udp;
  uint                               mlx5_ncounters_data;
  uint                               mlx5_reserved;
};
typedef struct fd_uverbs_create_udp_flow_req fd_uverbs_create_udp_flow_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_create_udp_flow_req_t)==144UL, uverbs_create_udp_flow_req_sz );

struct fd_uverbs_create_gre_flow_req {
  fd_uverbs_ex_hdr_t                 hdr;
  uint                               comp_mask;
  uint                               qp_handle;
  uint                               type;
  ushort                             size;
  ushort                             priority;
  uchar                              num_of_specs;
  uchar                              reserved[2];
  uchar                              port;
  uint                               flags;
  struct ib_uverbs_flow_spec_eth     eth;
  struct ib_uverbs_flow_spec_ipv4    outer_ipv4;
  struct ib_uverbs_flow_spec_gre     gre;
  struct ib_uverbs_flow_spec_ipv4    inner_ipv4;
  struct ib_uverbs_flow_spec_tcp_udp inner_udp;
  uint                               mlx5_ncounters_data;
  uint                               mlx5_reserved;
};
typedef struct fd_uverbs_create_gre_flow_req fd_uverbs_create_gre_flow_req_t;
FD_STATIC_ASSERT( sizeof(fd_uverbs_create_gre_flow_req_t)==200UL, uverbs_create_gre_flow_req_sz );

#define FD_RDMA_PATH_MAX (256UL)

#define FD_MLX5_FLOW_SPEC_ETH   (0x20U)  /* IB_FLOW_SPEC_ETH */
#define FD_MLX5_FLOW_SPEC_IPV4  (0x30U)  /* IB_FLOW_SPEC_IPV4 */
#define FD_MLX5_FLOW_SPEC_UDP   (0x41U)  /* IB_FLOW_SPEC_UDP */
#define FD_MLX5_FLOW_SPEC_GRE   (0x51U)  /* IB_FLOW_SPEC_GRE */
#define FD_MLX5_FLOW_SPEC_INNER (0x100U) /* IB_FLOW_SPEC_INNER */

/* fd_rdma_* helpers discover and inspect the selected Linux RDMA device */
static int
fd_rdma_read_text( char const * path,
                   char *       buf,
                   ulong        buf_sz ) {
  FD_TEST( buf_sz>1UL );

  int text_fd = open( path, O_RDONLY | O_CLOEXEC );
  if( FD_UNLIKELY( text_fd<0 ) ) return -1;

  long read_sz = read( text_fd, buf, buf_sz );
  int  err     = 0;
  if( FD_UNLIKELY( read_sz<0L ) )                  err = errno;
  else if( FD_UNLIKELY( (ulong)read_sz==buf_sz ) ) err = EOVERFLOW;
  if( FD_UNLIKELY( close( text_fd ) && !err ) )    err = errno;
  if( FD_UNLIKELY( err ) ) {
    errno = err;
    return -1;
  }

  ulong text_sz = (ulong)read_sz;
  while( text_sz && fd_isspace( (int)(uchar)buf[ text_sz-1UL ] ) ) text_sz--;
  if( FD_UNLIKELY( !text_sz ) ) {
    errno = EPROTO;
    return -1;
  }
  buf[ text_sz ] = '\0';
  return 0;
}

static int
fd_rdma_read_uint( char const * path,
                   uint *       value ) {
  char buf[ 32 ];
  if( FD_UNLIKELY( fd_rdma_read_text( path, buf, sizeof(buf) ) ) ) return -1;

  char * end;
  ulong parsed_value = strtoul( buf, &end, 10 );
  if( FD_UNLIKELY( *end || parsed_value>UINT_MAX ) ) {
    errno = EPROTO;
    return -1;
  }
  *value = (uint)parsed_value;
  return 0;
}

static int
fd_rdma_name_valid( char const * name,
                    ulong        name_max ) {
  if( FD_UNLIKELY( !name || !name[0] ) ) return 0;
  if( FD_UNLIKELY( name[0]=='.' && (!name[1] || (name[1]=='.' && !name[2])) ) ) return 0;
  for( ulong i=0UL; i<name_max; i++ ) {
    uchar c = (uchar)name[ i ];
    if( !c ) return 1;
    if( !((c>=(uchar)'a' && c<=(uchar)'z') ||
          (c>=(uchar)'A' && c<=(uchar)'Z') ||
          (c>=(uchar)'0' && c<=(uchar)'9') ||
          c==(uchar)'_' || c==(uchar)'-' || c==(uchar)'.') ) return 0;
  }
  return 0;
}

static int
fd_mlx5_check_driver( char const * rdma_name ) {
  char path[ FD_RDMA_PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL,
                                 "/sys/class/infiniband/%s/device/driver", rdma_name ) );

  char target[ FD_RDMA_PATH_MAX ];
  ssize_t target_sz = readlink( path, target, sizeof(target)-1UL );
  if( FD_UNLIKELY( target_sz<0 ) ) return -1;
  if( FD_UNLIKELY( (ulong)target_sz==sizeof(target)-1UL ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  target[ target_sz ] = '\0';

  char const * driver = strrchr( target, '/' );
  driver = driver ? driver+1 : target;
  if( FD_UNLIKELY( strcmp( driver, "mlx5_core" ) ) ) {
    errno = ENODEV;
    return -1;
  }
  return 0;
}

/* fd_mlx5_rdma_port_contains_if reports whether an RDMA device port is
   backed by the given network interface. */
static int
fd_mlx5_rdma_port_contains_if( char const * rdma_name,
                               uint         port_num,
                               char const * if_name ) {
  char dir_path[ FD_RDMA_PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( dir_path, sizeof(dir_path), NULL,
                                 "/sys/class/infiniband/%s/ports/%u/gid_attrs/ndevs",
                                 rdma_name, port_num ) );

  DIR * netdev_dir = opendir( dir_path );
  if( FD_UNLIKELY( !netdev_dir ) ) return 0;

  int             netdev_found = 0;
  struct dirent * netdev_entry;
  while( !netdev_found && (netdev_entry=readdir( netdev_dir )) ) {
    if( netdev_entry->d_name[0]=='.' ) continue;

    char path[ FD_RDMA_PATH_MAX ];
    char netdev_name[ IF_NAMESIZE+2UL ];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/%s", dir_path, netdev_entry->d_name ) );
    if( FD_UNLIKELY( fd_rdma_read_text( path, netdev_name, sizeof(netdev_name) ) ) ) continue;
    netdev_found = !strcmp( netdev_name, if_name );
  }
  if( FD_UNLIKELY( closedir( netdev_dir ) ) ) return 0;
  return netdev_found;
}

static int
fd_mlx5_rdma_port_matches_if( char const * rdma_name,
                              uint         port_num,
                              char const * if_name ) {
  if( fd_mlx5_rdma_port_contains_if( rdma_name, port_num, if_name ) ) return 1;
  if( !fd_bonding_is_master( if_name ) ) return 0;

  fd_bonding_slave_iter_t   iter_mem[1];
  fd_bonding_slave_iter_t * iter = fd_bonding_slave_iter_init( iter_mem, if_name );
  while( !fd_bonding_slave_iter_done( iter ) ) {
    if( fd_mlx5_rdma_port_contains_if( rdma_name, port_num, fd_bonding_slave_iter_ele( iter ) ) ) return 1;
    fd_bonding_slave_iter_next( iter );
  }
  return 0;
}

void
fd_mlx5_rdma_dev_find( char         rdma_name[ FD_MLX5_RDMA_NAME_MAX ],
                       uint *       port_num,
                       char const * if_name ) {
  DIR * infiniband_dir = opendir( "/sys/class/infiniband" );
  if( FD_UNLIKELY( !infiniband_dir ) ) {
    FD_LOG_ERR(( "opendir(/sys/class/infiniband) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  rdma_name[0] = '\0';
  *port_num = 0U;

  struct dirent * device_entry;
  while( (device_entry=readdir( infiniband_dir )) ) {
    if( device_entry->d_name[0]=='.' ) continue;

    char device_ports_path[ FD_RDMA_PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( device_ports_path, sizeof(device_ports_path), NULL,
                                   "/sys/class/infiniband/%s/ports", device_entry->d_name ) );
    DIR * ports_dir = opendir( device_ports_path );
    if( FD_UNLIKELY( !ports_dir ) ) continue;

    struct dirent * port_entry;
    while( (port_entry=readdir( ports_dir )) ) {
      char * port_end;
      ulong const port = strtoul( port_entry->d_name, &port_end, 10 );
      if( !port || *port_end || port>(ulong)UCHAR_MAX ) continue;

      if( !fd_mlx5_rdma_port_matches_if( device_entry->d_name, (uint)port, if_name ) ) continue;

      if( FD_UNLIKELY( rdma_name[0] ) ) {
        FD_LOG_ERR(( "multiple RDMA ports match interface `%s` (`%s` port %u and `%s` port %lu)",
                     if_name, rdma_name, *port_num, device_entry->d_name, port ));
      }
      fd_cstr_ncpy( rdma_name, device_entry->d_name, FD_MLX5_RDMA_NAME_MAX );
      *port_num = (uint)port;
    }
    closedir( ports_dir );
  }

  if( FD_UNLIKELY( closedir( infiniband_dir ) ) ) {
    FD_LOG_ERR(( "closedir(/sys/class/infiniband) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( !rdma_name[0] ) ) {
    FD_LOG_ERR(( "RDMA device port for interface `%s` not found", if_name ));
  }
}

/* fd_uverbs_* helpers build and submit Linux uverbs commands */
static int
fd_uverbs_name_valid( char const * name ) {
  ulong name_sz = strnlen( name, FD_UVERBS_NAME_MAX );
  if( name_sz==FD_UVERBS_NAME_MAX || name_sz==6UL || strncmp( name, "uverbs", 6UL ) ) return 0;
  for( char const * digit_cur=name+6; *digit_cur; digit_cur++ )
    if( *digit_cur<'0' || *digit_cur>'9' ) return 0;
  return 1;
}

static int
fd_uverbs_resolve( char         uverbs_name[ FD_UVERBS_NAME_MAX ],
                   char const * rdma_name ) {
  if( FD_UNLIKELY( !fd_rdma_name_valid( rdma_name, FD_MLX5_RDMA_NAME_MAX ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_mlx5_check_driver( rdma_name ) ) ) return -1;

  DIR * uverbs_dir = opendir( "/sys/class/infiniband_verbs" );
  if( FD_UNLIKELY( !uverbs_dir ) ) return -1;

  char matched_uverbs_name[ FD_UVERBS_NAME_MAX ];
  int  err;
  for(;;) {
    errno = 0;
    struct dirent * uverbs_entry = readdir( uverbs_dir );
    if( !uverbs_entry ) {
      err = errno ? errno : ENODEV;
      break;
    }
    if( !fd_uverbs_name_valid( uverbs_entry->d_name ) ) continue;

    char path[ FD_RDMA_PATH_MAX ];
    char entry_rdma_name[ FD_MLX5_RDMA_NAME_MAX ];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL,
                                   "/sys/class/infiniband_verbs/%s/ibdev", uverbs_entry->d_name ) );
    if( FD_UNLIKELY( fd_rdma_read_text( path, entry_rdma_name, sizeof(entry_rdma_name) ) ) ) {
      err = errno;
      break;
    }
    if( strcmp( entry_rdma_name, rdma_name ) ) continue;

    ulong name_sz = strlen( uverbs_entry->d_name );
    fd_memcpy( matched_uverbs_name, uverbs_entry->d_name, name_sz+1UL );
    err = 0;
    break;
  }
  closedir( uverbs_dir );
  if( FD_UNLIKELY( err ) ) {
    errno = err;
    return -1;
  }

  char path[ FD_RDMA_PATH_MAX ];
  uint core_abi;
  uint provider_abi;
  if( FD_UNLIKELY( fd_rdma_read_uint( "/sys/class/infiniband_verbs/abi_version", &core_abi ) ) ) return -1;
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL,
                                 "/sys/class/infiniband_verbs/%s/abi_version", matched_uverbs_name ) );
  if( FD_UNLIKELY( fd_rdma_read_uint( path, &provider_abi ) ) ) return -1;
  if( FD_UNLIKELY( core_abi!=IB_USER_VERBS_ABI_VERSION ||
                   provider_abi!=MLX5_IB_UVERBS_ABI_VERSION ) ) {
    FD_LOG_WARNING(( "mlx5 uverbs ABI mismatch (core %u, expected %u, provider %u, expected %u)",
                     core_abi, (uint)IB_USER_VERBS_ABI_VERSION,
                     provider_abi, (uint)MLX5_IB_UVERBS_ABI_VERSION ));
    errno = EPROTONOSUPPORT;
    return -1;
  }

  fd_memcpy( uverbs_name, matched_uverbs_name, strlen(matched_uverbs_name)+1UL );
  return 0;
}

static int
fd_uverbs_init_cmd_hdr( struct ib_uverbs_cmd_hdr * hdr,
                        uint                       command,
                        ulong                      request_sz,
                        ulong                      response_sz ) {
  if( FD_UNLIKELY( !hdr || command>IB_USER_VERBS_CMD_COMMAND_MASK || request_sz<sizeof(*hdr) ) ) return -1;

  hdr->command   = command;
  hdr->in_words  = (ushort)(request_sz / 4UL);
  hdr->out_words = (ushort)(response_sz / 4UL);
  return 0;
}

static int
fd_uverbs_init_ex_hdr( fd_uverbs_ex_hdr_t * hdr,
                       uint                 command,
                       ulong                core_request_sz,
                       ulong                request_sz,
                       void *               response,
                       ulong                core_response_sz,
                       ulong                response_sz ) {
  ulong const hdr_sz = sizeof(*hdr);
  if( FD_UNLIKELY( !hdr || command>IB_USER_VERBS_CMD_COMMAND_MASK ||
                   core_request_sz<hdr_sz || request_sz<core_request_sz ||
                   response_sz<core_response_sz || (response_sz && !response) ) ) return -1;

  hdr->cmd.command           = IB_USER_VERBS_CMD_FLAG_EXTENDED | command;
  hdr->cmd.in_words          = (ushort)((core_request_sz-hdr_sz) / 8UL);
  hdr->cmd.out_words         = (ushort)(core_response_sz / 8UL);
  hdr->ex.provider_in_words  = (ushort)((request_sz-core_request_sz) / 8UL);
  hdr->ex.provider_out_words = (ushort)((response_sz-core_response_sz) / 8UL);
  hdr->ex.response           = (ulong)response;
  hdr->ex.cmd_hdr_reserved   = 0U;
  return 0;
}

static int
fd_uverbs_write_cmd( int          cmd_fd,
                     void const * req,
                     ulong        req_sz ) {
  ssize_t write_sz = write( cmd_fd, req, req_sz );
  if( FD_UNLIKELY( write_sz<0 ) ) return -1;
  if( FD_UNLIKELY( (ulong)write_sz!=req_sz ) ) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

static int
fd_uverbs_get_context( fd_uverbs_ctx_t * ctx,
                       fd_mlx5_caps_t *  caps ) {
  fd_uverbs_get_context_req_t req [1];
  fd_uverbs_get_context_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );

  req->response                    = (ulong)resp;
  req->mlx5.total_num_bfregs       = 16U;
  req->mlx5.num_low_latency_bfregs = 4U;
  req->mlx5.max_cqe_version        = 1U;
  req->mlx5.lib_caps               = MLX5_LIB_CAP_4K_UAR | MLX5_LIB_CAP_DYN_UAR;
  if( FD_UNLIKELY( fd_uverbs_init_cmd_hdr( &req->hdr, IB_USER_VERBS_CMD_GET_CONTEXT,
                                           sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_uverbs_write_cmd( ctx->cmd_fd, req, sizeof(req) ) ) ) return -1;
  if( FD_UNLIKELY( resp->async_fd>(uint)INT_MAX ) ) {
    errno = EPROTO;
    return -1;
  }

  ctx->async_fd = (int)resp->async_fd;
  int fd_flags = fcntl( ctx->async_fd, F_GETFD );
  if( FD_UNLIKELY( fd_flags<0 || fcntl( ctx->async_fd, F_SETFD, fd_flags | FD_CLOEXEC ) ) ) return -1;

  ulong const uar_resp_sz = offsetof( struct mlx5_ib_alloc_ucontext_resp, num_uars_per_page )+
                            sizeof(resp->mlx5.num_uars_per_page);
  if( FD_UNLIKELY( resp->mlx5.response_length<uar_resp_sz                              ||
                   resp->mlx5.cqe_version>1U                                           ||
                   resp->mlx5.max_sq_desc_sz<sizeof(fd_mlx5_tx_wqe_t)                  ||
                   resp->mlx5.max_rq_desc_sz<sizeof(fd_mlx5_rx_wqe_t)                  ||
                   resp->mlx5.log_uar_size!=(uint)fd_ulong_find_lsb( FD_MLX5_PAGE_SZ ) ||
                   resp->mlx5.num_uars_per_page!=1U                                    ||
                   resp->mlx5.tot_bfregs ) ) {
    FD_LOG_WARNING(( "unsupported mlx5 context capabilities (response length %u, CQE version %u, "
                     "max SQ descriptor %u, max RQ descriptor %u, log UAR size %u, UARs per page %u, "
                     "legacy BF registers %u)",
                     resp->mlx5.response_length, (uint)resp->mlx5.cqe_version,
                     (uint)resp->mlx5.max_sq_desc_sz, (uint)resp->mlx5.max_rq_desc_sz,
                     resp->mlx5.log_uar_size, resp->mlx5.num_uars_per_page, resp->mlx5.tot_bfregs ));
    errno = EPROTONOSUPPORT;
    return -1;
  }

  caps->max_send_wqe = resp->mlx5.max_send_wqebb;
  caps->max_recv_wr  = resp->mlx5.max_recv_wr;
  switch( resp->mlx5.eth_min_inline ) {
  case MLX5_USER_INLINE_MODE_NONE: caps->eth_min_inline_hdr_sz = 0U;                        break;
  case MLX5_USER_INLINE_MODE_L2:   caps->eth_min_inline_hdr_sz = FD_MLX5_ETH_INLINE_HDR_SZ; break;
  default:
    FD_LOG_WARNING(( "unsupported mlx5 minimum inline mode %u", (uint)resp->mlx5.eth_min_inline ));
    errno = EPROTONOSUPPORT;
    return -1;
  }
  return 0;
}

static int
fd_uverbs_query_device( fd_uverbs_ctx_t * ctx,
                        fd_mlx5_caps_t *  caps ) {
  fd_uverbs_query_device_req_t       req [1];
  struct ib_uverbs_query_device_resp resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );

  req->response = (ulong)resp;
  if( FD_UNLIKELY( fd_uverbs_init_cmd_hdr( &req->hdr, IB_USER_VERBS_CMD_QUERY_DEVICE,
                                           sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_uverbs_write_cmd( ctx->cmd_fd, req, sizeof(req) ) ) ) return -1;

  caps->max_mr_size = resp->max_mr_size;
  caps->max_cqe     = resp->max_cqe;
  if( FD_UNLIKELY( !caps->max_mr_size || !resp->max_qp_wr || !resp->max_sge || !caps->max_cqe ||
                   resp->phys_port_cnt<ctx->port_num ) ) {
    FD_LOG_WARNING(( "unsupported mlx5 device capabilities (max MR size %lu, max QP WRs %u, max SGEs %u, "
                     "max CQEs %u, physical ports %u, requested port %u)",
                     caps->max_mr_size, resp->max_qp_wr, resp->max_sge, caps->max_cqe,
                     (uint)resp->phys_port_cnt, ctx->port_num ));
    errno = EPROTONOSUPPORT;
    return -1;
  }
  return 0;
}

static int
fd_uverbs_query_port( fd_uverbs_ctx_t * ctx ) {
  fd_uverbs_query_port_req_t       req [1];
  struct ib_uverbs_query_port_resp resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );

  req->response = (ulong)resp;
  req->port_num = (uchar)ctx->port_num;
  if( FD_UNLIKELY( fd_uverbs_init_cmd_hdr( &req->hdr, IB_USER_VERBS_CMD_QUERY_PORT,
                                           sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_uverbs_write_cmd( ctx->cmd_fd, req, sizeof(req) ) ) ) return -1;

  if( FD_UNLIKELY( resp->link_layer!=FD_MLX5_LINK_LAYER_ETHERNET ) ) {
    FD_LOG_WARNING(( "unsupported mlx5 link layer %u, expected Ethernet (%u)",
                     (uint)resp->link_layer, FD_MLX5_LINK_LAYER_ETHERNET ));
    errno = EPROTONOSUPPORT;
    return -1;
  }
  return 0;
}

int
fd_uverbs_open_cmd_fd( char const * rdma_name ) {
  char uverbs_name[ FD_UVERBS_NAME_MAX ];
  if( FD_UNLIKELY( fd_uverbs_resolve( uverbs_name, rdma_name ) ) ) return -1;

  char path[ FD_RDMA_PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/dev/infiniband/%s", uverbs_name ) );

  int cmd_fd = open( path, O_RDWR ); /* not close-on-exec */
  if( FD_UNLIKELY( cmd_fd<0 ) ) return -1;

  struct stat cmd_fd_stat;
  int err = 0;
  if( FD_UNLIKELY( fstat( cmd_fd, &cmd_fd_stat ) ) ) err = errno;
  else if( FD_UNLIKELY( !S_ISCHR( cmd_fd_stat.st_mode ) ) ) err = ENODEV;
  if( FD_UNLIKELY( err ) ) {
    close( cmd_fd );
    errno = err;
    return -1;
  }
  return cmd_fd;
}

fd_uverbs_ctx_t *
fd_uverbs_join( fd_uverbs_ctx_t * uverbs,
                int               cmd_fd,
                uint              port_num ) {
  if( FD_UNLIKELY( !uverbs || cmd_fd<0 || !port_num || port_num>(uint)UCHAR_MAX ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fcntl( cmd_fd, F_GETFD )<0 ) ) {
    errno = EBADF;
    return NULL;
  }
  fd_memset( uverbs, 0, sizeof(*uverbs) );
  uverbs->cmd_fd   = cmd_fd;
  uverbs->async_fd = -1;
  uverbs->port_num = port_num;
  return uverbs;
}

static fd_uverbs_ctx_t *
fd_uverbs_open_context( fd_uverbs_ctx_t * ctx,
                        fd_mlx5_caps_t *  caps,
                        char const *      rdma_name,
                        uint              port_num ) {
  fd_memset( caps, 0, sizeof(*caps) );

  int cmd_fd = fd_uverbs_open_cmd_fd( rdma_name );
  if( FD_UNLIKELY( cmd_fd<0 ) ) return NULL;

  if( FD_UNLIKELY( !fd_uverbs_join( ctx, cmd_fd, port_num ) ) ) {
    int err = errno;
    close( cmd_fd );
    errno = err;
    return NULL;
  }

  int cmd_fd_flags = fcntl( cmd_fd, F_GETFD );
  if( FD_UNLIKELY(
      cmd_fd_flags<0                                    ||
      fcntl( cmd_fd, F_SETFD, cmd_fd_flags|FD_CLOEXEC ) ||
      fd_uverbs_get_context( ctx, caps )                ||
      fd_uverbs_query_device( ctx, caps )               ||
      fd_uverbs_query_port( ctx ) ) ) {
    int err = errno;
    if( ctx->async_fd>=0 ) close( ctx->async_fd ); /* opened by get_context */
    close( cmd_fd );
    ctx->cmd_fd   = -1;
    ctx->async_fd = -1;
    errno = err;
    return NULL;
  }
  return ctx;
}

static fd_mlx5_pd_t *
fd_uverbs_alloc_pd( fd_mlx5_pd_t *      pd,
                    fd_uverbs_ctx_t *   ctx ) {
  if( FD_UNLIKELY( !pd ) ) {
    errno = EINVAL;
    return NULL;
  }
  fd_memset( pd, 0, sizeof(*pd) );
  if( FD_UNLIKELY( !ctx || ctx->cmd_fd<0 ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_uverbs_alloc_pd_req_t  req [1];
  fd_uverbs_alloc_pd_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );
  req->response = (ulong)resp;
  if( FD_UNLIKELY( fd_uverbs_init_cmd_hdr( &req->hdr, IB_USER_VERBS_CMD_ALLOC_PD,
                                           sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_uverbs_write_cmd( ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;

  pd->ctx    = ctx;
  pd->handle = resp->pd_handle;
  return pd;
}

static uint *
fd_uverbs_register_mr( uint *         lkey,
                       fd_mlx5_pd_t * pd,
                       void *         memory,
                       ulong          memory_sz,
                       ulong          max_mr_size ) {
  ulong memory_addr = (ulong)memory;
  if( FD_UNLIKELY( !memory || !memory_sz || memory_sz>ULONG_MAX-memory_addr ||
                   memory_sz>max_mr_size ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_uverbs_reg_mr_req_t  req [1];
  fd_uverbs_reg_mr_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );
  req->response     = (ulong)resp;
  req->start        = memory_addr;
  req->length       = memory_sz;
  req->hca_va       = memory_addr;
  req->pd_handle    = pd->handle;
  req->access_flags = IB_UVERBS_ACCESS_LOCAL_WRITE;
  if( FD_UNLIKELY( fd_uverbs_init_cmd_hdr( &req->hdr, IB_USER_VERBS_CMD_REG_MR,
                                           sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_uverbs_write_cmd( pd->ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;

  *lkey = resp->lkey;
  return lkey;
}

static void
fd_uverbs_init_ioctl_attr( struct ib_uverbs_attr * attr,
                           ushort                  attr_id,
                           ushort                  len,
                           ulong                   data ) {
  fd_memset( attr, 0, sizeof(*attr) );
  attr->attr_id = attr_id;
  attr->len     = len;
  attr->flags   = UVERBS_ATTR_F_MANDATORY;
  attr->data    = data;
}

static int
fd_uverbs_init_alloc_uar_req( fd_uverbs_alloc_uar_req_t * req,
                              ulong *                     mmap_offset,
                              uint *                      mmap_sz,
                              uint *                      page_id ) {
  if( FD_UNLIKELY( !req || !mmap_offset || !mmap_sz || !page_id ) ) return -1;
  fd_memset( req, 0, sizeof(*req) );
  req->hdr.length    = (ushort)sizeof(*req);
  req->hdr.object_id = MLX5_IB_OBJECT_UAR;
  req->hdr.method_id = MLX5_IB_METHOD_UAR_OBJ_ALLOC;
  req->hdr.num_attrs = 5U;
  req->hdr.driver_id = RDMA_DRIVER_MLX5;
  fd_uverbs_init_ioctl_attr( req->attrs+0, MLX5_IB_ATTR_UAR_OBJ_ALLOC_HANDLE,      0U, 0UL );
  fd_uverbs_init_ioctl_attr( req->attrs+1, MLX5_IB_ATTR_UAR_OBJ_ALLOC_TYPE,        8U, MLX5_IB_UAPI_UAR_ALLOC_TYPE_NC );
  fd_uverbs_init_ioctl_attr( req->attrs+2, MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_OFFSET, 8U, (ulong)mmap_offset );
  fd_uverbs_init_ioctl_attr( req->attrs+3, MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_LENGTH, 4U, (ulong)mmap_sz );
  fd_uverbs_init_ioctl_attr( req->attrs+4, MLX5_IB_ATTR_UAR_OBJ_ALLOC_PAGE_ID,     4U, (ulong)page_id );
  return 0;
}

static int
fd_uverbs_init_destroy_uar_req( fd_uverbs_destroy_uar_req_t * req,
                                uint                          handle ) {
  if( FD_UNLIKELY( !req ) ) return -1;
  fd_memset( req, 0, sizeof(*req) );
  req->hdr.length    = (ushort)sizeof(*req);
  req->hdr.object_id = MLX5_IB_OBJECT_UAR;
  req->hdr.method_id = MLX5_IB_METHOD_UAR_OBJ_DESTROY;
  req->hdr.num_attrs = 1U;
  req->hdr.driver_id = RDMA_DRIVER_MLX5;
  fd_uverbs_init_ioctl_attr( req->attrs, MLX5_IB_ATTR_UAR_OBJ_DESTROY_HANDLE, 0U, handle );
  return 0;
}

static int
fd_uverbs_destroy_uar( fd_uverbs_ctx_t * ctx,
                       uint              handle ) {
  fd_uverbs_destroy_uar_req_t req[1];
  if( FD_UNLIKELY( fd_uverbs_init_destroy_uar_req( req, handle ) ) ) {
    errno = EINVAL;
    return -1;
  }
  return ioctl( ctx->cmd_fd, RDMA_VERBS_IOCTL, &req->hdr );
}

static volatile uchar *
fd_uverbs_map_uar( fd_uverbs_ctx_t * ctx,
                   uint *            page_id ) {
  if( FD_UNLIKELY( !page_id ) ) {
    errno = EINVAL;
    return NULL;
  }
  *page_id = 0U;
  if( FD_UNLIKELY( !ctx || ctx->cmd_fd<0 ) ) {
    errno = EINVAL;
    return NULL;
  }
  ulong mmap_offset = 0UL;
  uint  mmap_sz     = 0U;
  uint  uar_page_id = 0U;
  fd_uverbs_alloc_uar_req_t req[1];
  if( FD_UNLIKELY( fd_uverbs_init_alloc_uar_req( req, &mmap_offset, &mmap_sz, &uar_page_id ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( ioctl( ctx->cmd_fd, RDMA_VERBS_IOCTL, &req->hdr ) ) ) return NULL;

  ulong handle_raw = req->attrs[0].data;
  if( FD_UNLIKELY( handle_raw>UINT_MAX || mmap_sz!=FD_MLX5_PAGE_SZ ||
                   (mmap_offset & (FD_MLX5_PAGE_SZ-1UL)) || mmap_offset>(ulong)LONG_MAX ) ) {
    FD_LOG_WARNING(( "invalid mlx5 UAR response (handle %lu, mapping size %u, mapping offset %#lx)",
                     handle_raw, mmap_sz, mmap_offset ));
    int err = EPROTO;
    if( handle_raw<=UINT_MAX ) fd_uverbs_destroy_uar( ctx, (uint)handle_raw );
    errno = err;
    return NULL;
  }

  void * uar_mapping = mmap( NULL, (ulong)mmap_sz, PROT_WRITE, MAP_SHARED, ctx->cmd_fd, (off_t)mmap_offset );
  if( FD_UNLIKELY( uar_mapping==MAP_FAILED ) ) {
    int err = errno;
    fd_uverbs_destroy_uar( ctx, (uint)handle_raw );
    errno = err;
    return NULL;
  }

  *page_id = uar_page_id;
  return (volatile uchar *)uar_mapping + FD_MLX5_UAR_DB_OFFSET;
}

static uint *
fd_uverbs_create_cq( uint *               handle,
                     fd_uverbs_ctx_t *    ctx,
                     fd_mlx5_cq_t const * cq,
                     uint                 page_id,
                     uint                 max_cqe ) {
  if( FD_UNLIKELY( !handle ) ) {
    errno = EINVAL;
    return NULL;
  }
  *handle = 0U;
  if( FD_UNLIKELY( !ctx || ctx->cmd_fd<0 || !cq || !cq->entries || !cq->control ||
                   !fd_uint_is_pow2( cq->depth ) || cq->depth-1U>max_cqe || page_id>(uint)USHRT_MAX ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_uverbs_create_cq_req_t  req [1];
  fd_uverbs_create_cq_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );

  req->response                = (ulong)resp;
  req->user_handle             = (ulong)cq;
  req->cqe                     = cq->depth-1U;
  req->comp_channel            = -1;
  req->mlx5.fields.buf_addr    = (ulong)cq->entries;
  req->mlx5.fields.db_addr     = (ulong)cq->control;
  req->mlx5.fields.cqe_size    = sizeof(fd_mlx5_cqe_t);
  req->mlx5.fields.flags       = MLX5_IB_CREATE_CQ_FLAGS_UAR_PAGE_INDEX;
  req->mlx5.uar.uar_page_index = (ushort)page_id;
  if( FD_UNLIKELY( fd_uverbs_init_cmd_hdr( &req->hdr, IB_USER_VERBS_CMD_CREATE_CQ,
                                           sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_uverbs_write_cmd( ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;
  if( FD_UNLIKELY( resp->cqe!=cq->depth-1U ) ) {
    fd_uverbs_destroy_cq_req_t       destroy[1];
    struct ib_uverbs_destroy_cq_resp destroy_resp[1];
    fd_memset( destroy,      0, sizeof(destroy)      );
    fd_memset( destroy_resp, 0, sizeof(destroy_resp) );

    destroy->response  = (ulong)destroy_resp;
    destroy->cq_handle = resp->cq_handle;
    if( !fd_uverbs_init_cmd_hdr( &destroy->hdr, IB_USER_VERBS_CMD_DESTROY_CQ,
                                 sizeof(destroy), sizeof(destroy_resp) ) ) {
      fd_uverbs_write_cmd( ctx->cmd_fd, destroy, sizeof(destroy) );
    }
    FD_LOG_WARNING(( "invalid mlx5 CQ response (CQEs %u, requested %u)", resp->cqe, cq->depth-1U ));
    errno = EPROTO;
    return NULL;
  }

  *handle = resp->cq_handle;
  return handle;
}

static int
fd_uverbs_modify_qp( fd_uverbs_ctx_t * uverbs,
                     fd_mlx5_qp_t *    qp,
                     uint              state ) {
  fd_uverbs_modify_qp_req_t req[1];
  fd_memset( req, 0, sizeof(req) );
  req->core.qp_handle = qp->handle;
  req->core.attr_mask = FD_MLX5_QP_ATTR_STATE;
  req->core.qp_state  = (uchar)state;
  if( state==FD_MLX5_QPS_INIT ) {
    req->core.attr_mask |= FD_MLX5_QP_ATTR_PORT;
    req->core.port_num   = (uchar)uverbs->port_num;
  }
  if( FD_UNLIKELY( fd_uverbs_init_cmd_hdr( &req->hdr, IB_USER_VERBS_CMD_MODIFY_QP,
                                           sizeof(req), 0UL ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_uverbs_write_cmd( uverbs->cmd_fd, req, sizeof(req) ) ) ) return -1;
  return 0;
}

static fd_mlx5_qp_t *
fd_uverbs_create_qp( fd_uverbs_ctx_t * uverbs,
                     fd_mlx5_qp_t *    qp,
                     fd_mlx5_pd_t *    pd,
                     uint              rx_cq_handle,
                     uint              tx_cq_handle,
                     uint              uar_page_id,
                     int               send_only ) {
  if( FD_UNLIKELY( !uverbs || !qp || !qp->tx_cq || !qp->sq ||
                   !qp->control || !pd || pd->ctx!=uverbs ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( !send_only && (!qp->rx_cq || !qp->rq) ) ) {
    errno = EINVAL;
    return NULL;
  }
  uint const rq_depth = send_only ? 0U : qp->rx_depth;

  fd_uverbs_create_qp_req_t  req [1];
  fd_uverbs_create_qp_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );

  req->response          = (ulong)resp;
  req->user_handle       = (ulong)qp;
  req->pd_handle         = pd->handle;
  req->send_cq_handle    = tx_cq_handle;
  req->recv_cq_handle    = rx_cq_handle;
  req->max_send_wr       = qp->tx_depth;
  req->max_recv_wr       = rq_depth;
  req->max_send_sge      = 1U;
  req->max_recv_sge      = send_only ? 0U : 1U;
  req->qp_type           = IB_UVERBS_QPT_RAW_PACKET;
  req->mlx5.buf_addr     = send_only ? (ulong)qp->sq : (ulong)qp->rq;
  req->mlx5.db_addr      = (ulong)qp->control;
  req->mlx5.sq_wqe_count = qp->tx_depth;
  req->mlx5.rq_wqe_count = rq_depth;
  req->mlx5.rq_wqe_shift = (uint)fd_ulong_find_lsb( sizeof(fd_mlx5_rx_wqe_t) );
  req->mlx5.flags        = MLX5_QP_FLAG_UAR_PAGE_INDEX;
  req->mlx5.uidx         = 0U;
  req->mlx5.bfreg_index  = uar_page_id;
  req->mlx5.sq_buf_addr  = (ulong)qp->sq;
  if( FD_UNLIKELY( fd_uverbs_init_cmd_hdr( &req->hdr, IB_USER_VERBS_CMD_CREATE_QP,
                                           sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_uverbs_write_cmd( uverbs->cmd_fd, req, sizeof(req) ) ) ) return NULL;

  if( FD_UNLIKELY( resp->core.max_send_wr <qp->tx_depth        ||
                   resp->core.max_recv_wr <rq_depth            ||
                   resp->core.max_send_sge<1U                  ||
                   resp->core.max_recv_sge<(send_only ? 0U:1U) ||
                   resp->core.qpn>0xffffffU ) ) {
    FD_LOG_WARNING(( "invalid mlx5 QP response (max send WRs %u, max receive WRs %u, max send SGEs %u, "
                     "max receive SGEs %u, QPN %u)",
                     resp->core.max_send_wr, resp->core.max_recv_wr, resp->core.max_send_sge,
                     resp->core.max_recv_sge, resp->core.qpn ));
    errno = EPROTO;
    return NULL;
  }

  qp->handle       = resp->core.qp_handle;
  qp->qpn          = resp->core.qpn;
  return qp;
}

static fd_mlx5_qp_t *
fd_uverbs_start_qp( fd_uverbs_ctx_t * uverbs,
                    fd_mlx5_qp_t *    qp ) {
  if( FD_UNLIKELY( fd_uverbs_modify_qp( uverbs, qp, FD_MLX5_QPS_INIT ) ||
                   fd_uverbs_modify_qp( uverbs, qp, FD_MLX5_QPS_RTR  ) ||
                   fd_uverbs_modify_qp( uverbs, qp, FD_MLX5_QPS_RTS  ) ) ) return NULL;
  return qp;
}

static int
fd_uverbs_create_wq( fd_uverbs_ctx_t *    uverbs,
                     uint                 pd_handle,
                     uint                 rx_cq_handle,
                     fd_mlx5_qp_t const * qp,
                     uint *               wq_handle ) {
  fd_uverbs_create_wq_req_t  req [1];
  fd_uverbs_create_wq_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );

  ulong const core_req_sz = offsetof( fd_uverbs_create_wq_req_t, mlx5 );
  if( FD_UNLIKELY( fd_uverbs_init_ex_hdr(
      &req->hdr, IB_USER_VERBS_EX_CMD_CREATE_WQ,
      core_req_sz, sizeof(*req), resp,
      sizeof(resp->core), sizeof(*resp) ) ) ) {
    errno = EINVAL;
    return -1;
  }
  req->core.user_handle  = (ulong)qp;
  req->core.pd_handle    = pd_handle;
  req->core.cq_handle    = rx_cq_handle;
  req->core.wq_type      = IB_UVERBS_WQT_RQ;
  req->core.max_wr       = qp->rx_depth;
  req->core.max_sge      = 1U;
  req->mlx5.buf_addr     = (ulong)qp->rq;
  req->mlx5.db_addr      = (ulong)qp->control;
  req->mlx5.rq_wqe_count = qp->rx_depth;
  req->mlx5.rq_wqe_shift = (uint)fd_ulong_find_lsb( sizeof(fd_mlx5_rx_wqe_t) );
  if( FD_UNLIKELY( fd_uverbs_write_cmd( uverbs->cmd_fd, req, sizeof(req) ) ) ) return -1;

  if( FD_UNLIKELY( resp->core.max_wr<qp->rx_depth || resp->core.max_sge<1U ) ) {
    FD_LOG_WARNING(( "invalid mlx5 WQ response (max WRs %u, requested %u, max SGEs %u)",
                     resp->core.max_wr, qp->rx_depth, resp->core.max_sge ));
    errno = EPROTO;
    return -1;
  }

  *wq_handle = resp->core.wq_handle;
  return 0;
}

static int
fd_uverbs_start_wq( fd_uverbs_ctx_t * uverbs,
                    uint              wq_handle ) {
  fd_uverbs_modify_wq_req_t req[1];
  fd_memset( req, 0, sizeof(req) );

  ulong const core_req_sz = offsetof( fd_uverbs_modify_wq_req_t, mlx5 );
  if( FD_UNLIKELY( fd_uverbs_init_ex_hdr( &req->hdr, IB_USER_VERBS_EX_CMD_MODIFY_WQ,
                                          core_req_sz, sizeof(*req), NULL, 0UL, 0UL ) ) ) {
    errno = EINVAL;
    return -1;
  }
  req->core.attr_mask = FD_MLX5_WQ_ATTR_STATE;
  req->core.wq_handle = wq_handle;
  req->core.wq_state  = FD_MLX5_WQS_RDY;
  return fd_uverbs_write_cmd( uverbs->cmd_fd, req, sizeof(req) );
}

int
fd_uverbs_create_rqt( fd_uverbs_ctx_t * uverbs,
                      uint const *      wq_handle,
                      uint              wq_cnt,
                      uint *            rqt_handle ) {
  if( FD_UNLIKELY( !uverbs || uverbs->cmd_fd<0 || !wq_handle || !wq_cnt ||
                   wq_cnt>FD_MLX5_RQT_SZ || !rqt_handle ) ) {
    errno = EINVAL;
    return -1;
  }

  fd_uverbs_create_rqt_req_t  req [1];
  fd_uverbs_create_rqt_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );

  if( FD_UNLIKELY( fd_uverbs_init_ex_hdr( &req->hdr, IB_USER_VERBS_EX_CMD_CREATE_RWQ_IND_TBL,
                                          sizeof(*req), sizeof(*req), resp,
                                          sizeof(resp->core), sizeof(*resp) ) ) ) {
    errno = EINVAL;
    return -1;
  }
  req->log_ind_tbl_size = FD_MLX5_RQT_LG_SZ;
  for( ulong i=0UL; i<FD_MLX5_RQT_SZ; i++ ) req->wq_handle[ i ] = wq_handle[ i%wq_cnt ];
  if( FD_UNLIKELY( fd_uverbs_write_cmd( uverbs->cmd_fd, req, sizeof(req) ) ) ) return -1;

  *rqt_handle = resp->core.ind_tbl_handle;
  return 0;
}

int
fd_uverbs_create_rss_qp( fd_uverbs_ctx_t * uverbs,
                         uint              pd_handle,
                         uint              rqt_handle,
                         int               inner,
                         uint *            qp_handle,
                         uint *            qpn ) {
  if( FD_UNLIKELY( !uverbs || uverbs->cmd_fd<0 || !qp_handle || !qpn ) ) {
    errno = EINVAL;
    return -1;
  }

  fd_uverbs_create_rss_qp_req_t  req [1];
  fd_uverbs_create_rss_qp_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );

  ulong const core_req_sz = offsetof( fd_uverbs_create_rss_qp_req_t, mlx5 );
  if( FD_UNLIKELY( fd_uverbs_init_ex_hdr( &req->hdr, IB_USER_VERBS_EX_CMD_CREATE_QP,
                                          core_req_sz, sizeof(*req), resp,
                                          sizeof(resp->core), sizeof(*resp) ) ) ) {
    errno = EINVAL;
    return -1;
  }

  /* An RSS QP carries neither a send nor a receive queue of its own.  It
     exists to name the indirection table in a flow rule, so every queue
     size stays zero and Linux skips the completion queue lookups. */
  req->core.pd_handle          = pd_handle;
  req->core.qp_type            = IB_UVERBS_QPT_RAW_PACKET;
  req->core.comp_mask          = IB_UVERBS_CREATE_QP_MASK_IND_TABLE;
  req->core.rwq_ind_tbl_handle = rqt_handle;

  req->mlx5.rx_hash_function   = MLX5_RX_HASH_FUNC_TOEPLITZ;
  req->mlx5.rx_key_len         = (uchar)FD_MLX5_RSS_KEY_SZ;
  fd_memcpy( req->mlx5.rx_hash_key, fd_mlx5_rss_key, FD_MLX5_RSS_KEY_SZ );
  req->mlx5.rx_hash_fields_mask = FD_MLX5_RSS_HASH_FIELDS;
  if( inner ) {
    req->mlx5.rx_hash_fields_mask |= MLX5_RX_HASH_INNER;
    req->mlx5.flags                = MLX5_QP_FLAG_TUNNEL_OFFLOADS;
  }
  if( FD_UNLIKELY( fd_uverbs_write_cmd( uverbs->cmd_fd, req, sizeof(req) ) ) ) return -1;

  if( FD_UNLIKELY( resp->core.base.qpn>0xffffffU ) ) {
    FD_LOG_WARNING(( "invalid mlx5 RSS QP response (QPN %u)", resp->core.base.qpn ));
    errno = EPROTO;
    return -1;
  }

  *qp_handle = resp->core.base.qp_handle;
  *qpn       = resp->core.base.qpn;
  return 0;
}

static int
fd_uverbs_init_udp_flow_req( fd_uverbs_create_udp_flow_req_t *   req,
                             struct ib_uverbs_create_flow_resp * resp,
                             uint                                qp_handle,
                             uint                                port_num,
                             uint                                dst_ip,
                             ushort                              dst_port ) {
  if( FD_UNLIKELY( !req || !resp || !port_num || port_num>UCHAR_MAX || !dst_port ) ) return -1;

  fd_memset( req,  0, sizeof(*req ) );
  fd_memset( resp, 0, sizeof(*resp) );
  ulong const core_req_sz = offsetof( fd_uverbs_create_udp_flow_req_t, mlx5_ncounters_data );
  if( FD_UNLIKELY( fd_uverbs_init_ex_hdr( &req->hdr, IB_USER_VERBS_EX_CMD_CREATE_FLOW,
                                          core_req_sz, sizeof(*req), resp,
                                          sizeof(*resp), sizeof(*resp) ) ) ) return -1;

  req->qp_handle           = qp_handle;
  req->size                = sizeof(req->eth)+sizeof(req->ipv4)+sizeof(req->udp);
  req->num_of_specs        = 3U;
  req->port                = (uchar)port_num;
  req->eth.type            = FD_MLX5_FLOW_SPEC_ETH;
  req->eth.size            = sizeof(req->eth);
  req->eth.val.ether_type  = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP );
  req->eth.mask.ether_type = USHORT_MAX;
  req->ipv4.type           = FD_MLX5_FLOW_SPEC_IPV4;
  req->ipv4.size           = sizeof(req->ipv4);
  req->ipv4.val.dst_ip     = dst_ip;
  req->ipv4.mask.dst_ip    = dst_ip ? UINT_MAX : 0U;
  req->udp.type            = FD_MLX5_FLOW_SPEC_UDP;
  req->udp.size            = sizeof(req->udp);
  req->udp.val.dst_port    = fd_ushort_bswap( dst_port );
  req->udp.mask.dst_port   = USHORT_MAX;
  return 0;
}

int
fd_uverbs_create_udp_flow( fd_uverbs_ctx_t * uverbs,
                           uint              qp_handle,
                           uint              dst_ip,
                           ushort            dst_port ) {
  if( FD_UNLIKELY( !uverbs || uverbs->cmd_fd<0 || !dst_port ) ) {
    errno = EINVAL;
    return -1;
  }

  fd_uverbs_create_udp_flow_req_t   req [1];
  struct ib_uverbs_create_flow_resp resp[1];
  if( FD_UNLIKELY( fd_uverbs_init_udp_flow_req(
        req, resp, qp_handle,
        uverbs->port_num, dst_ip,
        dst_port ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_uverbs_write_cmd( uverbs->cmd_fd, req, sizeof(req) ) ) ) return -1;
  return 0;
}

static int
fd_uverbs_init_gre_flow_req( fd_uverbs_create_gre_flow_req_t *   req,
                             struct ib_uverbs_create_flow_resp * resp,
                             uint                                qp_handle,
                             uint                                port_num,
                             uint                                inner_dst_ip,
                             ushort                              inner_dst_port ) {
  if( FD_UNLIKELY( !req || !resp || !port_num || port_num>UCHAR_MAX || !inner_dst_port ) ) return -1;

  fd_memset( req,  0, sizeof(*req ) );
  fd_memset( resp, 0, sizeof(*resp) );
  ulong const core_req_sz = offsetof( fd_uverbs_create_gre_flow_req_t, mlx5_ncounters_data );
  if( FD_UNLIKELY( fd_uverbs_init_ex_hdr( &req->hdr, IB_USER_VERBS_EX_CMD_CREATE_FLOW,
                                          core_req_sz, sizeof(*req), resp,
                                          sizeof(*resp), sizeof(*resp) ) ) ) return -1;

  req->qp_handle    = qp_handle;
  req->size         = sizeof(req->eth)+sizeof(req->outer_ipv4)+sizeof(req->gre)+
                      sizeof(req->inner_ipv4)+sizeof(req->inner_udp);
  req->num_of_specs = 5U;
  req->port         = (uchar)port_num;
  req->eth = (struct ib_uverbs_flow_spec_eth) {
    .type = FD_MLX5_FLOW_SPEC_ETH,
    .size = sizeof(req->eth),
    .val  = { .ether_type = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) },
    .mask = { .ether_type = USHORT_MAX },
  };
  req->outer_ipv4 = (struct ib_uverbs_flow_spec_ipv4) {
    .type = FD_MLX5_FLOW_SPEC_IPV4,
    .size = sizeof(req->outer_ipv4),
    .val  = { .proto = FD_IP4_HDR_PROTOCOL_GRE },
    .mask = { .proto = UCHAR_MAX },
  };
  req->gre = (struct ib_uverbs_flow_spec_gre) {
    .type = FD_MLX5_FLOW_SPEC_GRE,
    .size = sizeof(req->gre),
    .val  = { .protocol = fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) },
    .mask = { .protocol = USHORT_MAX },
  };
  req->inner_ipv4 = (struct ib_uverbs_flow_spec_ipv4) {
    .type = FD_MLX5_FLOW_SPEC_INNER | FD_MLX5_FLOW_SPEC_IPV4,
    .size = sizeof(req->inner_ipv4),
    .val  = { .dst_ip = inner_dst_ip, .proto = FD_IP4_HDR_PROTOCOL_UDP },
    .mask = { .dst_ip = inner_dst_ip ? UINT_MAX : 0U, .proto = UCHAR_MAX },
  };
  req->inner_udp = (struct ib_uverbs_flow_spec_tcp_udp) {
    .type = FD_MLX5_FLOW_SPEC_INNER | FD_MLX5_FLOW_SPEC_UDP,
    .size = sizeof(req->inner_udp),
    .val  = { .dst_port = fd_ushort_bswap( inner_dst_port ) },
    .mask = { .dst_port = USHORT_MAX },
  };
  return 0;
}

int
fd_uverbs_create_gre_udp_flow( fd_uverbs_ctx_t * uverbs,
                               uint              qp_handle,
                               uint              inner_dst_ip,
                               ushort            inner_dst_port ) {
  if( FD_UNLIKELY( !uverbs || uverbs->cmd_fd<0 || !inner_dst_port ) ) {
    errno = EINVAL;
    return -1;
  }

  fd_uverbs_create_gre_flow_req_t   req [1];
  struct ib_uverbs_create_flow_resp resp[1];
  if( FD_UNLIKELY( fd_uverbs_init_gre_flow_req(
        req, resp, qp_handle,
        uverbs->port_num, inner_dst_ip,
        inner_dst_port ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_uverbs_write_cmd( uverbs->cmd_fd, req, sizeof(req) ) ) ) return -1;
  return 0;
}

fd_mlx5_qp_t *
fd_uverbs_init( fd_uverbs_ctx_t * uverbs,
                fd_mlx5_cq_t *    rx_cq,
                fd_mlx5_cq_t *    tx_cq,
                fd_mlx5_qp_t *    qp,
                char const *      rdma_name,
                uint              port_num,
                void *            packet_memory,
                ulong             packet_memory_sz ) {
  if( FD_UNLIKELY( !uverbs || !rx_cq || !tx_cq || !qp ||
                   qp->rx_cq!=rx_cq || qp->tx_cq!=tx_cq ||
                   qp->rx_depth!=rx_cq->depth || qp->tx_depth!=tx_cq->depth ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_mlx5_caps_t caps[1];
  fd_mlx5_pd_t   pd[1];
  uint           uar_page_id;
  uint           rx_cq_handle;
  uint           tx_cq_handle;
  if( FD_UNLIKELY( !fd_uverbs_open_context( uverbs, caps, rdma_name, port_num ) ) ) return NULL;
  if( FD_UNLIKELY( !fd_uint_is_pow2( qp->rx_depth ) || !fd_uint_is_pow2( qp->tx_depth ) ||
                   qp->rx_depth>caps->max_recv_wr || qp->tx_depth>caps->max_send_wqe ||
                   qp->rx_depth-1U>caps->max_cqe || qp->tx_depth-1U>caps->max_cqe ) ) {
    errno = EINVAL;
    return NULL;
  }

  qp->sq_doorbell = fd_uverbs_map_uar( uverbs, &uar_page_id );
  if( FD_UNLIKELY( !qp->sq_doorbell ||
                   !fd_uverbs_create_cq( &rx_cq_handle, uverbs, rx_cq, uar_page_id, caps->max_cqe ) ||
                   !fd_uverbs_create_cq( &tx_cq_handle, uverbs, tx_cq, uar_page_id, caps->max_cqe ) ||
                   !fd_uverbs_alloc_pd( pd, uverbs ) ||
                   !fd_uverbs_register_mr( &qp->lkey, pd, packet_memory, packet_memory_sz, caps->max_mr_size ) ||
                   !fd_uverbs_create_qp( uverbs, qp, pd, rx_cq_handle, tx_cq_handle, uar_page_id, 0 ) ||
                   !fd_uverbs_start_qp( uverbs, qp ) ) ) return NULL;
  qp->tx_inline_hdr_sz = caps->eth_min_inline_hdr_sz;
  return qp;
}

int
fd_uverbs_open_shared( fd_uverbs_ctx_t * uverbs,
                       fd_mlx5_caps_t *  caps,
                       uint *            pd_handle ) {
  if( FD_UNLIKELY( !uverbs || uverbs->cmd_fd<0 || !caps || !pd_handle ) ) {
    errno = EINVAL;
    return -1;
  }
  fd_memset( caps, 0, sizeof(*caps) );

  if( FD_UNLIKELY(
      fd_uverbs_get_context( uverbs, caps )  ||
      fd_uverbs_query_device( uverbs, caps ) ||
      fd_uverbs_query_port( uverbs ) ) ) return -1;

  fd_mlx5_pd_t pd[1];
  if( FD_UNLIKELY( !fd_uverbs_alloc_pd( pd, uverbs ) ) ) return -1;
  *pd_handle = pd->handle;
  return 0;
}

int
fd_uverbs_init_rss_tile( fd_uverbs_ctx_t *      uverbs,
                         fd_mlx5_caps_t const * caps,
                         uint                   pd_handle,
                         fd_mlx5_qp_t *         qp,
                         void *                 packet_memory,
                         ulong                  packet_memory_sz,
                         uint *                 wq_handle ) {
  if( FD_UNLIKELY(
      !uverbs || !caps || !qp || !wq_handle ||
      !qp->rx_cq || !qp->tx_cq ||
      uverbs->cmd_fd<0 ||
      qp->rx_depth!=qp->rx_cq->depth ||
      qp->tx_depth!=qp->tx_cq->depth ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY(
      !fd_uint_is_pow2( qp->rx_depth ) ||
      !fd_uint_is_pow2( qp->tx_depth ) ||
      qp->rx_depth    > caps->max_recv_wr  ||
      qp->tx_depth    > caps->max_send_wqe ||
      qp->rx_depth-1U > caps->max_cqe      ||
      qp->tx_depth-1U > caps->max_cqe
  ) ) {
    errno = EINVAL;
    return -1;
  }

  fd_mlx5_pd_t pd[1] = {{ .ctx = uverbs, .handle = pd_handle }};

  uint uar_page_id;
  uint rx_cq_handle;
  uint tx_cq_handle;
  qp->sq_doorbell = fd_uverbs_map_uar( uverbs, &uar_page_id );
  if( FD_UNLIKELY(
      !qp->sq_doorbell ||
      !fd_uverbs_create_cq( &rx_cq_handle, uverbs, qp->rx_cq, uar_page_id, caps->max_cqe ) ||
      !fd_uverbs_create_cq( &tx_cq_handle, uverbs, qp->tx_cq, uar_page_id, caps->max_cqe ) ||
      !fd_uverbs_register_mr( &qp->lkey, pd, packet_memory, packet_memory_sz, caps->max_mr_size ) ) ) {
    return -1;
  }

  if( FD_UNLIKELY(
      fd_uverbs_create_wq( uverbs, pd_handle, rx_cq_handle, qp, wq_handle ) ||
      fd_uverbs_start_wq( uverbs, *wq_handle ) ) ) {
    return -1;
  }

  if( FD_UNLIKELY(
      !fd_uverbs_create_qp( uverbs, qp, pd, tx_cq_handle, tx_cq_handle, uar_page_id, 1 ) ||
      !fd_uverbs_start_qp( uverbs, qp ) ) ) {
    return -1;
  }

  qp->tx_inline_hdr_sz = caps->eth_min_inline_hdr_sz;
  return 0;
}

#define FD_MLX5_NL_RECV_BUF_SZ (8192UL)

struct fd_mlx5_nl_req {
  struct nlmsghdr nlh;
  uchar           attrs[ 5UL*(sizeof(struct nlattr)+sizeof(uint)) ];
};
typedef struct fd_mlx5_nl_req fd_mlx5_nl_req_t;

typedef int (*fd_mlx5_nl_parse_fn_t)( struct nlmsghdr const * nlh,
                                      void *                  parse_arg );

static void
fd_mlx5_nl_req_init( fd_mlx5_nl_req_t * req,
                     uint               type,
                     uint               flags,
                     uint               request_seq ) {
  fd_memset( req, 0, sizeof(*req) );
  req->nlh.nlmsg_len   = sizeof(struct nlmsghdr);
  req->nlh.nlmsg_type  = (ushort)type;
  req->nlh.nlmsg_flags = (ushort)flags;
  req->nlh.nlmsg_seq   = request_seq;
}

static int
fd_mlx5_nl_req_u32( fd_mlx5_nl_req_t * req,
                    ushort             type,
                    uint               value ) {
  ulong const attr_sz = sizeof(struct nlattr)+sizeof(uint);
  if( FD_UNLIKELY( (ulong)req->nlh.nlmsg_len+attr_sz>sizeof(*req) ) ) {
    errno = ENOSPC;
    return -1;
  }
  struct nlattr * attr = (struct nlattr *)((uchar *)req+req->nlh.nlmsg_len);
  attr->nla_len  = (ushort)attr_sz;
  attr->nla_type = type;
  fd_memcpy( (uchar *)(attr+1), &value, sizeof(value) );
  req->nlh.nlmsg_len += (uint)attr_sz;
  return 0;
}

static int
fd_mlx5_nla_next( uchar const **         attr_cur,
                  ulong *                attr_rem,
                  struct nlattr const ** attr ) {
  if( FD_UNLIKELY( !*attr_rem ) ) return 0;
  if( FD_UNLIKELY( *attr_rem<sizeof(struct nlattr) ) ) {
    errno = EPROTO;
    return -1;
  }

  struct nlattr const * next_attr       = (struct nlattr const *)*attr_cur;
  ulong const           attr_sz         = next_attr->nla_len;
  ulong const           aligned_attr_sz = fd_ulong_align_up( attr_sz, NLA_ALIGNTO );
  if( FD_UNLIKELY( attr_sz<sizeof(*next_attr) || aligned_attr_sz>*attr_rem ) ) {
    errno = EPROTO;
    return -1;
  }

  *attr      = next_attr;
  *attr_cur += aligned_attr_sz;
  *attr_rem -= aligned_attr_sz;
  return 1;
}

static int
fd_mlx5_nla_find( void const *           attr_data,
                  ulong                  attr_data_sz,
                  ushort                 type,
                  struct nlattr const ** result_attr ) {
  *result_attr = NULL;
  uchar const * attr_cur = attr_data;
  while( attr_data_sz ) {
    struct nlattr const * attr;
    int next_result = fd_mlx5_nla_next( &attr_cur, &attr_data_sz, &attr );
    if( FD_UNLIKELY( next_result<0 ) ) return -1;
    if( (attr->nla_type & (ushort)NLA_TYPE_MASK)==type ) {
      *result_attr = attr;
      return 1;
    }
  }
  return 0;
}

static int
fd_mlx5_nla_u32( struct nlattr const * attr,
                 uint *                value ) {
  if( FD_UNLIKELY( attr->nla_len!=sizeof(*attr)+sizeof(uint) ) ) {
    errno = EPROTO;
    return -1;
  }
  fd_memcpy( value, attr+1, sizeof(*value) );
  return 0;
}

static int
fd_mlx5_nl_send( int                      netlink_fd,
                 fd_mlx5_nl_req_t const * req ) {
  struct sockaddr_nl kernel_addr = { .nl_family=AF_NETLINK };
  ssize_t send_sz = sendto( netlink_fd, req, req->nlh.nlmsg_len, 0,
                            fd_type_pun_const( &kernel_addr ), sizeof(kernel_addr) );
  if( FD_UNLIKELY( send_sz!=(ssize_t)req->nlh.nlmsg_len ) ) {
    if( send_sz>=0 ) errno = EIO;
    return -1;
  }
  return 0;
}

static int
fd_mlx5_nl_recv( int                   netlink_fd,
                 uint                  request_seq,
                 int                   multipart,
                 fd_mlx5_nl_parse_fn_t parse_fn,
                 void *                parse_arg ) {
  uchar msg_buf[ FD_MLX5_NL_RECV_BUF_SZ ] __attribute__((aligned(alignof(struct nlmsghdr))));
  for(;;) {
    ssize_t recv_sz;
    do recv_sz = recvfrom( netlink_fd, msg_buf, sizeof(msg_buf), MSG_TRUNC, NULL, NULL );
    while( FD_UNLIKELY( recv_sz<0 && errno==EINTR ) );
    if( FD_UNLIKELY( recv_sz<=0 || (ulong)recv_sz>sizeof(msg_buf) ) ) {
      if( !recv_sz ) errno = EPROTO;
      else if( recv_sz>0 ) errno = EMSGSIZE;
      return -1;
    }

    uchar const * msg_cur = msg_buf;
    ulong msg_rem = (ulong)recv_sz;
    while( msg_rem ) {
      if( FD_UNLIKELY( msg_rem<sizeof(struct nlmsghdr) ) ) {
        errno = EPROTO;
        return -1;
      }
      struct nlmsghdr const * nlh = (struct nlmsghdr const *)msg_cur;
      ulong const msg_sz          = nlh->nlmsg_len;
      ulong const aligned_msg_sz  = fd_ulong_align_up( msg_sz, NLMSG_ALIGNTO );
      if( FD_UNLIKELY( msg_sz<sizeof(struct nlmsghdr) || aligned_msg_sz>msg_rem ) ) {
        errno = EPROTO;
        return -1;
      }
      if( FD_UNLIKELY( nlh->nlmsg_seq!=request_seq ) ) {
        errno = EPROTO;
        return -1;
      }
      if( FD_UNLIKELY( nlh->nlmsg_flags & NLM_F_DUMP_INTR ) ) {
        errno = EAGAIN;
        return -1;
      }
      if( nlh->nlmsg_type==NLMSG_DONE ) {
        ulong const payload_sz = msg_sz-sizeof(*nlh);
        if( payload_sz ) {
          if( FD_UNLIKELY( payload_sz<sizeof(int) ) ) {
            errno = EPROTO;
            return -1;
          }
          int done_err;
          fd_memcpy( &done_err, nlh+1, sizeof(done_err) );
          if( FD_UNLIKELY( done_err>0 ) ) {
            errno = EPROTO;
            return -1;
          }
          if( FD_UNLIKELY( done_err<0 ) ) {
            errno = -done_err;
            return -1;
          }
        }
        if( FD_UNLIKELY( !multipart ) ) {
          errno = EPROTO;
          return -1;
        }
        return 0;
      }
      if( nlh->nlmsg_type==NLMSG_ERROR ) {
        if( FD_UNLIKELY( msg_sz<sizeof(struct nlmsghdr)+sizeof(struct nlmsgerr) ) ) {
          errno = EPROTO;
          return -1;
        }
        int err = ((struct nlmsgerr const *)(nlh+1))->error;
        if( FD_UNLIKELY( err ) ) {
          errno = -err;
          return -1;
        }
        if( FD_UNLIKELY( multipart ) ) {
          errno = EPROTO;
          return -1;
        }
        return 0;
      }
      if( FD_UNLIKELY( parse_fn( nlh, parse_arg ) ) ) return -1;
      msg_cur += aligned_msg_sz;
      msg_rem -= aligned_msg_sz;
    }
  }
}

struct fd_mlx5_nl_dev_find {
  char const * rdma_name;
  uint         dev_idx;
};
typedef struct fd_mlx5_nl_dev_find fd_mlx5_nl_dev_find_t;

static int
fd_mlx5_nl_parse_dev( struct nlmsghdr const * nlh,
                      void *                  parse_arg ) {
  if( FD_UNLIKELY( nlh->nlmsg_type!=RDMA_NL_GET_TYPE( RDMA_NL_NLDEV, RDMA_NLDEV_CMD_GET ) ) ) {
    errno = EPROTO;
    return -1;
  }
  fd_mlx5_nl_dev_find_t * dev_find = parse_arg;
  void const * attr_data = nlh+1;
  ulong attr_data_sz = nlh->nlmsg_len-sizeof(*nlh);
  struct nlattr const * dev_idx_attr;
  int found = fd_mlx5_nla_find( attr_data, attr_data_sz, RDMA_NLDEV_ATTR_DEV_INDEX, &dev_idx_attr );
  if( FD_UNLIKELY( found<=0 ) ) return found;
  struct nlattr const * dev_name_attr;
  found = fd_mlx5_nla_find( attr_data, attr_data_sz, RDMA_NLDEV_ATTR_DEV_NAME, &dev_name_attr );
  if( FD_UNLIKELY( found<=0 ) ) return found;
  uint dev_idx;
  if( FD_UNLIKELY( fd_mlx5_nla_u32( dev_idx_attr, &dev_idx ) ) ) return -1;
  ulong const expected_name_sz = strlen( dev_find->rdma_name )+1UL;
  ulong const dev_name_sz = dev_name_attr->nla_len-sizeof(*dev_name_attr);
  if( dev_name_sz==expected_name_sz && !memcmp( dev_name_attr+1, dev_find->rdma_name, expected_name_sz ) ) {
    dev_find->dev_idx = dev_idx;
  }
  return 0;
}

struct fd_mlx5_nl_counter_find {
  uint counter_id;
  int  found;
};
typedef struct fd_mlx5_nl_counter_find fd_mlx5_nl_counter_find_t;

static int
fd_mlx5_nl_parse_counter_id( struct nlmsghdr const * nlh,
                             void *                  parse_arg ) {
  if( FD_UNLIKELY( nlh->nlmsg_type!=RDMA_NL_GET_TYPE( RDMA_NL_NLDEV, RDMA_NLDEV_CMD_STAT_SET ) ) ) {
    errno = EPROTO;
    return -1;
  }
  fd_mlx5_nl_counter_find_t * counter_find = parse_arg;
  struct nlattr const * counter_id_attr;
  int counter_id_found = fd_mlx5_nla_find( nlh+1, nlh->nlmsg_len-sizeof(*nlh),
                                           RDMA_NLDEV_ATTR_STAT_COUNTER_ID, &counter_id_attr );
  if( FD_UNLIKELY( counter_id_found<=0 ) ) {
    if( !counter_id_found ) errno = EPROTO;
    return -1;
  }
  if( FD_UNLIKELY( fd_mlx5_nla_u32( counter_id_attr, &counter_find->counter_id ) ) ) return -1;
  counter_find->found = 1;
  return 0;
}

struct fd_mlx5_nl_stat_find {
  uint  counter_id;
  ulong out_of_buffer;
  int   found;
};
typedef struct fd_mlx5_nl_stat_find fd_mlx5_nl_stat_find_t;

static int
fd_mlx5_nl_parse_hw_counters( uchar const *            attr_cur,
                              ulong                    attr_rem,
                              fd_mlx5_nl_stat_find_t * stat_find ) {
  while( attr_rem ) {
    struct nlattr const * entry_attr;
    int next_result = fd_mlx5_nla_next( &attr_cur, &attr_rem, &entry_attr );
    if( FD_UNLIKELY( next_result<=0 ) ) return next_result;
    if( (entry_attr->nla_type & (ushort)NLA_TYPE_MASK)!=RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY ) continue;

    void const * entry_data = entry_attr+1;
    ulong entry_data_sz     = entry_attr->nla_len-sizeof(*entry_attr);
    struct nlattr const * name_attr;
    struct nlattr const * value_attr;
    int name_found  = fd_mlx5_nla_find( entry_data, entry_data_sz,
                                        RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY_NAME, &name_attr );
    int value_found = fd_mlx5_nla_find( entry_data, entry_data_sz,
                                        RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY_VALUE, &value_attr );
    if( FD_UNLIKELY( name_found<0 || value_found<0 ) ) return -1;
    if( !name_found || name_attr->nla_len!=sizeof(*name_attr)+sizeof("out_of_buffer") ||
        memcmp( name_attr+1, "out_of_buffer", sizeof("out_of_buffer") ) ) continue;
    if( FD_UNLIKELY( !value_found || value_attr->nla_len!=sizeof(*value_attr)+sizeof(ulong) ) ) {
      errno = EPROTO;
      return -1;
    }
    fd_memcpy( &stat_find->out_of_buffer, value_attr+1, sizeof(ulong) );
    stat_find->found = 1;
  }
  return 0;
}

static int
fd_mlx5_nl_parse_counter_entry( uchar const *            attr_cur,
                                ulong                    attr_rem,
                                fd_mlx5_nl_stat_find_t * stat_find ) {
  struct nlattr const * counter_id_attr;
  int counter_id_found = fd_mlx5_nla_find( attr_cur, attr_rem, RDMA_NLDEV_ATTR_STAT_COUNTER_ID, &counter_id_attr );
  if( FD_UNLIKELY( counter_id_found<0 ) ) return -1;
  uint counter_id;
  if( !counter_id_found ) return 0;
  if( FD_UNLIKELY( fd_mlx5_nla_u32( counter_id_attr, &counter_id ) ) ) return -1;
  if( counter_id!=stat_find->counter_id ) return 0;
  struct nlattr const * hw_counters_attr;
  int hw_counters_found = fd_mlx5_nla_find( attr_cur, attr_rem, RDMA_NLDEV_ATTR_STAT_HWCOUNTERS, &hw_counters_attr );
  if( FD_UNLIKELY( hw_counters_found<0 ) ) return -1;
  if( !hw_counters_found ) return 0;
  return fd_mlx5_nl_parse_hw_counters( (uchar const *)(hw_counters_attr+1),
                                       hw_counters_attr->nla_len-sizeof(*hw_counters_attr), stat_find );
}

static int
fd_mlx5_nl_parse_stats( struct nlmsghdr const * nlh,
                        void *                  parse_arg ) {
  if( FD_UNLIKELY( nlh->nlmsg_type!=RDMA_NL_GET_TYPE( RDMA_NL_NLDEV, RDMA_NLDEV_CMD_STAT_GET ) ) ) {
    errno = EPROTO;
    return -1;
  }
  fd_mlx5_nl_stat_find_t * stat_find = parse_arg;
  struct nlattr const * counters_attr;
  int counters_found = fd_mlx5_nla_find( nlh+1, nlh->nlmsg_len-sizeof(*nlh),
                                         RDMA_NLDEV_ATTR_STAT_COUNTER, &counters_attr );
  if( FD_UNLIKELY( counters_found<0 ) ) return -1;
  if( !counters_found ) return 0;
  uchar const * attr_cur = (uchar const *)(counters_attr+1);
  ulong attr_rem = counters_attr->nla_len-sizeof(*counters_attr);
  while( attr_rem ) {
    struct nlattr const * entry_attr;
    int next_result = fd_mlx5_nla_next( &attr_cur, &attr_rem, &entry_attr );
    if( FD_UNLIKELY( next_result<=0 ) ) return next_result;
    if( (entry_attr->nla_type & (ushort)NLA_TYPE_MASK)==RDMA_NLDEV_ATTR_STAT_COUNTER_ENTRY &&
        FD_UNLIKELY( fd_mlx5_nl_parse_counter_entry( (uchar const *)(entry_attr+1),
                                                     entry_attr->nla_len-sizeof(*entry_attr), stat_find ) ) ) return -1;
  }
  return 0;
}

fd_netlink_rdma_ctx_t *
fd_mlx5_netlink_rdma_init( fd_netlink_rdma_ctx_t * netlink_rdma,
                           char const *            rdma_name,
                           uint                    port_num,
                           uint                    qpn ) {
  if( FD_UNLIKELY( !netlink_rdma ) ) { errno = EINVAL; return NULL; }
  fd_memset( netlink_rdma, 0, sizeof(*netlink_rdma) );
  netlink_rdma->fd = -1;
  int netlink_fd = socket( AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_RDMA );
  if( FD_UNLIKELY( netlink_fd<0 ) ) return NULL;
  struct sockaddr_nl local_addr = { .nl_family=AF_NETLINK };
  if( FD_UNLIKELY( bind( netlink_fd, fd_type_pun( &local_addr ), sizeof(local_addr) ) ) ) goto fail;
  netlink_rdma->fd = netlink_fd;

  fd_mlx5_nl_req_t req[1];
  uint request_seq = ++netlink_rdma->seq;
  fd_mlx5_nl_req_init( req, RDMA_NL_GET_TYPE( RDMA_NL_NLDEV, RDMA_NLDEV_CMD_GET ),
                       NLM_F_REQUEST|NLM_F_DUMP, request_seq );
  fd_mlx5_nl_dev_find_t dev_find = { .rdma_name=rdma_name };
  if( FD_UNLIKELY( fd_mlx5_nl_send( netlink_fd, req ) ||
                   fd_mlx5_nl_recv( netlink_fd, request_seq, 1, fd_mlx5_nl_parse_dev, &dev_find ) ) ) goto fail;
  if( FD_UNLIKELY( !dev_find.dev_idx ) ) { errno = ENODEV; goto fail; }

  request_seq = ++netlink_rdma->seq;
  fd_mlx5_nl_req_init( req, RDMA_NL_GET_TYPE( RDMA_NL_NLDEV, RDMA_NLDEV_CMD_STAT_SET ),
                       NLM_F_REQUEST|NLM_F_ACK, request_seq );
  if( FD_UNLIKELY( fd_mlx5_nl_req_u32( req, RDMA_NLDEV_ATTR_STAT_MODE, RDMA_COUNTER_MODE_MANUAL ) ||
                   fd_mlx5_nl_req_u32( req, RDMA_NLDEV_ATTR_STAT_RES,  RDMA_NLDEV_ATTR_RES_QP ) ||
                   fd_mlx5_nl_req_u32( req, RDMA_NLDEV_ATTR_DEV_INDEX, dev_find.dev_idx ) ||
                   fd_mlx5_nl_req_u32( req, RDMA_NLDEV_ATTR_PORT_INDEX, port_num ) ||
                   fd_mlx5_nl_req_u32( req, RDMA_NLDEV_ATTR_RES_LQPN, qpn ) ) ) goto fail;
  fd_mlx5_nl_counter_find_t counter_find = {0};
  if( FD_UNLIKELY( fd_mlx5_nl_send( netlink_fd, req ) ||
                   fd_mlx5_nl_recv( netlink_fd, request_seq, 0, fd_mlx5_nl_parse_counter_id,
                                    &counter_find ) ) ) goto fail;
  if( FD_UNLIKELY( !counter_find.found ) ) { errno = EPROTO; goto fail; }

  netlink_rdma->dev_idx    = dev_find.dev_idx;
  netlink_rdma->port_num   = port_num;
  netlink_rdma->counter_id = counter_find.counter_id;
  return netlink_rdma;

fail:
  {
    int err = errno;
    close( netlink_fd );
    netlink_rdma->fd = -1;
    errno = err;
    return NULL;
  }
}

int
fd_mlx5_netlink_rdma_qp_counter_read( fd_netlink_rdma_ctx_t * netlink_rdma,
                                      ulong *                   out_of_buffer ) {
  if( FD_UNLIKELY( !netlink_rdma || netlink_rdma->fd<0 || !netlink_rdma->dev_idx || !out_of_buffer ) ) {
    errno = EINVAL;
    return -1;
  }
  uint request_seq = ++netlink_rdma->seq;
  fd_mlx5_nl_req_t req[1];
  fd_mlx5_nl_req_init( req, RDMA_NL_GET_TYPE( RDMA_NL_NLDEV, RDMA_NLDEV_CMD_STAT_GET ),
                       NLM_F_REQUEST|NLM_F_DUMP, request_seq );
  if( FD_UNLIKELY( fd_mlx5_nl_req_u32( req, RDMA_NLDEV_ATTR_DEV_INDEX, netlink_rdma->dev_idx ) ||
                   fd_mlx5_nl_req_u32( req, RDMA_NLDEV_ATTR_PORT_INDEX, netlink_rdma->port_num ) ||
                   fd_mlx5_nl_req_u32( req, RDMA_NLDEV_ATTR_STAT_RES, RDMA_NLDEV_ATTR_RES_QP ) ||
                   fd_mlx5_nl_send( netlink_rdma->fd, req ) ) ) return -1;

  fd_mlx5_nl_stat_find_t stat_find = { .counter_id=netlink_rdma->counter_id };
  if( FD_UNLIKELY( fd_mlx5_nl_recv( netlink_rdma->fd, request_seq, 1, fd_mlx5_nl_parse_stats,
                                    &stat_find ) ) ) return -1;
  if( FD_UNLIKELY( !stat_find.found ) ) { errno = ENOENT; return -1; }
  *out_of_buffer = stat_find.out_of_buffer;
  return 0;
}
