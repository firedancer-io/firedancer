#include "fd_mlx5.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/mlx5-abi.h>
#include <rdma/mlx5_user_ioctl_cmds.h>
#include <rdma/mlx5_user_ioctl_verbs.h>
#include <rdma/rdma_user_ioctl_cmds.h>

#define FD_MLX5_ETH_INLINE_SZ       (18UL)
#define FD_MLX5_BF_OFFSET           (0x800UL)
#define FD_MLX5_DBREC_SZ            (8UL)
#define FD_MLX5_UVERBS_NAME_MAX     (32UL)
#define FD_MLX5_CORE_ABI            (6U)
#define FD_MLX5_PROVIDER_ABI        (1U)
#define FD_MLX5_LINK_LAYER_ETHERNET (2U)
#define FD_MLX5_CQE_OP_OWN_OFF      (63UL)
#define FD_MLX5_CQE_INVALID         (15U)

#define FD_MLX5_QPS_INIT (1U)
#define FD_MLX5_QPS_RTR  (2U)
#define FD_MLX5_QPS_RTS  (3U)

struct fd_mlx5_pd {
  fd_mlx5_context_t * ctx;
  uint                handle;
};
typedef struct fd_mlx5_pd fd_mlx5_pd_t;

struct fd_mlx5_caps {
  ulong max_mr_size;
  uint  max_send_wqebb;
  uint  max_recv_wr;
  uint  max_cqe;
  uint  bf_reg_size;
  uchar eth_min_inline_sz;
};
typedef struct fd_mlx5_caps fd_mlx5_caps_t;

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
  uint                               async_fd;
  uint                               num_comp_vectors;
  struct mlx5_ib_alloc_ucontext_resp mlx5;
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
  fd_mlx5_ioctl_hdr_t   hdr;
  struct ib_uverbs_attr attrs[ 5 ];
};
typedef struct fd_mlx5_uar_alloc_req fd_mlx5_uar_alloc_req_t;

struct fd_mlx5_uar_destroy_req {
  fd_mlx5_ioctl_hdr_t   hdr;
  struct ib_uverbs_attr attrs[ 1 ];
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
  struct ib_uverbs_cmd_hdr   hdr;
  struct ib_uverbs_modify_qp core;
};
typedef struct fd_mlx5_modify_qp_req fd_mlx5_modify_qp_req_t;

struct fd_mlx5_create_udp_flow_req {
  fd_mlx5_uverbs_ex_hdr_t            hdr;
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
typedef struct fd_mlx5_create_udp_flow_req fd_mlx5_create_udp_flow_req_t;

FD_STATIC_ASSERT( sizeof(fd_mlx5_get_context_req_t     )== 48UL, mlx5_get_context_req_sz      );
FD_STATIC_ASSERT( sizeof(fd_mlx5_get_context_resp_t    )== 80UL, mlx5_get_context_resp_sz     );
FD_STATIC_ASSERT( sizeof(fd_mlx5_query_device_req_t    )== 16UL, mlx5_query_device_req_sz     );
FD_STATIC_ASSERT( sizeof(fd_mlx5_query_port_req_t      )== 24UL, mlx5_query_port_req_sz       );
FD_STATIC_ASSERT( sizeof(fd_mlx5_alloc_pd_req_t        )== 16UL, mlx5_alloc_pd_req_sz         );
FD_STATIC_ASSERT( sizeof(fd_mlx5_alloc_pd_resp_t       )==  8UL, mlx5_alloc_pd_resp_sz        );
FD_STATIC_ASSERT( sizeof(fd_mlx5_reg_mr_req_t          )== 48UL, mlx5_reg_mr_req_sz           );
FD_STATIC_ASSERT( sizeof(fd_mlx5_reg_mr_resp_t         )== 12UL, mlx5_reg_mr_resp_sz          );
FD_STATIC_ASSERT( sizeof(struct ib_uverbs_ioctl_hdr    )== 24UL, uverbs_ioctl_hdr_sz           );
FD_STATIC_ASSERT( sizeof(struct ib_uverbs_attr         )== 16UL, uverbs_ioctl_attr_sz          );
FD_STATIC_ASSERT( sizeof(fd_mlx5_ioctl_hdr_t           )== 24UL, mlx5_ioctl_hdr_sz             );
FD_STATIC_ASSERT( sizeof(fd_mlx5_uar_alloc_req_t       )==104UL, mlx5_uar_alloc_req_sz         );
FD_STATIC_ASSERT( sizeof(fd_mlx5_uar_destroy_req_t     )== 40UL, mlx5_uar_destroy_req_sz       );
FD_STATIC_ASSERT( sizeof(fd_mlx5_create_cq_req_t       )== 72UL, mlx5_create_cq_req_sz         );
FD_STATIC_ASSERT( sizeof(fd_mlx5_create_cq_resp_t      )== 16UL, mlx5_create_cq_resp_sz        );
FD_STATIC_ASSERT( sizeof(fd_mlx5_destroy_cq_req_t      )== 24UL, mlx5_destroy_cq_req_sz        );
FD_STATIC_ASSERT( sizeof(fd_mlx5_create_qp_req_t       )==120UL, mlx5_create_qp_req_sz         );
FD_STATIC_ASSERT( sizeof(fd_mlx5_create_qp_resp_t      )== 72UL, mlx5_create_qp_resp_sz        );
FD_STATIC_ASSERT( sizeof(fd_mlx5_modify_qp_req_t       )==120UL, mlx5_modify_qp_req_sz         );
FD_STATIC_ASSERT( sizeof(fd_mlx5_create_udp_flow_req_t )==144UL, mlx5_create_udp_flow_req_sz   );

#define FD_MLX5_SUCCESS   (0)
#define FD_MLX5_ERR_INVAL (-1)

/* These helpers only marshal command headers.  Resource creation and
   write(2) execution belong to the control-plane layer built on top. */

static int
fd_mlx5_uverbs_cmd_hdr_init( struct ib_uverbs_cmd_hdr * hdr,
                             uint                        command,
                             ulong                       request_sz,
                             ulong                       response_sz );

static int
fd_mlx5_uverbs_ex_hdr_init( fd_mlx5_uverbs_ex_hdr_t * hdr,
                            uint                       command,
                            ulong                      core_request_sz,
                            ulong                      request_sz,
                            void *                     response,
                            ulong                      core_response_sz,
                            ulong                      response_sz );

static int
fd_mlx5_uar_alloc_req_init( fd_mlx5_uar_alloc_req_t * req,
                            ulong *                    mmap_offset,
                            uint *                     mmap_sz,
                            uint *                     page_id );

static int
fd_mlx5_uar_destroy_req_init( fd_mlx5_uar_destroy_req_t * req,
                              uint                        handle );

static int
fd_mlx5_create_udp_flow_req_init( fd_mlx5_create_udp_flow_req_t *     req,
                                  struct ib_uverbs_create_flow_resp * resp,
                                  uint                                qp_handle,
                                  uint                                port_num,
                                  uint                                dst_ip,
                                  ushort                              dst_port );

#define FD_MLX5_PATH_MAX (256UL)
#define FD_MLX5_FLOW_SPEC_ETH (0x20U)
#define FD_MLX5_FLOW_SPEC_IPV4 (0x30U)
#define FD_MLX5_FLOW_SPEC_UDP  (0x41U)

static int
fd_mlx5_path( char *       path,
              ulong        path_sz,
              char const * fmt,
              ... ) {
  va_list ap;
  va_start( ap, fmt );
  int n = vsnprintf( path, path_sz, fmt, ap );
  va_end( ap );
  if( FD_UNLIKELY( n<0 || (ulong)n>=path_sz ) ) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static int
fd_mlx5_read_text( char const * path,
                   char *       buf,
                   ulong        buf_sz ) {
  if( FD_UNLIKELY( buf_sz<2UL ) ) {
    errno = EINVAL;
    return -1;
  }

  int fd = open( path, O_RDONLY | O_CLOEXEC );
  if( FD_UNLIKELY( fd<0 ) ) return -1;

  int     err = 0;
  ssize_t n   = read( fd, buf, buf_sz-1UL );
  if( FD_UNLIKELY( n<0 ) ) err = errno;
  else if( FD_UNLIKELY( (ulong)n==buf_sz-1UL ) ) {
    char extra;
    ssize_t extra_sz = read( fd, &extra, 1UL );
    if( FD_UNLIKELY( extra_sz<0 ) ) err = errno;
    else if( FD_UNLIKELY( extra_sz ) ) err = EOVERFLOW;
  }
  if( FD_UNLIKELY( close( fd ) && !err ) ) err = errno;
  if( FD_UNLIKELY( err ) ) {
    errno = err;
    return -1;
  }

  ulong sz = (ulong)n;
  while( sz && (buf[ sz-1UL ]=='\n' || buf[ sz-1UL ]=='\r' ||
                buf[ sz-1UL ]==' '  || buf[ sz-1UL ]=='\t') ) sz--;
  if( FD_UNLIKELY( !sz ) ) {
    errno = EPROTO;
    return -1;
  }
  buf[ sz ] = '\0';
  return 0;
}

static int
fd_mlx5_read_uint( char const * path,
                   uint *       value ) {
  char buf[ 32 ];
  if( FD_UNLIKELY( fd_mlx5_read_text( path, buf, sizeof(buf) ) ) ) return -1;

  uint x = 0U;
  for( char const * p=buf; *p; p++ ) {
    uint digit = (uint)(uchar)*p - (uint)'0';
    if( FD_UNLIKELY( digit>9U || x>(UINT_MAX-digit)/10U ) ) {
      errno = EPROTO;
      return -1;
    }
    x = 10U*x + digit;
  }
  *value = x;
  return 0;
}

static int
fd_mlx5_name_valid( char const * name,
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
fd_mlx5_uverbs_name_valid( char const * name ) {
  if( strncmp( name, "uverbs", 6UL ) ) return 0;
  if( !name[6] ) return 0;
  for( char const * p=name+6; *p; p++ )
    if( *p<'0' || *p>'9' ) return 0;
  return 1;
}

static int
fd_mlx5_check_driver( char const * rdma_name ) {
  char path[ FD_MLX5_PATH_MAX ];
  if( FD_UNLIKELY( fd_mlx5_path( path, sizeof(path),
                                 "/sys/class/infiniband/%s/device/driver", rdma_name ) ) ) return -1;

  char target[ FD_MLX5_PATH_MAX ];
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

static int
fd_mlx5_resolve_uverbs( char        uverbs_name[ FD_MLX5_UVERBS_NAME_MAX ],
                        char const * rdma_name ) {
  if( FD_UNLIKELY( !fd_mlx5_name_valid( rdma_name, FD_MLX5_RDMA_NAME_MAX ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_mlx5_check_driver( rdma_name ) ) ) return -1;

  DIR * dir = opendir( "/sys/class/infiniband_verbs" );
  if( FD_UNLIKELY( !dir ) ) return -1;

  char found[ FD_MLX5_UVERBS_NAME_MAX ] = {0};
  int  err = 0;
  for(;;) {
    errno = 0;
    struct dirent * entry = readdir( dir );
    if( !entry ) {
      if( errno ) err = errno;
      break;
    }
    if( !fd_mlx5_uverbs_name_valid( entry->d_name ) ) continue;

    char path[ FD_MLX5_PATH_MAX ];
    if( FD_UNLIKELY( fd_mlx5_path( path, sizeof(path),
                                   "/sys/class/infiniband_verbs/%s/ibdev", entry->d_name ) ) ) {
      err = errno;
      break;
    }
    char ibdev[ FD_MLX5_RDMA_NAME_MAX ];
    if( FD_UNLIKELY( fd_mlx5_read_text( path, ibdev, sizeof(ibdev) ) ) ) {
      err = errno;
      break;
    }
    if( strcmp( ibdev, rdma_name ) ) continue;
    if( FD_UNLIKELY( found[0] ) ) {
      err = EEXIST;
      break;
    }
    ulong name_sz = strlen( entry->d_name );
    if( FD_UNLIKELY( name_sz>=sizeof(found) ) ) {
      err = ENAMETOOLONG;
      break;
    }
    fd_memcpy( found, entry->d_name, name_sz+1UL );
  }
  if( FD_UNLIKELY( closedir( dir ) && !err ) ) err = errno;
  if( FD_UNLIKELY( err ) ) {
    errno = err;
    return -1;
  }
  if( FD_UNLIKELY( !found[0] ) ) {
    errno = ENODEV;
    return -1;
  }

  char path[ FD_MLX5_PATH_MAX ];
  uint core_abi;
  uint provider_abi;
  if( FD_UNLIKELY( fd_mlx5_read_uint( "/sys/class/infiniband_verbs/abi_version", &core_abi ) ) ) return -1;
  if( FD_UNLIKELY( fd_mlx5_path( path, sizeof(path),
                                 "/sys/class/infiniband_verbs/%s/abi_version", found ) ) ) return -1;
  if( FD_UNLIKELY( fd_mlx5_read_uint( path, &provider_abi ) ) ) return -1;
  if( FD_UNLIKELY( core_abi!=FD_MLX5_CORE_ABI || provider_abi!=FD_MLX5_PROVIDER_ABI ) ) {
    errno = EPROTONOSUPPORT;
    return -1;
  }

  fd_memcpy( uverbs_name, found, strlen(found)+1UL );
  return 0;
}

static int
fd_mlx5_write_cmd( int          fd,
                   void const * req,
                   ulong        req_sz ) {
  ssize_t result = write( fd, req, req_sz );
  if( FD_UNLIKELY( result<0 ) ) return -1;
  if( FD_UNLIKELY( (ulong)result!=req_sz ) ) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

static int
fd_mlx5_get_context( fd_mlx5_context_t * ctx,
                     fd_mlx5_caps_t *    caps ) {
  fd_mlx5_get_context_req_t  req [1];
  fd_mlx5_get_context_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );

  req->response                      = (ulong)resp;
  req->mlx5.total_num_bfregs         = 16U;
  req->mlx5.num_low_latency_bfregs   = 4U;
  req->mlx5.max_cqe_version          = 1U;
  req->mlx5.lib_caps                 = MLX5_LIB_CAP_4K_UAR | MLX5_LIB_CAP_DYN_UAR;
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_GET_CONTEXT,
                                                sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( ctx->cmd_fd, req, sizeof(req) ) ) ) return -1;
  if( FD_UNLIKELY( resp->async_fd>(uint)INT_MAX ) ) {
    errno = EPROTO;
    return -1;
  }

  ctx->async_fd = (int)resp->async_fd;
  int fd_flags = fcntl( ctx->async_fd, F_GETFD );
  if( FD_UNLIKELY( fd_flags<0 || fcntl( ctx->async_fd, F_SETFD, fd_flags | FD_CLOEXEC ) ) ) return -1;

  ulong const min_resp_sz = offsetof( struct mlx5_ib_alloc_ucontext_resp, hca_core_clock_offset );
  ulong const uar_resp_sz = offsetof( struct mlx5_ib_alloc_ucontext_resp, dump_fill_mkey );
  if( FD_UNLIKELY( resp->mlx5.response_length<min_resp_sz ||
                   resp->mlx5.response_length<uar_resp_sz ||
                   resp->mlx5.num_ports<ctx->port_num ||
                   resp->mlx5.cqe_version>1U ||
                   resp->mlx5.max_sq_desc_sz<FD_MLX5_WQEBB_SZ ||
                   resp->mlx5.max_rq_desc_sz<FD_MLX5_RQ_WQE_SZ ||
                   !resp->mlx5.max_send_wqebb || !resp->mlx5.max_recv_wr ||
                   resp->mlx5.log_uar_size!=12U || resp->mlx5.num_uars_per_page!=1U ||
                   resp->mlx5.tot_bfregs ) ) {
    errno = EPROTONOSUPPORT;
    return -1;
  }

  caps->bf_reg_size    = resp->mlx5.bf_reg_size;
  caps->max_send_wqebb = resp->mlx5.max_send_wqebb;
  caps->max_recv_wr    = resp->mlx5.max_recv_wr;
  switch( resp->mlx5.eth_min_inline ) {
  case MLX5_USER_INLINE_MODE_NONE: caps->eth_min_inline_sz = 0U;                     break;
  case MLX5_USER_INLINE_MODE_L2:   caps->eth_min_inline_sz = FD_MLX5_ETH_INLINE_SZ; break;
  default:
    errno = EPROTONOSUPPORT;
    return -1;
  }
  return 0;
}

static int
fd_mlx5_query_device( fd_mlx5_context_t * ctx,
                      fd_mlx5_caps_t *    caps ) {
  fd_mlx5_query_device_req_t         req [1];
  struct ib_uverbs_query_device_resp resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );

  req->response = (ulong)resp;
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_QUERY_DEVICE,
                                                sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( ctx->cmd_fd, req, sizeof(req) ) ) ) return -1;

  caps->max_mr_size = resp->max_mr_size;
  caps->max_cqe     = resp->max_cqe;
  if( FD_UNLIKELY( !caps->max_mr_size || !resp->max_qp_wr || !resp->max_sge || !caps->max_cqe ||
                   resp->phys_port_cnt<ctx->port_num ) ) {
    errno = EPROTONOSUPPORT;
    return -1;
  }
  return 0;
}

static int
fd_mlx5_query_port( fd_mlx5_context_t * ctx ) {
  fd_mlx5_query_port_req_t         req [1];
  struct ib_uverbs_query_port_resp resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );

  req->response = (ulong)resp;
  req->port_num = (uchar)ctx->port_num;
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_QUERY_PORT,
                                                sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( ctx->cmd_fd, req, sizeof(req) ) ) ) return -1;

  if( FD_UNLIKELY( resp->link_layer!=FD_MLX5_LINK_LAYER_ETHERNET ) ) {
    errno = EPROTONOSUPPORT;
    return -1;
  }
  return 0;
}

static fd_mlx5_context_t *
fd_mlx5_context_fini( fd_mlx5_context_t * ctx ) {
  if( FD_UNLIKELY( !ctx ) ) return NULL;
  if( ctx->async_fd>=0 ) close( ctx->async_fd );
  if( ctx->cmd_fd  >=0 ) close( ctx->cmd_fd   );
  fd_memset( ctx, 0, sizeof(*ctx) );
  ctx->cmd_fd   = -1;
  ctx->async_fd = -1;
  return ctx;
}

static fd_mlx5_context_t *
fd_mlx5_context_init( fd_mlx5_context_t * ctx,
                      fd_mlx5_caps_t *    caps,
                      char const *         rdma_name,
                      uint                 port_num ) {
  if( FD_UNLIKELY( !ctx || !caps ) ) {
    errno = EINVAL;
    return NULL;
  }
  fd_memset( ctx, 0, sizeof(*ctx) );
  fd_memset( caps, 0, sizeof(*caps) );
  ctx->cmd_fd   = -1;
  ctx->async_fd = -1;
  if( FD_UNLIKELY( !port_num || port_num>(uint)UCHAR_MAX ) ) {
    errno = EINVAL;
    return NULL;
  }
  ctx->port_num = port_num;

  char uverbs_name[ FD_MLX5_UVERBS_NAME_MAX ];
  if( FD_UNLIKELY( fd_mlx5_resolve_uverbs( uverbs_name, rdma_name ) ) ) goto fail;

  char path[ FD_MLX5_PATH_MAX ];
  if( FD_UNLIKELY( fd_mlx5_path( path, sizeof(path), "/dev/infiniband/%s", uverbs_name ) ) ) goto fail;
  ctx->cmd_fd = open( path, O_RDWR | O_CLOEXEC );
  if( FD_UNLIKELY( ctx->cmd_fd<0 ) ) goto fail;

  struct stat st;
  if( FD_UNLIKELY( fstat( ctx->cmd_fd, &st ) ) ) goto fail;
  if( FD_UNLIKELY( !S_ISCHR( st.st_mode ) ) ) {
    errno = ENODEV;
    goto fail;
  }

  if( FD_UNLIKELY( fd_mlx5_get_context( ctx, caps ) ||
                   fd_mlx5_query_device( ctx, caps ) ||
                   fd_mlx5_query_port( ctx ) ) ) goto fail;
  return ctx;

fail:
  {
    int err = errno;
    fd_mlx5_context_fini( ctx );
    errno = err;
    return NULL;
  }
}

static fd_mlx5_pd_t *
fd_mlx5_pd_init( fd_mlx5_pd_t *      pd,
                 fd_mlx5_context_t * ctx ) {
  if( FD_UNLIKELY( !pd ) ) {
    errno = EINVAL;
    return NULL;
  }
  fd_memset( pd, 0, sizeof(*pd) );
  if( FD_UNLIKELY( !ctx || ctx->cmd_fd<0 ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_mlx5_alloc_pd_req_t  req [1];
  fd_mlx5_alloc_pd_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );
  req->response = (ulong)resp;
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_ALLOC_PD,
                                                sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;

  pd->ctx    = ctx;
  pd->handle = resp->pd_handle;
  return pd;
}

static uint *
fd_mlx5_mr_init( uint *         lkey,
                 fd_mlx5_pd_t * pd,
                 void *         memory,
                 ulong          memory_sz,
                 ulong          max_mr_size ) {
  if( FD_UNLIKELY( !lkey ) ) {
    errno = EINVAL;
    return NULL;
  }
  *lkey = 0U;
  ulong memory_addr = (ulong)memory;
  if( FD_UNLIKELY( !pd || !pd->ctx || pd->ctx->cmd_fd<0 || !memory || !memory_sz ||
                   memory_sz>ULONG_MAX-memory_addr || memory_sz>max_mr_size ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_mlx5_reg_mr_req_t  req [1];
  fd_mlx5_reg_mr_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );
  req->response     = (ulong)resp;
  req->start        = memory_addr;
  req->length       = memory_sz;
  req->hca_va       = memory_addr;
  req->pd_handle    = pd->handle;
  req->access_flags = IB_UVERBS_ACCESS_LOCAL_WRITE;
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_REG_MR,
                                                sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( pd->ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;

  *lkey = resp->lkey;
  return lkey;
}

static int
fd_mlx5_ioctl( int                    fd,
               fd_mlx5_ioctl_hdr_t * hdr ) {
  if( FD_UNLIKELY( ioctl( fd, RDMA_VERBS_IOCTL, hdr ) ) ) return -1;
  return 0;
}

static void
fd_mlx5_ioctl_attr_init( struct ib_uverbs_attr * attr,
                         ushort                   attr_id,
                         ushort                   len,
                         ulong                    data ) {
  fd_memset( attr, 0, sizeof(*attr) );
  attr->attr_id = attr_id;
  attr->len     = len;
  attr->flags   = UVERBS_ATTR_F_MANDATORY;
  attr->data    = data;
}

static int
fd_mlx5_uar_alloc_req_init( fd_mlx5_uar_alloc_req_t * req,
                            ulong *                    mmap_offset,
                            uint *                     mmap_sz,
                            uint *                     page_id ) {
  if( FD_UNLIKELY( !req || !mmap_offset || !mmap_sz || !page_id ) ) return FD_MLX5_ERR_INVAL;
  fd_memset( req, 0, sizeof(*req) );
  req->hdr.length    = (ushort)sizeof(*req);
  req->hdr.object_id = MLX5_IB_OBJECT_UAR;
  req->hdr.method_id = MLX5_IB_METHOD_UAR_OBJ_ALLOC;
  req->hdr.num_attrs = 5U;
  req->hdr.driver_id = RDMA_DRIVER_MLX5;
  fd_mlx5_ioctl_attr_init( req->attrs+0, MLX5_IB_ATTR_UAR_OBJ_ALLOC_HANDLE,      0U, 0UL );
  fd_mlx5_ioctl_attr_init( req->attrs+1, MLX5_IB_ATTR_UAR_OBJ_ALLOC_TYPE,        8U, MLX5_IB_UAPI_UAR_ALLOC_TYPE_BF );
  fd_mlx5_ioctl_attr_init( req->attrs+2, MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_OFFSET, 8U, (ulong)mmap_offset );
  fd_mlx5_ioctl_attr_init( req->attrs+3, MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_LENGTH, 4U, (ulong)mmap_sz );
  fd_mlx5_ioctl_attr_init( req->attrs+4, MLX5_IB_ATTR_UAR_OBJ_ALLOC_PAGE_ID,     4U, (ulong)page_id );
  return FD_MLX5_SUCCESS;
}

static int
fd_mlx5_uar_destroy_req_init( fd_mlx5_uar_destroy_req_t * req,
                              uint                        handle ) {
  if( FD_UNLIKELY( !req ) ) return FD_MLX5_ERR_INVAL;
  fd_memset( req, 0, sizeof(*req) );
  req->hdr.length    = (ushort)sizeof(*req);
  req->hdr.object_id = MLX5_IB_OBJECT_UAR;
  req->hdr.method_id = MLX5_IB_METHOD_UAR_OBJ_DESTROY;
  req->hdr.num_attrs = 1U;
  req->hdr.driver_id = RDMA_DRIVER_MLX5;
  fd_mlx5_ioctl_attr_init( req->attrs, MLX5_IB_ATTR_UAR_OBJ_DESTROY_HANDLE, 0U, handle );
  return FD_MLX5_SUCCESS;
}

static int
fd_mlx5_uar_destroy( fd_mlx5_context_t * ctx,
                     uint                 handle ) {
  fd_mlx5_uar_destroy_req_t req[1];
  if( FD_UNLIKELY( fd_mlx5_uar_destroy_req_init( req, handle ) ) ) {
    errno = EINVAL;
    return -1;
  }
  return fd_mlx5_ioctl( ctx->cmd_fd, &req->hdr );
}

static fd_mlx5_uar_t *
fd_mlx5_uar_init( fd_mlx5_uar_t *     uar,
                  fd_mlx5_context_t * ctx,
                  uint                bf_reg_size,
                  uint *              page_id ) {
  if( FD_UNLIKELY( !uar || !page_id ) ) {
    errno = EINVAL;
    return NULL;
  }
  fd_memset( uar, 0, sizeof(*uar) );
  if( FD_UNLIKELY( !ctx || ctx->cmd_fd<0 ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( bf_reg_size<64U || FD_MLX5_BF_OFFSET+bf_reg_size>FD_MLX5_PAGE_SZ ) ) {
    errno = EPROTONOSUPPORT;
    return NULL;
  }

  ulong mmap_offset = 0UL;
  uint  mmap_sz     = 0U;
  uint  uar_page_id = 0U;
  fd_mlx5_uar_alloc_req_t req[1];
  if( FD_UNLIKELY( fd_mlx5_uar_alloc_req_init( req, &mmap_offset, &mmap_sz, &uar_page_id ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_ioctl( ctx->cmd_fd, &req->hdr ) ) ) return NULL;

  ulong handle_raw = req->attrs[0].data;
  if( FD_UNLIKELY( handle_raw>UINT_MAX || mmap_sz!=FD_MLX5_PAGE_SZ ||
                   (mmap_offset & (FD_MLX5_PAGE_SZ-1UL)) || mmap_offset>(ulong)LONG_MAX ) ) {
    int err = EPROTO;
    if( handle_raw<=UINT_MAX ) fd_mlx5_uar_destroy( ctx, (uint)handle_raw );
    errno = err;
    return NULL;
  }

  void * map = mmap( NULL, (ulong)mmap_sz, PROT_WRITE, MAP_SHARED, ctx->cmd_fd, (off_t)mmap_offset );
  if( FD_UNLIKELY( map==MAP_FAILED ) ) {
    int err = errno;
    fd_mlx5_uar_destroy( ctx, (uint)handle_raw );
    errno = err;
    return NULL;
  }

  uar->reg = (volatile uchar *)map + FD_MLX5_BF_OFFSET;
  *page_id = uar_page_id;
  return uar;
}

static fd_mlx5_cq_t *
fd_mlx5_cq_init( fd_mlx5_cq_t *      cq,
                 fd_mlx5_context_t * ctx,
                 fd_mlx5_uar_t *     uar,
                 uint                 page_id,
                 uint                 max_cqe,
                 uint *               handle,
                 void *               entries,
                 uint *               dbrec,
                 uint                 depth ) {
  if( FD_UNLIKELY( !cq || !handle ) ) {
    errno = EINVAL;
    return NULL;
  }
  fd_memset( cq, 0, sizeof(*cq) );
  if( FD_UNLIKELY( !ctx || ctx->cmd_fd<0 || !uar || !uar->reg ||
                   !entries || !fd_ulong_is_aligned( (ulong)entries, FD_MLX5_PAGE_SZ ) ||
                   !dbrec || !fd_ulong_is_aligned( (ulong)dbrec, FD_MLX5_DBREC_SZ ) ||
                   !fd_uint_is_pow2( depth ) || depth-1U>max_cqe || page_id>(uint)USHRT_MAX ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_mlx5_create_cq_req_t  req [1];
  fd_mlx5_create_cq_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );
  req->response            = (ulong)resp;
  req->user_handle         = (ulong)cq;
  req->cqe                 = depth-1U;
  req->comp_channel        = -1;
  req->mlx5.buf_addr       = (ulong)entries;
  req->mlx5.db_addr        = (ulong)dbrec;
  req->mlx5.cqe_size       = FD_MLX5_CQE_SZ;
  req->mlx5.flags          = MLX5_IB_CREATE_CQ_FLAGS_UAR_PAGE_INDEX;
  req->mlx5.uar_page_index = (ushort)page_id;
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_CREATE_CQ,
                                                sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;
  if( FD_UNLIKELY( resp->cqe!=depth-1U ) ) {
    fd_mlx5_destroy_cq_req_t destroy[1];
    struct ib_uverbs_destroy_cq_resp destroy_resp[1];
    fd_memset( destroy,      0, sizeof(destroy)      );
    fd_memset( destroy_resp, 0, sizeof(destroy_resp) );
    destroy->response  = (ulong)destroy_resp;
    destroy->cq_handle = resp->cq_handle;
    if( !fd_mlx5_uverbs_cmd_hdr_init( &destroy->hdr, IB_USER_VERBS_CMD_DESTROY_CQ,
                                      sizeof(destroy), sizeof(destroy_resp) ) )
      fd_mlx5_write_cmd( ctx->cmd_fd, destroy, sizeof(destroy) );
    errno = EPROTO;
    return NULL;
  }

  cq->entries = (fd_mlx5_cqe_t *)entries;
  cq->dbrec   = dbrec;
  cq->depth   = depth;
  *handle     = resp->cq_handle;
  return cq;
}

static int
fd_mlx5_qp_modify( fd_mlx5_qp_t * qp,
                   uint            state ) {
  fd_mlx5_modify_qp_req_t req[1];
  fd_memset( req, 0, sizeof(req) );
  req->core.qp_handle = qp->handle;
  req->core.attr_mask = 1U;
  req->core.qp_state  = (uchar)state;
  if( state==FD_MLX5_QPS_INIT ) {
    req->core.attr_mask |= 1U<<5;
    req->core.port_num   = (uchar)qp->ctx->port_num;
  }
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_MODIFY_QP,
                                                sizeof(req), 0UL ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( qp->ctx->cmd_fd, req, sizeof(req) ) ) ) return -1;
  return 0;
}

static fd_mlx5_qp_t *
fd_mlx5_qp_init( fd_mlx5_qp_t * qp,
                 fd_mlx5_pd_t * pd,
                 fd_mlx5_cq_t * rx_cq,
                 fd_mlx5_cq_t * tx_cq,
                 fd_mlx5_uar_t * uar,
                 uint            rx_cq_handle,
                 uint            tx_cq_handle,
                 uint            uar_page_id,
                 uint            bf_reg_size,
                 uchar           tx_inline_sz,
                 void *          rq,
                 void *          sq,
                 ulong *         rx_user_data,
                 ulong *         tx_user_data,
                 uint *          dbrec ) {
  if( FD_UNLIKELY( !qp ) ) { errno = EINVAL; return NULL; }
  fd_memset( qp, 0, sizeof(*qp) );
  if( FD_UNLIKELY( !pd || !pd->ctx || !rx_cq || !tx_cq || !uar ||
                   !rq || !fd_ulong_is_aligned( (ulong)rq, FD_MLX5_PAGE_SZ ) ||
                   !sq || !fd_ulong_is_aligned( (ulong)sq, FD_MLX5_PAGE_SZ ) ||
                   !rx_user_data || !tx_user_data ||
                   !dbrec || !fd_ulong_is_aligned( (ulong)dbrec, FD_MLX5_DBREC_SZ ) ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_mlx5_create_qp_req_t  req [1];
  fd_mlx5_create_qp_resp_t resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );
  req->response          = (ulong)resp;
  req->user_handle       = (ulong)qp;
  req->pd_handle         = pd->handle;
  req->send_cq_handle    = tx_cq_handle;
  req->recv_cq_handle    = rx_cq_handle;
  req->max_send_wr       = tx_cq->depth;
  req->max_recv_wr       = rx_cq->depth;
  req->max_send_sge      = 1U;
  req->max_recv_sge      = 1U;
  req->qp_type           = IB_UVERBS_QPT_RAW_PACKET;
  req->mlx5.buf_addr     = (ulong)rq;
  req->mlx5.db_addr      = (ulong)dbrec;
  req->mlx5.sq_wqe_count = tx_cq->depth;
  req->mlx5.rq_wqe_count = rx_cq->depth;
  req->mlx5.rq_wqe_shift = 4U;
  req->mlx5.flags        = MLX5_QP_FLAG_UAR_PAGE_INDEX;
  req->mlx5.uidx         = 0U;
  req->mlx5.bfreg_index  = uar_page_id;
  req->mlx5.sq_buf_addr  = (ulong)sq;
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_CREATE_QP,
                                                sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( pd->ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;

  qp->ctx            = pd->ctx;
  qp->rx_cq          = rx_cq;
  qp->tx_cq          = tx_cq;
  qp->uar            = uar;
  qp->rq             = (fd_mlx5_rx_wqe_t *)rq;
  qp->sq             = (fd_mlx5_tx_wqe_t *)sq;
  qp->rx_user_data   = rx_user_data;
  qp->tx_user_data   = tx_user_data;
  qp->dbrec          = dbrec;
  qp->rx_depth       = rx_cq->depth;
  qp->tx_depth       = tx_cq->depth;
  qp->handle         = resp->core.qp_handle;
  qp->qpn            = resp->core.qpn;
  qp->bf_reg_size    = bf_reg_size;
  qp->tx_inline_sz   = tx_inline_sz;
  return qp;
}

static fd_mlx5_qp_t *
fd_mlx5_qp_start( fd_mlx5_qp_t * qp ) {
  if( FD_UNLIKELY( !qp || !qp->ctx ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_qp_modify( qp, FD_MLX5_QPS_INIT ) ||
                   fd_mlx5_qp_modify( qp, FD_MLX5_QPS_RTR  ) ||
                   fd_mlx5_qp_modify( qp, FD_MLX5_QPS_RTS  ) ) ) return NULL;
  return qp;
}

int
fd_mlx5_flow_create_udp( fd_mlx5_qp_t * qp,
                         uint           dst_ip,
                         ushort         dst_port ) {
  if( FD_UNLIKELY( !qp || !qp->ctx || !dst_port ) ) {
    errno = EINVAL;
    return -1;
  }

  fd_mlx5_create_udp_flow_req_t     req [1];
  struct ib_uverbs_create_flow_resp resp[1];
  if( FD_UNLIKELY( fd_mlx5_create_udp_flow_req_init( req, resp, qp->handle,
                                                     qp->ctx->port_num, dst_ip,
                                                     dst_port ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( qp->ctx->cmd_fd, req, sizeof(req) ) ) ) return -1;
  return 0;
}

static int
fd_mlx5_layout_region( ulong * off,
                       ulong   cnt,
                       ulong   elem_sz,
                       ulong * region_off ) {
  if( FD_UNLIKELY( cnt>ULONG_MAX/elem_sz ) ) return -1;
  ulong sz = cnt*elem_sz;
  if( FD_UNLIKELY( *off>ULONG_MAX-sz ) ) return -1;
  *region_off = *off;
  ulong end = *off+sz;
  if( FD_UNLIKELY( end>ULONG_MAX-(FD_MLX5_PAGE_SZ-1UL) ) ) return -1;
  *off = fd_ulong_align_up( end, FD_MLX5_PAGE_SZ );
  return 0;
}

struct fd_mlx5_queue_layout {
  uint rx_depth;
  uint tx_depth;

  ulong rx_cq_off;
  ulong tx_cq_off;
  ulong rq_off;
  ulong sq_off;

  ulong rx_cq_db_off;
  ulong tx_cq_db_off;
  ulong qp_db_off;
  ulong footprint;
};
typedef struct fd_mlx5_queue_layout fd_mlx5_queue_layout_t;

static fd_mlx5_queue_layout_t *
fd_mlx5_queue_layout_init( fd_mlx5_queue_layout_t * layout,
                           uint                      rx_depth,
                           uint                      tx_depth,
                           uint                      max_recv_wr,
                           uint                      max_send_wqebb,
                           uint                      max_cqe ) {
  if( FD_UNLIKELY( !layout ) ) {
    errno = EINVAL;
    return NULL;
  }
  fd_memset( layout, 0, sizeof(*layout) );
  if( FD_UNLIKELY( !fd_uint_is_pow2( rx_depth ) || !fd_uint_is_pow2( tx_depth ) ||
                   rx_depth>max_recv_wr || tx_depth>max_send_wqebb ||
                   rx_depth-1U>max_cqe || tx_depth-1U>max_cqe ) ) {
    errno = EINVAL;
    return NULL;
  }

  layout->rx_depth = rx_depth;
  layout->tx_depth = tx_depth;
  ulong off = 0UL;
  if( FD_UNLIKELY( fd_mlx5_layout_region( &off, rx_depth, FD_MLX5_CQE_SZ,    &layout->rx_cq_off ) ||
                   fd_mlx5_layout_region( &off, tx_depth, FD_MLX5_CQE_SZ,    &layout->tx_cq_off ) ||
                   fd_mlx5_layout_region( &off, rx_depth, FD_MLX5_RQ_WQE_SZ, &layout->rq_off    ) ||
                   fd_mlx5_layout_region( &off, tx_depth, FD_MLX5_WQEBB_SZ,  &layout->sq_off    ) ||
                   off>ULONG_MAX-FD_MLX5_PAGE_SZ ) ) {
    fd_memset( layout, 0, sizeof(*layout) );
    errno = EOVERFLOW;
    return NULL;
  }
  layout->rx_cq_db_off = off;
  layout->tx_cq_db_off = off + FD_MLX5_DBREC_SZ;
  layout->qp_db_off    = off + 2UL*FD_MLX5_DBREC_SZ;
  layout->footprint    = off + FD_MLX5_PAGE_SZ;
  return layout;
}

ulong
fd_mlx5_queue_footprint( uint rx_depth,
                         uint tx_depth ) {
  fd_mlx5_queue_layout_t layout[1];
  if( FD_UNLIKELY( !fd_mlx5_queue_layout_init( layout, rx_depth, tx_depth,
                                               UINT_MAX, UINT_MAX, UINT_MAX ) ) ) return 0UL;
  return layout->footprint;
}

static void *
fd_mlx5_queue_mem_init( void *                         memory,
                        fd_mlx5_queue_layout_t const * layout ) {
  if( FD_UNLIKELY( !memory || !layout || !layout->footprint ||
                   !fd_ulong_is_aligned( (ulong)memory, FD_MLX5_PAGE_SZ ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  fd_memset( memory, 0, layout->footprint );
  fd_mlx5_cqe_t * rx_cq = (fd_mlx5_cqe_t *)((uchar *)memory+layout->rx_cq_off);
  fd_mlx5_cqe_t * tx_cq = (fd_mlx5_cqe_t *)((uchar *)memory+layout->tx_cq_off);
  for( uint i=0U; i<layout->rx_depth; i++ ) rx_cq[ i ].bytes[ FD_MLX5_CQE_OP_OWN_OFF ] = (uchar)(FD_MLX5_CQE_INVALID<<4);
  for( uint i=0U; i<layout->tx_depth; i++ ) tx_cq[ i ].bytes[ FD_MLX5_CQE_OP_OWN_OFF ] = (uchar)(FD_MLX5_CQE_INVALID<<4);
  return memory;
}

fd_mlx5_t *
fd_mlx5_init( fd_mlx5_t * mlx5,
              char const * rdma_name,
              uint         port_num,
              void *       queue_memory,
              uint         rx_depth,
              uint         tx_depth,
              ulong *      rx_user_data,
              ulong *      tx_user_data,
              void *       packet_memory,
              ulong        packet_memory_sz ) {
  if( FD_UNLIKELY( !mlx5 || !queue_memory || !rx_user_data || !tx_user_data ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_memset( mlx5, 0, sizeof(*mlx5) );
  fd_mlx5_caps_t caps[1];
  fd_mlx5_pd_t   pd[1];
  uint           uar_page_id;
  uint           rx_cq_handle;
  uint           tx_cq_handle;
  uint           lkey;
  fd_mlx5_queue_layout_t layout[1];
  if( FD_UNLIKELY( !fd_mlx5_context_init( &mlx5->context, caps, rdma_name, port_num ) ||
                   !fd_mlx5_queue_layout_init( layout, rx_depth, tx_depth, caps->max_recv_wr,
                                               caps->max_send_wqebb, caps->max_cqe ) ||
                   !fd_mlx5_queue_mem_init( queue_memory, layout ) ||
                   !fd_mlx5_uar_init( &mlx5->uar, &mlx5->context, caps->bf_reg_size, &uar_page_id ) ||
                   !fd_mlx5_cq_init( &mlx5->rx_cq, &mlx5->context, &mlx5->uar,
                                     uar_page_id, caps->max_cqe, &rx_cq_handle,
                                     (uchar *)queue_memory+layout->rx_cq_off,
                                     (uint *)((uchar *)queue_memory+layout->rx_cq_db_off), rx_depth ) ||
                   !fd_mlx5_cq_init( &mlx5->tx_cq, &mlx5->context, &mlx5->uar,
                                     uar_page_id, caps->max_cqe, &tx_cq_handle,
                                     (uchar *)queue_memory+layout->tx_cq_off,
                                     (uint *)((uchar *)queue_memory+layout->tx_cq_db_off), tx_depth ) ||
                   !fd_mlx5_pd_init( pd, &mlx5->context ) ||
                   !fd_mlx5_mr_init( &lkey, pd, packet_memory, packet_memory_sz, caps->max_mr_size ) ||
                   !fd_mlx5_qp_init( &mlx5->qp, pd, &mlx5->rx_cq, &mlx5->tx_cq, &mlx5->uar,
                                     rx_cq_handle, tx_cq_handle, uar_page_id,
                                     caps->bf_reg_size, caps->eth_min_inline_sz,
                                     (uchar *)queue_memory+layout->rq_off,
                                     (uchar *)queue_memory+layout->sq_off,
                                     rx_user_data, tx_user_data,
                                     (uint *)((uchar *)queue_memory+layout->qp_db_off) ) ||
                   !fd_mlx5_qp_start( &mlx5->qp ) ) ) return NULL;
  mlx5->qp.lkey = lkey;
  return mlx5;
}

static int
fd_mlx5_uverbs_words( ulong   sz,
                      ulong   word_sz,
                      ushort * words ) {
  if( FD_UNLIKELY( (sz % word_sz) || (sz / word_sz)>USHORT_MAX ) ) return FD_MLX5_ERR_INVAL;
  *words = (ushort)(sz / word_sz);
  return FD_MLX5_SUCCESS;
}

static int
fd_mlx5_uverbs_cmd_hdr_init( struct ib_uverbs_cmd_hdr * hdr,
                             uint                        command,
                             ulong                       request_sz,
                             ulong                       response_sz ) {
  if( FD_UNLIKELY( !hdr || command>IB_USER_VERBS_CMD_COMMAND_MASK || request_sz<sizeof(*hdr) ) )
    return FD_MLX5_ERR_INVAL;

  ushort in_words;
  ushort out_words;
  if( FD_UNLIKELY( fd_mlx5_uverbs_words( request_sz,  4UL, &in_words  ) ||
                   fd_mlx5_uverbs_words( response_sz, 4UL, &out_words ) ) )
    return FD_MLX5_ERR_INVAL;

  hdr->command   = command;
  hdr->in_words  = in_words;
  hdr->out_words = out_words;
  return FD_MLX5_SUCCESS;
}

static int
fd_mlx5_uverbs_ex_hdr_init( fd_mlx5_uverbs_ex_hdr_t * hdr,
                            uint                       command,
                            ulong                      core_request_sz,
                            ulong                      request_sz,
                            void *                     response,
                            ulong                      core_response_sz,
                            ulong                      response_sz ) {
  ulong const hdr_sz = sizeof(*hdr);
  if( FD_UNLIKELY( !hdr || command>IB_USER_VERBS_CMD_COMMAND_MASK ||
                   core_request_sz<hdr_sz || request_sz<core_request_sz ||
                   response_sz<core_response_sz || (response_sz && !response) ) )
    return FD_MLX5_ERR_INVAL;

  ushort core_in_words;
  ushort core_out_words;
  ushort provider_in_words;
  ushort provider_out_words;
  if( FD_UNLIKELY( fd_mlx5_uverbs_words( core_request_sz-hdr_sz,         8UL, &core_in_words     ) ||
                   fd_mlx5_uverbs_words( core_response_sz,              8UL, &core_out_words    ) ||
                   fd_mlx5_uverbs_words( request_sz-core_request_sz,    8UL, &provider_in_words ) ||
                   fd_mlx5_uverbs_words( response_sz-core_response_sz,  8UL, &provider_out_words) ) )
    return FD_MLX5_ERR_INVAL;

  hdr->cmd.command           = IB_USER_VERBS_CMD_FLAG_EXTENDED | command;
  hdr->cmd.in_words          = core_in_words;
  hdr->cmd.out_words         = core_out_words;
  hdr->ex.response           = (ulong)response;
  hdr->ex.provider_in_words  = provider_in_words;
  hdr->ex.provider_out_words = provider_out_words;
  hdr->ex.cmd_hdr_reserved   = 0U;
  return FD_MLX5_SUCCESS;
}

static int
fd_mlx5_create_udp_flow_req_init( fd_mlx5_create_udp_flow_req_t *     req,
                                  struct ib_uverbs_create_flow_resp * resp,
                                  uint                                qp_handle,
                                  uint                                port_num,
                                  uint                                dst_ip,
                                  ushort                              dst_port ) {
  if( FD_UNLIKELY( !req || !resp || !port_num || port_num>UCHAR_MAX || !dst_port ) )
    return FD_MLX5_ERR_INVAL;

  fd_memset( req,  0, sizeof(*req ) );
  fd_memset( resp, 0, sizeof(*resp) );
  ulong const core_req_sz = offsetof( fd_mlx5_create_udp_flow_req_t, mlx5_ncounters_data );
  if( FD_UNLIKELY( fd_mlx5_uverbs_ex_hdr_init( &req->hdr, IB_USER_VERBS_EX_CMD_CREATE_FLOW,
                                               core_req_sz, sizeof(*req), resp,
                                               sizeof(*resp), sizeof(*resp) ) ) )
    return FD_MLX5_ERR_INVAL;

  req->qp_handle    = qp_handle;
  req->size         = sizeof(req->eth)+sizeof(req->ipv4)+sizeof(req->udp);
  req->num_of_specs = 3U;
  req->port         = (uchar)port_num;
  req->eth.type     = FD_MLX5_FLOW_SPEC_ETH;
  req->eth.size     = sizeof(req->eth);
  req->eth.val.ether_type  = fd_ushort_bswap( 0x0800U );
  req->eth.mask.ether_type = USHORT_MAX;
  req->ipv4.type    = FD_MLX5_FLOW_SPEC_IPV4;
  req->ipv4.size    = sizeof(req->ipv4);
  req->ipv4.val.dst_ip  = dst_ip;
  req->ipv4.mask.dst_ip = dst_ip ? UINT_MAX : 0U;
  req->udp.type     = FD_MLX5_FLOW_SPEC_UDP;
  req->udp.size     = sizeof(req->udp);
  req->udp.val.dst_port  = fd_ushort_bswap( dst_port );
  req->udp.mask.dst_port = USHORT_MAX;
  return FD_MLX5_SUCCESS;
}
