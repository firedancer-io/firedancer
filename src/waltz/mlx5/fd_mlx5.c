#include "fd_mlx5_private.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define FD_MLX5_PATH_MAX (256UL)
#define FD_MLX5_FLOW_SPEC_ETH (0x20U)
#define FD_MLX5_FLOW_SPEC_IPV4 (0x30U)
#define FD_MLX5_FLOW_SPEC_UDP  (0x41U)

static inline void
fd_mlx5_dma_to_device( void ) {
#if FD_HAS_X86
  FD_COMPILER_MFENCE();
#elif FD_HAS_ARM
  __asm__ __volatile__( "dmb oshst" ::: "memory" );
#else
  FD_HW_MFENCE_ST();
#endif
}

static inline void
fd_mlx5_dma_from_device( void ) {
#if FD_HAS_X86
  __asm__ __volatile__( "lfence" ::: "memory" );
#elif FD_HAS_ARM
  __asm__ __volatile__( "dmb oshld" ::: "memory" );
#else
  FD_HW_MFENCE();
#endif
}

static inline void
fd_mlx5_mmio_wc_fence( void ) {
#if FD_HAS_X86
  __asm__ __volatile__( "sfence" ::: "memory" );
#elif FD_HAS_ARM
  __asm__ __volatile__( "dsb st" ::: "memory" );
#else
  FD_HW_MFENCE_ST();
#endif
}

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
fd_mlx5_resolve_uverbs( fd_mlx5_context_t * ctx,
                        char const *         rdma_name ) {
  if( FD_UNLIKELY( !fd_mlx5_name_valid( rdma_name, FD_MLX5_RDMA_NAME_MAX ) ) ) {
    errno = EINVAL;
    return -1;
  }
  if( FD_UNLIKELY( fd_mlx5_check_driver( rdma_name ) ) ) return -1;

  DIR * dir = opendir( "/sys/class/infiniband_verbs" );
  if( FD_UNLIKELY( !dir ) ) return -1;

  char uverbs_name[ FD_MLX5_UVERBS_NAME_MAX ] = {0};
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
    if( FD_UNLIKELY( uverbs_name[0] ) ) {
      err = EEXIST;
      break;
    }
    ulong name_sz = strlen( entry->d_name );
    if( FD_UNLIKELY( name_sz>=sizeof(uverbs_name) ) ) {
      err = ENAMETOOLONG;
      break;
    }
    fd_memcpy( uverbs_name, entry->d_name, name_sz+1UL );
  }
  if( FD_UNLIKELY( closedir( dir ) && !err ) ) err = errno;
  if( FD_UNLIKELY( err ) ) {
    errno = err;
    return -1;
  }
  if( FD_UNLIKELY( !uverbs_name[0] ) ) {
    errno = ENODEV;
    return -1;
  }

  char path[ FD_MLX5_PATH_MAX ];
  if( FD_UNLIKELY( fd_mlx5_read_uint( "/sys/class/infiniband_verbs/abi_version", &ctx->core_abi ) ) ) return -1;
  if( FD_UNLIKELY( fd_mlx5_path( path, sizeof(path),
                                 "/sys/class/infiniband_verbs/%s/abi_version", uverbs_name ) ) ) return -1;
  if( FD_UNLIKELY( fd_mlx5_read_uint( path, &ctx->provider_abi ) ) ) return -1;
  if( FD_UNLIKELY( ctx->core_abi!=FD_MLX5_CORE_ABI || ctx->provider_abi!=FD_MLX5_PROVIDER_ABI ) ) {
    errno = EPROTONOSUPPORT;
    return -1;
  }

  fd_memcpy( ctx->rdma_name,    rdma_name,    strlen(rdma_name)+1UL       );
  fd_memcpy( ctx->uverbs_name, uverbs_name, strlen(uverbs_name)+1UL );
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
fd_mlx5_get_context( fd_mlx5_context_t * ctx ) {
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
  if( FD_UNLIKELY( resp->mlx5.response_length<min_resp_sz ||
                   resp->mlx5.num_ports<ctx->port_num ||
                   resp->mlx5.cqe_version>1U ||
                   resp->mlx5.max_sq_desc_sz<FD_MLX5_WQEBB_SZ ||
                   resp->mlx5.max_rq_desc_sz<FD_MLX5_RQ_WQE_SZ ||
                   !resp->mlx5.max_send_wqebb || !resp->mlx5.max_recv_wr ) ) {
    errno = EPROTONOSUPPORT;
    return -1;
  }

  ctx->num_comp_vectors    = resp->num_comp_vectors;
  ctx->qp_tab_size         = resp->mlx5.qp_tab_size;
  ctx->bf_reg_size         = resp->mlx5.bf_reg_size;
  ctx->tot_bfregs          = resp->mlx5.tot_bfregs;
  ctx->cache_line_size     = resp->mlx5.cache_line_size;
  ctx->max_sq_desc_sz      = resp->mlx5.max_sq_desc_sz;
  ctx->max_rq_desc_sz      = resp->mlx5.max_rq_desc_sz;
  ctx->max_send_wqebb      = resp->mlx5.max_send_wqebb;
  ctx->max_recv_wr         = resp->mlx5.max_recv_wr;
  ctx->num_ports           = resp->mlx5.num_ports;
  ctx->cqe_version         = resp->mlx5.cqe_version;
  ctx->eth_min_inline_mode = resp->mlx5.eth_min_inline;
  switch( resp->mlx5.eth_min_inline ) {
  case MLX5_USER_INLINE_MODE_NONE: ctx->eth_min_inline_sz = 0U;                      break;
  case MLX5_USER_INLINE_MODE_L2:   ctx->eth_min_inline_sz = FD_MLX5_ETH_INLINE_SZ;  break;
  default:
    errno = EPROTONOSUPPORT;
    return -1;
  }
  if( resp->mlx5.response_length>=offsetof(struct mlx5_ib_alloc_ucontext_resp, dump_fill_mkey) ) {
    ctx->log_uar_size      = resp->mlx5.log_uar_size;
    ctx->num_uars_per_page = resp->mlx5.num_uars_per_page;
    ctx->num_dyn_bfregs    = resp->mlx5.num_dyn_bfregs;
  }
  return 0;
}

static int
fd_mlx5_query_device( fd_mlx5_context_t * ctx ) {
  fd_mlx5_query_device_req_t      req [1];
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

  ctx->max_mr_size    = resp->max_mr_size;
  ctx->page_size_cap  = resp->page_size_cap;
  ctx->vendor_id      = resp->vendor_id;
  ctx->vendor_part_id = resp->vendor_part_id;
  ctx->max_qp_wr      = resp->max_qp_wr;
  ctx->max_sge        = resp->max_sge;
  ctx->max_cqe        = resp->max_cqe;
  ctx->phys_port_cnt  = resp->phys_port_cnt;
  if( FD_UNLIKELY( !ctx->max_mr_size || !ctx->max_qp_wr || !ctx->max_sge || !ctx->max_cqe ||
                   ctx->phys_port_cnt<ctx->port_num ) ) {
    errno = EPROTONOSUPPORT;
    return -1;
  }
  return 0;
}

static int
fd_mlx5_query_port( fd_mlx5_context_t * ctx ) {
  fd_mlx5_query_port_req_t          req [1];
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

  ctx->port_cap_flags = resp->port_cap_flags;
  ctx->gid_tbl_len    = resp->gid_tbl_len;
  ctx->port_state     = resp->state;
  ctx->max_mtu        = resp->max_mtu;
  ctx->active_mtu     = resp->active_mtu;
  ctx->phys_state     = resp->phys_state;
  ctx->link_layer     = resp->link_layer;
  if( FD_UNLIKELY( ctx->link_layer!=FD_MLX5_LINK_LAYER_ETHERNET ) ) {
    errno = EPROTONOSUPPORT;
    return -1;
  }
  return 0;
}

fd_mlx5_context_t *
fd_mlx5_context_fini( fd_mlx5_context_t * ctx ) {
  if( FD_UNLIKELY( !ctx ) ) return NULL;
  if( ctx->async_fd>=0 ) close( ctx->async_fd );
  if( ctx->cmd_fd  >=0 ) close( ctx->cmd_fd   );
  fd_memset( ctx, 0, sizeof(*ctx) );
  ctx->cmd_fd   = -1;
  ctx->async_fd = -1;
  return ctx;
}

fd_mlx5_context_t *
fd_mlx5_context_init( fd_mlx5_context_t * ctx,
                      char const *         rdma_name,
                      uint                 port_num ) {
  if( FD_UNLIKELY( !ctx ) ) {
    errno = EINVAL;
    return NULL;
  }
  fd_memset( ctx, 0, sizeof(*ctx) );
  ctx->cmd_fd   = -1;
  ctx->async_fd = -1;
  if( FD_UNLIKELY( !port_num || port_num>(uint)UCHAR_MAX ) ) {
    errno = EINVAL;
    return NULL;
  }
  ctx->port_num = port_num;

  if( FD_UNLIKELY( fd_mlx5_resolve_uverbs( ctx, rdma_name ) ) ) goto fail;

  char path[ FD_MLX5_PATH_MAX ];
  if( FD_UNLIKELY( fd_mlx5_path( path, sizeof(path), "/dev/infiniband/%s", ctx->uverbs_name ) ) ) goto fail;
  ctx->cmd_fd = open( path, O_RDWR | O_CLOEXEC );
  if( FD_UNLIKELY( ctx->cmd_fd<0 ) ) goto fail;

  struct stat st;
  if( FD_UNLIKELY( fstat( ctx->cmd_fd, &st ) ) ) goto fail;
  if( FD_UNLIKELY( !S_ISCHR( st.st_mode ) ) ) {
    errno = ENODEV;
    goto fail;
  }

  if( FD_UNLIKELY( fd_mlx5_get_context( ctx ) ||
                   fd_mlx5_query_device( ctx ) ||
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

fd_mlx5_pd_t *
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
  pd->pdn    = resp->mlx5.pdn;
  return pd;
}

fd_mlx5_pd_t *
fd_mlx5_pd_fini( fd_mlx5_pd_t * pd ) {
  if( FD_UNLIKELY( !pd ) ) return NULL;
  if( FD_LIKELY( !pd->ctx ) ) return pd;
  if( FD_UNLIKELY( pd->ctx->cmd_fd<0 ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_mlx5_dealloc_pd_req_t req[1];
  fd_memset( req, 0, sizeof(req) );
  req->pd_handle = pd->handle;
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_DEALLOC_PD,
                                                sizeof(req), 0UL ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( pd->ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;
  fd_memset( pd, 0, sizeof(*pd) );
  return pd;
}

fd_mlx5_mr_t *
fd_mlx5_mr_init( fd_mlx5_mr_t * mr,
                 fd_mlx5_pd_t * pd,
                 void *          memory,
                 ulong           memory_sz ) {
  if( FD_UNLIKELY( !mr ) ) {
    errno = EINVAL;
    return NULL;
  }
  fd_memset( mr, 0, sizeof(*mr) );
  ulong memory_addr = (ulong)memory;
  if( FD_UNLIKELY( !pd || !pd->ctx || pd->ctx->cmd_fd<0 || !memory || !memory_sz ||
                   memory_sz>ULONG_MAX-memory_addr || memory_sz>pd->ctx->max_mr_size ) ) {
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

  mr->pd        = pd;
  mr->memory    = memory;
  mr->memory_sz = memory_sz;
  mr->handle    = resp->mr_handle;
  mr->lkey      = resp->lkey;
  mr->rkey      = resp->rkey;
  return mr;
}

fd_mlx5_mr_t *
fd_mlx5_mr_fini( fd_mlx5_mr_t * mr ) {
  if( FD_UNLIKELY( !mr ) ) return NULL;
  if( FD_LIKELY( !mr->pd ) ) return mr;
  if( FD_UNLIKELY( !mr->pd->ctx || mr->pd->ctx->cmd_fd<0 ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_mlx5_dereg_mr_req_t req[1];
  fd_memset( req, 0, sizeof(req) );
  req->mr_handle = mr->handle;
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_DEREG_MR,
                                                sizeof(req), 0UL ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( mr->pd->ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;
  fd_memset( mr, 0, sizeof(*mr) );
  return mr;
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

int
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

int
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

fd_mlx5_uar_t *
fd_mlx5_uar_init( fd_mlx5_uar_t *     uar,
                  fd_mlx5_context_t * ctx ) {
  if( FD_UNLIKELY( !uar ) ) {
    errno = EINVAL;
    return NULL;
  }
  fd_memset( uar, 0, sizeof(*uar) );
  if( FD_UNLIKELY( !ctx || ctx->cmd_fd<0 ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( ctx->log_uar_size!=12U || ctx->num_uars_per_page!=1U || ctx->tot_bfregs ||
                   ctx->bf_reg_size<64U || FD_MLX5_BF_OFFSET+ctx->bf_reg_size>FD_MLX5_PAGE_SZ ) ) {
    errno = EPROTONOSUPPORT;
    return NULL;
  }

  ulong mmap_offset = 0UL;
  uint  mmap_sz     = 0U;
  uint  page_id     = 0U;
  fd_mlx5_uar_alloc_req_t req[1];
  if( FD_UNLIKELY( fd_mlx5_uar_alloc_req_init( req, &mmap_offset, &mmap_sz, &page_id ) ) ) {
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

  uar->ctx         = ctx;
  uar->map         = map;
  uar->map_sz      = mmap_sz;
  uar->mmap_offset = mmap_offset;
  uar->reg         = (volatile uchar *)map + FD_MLX5_BF_OFFSET;
  uar->handle      = (uint)handle_raw;
  uar->page_id     = page_id;
  return uar;
}

fd_mlx5_uar_t *
fd_mlx5_uar_fini( fd_mlx5_uar_t * uar ) {
  if( FD_UNLIKELY( !uar ) ) return NULL;
  if( FD_LIKELY( !uar->ctx ) ) return uar;
  if( FD_UNLIKELY( uar->ctx->cmd_fd<0 ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( uar->map ) {
    if( FD_UNLIKELY( munmap( uar->map, uar->map_sz ) ) ) return NULL;
    uar->map = NULL;
    uar->reg = NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_uar_destroy( uar->ctx, uar->handle ) ) ) return NULL;
  fd_memset( uar, 0, sizeof(*uar) );
  return uar;
}

fd_mlx5_cq_t *
fd_mlx5_cq_init( fd_mlx5_cq_t *      cq,
                 fd_mlx5_context_t * ctx,
                 fd_mlx5_uar_t *     uar,
                 void *               entries,
                 uint *               dbrec,
                 uint                 depth ) {
  if( FD_UNLIKELY( !cq ) ) {
    errno = EINVAL;
    return NULL;
  }
  fd_memset( cq, 0, sizeof(*cq) );
  if( FD_UNLIKELY( !ctx || ctx->cmd_fd<0 || !uar || uar->ctx!=ctx || !uar->map ||
                   !entries || !fd_ulong_is_aligned( (ulong)entries, FD_MLX5_PAGE_SZ ) ||
                   !dbrec || !fd_ulong_is_aligned( (ulong)dbrec, FD_MLX5_DBREC_SZ ) ||
                   !fd_uint_is_pow2( depth ) || depth-1U>ctx->max_cqe ||
                   uar->page_id>(uint)USHRT_MAX ) ) {
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
  req->mlx5.uar_page_index = (ushort)uar->page_id;
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

  cq->ctx     = ctx;
  cq->uar     = uar;
  cq->entries = (fd_mlx5_cqe_t *)entries;
  cq->dbrec   = dbrec;
  cq->depth   = depth;
  cq->handle  = resp->cq_handle;
  cq->cqn     = resp->mlx5.cqn;
  return cq;
}

fd_mlx5_cq_t *
fd_mlx5_cq_fini( fd_mlx5_cq_t * cq ) {
  if( FD_UNLIKELY( !cq ) ) return NULL;
  if( FD_LIKELY( !cq->ctx ) ) return cq;
  if( FD_UNLIKELY( cq->ctx->cmd_fd<0 ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_mlx5_destroy_cq_req_t       req [1];
  struct ib_uverbs_destroy_cq_resp resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );
  req->response  = (ulong)resp;
  req->cq_handle = cq->handle;
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_DESTROY_CQ,
                                                sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( cq->ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;
  fd_memset( cq, 0, sizeof(*cq) );
  return cq;
}

int
fd_mlx5_cqe_ready( fd_mlx5_cqe_t const * cqe,
                   uint                  cons_idx,
                   uint                  depth ) {
  fd_mlx5_cqe_wire_t const * wire = (fd_mlx5_cqe_wire_t const *)cqe;
  uchar op_own = FD_VOLATILE_CONST( wire->op_own );
  return ((op_own>>4)!=FD_MLX5_CQE_INVALID) &
         ((op_own & 1U)==!!(cons_idx & depth));
}

uint
fd_mlx5_cqe_opcode( fd_mlx5_cqe_t const * cqe ) {
  return (uint)(((fd_mlx5_cqe_wire_t const *)cqe)->op_own>>4);
}

uint
fd_mlx5_cqe_byte_cnt( fd_mlx5_cqe_t const * cqe ) {
  return fd_uint_bswap( ((fd_mlx5_cqe_wire_t const *)cqe)->byte_cnt );
}

ushort
fd_mlx5_cqe_wqe_counter( fd_mlx5_cqe_t const * cqe ) {
  return fd_ushort_bswap( ((fd_mlx5_cqe_wire_t const *)cqe)->wqe_counter );
}

uchar
fd_mlx5_cqe_vendor_err( fd_mlx5_cqe_t const * cqe ) {
  return ((fd_mlx5_cqe_wire_t const *)cqe)->vendor_err;
}

uchar
fd_mlx5_cqe_syndrome( fd_mlx5_cqe_t const * cqe ) {
  return ((fd_mlx5_cqe_wire_t const *)cqe)->syndrome;
}

uint
fd_mlx5_cqe_sq_opcode( fd_mlx5_cqe_t const * cqe ) {
  return fd_uint_bswap( ((fd_mlx5_cqe_wire_t const *)cqe)->sop_drop_qpn )>>24;
}

int
fd_mlx5_cq_poll_batch( fd_mlx5_cq_t *  cq,
                       fd_mlx5_cqe_t * cqe,
                       uint            cqe_max ) {
  if( FD_UNLIKELY( !cq || !cq->entries || !cq->dbrec ||
                   !fd_uint_is_pow2( cq->depth ) || (!cqe && cqe_max) ) ) {
    errno = EINVAL;
    return -1;
  }

  uint cqe_cnt = 0U;
  uint const max = fd_uint_min( cqe_max, cq->depth );
  for( ; cqe_cnt<max; cqe_cnt++ ) {
    fd_mlx5_cqe_t const * entry = cq->entries + (cq->cons_idx & (cq->depth-1U));
    if( FD_LIKELY( !fd_mlx5_cqe_ready( entry, cq->cons_idx, cq->depth ) ) ) break;
    fd_mlx5_dma_from_device();
    fd_memcpy( cqe+cqe_cnt, entry, sizeof(*cqe) );
    cq->cons_idx++;
  }
  if( FD_UNLIKELY( !cqe_cnt ) ) return 0;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( cq->dbrec[0] ) = fd_uint_bswap( cq->cons_idx & 0xffffffU );
  return (int)cqe_cnt;
}

int
fd_mlx5_cq_poll( fd_mlx5_cq_t *  cq,
                 fd_mlx5_cqe_t * cqe ) {
  return fd_mlx5_cq_poll_batch( cq, cqe, 1U );
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
  qp->state = state;
  return 0;
}

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
                 uint            flags ) {
  if( FD_UNLIKELY( !qp ) ) { errno = EINVAL; return NULL; }
  fd_memset( qp, 0, sizeof(*qp) );
  if( FD_UNLIKELY( !pd || !pd->ctx || !rx_cq || !tx_cq || !uar ||
                   rx_cq->ctx!=pd->ctx || tx_cq->ctx!=pd->ctx || uar->ctx!=pd->ctx ||
                   !rq || !fd_ulong_is_aligned( (ulong)rq, FD_MLX5_PAGE_SZ ) ||
                   !sq || !fd_ulong_is_aligned( (ulong)sq, FD_MLX5_PAGE_SZ ) ||
                   !rx_user_data || !tx_user_data ||
                   !dbrec || !fd_ulong_is_aligned( (ulong)dbrec, FD_MLX5_DBREC_SZ ) ||
                   (flags & ~FD_MLX5_QP_ALLOW_SELF_LOOPBACK_UC) ) ) {
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
  req->send_cq_handle    = tx_cq->handle;
  req->recv_cq_handle    = rx_cq->handle;
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
  req->mlx5.flags        = MLX5_QP_FLAG_UAR_PAGE_INDEX |
                           (flags & FD_MLX5_QP_ALLOW_SELF_LOOPBACK_UC ?
                            MLX5_QP_FLAG_TIR_ALLOW_SELF_LB_UC : 0U);
  req->mlx5.uidx         = 0U;
  req->mlx5.bfreg_index  = uar->page_id;
  req->mlx5.sq_buf_addr  = (ulong)sq;
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_CREATE_QP,
                                                sizeof(req), sizeof(resp) ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( pd->ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;

  qp->ctx         = pd->ctx;
  qp->pd          = pd;
  qp->rx_cq       = rx_cq;
  qp->tx_cq       = tx_cq;
  qp->uar         = uar;
  qp->rq          = (fd_mlx5_rx_wqe_t *)rq;
  qp->sq          = (fd_mlx5_tx_wqe_t *)sq;
  qp->rx_user_data   = rx_user_data;
  qp->tx_user_data   = tx_user_data;
  qp->dbrec       = dbrec;
  qp->rx_depth    = rx_cq->depth;
  qp->tx_depth    = tx_cq->depth;
  qp->handle      = resp->core.qp_handle;
  qp->qpn         = resp->core.qpn;
  qp->state       = FD_MLX5_QPS_RESET;
  qp->bfreg_index = resp->mlx5.bfreg_index;
  qp->rqn         = resp->mlx5.rqn;
  qp->sqn         = resp->mlx5.sqn;
  qp->tirn        = resp->mlx5.tirn;
  qp->tisn        = resp->mlx5.tisn;
  return qp;
}

fd_mlx5_qp_t *
fd_mlx5_qp_start( fd_mlx5_qp_t * qp ) {
  if( FD_UNLIKELY( !qp || !qp->ctx || qp->state!=FD_MLX5_QPS_RESET ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_qp_modify( qp, FD_MLX5_QPS_INIT ) ||
                   fd_mlx5_qp_modify( qp, FD_MLX5_QPS_RTR  ) ||
                   fd_mlx5_qp_modify( qp, FD_MLX5_QPS_RTS  ) ) ) return NULL;
  return qp;
}

fd_mlx5_qp_t *
fd_mlx5_qp_fini( fd_mlx5_qp_t * qp ) {
  if( FD_UNLIKELY( !qp ) ) return NULL;
  if( FD_LIKELY( !qp->ctx ) ) return qp;
  fd_mlx5_destroy_qp_req_t       req [1];
  struct ib_uverbs_destroy_qp_resp resp[1];
  fd_memset( req,  0, sizeof(req ) );
  fd_memset( resp, 0, sizeof(resp) );
  req->response  = (ulong)resp;
  req->qp_handle = qp->handle;
  if( FD_UNLIKELY( fd_mlx5_uverbs_cmd_hdr_init( &req->hdr, IB_USER_VERBS_CMD_DESTROY_QP,
                                                sizeof(req), sizeof(resp) ) ) ) { errno = EINVAL; return NULL; }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( qp->ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;
  fd_memset( qp, 0, sizeof(*qp) );
  return qp;
}

static int
fd_mlx5_qp_post_ready( fd_mlx5_qp_t * qp,
                       uint            wqe_cnt ) {
  if( FD_UNLIKELY( !qp || !qp->ctx || !qp->uar || !qp->uar->reg ||
                   !qp->sq || !qp->tx_user_data || !qp->dbrec || qp->state!=FD_MLX5_QPS_RTS ||
                   !fd_uint_is_pow2( qp->tx_depth ) ||
                   !fd_uint_is_pow2( qp->ctx->bf_reg_size ) ||
                   qp->ctx->bf_reg_size<2U*FD_MLX5_WQEBB_SZ ||
                   (qp->bf_offset && qp->bf_offset!=qp->ctx->bf_reg_size/2U) ) ) {
    errno = EINVAL;
    return -1;
  }
  uint outstanding = qp->sq_prod-qp->sq_cons;
  if( FD_UNLIKELY( outstanding>qp->tx_depth || wqe_cnt>qp->tx_depth-outstanding ) ) {
    errno = ENOSPC;
    return -1;
  }
  return 0;
}

static void
fd_mlx5_qp_ring( fd_mlx5_qp_t *     qp,
                 fd_mlx5_tx_wqe_t * wqe,
                 uint                wqe_cnt,
                 int                 copy_wqe ) {
  qp->sq_prod += wqe_cnt;
  fd_mlx5_dma_to_device();
  FD_VOLATILE( qp->dbrec[1] ) = fd_uint_bswap( qp->sq_prod & 0xffffU );

  fd_mlx5_mmio_wc_fence();
  volatile ulong * bf = (volatile ulong *)(qp->uar->reg + qp->bf_offset);
  if( copy_wqe ) {
    bf[0] = FD_LOAD( ulong, wqe->bytes    );
    bf[1] = FD_LOAD( ulong, wqe->bytes+ 8 );
    bf[2] = FD_LOAD( ulong, wqe->bytes+16 );
    bf[3] = FD_LOAD( ulong, wqe->bytes+24 );
    bf[4] = FD_LOAD( ulong, wqe->bytes+32 );
    bf[5] = FD_LOAD( ulong, wqe->bytes+40 );
    bf[6] = FD_LOAD( ulong, wqe->bytes+48 );
    bf[7] = FD_LOAD( ulong, wqe->bytes+56 );
  } else {
    bf[0] = FD_LOAD( ulong, wqe->bytes );
  }
  fd_mlx5_mmio_wc_fence();
  qp->bf_offset ^= qp->ctx->bf_reg_size/2U;
}

int
fd_mlx5_qp_post_nop( fd_mlx5_qp_t * qp ) {
  if( FD_UNLIKELY( fd_mlx5_qp_post_ready( qp, 1U ) ) ) return -1;

  uint const sq_idx = qp->sq_prod;
  fd_mlx5_tx_wqe_t * wqe = qp->sq + (sq_idx & (qp->tx_depth-1U));
  if( FD_UNLIKELY( !fd_mlx5_nop_wqe_init( wqe, sq_idx, qp->qpn ) ) ) {
    errno = EINVAL;
    return -1;
  }

  fd_mlx5_qp_ring( qp, wqe, 1U, 0 );
  return 0;
}

int
fd_mlx5_qp_post_send( fd_mlx5_qp_t * qp,
                      void const *    frame,
                      ulong           frame_sz,
                      ulong           user_data,
                      uint            lkey,
                      ulong           tx_inline_sz,
                      int             request_cqe ) {
  if( FD_UNLIKELY( !request_cqe ) ) {
    if( FD_UNLIKELY( fd_mlx5_qp_post_ready( qp, 1U ) ) ) return -1;

    uint const sq_idx = qp->sq_prod;
    fd_mlx5_tx_wqe_t * wqe = qp->sq + (sq_idx & (qp->tx_depth-1U));
    if( FD_UNLIKELY( !fd_mlx5_tx_wqe_init( wqe, sq_idx, qp->qpn, frame, frame_sz,
                                           lkey, tx_inline_sz, 0 ) ) ) {
      errno = EINVAL;
      return -1;
    }
    qp->tx_user_data[ sq_idx & (qp->tx_depth-1U) ] = user_data;
    fd_mlx5_qp_ring( qp, wqe, 1U, 1 );
    return 0;
  }

  fd_mlx5_send_t send = { .frame=frame, .frame_sz=frame_sz, .user_data=user_data,
                          .lkey=lkey, .tx_inline_sz=tx_inline_sz };
  return fd_mlx5_qp_post_send_batch( qp, &send, 1U );
}

int
fd_mlx5_qp_post_send_batch( fd_mlx5_qp_t *         qp,
                            fd_mlx5_send_t const * send,
                            uint                    send_cnt ) {
  if( FD_UNLIKELY( !send || !send_cnt ) ) { errno = EINVAL; return -1; }
  if( FD_UNLIKELY( fd_mlx5_qp_post_ready( qp, send_cnt ) ) ) return -1;

  uint const sq_prod = qp->sq_prod;
  for( uint i=0U; i<send_cnt; i++ ) {
    uint sq_idx = sq_prod+i;
    fd_mlx5_send_t const * job = send+i;
    fd_mlx5_tx_wqe_t * wqe = qp->sq + (sq_idx & (qp->tx_depth-1U));
    if( FD_UNLIKELY( !fd_mlx5_tx_wqe_init( wqe, sq_idx, qp->qpn, job->frame, job->frame_sz,
                                           job->lkey, job->tx_inline_sz, i+1U==send_cnt ) ) ) {
      errno = EINVAL;
      return -1;
    }
    qp->tx_user_data[ sq_idx & (qp->tx_depth-1U) ] = job->user_data;
  }

  fd_mlx5_tx_wqe_t * last = qp->sq + ((sq_prod+send_cnt-1U) & (qp->tx_depth-1U));
  fd_mlx5_qp_ring( qp, last, send_cnt, send_cnt==1U );
  return 0;
}

int
fd_mlx5_qp_post_recv( fd_mlx5_qp_t * qp,
                      void *          frame,
                      ulong           frame_sz,
                      ulong           user_data,
                      uint            lkey ) {
  fd_mlx5_recv_t recv = { .frame=frame, .frame_sz=frame_sz, .user_data=user_data, .lkey=lkey };
  return fd_mlx5_qp_post_recv_batch( qp, &recv, 1U );
}

int
fd_mlx5_qp_post_recv_batch( fd_mlx5_qp_t *         qp,
                            fd_mlx5_recv_t const * recv,
                            uint                    recv_cnt ) {
  if( FD_UNLIKELY( !qp || !qp->rq || !qp->rx_user_data || !qp->dbrec ||
                   qp->state!=FD_MLX5_QPS_RTS || !fd_uint_is_pow2( qp->rx_depth ) ||
                   !recv || !recv_cnt ) ) {
    errno = EINVAL;
    return -1;
  }
  uint outstanding = qp->rq_prod-qp->rq_cons;
  if( FD_UNLIKELY( outstanding>qp->rx_depth || recv_cnt>qp->rx_depth-outstanding ) ) {
    errno = ENOSPC;
    return -1;
  }

  uint const rq_prod = qp->rq_prod;
  for( uint i=0U; i<recv_cnt; i++ ) {
    fd_mlx5_recv_t const * job = recv+i;
    fd_mlx5_rx_wqe_t * wqe = qp->rq + ((rq_prod+i) & (qp->rx_depth-1U));
    if( FD_UNLIKELY( !fd_mlx5_rx_wqe_init( wqe, job->frame, job->frame_sz, job->lkey ) ) ) {
      errno = EINVAL;
      return -1;
    }
    qp->rx_user_data[ (rq_prod+i) & (qp->rx_depth-1U) ] = job->user_data;
  }
  qp->rq_prod += recv_cnt;
  fd_mlx5_dma_to_device();
  FD_VOLATILE( qp->dbrec[0] ) = fd_uint_bswap( qp->rq_prod & 0xffffU );
  return 0;
}

int
fd_mlx5_qp_tx_reclaim( fd_mlx5_qp_t *        qp,
                       fd_mlx5_cqe_t const * cqe ) {
  if( FD_UNLIKELY( !qp || !cqe || !fd_uint_is_pow2( qp->tx_depth ) ||
                   (fd_mlx5_cqe_opcode( cqe )!=FD_MLX5_CQE_REQ &&
                    fd_mlx5_cqe_opcode( cqe )!=FD_MLX5_CQE_REQ_ERR) ) ) {
    errno = EINVAL;
    return -1;
  }

  uint distance = (uint)(ushort)(fd_mlx5_cqe_wqe_counter( cqe )-(ushort)qp->sq_cons);
  uint outstanding = qp->sq_prod-qp->sq_cons;
  if( FD_UNLIKELY( outstanding>qp->tx_depth || distance>=outstanding ) ) {
    errno = EPROTO;
    return -1;
  }
  qp->sq_cons += distance+1U;
  return 0;
}

int
fd_mlx5_qp_rx_reclaim( fd_mlx5_qp_t *        qp,
                       fd_mlx5_cqe_t const * cqe ) {
  uint opcode = cqe ? fd_mlx5_cqe_opcode( cqe ) : FD_MLX5_CQE_INVALID;
  if( FD_UNLIKELY( !qp || !fd_uint_is_pow2( qp->rx_depth ) ||
                   (opcode!=FD_MLX5_CQE_RESP_SEND && opcode!=FD_MLX5_CQE_RESP_ERR) ) ) {
    errno = EINVAL;
    return -1;
  }

  uint distance = (uint)(ushort)(fd_mlx5_cqe_wqe_counter( cqe )-(ushort)qp->rq_cons);
  uint outstanding = qp->rq_prod-qp->rq_cons;
  if( FD_UNLIKELY( outstanding>qp->rx_depth || distance>=outstanding ) ) {
    errno = EPROTO;
    return -1;
  }
  qp->rq_cons += distance+1U;
  return 0;
}

int
fd_mlx5_qp_poll_rx( fd_mlx5_qp_t *      qp,
                    fd_mlx5_rx_comp_t * comp,
                    uint                 comp_max ) {
  if( FD_UNLIKELY( !qp || !qp->rx_cq || !qp->rx_user_data || !comp || !comp_max || comp_max>64U ) ) {
    errno = EINVAL;
    return -1;
  }

  fd_mlx5_cqe_t cqe[ 64 ];
  int comp_cnt = fd_mlx5_cq_poll_batch( qp->rx_cq, cqe, comp_max );
  if( FD_UNLIKELY( comp_cnt<0 ) ) return -1;
  for( uint i=0U; i<(uint)comp_cnt; i++ ) {
    uint wqe_counter = fd_mlx5_cqe_wqe_counter( cqe+i );
    comp[ i ] = (fd_mlx5_rx_comp_t) {
      .user_data   = qp->rx_user_data[ wqe_counter & (qp->rx_depth-1U) ],
      .byte_len = fd_mlx5_cqe_byte_cnt( cqe+i ),
      .opcode   = fd_mlx5_cqe_opcode( cqe+i )
    };
    if( FD_UNLIKELY( fd_mlx5_qp_rx_reclaim( qp, cqe+i ) ) ) return -1;
  }
  return comp_cnt;
}

int
fd_mlx5_qp_poll_tx( fd_mlx5_qp_t *      qp,
                    fd_mlx5_tx_comp_t * comp,
                    uint                 comp_max ) {
  if( FD_UNLIKELY( !qp || !qp->tx_cq || !qp->tx_user_data || !comp || !comp_max ) ) {
    errno = EINVAL;
    return -1;
  }

  fd_mlx5_cqe_t cqe[1];
  int cqe_cnt = fd_mlx5_cq_poll( qp->tx_cq, cqe );
  if( FD_UNLIKELY( cqe_cnt<=0 ) ) return cqe_cnt;
  uint const sq_cons = qp->sq_cons;
  uint const comp_cnt = (uint)(ushort)(fd_mlx5_cqe_wqe_counter( cqe )-(ushort)sq_cons)+1U;
  if( FD_UNLIKELY( comp_cnt>comp_max ) ) { errno = ENOSPC; return -1; }
  uint const opcode = fd_mlx5_cqe_opcode( cqe );
  if( FD_UNLIKELY( fd_mlx5_qp_tx_reclaim( qp, cqe ) ) ) return -1;
  for( uint i=0U; i<comp_cnt; i++ ) {
    comp[ i ] = (fd_mlx5_tx_comp_t) {
      .user_data = qp->tx_user_data[ (sq_cons+i) & (qp->tx_depth-1U) ],
      .opcode = opcode
    };
  }
  return (int)comp_cnt;
}

fd_mlx5_flow_t *
fd_mlx5_flow_init_eth( fd_mlx5_flow_t * flow,
                       fd_mlx5_qp_t *   qp,
                       uchar const      dst_mac[6],
                       ushort           ether_type ) {
  if( FD_UNLIKELY( !flow ) ) { errno = EINVAL; return NULL; }
  fd_memset( flow, 0, sizeof(*flow) );
  if( FD_UNLIKELY( !qp || !qp->ctx || qp->state!=FD_MLX5_QPS_RTS || !dst_mac ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_mlx5_create_flow_req_t        req [1];
  struct ib_uverbs_create_flow_resp resp[1];
  if( FD_UNLIKELY( fd_mlx5_create_flow_req_init( req, resp, qp->handle,
                                                 qp->ctx->port_num, dst_mac,
                                                 ether_type ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( qp->ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;
  flow->qp     = qp;
  flow->handle = resp->flow_handle;
  return flow;
}

fd_mlx5_flow_t *
fd_mlx5_flow_init_udp( fd_mlx5_flow_t * flow,
                       fd_mlx5_qp_t *   qp,
                       uint             dst_ip,
                       ushort           dst_port ) {
  if( FD_UNLIKELY( !flow ) ) { errno = EINVAL; return NULL; }
  fd_memset( flow, 0, sizeof(*flow) );
  if( FD_UNLIKELY( !qp || !qp->ctx || qp->state!=FD_MLX5_QPS_RTS || !dst_port ) ) {
    errno = EINVAL;
    return NULL;
  }

  fd_mlx5_create_udp_flow_req_t   req [1];
  struct ib_uverbs_create_flow_resp resp[1];
  if( FD_UNLIKELY( fd_mlx5_create_udp_flow_req_init( req, resp, qp->handle,
                                                     qp->ctx->port_num, dst_ip,
                                                     dst_port ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( qp->ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;
  flow->qp     = qp;
  flow->handle = resp->flow_handle;
  return flow;
}

fd_mlx5_flow_t *
fd_mlx5_flow_fini( fd_mlx5_flow_t * flow ) {
  if( FD_UNLIKELY( !flow ) ) return NULL;
  if( FD_LIKELY( !flow->qp ) ) return flow;

  fd_mlx5_destroy_flow_req_t req[1];
  if( FD_UNLIKELY( fd_mlx5_destroy_flow_req_init( req, flow->handle ) ) ) {
    errno = EINVAL;
    return NULL;
  }
  if( FD_UNLIKELY( fd_mlx5_write_cmd( flow->qp->ctx->cmd_fd, req, sizeof(req) ) ) ) return NULL;
  fd_memset( flow, 0, sizeof(*flow) );
  return flow;
}

static int
fd_mlx5_layout_region( ulong * off,
                       ulong   cnt,
                       ulong   elem_sz,
                       ulong * region_off,
                       ulong * region_sz ) {
  if( FD_UNLIKELY( cnt>ULONG_MAX/elem_sz ) ) return -1;
  ulong sz = cnt*elem_sz;
  if( FD_UNLIKELY( *off>ULONG_MAX-sz ) ) return -1;
  *region_off = *off;
  *region_sz  = sz;
  ulong end = *off+sz;
  if( FD_UNLIKELY( end>ULONG_MAX-(FD_MLX5_PAGE_SZ-1UL) ) ) return -1;
  *off = fd_ulong_align_up( end, FD_MLX5_PAGE_SZ );
  return 0;
}

fd_mlx5_queue_layout_t *
fd_mlx5_queue_layout_init( fd_mlx5_queue_layout_t * layout,
                           fd_mlx5_context_t const * ctx,
                           uint                      rx_depth,
                           uint                      tx_depth ) {
  if( FD_UNLIKELY( !layout ) ) {
    errno = EINVAL;
    return NULL;
  }
  fd_memset( layout, 0, sizeof(*layout) );
  if( FD_UNLIKELY( !ctx || !fd_uint_is_pow2( rx_depth ) || !fd_uint_is_pow2( tx_depth ) ||
                   rx_depth>ctx->max_recv_wr || tx_depth>ctx->max_send_wqebb ||
                   rx_depth-1U>ctx->max_cqe || tx_depth-1U>ctx->max_cqe ) ) {
    errno = EINVAL;
    return NULL;
  }

  layout->rx_depth = rx_depth;
  layout->tx_depth = tx_depth;
  ulong off = 0UL;
  if( FD_UNLIKELY( fd_mlx5_layout_region( &off, rx_depth, FD_MLX5_CQE_SZ,    &layout->rx_cq_off, &layout->rx_cq_sz ) ||
                   fd_mlx5_layout_region( &off, tx_depth, FD_MLX5_CQE_SZ,    &layout->tx_cq_off, &layout->tx_cq_sz ) ||
                   fd_mlx5_layout_region( &off, rx_depth, FD_MLX5_RQ_WQE_SZ, &layout->rq_off,    &layout->rq_sz    ) ||
                   fd_mlx5_layout_region( &off, tx_depth, FD_MLX5_WQEBB_SZ,  &layout->sq_off,    &layout->sq_sz    ) ||
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
  fd_mlx5_context_t limits = {
    .max_recv_wr    = UINT_MAX,
    .max_send_wqebb = UINT_MAX,
    .max_cqe        = UINT_MAX
  };
  fd_mlx5_queue_layout_t layout[1];
  if( FD_UNLIKELY( !fd_mlx5_queue_layout_init( layout, &limits, rx_depth, tx_depth ) ) ) return 0UL;
  return layout->footprint;
}

void *
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
  for( uint i=0U; i<layout->rx_depth; i++ ) ((fd_mlx5_cqe_wire_t *)(rx_cq+i))->op_own = (uchar)(FD_MLX5_CQE_INVALID<<4);
  for( uint i=0U; i<layout->tx_depth; i++ ) ((fd_mlx5_cqe_wire_t *)(tx_cq+i))->op_own = (uchar)(FD_MLX5_CQE_INVALID<<4);
  return memory;
}

static int
fd_mlx5_uverbs_words( ulong   sz,
                      ulong   word_sz,
                      ushort * words ) {
  if( FD_UNLIKELY( (sz % word_sz) || (sz / word_sz)>USHORT_MAX ) ) return FD_MLX5_ERR_INVAL;
  *words = (ushort)(sz / word_sz);
  return FD_MLX5_SUCCESS;
}

int
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

int
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

  hdr->cmd.command       = IB_USER_VERBS_CMD_FLAG_EXTENDED | command;
  hdr->cmd.in_words      = core_in_words;
  hdr->cmd.out_words     = core_out_words;
  hdr->ex.response       = (ulong)response;
  hdr->ex.provider_in_words  = provider_in_words;
  hdr->ex.provider_out_words = provider_out_words;
  hdr->ex.cmd_hdr_reserved   = 0U;
  return FD_MLX5_SUCCESS;
}

int
fd_mlx5_create_flow_req_init( fd_mlx5_create_flow_req_t *        req,
                              struct ib_uverbs_create_flow_resp * resp,
                              uint                               qp_handle,
                              uint                               port_num,
                              uchar const                         dst_mac[6],
                              ushort                              ether_type ) {
  if( FD_UNLIKELY( !req || !resp || !dst_mac || !port_num || port_num>UCHAR_MAX ) )
    return FD_MLX5_ERR_INVAL;

  fd_memset( req,  0, sizeof(*req ) );
  fd_memset( resp, 0, sizeof(*resp) );
  ulong const core_req_sz = offsetof( fd_mlx5_create_flow_req_t, mlx5_ncounters_data );
  if( FD_UNLIKELY( fd_mlx5_uverbs_ex_hdr_init( &req->hdr, IB_USER_VERBS_EX_CMD_CREATE_FLOW,
                                               core_req_sz, sizeof(*req), resp,
                                               sizeof(*resp), sizeof(*resp) ) ) )
    return FD_MLX5_ERR_INVAL;

  req->qp_handle    = qp_handle;
  req->type         = 0U;
  req->size         = sizeof(req->eth);
  req->num_of_specs = 1U;
  req->port         = (uchar)port_num;
  req->eth.type     = FD_MLX5_FLOW_SPEC_ETH;
  req->eth.size     = sizeof(req->eth);
  fd_memcpy( req->eth.val.dst_mac, dst_mac, 6UL );
  fd_memset( req->eth.mask.dst_mac, 0xff, 6UL );
  req->eth.val.ether_type  = fd_ushort_bswap( ether_type );
  req->eth.mask.ether_type = USHORT_MAX;
  return FD_MLX5_SUCCESS;
}

int
fd_mlx5_create_udp_flow_req_init( fd_mlx5_create_udp_flow_req_t * req,
                                  struct ib_uverbs_create_flow_resp * resp,
                                  uint                              qp_handle,
                                  uint                              port_num,
                                  uint                              dst_ip,
                                  ushort                            dst_port ) {
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

int
fd_mlx5_destroy_flow_req_init( fd_mlx5_destroy_flow_req_t * req,
                               uint                         handle ) {
  if( FD_UNLIKELY( !req ) ) return FD_MLX5_ERR_INVAL;
  fd_memset( req, 0, sizeof(*req) );
  if( FD_UNLIKELY( fd_mlx5_uverbs_ex_hdr_init( &req->hdr, IB_USER_VERBS_EX_CMD_DESTROY_FLOW,
                                               sizeof(*req), sizeof(*req), NULL, 0UL, 0UL ) ) )
    return FD_MLX5_ERR_INVAL;
  req->flow_handle = handle;
  return FD_MLX5_SUCCESS;
}

ulong
fd_mlx5_uar_mmap_offset( uint  command,
                         uint  index,
                         ulong page_sz ) {
  if( FD_UNLIKELY( command>0xffU || !fd_ulong_is_pow2( page_sz ) ) ) return ULONG_MAX;

  ulong page_off;
  if( command==MLX5_IB_MMAP_ALLOC_WC ) {
    if( FD_UNLIKELY( index>0xffffU ) ) return ULONG_MAX;
    page_off = ((ulong)(index>>8)<<16) | ((ulong)command<<8) | (ulong)(index & 0xffU);
  } else {
    if( FD_UNLIKELY( index>0xffU ) ) return ULONG_MAX;
    page_off = ((ulong)command<<8) | (ulong)index;
  }

  if( FD_UNLIKELY( page_off>ULONG_MAX/page_sz ) ) return ULONG_MAX;
  return page_off * page_sz;
}

fd_mlx5_tx_wqe_t *
fd_mlx5_tx_wqe_init( fd_mlx5_tx_wqe_t * wqe,
                     uint                sq_idx,
                     uint                qpn,
                     void const *        frame,
                     ulong               frame_sz,
                     uint                lkey,
                     ulong               tx_inline_sz,
                     int                 request_cqe ) {
  if( FD_UNLIKELY( !wqe || !frame || !frame_sz || frame_sz>UINT_MAX || qpn>0xffffffU ||
                   (tx_inline_sz!=0UL && tx_inline_sz!=FD_MLX5_ETH_INLINE_SZ) ||
                   tx_inline_sz>frame_sz ) )
    return NULL;

  fd_memset( wqe, 0, sizeof(*wqe) );

  uint const ds = tx_inline_sz ? 4U : 3U;
  fd_mlx5_wqe_ctrl_wire_t * ctrl = (fd_mlx5_wqe_ctrl_wire_t *)wqe;
  fd_mlx5_wqe_eth_wire_t * eth = (fd_mlx5_wqe_eth_wire_t *)(wqe->bytes+sizeof(*ctrl));
  ctrl->opmod_idx_opcode = fd_uint_bswap( ((sq_idx & 0xffffU)<<8) | FD_MLX5_OPCODE_SEND );
  ctrl->qpn_ds           = fd_uint_bswap( (qpn<<8) | ds );
  ctrl->flags            = request_cqe ? FD_MLX5_WQE_CTRL_CQ_UPDATE : 0U;

  eth->inline_hdr_sz = fd_ushort_bswap( (ushort)tx_inline_sz );
  if( tx_inline_sz ) fd_memcpy( eth->inline_hdr, frame, tx_inline_sz );

  ulong const data_off = tx_inline_sz ? 48UL : 32UL;
  fd_mlx5_wqe_data_wire_t * data = (fd_mlx5_wqe_data_wire_t *)(wqe->bytes+data_off);
  data->byte_cnt = fd_uint_bswap( (uint)(frame_sz-tx_inline_sz) );
  data->lkey     = fd_uint_bswap( lkey );
  data->addr     = fd_ulong_bswap( (ulong)frame+tx_inline_sz );
  return wqe;
}

fd_mlx5_tx_wqe_t *
fd_mlx5_nop_wqe_init( fd_mlx5_tx_wqe_t * wqe,
                      uint                sq_idx,
                      uint                qpn ) {
  if( FD_UNLIKELY( !wqe || qpn>0xffffffU ) ) return NULL;

  fd_memset( wqe, 0, sizeof(*wqe) );
  fd_mlx5_wqe_ctrl_wire_t * ctrl = (fd_mlx5_wqe_ctrl_wire_t *)wqe;
  ctrl->opmod_idx_opcode = fd_uint_bswap( ((sq_idx & 0xffffU)<<8) | FD_MLX5_OPCODE_NOP );
  ctrl->qpn_ds           = fd_uint_bswap( (qpn<<8) | 1U );
  ctrl->flags            = FD_MLX5_WQE_CTRL_CQ_UPDATE;
  return wqe;
}

fd_mlx5_rx_wqe_t *
fd_mlx5_rx_wqe_init( fd_mlx5_rx_wqe_t * wqe,
                     void *              frame,
                     ulong               frame_sz,
                     uint                lkey ) {
  if( FD_UNLIKELY( !wqe || !frame || !frame_sz || frame_sz>UINT_MAX ) ) return NULL;

  fd_mlx5_wqe_data_wire_t * data = (fd_mlx5_wqe_data_wire_t *)wqe;
  data->byte_cnt = fd_uint_bswap( (uint)frame_sz );
  data->lkey     = fd_uint_bswap( lkey );
  data->addr     = fd_ulong_bswap( (ulong)frame );
  return wqe;
}
