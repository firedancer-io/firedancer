#ifndef HEADER_fd_src_util_alloc_fd_alloc_cfg_h
#define HEADER_fd_src_util_alloc_fd_alloc_cfg_h

struct __attribute__((aligned(8))) fd_alloc_sizeclass_cfg {
  uint   block_footprint;
  ushort parent_sizeclass;
  uchar  block_cnt;
  uchar  cgroup_mask;
};

typedef struct fd_alloc_sizeclass_cfg fd_alloc_sizeclass_cfg_t;

#if FD_HAS_ALLOC_CFG_LARGE
/* When selecting cfg_large, please make sure that all instances are
   assigned sufficient memory in workspace. */
#include "fd_alloc_cfg_large.h"
#else
#include "fd_alloc_cfg_small.h"
#endif

#endif /* HEADER_fd_src_util_alloc_fd_alloc_cfg_h */
