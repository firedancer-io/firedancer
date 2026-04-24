struct __attribute__((aligned(8))) fd_alloc_sizeclass_cfg {
  uint   block_footprint;
  ushort parent_sizeclass;
  uchar  block_cnt;
  uchar  cgroup_mask;
};

typedef struct fd_alloc_sizeclass_cfg fd_alloc_sizeclass_cfg_t;

#include "fd_alloc_cfg_large.h"
