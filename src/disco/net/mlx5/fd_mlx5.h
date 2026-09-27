#ifndef HEADER_fd_src_disco_net_mlx5_fd_mlx5_h
#define HEADER_fd_src_disco_net_mlx5_fd_mlx5_h

#if defined(__linux__)

#include "../../../util/bits/fd_bits.h"

#define FD_MLX5_RDMA_NAME_MAX (64UL)

FD_PROTOTYPES_BEGIN

/* fd_mlx5_rdma_dev_find maps interface_name or one of its bond members
   to exactly one Linux RDMA device and port.  It returns 1 on success.
   On failure, it returns 0 and sets errno to ENOENT when no port matches,
   EEXIST when multiple ports match, or the relevant system error.  It
   clears rdma_name and rdma_port on failure. */
int
fd_mlx5_rdma_dev_find( char         rdma_name[ FD_MLX5_RDMA_NAME_MAX ],
                       uint *       rdma_port,
                       char const * interface_name );

int
fd_mlx5_uverbs_avail( void );

/* fd_mlx5_uverbs_modprobe invokes modprobe for ib_uverbs.  is_dry_run=1
   checks module availability without loading it, is_dry_run=0 loads it.
   Returns 0 if modprobe succeeds, otherwise -1. */
int
fd_mlx5_uverbs_modprobe( int is_dry_run );

FD_PROTOTYPES_END

#endif /* defined(__linux__) */

#endif /* HEADER_fd_src_disco_net_mlx5_fd_mlx5_h */
