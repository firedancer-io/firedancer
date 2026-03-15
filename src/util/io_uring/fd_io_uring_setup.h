#ifndef HEADER_fd_src_util_io_fd_io_uring_setup_h
#define HEADER_fd_src_util_io_fd_io_uring_setup_h

#include "fd_io_uring.h"

#if defined(__linux__)
#include <linux/io_uring.h>
#endif

#include "../../util/fd_util_base.h"

FD_PROTOTYPES_BEGIN

#if defined(__linux__)

ulong fd_io_uring_shmem_align( void );
ulong fd_io_uring_shmem_footprint( ulong sq_depth, ulong cq_depth );
fd_io_uring_params_t * fd_io_uring_shmem_setup( fd_io_uring_params_t * params, void * shmem, ulong sq_depth, ulong cq_depth );

FD_FN_UNUSED static fd_io_uring_params_t *
fd_io_uring_params_init( fd_io_uring_params_t * params,
                         uint                   depth ) {
  memset( params, 0, sizeof(fd_io_uring_params_t) );
  params->flags      |= IORING_SETUP_CQSIZE;
  params->sq_entries  = depth;
  params->cq_entries  = depth;
  params->flags      |= IORING_SETUP_SINGLE_ISSUER;
  params->flags      |= IORING_SETUP_R_DISABLED;
  return params;
}

fd_io_uring_t * fd_io_uring_init_shmem( fd_io_uring_t * ring, fd_io_uring_params_t * params, void * shmem, ulong sq_depth, ulong cq_depth );
fd_io_uring_t * fd_io_uring_init_mmap( fd_io_uring_t * ring, fd_io_uring_params_t * params );
void * fd_io_uring_fini( fd_io_uring_t * ring );

#else /* !__linux__ */

static inline ulong fd_io_uring_shmem_align( void ) { return 1UL; }
static inline ulong fd_io_uring_shmem_footprint( ulong sq_depth, ulong cq_depth ) { (void)sq_depth; (void)cq_depth; return 0UL; }
static inline fd_io_uring_t * fd_io_uring_init_shmem( fd_io_uring_t * ring, void * params, void * shmem, ulong sq_depth, ulong cq_depth ) { (void)ring; (void)params; (void)shmem; (void)sq_depth; (void)cq_depth; return NULL; }
static inline void * fd_io_uring_fini( fd_io_uring_t * ring ) { return ring; }

#endif /* __linux__ */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_io_fd_io_uring_setup_h */
