#ifndef HEADER_fd_src_util_io_fd_io_uring_setup_h
#define HEADER_fd_src_util_io_fd_io_uring_setup_h

/* fd_io_uring_setup.h provides an API to setup Linux io_uring
   instances. */

#include "fd_io_uring.h"
#include <linux/io_uring.h>
#include "../../util/fd_util_base.h"

FD_PROTOTYPES_BEGIN

/* IORING_SETUP_NO_MMAP related ***************************************/

/* fd_io_uring_shmem_{align,footprint} return the required alignment
   and footprint for a user-managed shared memory region suitable to
   hold io_uring data structures.  This includes the submission queue
   array, the submission queue entries, and the completion queue.
   {sq,cq}_depth must be powers of two.  footprint returns non-zero on
   success, and 0 (silently) if {sq,cq}_depth are invalid. */

ulong
fd_io_uring_shmem_align( void );

ulong
fd_io_uring_shmem_footprint( ulong sq_depth,
                             ulong cq_depth );

/* fd_io_uring_shmem_setup adds a user-managed shared memory region to
   params.  params is zero initialized by the caller.  shmem points to
   a region allocated according to the above align/footprint
   requirements.  Sets the IORING_SETUP_NO_MMAP flag, which instructs
   the kernel to map user memory instead of allocating new rings.

   Returns params on success.  On failure, returns NULL.  Reasons for
   failure include obviously invalid shmem pointer or invalid
   {sq,cq}_depth.  Logs reason for failure to WARNING. */

struct io_uring_params *
fd_io_uring_shmem_setup( struct io_uring_params * params,
                         void *                   shmem,
                         ulong                    sq_depth,
                         ulong                    cq_depth );

/* Setup API **********************************************************/

/* fd_io_uring_params_init initializes default io_uring parameters that
   are compatible with this library.

   - Custom completion queue depth
   - Single issuer thread
   - Rings disabled on startup */

FD_FN_UNUSED static struct io_uring_params *
fd_io_uring_params_init( struct io_uring_params * params,
                         uint                     depth ) {
  memset( params, 0, sizeof(struct io_uring_params) );
  params->flags      |= IORING_SETUP_CQSIZE;
  params->sq_entries  = depth;
  params->cq_entries  = depth;
  params->flags      |= IORING_SETUP_SINGLE_ISSUER;
  params->flags      |= IORING_SETUP_R_DISABLED;
  return params;
}

/* fd_io_uring_init_shmem creates a new io_uring instance (using
   io_uring_setup(2)) with a user-allocated ring.  shmem points to the
   io_uring_shmem allocated ring with {sq,cq}_depth ring space. */

fd_io_uring_t *
fd_io_uring_init_shmem(
    fd_io_uring_t *          ring,
    struct io_uring_params * params, /* modified */
    void *                   shmem,
    ulong                    sq_depth,
    ulong                    cq_depth
);

/* fd_io_uring_init_mmap creates a new io_uring instance (using
   io_uring_setup(2)) with a kernel-allocated ring.  The kernel ring is
   mapped into userspace using mmap.  Uses up MEMLOCK quota. */

fd_io_uring_t *
fd_io_uring_init_mmap(
    fd_io_uring_t *          ring,
    struct io_uring_params * params /* modified */
);

/* fd_io_uring_fini destroys an io_uring instance (using close(2)).  If
   the ring was created with fd_io_uring_init_mmap, calls munmap(2) to
   unregister the kernel rings. */

void *
fd_io_uring_fini( fd_io_uring_t * ring );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_io_fd_io_uring_setup_h */
