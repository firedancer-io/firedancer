#ifndef HEADER_fd_src_util_io_fd_io_uring_register_h
#define HEADER_fd_src_util_io_fd_io_uring_register_h

/* fd_io_uring_register.h provides APIs to add file descriptors and
   sandbox restrictions to an ioring. */

#include "fd_io_uring_sys.h"
#include <linux/io_uring.h>
#include <errno.h>
#include "../../util/fd_util_base.h"

FD_PROTOTYPES_BEGIN

static inline int
fd_io_uring_register_files( int         ring_fd,
                            int const * fds,
                            ulong       fd_cnt ) {
  if( FD_UNLIKELY( fd_cnt > UINT_MAX ) ) return -EINVAL;
  return fd_io_uring_register( ring_fd, IORING_REGISTER_FILES, fds, (uint)fd_cnt );
}

static inline int
fd_io_uring_register_restrictions( int                           ring_fd,
                                   struct io_uring_restriction * res,
                                   uint                          res_cnt ) {
  return fd_io_uring_register( ring_fd, IORING_REGISTER_RESTRICTIONS, res, res_cnt );
}

static inline int
fd_io_uring_enable_rings( int ring_fd ) {
  return fd_io_uring_register( ring_fd, IORING_REGISTER_ENABLE_RINGS, NULL, 0 );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_io_fd_io_uring_register_h */
