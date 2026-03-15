#ifndef HEADER_fd_src_util_io_fd_io_uring_register_h
#define HEADER_fd_src_util_io_fd_io_uring_register_h

#include "fd_io_uring_sys.h"

#if defined(__linux__)
#include <linux/io_uring.h>
#endif

#include <errno.h>
#include "../../util/fd_util_base.h"

FD_PROTOTYPES_BEGIN

#if defined(__linux__)

static inline int
fd_io_uring_register_files( int         ring_fd,
                            int const * fds,
                            ulong       fd_cnt ) {
  if( FD_UNLIKELY( fd_cnt > UINT_MAX ) ) return -EINVAL;
  return fd_io_uring_register( ring_fd, FD_IORING_REGISTER_FILES, fds, (uint)fd_cnt );
}

static inline int
fd_io_uring_register_restrictions( int                         ring_fd,
                                   fd_io_uring_restriction_t * res,
                                   uint                        res_cnt ) {
  return fd_io_uring_register( ring_fd, FD_IORING_REGISTER_RESTRICTIONS, res, res_cnt );
}

static inline int
fd_io_uring_enable_rings( int ring_fd ) {
  return fd_io_uring_register( ring_fd, FD_IORING_REGISTER_ENABLE_RINGS, NULL, 0 );
}

#else /* !__linux__ */

static inline int fd_io_uring_register_files( int ring_fd, int const * fds, ulong fd_cnt ) { (void)ring_fd; (void)fds; (void)fd_cnt; return -1; }
static inline int fd_io_uring_register_restrictions( int ring_fd, void * res, uint res_cnt ) { (void)ring_fd; (void)res; (void)res_cnt; return -1; }
static inline int fd_io_uring_enable_rings( int ring_fd ) { (void)ring_fd; return -1; }

#endif /* __linux__ */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_io_fd_io_uring_register_h */
