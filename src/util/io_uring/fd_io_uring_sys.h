#ifndef HEADER_fd_src_util_io_fd_io_uring_sys_h
#define HEADER_fd_src_util_io_fd_io_uring_sys_h

/* fd_io_uring_sys.h provides the io_uring syscall API. */

#include "../fd_util_base.h"

FD_PROTOTYPES_BEGIN

/* fd_io_uring_enter wraps the fd_io_uring_enter(2) syscall. */

int
fd_io_uring_enter( int    ring_fd,
                   uint   to_submit,
                   uint   min_complete,
                   uint   flags,
                   void * arg,
                   ulong  arg_sz );

/* fd_io_uring_register wraps the io_uring_register(2) syscall. */

int
fd_io_uring_register( int          ring_fd,
                      uint         opcode,
                      void const * arg,
                      uint         arg_cnt );

/* fd_io_uring_setup wraps the io_uring_setup(2) syscall. */

struct io_uring_params;

int
fd_io_uring_setup( uint                     entry_cnt,
                   struct io_uring_params * p );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_io_fd_io_uring_sys_h */
