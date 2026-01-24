#define _GNU_SOURCE
#include "fd_io_uring_sys.h"
#include <sys/syscall.h> /* SYS_* */
#include <unistd.h> /* syscall */

int
fd_io_uring_setup( uint                     entry_cnt,
                   struct io_uring_params * p ) {
  return (int)syscall( SYS_io_uring_setup, entry_cnt, p );
}

int
fd_io_uring_register( int          ring_fd,
                      uint         opcode,
                      void const * arg,
                      uint         arg_cnt ) {
  return (int)syscall( SYS_io_uring_register, ring_fd, opcode, arg, arg_cnt );
}

int
fd_io_uring_enter( int    ring_fd,
                   uint   to_submit,
                   uint   min_complete,
                   uint   flags,
                   void * arg,
                   ulong  arg_sz ) {
  return (int)syscall( SYS_io_uring_enter, ring_fd, to_submit, min_complete, flags, arg, arg_sz );
}
