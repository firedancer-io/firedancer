#ifndef HEADER_fd_src_util_io_uring_fd_io_uring_h
#define HEADER_fd_src_util_io_uring_fd_io_uring_h

#if defined(__linux__)

#include "fd_io_uring_sys.h"
#include <stdatomic.h>
#include <linux/io_uring.h>

struct fd_io_uring_sq {
  atomic_uint * khead;
  atomic_uint * ktail;
  atomic_uint * kflags;
  atomic_uint * kdropped;
  uint *                array;
  struct io_uring_sqe * sqes;
  uint sqe_head;
  uint sqe_tail;
  uint depth;
};
typedef struct fd_io_uring_sq fd_io_uring_sq_t;

struct fd_io_uring_cq {
  ulong depth;
  atomic_uint * khead;
  atomic_uint * ktail;
  atomic_uint * koverflow;
  struct io_uring_cqe * cqes;
};
typedef struct fd_io_uring_cq fd_io_uring_cq_t;

struct fd_io_uring {
  int ioring_fd;
  fd_io_uring_sq_t sq[1];
  fd_io_uring_cq_t cq[1];
  void * kern_sq_mem;
  ulong  kern_sq_sz;
  void * kern_cq_mem;
  ulong  kern_cq_sz;
  void * kern_sqe_mem;
  ulong  kern_sqe_sz;
};
typedef struct fd_io_uring fd_io_uring_t;

FD_PROTOTYPES_BEGIN

static int fd_io_uring_submit( fd_io_uring_sq_t * sq, int ring_fd, uint wait_cnt, uint flags );
static inline uint fd_io_uring_sq_dropped( fd_io_uring_sq_t const * sq ) { return atomic_load_explicit( sq->kdropped, memory_order_relaxed ); }
static inline uint fd_io_uring_cq_overflow( fd_io_uring_cq_t const * cq ) { return atomic_load_explicit( cq->koverflow, memory_order_relaxed ); }
static inline struct io_uring_sqe * fd_io_uring_get_sqe( fd_io_uring_sq_t * sq );
static inline uint fd_io_uring_sq_space_left( fd_io_uring_sq_t * sq );
static inline uint fd_io_uring_cq_ready( fd_io_uring_cq_t const * cq );
static inline void fd_io_uring_cq_advance( fd_io_uring_cq_t * cq, uint cnt );
static inline struct io_uring_cqe * fd_io_uring_cq_head( fd_io_uring_cq_t const * cq );

FD_PROTOTYPES_END

#else /* __linux__ */

#include "../fd_util_base.h"

struct fd_io_uring_sq {
  uint depth;
  uint sqe_head;
  uint sqe_tail;
  void * sqes;
};
typedef struct fd_io_uring_sq fd_io_uring_sq_t;

struct fd_io_uring_cq {
  ulong depth;
  void * cqes;
};
typedef struct fd_io_uring_cq fd_io_uring_cq_t;

struct fd_io_uring {
  int ioring_fd;
  fd_io_uring_sq_t sq[1];
  fd_io_uring_cq_t cq[1];
};
typedef struct fd_io_uring fd_io_uring_t;

/* Stubs for non-Linux */
#define fd_io_uring_setup(a,b) (-1)
#define fd_io_uring_register_files(a,b,c) (-1)
#define fd_io_uring_register_restrictions(a,b,c) (-1)
#define fd_io_uring_enable_rings(a) (-1)

#endif /* __linux__ */

#endif /* HEADER_fd_src_util_io_uring_fd_io_uring_h */
