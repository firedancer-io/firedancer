#ifndef HEADER_fd_src_util_io_fd_io_uring_sys_h
#define HEADER_fd_src_util_io_fd_io_uring_sys_h

/* fd_io_uring_sys.h provides the io_uring syscall API. */

#include "../fd_util_base.h"

#ifndef IORING_SETUP_R_DISABLED
#define IORING_SETUP_R_DISABLED (1U<<6)
#endif

#ifndef IORING_SETUP_COOP_TASKRUN
#define IORING_SETUP_COOP_TASKRUN (1U << 8)
#endif

#ifndef IORING_SETUP_SINGLE_ISSUER
#define IORING_SETUP_SINGLE_ISSUER (1U<<12)
#endif

#ifndef IORING_SETUP_DEFER_TASKRUN
#define IORING_SETUP_DEFER_TASKRUN (1U << 13)
#endif

#ifndef IORING_SETUP_NO_MMAP
#define IORING_SETUP_NO_MMAP (1U<<14)
#endif

#define FD_IORING_REGISTER_FILES         2
#define FD_IORING_REGISTER_RESTRICTIONS 11
#define FD_IORING_REGISTER_ENABLE_RINGS 12

#define FD_IORING_RESTRICTION_SQE_OP 1
#define FD_IORING_RESTRICTION_SQE_FLAGS_ALLOWED 2
#define FD_IORING_RESTRICTION_SQE_FLAGS_REQUIRED 3

#ifndef IOSQE_CQE_SKIP_SUCCESS
#define IOSQE_CQE_SKIP_SUCCESS (1U<<6)
#endif

struct fd_io_uring_restriction {
  ushort opcode;
  union {
    uchar register_op;
    uchar sqe_op;
    uchar sqe_flags;
  };
  uchar resv;
  uint  resv2[3];
};

typedef struct fd_io_uring_restriction fd_io_uring_restriction_t;

struct fd_io_sqring_offsets {
  uint head;
  uint tail;
  uint ring_mask;
  uint ring_entries;
  uint flags;
  uint dropped;
  uint array;
  uint resv1;
  ulong user_addr;
};

typedef struct fd_io_sqring_offsets fd_io_sqring_offsets_t;

struct fd_io_cqring_offsets {
  uint head;
  uint tail;
  uint ring_mask;
  uint ring_entries;
  uint overflow;
  uint cqes;
  uint flags;
  uint resv1;
  ulong user_addr;
};

typedef struct fd_io_cqring_offsets fd_io_cqring_offsets_t;

struct fd_io_uring_params {
  uint sq_entries;
  uint cq_entries;
  uint flags;
  uint sq_thread_cpu;
  uint sq_thread_idle;
  uint features;
  uint wq_fd;
  uint resv[3];
  fd_io_sqring_offsets_t sq_off;
  fd_io_cqring_offsets_t cq_off;
};

typedef struct fd_io_uring_params fd_io_uring_params_t;

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

int
fd_io_uring_setup( uint                   entry_cnt,
                   fd_io_uring_params_t * p );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_io_fd_io_uring_sys_h */
