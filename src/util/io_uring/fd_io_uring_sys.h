#ifndef HEADER_fd_src_util_io_fd_io_uring_sys_h
#define HEADER_fd_src_util_io_fd_io_uring_sys_h

/* fd_io_uring_sys.h provides the io_uring syscall API. */

#include "../fd_util_base.h"
#include <sys/syscall.h> /* SYS_* */

/* fd_kernel_timespec_t matches struct __kernel_timespec, which
   <linux/time_types.h> only provides since Linux v5.1. */

struct fd_kernel_timespec {
  long tv_sec;
  long tv_nsec;
};

typedef struct fd_kernel_timespec fd_kernel_timespec_t;

struct fd_io_uring_sqe {
  uchar  opcode;  /* FD_IORING_OP_* */
  uchar  flags;   /* FD_IOSQE_* */
  ushort ioprio;
  int    fd;
  union {
    ulong off;
    ulong addr2;
  };
  union {
    ulong addr;
    ulong splice_off_in;
  };
  uint len;
  union {
    uint   rw_flags;
    uint   fsync_flags;
    ushort poll_events;
    uint   poll32_events;
    uint   sync_range_flags;
    uint   msg_flags;
    uint   timeout_flags;
    uint   accept_flags;
    uint   cancel_flags;
    uint   open_flags;
    uint   splice_flags;
    uint   futex_flags;
  };
  ulong user_data;
  union {
    ushort buf_index;
    ushort buf_group;
  } __attribute__((packed));
  ushort personality;
  union {
    int  splice_fd_in;
    uint file_index;
  };
  union {
    ulong addr3;
    ulong optval;
  };
  ulong __pad2[1];
};

typedef struct fd_io_uring_sqe fd_io_uring_sqe_t;

struct fd_io_uring_cqe {
  ulong user_data; /* sqe->user_data value passed back */
  int   res;       /* result code for this event */
  uint  flags;
};

typedef struct fd_io_uring_cqe fd_io_uring_cqe_t;

struct fd_io_uring_rsrc_update {
  uint  offset;
  uint  resv;
  ulong data;
};

typedef struct fd_io_uring_rsrc_update fd_io_uring_rsrc_update_t;

struct fd_io_uring_getevents_arg {
  ulong sigmask;
  uint  sigmask_sz;
  uint  min_wait_usec;
  ulong ts;
};

typedef struct fd_io_uring_getevents_arg fd_io_uring_getevents_arg_t;

FD_STATIC_ASSERT( sizeof(fd_kernel_timespec_t)            ==16UL, abi );
FD_STATIC_ASSERT( sizeof(fd_io_uring_sqe_t)               ==64UL, abi );
FD_STATIC_ASSERT( sizeof(fd_io_uring_cqe_t)               ==16UL, abi );
FD_STATIC_ASSERT( sizeof(fd_io_uring_rsrc_update_t)       ==16UL, abi );
FD_STATIC_ASSERT( sizeof(fd_io_uring_getevents_arg_t)     ==24UL, abi );
FD_STATIC_ASSERT( __builtin_offsetof( fd_io_uring_sqe_t, user_data )==32UL, abi );
FD_STATIC_ASSERT( __builtin_offsetof( fd_io_uring_sqe_t, addr3     )==48UL, abi );

/* io_uring syscall numbers are identical on all architectures that
   Firedancer supports. */

#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif

#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter 426
#endif

#ifndef SYS_io_uring_register
#define SYS_io_uring_register 427
#endif

#define FD_IORING_SETUP_CQSIZE        (1U<< 3)
#define FD_IORING_SETUP_R_DISABLED    (1U<< 6)
#define FD_IORING_SETUP_COOP_TASKRUN  (1U<< 8)
#define FD_IORING_SETUP_SINGLE_ISSUER (1U<<12)
#define FD_IORING_SETUP_DEFER_TASKRUN (1U<<13)
#define FD_IORING_SETUP_NO_MMAP       (1U<<14)

/* mmap(2) offsets of the ring regions */

#define FD_IORING_OFF_SQ_RING 0x0UL
#define FD_IORING_OFF_CQ_RING 0x8000000UL
#define FD_IORING_OFF_SQES    0x10000000UL

#define FD_IORING_ENTER_GETEVENTS (1U<<0)
#define FD_IORING_ENTER_EXT_ARG   (1U<<3)

#define FD_IORING_REGISTER_BUFFERS           0
#define FD_IORING_REGISTER_FILES             2
#define FD_IORING_REGISTER_FILES_UPDATE      6
#define FD_IORING_REGISTER_RESTRICTIONS     11
#define FD_IORING_REGISTER_ENABLE_RINGS     12
#define FD_IORING_REGISTER_IOWQ_MAX_WORKERS 19

#define FD_IORING_RESTRICTION_REGISTER_OP        0
#define FD_IORING_RESTRICTION_SQE_OP             1
#define FD_IORING_RESTRICTION_SQE_FLAGS_ALLOWED  2
#define FD_IORING_RESTRICTION_SQE_FLAGS_REQUIRED 3

#define FD_IORING_OP_NOP                     0
#define FD_IORING_OP_READV                   1
#define FD_IORING_OP_WRITEV                  2
#define FD_IORING_OP_FSYNC                   3
#define FD_IORING_OP_READ_FIXED              4
#define FD_IORING_OP_WRITE_FIXED             5
#define FD_IORING_OP_POLL_ADD                6
#define FD_IORING_OP_POLL_REMOVE             7
#define FD_IORING_OP_SYNC_FILE_RANGE         8
#define FD_IORING_OP_SENDMSG                 9
#define FD_IORING_OP_RECVMSG                10
#define FD_IORING_OP_TIMEOUT                11
#define FD_IORING_OP_TIMEOUT_REMOVE         12
#define FD_IORING_OP_ACCEPT                 13
#define FD_IORING_OP_ASYNC_CANCEL           14
#define FD_IORING_OP_LINK_TIMEOUT           15
#define FD_IORING_OP_CONNECT                16
#define FD_IORING_OP_FALLOCATE              17
#define FD_IORING_OP_OPENAT                 18
#define FD_IORING_OP_CLOSE                  19
#define FD_IORING_OP_FILES_UPDATE           20
#define FD_IORING_OP_STATX                  21
#define FD_IORING_OP_READ                   22
#define FD_IORING_OP_WRITE                  23
#define FD_IORING_OP_FADVISE                24
#define FD_IORING_OP_MADVISE                25
#define FD_IORING_OP_SEND                   26
#define FD_IORING_OP_RECV                   27
#define FD_IORING_OP_OPENAT2                28
#define FD_IORING_OP_EPOLL_CTL              29
#define FD_IORING_OP_SPLICE                 30
#define FD_IORING_OP_PROVIDE_BUFFERS        31
#define FD_IORING_OP_REMOVE_BUFFERS         32
#define FD_IORING_OP_TEE                    33
#define FD_IORING_OP_SHUTDOWN               34
#define FD_IORING_OP_RENAMEAT               35
#define FD_IORING_OP_UNLINKAT               36
#define FD_IORING_OP_MKDIRAT                37
#define FD_IORING_OP_SYMLINKAT              38
#define FD_IORING_OP_LINKAT                 39
#define FD_IORING_OP_MSG_RING               40
#define FD_IORING_OP_FSETXATTR              41
#define FD_IORING_OP_SETXATTR               42
#define FD_IORING_OP_FGETXATTR              43
#define FD_IORING_OP_GETXATTR               44
#define FD_IORING_OP_SOCKET                 45
#define FD_IORING_OP_URING_CMD              46
#define FD_IORING_OP_SEND_ZC                47
#define FD_IORING_OP_SENDMSG_ZC             48
#define FD_IORING_OP_READ_MULTISHOT         49
#define FD_IORING_OP_WAITID                 50
#define FD_IORING_OP_FUTEX_WAIT             51
#define FD_IORING_OP_FUTEX_WAKE             52
#define FD_IORING_OP_FUTEX_WAITV            53

#define FD_IOSQE_FIXED_FILE       (1U<<0)
#define FD_IOSQE_IO_LINK          (1U<<2)
#define FD_IOSQE_CQE_SKIP_SUCCESS (1U<<6)

#define FD_IORING_RECVSEND_FIXED_BUF (1U<<2)

#ifndef FUTEX2_SIZE_U32
#define FUTEX2_SIZE_U32 0x02
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
