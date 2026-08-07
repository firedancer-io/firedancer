#ifndef HEADER_fd_src_util_futex_fd_futex_h
#define HEADER_fd_src_util_futex_fd_futex_h

/* fd_futex.h contains Linux uapi wrappers for the futex API.
   This exists so the build does not fail with old kernel headers. */

#include "../fd_util_base.h"

#ifndef FUTEX2_SIZE_U32
#define FUTEX2_SIZE_U32 0x02
#endif

/* Mirrors 'struct futex_waitv' */

struct fd_futex_waitv {
  ulong val;
  ulong uaddr;
  uint  flags;
  uint  reserved;
};

typedef struct fd_futex_waitv fd_futex_waitv_t;

#endif /* HEADER_fd_src_util_futex_fd_futex_h */
