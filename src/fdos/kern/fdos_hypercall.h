#ifndef HEADER_fd_src_fdos_kern_fdos_hypercall_h
#define HEADER_fd_src_fdos_kern_fdos_hypercall_h

/* fdos_hypercall.h provides the ABI for kernel-to-host hypercalls.
   This mechanism is used by the fdos kernel to sychronously send
   messages to the KVM host (e.g. logging). */

#include "../../util/fd_util_base.h"

/* kernel boot parameters */

struct fdos_kern_args {
  ulong hyper_args_gvaddr;
  ulong stack_user_top_gvaddr;
};

typedef struct fdos_kern_args fdos_kern_args_t;

/* FDOS_HYPERCALL_* give hypercall IDs. */

#define FDOS_HYPERCALL_LOG 1

/* fd_hypercall_args_t holds hypercall request and reply arguments. */

struct fd_hypercall_args {
  ulong arg[5];
};

typedef struct fd_hypercall_args fd_hypercall_args_t;

#endif /* HEADER_fd_src_fdos_kern_fdos_hypercall_h */
