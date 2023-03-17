#ifndef HEADER_fd_src_disco_tpu_fd_tpu_h
#define HEADER_fd_src_disco_tpu_fd_tpu_h

#include "../../util/fd_util_base.h"

/* FD_TPU_MTU is the max serialized byte size of a txn sent over TPU. */

#define FD_TPU_MTU (1232UL)

/* fd_tpu_context_t is the context object of a TPU stream recv. */

struct fd_tpu_context {
  ulong placeholder;
};
typedef struct fd_tpu_context fd_tpu_context_t;

#endif /* HEADER_fd_src_disco_tpu_fd_tpu_h */
