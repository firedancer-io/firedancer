#ifndef HEADER_fd_src_app_fdctl_run_util_h
#define HEADER_fd_src_app_fdctl_run_util_h

#include "../../tango/fd_tango_base.h"
#include "../../flamenco/repair/fd_repair.h"

#define FD_REPAIR_REQ_TYPE_NEED_WINDOW_INDEX          (0U)
#define FD_REPAIR_REQ_TYPE_NEED_HIGHEST_WINDOW_INDEX  (1U)
#define FD_REPAIR_REQ_TYPE_NEED_ORPHAN                (2U)

struct __attribute__((aligned(FD_CHUNK_ALIGN))) fd_repair_request {
  uint type;
  uint shred_index;
  ulong slot;
};
typedef struct fd_repair_request fd_repair_request_t;

#endif /* HEADER_fd_src_app_fdctl_run_util_h */
