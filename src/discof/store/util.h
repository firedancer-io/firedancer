#ifndef HEADER_fd_src_discof_store_util_h
#define HEADER_fd_src_discof_store_util_h

#include "../../tango/fd_tango_base.h"
#include "../../flamenco/repair/fd_repair.h"
#include "../../flamenco/gossip/fd_contact_info.h"

#define FD_REPAIR_REQ_TYPE_NEED_WINDOW_INDEX          (0U)
#define FD_REPAIR_REQ_TYPE_NEED_HIGHEST_WINDOW_INDEX  (1U)
#define FD_REPAIR_REQ_TYPE_NEED_ORPHAN                (2U)

struct fd_repair_request {
  uint type;
  uint shred_index;
  ulong slot;
};
typedef struct fd_repair_request fd_repair_request_t;

struct fd_contact_info_elem {
  fd_pubkey_t key;
  ulong next;
  fd_contact_info_t contact_info;
};
typedef struct fd_contact_info_elem fd_contact_info_elem_t;

#endif /* HEADER_fd_src_discof_store_util_h */
