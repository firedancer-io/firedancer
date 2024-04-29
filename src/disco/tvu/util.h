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

struct __attribute__((packed)) fd_shred_dest_wire {
  fd_pubkey_t pubkey[1];
  /* The Labs splice writes this as octets, which means when we read
     this, it's essentially network byte order */
  uint   ip4_addr;
  ushort udp_port;
};
typedef struct fd_shred_dest_wire fd_shred_dest_wire_t;

struct fd_contact_info_elem {
  fd_pubkey_t key;
  ulong next;
  fd_gossip_contact_info_v1_t contact_info;
};
typedef struct fd_contact_info_elem fd_contact_info_elem_t;

#endif /* HEADER_fd_src_app_fdctl_run_util_h */
