#ifndef HEADER_fd_src_discof_resolv_fd_resolv_tile_h
#define HEADER_fd_src_discof_resolv_fd_resolv_tile_h

#include "../../util/fd_util_base.h"

/* fd_resolv_slot_exchanged is sent by the resolv tile to replay to
   indicate that it is done with a particular root bank, and that replay
   can free it if it wants to. */

struct fd_resolv_slot_exchanged {
  ulong bank_idx;
};

typedef struct fd_resolv_slot_exchanged fd_resolv_slot_exchanged_t;

#endif /* HEADER_fd_src_discof_resolv_fd_resolv_tile_h */
