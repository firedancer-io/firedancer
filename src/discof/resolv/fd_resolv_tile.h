#ifndef HEADER_fd_src_discof_resolv_fd_resolv_tile_h
#define HEADER_fd_src_discof_resolv_fd_resolv_tile_h

#include "../../util/fd_util_base.h"

/* fd_resov_slot_completed is sent by the replay tile to the
   resolve tile to indicate that replay has completed a slot. */
#define FD_RESOLV_COMPLETED_SLOT_SIG (0UL)
struct fd_resov_completed_slot {
  ulong slot;
  uchar blockhash[32];
};
typedef struct fd_resov_completed_slot fd_resov_completed_slot_t;

/* fd_resov_slot_rooted is sent by the replay tile to the
   resolve tile to indicate that replay has rooted a slot.
   replay guarantees the bank's lifetime will persist until
   resolve sends replay the fd_resolv_slot_exchanged message
   corresponding to that slot. */
#define FD_RESOLV_ROOTED_SLOT_SIG (1UL)
struct fd_resolv_rooted_slot {
  ulong bank_idx;
};
typedef struct fd_resolv_rooted_slot fd_resolv_rooted_slot_t;

/* fd_resolv_slot_exchanged is sent by the resolv tile to replay to
   indicate that it is done with a particular root bank, and that replay
   can free it if it wants to. */
struct fd_resolv_slot_exchanged {
  ulong bank_idx;
};

typedef struct fd_resolv_slot_exchanged fd_resolv_slot_exchanged_t;

#endif /* HEADER_fd_src_discof_resolv_fd_resolv_tile_h */
