#ifndef HEADER_fd_src_discof_fd_poh_tile_h
#define HEADER_fd_src_discof_fd_poh_tile_h

#include "../../util/fd_util_base.h"

struct fd_poh_reset {
  ulong completed_slot;
  uchar completed_blockhash[ 32UL ];
  ulong hashcnt_per_tick;
  ulong next_leader_slot;
};

typedef struct fd_poh_reset fd_poh_reset_t;

struct fd_poh_begin_leader {
  ulong slot;
  ulong hashcnt_per_tick;
};

typedef struct fd_poh_begin_leader fd_poh_begin_leader_t;

#endif /* HEADER_fd_src_discof_fd_poh_tile_h */
