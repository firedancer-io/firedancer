#ifndef HEADER_fd_src_discof_poh_fd_poh_tile_h
#define HEADER_fd_src_discof_poh_fd_poh_tile_h

#include "../../util/fd_util_base.h"

struct fd_poh_reset {
  ulong bank_idx;

  long  timestamp;
  ulong completed_slot;
  uchar completed_blockhash[ 32UL ];
  ulong hashcnt_per_tick;
  ulong ticks_per_slot;
  ulong tick_duration_ns;
  ulong next_leader_slot;
  ulong max_microblocks_in_slot;
  uchar completed_cmr[ 32UL ];
  uchar completed_dmr[ 32UL ]; /* ALPENGLOW-ONLY */
  int   wfs_paused;

  /* The cluster tip and the boot catch-up latch, for the failover
     controller's readiness checks.  turbine_slot is the highest slot
     seen in a FEC set this validator did not produce, ULONG_MAX before
     any, and caught_up is the one-way latch replay sets when it first
     completes a slot near that tip. */
  ulong turbine_slot;
  int   caught_up;
};

typedef struct fd_poh_reset fd_poh_reset_t;

struct fd_poh_begin_leader {
  ulong slot;
  ulong hashcnt_per_tick;
};

typedef struct fd_poh_begin_leader fd_poh_begin_leader_t;

#endif /* HEADER_fd_src_discof_poh_fd_poh_tile_h */
