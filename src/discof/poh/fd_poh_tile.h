#ifndef HEADER_fd_src_discof_poh_fd_poh_tile_h
#define HEADER_fd_src_discof_poh_fd_poh_tile_h

#include "fd_poh.h" /* for fd_poh_leader_slot_ended_t */

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
  uchar completed_block_id[ 32UL ];
  int   wfs_paused;

  /* ALPENGLOW.  Whether the cluster is running alpenglow consensus.
     The poh tile has no other way to learn it -- it never sees a bank
     -- and it has to know before it produces anything, not just before
     it leads: an alpenglow genesis leaves hashes_per_tick unset, and
     free running the tick grid on top of that is meaningless work whose
     only effect is to move poh->slot out from under the leader path. */
  int   alpenglow;
};

typedef struct fd_poh_reset fd_poh_reset_t;

struct fd_poh_begin_leader {
  ulong slot;
  ulong hashcnt_per_tick;
};

typedef struct fd_poh_begin_leader fd_poh_begin_leader_t;

/* Sigs on the poh_replay link.  Before alpenglow the link carried
   exactly one message type and the sig was always 0, which is why
   FD_POH_SIG_SLOT_ENDED is 0. */

#define FD_POH_SIG_SLOT_ENDED   (0UL)
#define FD_POH_SIG_AG_TICK      (1UL)

/* ALPENGLOW.  Published when the closing tick of a block has been
   computed, which happens only once every microblock pack sent for the
   slot has landed.

   It is a request, not a notification: replay must register the tick
   into the leader bank (which takes tick_height to max_tick_height and
   lets the bank freeze), take the resulting bank hash, build the
   BlockFooter, and hand it back with REPLAY_SIG_AG_FOOTER.  Only then
   does poh put the footer and the tick on the wire.

   The round trip exists because the footer states the bank hash, so it
   cannot be built before the bank freezes, and the bank cannot freeze
   before the tick is registered.  Agave does the same thing inside one
   thread under a lock; here the bank lives in replay and the hash chain
   lives in poh, so it costs a message each way. */

struct fd_poh_ag_tick_ready {
  ulong slot;
  uchar tick_hash[ 32UL ];
};

typedef struct fd_poh_ag_tick_ready fd_poh_ag_tick_ready_t;

/* The poh_replay link's mtu.  A union so adding a message type resizes
   the link automatically. */

union fd_poh_replay_msg {
  fd_poh_leader_slot_ended_t slot_ended;
  fd_poh_ag_tick_ready_t     ag_tick_ready;
};

typedef union fd_poh_replay_msg fd_poh_replay_msg_t;

#endif /* HEADER_fd_src_discof_poh_fd_poh_tile_h */
