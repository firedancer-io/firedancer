#ifndef HEADER_fd_src_discof_repair_fd_repair_tile_h
#define HEADER_fd_src_discof_repair_fd_repair_tile_h

#include "../../disco/tiles.h"
#include "../../disco/shred/fd_shred_tile.h"

/* Repair tile forwards all FEC completes received by the shred tile.
   It forwards the FEC completes with new sigs:
   - REPAIR_SIG_FEC: FEC set complete
   - REPAIR_SIG_FEC_LEADER: Leader FEC set complete
   - REPAIR_SIG_FEC_INVALID: FEC set detected as invalid based on duplicate confirmations

   Note that invalidity is very strict. i.e., sometimes replay may not
   want FEC set at the root / or older than the root to be inserted.
   Repair should still forward these as REPAIR_SIG_FEC, because they are
   FEC sets that are either valid, or cannot be verified as invalid.
   Similarly, repair may have received two versions of one FEC, but is
   unsure which one is canonical.  These are also forwarded as
   REPAIR_SIG_FEC. It's up to replay tile to arbitrate whether to insert
   these FEC sets.

   A FEC set forwarded as REPAIR_SIG_FEC_INVALID is with confidence
   guaranteed to be not part of the canonical chain. */

struct fd_fec_complete_metrics {
  uint  stats_valid;             /* 1 if the forest still tracked the block and the blk_* stats are filled */
  uint  blk_turbine_cnt;         /* block: shreds received via turbine */
  uint  blk_repair_cnt;          /* block: data shreds received via repair */
  uint  blk_recovered_cnt;       /* block: shreds recovered via reed-solomon */
  uint  blk_data_cnt;            /* block: data shreds received so far (reaches complete_idx+1 once the slot is fully buffered) */
  uint  blk_parity_cnt;          /* block: coding (parity) shreds received so far */
  uint  blk_lowest_verified_fec; /* block: lowest verified FEC index, UINT_MAX if none */
  uchar blk_chain_confirmed;     /* block: 1 if the whole chain has been merkle-verified */
  uchar blk_slot_complete;       /* block: 1 if the slot-complete shred has been received */

  uint  blk_req_window_cnt;      /* block: window (specific-shred) repair requests sent */
  uint  blk_req_highest_cnt;     /* block: highest-window repair requests sent */
  uint  blk_req_orphan_cnt;      /* block: orphan repair requests sent */
  uint  blk_req_retransmit_cnt;  /* block: repair requests re-sent after a response timeout */
  uint  blk_repair_responses;    /* block: repair responses received */
  uchar blk_chain_verify_failed; /* block: 1 if merkle chain verification flagged this block bad */

  ulong fec_completed_ts_nanos;

  ulong blk_first_shred_ts_nanos;      /* when the first shred of the slot arrived */
  ulong blk_last_shred_ts_nanos;       /* when the slot became fully buffered */
  ulong blk_first_req_ts_nanos;        /* when the first repair request for the slot was sent */
  ulong blk_last_repair_resp_ts_nanos; /* when the most recent repair response for the slot arrived */
};
typedef struct fd_fec_complete_metrics fd_fec_complete_metrics_t;

struct fd_repair_fec_complete {
  fd_fec_complete_t         fec;
  fd_fec_complete_metrics_t metrics;
};
typedef struct fd_repair_fec_complete fd_repair_fec_complete_t;

#define REPAIR_SIG_FEC         (0UL)  /* FEC set complete */
#define REPAIR_SIG_FEC_LEADER  (1UL)  /* Leader FEC set complete */
#define REPAIR_SIG_FEC_INVALID (2UL)  /* FEC set detected as invalid based on duplicate confirmations */

#endif /* HEADER_fd_src_discof_repair_fd_repair_tile_h */
