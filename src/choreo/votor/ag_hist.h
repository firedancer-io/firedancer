#ifndef HEADER_fd_src_choreo_votor_ag_hist_h
#define HEADER_fd_src_choreo_votor_ag_hist_h

/* ag_hist is a validator's own Alpenglow votes since a finality
   anchor.  The votor exports it and a failover peer adopts it before
   voting so the pair never casts a conflicting vote on a slot.  On the
   wire it is a packed little endian header of anchor, last_leader_slot
   and rec_cnt followed by one record per voted slot, each a slot, a
   flags byte and the 32 byte notar hash only when VOTED_NOTAR is
   set. */

#include "ag_votor_base.h"

#define AG_HIST_MAX (128UL)                      /* records per history, 32 leader windows */

#define AG_HIST_FLAG_VOTED       (1U)            /* any own vote on the slot */
#define AG_HIST_FLAG_VOTED_NOTAR (2U)            /* a notar vote, notar_hash is set */
#define AG_HIST_FLAG_BAD_WINDOW  (4U)            /* no final vote may follow, a skip or fallback vote or a vote built here that never left */
#define AG_HIST_FLAG_RETIRED     (8U)            /* the slot is done, a final vote or the anchor the votor was initialised on */
#define AG_HIST_FLAG_MASK        (15U)

#define AG_HIST_HDR_SZ     (18UL)                /* anchor u64, last_leader_slot u64, rec_cnt u16 */
#define AG_HIST_REC_MIN_SZ (9UL)                 /* slot u64, flags u8 */
#define AG_HIST_REC_MAX_SZ (41UL)                /* plus the 32 byte notar hash */
#define AG_HIST_SER_MAX    (AG_HIST_HDR_SZ+AG_HIST_MAX*AG_HIST_REC_MAX_SZ) /* 5266 */

struct ag_hist_rec {
  ulong           slot;
  uchar           flags;      /* AG_HIST_FLAG_* */
  ag_block_hash_t notar_hash; /* only meaningful when AG_HIST_FLAG_VOTED_NOTAR is set */
};
typedef struct ag_hist_rec ag_hist_rec_t;

struct ag_hist {
  ulong         anchor;             /* exporter's highest_final_cert_slot at export time */
  ulong         last_leader_slot;   /* slot of the last LEADER the exporter published, ULONG_MAX when none */
  ulong         rec_cnt;
  ag_hist_rec_t rec[ AG_HIST_MAX ]; /* ascending slots */
};
typedef struct ag_hist ag_hist_t;

FD_PROTOTYPES_BEGIN

/* ag_hist_first_slot returns the lowest slot a history with this
   anchor may contain, the same bound as the votor's
   first_unpruned_slot. */

FD_FN_CONST static inline ulong
ag_hist_first_slot( ulong anchor ) {
  return ag_first_slot_in_window( fd_ulong_sat_sub( anchor, AG_REWARD_SLOT_DELTA ) );
}

/* ag_hist_ser serializes hist into buf and writes the byte count to
   out_sz.  Returns 0 on success, -1 if hist breaks a rule ag_hist_de
   enforces or buf_max is too small, in which case nothing is
   written. */

int
ag_hist_ser( ag_hist_t const * hist,
             uchar *           buf,
             ulong             buf_max,
             ulong *           out_sz );

/* ag_hist_de deserializes exactly buf_sz bytes of buf into out.  It
   rejects trailing bytes, more than AG_HIST_MAX records, an anchor of
   ULONG_MAX, slots that are not strictly ascending or fall below
   ag_hist_first_slot( anchor ), flag bits outside AG_HIST_FLAG_MASK
   and any record without AG_HIST_FLAG_VOTED.  Returns 0 with out
   filled, -1 with out untouched. */

int
ag_hist_de( uchar const * buf,
            ulong         buf_sz,
            ag_hist_t *   out );

/* ag_hist_tip returns the highest record slot, ULONG_MAX when the
   history is empty. */

FD_FN_PURE static inline ulong
ag_hist_tip( ag_hist_t const * hist ) {
  return hist->rec_cnt ? hist->rec[ hist->rec_cnt-1UL ].slot : ULONG_MAX;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_ag_hist_h */
