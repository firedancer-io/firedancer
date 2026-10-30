#ifndef HEADER_fd_src_choreo_votor_ag_hist_h
#define HEADER_fd_src_choreo_votor_ag_hist_h

/* ag_hist serializes and deserializes a validator's own Alpenglow votes
   since a finality anchor, so another validator can adopt the same
   consensus state before voting as the same identity. */

#include "ag_votor_base.h"

#define AG_HIST_MAX (128UL) /* records per history, 32 leader windows */

#define AG_HIST_FLAG_VOTED       (1U) /* any own vote on the slot */
#define AG_HIST_FLAG_VOTED_NOTAR (2U) /* a notar vote, notar_hash is set */
#define AG_HIST_FLAG_BAD_WINDOW  (4U) /* no final vote may follow on this slot */
#define AG_HIST_FLAG_RETIRED     (8U) /* the slot is done */
#define AG_HIST_FLAG_MASK        (15U)

#define AG_HIST_HDR_SZ     (26UL) /* anchor u64, last_leader_slot u64, vote_bound u64, rec_cnt u16 */
#define AG_HIST_REC_MIN_SZ (9UL)  /* slot u64, flags u8 */
#define AG_HIST_REC_MAX_SZ (41UL) /* plus the 32 byte notar hash */
#define AG_HIST_SER_MAX    (AG_HIST_HDR_SZ+AG_HIST_MAX*AG_HIST_REC_MAX_SZ) /* 5274 */

struct ag_hist_rec {
  ulong           slot;
  uchar           flags;      /* AG_HIST_FLAG_* */
  ag_block_hash_t notar_hash; /* only meaningful when AG_HIST_FLAG_VOTED_NOTAR is set */
};
typedef struct ag_hist_rec ag_hist_rec_t;

struct ag_hist {
  ulong         anchor;             /* exporter's highest_final_cert_slot, raised when the export was truncated */
  ulong         last_leader_slot;   /* slot of the last LEADER the exporter published, ULONG_MAX when none */
  ulong         vote_bound;         /* the exporter casts no vote at or below this slot, ULONG_MAX when none */
  ulong         rec_cnt;
  ag_hist_rec_t rec[ AG_HIST_MAX ]; /* ascending slots */
};
typedef struct ag_hist ag_hist_t;

FD_PROTOTYPES_BEGIN

/* ag_hist_first_slot returns the lowest slot a history with this anchor
   may contain. */

FD_FN_CONST static inline ulong
ag_hist_first_slot( ulong anchor ) {
  return ag_first_slot_in_window( fd_ulong_sat_sub( anchor, AG_REWARD_SLOT_DELTA ) );
}

/* ag_hist_ser serializes hist into buf.  Returns 0 on success, -1 if hist
   is invalid or buf_max is too small. */

int
ag_hist_ser( ag_hist_t const * hist,
             uchar *           buf,
             ulong             buf_max,
             ulong *           out_sz );

/* ag_hist_de deserializes exactly buf_sz bytes of buf into out.  Returns 0
   on success, -1 if the bytes are not a valid history. */

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
