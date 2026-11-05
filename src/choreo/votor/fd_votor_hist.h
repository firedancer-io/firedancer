#ifndef HEADER_fd_src_choreo_votor_fd_votor_hist_h
#define HEADER_fd_src_choreo_votor_fd_votor_hist_h

/* fd_votor_hist serializes and deserializes a validator's own Alpenglow
   votes since a finality anchor, so another validator can adopt the
   same consensus state before voting as the same identity. */

#include "fd_votor_base.h"

#define FD_VOTOR_HIST_MAX (128UL) /* records per history, 32 leader windows */

#define FD_VOTOR_HIST_FLAG_VOTED       (1U) /* any own vote on the slot */
#define FD_VOTOR_HIST_FLAG_VOTED_NOTAR (2U) /* a notar vote, notar_hash is set */
#define FD_VOTOR_HIST_FLAG_BAD_WINDOW  (4U) /* no final vote may follow on this slot */
#define FD_VOTOR_HIST_FLAG_RETIRED     (8U) /* the slot is done */
#define FD_VOTOR_HIST_FLAG_MASK        (15U)

#define FD_VOTOR_HIST_HDR_SZ     (26UL) /* anchor u64, last_leader_slot u64, vote_bound u64, rec_cnt u16 */
#define FD_VOTOR_HIST_REC_MIN_SZ (9UL)  /* slot u64, flags u8 */
#define FD_VOTOR_HIST_REC_MAX_SZ (41UL) /* plus the 32 byte notar hash */
#define FD_VOTOR_HIST_SER_MAX    (FD_VOTOR_HIST_HDR_SZ+FD_VOTOR_HIST_MAX*FD_VOTOR_HIST_REC_MAX_SZ) /* 5274 */

struct fd_votor_hist_rec {
  ulong           slot;
  uchar           flags;      /* FD_VOTOR_HIST_FLAG_* */
  fd_block_hash_t notar_hash; /* only meaningful when FD_VOTOR_HIST_FLAG_VOTED_NOTAR is set */
};
typedef struct fd_votor_hist_rec fd_votor_hist_rec_t;

struct fd_votor_hist {
  ulong               anchor;                   /* exporter's highest_final_slot, raised when the export was truncated */
  ulong               last_leader_slot;         /* slot of the last LEADER the exporter published, ULONG_MAX when none */
  ulong               vote_bound;               /* the exporter casts no vote at or below this slot, ULONG_MAX when none */
  ulong               rec_cnt;
  fd_votor_hist_rec_t rec[ FD_VOTOR_HIST_MAX ]; /* ascending slots */
};
typedef struct fd_votor_hist fd_votor_hist_t;

FD_PROTOTYPES_BEGIN

/* fd_votor_hist_first_slot returns the lowest slot a history with this
   anchor may contain. */

FD_FN_CONST static inline ulong
fd_votor_hist_first_slot( ulong anchor ) {
  return fd_first_slot_in_window( fd_ulong_sat_sub( anchor, FD_VOTOR_REWARD_SLOT_DELTA ) );
}

/* fd_votor_hist_ser serializes self into buf.  Returns 0 on success, -1
   if self is invalid or buf_max is too small. */

int
fd_votor_hist_ser( fd_votor_hist_t const * self,
                   uchar *                 buf,
                   ulong                   buf_max,
                   ulong *                 out_sz );

/* fd_votor_hist_de deserializes exactly buf_sz bytes of buf into out.
   Returns 0 on success, -1 if the bytes are not a valid history. */

int
fd_votor_hist_de( uchar const *     buf,
                  ulong             buf_sz,
                  fd_votor_hist_t * out );

/* fd_votor_hist_tip returns the highest record slot, ULONG_MAX when the
   history is empty. */

FD_FN_PURE static inline ulong
fd_votor_hist_tip( fd_votor_hist_t const * self ) {
  return self->rec_cnt ? self->rec[ self->rec_cnt-1UL ].slot : ULONG_MAX;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votor_fd_votor_hist_h */
