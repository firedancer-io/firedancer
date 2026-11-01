#ifndef HEADER_fd_src_choreo_votor_ag_slot_state_h
#define HEADER_fd_src_choreo_votor_ag_slot_state_h

#include "ag_votor_base.h"
#include "ag_cert.h"
#include "ag_epoch_info.h"
#include "ag_vote.h"

#define AG_PARENT_STATUS_KNOWN     (1)
#define AG_PARENT_STATUS_CERTIFIED (2)

#define AG_SLASHABLE_NONE                        (0)
#define AG_SLASHABLE_NOTAR_DIFFERENT_HASH        (1)
#define AG_SLASHABLE_SKIP_AND_NOTARIZE           (2)
#define AG_SLASHABLE_SKIP_AND_FINALIZE           (3)
#define AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE (4)
#define AG_SLASHABLE_NOTAR_FALLBACK_OVER_THREE   (5)

#define AG_SLOT_STATE_OUT_CERT_MAX   (3UL)
#define AG_SLOT_STATE_OUT_EVENT_MAX  (3UL)
#define AG_SLOT_STATE_OUT_REPAIR_MAX (3UL)

#define AG_NOTAR_FALLBACK_HASH_MAX (AG_VAT_MAX*AG_NOTAR_FALLBACK_VOTE_MAX)

/* Stake per block hash.  The first AG_HASH_STAKE_INLINE_MAX hashes of
   a slot live inline; the rest (only reachable with garbage hashes from
   staked voters) go to the slot's region of the spill file, read and
   written with pread/pwrite.  A free spill record has stake ULONG_MAX.
   Ids are stable: id<AG_HASH_STAKE_INLINE_MAX is inline, else spill
   record id-AG_HASH_STAKE_INLINE_MAX.  Inline ids keep the sum of
   their votes' sigs (unverified, like skip_agg). */

#define AG_HASH_STAKE_INLINE_MAX (32UL)
#define AG_NOTAR_SPILL_MAX       (AG_VAT_MAX                -AG_HASH_STAKE_INLINE_MAX)
#define AG_NF_SPILL_MAX          (AG_NOTAR_FALLBACK_HASH_MAX-AG_HASH_STAKE_INLINE_MAX)

struct ag_hash_stake {
  ag_block_hash_t hash;
  ulong           stake;
};
typedef struct ag_hash_stake ag_hash_stake_t;

/* Vote sigs live at a fixed position [ks][rank] of a slot.  Kind
   slots: 0 notar|skip, 1-3 notar fallback j, 4 skip fallback|final;
   kinds sharing a slot are exclusive per rank (check_slashable_offence,
   should_ignore_vote).  Each [ks][64 ranks] page takes one of the
   preallocated RAM pages on its first sig, else lives at its offset in
   the slot's spill region after the hash stake records.  Sigs are
   stored compressed. */

#define AG_SLOT_SIG_CNT        (AG_SLOT_VOTE_SIG_MAX*AG_VAT_MAX)
#define AG_SIG_PG_RANKS        (64UL) /* one fd_bls_set word */
#define AG_SIG_PG_SZ           (AG_SIG_PG_RANKS*FD_BLS_SIG_COMPRESSED_SZ)
#define AG_SLOT_SIG_PG_MAX     (AG_SLOT_VOTE_SIG_MAX*fd_bls_set_word_cnt)
#define AG_HS_SPILL_SZ         ((AG_NOTAR_SPILL_MAX+AG_NF_SPILL_MAX)*sizeof(ag_hash_stake_t))
#define AG_SLOT_STATE_SPILL_SZ (AG_HS_SPILL_SZ+AG_SLOT_SIG_CNT*FD_BLS_SIG_COMPRESSED_SZ)
#define AG_SIG_PG_DISK         (UINT_MAX)

struct ag_hash_stakes {
  ag_hash_stake_t ele    [ AG_HASH_STAKE_INLINE_MAX ];
  fd_bls_sig_t    sig_sum[ AG_HASH_STAKE_INLINE_MAX ];
  uint            used;      /* inline occupancy */
  ushort          spill_cnt; /* live spill records */
  ushort          spill_hwm; /* spill records [0,hwm) were written */
};
typedef struct ag_hash_stakes ag_hash_stakes_t;

struct ag_parent_status {
  ag_block_hash_t hash;
  int             kind;
};
typedef struct ag_parent_status ag_parent_status_t;

struct ag_block_hash_set {
  ag_block_hash_t hash[ AG_EQVOC_BLOCK_HASH_MAX ];
  ulong           cnt;
};
typedef struct ag_block_hash_set ag_block_hash_set_t;

struct ag_slot_votes {
  fd_bls_set_t    notar_set                    [ fd_bls_set_word_cnt ];
  ushort          notar_hash_stake_idx         [ AG_VAT_MAX ];
  ag_hash_stakes_t notar_hash_stake;
  ushort          notar_fallback_hash_stake_idx[ AG_VAT_MAX ][ AG_NOTAR_FALLBACK_VOTE_MAX ];
  ag_hash_stakes_t notar_fallback_hash_stake;
  uchar           notar_fallback_sig_cnt       [ AG_VAT_MAX ];
  ulong           skip_stake;
  fd_bls_agg_t    skip_agg;
  ulong           skip_fallback_stake;
  fd_bls_agg_t    skip_fallback_agg;
  ulong           finalize_stake;
  fd_bls_agg_t    finalize_agg;
  ulong           notar_or_skip_stake;
  ulong           top_notar_stake;
  ag_block_hash_t top_notar_hash;
};
typedef struct ag_slot_votes ag_slot_votes_t;

struct ag_slot_certs {
  ag_cert_notar_t          notar;
  ag_cert_notar_fallback_t notar_fallback[ AG_NOTAR_FALLBACK_CERT_MAX ];
  ag_cert_skip_t           skip;
  ag_cert_fast_final_t     fast_finalize;
  ag_cert_final_t          finalize;
  uchar                    notar_fallback_cnt;
};
typedef struct ag_slot_certs ag_slot_certs_t;

struct ag_slot_state {
  ag_slot_votes_t votes;
  ag_slot_certs_t certs;

  ag_parent_status_t parents[ AG_EQVOC_BLOCK_HASH_MAX ];
  ulong              parents_cnt;

  ag_block_hash_set_t pending_safe_to_notar;
  ag_block_hash_set_t verified_safe_to_notar; /* verified votes alone meet its safe-to-notar threshold */
  ag_block_hash_set_t sent_safe_to_notar;
  int                 sent_safe_to_skip;

  ulong  slot;
  ulong  own_rank;
  ulong  spill_off; /* this slot's spill file region */
  uint   sig_pg[ AG_SLOT_VOTE_SIG_MAX ][ fd_bls_set_word_cnt ]; /* 0 none yet, AG_SIG_PG_DISK, else RAM page+1 */
  ushort shred_version;
};
typedef struct ag_slot_state ag_slot_state_t;

struct ag_slot_states {
  uchar *                 sig_pg;      /* RAM pages of AG_SIG_PG_RANKS */
  uint *                  sig_pg_free; /* free page stack */
  ulong                   sig_pg_free_cnt;
  int                     spill_fd;
  ag_epoch_info_t const * prev_epoch_info;
  ulong                   prev_epoch_rank;
  ulong                   prev_epoch_slot;
  ag_epoch_info_t const * curr_epoch_info;
  ulong                   curr_epoch_rank;
  ulong                   curr_epoch_slot;
  ag_epoch_info_t const * next_epoch_info;
  ulong                   next_epoch_rank;
  ulong                   next_epoch_slot;
  ulong                   bls_verify_cnt;
};
typedef struct ag_slot_states ag_slot_states_t;

FD_PROTOTYPES_BEGIN

/* Resets self to an empty slot state.  self must be zeroed memory or a
   slot state. */

void
ag_slot_state_null( ag_slot_state_t *  self,
                    ag_slot_states_t * states );

/* Replaces our rank own_rank (USHORT_MAX if unstaked). */

void
ag_slot_state_set_own_rank( ag_slot_state_t * self,
                            ulong             own_rank );

/* Definition 13. SlotState::add_cert */

void
ag_slot_state_add_cert( ag_slot_state_t * self,
                        ag_cert_t const * cert );

/* Definition 12. SlotState::add_vote */

int
ag_slot_state_add_vote( ag_slot_state_t *  self,
                        ag_slot_states_t * states,
                        ag_vote_t const *  vote,
                        ulong              stake,
                        ag_cert_t *        out_cert_events,
                        ulong *            out_cert_event_cnt,
                        ag_block_id_t *    out_safe_to_notar,
                        ulong *            out_safe_to_notar_cnt,
                        ulong *            out_safe_to_skip,
                        ulong *            out_safe_to_skip_cnt,
                        ag_block_id_t *    out_repair_events,
                        ulong *            out_repair_event_cnt,
                        fd_bls_set_t *     bad );

/* Definition 16. SlotState::notify_parent_known */

void
ag_slot_state_notify_parent_known( ag_slot_state_t *     self,
                                   ag_slot_states_t *    states,
                                   ag_block_hash_t const block_hash,
                                   fd_bls_set_t *        bad );

/* Definition 16. SlotState::notify_parent_certified */

int
ag_slot_state_notify_parent_certified( ag_slot_state_t *     self,
                                       ag_slot_states_t *    states,
                                       ag_block_hash_t const block_hash,
                                       fd_bls_set_t *        bad );

/* SlotState::check_slashable_offence */

int
ag_slot_state_check_slashable_offence( ag_slot_state_t const *  self,
                                       ag_slot_states_t const * states,
                                       ag_vote_t const *        vote );

/* Definition 12. SlotState::should_ignore_vote */

int
ag_slot_state_should_ignore_vote( ag_slot_state_t const *  self,
                                  ag_slot_states_t const * states,
                                  ag_vote_t const *        vote );

/* Definition 13. SlotState::is_notar_fallback */

FD_FN_PURE int
ag_slot_state_is_notar_fallback( ag_slot_state_t const * self,
                                 ag_block_hash_t const   block_hash );

/* Definition 13. SlotState::is_notar_fallback_or_stronger */

FD_FN_PURE int
ag_slot_state_is_notar_fallback_or_stronger( ag_slot_state_t const * self,
                                             ag_block_hash_t const   block_hash );

/* Accessors for reward certs */

fd_bls_agg_t *
ag_slot_state_notar_reward_agg( ag_slot_state_t const *  self,
                                ag_slot_states_t const * states,
                                fd_bls_agg_t *           out );

FD_FN_PURE fd_bls_agg_t const *
ag_slot_state_skip_reward_agg( ag_slot_state_t const * self );

/* Copies into out the block hash of rank's notar vote (kind NOTAR) or
   its j-th notar fallback vote. */

uchar *
ag_slot_state_vote_hash( ag_slot_state_t const *  self,
                         ag_slot_states_t const * states,
                         uint                     kind,
                         ulong                    rank,
                         ulong                    j,
                         ag_block_hash_t          out );

/* Copies into out the sig of rank's kind vote (j-th for notar
   fallback). */

fd_bls_sig_t *
ag_slot_state_vote_sig( ag_slot_state_t const *  self,
                        ag_slot_states_t const * states,
                        uint                     kind,
                        ulong                    rank,
                        ulong                    j,
                        fd_bls_sig_t *           out );

/* Copies the kind vote sigs of the ranks in set into out[ rank ].
   block_hash selects the sig for notar fallback; for notar the caller
   filters set by hash. */

fd_bls_sig_t *
ag_slot_state_sigs( ag_slot_state_t const *  self,
                    ag_slot_states_t const * states,
                    uint                     kind,
                    ag_block_hash_t const    block_hash,
                    fd_bls_set_t const *     set,
                    fd_bls_sig_t *           out );

/* fd_bls_agg_verify_subtract of agg (kind votes of self, block_hash
   as in ag_slot_state_sigs) on msg, reading the sigs only if the
   aggregate fails. */

int
ag_slot_state_agg_verify( ag_slot_state_t const *  self,
                          ag_slot_states_t const * states,
                          uint                     kind,
                          ag_block_hash_t const    block_hash,
                          uchar const *            msg,
                          ulong                    msg_sz,
                          fd_bls_agg_t *           agg,
                          fd_bls_set_t *           bad );

FD_PROTOTYPES_END

#endif
