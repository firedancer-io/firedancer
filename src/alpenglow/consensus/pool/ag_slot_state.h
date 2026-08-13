#ifndef HEADER_fd_src_alpenglow_consensus_pool_ag_slot_state_h
#define HEADER_fd_src_alpenglow_consensus_pool_ag_slot_state_h

#include "../../ag_alpenglow_base.h"
#include "../ag_vote.h"
#include "../ag_cert.h"
#include "../ag_epoch_info.h"
#include "../ag_pool.h"              /* ag_pool_event_t */

#define AG_PARENT_STATUS_KNOWN     (1)
#define AG_PARENT_STATUS_CERTIFIED (2)

#define AG_SLASHABLE_NONE                        (0)
#define AG_SLASHABLE_NOTAR_DIFFERENT_HASH        (1)
#define AG_SLASHABLE_SKIP_AND_NOTARIZE           (2)
#define AG_SLASHABLE_SKIP_AND_FINALIZE           (3)
#define AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE (4)

#define AG_SLOT_STATE_OUT_CERT_MAX   (3UL)
#define AG_SLOT_STATE_OUT_EVENT_MAX  (3UL)
#define AG_SLOT_STATE_OUT_REPAIR_MAX (3UL)

struct ag_slot_state_outputs {
  ag_cert_t       certs        [ AG_SLOT_STATE_OUT_CERT_MAX   ]; ulong certs_cnt;
  ag_pool_event_t pool_events  [ AG_SLOT_STATE_OUT_EVENT_MAX  ]; ulong pool_events_cnt;
  ag_block_id_t   block_repairs[ AG_SLOT_STATE_OUT_REPAIR_MAX ]; ulong block_repairs_cnt;
};
typedef struct ag_slot_state_outputs ag_slot_state_outputs_t;

/* voted_stakes.notar / notar_fallback tally, per block hash, the stake
   voted for it, in descending stake order -- the top hash at index 0.

   Neither is bounded by AG_BLOCK_HASH_EQVOC_MAX: that bounds the hashes a
   slot can legitimately produce, but a vote's hash is a field its signer
   filled in, so the bound is the votes admitted.  One notar vote per rank,
   AG_NOTAR_FALLBACK_VOTE_MAX notar-fallback votes per rank. */

#define AG_NOTAR_STAKE_MAX          (AG_VAT_MAX)
#define AG_NOTAR_FALLBACK_STAKE_MAX (AG_VAT_MAX*AG_NOTAR_FALLBACK_VOTE_MAX)

struct ag_hashstake {
  fd_hash_t hash;
  ulong     stake;
};
typedef struct ag_hashstake ag_hashstake_t;

/* parents records, per block hash, whether we know the block's parent
   and whether that parent is certified.  Populated when a block is
   registered (ag_pool_add_block) and read by the safe-to-notar check,
   which returns MISSING_BLOCK -- and so triggers repair -- for a hash
   that is not in here yet. */

struct ag_parent_status {
  fd_hash_t hash;
  int       kind; /* AG_PARENT_STATUS_* */
};
typedef struct ag_parent_status ag_parent_status_t;

/* pending_safe_to_notar / sent_safe_to_notar are sets of block hashes.
   Unlike the tallies above these ARE bounded by what a hash must earn to
   get in: the weakest notar quorum is a fifth of the stake and a rank casts
   one notar vote, so at most five hashes can qualify. */

struct ag_hash_set {
  ulong     cnt;
  fd_hash_t hash[ AG_BLOCK_HASH_EQVOC_MAX ];
};
typedef struct ag_hash_set ag_hash_set_t;

/* The slot's votes, retained individually and indexed by ValidatorIndex,
   mirroring the reference's SlotVotes.  Certificates are built by
   gathering the votes for a block hash and handing them to the
   ag_*_cert_try_new constructors, the same way the reference's
   notar_votes() / try_new pair works, so nothing is aggregated until a
   threshold is actually crossed.  Our own votes need no separate copy:
   they are the entries at own_rank.

   An entry no validator has filled is Option::None, spelled slot
   ULONG_MAX: every vote carries the slot it is cast for and ULONG_MAX is
   never one of them, so the entry is its own presence bit and no parallel
   voter_set is needed.  ag_slot_state_init stamps it, since the zero a
   memset leaves behind is the perfectly real slot 0.  notar-fallback is
   the exception: it is a counted array per validator, so
   notar_fallback_cnt is its presence, and it has to be carried anyway to
   index the AG_NOTAR_FALLBACK_VOTE_MAX slots. */

struct ag_slot_votes {
  ag_notar_vote_t          notar             [AG_VAT_MAX];
  ag_notar_fallback_vote_t notar_fallback    [AG_VAT_MAX][AG_NOTAR_FALLBACK_VOTE_MAX];
  uchar                    notar_fallback_cnt[AG_VAT_MAX];
  ag_skip_vote_t           skip              [AG_VAT_MAX];
  ag_skip_fallback_vote_t  skip_fallback     [AG_VAT_MAX];
  ag_final_vote_t          finalize          [AG_VAT_MAX];
};
typedef struct ag_slot_votes ag_slot_votes_t;

struct ag_slot_voted_stake {
  ag_hashstake_t notar             [ AG_NOTAR_STAKE_MAX          ]; ulong notar_cnt;
  ag_hashstake_t notar_fallback    [ AG_NOTAR_FALLBACK_STAKE_MAX ]; ulong notar_fallback_cnt;
  ulong          skip;
  ulong          skip_fallback;
  ulong          finalize;
  ulong          notar_or_skip;
};
typedef struct ag_slot_voted_stake ag_slot_voted_stake_t;

/* A cert the slot does not hold is the same Option::None the votes use:
   slot ULONG_MAX.  notar-fallback is again the exception --
   notar_fallback_cnt counts the ones held. */

struct ag_slot_certificates {
  ag_notar_cert_t          notar;
  ag_notar_fallback_cert_t notar_fallback[ AG_NOTAR_FALLBACK_CERT_MAX ];
  ulong                    notar_fallback_cnt;
  ag_skip_cert_t           skip;
  ag_fast_final_cert_t     fast_finalize;
  ag_final_cert_t          finalize;
};
typedef struct ag_slot_certificates ag_slot_certificates_t;

/* The layout is public: the fields below are the slot's decisions, and
   wrapping each of them in a reader only obscured that.  Read them; the
   functions below are the ones that DO something. */

struct __attribute__((aligned(128UL))) ag_slot_state {
  ag_slot_votes_t        votes;
  ag_slot_voted_stake_t  voted_stakes;
  ag_slot_certificates_t certificates;

  ag_parent_status_t parents[ AG_BLOCK_HASH_EQVOC_MAX ];
  ulong              parents_cnt;

  ag_hash_set_t pending_safe_to_notar;
  ag_hash_set_t sent_safe_to_notar;
  int           sent_safe_to_skip;
  uint          own_agg_logged; /* per-cert-kind bits: own aggregation reached threshold post-cert (logged once) */

  ulong slot;
  ulong own_rank; /* our rank in this slot's epoch; identifies our own votes */

  /* Caller-owned and shared across every slot state in the epoch; the
     only pointer the struct holds. */

  ag_epoch_info_t const * epoch_info;
};
typedef struct ag_slot_state ag_slot_state_t;

FD_PROTOTYPES_BEGIN

/* ag_slot_state_init arms self for slot, discarding whatever a previous
   occupant accumulated.  It is the only lifecycle call: the struct is
   self-contained, so an owner recycling one out of an fd_pool does an
   ele_acquire and this, with no formatting step in between.  epoch_info is
   caller-owned and must outlive the slot state.  own_rank is OUR rank
   (ValidatorIndex) in it, which the slot state uses to tell our own votes
   apart from everyone else's. */

void
ag_slot_state_init( ag_slot_state_t *       self,
                    ulong                   slot,
                    ag_epoch_info_t const * epoch_info,
                    ulong                   own_rank );

/* ag_slot_state_vote_fits reports whether vote can be admitted -- only a
   notar-fallback signer past its per-slot cap cannot.  The caller must
   check this BEFORE ag_slot_state_add_vote: a vote lands in several places
   and there is no way to unwind a partial admission. */

FD_FN_PURE int
ag_slot_state_vote_fits( ag_slot_state_t const * self,
                         ag_vote_t const *       vote );

/* ag_slot_state_cert_fits reports whether cert can be recorded without
   exceeding AG_NOTAR_FALLBACK_CERT_MAX notar-fallback certs.  Only
   notar-fallback certs are held per block hash; every other kind is
   per-slot and always fits. */

FD_FN_PURE int
ag_slot_state_cert_fits( ag_slot_state_t const * self,
                         ag_cert_t const *       cert );

void
ag_slot_state_add_cert( ag_slot_state_t * self,
                        ag_cert_t const * cert );

ag_slot_state_outputs_t
ag_slot_state_add_vote( ag_slot_state_t * self,
                        ag_vote_t const * vote,
                        ulong             voter_stake );

void
ag_slot_state_notify_parent_known( ag_slot_state_t * self,
                                   fd_hash_t const * hash );

/* Marks hash's parent certified and reports what that made of the block:
   1 safe-to-notar, -1 its block is missing and wants repair, 0 neither.
   The safe-to-notar event and the repair are both just (self's slot, hash),
   which the caller already holds, so it builds whichever one the verdict
   calls for rather than being handed it.  notify_parent_known must have run
   for hash. */

int
ag_slot_state_notify_parent_certified( ag_slot_state_t * self,
                                       fd_hash_t const * hash );

FD_FN_PURE int
ag_slot_state_check_slashable_offence( ag_slot_state_t const * self,
                                       ag_vote_t const *       vote );

FD_FN_PURE int
ag_slot_state_should_ignore_vote( ag_slot_state_t const * self,
                                  ag_vote_t const *       vote );

/* ag_slot_state_stake returns the stake one of the two tallies -- pass
   voted_stakes.notar / notar_fallback with its cnt -- holds for hash, 0 if
   it holds none.  Ordered by stake, not by hash, so this is a scan over the
   hashes actually voted for. */

FD_FN_PURE ulong
ag_slot_state_stake( ag_hashstake_t const * ele,
                     ulong                  cnt,
                     fd_hash_t const *      hash );

/* is_notar_fallback asks only whether the slot holds a notar-fallback cert
   for block_hash, which is what deciding whether to build another one
   needs.  A parent-certified check wants _or_stronger: a notar or
   fast-final cert for the hash implies notarized-fallback, and either can
   arrive without the notar-fallback cert ever doing so. */

FD_FN_PURE int
ag_slot_state_is_notar_fallback( ag_slot_state_t const * self,
                                 fd_hash_t const *       block_hash );

FD_FN_PURE int
ag_slot_state_is_notar_fallback_or_stronger( ag_slot_state_t const * self,
                                            fd_hash_t const *       block_hash );

/* ag_slot_state_cert_voted_stake returns the stake accumulated from
   individual votes toward building cert's aggregate: notar
   [+ notar-fallback] stake for the cert's block hash, skip +
   skip-fallback, or finalize. */

FD_FN_PURE ulong ag_slot_state_cert_voted_stake( ag_slot_state_t const * self, ag_cert_t const * cert );

FD_PROTOTYPES_END

#endif
