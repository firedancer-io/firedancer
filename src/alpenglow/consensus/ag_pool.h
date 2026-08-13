#ifndef HEADER_fd_src_alpenglow_consensus_ag_pool_h
#define HEADER_fd_src_alpenglow_consensus_ag_pool_h

#include "../ag_alpenglow_base.h"
#include "ag_vote.h"
#include "ag_cert.h"
#include "ag_epoch_info.h"

/* PoolEvent in the reference (src/consensus/pool.rs): everything the pool
   tells the votor.  The reference's Standstill arm carries the certs and
   votes to re-broadcast alongside the slot; here the event is just the
   slot and the caller collects the bundle itself, with
   ag_pool_recover_from_standstill into its own buffers, so the event stays
   a fixed-size FIFO element. */

#define AG_POOL_EVENT_PARENT_READY  (0)
#define AG_POOL_EVENT_SAFE_TO_NOTAR (1)
#define AG_POOL_EVENT_SAFE_TO_SKIP  (2)
#define AG_POOL_EVENT_CERT_CREATED  (3)
#define AG_POOL_EVENT_STANDSTILL    (4)

struct ag_pool_event {
  int kind;
  union {
    struct { ulong slot; ag_block_id_t parent; } parent_ready;
    ag_block_id_t safe_to_notar;
    ulong         safe_to_skip;
    ag_cert_t     cert_created;
    ulong         standstill;
  } inner;
};
typedef struct ag_pool_event ag_pool_event_t;

#define AG_POOL_SUCCESS                ( 0)
#define AG_POOL_ERR_SLOT_OUT_OF_BOUNDS (-1)
#define AG_POOL_ERR_DUPLICATE          (-2)
#define AG_POOL_ERR_SLASHABLE          (-3)

/* HASH_CAPACITY has no reference counterpart: the vote / cert names a
   block hash the slot has no room left to track.  The per-hash stake
   tallies are sized for every vote a slot can admit, so a vote only lands
   here by exceeding a per-signer cap -- a rank past its
   AG_NOTAR_FALLBACK_VOTE_MAX notar-fallback votes.  A cert lands here once
   the slot holds AG_NOTAR_FALLBACK_CERT_MAX notar-fallback certs, which
   takes equivocation well past what the protocol admits. */

#define AG_POOL_ERR_HASH_CAPACITY      (-4)

/* Caller-buffer caps for ag_pool_recover_from_standstill's recovery
   bundle.  Only slots above the finalized one are unpruned and the loop
   re-runs every DELTA_STANDSTILL, so these are headroom rather than a
   functional limit; a bundle that hits them is truncated and logged. */

#define AG_POOL_STANDSTILL_CERT_MAX (4096UL)
#define AG_POOL_STANDSTILL_VOTE_MAX (4096UL)

/* The pool resolves stakes and BLS ranks from the epoch containing the
   vote's / cert's own slot, matching Agave's
   Bank::epoch_stakes_from_slot.  Like Agave that is an EPOCH-keyed
   lookup, not a slot-keyed one: the validator set is constant across an
   entire epoch.

   Only two epochs are ever reachable, so the pool holds exactly two --
   curr, the epoch the consensus root is in, and next, its successor.
   The one before curr is unreachable: all of its slots are at or below
   the root, so admission rejects them before any rank lookup.  The one
   after next is unverifiable: its stakes snapshot is only minted once
   the chain has crossed into next.  See ag_pool_set_epoch. */

typedef struct ag_pool ag_pool_t;

FD_PROTOTYPES_BEGIN

/* ag_pool_strerror converts an AG_POOL_SUCCESS / AG_POOL_ERR_* code into
   a cstr. */

FD_FN_CONST char const *
ag_pool_strerror( int err );

/* Construction.  The reference's PoolImpl::new takes the validator epoch
   info and both output channels as constructor arguments; here the
   channels live inside the pool's footprint and the epoch window is
   installed afterwards, by ag_pool_set_epoch. */

FD_FN_CONST ulong
ag_pool_align( void );

/* The footprint takes no validator count: a slot state is statically
   sized for AG_VAT_MAX of them -- its votes, and the per-hash stake they
   are tallied into, both -- so it is the same whatever set the epoch
   installs.  What the epoch is held to is AG_AGGSIG_MAX_SIGNERS, which
   ag_pool_set_epoch enforces against it. */

FD_FN_CONST ulong
ag_pool_footprint( ulong slot_max );

/* ag_pool_new formats a pool with an EMPTY epoch window, so no slot has a
   validator set to resolve against -- and callers must therefore drop
   every vote and cert -- until ag_pool_set_epoch installs at least curr,
   the epoch the root sits in. */

void *
ag_pool_new( void * mem,
             ulong  slot_max,
             ulong  seed );

ag_pool_t * ag_pool_join  ( void *            mem );
void *      ag_pool_leave ( ag_pool_t const * pool );
void *      ag_pool_delete( void *            mem );

/* ag_pool_set_root installs the consensus root the pool starts from.
   new only formats memory, so the pool has no root until this runs, and
   it is callable exactly once -- it asserts the root is still unset. */

void
ag_pool_set_root( ag_pool_t *       self,
                  ulong             slot,
                  fd_hash_t const * block_id );

/* ag_pool_set_epoch advances the two-epoch window by one: the epoch it is
   handed becomes next, and whatever next held becomes curr.  The first
   two calls fill the window rather than rotate it -- the first epoch
   handed over is the one the root sits in, so it becomes curr, and the
   second takes the empty next.  next's start slot is the exclusive end of
   curr, so until a second epoch arrives curr answers for every slot above
   its own start.  The pool only borrows the ag_epoch_info_t, so each
   stays caller-owned and must outlive its stay in the window.

   PRECONDITION: no live slot state may fall below curr's start slot.
   Every slot state caches the ag_epoch_info_t it was created against, so
   retiring an epoch that still has one is unrecoverable -- the pool
   cannot keep it (the caller is free to recycle that memory the moment
   this returns) and cannot drop it either (its slot is undecided, so the
   votes counted into it are still needed).  The caller therefore retires
   an epoch only once finalization has pruned past it: drain the pool's
   events, let handle_finalization shed everything below the finalized
   slot, and only then advance the window to the epoch that slot is in.
   Violating this is fatal, not silently corrected. */

void
ag_pool_set_epoch( ag_pool_t *             self,
                   ag_epoch_info_t const * next_epoch_info,
                   ulong                   next_epoch_rank,
                   ulong                   next_epoch_slot );

/* What follows is `trait Pool` in the reference implementation
   (src/consensus/pool.rs), declared in the trait's order: add_cert,
   add_vote, add_block, recover_from_standstill, finalized_slot,
   parents_ready, wait_for_parent_ready.

   The trait is the whole surface.  The pool's two outputs -- the
   reference's pool_event_sender and repair_sender -- have no accessor at
   the moment: the drain pair that used to expose them is gone and the
   replacement is TODO, so both FIFOs currently fill without a reader.
   The reference's inherent PoolImpl query methods (is_parent_ready,
   get_notarized_block, has_notar_cert, ...) have no counterpart:
   everything they reported is already carried by the CertCreated /
   ParentReady / SafeTo* events, and the pool's owner has to drain those
   anyway, so it tracks what it needs from the stream rather than polling
   the slot states back out.  ag_pool_t's layout, the two output FIFOs and
   the slot states they are fed from are all private to ag_pool.c. */

int
ag_pool_add_cert( ag_pool_t *       self,
                  ag_cert_t const * cert );

int
ag_pool_add_vote( ag_pool_t *       self,
                  ag_vote_t const * vote );

void
ag_pool_add_block( ag_pool_t *           self,
                   ag_block_id_t const * block_id,
                   ag_block_id_t const * parent_id );

void
ag_pool_recover_from_standstill( ag_pool_t * self,
                                 ag_cert_t * certs,
                                 ulong *     certs_cnt,
                                 ulong       certs_max,
                                 ag_vote_t * votes,
                                 ulong *     votes_cnt,
                                 ulong       votes_max );

FD_FN_PURE ulong
ag_pool_finalized_slot( ag_pool_t const * self );

ag_block_id_t const *
ag_pool_parents_ready( ag_pool_t * self,
                       ulong       slot,
                       ulong *     cnt );

/* ag_pool_wait_for_parent_ready asks for one parent to build slot on --
   slot being the first of a leader window we are about to produce for --
   and returns 1 having written it to out_id, or 0 if none is ready yet.

   The reference returns either the block id or a oneshot channel to await
   it on.  There is no channel to hand back here, so the 0 return IS the
   other arm: the caller stops, and picks the answer up from the
   ParentReady event the pool emits when the first parent lands.  Nothing
   is registered by asking, so asking again later is free and a caller
   that never asks still gets the event.

   Where parents_ready hands back every valid parent, this picks the one
   to use: lowest slot, ties broken by block hash.  That matches the
   reference's sort-then-take-first, and it is the conservative choice --
   building on the lowest ready parent leaves the most room for a higher
   one to still be notarized.  Asking about a slot opens tracker state for
   it, so this is not a const operation. */

int
ag_pool_wait_for_parent_ready( ag_pool_t *     self,
                               ulong           slot,
                               ag_block_id_t * out_id );

FD_PROTOTYPES_END

#endif
