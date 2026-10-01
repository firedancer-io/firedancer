#ifndef HEADER_fd_src_disco_pack_fd_pack_dual_lane_h
#define HEADER_fd_src_disco_pack_fd_pack_dual_lane_h

/* fd_pack_dual_lane pairs transactions that pack received both inside
   a bundle and over TPU (the "dual-lane" case: the same signed
   transaction, i.e. the same signature, sent both ways), and decides
   which lane won.  It is pure bookkeeping for metrics: it never
   influences scheduling.

   The pack tile inserts one entry per accepted non-vote TPU
   transaction and per transaction of each accepted bundle.  Entries
   live in a fixed-size table and are evicted oldest first.  A new
   entry pairs with the most recent unpaired entry of the other lane
   with the same signature.  As the two copies are scheduled, and as
   the bundle's outcome becomes known, the pair is evaluated; once
   decided, the verdict callback is invoked exactly once for the pair:

   - BUNDLE_WON: the bundle landed and was scheduled before the TPU
     copy (or the TPU copy was never scheduled).
   - TPU_WON: the TPU copy was scheduled before the bundle landed.  A
     scheduled TPU transaction is assumed to land.
   - NEITHER: the bundle did not land and the TPU copy was never
     scheduled, decided when one of the two entries is evicted.

   Because the two copies are the same transaction, the TPU copy pays
   exactly what that transaction pays inside the bundle; the bundle as
   a whole may pay more (e.g. a separate tip transaction). */

#include "../../ballet/fd_ballet_base.h"

#define FD_PACK_DUAL_LANE_TPU    0
#define FD_PACK_DUAL_LANE_BUNDLE 1

/* Verdicts.  The order matches the verdict part of the
   DualLanePairResult metrics enum. */

#define FD_PACK_DUAL_VERDICT_BUNDLE_WON 0
#define FD_PACK_DUAL_VERDICT_TPU_WON    1
#define FD_PACK_DUAL_VERDICT_NEITHER    2
#define FD_PACK_DUAL_VERDICT_CNT        3

/* Why the TPU copy won.  The order matches the DualLaneTpuWonCause
   metrics enum. */

#define FD_PACK_DUAL_TPU_WON_BUNDLE_LATE    0 /* the bundle arrived after the TPU copy was scheduled */
#define FD_PACK_DUAL_TPU_WON_BUNDLE_WAITING 1 /* the bundle was in pack, unscheduled, when the TPU copy was scheduled */
#define FD_PACK_DUAL_TPU_WON_BUNDLE_FAILED  2 /* the bundle was scheduled first but did not land */
#define FD_PACK_DUAL_TPU_WON_CNT            3

/* Evicting an entry younger than this suggests the table is too small
   to cover the time between the two copies' arrivals. */

#define FD_PACK_DUAL_MIN_RETENTION_NS (1000000000L)

struct fd_pack_dual_pair {
  int   verdict;
  ulong tpu_offer;    /* lamports: what the transaction itself offers */
  ulong bundle_offer; /* lamports: what its whole bundle offers */

  /* slot of the winning copy's schedule; for NEITHER, of the bundle's
     schedule, or ULONG_MAX if neither was scheduled */
  ulong slot;

  /* When each copy arrived and was scheduled (ns), 0 if not scheduled */
  long tpu_arrival_ns;
  long tpu_sched_ns;
  long bundle_arrival_ns;
  long bundle_sched_ns;
};
typedef struct fd_pack_dual_pair fd_pack_dual_pair_t;

typedef void (* fd_pack_dual_verdict_fn_t)( void * ctx, fd_pack_dual_pair_t const * pair );

struct fd_pack_dual;
typedef struct fd_pack_dual fd_pack_dual_t;

FD_PROTOTYPES_BEGIN

/* ent_max must be a power of two in [2, 2^31]. */

FD_FN_CONST ulong fd_pack_dual_align    ( void );
FD_FN_CONST ulong fd_pack_dual_footprint( ulong ent_max );

void *           fd_pack_dual_new ( void * mem, ulong ent_max );
fd_pack_dual_t * fd_pack_dual_join( void * mem );

/* fd_pack_dual_set_verdict_cb sets the verdict callback (process-local;
   call after every join).  The callback must not call back into dual. */

void fd_pack_dual_set_verdict_cb( fd_pack_dual_t * dual, fd_pack_dual_verdict_fn_t fn, void * ctx );

/* fd_pack_dual_insert_tpu records an accepted TPU transaction with
   64-byte first signature sig.  fd_pack_dual_insert_bundle records a
   transaction of an accepted bundle identified by bundle_obs_id (used
   to match later bundle updates); txn_offer is what the transaction
   offers and bundle_offer what the whole bundle offers.  now is the
   current time in ns (for eviction statistics).  Both return 1 if the
   entry formed a pair, 0 otherwise, and may invoke the verdict
   callback (for the new pair, or for a pair whose entry was
   evicted). */

int
fd_pack_dual_insert_tpu( fd_pack_dual_t * dual,
                         uchar const      sig[ static 64 ],
                         long             now );

int
fd_pack_dual_insert_bundle( fd_pack_dual_t * dual,
                            uchar const      sig[ static 64 ],
                            ulong            txn_offer,
                            ulong            bundle_offer,
                            ulong            bundle_obs_id,
                            long             now );

/* fd_pack_dual_tpu_scheduled records that the TPU transaction with
   signature sig was scheduled at time now in slot. */

void
fd_pack_dual_tpu_scheduled( fd_pack_dual_t * dual,
                            uchar const      sig[ static 64 ],
                            long             now,
                            ulong            slot );

/* fd_pack_dual_bundle_scheduled records that the bundle
   bundle_obs_id, which contains a transaction whose signature starts
   with the 8 bytes sig8 (as loaded by fd_ulong_load_8), was scheduled
   at time now in slot.  Call once per transaction in the bundle. */

void
fd_pack_dual_bundle_scheduled( fd_pack_dual_t * dual,
                               ulong            sig8,
                               ulong            bundle_obs_id,
                               long             now,
                               ulong            slot );

/* fd_pack_dual_bundle_done records the final outcome of bundle
   bundle_obs_id (landed or not; a bundle that left pack without being
   scheduled did not land).  Call once per transaction in the bundle. */

void
fd_pack_dual_bundle_done( fd_pack_dual_t * dual,
                          ulong            sig8,
                          ulong            bundle_obs_id,
                          int              landed );

/* fd_pack_dual_tpu_won_cause returns the FD_PACK_DUAL_TPU_WON_* cause
   of a pair whose verdict is FD_PACK_DUAL_VERDICT_TPU_WON. */

static inline int
fd_pack_dual_tpu_won_cause( fd_pack_dual_pair_t const * pair ) {
  if( (pair->bundle_sched_ns!=0L) & (pair->bundle_sched_ns<=pair->tpu_sched_ns) ) return FD_PACK_DUAL_TPU_WON_BUNDLE_FAILED;
  if( pair->bundle_arrival_ns>pair->tpu_sched_ns )                               return FD_PACK_DUAL_TPU_WON_BUNDLE_LATE;
  return FD_PACK_DUAL_TPU_WON_BUNDLE_WAITING;
}

/* Statistics */

ulong fd_pack_dual_evicted_young( fd_pack_dual_t const * dual ); /* evictions of entries younger than FD_PACK_DUAL_MIN_RETENTION_NS */
ulong fd_pack_dual_pair_cnt     ( fd_pack_dual_t const * dual ); /* pairs formed */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_pack_fd_pack_dual_lane_h */
