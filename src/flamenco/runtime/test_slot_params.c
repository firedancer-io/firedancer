#include "fd_slot_params.h"
#include "../features/fd_features.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include <string.h>

/* Mirrors Agave's slot_params.rs cost-limit test and the bank-level
   test_reduce_slot_time_range_duration normalization cases, ported to the
   Firedancer stateless fd_slot_params API.  The default is fixed at
   FD_SLOT_PARAMS_400MS (Firedancer assumes the standard 400ms genesis). */

#define SLOTS_PER_EPOCH (32UL)

static fd_epoch_schedule_t
test_epoch_schedule( void ) {
  /* No-warmup, 32-slot epochs: epoch(s)=s/32, slot0(E)=32*E.  Matches
     Agave EpochSchedule::custom(32, 32, false). */
  fd_epoch_schedule_t s;
  memset( &s, 0, sizeof(s) );
  s.slots_per_epoch             = SLOTS_PER_EPOCH;
  s.leader_schedule_slot_offset = SLOTS_PER_EPOCH;
  s.warmup                      = 0;
  s.first_normal_epoch          = 0UL;
  s.first_normal_slot           = 0UL;
  return s;
}

static fd_features_t
no_features( void ) {
  fd_features_t f;
  memset( &f, 0xFF, sizeof(f) ); /* every field == FD_FEATURE_DISABLED */
  return f;
}

static int
params_eq( fd_slot_params_t const * a, fd_slot_params_t const * b ) {
  return a->ns_per_slot                                              ==b->ns_per_slot
      && a->slots_per_year                                           ==b->slots_per_year
      && a->hashes_per_tick                                          ==b->hashes_per_tick
      && a->max_block_units                                          ==b->max_block_units
      && a->max_writable_account_units                               ==b->max_writable_account_units
      && a->max_block_accounts_data_size_delta                       ==b->max_block_accounts_data_size_delta
      && a->max_shred_idx                                            ==b->max_shred_idx
      && a->max_entry_bytes_per_slot                                 ==b->max_entry_bytes_per_slot
      && a->partitioned_epoch_rewards_stake_account_stores_per_block ==b->partitioned_epoch_rewards_stake_account_stores_per_block;
}

/* Asserts the regime effective at `slot` (built from `feat`/`es` over the
   fixed 400ms default) equals `exp`. */
#define EXPECT_REGIME( feat, es, slot, exp ) do {                          \
    fd_slot_params_t _p = fd_slot_params_at_slot( &FD_SLOT_PARAMS_400MS, (feat), (es), (slot) );  \
    FD_TEST( params_eq( &_p, &(exp) ) );                                   \
  } while( 0 )

/* Cost-limit scaling (formerly fd_slot_params_cost_limits) is now a static
   helper inside fd_cost_tracker.c; its per-regime scaling is exercised via
   fd_cost_tracker_init in test_cost_tracker.c. */

static void
test_default_only( void ) {
  fd_epoch_schedule_t es = test_epoch_schedule();
  fd_features_t       f  = no_features();
  EXPECT_REGIME( &f, &es, 0UL,    FD_SLOT_PARAMS_400MS );
  EXPECT_REGIME( &f, &es, 1000UL, FD_SLOT_PARAMS_400MS );
}

/* https://github.com/anza-xyz/agave/blob/8d6ad05ea1424cb40e7bed7830759347b1b1571b/runtime/src/bank/tests.rs#L6516 (test_reduce_slot_time_range_duration, in-order case) */
static void
test_in_order_activation( void ) {
  fd_epoch_schedule_t es = test_epoch_schedule();
  fd_features_t       f  = no_features();
  f.reduce_slot_time_to_350ms = 1UL;  /* epoch 0 -> effective slot 32 */
  f.reduce_slot_time_to_300ms = 33UL; /* epoch 1 -> effective slot 64 */
  f.reduce_slot_time_to_250ms = 65UL; /* epoch 2 -> effective slot 96 */
  f.reduce_slot_time_to_200ms = 97UL; /* epoch 3 -> effective slot 128 */

  EXPECT_REGIME( &f, &es, 31UL,  FD_SLOT_PARAMS_400MS );
  EXPECT_REGIME( &f, &es, 32UL,  FD_SLOT_PARAMS_350MS );
  EXPECT_REGIME( &f, &es, 63UL,  FD_SLOT_PARAMS_350MS );
  EXPECT_REGIME( &f, &es, 64UL,  FD_SLOT_PARAMS_300MS );
  EXPECT_REGIME( &f, &es, 96UL,  FD_SLOT_PARAMS_250MS );
  EXPECT_REGIME( &f, &es, 200UL, FD_SLOT_PARAMS_200MS );
}

/* https://github.com/anza-xyz/agave/blob/8d6ad05ea1424cb40e7bed7830759347b1b1571b/runtime/src/bank/tests.rs#L6516 (test_reduce_slot_time_range_duration, out-of-order case) */
static void
test_out_of_order_normalization( void ) {
  fd_epoch_schedule_t es = test_epoch_schedule();
  fd_features_t       f  = no_features();
  f.reduce_slot_time_to_200ms = 1UL;                  /* epoch 0 -> effective 32 */
  f.reduce_slot_time_to_350ms = SLOTS_PER_EPOCH+1UL;  /* epoch 1 -> effective 64, redundant */

  /* 350ms transition is dropped: slot time never increases. */
  EXPECT_REGIME( &f, &es, 31UL, FD_SLOT_PARAMS_400MS );
  EXPECT_REGIME( &f, &es, 32UL, FD_SLOT_PARAMS_200MS );
  EXPECT_REGIME( &f, &es, 64UL, FD_SLOT_PARAMS_200MS );
}

/* Out-of-order activation must match Agave's *normalized* archive: the
   redundant 350ms transition (longer than the already-effective 200ms) is
   dropped, so the regime is 400ms on [0,32) and 200ms on [32,inf) — with NO
   segment boundary at slot 64.  The range integrators must reproduce that
   exact segmentation.  This matters for range_years: a spurious split at 64
   would change the floating-point rounding (a/spy + b/spy != (a+b)/spy),
   diverging from Agave's bank hash on the inflation path.  range_ns is
   integer-exact so it is robust, but we pin it too.

   Expected values are written exactly as Agave sums them: ascending over the
   normalized segments. */
static void
test_out_of_order_range( void ) {
  fd_epoch_schedule_t es = test_epoch_schedule();
  fd_features_t       f  = no_features();
  f.reduce_slot_time_to_200ms = 1UL;   /* effective 32 */
  f.reduce_slot_time_to_350ms = 33UL;  /* effective 64 — redundant, must be dropped */

  uint128 const ns400  = FD_SLOT_PARAMS_400MS.ns_per_slot;
  uint128 const ns200  = FD_SLOT_PARAMS_200MS.ns_per_slot;
  double  const spy400 = FD_SLOT_PARAMS_400MS.slots_per_year;
  double  const spy200 = FD_SLOT_PARAMS_200MS.slots_per_year;

  /* range_ns (half-open) — integer-exact even across the dropped boundary. */
  FD_TEST( fd_slot_params_slot_range_duration_ns( &FD_SLOT_PARAMS_400MS, &f, &es,  0UL, 160UL )==(uint128)32UL*ns400 + (uint128)128UL*ns200 ); /* [0,160), 64 interior */
  FD_TEST( fd_slot_params_slot_range_duration_ns( &FD_SLOT_PARAMS_400MS, &f, &es, 40UL, 100UL )==(uint128)60UL*ns200 );                        /* [40,100) inside 200ms, 64 interior */

  /* range_years (half-open) — must integrate over the normalized segments
     (no split at 64).  The first two inputs are chosen so that a spurious
     split at 64 changes the floating-point result (a/spy + b/spy !=
     (a+b)/spy), i.e. they diverge from Agave until the segmentation matches
     the normalized archive. */
  FD_TEST( fd_slot_params_slot_range_duration_years( &FD_SLOT_PARAMS_400MS, &f, &es, 32UL,  66UL )==(double)34UL/spy200 );                       /* [32,66), pure 200ms, 64 interior */
  FD_TEST( fd_slot_params_slot_range_duration_years( &FD_SLOT_PARAMS_400MS, &f, &es,  0UL,  66UL )==(double)32UL/spy400 + (double)34UL/spy200 ); /* [0,66), crosses 32 and 64 */
  FD_TEST( fd_slot_params_slot_range_duration_years( &FD_SLOT_PARAMS_400MS, &f, &es, 40UL, 100UL )==(double)60UL/spy200 );                       /* [40,100), 64 interior, single segment */

  /* Sanity: ranges that don't straddle slot 64 already agree. */
  FD_TEST( fd_slot_params_slot_range_duration_years( &FD_SLOT_PARAMS_400MS, &f, &es, 32UL,  64UL )==(double)32UL/spy200 ); /* boundary at the range end */
  FD_TEST( fd_slot_params_slot_range_duration_years( &FD_SLOT_PARAMS_400MS, &f, &es,  0UL,  32UL )==(double)32UL/spy400 ); /* pre-reduction segment */
}

/* All four gates activated OUT of slot-time order, exercising multiple
   redundant drops and a multi-regime range.  Effective slots (32-slot
   epochs): 300ms@32, 350ms@64, 200ms@96, 250ms@128.  Since slot time only
   decreases, the normalized regime sequence is 400ms on [0,32), 300ms on
   [32,96), 200ms on [96,inf) — the 350ms@64 and 250ms@128 gates are longer
   than the regime already in effect, so they are dropped (no segment
   boundary).  Mirror of the Agave test test_out_of_order_all_gates_matches_fd
   in runtime/src/slot_params.rs. */
static void
test_out_of_order_all_gates( void ) {
  fd_epoch_schedule_t es = test_epoch_schedule();
  fd_features_t       f  = no_features();
  f.reduce_slot_time_to_300ms = 1UL;   /* effective 32  — real:  400->300 */
  f.reduce_slot_time_to_350ms = 33UL;  /* effective 64  — redundant (350 > 300) */
  f.reduce_slot_time_to_200ms = 65UL;  /* effective 96  — real:  300->200 */
  f.reduce_slot_time_to_250ms = 97UL;  /* effective 128 — redundant (250 > 200) */

  /* Regime selection across the scramble. */
  EXPECT_REGIME( &f, &es,  31UL, FD_SLOT_PARAMS_400MS );
  EXPECT_REGIME( &f, &es,  32UL, FD_SLOT_PARAMS_300MS );
  EXPECT_REGIME( &f, &es,  64UL, FD_SLOT_PARAMS_300MS ); /* 350ms redundant */
  EXPECT_REGIME( &f, &es,  95UL, FD_SLOT_PARAMS_300MS );
  EXPECT_REGIME( &f, &es,  96UL, FD_SLOT_PARAMS_200MS );
  EXPECT_REGIME( &f, &es, 128UL, FD_SLOT_PARAMS_200MS ); /* 250ms redundant */
  EXPECT_REGIME( &f, &es, 200UL, FD_SLOT_PARAMS_200MS );

  uint128 const ns400  = FD_SLOT_PARAMS_400MS.ns_per_slot;
  uint128 const ns300  = FD_SLOT_PARAMS_300MS.ns_per_slot;
  uint128 const ns200  = FD_SLOT_PARAMS_200MS.ns_per_slot;
  double  const spy400 = FD_SLOT_PARAMS_400MS.slots_per_year;
  double  const spy300 = FD_SLOT_PARAMS_300MS.slots_per_year;
  double  const spy200 = FD_SLOT_PARAMS_200MS.slots_per_year;

  /* range_ns (half-open) [0,160): 32 @ 400ms, 64 @ 300ms, 64 @ 200ms. */
  FD_TEST( fd_slot_params_slot_range_duration_ns( &FD_SLOT_PARAMS_400MS, &f, &es, 0UL, 160UL )
           ==(uint128)32UL*ns400 + (uint128)64UL*ns300 + (uint128)64UL*ns200 );

  /* range_years (half-open) [0,160): same normalized segments.  A spurious
     boundary at 64 or 128 would change the float result here. */
  FD_TEST( fd_slot_params_slot_range_duration_years( &FD_SLOT_PARAMS_400MS, &f, &es, 0UL, 160UL )
           ==(double)32UL/spy400 + (double)64UL/spy300 + (double)64UL/spy200 );
}

/* https://github.com/anza-xyz/agave/blob/8d6ad05ea1424cb40e7bed7830759347b1b1571b/runtime/src/bank/tests.rs#L6516 (range duration) */
static void
test_range_integration( void ) {
  fd_epoch_schedule_t es = test_epoch_schedule();
  fd_features_t       f  = no_features();
  f.reduce_slot_time_to_350ms = 1UL;  /* effective 32 */
  f.reduce_slot_time_to_300ms = 33UL; /* effective 64 */
  f.reduce_slot_time_to_250ms = 65UL; /* effective 96 */
  f.reduce_slot_time_to_200ms = 97UL; /* effective 128 */

  /* range_ns over half-open [0, 5*32=160): 32 slots of each regime. */
  uint128 exp_ns = (uint128)SLOTS_PER_EPOCH*FD_SLOT_PARAMS_400MS.ns_per_slot
                 + (uint128)SLOTS_PER_EPOCH*FD_SLOT_PARAMS_350MS.ns_per_slot
                 + (uint128)SLOTS_PER_EPOCH*FD_SLOT_PARAMS_300MS.ns_per_slot
                 + (uint128)SLOTS_PER_EPOCH*FD_SLOT_PARAMS_250MS.ns_per_slot
                 + (uint128)SLOTS_PER_EPOCH*FD_SLOT_PARAMS_200MS.ns_per_slot;
  FD_TEST( fd_slot_params_slot_range_duration_ns( &FD_SLOT_PARAMS_400MS, &f, &es, 0UL, SLOTS_PER_EPOCH*5UL )==exp_ns );

  /* range_years over half-open [0, 5*32=160). */
  double exp_years = (double)SLOTS_PER_EPOCH/FD_SLOT_PARAMS_400MS.slots_per_year
                   + (double)SLOTS_PER_EPOCH/FD_SLOT_PARAMS_350MS.slots_per_year
                   + (double)SLOTS_PER_EPOCH/FD_SLOT_PARAMS_300MS.slots_per_year
                   + (double)SLOTS_PER_EPOCH/FD_SLOT_PARAMS_250MS.slots_per_year
                   + (double)SLOTS_PER_EPOCH/FD_SLOT_PARAMS_200MS.slots_per_year;
  FD_TEST( fd_slot_params_slot_range_duration_years( &FD_SLOT_PARAMS_400MS, &f, &es, 0UL, SLOTS_PER_EPOCH*5UL )==exp_years );

  /* Degenerate ranges (both half-open: start>=end is the empty range). */
  FD_TEST( fd_slot_params_slot_range_duration_ns   ( &FD_SLOT_PARAMS_400MS, &f, &es, 5UL, 4UL )==(uint128)0 ); /* start>end */
  FD_TEST( fd_slot_params_slot_range_duration_years( &FD_SLOT_PARAMS_400MS, &f, &es, 5UL, 5UL )==0.0         ); /* start>=end */

  /* No reduction: range reduces to a constant default. */
  fd_features_t f0 = no_features();
  FD_TEST( fd_slot_params_slot_range_duration_ns   ( &FD_SLOT_PARAMS_400MS, &f0, &es, 0UL, 100UL )==(uint128)100UL*FD_SLOT_PARAMS_400MS.ns_per_slot );
  FD_TEST( fd_slot_params_slot_range_duration_years( &FD_SLOT_PARAMS_400MS, &f0, &es, 0UL, 100UL )==(double)100UL/FD_SLOT_PARAMS_400MS.slots_per_year );
}

/* ---------------------------------------------------------------------------
   Snapshot-restore baseline selection (Phase 2 / §8a addendum).

   Hand-kept mirror of fd_replay_tile.c:restore_default_slot_params, which is
   Firedancer's analogue of Agave's snapshot_restore_slot_params_baseline
   (https://github.com/anza-xyz/agave/blob/8d6ad05ea1424cb40e7bed7830759347b1b1571b/runtime/src/bank.rs#L2779).
   The real function is static in the replay tile, so this copy is the unit
   under test (kept in sync by hand).  It returns the slot-0 default the
   reduce_slot_time gates normalize down from: the genesis 400ms baseline once
   a reduction is already effective at the restored slot, else the restored
   manifest params (so a pre-reduction chain keeps e.g. update_hashes_per_tick6's
   57500 hpt). */
static fd_slot_params_t
restore_default_slot_params( fd_slot_params_t const *    manifest,
                             fd_features_t const *       features,
                             fd_epoch_schedule_t const * es,
                             ulong                       slot ) {
  int reduction_effective =
      fd_slot_params_at_slot( &FD_SLOT_PARAMS_400MS, features, es, slot ).ns_per_slot
        < FD_SLOT_PARAMS_400MS.ns_per_slot;
  return reduction_effective ? FD_SLOT_PARAMS_400MS : *manifest;
}

static void
test_snapshot_baseline_select( void ) {
  fd_epoch_schedule_t es = test_epoch_schedule();

  /* 350ms flag@1 (epoch 0) -> effective 32; 300ms flag@33 (epoch 1) ->
     effective 64.  Mirrors the 300ms backtest ledger, which boots from a
     snapshot taken after an earlier reduction is already effective. */
  fd_features_t f = no_features();
  f.reduce_slot_time_to_350ms = 1UL;
  f.reduce_slot_time_to_300ms = 33UL;

  /* Case 1 -- no reduction effective yet (restore slot 31 < 32): keep the
     manifest verbatim.  The manifest carries hpt=57500 (the pre-
     update_hashes_per_tick6 mainnet value) to prove the restored fields are
     preserved, not clobbered to the 400ms table hpt (62500). */
  fd_slot_params_t manifest_pre = FD_SLOT_PARAMS_400MS;
  manifest_pre.hashes_per_tick  = 57500UL;
  fd_slot_params_t d0 = restore_default_slot_params( &manifest_pre, &f, &es, 31UL );
  FD_TEST( params_eq( &d0, &manifest_pre ) );
  FD_TEST( d0.hashes_per_tick==57500UL );

  /* Case 2 -- reduction effective.  At the 350ms effective slot (32) and
     beyond, the manifest holds a *reduced* regime, so the default reverts to
     the genesis 400ms baseline (else inflation integrated over pre-reduction
     slots uses the reduced slots_per_year -> wrong bank hash; this was the
     8/10-ledger bug).  Tested at the boundary and two deeper reductions. */
  fd_slot_params_t manifest_350 = FD_SLOT_PARAMS_350MS;
  fd_slot_params_t d_b = restore_default_slot_params( &manifest_350, &f, &es, 32UL );
  FD_TEST( params_eq( &d_b, &FD_SLOT_PARAMS_400MS ) ); /* boundary: just effective */
  FD_TEST( d_b.hashes_per_tick==62500UL );             /* manifest hpt dropped */

  fd_slot_params_t d1 = restore_default_slot_params( &manifest_350, &f, &es, 40UL );
  FD_TEST( params_eq( &d1, &FD_SLOT_PARAMS_400MS ) );

  fd_slot_params_t manifest_300 = FD_SLOT_PARAMS_300MS;
  fd_slot_params_t d2 = restore_default_slot_params( &manifest_300, &f, &es, 100UL );
  FD_TEST( params_eq( &d2, &FD_SLOT_PARAMS_400MS ) );

  /* No reduce_slot_time gate active: always keep the manifest, even a wildly
     non-400ms one (the 64ms-genesis multi-epoch-per-* test ledgers).  Proves
     we never spuriously revert a non-reduced chain to 400ms. */
  fd_features_t    f_none      = no_features();
  fd_slot_params_t manifest_64 = FD_SLOT_PARAMS_400MS;
  manifest_64.ns_per_slot     = (uint128)64000000UL;
  manifest_64.slots_per_year  = 493076968.65;
  manifest_64.hashes_per_tick = 0UL;
  fd_slot_params_t d3 = restore_default_slot_params( &manifest_64, &f_none, &es, 1000UL );
  FD_TEST( params_eq( &d3, &manifest_64 ) );
}

/* hashes_per_tick is consensus-critical: it sets the tick hash count ->
   last blockhash -> bank hash, so it must switch to the exact table value at
   the effective (E+2) slot.  Agave applies it in
   apply_slot_time_persistent_changes guarded on !alpenglow &&
   hashes_per_tick.is_some(); FD has no alpenglow gate yet, so it always
   applies when the regime's hpt != 0. */
static void
test_hashes_per_tick( void ) {
  fd_epoch_schedule_t es = test_epoch_schedule();
  fd_features_t       f  = no_features();
  f.reduce_slot_time_to_350ms = 1UL;  /* effective 32 */
  f.reduce_slot_time_to_300ms = 33UL; /* effective 64 */
  f.reduce_slot_time_to_250ms = 65UL; /* effective 96 */
  f.reduce_slot_time_to_200ms = 97UL; /* effective 128 */

  /* hpt steps with the regime at each effective slot (Agave slot_params.rs
     table values, verbatim). */
  FD_TEST( fd_slot_params_at_slot( &FD_SLOT_PARAMS_400MS, &f, &es,  31UL ).hashes_per_tick==62500UL );
  FD_TEST( fd_slot_params_at_slot( &FD_SLOT_PARAMS_400MS, &f, &es,  32UL ).hashes_per_tick==54687UL );
  FD_TEST( fd_slot_params_at_slot( &FD_SLOT_PARAMS_400MS, &f, &es,  64UL ).hashes_per_tick==46875UL );
  FD_TEST( fd_slot_params_at_slot( &FD_SLOT_PARAMS_400MS, &f, &es,  96UL ).hashes_per_tick==39062UL );
  FD_TEST( fd_slot_params_at_slot( &FD_SLOT_PARAMS_400MS, &f, &es, 128UL ).hashes_per_tick==31250UL );

  /* The 400ms regime hpt is the exported LEGACY constant. */
  FD_TEST( FD_LEGACY_HASHES_PER_TICK==62500UL );
  FD_TEST( FD_SLOT_PARAMS_400MS.hashes_per_tick==FD_LEGACY_HASHES_PER_TICK );

  /* When the default IS the manifest (no reduction, Case 1), a non-standard
     restored hpt (update_hashes_per_tick6 -> 57500) flows through unchanged --
     the regime equals the baseline when no gate is effective. */
  fd_slot_params_t manifest = FD_SLOT_PARAMS_400MS;
  manifest.hashes_per_tick  = 57500UL;
  fd_features_t f0 = no_features();
  FD_TEST( fd_slot_params_at_slot( &manifest, &f0, &es, 10UL ).hashes_per_tick==57500UL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_default_only();
  test_in_order_activation();
  test_range_integration();
  test_out_of_order_normalization();
  test_out_of_order_range();
  test_out_of_order_all_gates();
  test_snapshot_baseline_select();
  test_hashes_per_tick();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
