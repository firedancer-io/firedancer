#include "fd_slot_params.h"
#include "fd_bank.h"
#include "../features/fd_features.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include <string.h>

/* Tests fd_slot_params against Agave's slot_params.rs cost-limit
   test and test_reduce_slot_time_range_duration.  Default is
   FD_SLOT_PARAMS_400MS (FD assumes a 400ms genesis). */

#define SLOTS_PER_EPOCH (32UL)

static fd_epoch_schedule_t
test_epoch_schedule( void ) {
  /* No-warmup, 32-slot epochs.  Agave EpochSchedule::custom(32, 32,
     false). */
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
  return a->ns_per_slot                        ==b->ns_per_slot
      && a->slots_per_year                     ==b->slots_per_year
      && a->hashes_per_tick                    ==b->hashes_per_tick
      && a->max_block_units                    ==b->max_block_units
      && a->max_writable_account_units         ==b->max_writable_account_units
      && a->max_block_accounts_data_size_delta ==b->max_block_accounts_data_size_delta
      && a->max_shred_idx                      ==b->max_shred_idx
      && a->max_entry_bytes_per_slot           ==b->max_entry_bytes_per_slot
      && a->stake_account_stores_per_block     ==b->stake_account_stores_per_block;
}

/* fd_slot_params_slot_range_duration_{ns,years} take a bank.  These
   wrappers stuff hand-built params/features/schedule into a scratch
   bank so the range logic can be tested without bank infrastructure. */
static fd_bank_t range_bank[1];

static ulong
range_ns( fd_slot_params_t const *    d,
          fd_features_t const *       f,
          fd_epoch_schedule_t const * es,
          ulong                       start_slot,
          ulong                       end_slot ) {
  range_bank->f.slot_params_default = *d;
  range_bank->f.features            = *f;
  range_bank->f.epoch_schedule      = *es;
  return fd_slot_params_slot_range_duration_ns( range_bank, start_slot, end_slot );
}

static double
range_years( fd_slot_params_t const *    d,
             fd_features_t const *       f,
             fd_epoch_schedule_t const * es,
             ulong                       start_slot,
             ulong                       end_slot ) {
  range_bank->f.slot_params_default = *d;
  range_bank->f.features            = *f;
  range_bank->f.epoch_schedule      = *es;
  return fd_slot_params_slot_range_duration_years( range_bank, start_slot, end_slot );
}

/* Assert the regime effective at `slot` equals `exp`. */
#define EXPECT_REGIME( feat, es, slot, exp ) do {                                               \
    fd_slot_params_t _p = fd_slot_params_lookup( &FD_SLOT_PARAMS_400MS, (feat), (es), (slot) ); \
    FD_TEST( params_eq( &_p, &(exp) ) );                                                        \
  } while( 0 )

/* Cost-limit scaling now lives in fd_cost_tracker.c; exercised via
   fd_cost_tracker_init in test_cost_tracker.c. */

static void
test_default_only( void ) {
  fd_epoch_schedule_t es = test_epoch_schedule();
  fd_features_t       f  = no_features();
  EXPECT_REGIME( &f, &es, 0UL,    FD_SLOT_PARAMS_400MS );
  EXPECT_REGIME( &f, &es, 1000UL, FD_SLOT_PARAMS_400MS );
}

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

/* Out-of-order activation normalizes like Agave: the redundant 350ms
   transition (longer than the already-effective 200ms) is dropped,
   leaving no segment boundary at slot 64.  range_years must integrate
   over those segments, or float rounding (a/spy + b/spy != (a+b)/spy)
   diverges from Agave's bank hash. */
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

  /* range_ns is integer-exact across the dropped boundary. */
  FD_TEST( range_ns( &FD_SLOT_PARAMS_400MS, &f, &es,  0UL, 160UL )==(uint128)32UL*ns400 + (uint128)128UL*ns200 );
  FD_TEST( range_ns( &FD_SLOT_PARAMS_400MS, &f, &es, 40UL, 100UL )==(uint128)60UL*ns200 );

  /* range_years must integrate over the normalized segments (no split
     at 64). */
  FD_TEST( range_years( &FD_SLOT_PARAMS_400MS, &f, &es, 32UL,  66UL )==(double)34UL/spy200 );
  FD_TEST( range_years( &FD_SLOT_PARAMS_400MS, &f, &es,  0UL,  66UL )==(double)32UL/spy400 + (double)34UL/spy200 ); /* crosses 32 and 64 */
  FD_TEST( range_years( &FD_SLOT_PARAMS_400MS, &f, &es, 40UL, 100UL )==(double)60UL/spy200 );

  /* Ranges that don't straddle slot 64 already agree. */
  FD_TEST( range_years( &FD_SLOT_PARAMS_400MS, &f, &es, 32UL,  64UL )==(double)32UL/spy200 );
  FD_TEST( range_years( &FD_SLOT_PARAMS_400MS, &f, &es,  0UL,  32UL )==(double)32UL/spy400 );
}

/* All four gates activated out of slot-time order.  Effective slots:
   300ms@32, 350ms@64, 200ms@96, 250ms@128.  Slot time only decreases,
   so the normalized sequence is 400ms [0,32), 300ms [32,96), 200ms
   [96,inf) — 350ms@64 and 250ms@128 are dropped.  Mirror of Agave's
   test_out_of_order_all_gates_matches_fd. */
static void
test_out_of_order_all_gates( void ) {
  fd_epoch_schedule_t es = test_epoch_schedule();
  fd_features_t       f  = no_features();
  f.reduce_slot_time_to_300ms = 1UL;   /* effective 32  — real:  400->300 */
  f.reduce_slot_time_to_350ms = 33UL;  /* effective 64  — redundant (350 > 300) */
  f.reduce_slot_time_to_200ms = 65UL;  /* effective 96  — real:  300->200 */
  f.reduce_slot_time_to_250ms = 97UL;  /* effective 128 — redundant (250 > 200) */

  /* Regime selection. */
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

  /* range_ns (half-open) [0,160): 32 @ 400ms, 64 @ 300ms, 64 @
     200ms. */
  FD_TEST( range_ns( &FD_SLOT_PARAMS_400MS, &f, &es, 0UL, 160UL )
           ==(uint128)32UL*ns400 + (uint128)64UL*ns300 + (uint128)64UL*ns200 );

  /* range_years over the same segments. */
  FD_TEST( range_years( &FD_SLOT_PARAMS_400MS, &f, &es, 0UL, 160UL )
           ==(double)32UL/spy400 + (double)64UL/spy300 + (double)64UL/spy200 );
}

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
  FD_TEST( range_ns( &FD_SLOT_PARAMS_400MS, &f, &es, 0UL, SLOTS_PER_EPOCH*5UL )==exp_ns );

  /* range_years over half-open [0, 5*32=160). */
  double exp_years = (double)SLOTS_PER_EPOCH/FD_SLOT_PARAMS_400MS.slots_per_year
                   + (double)SLOTS_PER_EPOCH/FD_SLOT_PARAMS_350MS.slots_per_year
                   + (double)SLOTS_PER_EPOCH/FD_SLOT_PARAMS_300MS.slots_per_year
                   + (double)SLOTS_PER_EPOCH/FD_SLOT_PARAMS_250MS.slots_per_year
                   + (double)SLOTS_PER_EPOCH/FD_SLOT_PARAMS_200MS.slots_per_year;
  FD_TEST( range_years( &FD_SLOT_PARAMS_400MS, &f, &es, 0UL, SLOTS_PER_EPOCH*5UL )==exp_years );

  /* Empty ranges: start>=end. */
  FD_TEST( range_ns( &FD_SLOT_PARAMS_400MS, &f, &es, 5UL, 4UL )==(uint128)0 );
  FD_TEST( range_years( &FD_SLOT_PARAMS_400MS, &f, &es, 5UL, 5UL )==0.0         );

  /* No reduction: constant default. */
  fd_features_t f0 = no_features();
  FD_TEST( range_ns( &FD_SLOT_PARAMS_400MS, &f0, &es, 0UL, 100UL )==(uint128)100UL*FD_SLOT_PARAMS_400MS.ns_per_slot );
  FD_TEST( range_years( &FD_SLOT_PARAMS_400MS, &f0, &es, 0UL, 100UL )==(double)100UL/FD_SLOT_PARAMS_400MS.slots_per_year );
}

/* Snapshot-restore baseline selection.  Hand-kept copy of the static
   fd_replay_tile.c:restore_default_slot_params, FD's analogue of
   Agave's snapshot_restore_slot_params_baseline
   (https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/bank.rs#L2775).
   Returns the slot-0 default: the 400ms baseline once a reduction is
   effective, else the restored manifest params. */
static fd_slot_params_t
restore_default_slot_params( fd_slot_params_t const *    manifest,
                             fd_features_t const *       features,
                             fd_epoch_schedule_t const * es,
                             ulong                       slot ) {
  int reduction_effective =
      fd_slot_params_lookup( &FD_SLOT_PARAMS_400MS, features, es, slot ).ns_per_slot
        < FD_SLOT_PARAMS_400MS.ns_per_slot;
  return reduction_effective ? FD_SLOT_PARAMS_400MS : *manifest;
}

static void
test_snapshot_baseline_select( void ) {
  fd_epoch_schedule_t es = test_epoch_schedule();

  /* 350ms@1 -> effective 32; 300ms@33 -> effective 64. */
  fd_features_t f = no_features();
  f.reduce_slot_time_to_350ms = 1UL;
  f.reduce_slot_time_to_300ms = 33UL;

  /* No reduction yet (slot 31 < 32): keep the manifest.  hpt=57500
     checks the restored fields survive rather than snapping to the
     400ms table (62500). */
  fd_slot_params_t manifest_pre = FD_SLOT_PARAMS_400MS;
  manifest_pre.hashes_per_tick  = 57500UL;
  fd_slot_params_t d0 = restore_default_slot_params( &manifest_pre, &f, &es, 31UL );
  FD_TEST( params_eq( &d0, &manifest_pre ) );
  FD_TEST( d0.hashes_per_tick==57500UL );

  /* Reduction effective (slot >= 32): the manifest holds a reduced
     regime, so revert to the 400ms baseline, else inflation over
     pre-reduction slots uses the reduced slots_per_year and the bank
     hash is wrong. */
  fd_slot_params_t manifest_350 = FD_SLOT_PARAMS_350MS;
  fd_slot_params_t d_b = restore_default_slot_params( &manifest_350, &f, &es, 32UL );
  FD_TEST( params_eq( &d_b, &FD_SLOT_PARAMS_400MS ) ); /* boundary: just effective */
  FD_TEST( d_b.hashes_per_tick==62500UL );

  fd_slot_params_t d1 = restore_default_slot_params( &manifest_350, &f, &es, 40UL );
  FD_TEST( params_eq( &d1, &FD_SLOT_PARAMS_400MS ) );

  fd_slot_params_t manifest_300 = FD_SLOT_PARAMS_300MS;
  fd_slot_params_t d2 = restore_default_slot_params( &manifest_300, &f, &es, 100UL );
  FD_TEST( params_eq( &d2, &FD_SLOT_PARAMS_400MS ) );

  /* No gate active: keep the manifest, even a non-400ms one. */
  fd_features_t    f_none      = no_features();
  fd_slot_params_t manifest_64 = FD_SLOT_PARAMS_400MS;
  manifest_64.ns_per_slot     = 64000000UL;
  manifest_64.slots_per_year  = 493076968.65;
  manifest_64.hashes_per_tick = 0UL;
  fd_slot_params_t d3 = restore_default_slot_params( &manifest_64, &f_none, &es, 1000UL );
  FD_TEST( params_eq( &d3, &manifest_64 ) );
}

/* hashes_per_tick feeds the tick count -> last blockhash -> bank
   hash, so it must switch to the table value at the effective slot.
   Agave guards this on !alpenglow; FD has no alpenglow gate yet. */
static void
test_hashes_per_tick( void ) {
  fd_epoch_schedule_t es = test_epoch_schedule();
  fd_features_t       f  = no_features();
  f.reduce_slot_time_to_350ms = 1UL;  /* effective 32 */
  f.reduce_slot_time_to_300ms = 33UL; /* effective 64 */
  f.reduce_slot_time_to_250ms = 65UL; /* effective 96 */
  f.reduce_slot_time_to_200ms = 97UL; /* effective 128 */

  /* hpt steps with the regime (Agave table values). */
  FD_TEST( fd_slot_params_lookup( &FD_SLOT_PARAMS_400MS, &f, &es,  31UL ).hashes_per_tick==62500UL );
  FD_TEST( fd_slot_params_lookup( &FD_SLOT_PARAMS_400MS, &f, &es,  32UL ).hashes_per_tick==54687UL );
  FD_TEST( fd_slot_params_lookup( &FD_SLOT_PARAMS_400MS, &f, &es,  64UL ).hashes_per_tick==46875UL );
  FD_TEST( fd_slot_params_lookup( &FD_SLOT_PARAMS_400MS, &f, &es,  96UL ).hashes_per_tick==39062UL );
  FD_TEST( fd_slot_params_lookup( &FD_SLOT_PARAMS_400MS, &f, &es, 128UL ).hashes_per_tick==31250UL );

  /* 400ms hpt is the exported LEGACY constant. */
  FD_TEST( FD_LEGACY_HASHES_PER_TICK==62500UL );
  FD_TEST( FD_SLOT_PARAMS_400MS.hashes_per_tick==FD_LEGACY_HASHES_PER_TICK );

  /* No reduction: a non-standard restored hpt (57500) flows through
     unchanged. */
  fd_slot_params_t manifest = FD_SLOT_PARAMS_400MS;
  manifest.hashes_per_tick  = 57500UL;
  fd_features_t f0 = no_features();
  FD_TEST( fd_slot_params_lookup( &manifest, &f0, &es, 10UL ).hashes_per_tick==57500UL );
}

/* Test that all the regimes have different ns_per_slot  */
static void
test_distinct_regimes( void ) {
  fd_slot_params_t const * r[] = { &FD_SLOT_PARAMS_400MS,
                                   &FD_SLOT_PARAMS_350MS,
                                   &FD_SLOT_PARAMS_300MS,
                                   &FD_SLOT_PARAMS_250MS,
                                   &FD_SLOT_PARAMS_200MS };
  ulong n = sizeof(r)/sizeof(r[0]);
  for( ulong i=0UL; i<n; i++ )
    for( ulong j=i+1UL; j<n; j++ )
      FD_TEST( r[i]->ns_per_slot != r[j]->ns_per_slot );
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
  test_distinct_regimes();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
