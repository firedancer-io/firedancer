#include "../../util/fd_util.h"

#include "fd_stake_warmup_cooldown_allowance.h"

#include "../../util/bits/fd_sat.h"
#include "../../util/bits/fd_float.h"
#include "../types/fd_cast.h"

/* Source of truth:
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L95 */

/* Legacy float constants referenced by the Rust tests:
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/state.rs#L35 */
static const double DEFAULT_WARMUP_COOLDOWN_RATE = 0.25;
/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/state.rs#L40 */
static const double NEW_WARMUP_COOLDOWN_RATE     = 0.09;

static inline ulong
abs_diff_ulong( ulong a, ulong b ) {
  return ( a > b ) ? ( a - b ) : ( b - a );
}

/* C port of Rust's `ulp::ulp_of_u64`: the gap between adjacent f64
   values at this magnitude (f64::next_up realized by incrementing the
   bit pattern of a positive finite double).
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/ulp.rs#L14 */
static inline ulong
ulp_of_u64( ulong magnitude ) {
  /* Avoid the special zero case by forcing at least 1 */
  double magnitude_f64 = (double)fd_ulong_max( magnitude, 1UL );

  /* spacing to the next representable f64 */
  double spacing = fd_double( fd_dblbits( magnitude_f64 ) + 1UL ) - magnitude_f64;

  /* Map back to integer units, clamp so we never return 0 */
  if( spacing<1.0 ) spacing = 1.0;
  return (ulong)spacing;
}

/* C port of Rust's `ulp::max_ulp_tolerance` ("10x ULP tolerance",
   widened from 4x after the proptest surfaced a valid 5-ULP case; see
   test_high_ulp_case below).
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/ulp.rs#L32 */
static inline ulong
max_ulp_tolerance( ulong candidate, ulong oracle ) {
  ulong mag = fd_ulong_max( candidate, oracle );
  return fd_ulong_sat_mul( ulp_of_u64( mag ), 10UL );
}

/* The legacy oracle deliberately keeps the unwrap_or(ULONG_MAX)
   semantics of the deprecated float implementation (a missing
   activation epoch selects the new rate at epoch ULONG_MAX), unlike
   fd_stake_warmup_cooldown_rate_bps which mirrors the Rust
   is_some_and semantics.  The proptest samples epochs well below
   ULONG_MAX, so the two never disagree here.
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L334 */
static inline double
legacy_warmup_cooldown_rate( ulong epoch, ulong const * new_rate_activation_epoch ) {
  return ( epoch < ( new_rate_activation_epoch ? *new_rate_activation_epoch : ULONG_MAX ) )
           ? DEFAULT_WARMUP_COOLDOWN_RATE
           : NEW_WARMUP_COOLDOWN_RATE;
}

/* Legacy f64 oracle used by the Rust proptest.  Rust's `as u64` is a
   saturating cast; a raw C cast is undefined for out-of-range values
   (and diverges between x86_64 and aarch64 hardware), so use the fd
   helper that replicates Rust semantics.
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L346 */
static ulong
calculate_stake_delta_f64_legacy( ulong account_portion,
                                  ulong cluster_portion,
                                  ulong cluster_effective,
                                  ulong epoch,
                                  ulong const * new_rate_activation_epoch ) {
  if( cluster_portion==0UL || account_portion==0UL || cluster_effective==0UL ) return 0UL;

  double weight = (double)account_portion / (double)cluster_portion;
  double rate   = legacy_warmup_cooldown_rate( epoch, new_rate_activation_epoch );

  double newly_effective_cluster_stake = (double)cluster_effective * rate;
  return fd_rust_cast_double_to_ulong( weight * newly_effective_cluster_stake );
}

static inline ulong
xorshift64star( ulong * s ) {
  ulong x = *s;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  *s = x;
  return x * 2685821657736338717UL;
}

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L158 */
static void
test_rate_bps_selects_expected( void ) {
  ulong ten  = 10UL;
  ulong zero = 0UL;

  struct { ulong epoch; ulong const * activation; ulong expected; } cases[] = {
    { 9UL,        &ten, FD_STAKE_ORIGINAL_WARMUP_COOLDOWN_RATE_BPS }, /* before activation epoch */
    { 10UL,       &ten, FD_STAKE_TOWER_WARMUP_COOLDOWN_RATE_BPS    }, /* at activation epoch */
    { 11UL,       &ten, FD_STAKE_TOWER_WARMUP_COOLDOWN_RATE_BPS    }, /* after activation epoch */
    { 123UL,      NULL, FD_STAKE_ORIGINAL_WARMUP_COOLDOWN_RATE_BPS }, /* without activation epoch */
    { 0UL,       &zero, FD_STAKE_TOWER_WARMUP_COOLDOWN_RATE_BPS    }, /* activation at epoch 0 uses new rate from genesis */
    { ULONG_MAX,  NULL, FD_STAKE_ORIGINAL_WARMUP_COOLDOWN_RATE_BPS }, /* None never activates even at ULONG_MAX */
  };

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    FD_TEST( fd_stake_warmup_cooldown_rate_bps( cases[i].epoch, cases[i].activation )==cases[i].expected );
  }
}

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L175 */
static void
test_activation_zero_cases_return_zero( void ) {
  fd_stake_history_entry_t prev1 = { .activating = 10UL, .effective = 100UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance( 0UL, 0UL, &prev1, &(ulong){0UL} )==0UL );

  fd_stake_history_entry_t prev2 = { .activating = 0UL, .effective = 100UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance( 0UL, 5UL, &prev2, &(ulong){0UL} )==0UL );

  fd_stake_history_entry_t prev3 = { .activating = 10UL, .effective = 0UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance( 0UL, 5UL, &prev3, &(ulong){0UL} )==0UL );
}

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L175 */
static void
test_cooldown_zero_cases_return_zero( void ) {
  fd_stake_history_entry_t prev1 = { .deactivating = 10UL, .effective = 100UL, .activating = 0UL };
  FD_TEST( fd_stake_calculate_deactivation_allowance( 0UL, 0UL, &prev1, &(ulong){0UL} )==0UL );

  fd_stake_history_entry_t prev2 = { .deactivating = 0UL, .effective = 100UL, .activating = 0UL };
  FD_TEST( fd_stake_calculate_deactivation_allowance( 0UL, 5UL, &prev2, &(ulong){0UL} )==0UL );

  fd_stake_history_entry_t prev3 = { .deactivating = 10UL, .effective = 0UL, .activating = 0UL };
  FD_TEST( fd_stake_calculate_deactivation_allowance( 0UL, 5UL, &prev3, &(ulong){0UL} )==0UL );
}

/* account share = 100 / 500 -> 1/5
   old rate: 1_000 * 25% = 250, expected 50
   new rate: 1_000 * 9%  = 90,  expected 18
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L191 */
static void
test_basic_proportional_allowance_matches_expected( void ) {
  ulong activation = 100UL;

  fd_stake_history_entry_t prev_act = { .activating = 500UL, .effective = 1000UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance(  99UL, 100UL, &prev_act, &activation )==50UL );
  FD_TEST( fd_stake_calculate_activation_allowance( 100UL, 100UL, &prev_act, &activation )==18UL );

  fd_stake_history_entry_t prev_deact = { .deactivating = 500UL, .effective = 1000UL, .activating = 0UL };
  FD_TEST( fd_stake_calculate_deactivation_allowance(  99UL, 100UL, &prev_deact, &activation )==50UL );
  FD_TEST( fd_stake_calculate_deactivation_allowance( 100UL, 100UL, &prev_deact, &activation )==18UL );
}

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L229 */
static void
test_activation_caps_at_account_portion_when_network_allowance_is_large( void ) {
  ulong current_epoch = 99UL;
  ulong activation    = 100UL;

  fd_stake_history_entry_t prev = { .activating = 100UL, .effective = 1000000UL, .deactivating = 0UL };

  ulong account_portion = 40UL;
  ulong result          = fd_stake_calculate_activation_allowance( current_epoch, account_portion, &prev, &activation );
  FD_TEST( result==account_portion );
}

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L229 */
static void
test_cooldown_caps_at_account_portion_when_network_allowance_is_large( void ) {
  ulong current_epoch = 0UL;

  fd_stake_history_entry_t prev = { .deactivating = 100UL, .effective = 1000000UL, .activating = 0UL };

  ulong account_portion = 70UL;
  ulong result          = fd_stake_calculate_deactivation_allowance( current_epoch, account_portion, &prev, NULL );
  FD_TEST( result==account_portion );
}

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L258 */
static void
test_overflow_scenario_still_rate_limits( void ) {
  ulong supply_lamports = 400000000000000000UL;
  ulong account_portion = supply_lamports;

  fd_stake_history_entry_t prev = {
    .activating   = supply_lamports,
    .deactivating = supply_lamports,
    .effective    = supply_lamports
  };

  ulong actual_activation   = fd_stake_calculate_activation_allowance  ( 100UL, account_portion, &prev, NULL );
  ulong actual_deactivation = fd_stake_calculate_deactivation_allowance( 100UL, account_portion, &prev, NULL );

  ulong rate_bps = FD_STAKE_ORIGINAL_WARMUP_COOLDOWN_RATE_BPS;
  __uint128_t n1 = (__uint128_t)account_portion * (__uint128_t)supply_lamports;
  int would_overflow = ( rate_bps!=0UL ) && ( n1 > ( UINT128_MAX / (__uint128_t)rate_bps ) );
  FD_TEST( would_overflow );

  ulong ideal_allowance = supply_lamports / 4UL;

  __uint128_t numerator =
      fd_uint128_sat_mul( fd_uint128_sat_mul( (__uint128_t)account_portion, (__uint128_t)supply_lamports ),
                          (__uint128_t)rate_bps );
  FD_TEST( numerator==UINT128_MAX );

  __uint128_t denominator = fd_uint128_sat_mul( (__uint128_t)supply_lamports, (__uint128_t)FD_STAKE_BASIS_POINTS_PER_UNIT );
  FD_TEST( denominator==(__uint128_t)400000000000000000UL * (__uint128_t)10000UL );

  ulong expected_result = (ulong)fd_uint128_min( (uint128)(numerator / denominator), (uint128)account_portion );
  FD_TEST( expected_result==85070591730234615UL );

  FD_TEST( actual_activation  ==expected_result );
  FD_TEST( actual_deactivation==expected_result );
  FD_TEST( actual_activation<account_portion );
  FD_TEST( actual_activation<=ideal_allowance );
}

/* Not present in the upstream suite; extra check that activation and
   deactivation share the same helper math given identical inputs. */
static void
test_activation_and_cooldown_are_symmetric_given_same_inputs( void ) {
  ulong epoch      = 42UL;
  ulong activation = 1000UL;

  fd_stake_history_entry_t prev = { .activating = 1000UL, .deactivating = 1000UL, .effective = 5000UL };
  ulong account = 333UL;

  ulong act  = fd_stake_calculate_activation_allowance( epoch, account, &prev, &activation );
  ulong cool = fd_stake_calculate_deactivation_allowance( epoch, account, &prev, &activation );
  FD_TEST( act==cool );
}

/* https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L312 */
static void
test_integer_division_truncation_matches_expected( void ) {
  ulong account_portion   = 100UL;
  ulong cluster_portion   = 1000UL;
  ulong cluster_effective = 10001UL;
  ulong epoch             = 20UL;
  ulong activation        = 10UL;

  fd_stake_history_entry_t prev = { .activating = cluster_portion, .effective = cluster_effective, .deactivating = 0UL };
  ulong result = fd_stake_calculate_activation_allowance( epoch, account_portion, &prev, &activation );
  FD_TEST( result==90UL );
}

/* Differs by 5 ULPs (difficult to find a higher diff); a valid case
   that the 10x tolerance must accept and a 4x tolerance would reject.
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L362 */
static void
test_high_ulp_case( void ) {
  ulong account_portion   = 342898401157885026UL;
  ulong cluster_portion   = 2426138261763124479UL;
  ulong cluster_effective = 708104488956562499UL;
  ulong current_epoch     = 10UL;
  ulong activation        = 0UL;

  fd_stake_history_entry_t prev = { .activating = cluster_portion, .effective = cluster_effective, .deactivating = 0UL };
  ulong integer_math_result = fd_stake_calculate_activation_allowance( current_epoch, account_portion, &prev, &activation );

  ulong float_math_result = calculate_stake_delta_f64_legacy( account_portion,
                                                              cluster_portion,
                                                              cluster_effective,
                                                              current_epoch,
                                                              &activation );
  if( float_math_result > account_portion ) float_math_result = account_portion;

  FD_TEST( integer_math_result==9007199253579461UL );
  FD_TEST( float_math_result ==9007199253579466UL );

  ulong diff      = abs_diff_ulong( integer_math_result, float_math_result );
  ulong tolerance = max_ulp_tolerance( integer_math_result, float_math_result );
  ulong ulp       = tolerance / 10UL;

  FD_TEST( ulp==1UL );
  FD_TEST( diff==5UL*ulp );
  FD_TEST( diff<=tolerance );
}

/* Rust uses `proptest! { ... with_cases(10_000) }`; this is a deterministic port.
   https://github.com/solana-program/stake/blob/1fc6e8433ae893b59b5156277617f07e09415cdc/interface/src/warmup_cooldown_allowance.rs#L399 */
static void
test_rate_limited_change_consistent_with_legacy( void ) {
  ulong rng = 0x123456789abcdef0UL;

  for( int i=0; i<10000; i++ ) {
    ulong account_portion   = xorshift64star( &rng );
    ulong cluster_portion   = xorshift64star( &rng );
    ulong cluster_effective = xorshift64star( &rng );

    /* xorshift64* never yields zero, so deterministically zero out
       inputs occasionally to exercise the zero-input branch (Rust's
       proptest reaches zeros via its edge-case bias). */
    ulong zero_mask = xorshift64star( &rng );
    if( !(  zero_mask      & 0x3fUL ) ) account_portion   = 0UL;
    if( !( (zero_mask>> 6) & 0x3fUL ) ) cluster_portion   = 0UL;
    if( !( (zero_mask>>12) & 0x3fUL ) ) cluster_effective = 0UL;

    ulong epoch = xorshift64star( &rng ) % 2001UL;

    ulong activation_value = xorshift64star( &rng ) % 2001UL;
    int   have_activation  = !!( xorshift64star( &rng ) & 1UL );
    ulong const * activation_opt = have_activation ? &activation_value : NULL;

    fd_stake_history_entry_t prev = { .activating = cluster_portion, .effective = cluster_effective, .deactivating = 0UL };
    ulong integer_math_result = fd_stake_calculate_activation_allowance( epoch, account_portion, &prev, activation_opt );

    ulong float_math_result = calculate_stake_delta_f64_legacy( account_portion,
                                                                cluster_portion,
                                                                cluster_effective,
                                                                epoch,
                                                                activation_opt );
    if( float_math_result > account_portion ) float_math_result = account_portion;

    ulong rate_bps = fd_stake_warmup_cooldown_rate_bps( epoch, activation_opt );

    int would_overflow = 0;
    if( account_portion && cluster_effective && rate_bps ) {
      __uint128_t prod = (__uint128_t)account_portion * (__uint128_t)cluster_effective;
      would_overflow   = prod > ( UINT128_MAX / (__uint128_t)rate_bps );
    }

    if( !account_portion || !cluster_portion || !cluster_effective ) {
      FD_TEST( integer_math_result==0UL );
      FD_TEST( float_math_result==0UL );
    } else if( would_overflow ) {
      /* In the overflow path, the helper saturates the numerator to
         UINT128_MAX, then divides and clamps to account_portion. */
      __uint128_t denominator = (__uint128_t)cluster_portion * (__uint128_t)FD_STAKE_BASIS_POINTS_PER_UNIT;
      ulong saturated_result  = (ulong)fd_uint128_min( UINT128_MAX / denominator, (uint128)account_portion );
      FD_TEST( integer_math_result==saturated_result );
    } else {
      FD_TEST( integer_math_result<=account_portion );
      FD_TEST( float_math_result<=account_portion );

      ulong diff      = abs_diff_ulong( integer_math_result, float_math_result );
      ulong tolerance = max_ulp_tolerance( integer_math_result, float_math_result );

      FD_TEST( diff<=tolerance );
    }
  }
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_rate_bps_selects_expected();

  test_activation_zero_cases_return_zero();
  test_cooldown_zero_cases_return_zero();

  test_basic_proportional_allowance_matches_expected();

  test_activation_caps_at_account_portion_when_network_allowance_is_large();
  test_cooldown_caps_at_account_portion_when_network_allowance_is_large();

  test_overflow_scenario_still_rate_limits();
  test_activation_and_cooldown_are_symmetric_given_same_inputs();
  test_integer_division_truncation_matches_expected();
  test_high_ulp_case();

  test_rate_limited_change_consistent_with_legacy();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
