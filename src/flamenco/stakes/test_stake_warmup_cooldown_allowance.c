#include "../../util/fd_util.h"

#include "fd_stake_warmup_cooldown_allowance.h"

#include "../../util/bits/fd_sat.h"

static const double DEFAULT_WARMUP_COOLDOWN_RATE = 0.25;
static const double NEW_WARMUP_COOLDOWN_RATE     = 0.09;

static inline ulong
abs_diff_ulong( ulong a, ulong b ) {
  return ( a > b ) ? ( a - b ) : ( b - a );
}

static inline ulong
max_ulp_tolerance( ulong int_result, ulong float_result ) {
  ulong maxv = ( int_result > float_result ) ? int_result : float_result;
  if( maxv==0UL ) return 0UL;

  int bits = (int)( 8UL * sizeof(ulong) );
  int e    = ( bits - 1 ) - __builtin_clzl( maxv );

  ulong spacing;
  if( e<=52 ) spacing = 1UL;
  else        spacing = 1UL << (ulong)( e - 52 );

  __uint128_t tol = (__uint128_t)spacing * 4U;
  return ( tol > (__uint128_t)ULONG_MAX ) ? ULONG_MAX : (ulong)tol;
}

static inline double
legacy_warmup_cooldown_rate( ulong epoch, ulong const * new_rate_activation_epoch ) {
  return ( epoch < ( new_rate_activation_epoch ? *new_rate_activation_epoch : ULONG_MAX ) )
           ? DEFAULT_WARMUP_COOLDOWN_RATE
           : NEW_WARMUP_COOLDOWN_RATE;
}

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
  return (ulong)( weight * newly_effective_cluster_stake );
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

static void
test_rate_bps_before_activation_epoch_uses_prev_rate( void ) {
  ulong epoch      = 9UL;
  ulong activation = 10UL;
  ulong bps        = fd_stake_warmup_cooldown_rate_bps( epoch, &activation );
  FD_TEST( bps==FD_STAKE_ORIGINAL_WARMUP_COOLDOWN_RATE_BPS );
}

static void
test_rate_bps_at_or_after_activation_epoch_uses_curr_rate( void ) {
  ulong activation = 10UL;

  ulong epoch = 10UL;
  FD_TEST( fd_stake_warmup_cooldown_rate_bps( epoch, &activation )==FD_STAKE_TOWER_WARMUP_COOLDOWN_RATE_BPS );

  ulong epoch2 = 11UL;
  FD_TEST( fd_stake_warmup_cooldown_rate_bps( epoch2, &activation )==FD_STAKE_TOWER_WARMUP_COOLDOWN_RATE_BPS );
}

static void
test_rate_bps_none_activation_epoch_behaves_like_prev_rate( void ) {
  ulong epoch = 123UL;
  ulong bps   = fd_stake_warmup_cooldown_rate_bps( epoch, NULL );
  FD_TEST( bps==FD_STAKE_ORIGINAL_WARMUP_COOLDOWN_RATE_BPS );
}

static void
test_activation_zero_cases_return_zero( void ) {
  fd_stake_history_entry_t prev1 = { .activating = 10UL, .effective = 100UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance( 0UL, 0UL, &prev1, &(ulong){0UL} )==0UL );

  fd_stake_history_entry_t prev2 = { .activating = 0UL, .effective = 100UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance( 0UL, 5UL, &prev2, &(ulong){0UL} )==0UL );

  fd_stake_history_entry_t prev3 = { .activating = 10UL, .effective = 0UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance( 0UL, 5UL, &prev3, &(ulong){0UL} )==0UL );
}

static void
test_activation_basic_proportional_prev_rate( void ) {
  ulong current_epoch = 99UL;
  ulong activation    = 100UL;

  fd_stake_history_entry_t prev = { .activating = 500UL, .effective = 1000UL, .deactivating = 0UL };
  ulong result = fd_stake_calculate_activation_allowance( current_epoch, 100UL, &prev, &activation );
  FD_TEST( result==50UL );
}

static void
test_activation_caps_at_account_portion_when_network_allowance_is_large( void ) {
  ulong current_epoch = 99UL;
  ulong activation    = 100UL;

  fd_stake_history_entry_t prev = { .activating = 100UL, .effective = 1000000UL, .deactivating = 0UL };

  ulong account_portion = 40UL;
  ulong result          = fd_stake_calculate_activation_allowance( current_epoch, account_portion, &prev, &activation );
  FD_TEST( result==account_portion );
}

static void
test_activation_overflow_scenario_still_rate_limits( void ) {
  ulong supply_lamports = 400000000000000000UL;
  ulong account_portion = supply_lamports;

  fd_stake_history_entry_t prev = {
    .activating   = supply_lamports,
    .deactivating = 0UL,
    .effective    = supply_lamports
  };

  ulong actual_result = fd_stake_calculate_activation_allowance( 100UL, account_portion, &prev, NULL );

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

  FD_TEST( actual_result==expected_result );
  FD_TEST( actual_result<account_portion );
  FD_TEST( actual_result<=ideal_allowance );
}

static void
test_cooldown_zero_cases_return_zero( void ) {
  fd_stake_history_entry_t prev1 = { .deactivating = 10UL, .effective = 100UL, .activating = 0UL };
  FD_TEST( fd_stake_calculate_deactivation_allowance( 0UL, 0UL, &prev1, &(ulong){0UL} )==0UL );

  fd_stake_history_entry_t prev2 = { .deactivating = 0UL, .effective = 100UL, .activating = 0UL };
  FD_TEST( fd_stake_calculate_deactivation_allowance( 0UL, 5UL, &prev2, &(ulong){0UL} )==0UL );

  fd_stake_history_entry_t prev3 = { .deactivating = 10UL, .effective = 0UL, .activating = 0UL };
  FD_TEST( fd_stake_calculate_deactivation_allowance( 0UL, 5UL, &prev3, &(ulong){0UL} )==0UL );
}

static void
test_cooldown_basic_proportional_curr_rate( void ) {
  ulong current_epoch = 5UL;
  ulong activation    = 5UL;

  fd_stake_history_entry_t prev = { .deactivating = 1000UL, .effective = 10000UL, .activating = 0UL };

  ulong result = fd_stake_calculate_deactivation_allowance( current_epoch, 200UL, &prev, &activation );
  FD_TEST( result==180UL );
}

static void
test_cooldown_caps_at_account_portion_when_network_allowance_is_large( void ) {
  ulong current_epoch = 0UL;

  fd_stake_history_entry_t prev = { .deactivating = 100UL, .effective = 1000000UL, .activating = 0UL };

  ulong account_portion = 70UL;
  ulong result          = fd_stake_calculate_deactivation_allowance( current_epoch, account_portion, &prev, NULL );
  FD_TEST( result==account_portion );
}

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

static void
test_rate_limited_change_consistent_with_legacy( void ) {
  ulong rng = 0x123456789abcdef0UL;

  for( int i=0; i<10000; i++ ) {
    ulong account_portion   = xorshift64star( &rng );
    ulong cluster_portion   = xorshift64star( &rng );
    ulong cluster_effective = xorshift64star( &rng );

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
      FD_TEST( integer_math_result<=account_portion );
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

  test_rate_bps_before_activation_epoch_uses_prev_rate();
  test_rate_bps_at_or_after_activation_epoch_uses_curr_rate();
  test_rate_bps_none_activation_epoch_behaves_like_prev_rate();

  test_activation_zero_cases_return_zero();
  test_activation_basic_proportional_prev_rate();
  test_activation_caps_at_account_portion_when_network_allowance_is_large();
  test_activation_overflow_scenario_still_rate_limits();

  test_cooldown_zero_cases_return_zero();
  test_cooldown_basic_proportional_curr_rate();
  test_cooldown_caps_at_account_portion_when_network_allowance_is_large();

  test_activation_and_cooldown_are_symmetric_given_same_inputs();
  test_integer_division_truncation_matches_expected();

  test_rate_limited_change_consistent_with_legacy();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

