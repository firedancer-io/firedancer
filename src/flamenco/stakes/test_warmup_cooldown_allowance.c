#include "fd_stakes.c"
#include "../types/fd_cast.h"
#include "../../util/bits/fd_sat.h"
#include <math.h>

#define ORIGINAL_BPS (2500UL)
#define TOWER_BPS    (900UL)

static inline ulong
abs_diff_ulong( ulong a, ulong b ) {
  return a>b ? a-b : b-a;
}

static ulong
ulp_of_u64( ulong magnitude ) {
  double m   = (double)fd_ulong_max( magnitude, 1UL );
  int    exp = 0;
  frexp( m, &exp );
  int spacing_exp = exp - 53;
  if( spacing_exp<=0 ) return 1UL;
  return 1UL<<spacing_exp;
}

static ulong
max_ulp_tolerance( ulong candidate, ulong oracle ) {
  ulong mag = fd_ulong_max( candidate, oracle );
  ulong ulp = ulp_of_u64( mag );
  return ulp*10UL;
}

static double
legacy_warmup_cooldown_rate( ulong current_epoch, ulong * opt_rate_change_activation_epoch ) {
  ulong activation = opt_rate_change_activation_epoch ? *opt_rate_change_activation_epoch : ULONG_MAX;
  return current_epoch<activation ? 0.25 : 0.09;
}

static ulong
calculate_stake_delta_f64_legacy( ulong   account_portion,
                                  ulong   cluster_portion,
                                  ulong   cluster_effective,
                                  ulong   current_epoch,
                                  ulong * opt_rate_change_activation_epoch ) {
  if( cluster_portion==0UL || account_portion==0UL || cluster_effective==0UL ) return 0UL;
  double weight = (double)account_portion / (double)cluster_portion;
  double rate   = legacy_warmup_cooldown_rate( current_epoch, opt_rate_change_activation_epoch );
  double newly_effective_cluster_stake = (double)cluster_effective * rate;
  return fd_rust_cast_double_to_ulong( weight * newly_effective_cluster_stake );
}

static void
test_rate_bps_selects_expected( void ) {
  ulong ten = 10UL, zero = 0UL;
  FD_TEST( fd_stake_warmup_cooldown_rate_bps(  9UL, &ten )==ORIGINAL_BPS );
  FD_TEST( fd_stake_warmup_cooldown_rate_bps( 10UL, &ten )==TOWER_BPS    );
  FD_TEST( fd_stake_warmup_cooldown_rate_bps( 11UL, &ten )==TOWER_BPS    );
  FD_TEST( fd_stake_warmup_cooldown_rate_bps( 123UL, NULL )==ORIGINAL_BPS );
  FD_TEST( fd_stake_warmup_cooldown_rate_bps(  0UL, &zero )==TOWER_BPS    );
  FD_TEST( fd_stake_warmup_cooldown_rate_bps( ULONG_MAX, NULL )==ORIGINAL_BPS );
}

static void
test_activation_zero_cases_return_zero( void ) {
  ulong e0 = 0UL;
  fd_stake_history_entry_t prev1 = { .activating = 10UL, .effective = 100UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance( 0UL, 0UL, &prev1, &e0 )==0UL );
  fd_stake_history_entry_t prev2 = { .activating = 0UL, .effective = 100UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance( 0UL, 5UL, &prev2, &e0 )==0UL );
  fd_stake_history_entry_t prev3 = { .activating = 10UL, .effective = 0UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance( 0UL, 5UL, &prev3, &e0 )==0UL );
}

static void
test_cooldown_zero_cases_return_zero( void ) {
  ulong e0 = 0UL;
  fd_stake_history_entry_t prev1 = { .deactivating = 10UL, .effective = 100UL, .activating = 0UL };
  FD_TEST( fd_stake_calculate_deactivation_allowance( 0UL, 0UL, &prev1, &e0 )==0UL );
  fd_stake_history_entry_t prev2 = { .deactivating = 0UL, .effective = 100UL, .activating = 0UL };
  FD_TEST( fd_stake_calculate_deactivation_allowance( 0UL, 5UL, &prev2, &e0 )==0UL );
  fd_stake_history_entry_t prev3 = { .deactivating = 10UL, .effective = 0UL, .activating = 0UL };
  FD_TEST( fd_stake_calculate_deactivation_allowance( 0UL, 5UL, &prev3, &e0 )==0UL );
}

static void
test_basic_proportional_allowance( void ) {
  ulong activation = 100UL;
  fd_stake_history_entry_t prev_act = { .activating = 500UL, .effective = 1000UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance(  99UL, 100UL, &prev_act, &activation )==50UL );
  FD_TEST( fd_stake_calculate_activation_allowance( 100UL, 100UL, &prev_act, &activation )==18UL );

  fd_stake_history_entry_t prev_deact = { .deactivating = 500UL, .effective = 1000UL, .activating = 0UL };
  FD_TEST( fd_stake_calculate_deactivation_allowance(  99UL, 100UL, &prev_deact, &activation )==50UL );
  FD_TEST( fd_stake_calculate_deactivation_allowance( 100UL, 100UL, &prev_deact, &activation )==18UL );
}

static void
test_caps_at_account_portion( void ) {
  ulong activation = 100UL;
  fd_stake_history_entry_t prev_act = { .activating = 100UL, .effective = 1000000UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance( 99UL, 40UL, &prev_act, &activation )==40UL );

  fd_stake_history_entry_t prev_deact = { .deactivating = 100UL, .effective = 1000000UL, .activating = 0UL };
  FD_TEST( fd_stake_calculate_deactivation_allowance( 0UL, 70UL, &prev_deact, NULL )==70UL );
}

static void
test_overflow_scenario_still_rate_limits( void ) {
  ulong supply = 400000000000000000UL;
  ulong account_portion = supply;
  fd_stake_history_entry_t prev = { .activating = supply, .deactivating = supply, .effective = supply };

  ulong actual_activation   = fd_stake_calculate_activation_allowance  ( 100UL, account_portion, &prev, NULL );
  ulong actual_deactivation = fd_stake_calculate_deactivation_allowance( 100UL, account_portion, &prev, NULL );

  uint128 ae = (uint128)account_portion * (uint128)supply;
  FD_TEST( ae > ( UINT128_MAX / (uint128)ORIGINAL_BPS ) );

  uint128 numerator   = fd_uint128_sat_mul( fd_uint128_sat_mul( (uint128)account_portion, (uint128)supply ), (uint128)ORIGINAL_BPS );
  FD_TEST( numerator==UINT128_MAX );
  uint128 denominator = fd_uint128_sat_mul( (uint128)supply, (uint128)10000UL );
  FD_TEST( denominator==(uint128)400000000000000000UL * (uint128)10000UL );
  ulong expected = (ulong)fd_uint128_min( numerator/denominator, (uint128)account_portion );
  FD_TEST( expected==85070591730234615UL );

  FD_TEST( actual_activation  ==expected );
  FD_TEST( actual_deactivation==expected );
  FD_TEST( actual_activation<supply );
  FD_TEST( actual_activation<=supply/4UL );
}

static void
test_activation_and_cooldown_are_symmetric( void ) {
  ulong activation = 1000UL;
  fd_stake_history_entry_t prev = { .activating = 1000UL, .deactivating = 1000UL, .effective = 5000UL };
  ulong act  = fd_stake_calculate_activation_allowance( 42UL, 333UL, &prev, &activation );
  ulong cool = fd_stake_calculate_deactivation_allowance( 42UL, 333UL, &prev, &activation );
  FD_TEST( act==cool );
}

static void
test_integer_division_truncation( void ) {
  ulong activation = 10UL;
  fd_stake_history_entry_t prev = { .activating = 1000UL, .effective = 10001UL, .deactivating = 0UL };
  FD_TEST( fd_stake_calculate_activation_allowance( 20UL, 100UL, &prev, &activation )==90UL );
}

static void
test_high_ulp_case( void ) {
  ulong account_portion   = 342898401157885026UL;
  ulong cluster_portion   = 2426138261763124479UL;
  ulong cluster_effective = 708104488956562499UL;
  ulong e0                = 0UL;
  fd_stake_history_entry_t prev = { .activating = cluster_portion, .effective = cluster_effective, .deactivating = 0UL };

  ulong integer_math_result = fd_stake_calculate_activation_allowance( 10UL, account_portion, &prev, &e0 );
  ulong float_math_result   = fd_ulong_min( calculate_stake_delta_f64_legacy( account_portion, cluster_portion, cluster_effective, 10UL, &e0 ), account_portion );

  FD_TEST( integer_math_result==9007199253579461UL );
  FD_TEST( float_math_result  ==9007199253579466UL );

  ulong diff      = abs_diff_ulong( integer_math_result, float_math_result );
  ulong tolerance = max_ulp_tolerance( integer_math_result, float_math_result );
  ulong ulp       = tolerance/10UL;
  FD_TEST( ulp==1UL );
  FD_TEST( diff==5UL*ulp );
  FD_TEST( diff<=tolerance );
}

static void
test_ulp_helpers( void ) {
  FD_TEST( ulp_of_u64( 0UL )==1UL );
  FD_TEST( ulp_of_u64( 1UL )==1UL );
  FD_TEST( ulp_of_u64( (1UL<<53)-1UL )==1UL );
  FD_TEST( ulp_of_u64( 1UL<<53 )==2UL );
  FD_TEST( ulp_of_u64( ULONG_MAX )==4096UL );

  FD_TEST( max_ulp_tolerance( 0UL, 0UL )==10UL );
  FD_TEST( max_ulp_tolerance( 1UL<<53, 0UL )==20UL );
  FD_TEST( max_ulp_tolerance( 1UL<<54, 0UL )==40UL );
  FD_TEST( max_ulp_tolerance( 1UL<<55, 0UL )==80UL );
  FD_TEST( max_ulp_tolerance( ULONG_MAX, 0UL )==40960UL );
}

static void
test_float_int_parity( fd_rng_t * rng ) {
  ulong const cases = 2000000UL;
  for( ulong i=0UL; i<cases; i++ ) {
    ulong account_portion   = fd_rng_ulong( rng );
    ulong cluster_portion   = fd_rng_ulong( rng );
    ulong cluster_effective = fd_rng_ulong( rng );
    ulong current_epoch     = fd_rng_ulong( rng ) % 2001UL;
    int   has_activation    = (int)( fd_rng_uint( rng ) & 1U );
    ulong activation_epoch  = fd_rng_ulong( rng ) % 2001UL;
    ulong * activation_ptr  = has_activation ? &activation_epoch : NULL;

    fd_stake_history_entry_t prev = { .activating = cluster_portion, .effective = cluster_effective, .deactivating = 0UL };
    ulong integer_math_result = fd_stake_calculate_activation_allowance( current_epoch, account_portion, &prev, activation_ptr );
    ulong float_math_result   = fd_ulong_min( calculate_stake_delta_f64_legacy( account_portion, cluster_portion, cluster_effective, current_epoch, activation_ptr ), account_portion );

    ulong rate_bps = fd_stake_warmup_cooldown_rate_bps( current_epoch, activation_ptr );

    if( account_portion==0UL || cluster_portion==0UL || cluster_effective==0UL ) {
      FD_TEST( integer_math_result==0UL );
      FD_TEST( float_math_result  ==0UL );
      continue;
    }

    uint128 ae = (uint128)account_portion * (uint128)cluster_effective;
    int would_overflow = ae > ( UINT128_MAX / (uint128)rate_bps );

    if( would_overflow ) {
      uint128 denominator      = (uint128)cluster_portion * (uint128)10000UL;
      ulong   saturated_result = (ulong)fd_uint128_min( UINT128_MAX / denominator, (uint128)account_portion );
      FD_TEST( integer_math_result==saturated_result );
    } else {
      FD_TEST( integer_math_result<=account_portion );
      FD_TEST( float_math_result  <=account_portion );
      ulong diff      = abs_diff_ulong( integer_math_result, float_math_result );
      ulong tolerance = max_ulp_tolerance( integer_math_result, float_math_result );
      if( FD_UNLIKELY( diff>tolerance ) ) {
        FD_LOG_ERR(( "parity failed: candidate=%lu oracle=%lu diff=%lu tolerance=%lu (account=%lu cluster_portion=%lu cluster_effective=%lu epoch=%lu act=%s%lu)",
                     integer_math_result, float_math_result, diff, tolerance,
                     account_portion, cluster_portion, cluster_effective, current_epoch,
                     has_activation?"":"None:", activation_epoch ));
      }
    }
  }
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_rate_bps_selects_expected();
  test_activation_zero_cases_return_zero();
  test_cooldown_zero_cases_return_zero();
  test_basic_proportional_allowance();
  test_caps_at_account_portion();
  test_overflow_scenario_still_rate_limits();
  test_activation_and_cooldown_are_symmetric();
  test_integer_division_truncation();
  test_high_ulp_case();
  test_ulp_helpers();
  test_float_int_parity( rng );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
