#include "fd_integer_inflation.h"
#include "../features/fd_features.h"
#include "../runtime/fd_bank.h"
#include "../runtime/fd_slot_params.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L6-L8 */
#define FD_INTEGER_INFLATION_RATE_SCALE  (1000000000000000UL)
#define FD_INTEGER_INFLATION_YEAR_NS     (31556925993600000UL)
#define FD_INTEGER_INFLATION_DECAY_SCALE (((uint128)1UL)<<64)

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/runtime/src/bank.rs#L261-L262 */
#define FD_INTEGER_INFLATION_INITIAL_RATE  (80000000000000UL)
#define FD_INTEGER_INFLATION_TERMINAL_RATE (15000000000000UL)

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/runtime/src/bank.rs#L3111
   https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/runtime/src/bank.rs#L3138-L3143 */
#define FD_INTEGER_INFLATION_TAPER_DEN                     (100U)
#define FD_INTEGER_INFLATION_TAPER_NUM                     (15U)
#define FD_INTEGER_INFLATION_DOUBLE_DISINFLATION_TAPER_NUM (30U)

/* approximate_logarithm computes ln(numerator/denominator) scaled by
   FD_INTEGER_INFLATION_DECAY_SCALE, using the first 32 terms of the
   atanh series.

   approximate_logarithm calculates ln(numerator/denominator) using
   the first 32 terms of the atanh series.  The terms are scaled by
   FD_INTEGER_INFLATION_DECAY_SCALE.

   https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L50-L77 */
static int
approximate_logarithm( uint      numerator,
                       uint      denominator,
                       uint128 * out ) {
  if( FD_UNLIKELY( !denominator || numerator<denominator ) ) return -1;

  uint128 z_num    = (uint128)numerator - (uint128)denominator;
  uint128 z_den    = (uint128)numerator + (uint128)denominator;
  uint128 z_num_sq = z_num*z_num;
  uint128 z_den_sq = z_den*z_den;

  uint128 term = ( FD_INTEGER_INFLATION_DECAY_SCALE*z_num ) / z_den;
  uint128 sum  = 0;
  for( ulong i=0UL; i<32UL; i++ ) {
    sum += term / (uint128)( ( 2UL*i )+1UL );
    if( i<31UL ) term = ( term*z_num_sq ) / z_den_sq;
  }

  *out = sum*2;
  return 0;
}

/* approximate_exponential calculates an approximate value of e^-x
   using the first 4 terms of it's Taylor series.  x and the result
   are scaled by FD_INTEGER_INFLATION_DECAY_SCALE.

   https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L80-L87 */
static int
approximate_exponential( uint128   x,
                         uint128 * out ) {
  uint128 x_sq;
  if( FD_UNLIKELY( __builtin_mul_overflow( x, x, &x_sq ) ) ) return -1;
  uint128 second = x_sq / ( 2*FD_INTEGER_INFLATION_DECAY_SCALE );

  uint128 second_x;
  if( FD_UNLIKELY( __builtin_mul_overflow( second, x, &second_x ) ) ) return -1;
  uint128 third = second_x / ( 3*FD_INTEGER_INFLATION_DECAY_SCALE );

  if( FD_UNLIKELY( second>x ) ) return -1;
  uint128 decrement;
  if( FD_UNLIKELY( __builtin_add_overflow( x-second, third, &decrement ) ) ) return -1;
  if( FD_UNLIKELY( decrement>FD_INTEGER_INFLATION_DECAY_SCALE ) ) return -1;

  *out = FD_INTEGER_INFLATION_DECAY_SCALE - decrement;
  return 0;
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L93-L101 */
static int
decay_per_slot( ulong     ns_per_slot,
                uint      taper_num,
                uint      taper_den,
                uint128 * out ) {
  if( FD_UNLIKELY( !ns_per_slot || !taper_den || taper_num>=taper_den ) ) return -1;

  uint128 annual_exponent;
  if( FD_UNLIKELY( approximate_logarithm( taper_den, taper_den-taper_num, &annual_exponent ) ) ) return -1;

  uint128 product;
  if( FD_UNLIKELY( __builtin_mul_overflow( annual_exponent, (uint128)ns_per_slot, &product ) ) ) return -1;

  return approximate_exponential( product / (uint128)FD_INTEGER_INFLATION_YEAR_NS, out );
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L105-L116 */
static uint128
mul_decay_floor( uint128 a,
                 uint128 b ) {
  if( a==FD_INTEGER_INFLATION_DECAY_SCALE ) return b;
  if( b==FD_INTEGER_INFLATION_DECAY_SCALE ) return a;
  return ( a*b )>>64;
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L120-L135 */
static int
pow_decay_floor( uint128   base,
                 ulong     slots,
                 uint128 * out ) {
  if( FD_UNLIKELY( base>FD_INTEGER_INFLATION_DECAY_SCALE ) ) return -1;
  uint128 result = FD_INTEGER_INFLATION_DECAY_SCALE;
  while( slots ) {
    if( slots&1UL ) result = mul_decay_floor( result, base );
    slots >>= 1;
    if( slots ) base = mul_decay_floor( base, base );
  }
  *out = result;
  return 0;
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L138-L146 */
static int
apply_decay_floor( ulong   anchor_rate,
                   uint128 decay,
                   ulong * out ) {
  if( FD_UNLIKELY( anchor_rate>FD_INTEGER_INFLATION_RATE_SCALE || decay>FD_INTEGER_INFLATION_DECAY_SCALE ) ) return -1;
  *out = (ulong)( ( (uint128)anchor_rate*decay )>>64 );
  return 0;
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L12-L22 */
static int
decayed_rate( ulong   anchor_rate,
              uint    taper_num,
              uint    taper_den,
              ulong   ns_per_slot,
              ulong   slots,
              ulong * out ) {
  uint128 factor;
  if( FD_UNLIKELY( decay_per_slot( ns_per_slot, taper_num, taper_den, &factor ) ) ) return -1;
  uint128 decay;
  if( FD_UNLIKELY( pow_decay_floor( factor, slots, &decay ) ) ) return -1;
  return apply_decay_floor( anchor_rate, decay, out );
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L26-L43 */
static int
epoch_reward( ulong   capitalization,
              ulong   rate,
              ulong   slots_in_epoch,
              ulong   ns_per_slot,
              ulong * out ) {
  if( FD_UNLIKELY( rate>FD_INTEGER_INFLATION_RATE_SCALE || !ns_per_slot ) ) return -1;

  uint128 annual = ( (uint128)capitalization*(uint128)rate ) / (uint128)FD_INTEGER_INFLATION_RATE_SCALE;

  uint128 reward;
  if( FD_UNLIKELY( __builtin_mul_overflow( annual, (uint128)slots_in_epoch, &reward ) ||
                   __builtin_mul_overflow( reward, (uint128)ns_per_slot,    &reward ) ) ) return -1;
  reward /= (uint128)FD_INTEGER_INFLATION_YEAR_NS;
  if( FD_UNLIKELY( reward>(uint128)ULONG_MAX ) ) return -1;

  *out = (ulong)reward;
  return 0;
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/runtime/src/bank.rs#L3089-L3120 */
static ulong
integer_inflation_rate_between( fd_bank_t const * bank,
                                ulong             anchor_rate,
                                ulong             start_slot,
                                ulong             end_slot,
                                uint              taper_num ) {
  if( FD_UNLIKELY( start_slot>end_slot ) ) {
    FD_LOG_ERR(( "inflation rate calculation failed (start_slot=%lu end_slot=%lu)", start_slot, end_slot ));
  }

  fd_features_t const *       features       = &bank->f.features;
  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;

  ulong rate   = anchor_rate;
  ulong cursor = start_slot;
  while( cursor<end_slot ) {
    ulong ns_per_slot = fd_slot_params_at_slot( bank, cursor ).ns_per_slot;
    ulong seg_end     = fd_ulong_min( fd_slot_params_next_transition( features, epoch_schedule, cursor, ns_per_slot ), end_slot );
    if( FD_UNLIKELY( decayed_rate( rate, taper_num, FD_INTEGER_INFLATION_TAPER_DEN, ns_per_slot, seg_end-cursor, &rate ) ) ) {
      FD_LOG_ERR(( "inflation rate calculation failed (rate=%lu taper=%u/%u ns_per_slot=%lu slots=%lu)",
                   rate, taper_num, FD_INTEGER_INFLATION_TAPER_DEN, ns_per_slot, seg_end-cursor ));
    }
    cursor = seg_end;
  }
  return rate;
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/runtime/src/bank.rs#L3127-L3146 */
static ulong
integer_inflation_rate( fd_bank_t const * bank,
                        ulong             inflation_start_slot ) {
  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong end_slot = fd_epoch_slot0( epoch_schedule, fd_slot_to_epoch( epoch_schedule, bank->f.slot, NULL ) );

  ulong rate;
  if( FD_FEATURE_ACTIVE_BANK( bank, double_disinflation_rate ) ) {
    ulong anchor_slot = fd_ulong_min( bank->f.features.double_disinflation_rate, end_slot );
    ulong anchor_rate = integer_inflation_rate_between( bank, FD_INTEGER_INFLATION_INITIAL_RATE, inflation_start_slot, anchor_slot, FD_INTEGER_INFLATION_TAPER_NUM );
    anchor_rate       = fd_ulong_max( anchor_rate, FD_INTEGER_INFLATION_TERMINAL_RATE );
    rate              = integer_inflation_rate_between( bank, anchor_rate, anchor_slot, end_slot, FD_INTEGER_INFLATION_DOUBLE_DISINFLATION_TAPER_NUM );
  } else {
    rate              = integer_inflation_rate_between( bank, FD_INTEGER_INFLATION_INITIAL_RATE, inflation_start_slot, end_slot, FD_INTEGER_INFLATION_TAPER_NUM );
  }
  return fd_ulong_max( rate, FD_INTEGER_INFLATION_TERMINAL_RATE );
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/runtime/src/bank.rs#L3155-L3172 */
ulong
fd_integer_inflation_epoch_rewards( fd_bank_t const * bank,
                                    ulong             inflation_start_slot,
                                    ulong             capitalization,
                                    ulong             epoch ) {
  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;

  ulong rate        = integer_inflation_rate( bank, inflation_start_slot );
  ulong ns_per_slot = fd_slot_params_at_slot( bank, fd_epoch_slot0( epoch_schedule, epoch ) ).ns_per_slot;
  ulong reward;
  if( FD_UNLIKELY( epoch_reward( capitalization, rate, fd_epoch_slot_cnt( epoch_schedule, epoch ), ns_per_slot, &reward ) ) ) {
    FD_LOG_ERR(( "epoch reward calculation failed (capitalization=%lu rate=%lu epoch=%lu)", capitalization, rate, epoch ));
  }
  ulong new_capitalization;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( capitalization, reward, &new_capitalization ) ) ) {
    FD_LOG_ERR(( "capitalization overflow (capitalization=%lu reward=%lu)", capitalization, reward ));
  }
  return reward;
}
