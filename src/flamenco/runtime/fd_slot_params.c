#include "fd_slot_params.h"
#include "fd_bank.h"
#include "../features/fd_features.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "../../util/bits/fd_sat.h"
#include <stddef.h>

/* The reduce_slot_time feature gates take effect an epoch after they
   have been activated, because they affect the turbine shred filtering
   rules. */
static ulong
feature_effective_slot( fd_epoch_schedule_t const * epoch_schedule,
                        ulong                       activation_slot ) {
  ulong activation_epoch = fd_slot_to_epoch( epoch_schedule, activation_slot, NULL );
  return fd_epoch_slot0( epoch_schedule, fd_ulong_sat_add( activation_epoch, 1UL ) );
}

#define FD_SLOT_TIME_GATE_CNT (4UL)
struct fd_slot_time_gate {
  ulong                    feature_off;
  fd_slot_params_t const * params;
};

typedef struct fd_slot_time_gate fd_slot_time_gate_t;

static fd_slot_time_gate_t const fd_slot_time_gates[ FD_SLOT_TIME_GATE_CNT ] = {
  { .feature_off = offsetof( fd_features_t, reduce_slot_time_to_350ms ), .params = &FD_SLOT_PARAMS_350MS },
  { .feature_off = offsetof( fd_features_t, reduce_slot_time_to_300ms ), .params = &FD_SLOT_PARAMS_300MS },
  { .feature_off = offsetof( fd_features_t, reduce_slot_time_to_250ms ), .params = &FD_SLOT_PARAMS_250MS },
  { .feature_off = offsetof( fd_features_t, reduce_slot_time_to_200ms ), .params = &FD_SLOT_PARAMS_200MS },
};

static ulong
fd_slot_params_feature_effective_slot( fd_features_t const *       features,
                                       fd_epoch_schedule_t const * epoch_schedule,
                                       fd_slot_time_gate_t const * gate ) {
  ulong activation_slot = fd_features_get_activation_slot_from_offset( features, gate->feature_off );
  if( activation_slot==FD_FEATURE_DISABLED ) return ULONG_MAX;
  return feature_effective_slot( epoch_schedule, activation_slot );
}

fd_slot_params_t
fd_slot_params_at_slot( fd_bank_t const * bank,
                        ulong             slot ) {
  return fd_slot_params_lookup( &bank->f.slot_params_default,
                                &bank->f.features,
                                &bank->f.epoch_schedule,
                                slot );
}

fd_slot_params_t
fd_slot_params_lookup( fd_slot_params_t const *    default_params,
                       fd_features_t const *       features,
                       fd_epoch_schedule_t const * epoch_schedule,
                       ulong                       slot ) {
  fd_slot_params_t result = *default_params;
  for( ulong i=0UL; i<FD_SLOT_TIME_GATE_CNT; i++ ) {
    fd_slot_time_gate_t const * gate = &fd_slot_time_gates[ i ];
    ulong eff                        = fd_slot_params_feature_effective_slot( features, epoch_schedule, gate );
    if( gate->params->ns_per_slot <= result.ns_per_slot && eff!=ULONG_MAX && eff<=slot ) {
      result = *gate->params;
    }
  }
  return result;
}

ulong
fd_slot_params_effective_slot( fd_slot_params_t const *    params,
                               fd_features_t const *       features,
                               fd_epoch_schedule_t const * epoch_schedule ) {
  for( ulong i=0UL; i<FD_SLOT_TIME_GATE_CNT; i++ ) {
    fd_slot_time_gate_t const * gate = &fd_slot_time_gates[ i ];
    if( gate->params->ns_per_slot==params->ns_per_slot )
      return fd_slot_params_feature_effective_slot( features, epoch_schedule, gate );
  }
  return 0UL;
}

static ulong
fd_slot_params_next_transition( fd_features_t const *       features,
                                fd_epoch_schedule_t const * epoch_schedule,
                                ulong                       slot,
                                ulong                       current_ns_per_slot ) {
  ulong next = ULONG_MAX;
  for( ulong i=0UL; i<FD_SLOT_TIME_GATE_CNT; i++ ) {
    fd_slot_time_gate_t const * gate = &fd_slot_time_gates[ i ];
    if( gate->params->ns_per_slot > current_ns_per_slot ) continue;
    ulong eff = fd_slot_params_feature_effective_slot( features, epoch_schedule, gate );
    if( eff>slot && eff<next ) next = eff;
  }
  return next;
}

ulong
fd_slot_params_next_effective_slot( fd_slot_params_t const *    params,
                                    fd_features_t const *       features,
                                    fd_epoch_schedule_t const * epoch_schedule ) {
  ulong next = ULONG_MAX;
  for( ulong i=0UL; i<FD_SLOT_TIME_GATE_CNT; i++ ) {
    fd_slot_time_gate_t const * gate = &fd_slot_time_gates[ i ];
    if( gate->params->ns_per_slot >= params->ns_per_slot ) continue;
    ulong eff = fd_slot_params_feature_effective_slot( features, epoch_schedule, gate );
    if( eff<next ) next = eff;
  }
  return next;
}

FD_FN_PURE ulong
fd_slot_params_slot_range_duration_ns( fd_bank_t const * bank,
                                       ulong             start_slot,
                                       ulong             end_slot ) {
  fd_slot_params_t const *    default_params = &bank->f.slot_params_default;
  fd_features_t const *       features       = &bank->f.features;
  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong   curr_slot = start_slot;
  uint128 ns        = 0;
  while( curr_slot<end_slot ) {
    fd_slot_params_t params    = fd_slot_params_lookup( default_params, features, epoch_schedule, curr_slot );
    ulong            next      = fd_slot_params_next_transition( features, epoch_schedule, curr_slot, params.ns_per_slot );
    ulong            seg_end   = next<end_slot ? next : end_slot;
                     ns        = fd_uint128_sat_add( ns, fd_uint128_sat_mul( (uint128)( seg_end-curr_slot ), (uint128)params.ns_per_slot ) );
                     curr_slot = seg_end;
  }
  /* We saturate here because all the Agave callers do as well. In
     practice, the callers all limit the inputs such that this range
     will never overflow ULONG_MAX, but we saturate for defense in
     depth.
     https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/bank.rs#L2985-L2987 */
  return ns>(uint128)ULONG_MAX ? ULONG_MAX : (ulong)ns;
}

FD_FN_PURE double
fd_slot_params_slot_range_duration_years( fd_bank_t const * bank,
                                          ulong             start_slot,
                                          ulong             end_slot ) {
  fd_slot_params_t const *    default_params = &bank->f.slot_params_default;
  fd_features_t const *       features       = &bank->f.features;
  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong  curr_slot = start_slot;
  double years     = 0.0;
  while( curr_slot<end_slot ) {
    fd_slot_params_t p         = fd_slot_params_lookup( default_params, features, epoch_schedule, curr_slot );
    ulong            next      = fd_slot_params_next_transition( features, epoch_schedule, curr_slot, p.ns_per_slot );
    ulong            seg_end   = next<end_slot ? next : end_slot;
                     years    += (double)( seg_end-curr_slot ) / p.slots_per_year;
                     curr_slot = seg_end;
  }
  return years;
}
