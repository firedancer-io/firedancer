#ifndef HEADER_fd_src_flamenco_runtime_fd_slot_params_h
#define HEADER_fd_src_flamenco_runtime_fd_slot_params_h

#include "../fd_flamenco_base.h"

/* fd_slot_params groups the runtime parameters that move together when
   the slot time changes due to the reduce_slot_time feature gates as
   described in SIMD-525.

   Slot time reductions happen in 50ms increments, each with a separate
   feature gate:
     reduce_slot_time_to_350ms
     reduce_slot_time_to_300ms
     reduce_slot_time_to_250ms
     reduce_slot_time_to_200ms

   Note that these feature gates take effect an epoch after they
   have been activated, because they affect the turbine shred filtering
   rules. */

/* https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L13 */
#define FD_DEFAULT_MAX_ENTRY_BYTES_PER_SLOT (20UL*1024UL*1024UL) /* 20 MiB */

/* https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L122 */
#define FD_LEGACY_HASHES_PER_TICK (62500UL)

/* Runtime parameters that need to change when the slot time changes
   due to one of the reduce_slot_time feature gates.

   https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L20-L30 */

struct fd_slot_params {
  ulong  ns_per_slot;
  double slots_per_year;
  ulong  hashes_per_tick;
  ulong  max_block_units;
  ulong  max_writable_account_units;
  ulong  max_block_accounts_data_size_delta;
  uint   max_shred_idx;
  ulong  max_entry_bytes_per_slot;
  ulong  partitioned_epoch_rewards_stake_account_stores_per_block;
};
typedef struct fd_slot_params fd_slot_params_t;

extern fd_slot_params_t const FD_SLOT_PARAMS_400MS;
extern fd_slot_params_t const FD_SLOT_PARAMS_350MS;
extern fd_slot_params_t const FD_SLOT_PARAMS_300MS;
extern fd_slot_params_t const FD_SLOT_PARAMS_250MS;
extern fd_slot_params_t const FD_SLOT_PARAMS_200MS;

FD_PROTOTYPES_BEGIN

/* fd_slot_params_at_slot returns the effective slot params at the
   given slot.

   This takes into account the fact that the reduce_slot_time feature
   gates take effect an epoch after they have been activated.

   https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L241-L286 */

fd_slot_params_t
fd_slot_params_at_slot( fd_features_t const *       features,
                        fd_epoch_schedule_t const * epoch_schedule,
                        ulong                       slot );

/* fd_slot_params_effective_slot returns the slot at which the given
   slot params regime takes effect. */

ulong
fd_slot_params_effective_slot( fd_slot_params_t const *    params,
                               fd_features_t const *       features,
                               fd_epoch_schedule_t const * epoch_schedule );

/* fd_slot_params_next_effective_slot returns the slot at which the next
   slot params regime after the given one takes effect. */

ulong
fd_slot_params_next_effective_slot( fd_slot_params_t const *    params,
                                    fd_features_t const *       features,
                                    fd_epoch_schedule_t const * epoch_schedule );

/* fd_slot_params_slot_range_duration_ns returns the duration in
   nanoseconds for the slot range [start_slot, end_slot),
   taking into account any reduce_slot_time feature gate activations
   between the two slots.

   This is equivalent to Agave's slot_range_duration_nanos
   https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L295-L320 */

FD_FN_PURE ulong
fd_slot_params_slot_range_duration_ns( fd_features_t const *       features,
                                       fd_epoch_schedule_t const * epoch_schedule,
                                       ulong                       start_slot,
                                       ulong                       end_slot );

/* fd_slot_params_slot_range_duration_years returns the duration in
   years for the slot range [start_slot, end_slot), taking into
   account any reduce_slot_time feature gate activations between the
   two slots.

   This is equivalent to Agave's slot_range_duration_in_years:
   https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/bank.rs#L2850-L2874 */

FD_FN_PURE double
fd_slot_params_slot_range_duration_years( fd_features_t const *       features,
                                          fd_epoch_schedule_t const * epoch_schedule,
                                          ulong                       start_slot,
                                          ulong                       end_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_slot_params_h */
