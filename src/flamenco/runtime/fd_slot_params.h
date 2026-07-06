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

/* In order to hit the target slot time, when producing blocks we
   subtract a fixed overhead amount to compensate for time spent
   outside of block production itself, such as network propagation.

   50ms is used to match Agave's behaviour:
   https://github.com/anza-xyz/agave/blob/v4.2/poh/src/poh_service.rs#L47 */
#define FD_TARGET_SLOT_ADJUSTMENT_NS (50000000UL)

/* Runtime parameters that need to change when the slot time changes
   due to one of the reduce_slot_time feature gates.

   https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L20-L30 */

struct fd_slot_params {
  ulong  ns_per_slot;
  ulong  ns_per_slot_adjusted;
  double slots_per_year;
  ulong  hashes_per_tick;
  ulong  max_block_units;
  ulong  max_writable_account_units;
  ulong  max_block_accounts_data_size_delta;
  ulong  max_shred_idx;
  ulong  max_entry_bytes_per_slot;
  ulong  stake_account_stores_per_block;
};
typedef struct fd_slot_params fd_slot_params_t;

/* https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L123-L133 */
#define FD_SLOT_PARAMS_400MS ((fd_slot_params_t){                                 \
  .ns_per_slot                        = 400000000UL,                              \
  .ns_per_slot_adjusted               = 400000000UL-FD_TARGET_SLOT_ADJUSTMENT_NS, \
  .slots_per_year                     = 78892314.984,                             \
  .hashes_per_tick                    = FD_LEGACY_HASHES_PER_TICK,                \
  .max_block_units                    = 60000000UL,                               \
  .max_writable_account_units         = 24000000UL,                               \
  .max_block_accounts_data_size_delta = 100000000UL,                              \
  .max_shred_idx                      = 32768UL,                                  \
  .max_entry_bytes_per_slot           = FD_DEFAULT_MAX_ENTRY_BYTES_PER_SLOT,      \
  .stake_account_stores_per_block     = 4096UL,                                   \
})

/* https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L135-L145 */
#define FD_SLOT_PARAMS_350MS ((fd_slot_params_t){                                 \
  .ns_per_slot                        = 350000000UL,                              \
  .ns_per_slot_adjusted               = 350000000UL-FD_TARGET_SLOT_ADJUSTMENT_NS, \
  .slots_per_year                     = 90162645.696,                             \
  .hashes_per_tick                    = 54687UL,                                  \
  .max_block_units                    = 52500000UL,                               \
  .max_writable_account_units         = 21000000UL,                               \
  .max_block_accounts_data_size_delta = 87500000UL,                               \
  .max_shred_idx                      = 28672UL,                                  \
  .max_entry_bytes_per_slot           = 18350080UL,                               \
  .stake_account_stores_per_block     = 3584UL,                                   \
})

/* https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L147-L157 */
#define FD_SLOT_PARAMS_300MS ((fd_slot_params_t){                                 \
  .ns_per_slot                        = 300000000UL,                              \
  .ns_per_slot_adjusted               = 300000000UL-FD_TARGET_SLOT_ADJUSTMENT_NS, \
  .slots_per_year                     = 105189753.312,                            \
  .hashes_per_tick                    = 46875UL,                                  \
  .max_block_units                    = 45000000UL,                               \
  .max_writable_account_units         = 18000000UL,                               \
  .max_block_accounts_data_size_delta = 75000000UL,                               \
  .max_shred_idx                      = 24576UL,                                  \
  .max_entry_bytes_per_slot           = 15728640UL,                               \
  .stake_account_stores_per_block     = 3072UL,                                   \
})

/* https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L159-L169 */
#define FD_SLOT_PARAMS_250MS ((fd_slot_params_t){                                 \
  .ns_per_slot                        = 250000000UL,                              \
  .ns_per_slot_adjusted               = 250000000UL-FD_TARGET_SLOT_ADJUSTMENT_NS, \
  .slots_per_year                     = 126227703.974,                            \
  .hashes_per_tick                    = 39062UL,                                  \
  .max_block_units                    = 37500000UL,                               \
  .max_writable_account_units         = 15000000UL,                               \
  .max_block_accounts_data_size_delta = 62500000UL,                               \
  .max_shred_idx                      = 20480UL,                                  \
  .max_entry_bytes_per_slot           = 13107200UL,                               \
  .stake_account_stores_per_block     = 2560UL,                                   \
})

/* https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L171-L181 */
#define FD_SLOT_PARAMS_200MS ((fd_slot_params_t){                                 \
  .ns_per_slot                        = 200000000UL,                              \
  .ns_per_slot_adjusted               = 200000000UL-FD_TARGET_SLOT_ADJUSTMENT_NS, \
  .slots_per_year                     = 157784629.968,                            \
  .hashes_per_tick                    = 31250UL,                                  \
  .max_block_units                    = 30000000UL,                               \
  .max_writable_account_units         = 12000000UL,                               \
  .max_block_accounts_data_size_delta = 50000000UL,                               \
  .max_shred_idx                      = 16384UL,                                  \
  .max_entry_bytes_per_slot           = 10485760UL,                               \
  .stake_account_stores_per_block     = 2048UL,                                   \
})

FD_PROTOTYPES_BEGIN

/* fd_slot_params_at_slot returns the effective slot params at the given
   slot, using the bank's default params, features, and epoch schedule.

   This takes into account the fact that the reduce_slot_time feature
   gates take effect an epoch after they have been activated.

   https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/slot_params.rs#L241-L286 */

fd_slot_params_t
fd_slot_params_at_slot( fd_bank_t const * bank,
                        ulong             slot );

/* fd_slot_params_lookup returns the effective slot params at the given
   slot, using the given default params, features, and epoch schedule.

   This takes into account the fact that the reduce_slot_time feature
   gates take effect an epoch after they have been activated. */

fd_slot_params_t
fd_slot_params_lookup( fd_slot_params_t const *    default_params,
                       fd_features_t const *       features,
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
fd_slot_params_slot_range_duration_ns( fd_bank_t const * bank,
                                       ulong             start_slot,
                                       ulong             end_slot );

/* fd_slot_params_slot_range_duration_years returns the duration in
   years for the slot range [start_slot, end_slot), taking into
   account any reduce_slot_time feature gate activations between the
   two slots.

   This is equivalent to Agave's slot_range_duration_in_years:
   https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/bank.rs#L2850-L2874 */

FD_FN_PURE double
fd_slot_params_slot_range_duration_years( fd_bank_t const * bank,
                                          ulong             start_slot,
                                          ulong             end_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_slot_params_h */
