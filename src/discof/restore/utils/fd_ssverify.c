#include "fd_ssverify.h"

#include "../../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"

int
fd_ssverify_epoch_stakes( fd_snapshot_manifest_t * manifest ) {
  fd_epoch_schedule_t epoch_schedule[1];
  if( FD_UNLIKELY( !fd_epoch_schedule_derive( epoch_schedule,
                                               manifest->epoch_schedule_params.slots_per_epoch,
                                               manifest->epoch_schedule_params.leader_schedule_slot_offset,
                                               manifest->epoch_schedule_params.warmup ) ) ) {
    return FD_SSVERIFY_INVALID_EPOCH_SCHEDULE;
  }

  ulong epoch                 = fd_slot_to_epoch( epoch_schedule, manifest->slot, NULL );
  ulong leader_schedule_epoch = fd_slot_to_leader_schedule_epoch( epoch_schedule, manifest->slot );

  if( FD_UNLIKELY( manifest->epoch_stakes[ 0UL ].epoch!=epoch ) ) {
    return FD_SSVERIFY_EPOCH_STAKES_NOT_FOUND;
  }

  if( FD_UNLIKELY( manifest->epoch_stakes[ 1UL ].epoch==leader_schedule_epoch ) ) {
    return FD_SSVERIFY_EPOCH_STAKES_NOT_FOUND;
  }

  return 0;
}