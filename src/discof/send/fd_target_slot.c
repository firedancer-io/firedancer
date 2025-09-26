#include "fd_target_slot.h"
#include "../../flamenco/leaders/fd_leaders.h" /* FD_EPOCH_SLOTS_PER_ROTATION */

/* Up to FD_TARGET_SLOT_FANOUT_MAX predicted slots can be populated by simple fanout from
   any given prediction */

#define FD_TARGET_SLOT_FANOUT_MAX (3UL)

/* Consider caught up if we've voted within 4 slots of turbine tip */

#define FD_TARGET_SLOT_CAUGHT_UP_THRESHOLD (4L)

fd_target_slot_t *
fd_target_slot_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "NULL mem" ));
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_target_slot_align() ) ) ) {
    FD_LOG_ERR(( "misaligned mem" ));
  }

  fd_memset( mem, 0, fd_target_slot_footprint() );

  return fd_type_pun( mem );
}

void
fd_target_slot_push( fd_target_slot_t * target,
                     uint               slot_type,
                     ulong              slot ) {
  target->private.last_slot[slot_type] = slot;
  if( slot_type == FD_TARGET_SLOT_TYPE_TURBINE ) {
    target->private.max_turbine_slot = fd_ulong_max( target->private.max_turbine_slot, slot );
  }
  ulong const last_vote   = target->private.last_slot[FD_TARGET_SLOT_TYPE_VOTE];
  ulong const max_turbine = target->private.max_turbine_slot;

  /* consider caught up if turbine is at most 4 slots ahead */
  if( FD_UNLIKELY( !target->private.caught_up ) ) {
    if( FD_UNLIKELY( (long)max_turbine - (long)last_vote < FD_TARGET_SLOT_CAUGHT_UP_THRESHOLD ) ) {
      target->private.caught_up = !!max_turbine; /* don't set if turbine_slot==0 */
    }
  }
}


ulong
fd_target_slot_predict( fd_target_slot_t * target ) {
  ulong * predictions = target->slots;
  ulong const vote_prediction = target->private.last_slot[FD_TARGET_SLOT_TYPE_VOTE] + 1;
  ulong const turbine_prediction = target->private.last_slot[FD_TARGET_SLOT_TYPE_TURBINE] + 1;
  /* TODO: incorporate POH, generally be smarter */
  /* TODO: deduplicate */

  uint idx = 0U;

  /* if we've caught up, fanout from vote prediction and add turbine just in case.
     If we're behind, do the opposite. */
  ulong const base_slots[] = { turbine_prediction, vote_prediction };
  int   const caught_up    = target->private.caught_up;

  for( uint i=0U; i<FD_TARGET_SLOT_FANOUT_MAX; ++i ) {
    predictions[idx++] = base_slots[caught_up]+i*FD_EPOCH_SLOTS_PER_ROTATION;
  }
  predictions[idx++] = base_slots[!caught_up];

  return idx;
}
