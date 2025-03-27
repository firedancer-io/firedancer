#include "fd_blind_fec_tracker.h"

void *
fd_blind_fec_tracker_new( void * shmem, ulong slot_max, ulong fec_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_blind_fec_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_blind_fec_tracker_footprint( slot_max, fec_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad fec_max (%lu)", fec_max ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );



  return shmem;
}

// evict as soon as see a parity shred

ulong
fd_blind_fec_tracker_add( fd_blind_fec_tracker_t * tracker,
                          ulong slot,
                          uint  fec_set_idx,
                          uint  shred_idx,
                          int   completes /* batch or slot */ ) {
  ulong fec_key = ( slot << 32 ) | fec_set_idx;
  fd_fec_wmark_t * fec_wmark = fd_fec_wmark_map_query( tracker->fec_wmark_map, fec_key, NULL );

  if( FD_UNLIKELY( !fec_wmark ) ) {
    fec_wmark = fd_fec_wmark_map_insert( tracker->fec_wmark_map, fec_key );
    fec_wmark->wmark = UINT_MAX;
    fec_wmark->completes_idx = UINT_MAX;
    fd_shred_set_null( fec_wmark->shred_set );
  }

  fd_slot_wmark_t * slot_wmark = fd_slot_wmark_map_query( tracker->slot_wmark_map, slot, NULL );
  if( FD_UNLIKELY( !slot_wmark ) ) {
    slot_wmark = fd_slot_wmark_map_insert( tracker->slot_wmark_map, slot );
    fd_wmark_set_null( slot_wmark->wmark_set );
  }

  fd_wmark_set_remove_if( slot_wmark->wmark_set, fec_wmark->wmark != UINT_MAX, fec_wmark->wmark + fec_set_idx );
  if( FD_UNLIKELY( completes ) ) {
    fec_wmark->completes_idx = shred_idx - fec_set_idx;
  }
  fd_shred_set_insert( fec_wmark->shred_set, shred_idx - fec_set_idx );

  /* increment wmark if possible */
  for( uint i=fec_wmark->wmark + 1; i<fd_shred_set_max( fec_wmark->shred_set ); i++ ) {
    if( !fd_shred_set_test( fec_wmark->shred_set, i ) ) {
      break;
    }
    fec_wmark->wmark++;
  }

  fd_wmark_set_insert_if( slot_wmark->wmark_set, fec_wmark->wmark != UINT_MAX, fec_wmark->wmark + fec_set_idx );

  /* Case 1. This FEC set idx arrives after the previous FEC set completes.
     Then we can free the previous FEC set. */
  if( fd_wmark_set_test( slot_wmark->wmark_set, fec_set_idx - 1 ) ) {
    return fec_set_idx - 1;
  }

  /* Case 2. This FEC set is the last in batch or slot, and thus knows which
     shred_idx is the last because it came with a completes flag. And the wmark matches this shred idx */
  if( fec_wmark->completes_idx != UINT_MAX && fec_wmark->wmark == fec_wmark->completes_idx ) {
    return fec_wmark->completes_idx + fec_set_idx;
  }

  /* Case 3. This FEC set completes because the following FEC set idx
     has been learned. */
  if( fec_wmark->wmark != UINT_MAX && fd_fec_wmark_map_query( tracker->fec_wmark_map, (slot << 32) | ( fec_wmark->wmark + 1 ), NULL ) ) {
    return fec_wmark->wmark + fec_set_idx;
  }

  return ULONG_MAX;
}
