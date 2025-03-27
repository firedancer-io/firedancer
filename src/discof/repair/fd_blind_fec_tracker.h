#ifndef HEADER_fd_src_discof_repair_fd_blind_fec_tracker_h
#define HEADER_fd_src_discof_repair_fd_blind_fec_tracker_h

/* This provides APIs for releasing FEC sets that are recieved
   exclusively through repair, and not turbine. In the usual path,
   fd_fec_resolver recieves data and coding shreds through turbine, and
   uses the data_cnt field on a coding shred to determine when a FEC set
   completes. However, the repair protocol only returns data shreds -
   coding shreds are not sent through repair. Thus fec_resolver has no
   way of knowing if a FEC set completes if the FEC set was received
   exclusively through repair. This happens mostly from snapshot loading
   and catching up, although it is possible that we may not recieve
   turbine shreds for a period of time due to being down/network
   disruption and we may need to repair them. */

#include "../../ballet/shred/fd_shred.h"

/* fd_lost_fecs is tracked by two data structures.

   1. slot_wmark_set_t

            slot->bit_vec

   This is a bit vector that tracks different wmarks of different FEC
   sets in the slot. We maintain one of these for every pending slot.

   2. fec_wmark_map_t

            slot|fec_set_idx -> [shred_bit_vec, wmark]

   This is a map that tracks the wmark of different FEC sets. The key is
   the slot | fec_set_idx. It also maintains a bit vector of recieved
   shreds in the FEC set.

   The key is that the fec_set_idx is easily available, but we don't
   know where the FEC set F ends until we've a) received a shred G with
   fec_set_idx value higher than the current F.fec_set_idx, and b)
   we've recieved contiguous shreds in F until G.fec_set_idx - 1.

   Thus, when we recieve a shred F with F.fec_set_idx, we do the following:
   Create a wmark map entry for F.slot | F.fec_set_idx if the map entry is not
   present. If it is, insert the F.shred_idx into the shred bit vector, and
   advance the wmark if possible. If the wmark is advanced, retrieve
   slot_wmark_set_t[slot] and erase the old wmark bit and write 1 to the
   new wmark.

   There's also a possibility that with this shred, we have completed the FEC set.
   Query the fec_wmark_map_t to see if F.slot | F.wmark + 1 is present. If it is,
   we know that the FEC set is complete.

   If F.fec_set_idx is a new entry, we need to check if this new fec_set_idx
   can signal the end (of suffering) of a previous FEC set. We also check the
   slot_wmark_set_t[slot] to see if there is a wmark for F.fec_set_idx - 1.

   If so, we know the FEC set previous to F.fec_set_idx is complete. We can
   then call fd_fec_resolver_force_complete( shred F.fec_set_idx - 1 )

   Unfortunately we cannot remove the completed FEC sets until the end of the
   slot, because the previous FEC relies on the completed FEC set to know
   the fec_set_idxes existences. So instead we remove the completed FEC sets at the
   end of the slot, and do this by iterating the slot_wmark_set for the
   fec_set_idxs.
*/

typedef struct fd_blind_fec_tracker fd_blind_fec_tracker_t;

#define SET_NAME fd_wmark_set
#define SET_MAX  FD_SHRED_MAX_PER_SLOT
#include "../../util/tmpl/fd_set.c"

struct fd_slot_wmark {
    ulong slot;
    fd_wmark_set_t wmark_set[FD_SHRED_MAX_PER_SLOT/64];
};
typedef struct fd_slot_wmark fd_slot_wmark_t;

#define MAP_NAME    fd_slot_wmark_map
#define MAP_T       fd_slot_wmark_t
#define MAP_KEY     slot
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

#define SET_NAME fd_shred_set
#define SET_MAX  128
#include "../../util/tmpl/fd_set.c"

struct fd_fec_wmark_t {
    ulong          key;     /* 32 bits slot | 32 bits fec_set_idx */
    fd_shred_set_t shred_set[128/64];
    uint           wmark;
    uint           completes_idx; /* UINT_MAX unless this fec contains a shred with a batch_complete or slot_complete flag. */
};
typedef struct fd_fec_wmark_t fd_fec_wmark_t;

#define MAP_NAME    fd_fec_wmark_map
#define MAP_T       fd_fec_wmark_t
#define MAP_KEY     key
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

struct fd_blind_fec_tracker {
  fd_slot_wmark_t * slot_wmark_map; /* slot | fec_set_idx -> fd_slot_wmark_t */
  fd_fec_wmark_t  * fec_wmark_map;  /* slot | fec_set_idx -> fd_fec_wmark_t */
};

FD_PROTOTYPES_BEGIN

/* Constructors */

/* fd_blind_fec_tracker_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as tracker with up to
   fec_max elements and slot_max slots. */

FD_FN_CONST static inline ulong
fd_blind_fec_tracker_align( void ) { return alignof(fd_blind_fec_tracker_t); }

FD_FN_CONST static inline ulong
fd_blind_fec_tracker_footprint( ulong slot_max, ulong fec_max ) {
  int lg_slot_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max  ) );
  int lg_fec_cnt  = fd_ulong_find_msb( fd_ulong_pow2_up( fec_max ) );
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_blind_fec_tracker_t), sizeof(fd_blind_fec_tracker_t) ),
      fd_slot_wmark_map_align(),       fd_slot_wmark_map_footprint( lg_slot_cnt ) ),
      fd_fec_wmark_map_align(),        fd_fec_wmark_map_footprint( lg_fec_cnt ) ),
    fd_blind_fec_tracker_align() );
}

/* fd_blind_fec_tracker_new formats an unused memory region for use as a
   tracker.  mem is a non-NULL pointer to this region in the local
   address space with the required footprint and alignment. */

void *
fd_blind_fec_tracker_new( void * shmem, ulong slot_max, ulong fec_max );

/* fd_blind_fec_tracker joins the caller to the chainer.  tracker points
   to the first byte of the memory region backing the tracker in the
   caller's address space.
   Returns a pointer in the local address space to tracker on
   success. */

fd_blind_fec_tracker_t *
fd_blind_fec_tracker_join( void * shmem );

/* fd_blind_fec_trackerr_leave leaves a current local join.  Returns a pointer
   to the underlying shared memory region on success and NULL on failure
   (logs details).  Reasons for failure include tracker is NULL. */

void *
fd_blind_fec_tracker_leave( fd_blind_fec_tracker_t * chainer );

/* fd_blind_fec_tracker_delete unformats a memory region used as a tracker.
    Assumes only the nobody is joined to the region.  Returns a pointer
    to the underlying shared memory region or NULL if used obviously in
    error (e.g. tracker is obviously not a tracker... logs details).
    The ownership of the memory region is transferred to the caller. */

void *
fd_fec_chainer_delete( void * chainer );

fd_blind_fec_tracker_t *
fd_blind_fec_tracker_init( fd_blind_fec_tracker_t * tracker, ulong slot );

ulong
fd_blind_fec_tracker_add( fd_blind_fec_tracker_t * tracker,
                          ulong slot,
                          uint  fec_set_idx,
                          uint  shred_idx,
                          int   completes );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_repair_fd_blind_fec_tracker_h */