#ifndef HEADER_fd_src_choreo_votor_fd_finality_tracker_h
#define HEADER_fd_src_choreo_votor_fd_finality_tracker_h

#include "fd_votor_base.h"

/* Finalization status of a slot, as returned by
   fd_finality_tracker_status. */

#define FD_FINALIZATION_STATUS_NOTARIZED            (0)
#define FD_FINALIZATION_STATUS_FINAL_PENDING_NOTAR  (1)
#define FD_FINALIZATION_STATUS_FINALIZED            (2)
#define FD_FINALIZATION_STATUS_IMPLICITLY_FINALIZED (3)
#define FD_FINALIZATION_STATUS_IMPLICITLY_SKIPPED   (4)

struct fd_finalization_event {
  fd_block_id_t   finalized;
  fd_block_id_t * implicitly_finalized; ulong implicitly_finalized_cnt;
  ulong *         implicitly_skipped;   ulong implicitly_skipped_cnt;
};
typedef struct fd_finalization_event fd_finalization_event_t;

typedef struct fd_finality_tracker fd_finality_tracker_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline fd_finalization_event_t
fd_finalization_event_default( fd_block_id_t * implicitly_finalized,
                               ulong *         implicitly_skipped ) {
  fd_finalization_event_t event;
  event.finalized.slot       = ULONG_MAX;
  event.implicitly_finalized = implicitly_finalized; event.implicitly_finalized_cnt = 0UL;
  event.implicitly_skipped   = implicitly_skipped;   event.implicitly_skipped_cnt   = 0UL;
  return event;
}

FD_FN_CONST ulong
fd_finality_tracker_align( void );

FD_FN_CONST ulong
fd_finality_tracker_footprint( ulong slot_max );

void *
fd_finality_tracker_new( void * shmem,
                         ulong  slot_max,
                         ulong  seed );

fd_finality_tracker_t *
fd_finality_tracker_join( void * shtracker );

void *
fd_finality_tracker_leave( fd_finality_tracker_t const * self );

void *
fd_finality_tracker_delete( void * shtracker );

void
fd_finality_tracker_init( fd_finality_tracker_t * self,
                          ulong                   slot );

void
fd_finality_tracker_fini( fd_finality_tracker_t * self );

/* Definition 14. FinalityTracker::add_parent */

void
fd_finality_tracker_add_parent( fd_finality_tracker_t *   self,
                                fd_block_id_t const *     block,
                                fd_block_id_t const *     parent,
                                fd_finalization_event_t * event );

/* Definition 14. FinalityTracker::mark_fast_finalized */

void
fd_finality_tracker_mark_fast_finalized( fd_finality_tracker_t *   self,
                                         fd_block_id_t const *     block,
                                         fd_finalization_event_t * event );

/* Definition 14. FinalityTracker::mark_notarized */

void
fd_finality_tracker_mark_notarized( fd_finality_tracker_t *   self,
                                    fd_block_id_t const *     block,
                                    fd_finalization_event_t * event );

/* Definition 14. FinalityTracker::mark_finalized */

void
fd_finality_tracker_mark_finalized( fd_finality_tracker_t *   self,
                                    ulong                     slot,
                                    fd_finalization_event_t * event );

/* Definition 14. FinalityTracker::highest_finalized_slot */

FD_FN_PURE ulong
fd_finality_tracker_highest_finalized_slot( fd_finality_tracker_t const * self );

FD_FN_PURE fd_block_hash_t const *
fd_finality_tracker_highest_finalized_block_hash( fd_finality_tracker_t const * self );

/* Section 2.9. FinalityTracker::first_unpruned_slot */

FD_FN_PURE ulong
fd_finality_tracker_first_unpruned_slot( fd_finality_tracker_t const * self );

int
fd_finality_tracker_status( fd_finality_tracker_t const * self,
                            ulong                         slot,
                            fd_block_hash_t *             out_hash );

FD_FN_PURE int
fd_finality_tracker_has_parent( fd_finality_tracker_t const * self,
                                fd_block_id_t const *         block );

FD_PROTOTYPES_END

#endif
