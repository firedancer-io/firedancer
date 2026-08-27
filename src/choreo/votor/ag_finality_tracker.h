#ifndef HEADER_fd_src_choreo_votor_ag_finality_tracker_h
#define HEADER_fd_src_choreo_votor_ag_finality_tracker_h

#include "ag_votor_base.h"

/* Finalization status of a slot, as returned by
   ag_finality_tracker_status. */

#define AG_FINALIZATION_STATUS_NOTARIZED            (0)
#define AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR  (1)
#define AG_FINALIZATION_STATUS_FINALIZED            (2)
#define AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED (3)
#define AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED   (4)

struct ag_finalization_event {
  ag_block_id_t   finalized;
  ag_block_id_t * implicitly_finalized; ulong implicitly_finalized_cnt;
  ulong *         implicitly_skipped;   ulong implicitly_skipped_cnt;
};
typedef struct ag_finalization_event ag_finalization_event_t;

typedef struct ag_finality_tracker ag_finality_tracker_t;

FD_PROTOTYPES_BEGIN

/* ag_finalization_event_default returns an empty event backed by the
   caller's storage.  implicitly_finalized and implicitly_skipped must
   each hold at least (source_slot-first_unpruned_slot) entries, as a
   single call can walk the whole unpruned ancestry. */

FD_FN_CONST static inline ag_finalization_event_t
ag_finalization_event_default( ag_block_id_t * implicitly_finalized,
                               ulong *         implicitly_skipped ) {
  ag_finalization_event_t event;
  event.finalized.slot       = ULONG_MAX;
  event.implicitly_finalized = implicitly_finalized; event.implicitly_finalized_cnt = 0UL;
  event.implicitly_skipped   = implicitly_skipped;   event.implicitly_skipped_cnt   = 0UL;
  return event;
}

FD_FN_CONST ulong
ag_finality_tracker_align( void );

FD_FN_CONST ulong
ag_finality_tracker_footprint( ulong slot_max );

void *
ag_finality_tracker_new( void * shmem,
                         ulong  slot_max,
                         ulong  seed );

ag_finality_tracker_t *
ag_finality_tracker_join( void * shtracker );

void *
ag_finality_tracker_leave( ag_finality_tracker_t const * tracker );

void *
ag_finality_tracker_delete( void * shtracker );

/* init before any block, cert or vote is added; genesis is slot 0 */

void
ag_finality_tracker_init( ag_finality_tracker_t * self,
                          ulong                   slot );

void
ag_finality_tracker_fini( ag_finality_tracker_t * self );

/* The mark_* and add_parent entry points append newly finalized and
   newly skipped slots to event, which the caller supplies already
   initialized by ag_finalization_event_default. */

void
ag_finality_tracker_add_parent( ag_finality_tracker_t *   self,
                                ag_block_id_t const *     block,
                                ag_block_id_t const *     parent,
                                ag_finalization_event_t * event );

void
ag_finality_tracker_mark_fast_finalized( ag_finality_tracker_t *   self,
                                         ag_block_id_t const *     block,
                                         ag_finalization_event_t * event );

void
ag_finality_tracker_mark_notarized( ag_finality_tracker_t *   self,
                                    ag_block_id_t const *     block,
                                    ag_finalization_event_t * event );

void
ag_finality_tracker_mark_finalized( ag_finality_tracker_t *   self,
                                    ulong                     slot,
                                    ag_finalization_event_t * event );

FD_FN_PURE ulong
ag_finality_tracker_highest_finalized_slot( ag_finality_tracker_t const * self );

FD_FN_PURE ulong
ag_finality_tracker_first_unpruned_slot( ag_finality_tracker_t const * self );

int
ag_finality_tracker_status( ag_finality_tracker_t const * self,
                            ulong                         slot,
                            ag_block_hash_t               out_hash );

FD_FN_PURE int
ag_finality_tracker_has_parent( ag_finality_tracker_t const * self,
                                ag_block_id_t const *         block );

FD_PROTOTYPES_END

#endif
