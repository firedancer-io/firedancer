#ifndef HEADER_fd_src_choreo_votor_ag_parent_ready_tracker_h
#define HEADER_fd_src_choreo_votor_ag_parent_ready_tracker_h

#include "ag_votor_base.h"

struct ag_parent_ready {
  ulong         slot;
  ag_block_id_t parent;
};
typedef struct ag_parent_ready ag_parent_ready_t;

struct ag_parent_ready_state {
  ulong slot; /* map key */
  ulong next; /* reserved for fd_pool, fd_map_chain */

  int skip;

  ag_block_hash_t notar_fallbacks[AG_NOTAR_FALLBACK_CERT_MAX];
  uchar           notar_fallbacks_cnt;

  /* window starts only.  The ready parents of a window start are the
     notar fallbacks of slots [b_lo,slot), Definition 15 with every
     slot strictly between b_lo and slot skip certified. */

  ulong         b_lo;            /* highest slot below that is not skipped, ULONG_MAX if slot-1 */
  ag_block_id_t parent_ready_lo; /* lowest ready parent by (slot,hash), slot ULONG_MAX if none */
  int           ready;           /* a ParentReady for this slot is queued but not delivered */
};
typedef struct ag_parent_ready_state ag_parent_ready_state_t;

#define POOL_NAME ag_parent_ready_state_pool
#define POOL_T    ag_parent_ready_state_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               ag_parent_ready_state_map
#define MAP_ELE_T              ag_parent_ready_state_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

struct ag_parent_ready_states {
  ag_parent_ready_state_t *     pool;
  ag_parent_ready_state_map_t * map;
};
typedef struct ag_parent_ready_states ag_parent_ready_states_t;

struct __attribute__((aligned(128UL))) ag_parent_ready_tracker {
  ag_parent_ready_states_t states;
  ulong                    root;
  ulong                    highest_parent_ready; /* highest slot with a ready parent, 0 if none */
};
typedef struct ag_parent_ready_tracker ag_parent_ready_tracker_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
ag_parent_ready_tracker_align( void );

FD_FN_CONST ulong
ag_parent_ready_tracker_footprint( ulong slot_max );

void *
ag_parent_ready_tracker_new( void * shmem,
                             ulong  slot_max,
                             ulong  seed );

ag_parent_ready_tracker_t *
ag_parent_ready_tracker_join( void * shtracker );

void *
ag_parent_ready_tracker_leave( ag_parent_ready_tracker_t const * tracker );

void *
ag_parent_ready_tracker_delete( void * shtracker );

/* Definition 15. ParentReadyTracker::mark_notar_fallback */

void
ag_parent_ready_tracker_mark_notar_fallback( ag_parent_ready_tracker_t * self,
                                             ag_block_id_t const *       id,
                                             ag_parent_ready_t *         newly_certified,
                                             ulong *                     newly_certified_cnt );

/* Definition 15. ParentReadyTracker::mark_skipped */

void
ag_parent_ready_tracker_mark_skipped( ag_parent_ready_tracker_t * self,
                                      ulong                       marked_slot,
                                      ag_parent_ready_t *         newly_certified,
                                      ulong *                     newly_certified_cnt );

/* ag_parent_ready_tracker_delivered marks the ParentReady queued for
   slot as delivered, so the next ready parent queues another. */

void
ag_parent_ready_tracker_delivered( ag_parent_ready_tracker_t * self,
                                   ulong                       slot );

/* Definition 15. ParentReadyTracker::parents_ready.  Writes up to
   out_max ready parents of slot to out and returns how many are ready. */

ulong
ag_parent_ready_tracker_parents_ready( ag_parent_ready_tracker_t const * self,
                                       ulong                             slot,
                                       ag_block_id_t *                   out,
                                       ulong                             out_max );

/* Definition 15. Pool::is_parent_ready */

int
ag_parent_ready_tracker_is_parent_ready( ag_parent_ready_tracker_t const * self,
                                         ulong                             slot,
                                         ag_block_id_t const *             parent );

/* Definition 15. ParentReadyTracker::wait_for_parent_ready; slot ULONG_MAX is the pending receiver */

ag_block_id_t
ag_parent_ready_tracker_wait_for_parent_ready( ag_parent_ready_tracker_t const * self,
                                               ulong                             slot );

/* ag_parent_ready_tracker_highest_parent_ready returns the highest slot
   (window start or not) that has a ready parent, 0 if none.  A leader
   window starting below it was certified without its leader, Agave's
   ParentReadyTracker::block_production_parent MissedWindow. */

FD_FN_PURE static inline ulong
ag_parent_ready_tracker_highest_parent_ready( ag_parent_ready_tracker_t const * self ) {
  return self->highest_parent_ready;
}

/* Section 2.9. ParentReadyTracker::prune */

void
ag_parent_ready_tracker_prune( ag_parent_ready_tracker_t * self,
                               ulong                       new_root );

FD_PROTOTYPES_END

#endif
