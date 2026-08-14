#ifndef HEADER_fd_src_choreo_votor_ag_parent_ready_tracker_h
#define HEADER_fd_src_choreo_votor_ag_parent_ready_tracker_h

#include "ag_votor_base.h"
#include "ag_finality_tracker.h"

struct ag_parent_ready {
  ulong         slot;
  ag_block_id_t parent;
};
typedef struct ag_parent_ready ag_parent_ready_t;

struct ag_parent_ready_state {
  ulong         slot; /* map key */
  ulong         next; /* reserved for fd_pool, fd_map_chain */

  int           skip;

  fd_hash_t     notar_fallbacks[AG_NOTAR_FALLBACK_CERT_MAX];
  uchar         notar_fallbacks_cnt;

  int           is_ready;
  ag_block_id_t ready_ids[AG_SLOTS_PER_WINDOW*AG_NOTAR_FALLBACK_CERT_MAX];
  ulong         ready_id_cnt;
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

void
ag_parent_ready_tracker_mark_notar_fallback( ag_parent_ready_tracker_t * self,
                                             ag_block_id_t const *       id,
                                             ag_parent_ready_t *         newly_certified,
                                             ulong *                     newly_certified_cnt );

void
ag_parent_ready_tracker_mark_skipped( ag_parent_ready_tracker_t * self,
                                      ulong                       marked_slot,
                                      ag_parent_ready_t *         newly_certified,
                                      ulong *                     newly_certified_cnt );

ag_parent_ready_t
ag_parent_ready_tracker_handle_finalization( ag_parent_ready_tracker_t *     self,
                                             ag_finalization_event_t const * event,
                                             ag_parent_ready_t *             newly_certified,
                                             ulong *                         newly_certified_cnt );

ag_block_id_t const *
ag_parent_ready_tracker_parents_ready( ag_parent_ready_tracker_t * self,
                                       ulong                       slot,
                                       ulong *                     cnt );

ag_block_id_t
ag_parent_ready_tracker_wait_for_parent_ready( ag_parent_ready_tracker_t * self,
                                               ulong                       slot );

void
ag_parent_ready_tracker_prune( ag_parent_ready_tracker_t * self,
                               ulong                       new_root );

FD_PROTOTYPES_END

#endif
