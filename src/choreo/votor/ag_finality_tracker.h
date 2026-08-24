#ifndef HEADER_fd_src_choreo_votor_ag_finality_tracker_h
#define HEADER_fd_src_choreo_votor_ag_finality_tracker_h

#include "ag_votor_base.h"

#define AG_FINALIZATION_STATUS_NOTARIZED            (0)
#define AG_FINALIZATION_STATUS_FINAL_PENDING_NOTAR  (1)
#define AG_FINALIZATION_STATUS_FINALIZED            (2)
#define AG_FINALIZATION_STATUS_IMPLICITLY_FINALIZED (3)
#define AG_FINALIZATION_STATUS_IMPLICITLY_SKIPPED   (4)

              struct ag_finalization_notarized            { ag_block_hash_t hash; };
__extension__ struct ag_finalization_final_pending_notar  {                       };
              struct ag_finalization_finalized            { ag_block_hash_t hash; };
              struct ag_finalization_implicitly_finalized { ag_block_hash_t hash; };
__extension__ struct ag_finalization_implicitly_skipped   {                       };

typedef struct ag_finalization_notarized            ag_finalization_notarized_t;
typedef struct ag_finalization_final_pending_notar  ag_finalization_final_pending_notar_t;
typedef struct ag_finalization_finalized            ag_finalization_finalized_t;
typedef struct ag_finalization_implicitly_finalized ag_finalization_implicitly_finalized_t;
typedef struct ag_finalization_implicitly_skipped   ag_finalization_implicitly_skipped_t;

struct ag_finalization_status {
  int kind;
  union {
    ag_finalization_notarized_t            notarized;
    ag_finalization_final_pending_notar_t  final_pending_notar;
    ag_finalization_finalized_t            finalized;
    ag_finalization_implicitly_finalized_t implicitly_finalized;
    ag_finalization_implicitly_skipped_t   implicitly_skipped;
  } inner;
};
typedef struct ag_finalization_status ag_finalization_status_t;

struct ag_finalization_event {
  ag_block_id_t   finalized;
  ag_block_id_t * implicitly_finalized; ulong implicitly_finalized_cnt;
  ulong *         implicitly_skipped;   ulong implicitly_skipped_cnt;
};
typedef struct ag_finalization_event ag_finalization_event_t;

struct status_ele {
  ulong                    slot;
  ag_finalization_status_t status;
  ulong                    next;
};
typedef struct status_ele status_ele_t;

#define POOL_NAME status_pool
#define POOL_T    status_ele_t
#define POOL_NEXT next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               status_map
#define MAP_ELE_T              status_ele_t
#define MAP_KEY                slot
#define MAP_KEY_T              ulong
#define MAP_KEY_EQ(k0,k1)      ((*(k0))==(*(k1)))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (*(key)) ^ (seed) ))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

struct parent_ele {
  ag_block_id_t block_id;
  ag_block_id_t parent_block_id;
  ulong         next;
};
typedef struct parent_ele parent_ele_t;

#define POOL_NAME parent_pool
#define POOL_T    parent_ele_t
#define POOL_NEXT next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               parent_map
#define MAP_ELE_T              parent_ele_t
#define MAP_KEY                block_id
#define MAP_KEY_T              ag_block_id_t
#define MAP_KEY_EQ(k0,k1)      (ag_block_id_eq( (k0), (k1) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( (seed), (key), sizeof(ag_block_id_t) ))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

struct status {
  status_ele_t * pool;
  status_map_t * map;
};
typedef struct status status_t;

struct parents {
  parent_ele_t * pool;
  parent_map_t * map;
};
typedef struct parents parents_t;

struct ag_finality_tracker {
  status_t  status;
  parents_t parents;
  ulong     highest_finalized_slot;
  ulong     first_unpruned_slot;

  struct {
    ag_block_id_t * implicitly_finalized;
    ulong *         implicitly_skipped;
  } scratch;
};
typedef struct ag_finality_tracker ag_finality_tracker_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ag_finalization_event_t
ag_finalization_event_default( void ) {
  ag_finalization_event_t event;
  event.finalized.slot       = ULONG_MAX;
  event.implicitly_finalized = NULL; event.implicitly_finalized_cnt = 0UL;
  event.implicitly_skipped   = NULL; event.implicitly_skipped_cnt   = 0UL;
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

ag_finalization_event_t
ag_finality_tracker_add_parent( ag_finality_tracker_t * self,
                                ag_block_id_t const *   block,
                                ag_block_id_t const *   parent );

ag_finalization_event_t
ag_finality_tracker_mark_fast_finalized( ag_finality_tracker_t * self,
                                         ag_block_id_t const *   block );

ag_finalization_event_t
ag_finality_tracker_mark_notarized( ag_finality_tracker_t * self,
                                    ag_block_id_t const *   block );

ag_finalization_event_t
ag_finality_tracker_mark_finalized( ag_finality_tracker_t * self,
                                    ulong                   slot );

FD_FN_PURE ulong
ag_finality_tracker_highest_finalized_slot( ag_finality_tracker_t const * self );

FD_FN_PURE ulong
ag_finality_tracker_first_unpruned_slot( ag_finality_tracker_t const * self );

/* ag_finality_tracker_status returns the finalization status of slot, or
   -1 if the slot is unknown.  out_hash, if non-NULL, receives the block
   hash the status refers to, zeroed when the status carries none. */

int
ag_finality_tracker_status( ag_finality_tracker_t const * self,
                            ulong                         slot,
                            ag_block_hash_t               out_hash );

FD_FN_PURE int
ag_finality_tracker_has_parent( ag_finality_tracker_t const * self,
                                ag_block_id_t const *         block );

FD_PROTOTYPES_END

#endif
