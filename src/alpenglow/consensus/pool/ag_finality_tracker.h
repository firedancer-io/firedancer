#ifndef HEADER_fd_src_alpenglow_consensus_pool_ag_finality_tracker_h
#define HEADER_fd_src_alpenglow_consensus_pool_ag_finality_tracker_h

#include "../../ag_alpenglow_base.h"

#define AG_FIN_STATUS_NOTARIZED            (0)
#define AG_FIN_STATUS_FINAL_PENDING_NOTAR  (1)
#define AG_FIN_STATUS_FINALIZED            (2)
#define AG_FIN_STATUS_IMPLICITLY_FINALIZED (3)
#define AG_FIN_STATUS_IMPLICITLY_SKIPPED   (4)

#define AG_FINALITY_EVENT_CAP (512UL)

struct ag_finalization_event {
  int           has_finalized;
  ag_block_id_t finalized;
  ulong         if_cnt;
  ag_block_id_t implicitly_finalized[ AG_FINALITY_EVENT_CAP ];
  ulong         is_cnt;
  ulong         implicitly_skipped[ AG_FINALITY_EVENT_CAP ];
};
typedef struct ag_finalization_event ag_finalization_event_t;

struct ag_finality_tracker;
typedef struct ag_finality_tracker ag_finality_tracker_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
ag_finality_tracker_align( void );

FD_FN_CONST ulong
ag_finality_tracker_footprint( ulong slot_max,
                               ulong blockid_max );

void *
ag_finality_tracker_new( void *            shmem,
                         ulong             slot_max,
                         ulong             blockid_max,
                         ulong             seed,
                         ulong             root_slot,
                         fd_hash_t const * root_hash );

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

/* ag_finality_tracker_prune_to force-advances the prune watermark to
   root_slot, the certified-final consensus root published by the votor.
   The bounded pools must shed undecided older slots -- one status-less
   slot otherwise pins the prune walk and the per-slot pools exhaust
   ~slot_max slots later.  Nothing below the root can affect consensus
   again. */

void
ag_finality_tracker_prune_to( ag_finality_tracker_t * self,
                              ulong                   root_slot,
                              fd_hash_t const *       root_hash );

FD_FN_PURE ulong
ag_finality_tracker_highest_finalized_slot( ag_finality_tracker_t const * self );

FD_FN_PURE ulong
ag_finality_tracker_first_unpruned_slot( ag_finality_tracker_t const * self );

int
ag_finality_tracker_status( ag_finality_tracker_t const * self,
                            ulong                         slot,
                            fd_hash_t *                   out_hash );

FD_FN_PURE int
ag_finality_tracker_has_parent( ag_finality_tracker_t const * self,
                                ag_block_id_t const *         block );

FD_PROTOTYPES_END

#endif
