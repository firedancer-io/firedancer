#ifndef HEADER_fd_src_alpenglow_consensus_pool_ag_parent_ready_tracker_h
#define HEADER_fd_src_alpenglow_consensus_pool_ag_parent_ready_tracker_h

#include "../../ag_alpenglow_base.h"
#include "parent_ready_tracker/ag_parent_ready_state.h"

struct ag_parent_ready {
  ulong         slot;
  ag_block_id_t parent;
};
typedef struct ag_parent_ready ag_parent_ready_t;

#define AG_PARENT_READY_OUT_MAX (64UL)

struct ag_parent_ready_tracker;
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

ag_parent_ready_tracker_t *
ag_parent_ready_tracker_default( ag_parent_ready_tracker_t * tracker );

ag_parent_ready_tracker_t *
ag_parent_ready_tracker_seed_root( ag_parent_ready_tracker_t * tracker,
                                   ulong                       root_slot,
                                   fd_hash_t const *           root_hash );

FD_FN_PURE ulong
ag_parent_ready_tracker_root( ag_parent_ready_tracker_t const * self );

void
ag_parent_ready_tracker_mark_notar_fallback( ag_parent_ready_tracker_t * self,
                                             ag_block_id_t const *       id,
                                             ag_parent_ready_t *         out,
                                             ulong *                     out_cnt );

void
ag_parent_ready_tracker_mark_skipped( ag_parent_ready_tracker_t * self,
                                      ulong                       marked_slot,
                                      ag_parent_ready_t *         out,
                                      ulong *                     out_cnt );

/* Returns 1 and writes out if a parent became newly ready; at most one
   parent can become ready per call. */

int
ag_parent_ready_tracker_handle_finalization( ag_parent_ready_tracker_t * self,
                                             int                         has_finalized,
                                             ag_block_id_t const *       finalized,
                                             ag_block_id_t const *       implicitly_finalized,
                                             ulong                       if_cnt,
                                             ulong const *               implicitly_skipped,
                                             ulong                       is_cnt,
                                             ag_parent_ready_t *         out );

ag_block_id_t const *
ag_parent_ready_tracker_parents_ready( ag_parent_ready_tracker_t * self,
                                       ulong                       slot,
                                       ulong *                     cnt );

int
ag_parent_ready_tracker_wait_for_parent_ready( ag_parent_ready_tracker_t * self,
                                               ulong                       slot,
                                               ag_block_id_t *             out_id );

void
ag_parent_ready_tracker_prune( ag_parent_ready_tracker_t * self,
                               ulong                       new_root );

ag_parent_ready_state_t *
ag_parent_ready_tracker_slot_state( ag_parent_ready_tracker_t * self,
                                    ulong                       slot );

FD_PROTOTYPES_END

#endif
