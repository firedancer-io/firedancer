#ifndef HEADER_fd_src_alpenglow_consensus_pool_parent_ready_tracker_ag_parent_ready_state_h
#define HEADER_fd_src_alpenglow_consensus_pool_parent_ready_tracker_ag_parent_ready_state_h

#include "../../../ag_alpenglow_base.h"

#define AG_PARENT_READY_STATE_CAP (8UL)

struct ag_parent_ready_state {
  ulong         slot;
  ulong         next;

  int           skip;

  uchar         notar_fallbacks_cnt;
  fd_hash_t     notar_fallbacks[AG_PARENT_READY_STATE_CAP];

  uchar         is_ready;
  uchar         ready_cnt;
  ag_block_id_t ready_ids[AG_PARENT_READY_STATE_CAP];
};
typedef struct ag_parent_ready_state ag_parent_ready_state_t;

FD_PROTOTYPES_BEGIN

void
ag_parent_ready_state_init( ag_parent_ready_state_t * state,
                            ulong                     slot );

void
ag_parent_ready_state_genesis( ag_parent_ready_state_t * state,
                               ulong                     slot );

int
ag_parent_ready_state_mark_skip( ag_parent_ready_state_t * self );

FD_FN_PURE static inline int
ag_parent_ready_state_is_skip_certified( ag_parent_ready_state_t const * self ) {
  return self->skip;
}

int
ag_parent_ready_state_mark_notar_fallback( ag_parent_ready_state_t * self,
                                           fd_hash_t const *         hash );

FD_FN_PURE static inline fd_hash_t const *
ag_parent_ready_state_notar_fallback_blocks( ag_parent_ready_state_t const * self,
                                             ulong *                         cnt ) {
  *cnt = (ulong)self->notar_fallbacks_cnt;
  return self->notar_fallbacks;
}

void
ag_parent_ready_state_add_to_ready( ag_parent_ready_state_t * self,
                                    ag_block_id_t const *     id );

FD_FN_PURE static inline ag_block_id_t const *
ag_parent_ready_state_ready_block_ids( ag_parent_ready_state_t const * self,
                                       ulong *                         cnt ) {
  *cnt = (ulong)self->ready_cnt;
  return self->ready_ids;
}

int
ag_parent_ready_state_wait_for_parent_ready( ag_parent_ready_state_t * self,
                                             ag_block_id_t *           out_id );

FD_PROTOTYPES_END

#endif
