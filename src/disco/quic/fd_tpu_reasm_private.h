#include "fd_tpu.h"

#include <assert.h>

/* fd_tpu_reasm_private.h contains reusable logic of fd_tpu_reasm such
   that it can be included in test cases. */

#define FD_TPU_REASM_MAGIC (0xb4ef0d5ea766713cUL) /* random */

/* fd_tpu_reasm_reset initializes all reassembly slots to their initial
   state.  Also sets the 'sig' field of every mcache line. mcache is
   assumed to be of depth reasm->depth. */

void
fd_tpu_reasm_reset( fd_tpu_reasm_t * reasm );

/* Slot class methods *************************************************/

static inline uint
slot_get_idx( fd_tpu_reasm_t const *      reasm,
              fd_tpu_reasm_slot_t const * slot ) {
  ulong slot_idx = (ulong)( slot - fd_tpu_reasm_slots_laddr_const( reasm ) );
  if( FD_UNLIKELY( slot_idx >= (reasm->depth + reasm->burst) ) ) {
    FD_LOG_CRIT(( "invalid slot pointer! slot_idx=%lu, depth+burst=%u\n",
                  slot_idx, reasm->depth + reasm->burst ));
  }
  return (uint)slot_idx;
}

FD_FN_PURE static inline uchar *
slot_get_data( fd_tpu_reasm_t * reasm,
               ulong            slot_idx ) {
  return fd_tpu_reasm_chunks_laddr( reasm ) + (slot_idx * FD_TPU_REASM_MTU);
}

static FD_FN_UNUSED void
slot_begin( fd_tpu_reasm_slot_t * slot ) {
  memset( slot, 0, sizeof(fd_tpu_reasm_slot_t) );
  slot->state = FD_TPU_REASM_STATE_BUSY;
}

/* Slot queue methods *************************************************/

/* slotq_push_head adds the given slot to the reassembly queue head.
   Assumes queue element count > 2. */

static FD_FN_UNUSED void
slotq_push_head( fd_tpu_reasm_t *      reasm,
                 fd_tpu_reasm_slot_t * slot ) {

  uint slot_idx = slot_get_idx( reasm, slot );
  uint head_idx = reasm->head;

  fd_tpu_reasm_slot_t * head = fd_tpu_reasm_slots_laddr( reasm ) + head_idx;

  head->prev_idx = slot_idx;
  slot->prev_idx = UINT_MAX;
  slot->next_idx = head_idx;
  reasm->head    = slot_idx;
}

/* slotq_push_tail adds the given slot to the reassembly queue tail.
   Assumes queue element count > 2. */

static FD_FN_UNUSED void
slotq_push_tail( fd_tpu_reasm_t *      reasm,
                 fd_tpu_reasm_slot_t * slot ) {

  uint slot_idx = slot_get_idx( reasm, slot );
  uint tail_idx = reasm->tail;
  FD_TEST( tail_idx < reasm->slot_cnt );

  fd_tpu_reasm_slot_t * tail = fd_tpu_reasm_slots_laddr( reasm ) + tail_idx;

  tail->next_idx = slot_idx;
  slot->prev_idx = tail_idx;
  slot->next_idx = UINT_MAX;
  reasm->tail    = slot_idx;
}

/* slotq_pop_tail removes a slot from the reassembly queue tail.
   Assumes queue element count > 2. */

static FD_FN_UNUSED fd_tpu_reasm_slot_t *
slotq_pop_tail( fd_tpu_reasm_t * reasm ) {

  uint                  tail_idx = reasm->tail;
  fd_tpu_reasm_slot_t * tail     = fd_tpu_reasm_slots_laddr( reasm ) + tail_idx;
  uint                  slot_idx = tail->prev_idx;
  fd_tpu_reasm_slot_t * slot     = fd_tpu_reasm_slots_laddr( reasm ) + slot_idx;

  slot->next_idx = UINT_MAX;
  reasm->tail    = slot_idx;
  return tail;
}

/* slotq_remove removes a slot at an arbitrary position in the
   reassembly queue.  Aborts the process if the slot is not part of the
   queue.  Assumes queue element count > 2. */

static FD_FN_UNUSED void
slotq_remove( fd_tpu_reasm_t *      reasm,
              fd_tpu_reasm_slot_t * slot ) {

  uint slot_idx = slot_get_idx( reasm, slot );
  uint prev_idx = slot->prev_idx;
  uint next_idx = slot->next_idx;

  slot->prev_idx = UINT_MAX;
  slot->next_idx = UINT_MAX;

  fd_tpu_reasm_slot_t * prev = fd_tpu_reasm_slots_laddr( reasm ) + prev_idx;
  fd_tpu_reasm_slot_t * next = fd_tpu_reasm_slots_laddr( reasm ) + next_idx;

  if( slot_idx==reasm->head ) {
    assert( next_idx < reasm->slot_cnt );
    reasm->head    = next_idx;
    next->prev_idx = UINT_MAX;
    return;
  }
  if( slot_idx==reasm->tail ) {
    assert( prev_idx < reasm->slot_cnt );
    reasm->tail    = prev_idx;
    prev->next_idx = UINT_MAX;
    return;
  }

  assert( prev_idx < reasm->slot_cnt );
  assert( next_idx < reasm->slot_cnt );
  prev->next_idx = next_idx;
  next->prev_idx = prev_idx;
}
