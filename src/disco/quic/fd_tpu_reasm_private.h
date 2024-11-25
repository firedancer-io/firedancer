#include "fd_tpu.h"

#include <assert.h>

/* fd_tpu_reasm_private.h contains reusable logic of fd_tpu_reasm such
   that it can be included in test cases. */

#define FD_TPU_REASM_MAGIC (0xb4ef0d5ea766713cUL) /* random */

/* FIXME use a doubly-linked map_chain here to optimize for fast removes */
#define MAP_NAME  fd_tpu_reasm_map
#define MAP_KEY_T fd_tpu_reasm_key_t
#define MAP_ELE_T fd_tpu_reasm_slot_t
#define MAP_IDX_T uint
#define MAP_KEY   k
#define MAP_KEY_EQ(a,b) (((a)->conn_uid==(b)->conn_uid) & ((a)->stream_id==(b)->stream_id))
#define MAP_KEY_HASH(key,seed) fd_tpu_reasm_key_hash( key, seed )
#define MAP_NEXT  chain_next
#include "../../util/tmpl/fd_map_chain.c"

/* fd_tpu_reasm_reset initializes all reassembly slots to their initial
   state.  Corrupts messages currently visible in mcache ring. */

void
fd_tpu_reasm_reset( fd_tpu_reasm_t * reasm );

static inline FD_FN_PURE fd_tpu_reasm_map_t *
fd_tpu_reasm_map_laddr( fd_tpu_reasm_t * reasm ) {
  return (fd_tpu_reasm_map_t *)( (ulong)reasm + reasm->map_off );
}

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

FD_FN_PURE static inline uchar const *
slot_get_data_const( fd_tpu_reasm_t const * reasm,
                     ulong                  slot_idx ) {
  return fd_tpu_reasm_chunks_laddr_const( reasm ) + (slot_idx * FD_TPU_REASM_MTU);
}

static FD_FN_UNUSED void
slot_begin( fd_tpu_reasm_slot_t * slot ) {
  memset( slot, 0, sizeof(fd_tpu_reasm_slot_t) );
  slot->k.state     = FD_TPU_REASM_STATE_BUSY;
  slot->k.conn_uid  = ULONG_MAX;
  slot->k.stream_id = FD_TPU_REASM_SID_MASK;
}

/* Slot queue methods **************************************************

   slotq is an LRU cache implemented by a doubly linked list.
   tpu_reasm uses it to allocate and evict reassembly slots. */

/* slotq_push_head adds the given slot to the reassembly queue head.
   Assumes queue element count > 2. */

static FD_FN_UNUSED void
slotq_push_head( fd_tpu_reasm_t *      reasm,
                 fd_tpu_reasm_slot_t * slot ) {

  uint slot_idx = slot_get_idx( reasm, slot );
  uint head_idx = reasm->head;

  fd_tpu_reasm_slot_t * head = fd_tpu_reasm_slots_laddr( reasm ) + head_idx;

  head->lru_prev = slot_idx;
  slot->lru_prev = UINT_MAX;
  slot->lru_next = head_idx;
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

  tail->lru_next = slot_idx;
  slot->lru_prev = tail_idx;
  slot->lru_next = UINT_MAX;
  reasm->tail    = slot_idx;
}

/* slotq_pop_tail removes a slot from the reassembly queue tail.
   Assumes queue element count > 2. */

static FD_FN_UNUSED fd_tpu_reasm_slot_t *
slotq_pop_tail( fd_tpu_reasm_t * reasm ) {

  uint                  tail_idx = reasm->tail;
  fd_tpu_reasm_slot_t * tail     = fd_tpu_reasm_slots_laddr( reasm ) + tail_idx;
  uint                  slot_idx = tail->lru_prev;
  fd_tpu_reasm_slot_t * slot     = fd_tpu_reasm_slots_laddr( reasm ) + slot_idx;

  slot->lru_next = UINT_MAX;
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
  uint lru_prev = slot->lru_prev;
  uint lru_next = slot->lru_next;

  slot->lru_prev = UINT_MAX;
  slot->lru_next = UINT_MAX;

  fd_tpu_reasm_slot_t * prev = fd_tpu_reasm_slots_laddr( reasm ) + lru_prev;
  fd_tpu_reasm_slot_t * next = fd_tpu_reasm_slots_laddr( reasm ) + lru_next;

  if( slot_idx==reasm->head ) {
    if( FD_UNLIKELY( lru_next >= reasm->slot_cnt ) ) {
      FD_LOG_ERR(( "OOB lru_next (lru_next=%u, slot_cnt=%u)", lru_next, reasm->slot_cnt ));
    }
    reasm->head    = lru_next;
    next->lru_prev = UINT_MAX;
    return;
  }
  if( slot_idx==reasm->tail ) {
    if( FD_UNLIKELY( lru_prev >= reasm->slot_cnt ) ) {
      FD_LOG_ERR(( "OOB lru_prev (lru_prev=%u, slot_cnt=%u)", lru_prev, reasm->slot_cnt ));
    }
    reasm->tail    = lru_prev;
    prev->lru_next = UINT_MAX;
    return;
  }

  assert( lru_prev < reasm->slot_cnt );
  assert( lru_next < reasm->slot_cnt );
  if( FD_UNLIKELY( lru_prev >= reasm->slot_cnt ) ) {
    FD_LOG_ERR(( "OOB lru_prev (lru_prev=%u, slot_cnt=%u)", lru_prev, reasm->slot_cnt ));
  }
  if( FD_UNLIKELY( lru_next >= reasm->slot_cnt ) ) {
    FD_LOG_ERR(( "OOB lru_next (lru_next=%u, slot_cnt=%u)", lru_next, reasm->slot_cnt ));
  }
  prev->lru_next = lru_next;
  next->lru_prev = lru_prev;
}

static FD_FN_UNUSED void
smap_insert( fd_tpu_reasm_t *      reasm,
             fd_tpu_reasm_slot_t * slot ) {
  fd_tpu_reasm_map_ele_insert(
      fd_tpu_reasm_map_laddr( reasm ),
      slot,
      fd_tpu_reasm_slots_laddr( reasm )
  );
}

static FD_FN_UNUSED fd_tpu_reasm_slot_t *
smap_query( fd_tpu_reasm_t * reasm,
            ulong            conn_uid,
            ulong            stream_id ) {
  fd_tpu_reasm_key_t k = {
    .conn_uid  = conn_uid,
    .stream_id = stream_id & FD_TPU_REASM_SID_MASK
  };
  return fd_tpu_reasm_map_ele_query(
      fd_tpu_reasm_map_laddr( reasm ),
      &k,
      NULL,
      fd_tpu_reasm_slots_laddr( reasm )
  );
}

static FD_FN_UNUSED void
smap_remove( fd_tpu_reasm_t *      reasm,
             fd_tpu_reasm_slot_t * slot ) {
  /* FIXME use a doubly linked list remove */
  fd_tpu_reasm_map_idx_remove(
      fd_tpu_reasm_map_laddr( reasm ),
      &slot->k,
      ULONG_MAX,
      fd_tpu_reasm_slots_laddr( reasm )
  );
}
