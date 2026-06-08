#include "fd_parent_ready_state.h"

void
fd_parent_ready_state_init( fd_parent_ready_state_t * state,
                            ulong                     slot ) {
  state->slot                = slot;
  state->skip                = 0;
  state->notar_fallbacks_cnt = (uchar)0;
  state->is_ready            = (uchar)0;
  state->ready_cnt           = (uchar)0;
}

void
fd_parent_ready_state_genesis( fd_parent_ready_state_t * state,
                               ulong                     slot ) {
  fd_parent_ready_state_init( state, slot );

  /* Initially, only the genesis block is considered notarized-fallback.
     GENESIS_BLOCK_HASH is the all-zero 32-byte hash. */

  fd_memset( &state->notar_fallbacks[0], 0, sizeof(fd_hash_t) );
  state->notar_fallbacks_cnt = (uchar)1;
}

int
fd_parent_ready_state_mark_skip( fd_parent_ready_state_t * state ) {
  if( FD_UNLIKELY( state->skip ) ) return 0;
  state->skip = 1;
  return 1;
}

int
fd_parent_ready_state_mark_notar_fallback( fd_parent_ready_state_t * state,
                                           fd_hash_t const *         hash ) {

  /* Returns false iff this block was already marked notarized-fallback. */

  for( ulong i=0UL; i<(ulong)state->notar_fallbacks_cnt; i++ ) {
    if( FD_UNLIKELY( 0==memcmp( &state->notar_fallbacks[i], hash, sizeof(fd_hash_t) ) ) ) return 0;
  }

  if( FD_UNLIKELY( (ulong)state->notar_fallbacks_cnt>=FD_PARENT_READY_STATE_CAP ) ) {
    FD_LOG_ERR(( "notar_fallbacks overflow for slot %lu (cap %lu)", state->slot, FD_PARENT_READY_STATE_CAP ));
  }

  state->notar_fallbacks[ state->notar_fallbacks_cnt ] = *hash;
  state->notar_fallbacks_cnt = (uchar)( state->notar_fallbacks_cnt + 1 );
  return 1;
}

void
fd_parent_ready_state_add_to_ready( fd_parent_ready_state_t * state,
                                    fd_block_id_t const *     id ) {

  /* The specific parent must not already be marked ready for this slot
     (matches the Rust assert!(!ready_ids.contains(&id))). */

  for( ulong i=0UL; i<(ulong)state->ready_cnt; i++ ) {
    if( FD_UNLIKELY( fd_block_id_eq( &state->ready_ids[i], id ) ) ) {
      FD_LOG_ERR(( "add_to_ready: parent already ready for slot %lu", state->slot ));
    }
  }

  if( FD_UNLIKELY( (ulong)state->ready_cnt>=FD_PARENT_READY_STATE_CAP ) ) {
    FD_LOG_ERR(( "ready_ids overflow for slot %lu (cap %lu)", state->slot, FD_PARENT_READY_STATE_CAP ));
  }

  state->ready_ids[ state->ready_cnt ] = *id;
  state->ready_cnt = (uchar)( state->ready_cnt + 1 );
  state->is_ready  = (uchar)1;
}

int
fd_parent_ready_state_wait_for_parent_ready( fd_parent_ready_state_t const * state,
                                             fd_block_id_t *                 out_id ) {

  /* Not ready: the Rust Either::Right(oneshot::Receiver) case.  In the
     synchronous port this is simply "no parent yet". */

  if( FD_UNLIKELY( !state->is_ready ) ) return 0;

  FD_TEST( state->ready_cnt>0 ); /* mirrors assert!(!block_ids.is_empty()) */

  /* Ready: the Rust sorts block_ids and returns the minimal one.
     BlockId = (Slot, BlockHash) and Ord is lexicographic, so the
     minimum is the one with the smallest (slot, then hash). */

  fd_block_id_t const * best = &state->ready_ids[0];
  for( ulong i=1UL; i<(ulong)state->ready_cnt; i++ ) {
    fd_block_id_t const * cur = &state->ready_ids[i];
    int lt = ( cur->slot < best->slot ) ||
             ( cur->slot==best->slot && memcmp( cur->hash.uc, best->hash.uc, sizeof(fd_hash_t) )<0 );
    if( lt ) best = cur;
  }

  *out_id = *best;
  return 1;
}
