#include "ag_parent_ready_state.h"

void
ag_parent_ready_state_init( ag_parent_ready_state_t * state,
                            ulong                     slot ) {
  state->slot                = slot;
  state->skip                = 0;
  state->notar_fallbacks_cnt = (uchar)0;
  state->is_ready            = (uchar)0;
  state->ready_cnt           = (uchar)0;
}

void
ag_parent_ready_state_genesis( ag_parent_ready_state_t * state,
                               ulong                     slot ) {
  ag_parent_ready_state_init( state, slot );

  fd_memset( &state->notar_fallbacks[0], 0, sizeof(fd_hash_t) );
  state->notar_fallbacks_cnt = (uchar)1;
}

int
ag_parent_ready_state_mark_skip( ag_parent_ready_state_t * self ) {
  if( FD_UNLIKELY( self->skip ) ) return 0;
  self->skip = 1;
  return 1;
}

int
ag_parent_ready_state_mark_notar_fallback( ag_parent_ready_state_t * self,
                                           fd_hash_t const *         hash ) {

  for( ulong i=0UL; i<(ulong)self->notar_fallbacks_cnt; i++ ) {
    if( FD_UNLIKELY( 0==memcmp( &self->notar_fallbacks[i], hash, sizeof(fd_hash_t) ) ) ) return 0;
  }

  if( FD_UNLIKELY( (ulong)self->notar_fallbacks_cnt>=AG_PARENT_READY_STATE_CAP ) ) {
    FD_LOG_ERR(( "notar_fallbacks overflow for slot %lu (cap %lu)", self->slot, AG_PARENT_READY_STATE_CAP ));
  }

  self->notar_fallbacks[ self->notar_fallbacks_cnt ] = *hash;
  self->notar_fallbacks_cnt = (uchar)( self->notar_fallbacks_cnt + 1 );
  return 1;
}

void
ag_parent_ready_state_add_to_ready( ag_parent_ready_state_t * self,
                                    ag_block_id_t const *     id ) {

  for( ulong i=0UL; i<(ulong)self->ready_cnt; i++ ) {
    if( FD_UNLIKELY( ag_block_id_eq( &self->ready_ids[i], id ) ) ) {
      FD_LOG_ERR(( "add_to_ready: parent already ready for slot %lu", self->slot ));
    }
  }

  if( FD_UNLIKELY( (ulong)self->ready_cnt>=AG_PARENT_READY_STATE_CAP ) ) {
    FD_LOG_ERR(( "ready_ids overflow for slot %lu (cap %lu)", self->slot, AG_PARENT_READY_STATE_CAP ));
  }

  self->ready_ids[ self->ready_cnt ] = *id;
  self->ready_cnt = (uchar)( self->ready_cnt + 1 );
  self->is_ready  = (uchar)1;
}

int
ag_parent_ready_state_wait_for_parent_ready( ag_parent_ready_state_t * self,
                                             ag_block_id_t *           out_id ) {

  if( FD_UNLIKELY( !self->is_ready ) ) return 0;

  FD_TEST( self->ready_cnt>0 );

  /* sort in place: later readers observe sorted order */
  for( ulong i=1UL; i<(ulong)self->ready_cnt; i++ ) {
    ag_block_id_t key = self->ready_ids[i];
    ulong j = i;
    while( j>0UL ) {
      ag_block_id_t const * prev = &self->ready_ids[j-1UL];
      int lt = ( key.slot < prev->slot ) ||
               ( key.slot==prev->slot && memcmp( key.hash.uc, prev->hash.uc, sizeof(fd_hash_t) )<0 );
      if( !lt ) break;
      self->ready_ids[j] = *prev;
      j--;
    }
    self->ready_ids[j] = key;
  }

  *out_id = self->ready_ids[0];
  return 1;
}
