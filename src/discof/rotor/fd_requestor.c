#include "fd_requestor.h"
#include "../repair/fd_repair.h" /* FD_REPAIR_KIND_*, AG_REPAIR_KIND_* */

#define FD_REQUESTOR_MAGIC (0xf17eda2ce7000067UL) /* firedancer requestor v1 */

struct fd_requestor {
  int       active;        /* a walk is in progress */
  uint      fill_cnt;      /* fill requests emitted during this walk */
  ulong     slot;          /* block of the current or last walk */
  fd_hash_t block_id;
  uint      cursor;        /* next shred position to examine */
  int       block_id_only;
  ulong     magic;
};

FD_FN_CONST ulong
fd_requestor_align( void ) {
  return alignof(fd_requestor_t);
}

FD_FN_CONST ulong
fd_requestor_footprint( void ) {
  return sizeof(fd_requestor_t);
}

void *
fd_requestor_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_requestor_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_requestor_t * self = (fd_requestor_t *)mem;
  fd_memset( self, 0, fd_requestor_footprint() );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( self->magic ) = FD_REQUESTOR_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_requestor_t *
fd_requestor_join( void * mem ) {
  fd_requestor_t * self = (fd_requestor_t *)mem;
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( self->magic!=FD_REQUESTOR_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return self;
}

void *
fd_requestor_leave( fd_requestor_t const * self ) {
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL requestor" ));
    return NULL;
  }
  return (void *)self;
}

void *
fd_requestor_delete( void * mem ) {
  fd_requestor_t * self = (fd_requestor_t *)mem;
  if( FD_UNLIKELY( !self ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( self->magic!=FD_REQUESTOR_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  FD_COMPILER_MFENCE();
  FD_VOLATILE( self->magic ) = 0UL;
  FD_COMPILER_MFENCE();
  return mem;
}

void
fd_requestor_set_block_id_only( fd_requestor_t * self,
                                int              block_id_only ) {
  self->block_id_only = !!block_id_only;
}

ulong
fd_requestor_block_slot( fd_requestor_t const * self ) {
  return self->slot;
}

fd_hash_t const *
fd_requestor_block_id( fd_requestor_t const * self ) {
  return &self->block_id;
}

/* Block reads */

/* block_query returns the live, repairable version for {slot,
   block_id}, or NULL if it is gone or rooted. */

static fd_chainer_block_t const *
block_query( fd_chainer_t const * chainer,
             ulong                slot,
             fd_hash_t const *    block_id ) {
  if( FD_UNLIKELY( slot<=chainer->root ) ) return NULL;
  fd_chainer_block_t const * block = fd_chainer_block_query( chainer, slot, block_id );
  return block;
}

static inline int
parent_present( fd_chainer_t const *       chainer,
                fd_chainer_block_t const * block ) {
  return block->parent_slot<=chainer->root || !!fd_chainer_block_query( chainer, block->parent_slot, &block->parent_block_id );
}

/* emit fills *request for the block being walked.  block_id and
   fec_root may be NULL for all-zero. */

static void
emit( fd_requestor_t const * self,
      fd_rotor_request_t *   request,
      uint                   kind,
      uint                   idx,
      fd_hash_t const *      block_id,
      fd_hash_t const *      fec_root ) {
  *request = (fd_rotor_request_t){ .kind = kind, .slot = self->slot, .idx = idx };
  if( block_id ) request->block_id = *block_id;
  if( fec_root ) request->fec_root = *fec_root;
}

/* parent_orphaned returns 1 if the block names a parent we do not
   hold: its ancestry is known but not yet in the chainer. */

static inline int
parent_orphaned( fd_chainer_t const *       chainer,
                 fd_chainer_block_t const * block ) {
  return block->parent_slot!=AG_UNKNOWN_SLOT && !parent_present( chainer, block );
}

/* parent_next emits the request that names the block's parent and
   returns 1, or returns 0 if the parent slot is already known. */

static int
parent_next( fd_requestor_t const *     self,
             fd_chainer_block_t const * block,
             fd_rotor_request_t *       request ) {
  if( block->parent_slot!=AG_UNKNOWN_SLOT ) return 0;
  int verified = !fd_hash_check_zero( &block->block_id );
  if( verified )             { emit( self, request, AG_REPAIR_KIND_PARENT_FEC_COUNT, 0U, &block->block_id, NULL ); return 1; }
  if( !self->block_id_only ) { emit( self, request, FD_REPAIR_KIND_SHRED,            0U, NULL,             NULL ); return 1; }
  return 0;
}

/* metadata_next emits the single metadata request the block still
   needs once its fill pass is over and returns 1, or returns 0 if its
   metadata is settled: Orphan while the parent is absent, else the
   highest window while the tip is unknown. */

static int
metadata_next( fd_requestor_t const *     self,
               fd_chainer_t const *       chainer,
               fd_chainer_block_t const * block,
               fd_rotor_request_t *       request ) {
  int verified = !fd_hash_check_zero( &block->block_id );

  if( parent_orphaned( chainer, block ) ) {
    if( !self->block_id_only ) { emit( self, request, FD_REPAIR_KIND_ORPHAN,           0U, NULL,             NULL ); return 1; }
  }

  if( block->complete_idx==UINT_MAX ) {
    if( verified )             { emit( self, request, AG_REPAIR_KIND_PARENT_FEC_COUNT, 0U, &block->block_id, NULL ); return 1; }
    if( !self->block_id_only ) { emit( self, request, FD_REPAIR_KIND_HIGHEST_SHRED,    0U, NULL,             NULL ); return 1; }
  }
  return 0;
}

/* fill_next advances the cursor to the next missing shred at or past
   it, emits the request for it and returns 1, or returns 0 once the
   cursor is past the tip. */

static int
fill_next( fd_requestor_t *           self,
           fd_chainer_t const *       chainer,
           fd_chainer_block_t const * block,
           fd_rotor_request_t *       request ) {
  if( FD_UNLIKELY( block->complete_idx==UINT_MAX ) ) return 0; /* metadata rung would have fired */
  int  verified  = !fd_hash_check_zero( &block->block_id );
  uint shred_max = (uint)( chainer->fec_blk_max*FD_FEC_SHRED_CNT );

  /* never behind the buffered prefix, which is all present */
  if( block->buffered_idx!=UINT_MAX ) self->cursor = fd_uint_max( self->cursor, block->buffered_idx + 1U );

  while( self->cursor<=block->complete_idx && self->cursor<shred_max ) {
    uint idx = self->cursor;
    if( fd_chainer_shred_test( chainer, block, idx ) ) { self->cursor++; continue; }
    uint fec_set_idx = idx & ~( (uint)FD_FEC_SHRED_CNT - 1U );

    if( verified ) {
      fd_chainer_fec_t const * fec = fd_chainer_fec_query( chainer, block->slot, fec_set_idx, &block->block_id );
      if( FD_UNLIKELY( !fec ) ) {
        /* No entry at this set: ask for its root and move to the next
           set.  Its shreds are asked for once the sentinel lands and
           the block is walked again. */
        emit( self, request, AG_REPAIR_KIND_FEC_ROOT, fec_set_idx, &block->block_id, NULL );
        self->cursor = fec_set_idx + (uint)FD_FEC_SHRED_CNT;
        return 1;
      }
      emit( self, request, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, idx, &block->block_id, &fec->merkle_root );
      self->cursor = idx + 1U;
      return 1;
    }
    if( !self->block_id_only ) {
      emit( self, request, FD_REPAIR_KIND_SHRED, idx, NULL, NULL );
      self->cursor = idx + 1U;
      return 1;
    }
    self->cursor++; /* positional request suppressed */
  }
  return 0;
}

/* Public API */

void
fd_requestor_block_start( fd_requestor_t *  self,
                          ulong             slot,
                          fd_hash_t const * block_id ) {
  self->active    = 1;
  self->fill_cnt  = 0U;
  self->slot      = slot;
  self->block_id  = *block_id;
  self->cursor    = 0U;
}

int
fd_requestor_block_advance( fd_requestor_t *     self,
                            fd_chainer_t const * chainer,
                            fd_rotor_request_t * out_request,
                            ulong *              out_slot,
                            fd_hash_t *          out_block_id ) {
  if( FD_UNLIKELY( !self->active ) ) return FD_REQUESTOR_ADVANCE_IDLE;

  *out_slot     = self->slot;
  *out_block_id = self->block_id;

  /* The ladder, top to bottom: gone, parent, fill, metadata, exhausted.
     An orphaned block (parent known, absent) fills at most
     FD_REQUESTOR_ORPHAN_FILL_MAX shreds per walk so children repair in
     parallel with their ancestry rather than waiting on it. */

  fd_chainer_block_t const * block = block_query( chainer, self->slot, &self->block_id );
  if( FD_UNLIKELY( !block ) )                              { self->active = 0; return FD_REQUESTOR_ADVANCE_DONE;             } /* gone or rooted mid-walk */
  if( parent_next( self, block, out_request ) )            { self->active = 0; return FD_REQUESTOR_ADVANCE_REQUESTED_PARENT; } /* one request, carried in *out_request */
  uint fill_max = parent_orphaned( chainer, block ) ? FD_REQUESTOR_ORPHAN_FILL_MAX : UINT_MAX;
  if( self->fill_cnt<fill_max && fill_next( self, chainer, block, out_request ) ) { self->fill_cnt++; return FD_REQUESTOR_ADVANCE_REQUEST; }
  if( metadata_next( self, chainer, block, out_request ) ) { self->active = 0; return FD_REQUESTOR_ADVANCE_REQUESTED_PARENT; } /* one request, carried in *out_request */
  self->active = 0;
  return self->fill_cnt ? FD_REQUESTOR_ADVANCE_REQUESTED : FD_REQUESTOR_ADVANCE_DONE;
}
