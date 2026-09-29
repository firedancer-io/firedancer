#include "ag_vote_history_file.h"

#include "../../ballet/ed25519/fd_ed25519.h"

#define SAVED_KIND (0U) /* SavedVoteHistoryVersions::Current */

#define SIG_OFF  (4UL)          /* u32 kind precedes the signature */
#define DATA_OFF (4UL+64UL+8UL) /* kind, signature, data_sz */

#define LOAD( T, dst ) do {                                                         \
    if( FD_UNLIKELY( sizeof(T)>buf_sz-off ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE; \
    (dst) = FD_LOAD( T, buf+off );                                                  \
    off += sizeof(T);                                                               \
  } while(0)

#define LOAD_HASH( dst ) do {                                                  \
    if( FD_UNLIKELY( 32UL>buf_sz-off ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE; \
    fd_memcpy( (dst), buf+off, 32UL );                                         \
    off += 32UL;                                                               \
  } while(0)

/* LOAD_LEN loads a u64 sequence length of elements at least min_sz
   bytes each, rejecting lengths the rest of the buffer cannot hold. */
#define LOAD_LEN( dst, min_sz ) do {                                                       \
    LOAD( ulong, dst );                                                                    \
    if( FD_UNLIKELY( (dst)>(buf_sz-off)/(min_sz) ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE; \
  } while(0)

#define PUSH( arr, cnt, max ) ( __extension__({                             \
    if( FD_UNLIKELY( (cnt)>=(max) ) ) return AG_VOTE_HISTORY_FILE_ERR_FULL; \
    &(arr)[ (cnt)++ ];                                                      \
  }))

/* LOAD_SLOT loads a slot that must not be below root.  root comes
   last, so slots are folded into min_slot and checked at the end. */
#define LOAD_SLOT( dst ) do {                   \
    LOAD( ulong, dst );                         \
    min_slot = fd_ulong_min( min_slot, (dst) ); \
  } while(0)

#define LOAD_SLOTS( arr, cnt ) do {                            \
    ulong n_; LOAD_LEN( n_, 8UL );                             \
    for( ulong i_=0UL; i_<n_; i_++ ) {                         \
      ulong * s_ = PUSH( arr, cnt, AG_VOTE_HISTORY_SLOT_MAX ); \
      LOAD_SLOT( *s_ );                                        \
    }                                                          \
  } while(0)

#define LOAD_BLOCK( dst ) do {  \
    ag_block_id_t * b_ = (dst); \
    LOAD( ulong, b_->slot );    \
    LOAD_HASH( b_->hash );      \
  } while(0)

int
ag_vote_history_file_de( uchar const *            buf,
                         ulong                    buf_sz,
                         uchar const              identity[ static 32 ],
                         ag_vote_history_file_t * out ) {
  if( FD_UNLIKELY( buf_sz>AG_VOTE_HISTORY_FILE_MAX ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;
  ulong off = 0UL;

  uint kind; LOAD( uint, kind );
  if( FD_UNLIKELY( kind!=SAVED_KIND ) ) return AG_VOTE_HISTORY_FILE_ERR_VERSION;

  if( FD_UNLIKELY( buf_sz<DATA_OFF ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;
  uchar const * sig = buf+SIG_OFF;
  off = SIG_OFF+64UL;
  ulong data_sz; LOAD( ulong, data_sz );
  if( FD_UNLIKELY( data_sz!=buf_sz-DATA_OFF ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;

  fd_sha512_t sha[ 1 ];
  if( FD_UNLIKELY( FD_ED25519_SUCCESS!=fd_ed25519_verify( buf+DATA_OFF, data_sz, sig, identity, sha ) ) ) return AG_VOTE_HISTORY_FILE_ERR_SIG;

  if( FD_UNLIKELY( 32UL>buf_sz-off ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;
  if( FD_UNLIKELY( !fd_memeq( buf+off, identity, 32UL ) ) ) return AG_VOTE_HISTORY_FILE_ERR_IDENTITY;
  off += 32UL;

  out->voted_cnt                = 0UL;
  out->voted_skip_fallback_cnt  = 0UL;
  out->skipped_cnt              = 0UL;
  out->its_over_cnt             = 0UL;
  out->voted_notar_cnt          = 0UL;
  out->voted_notar_fallback_cnt = 0UL;
  out->notarized_blocks_cnt     = 0UL;
  out->parent_ready_slot        = 0UL;
  out->parent_ready_cnt         = 0UL;
  out->votes_cast_cnt           = 0UL;

  ulong min_slot = ULONG_MAX;

  LOAD_SLOTS( out->voted, out->voted_cnt );

  ulong notar_cnt; LOAD_LEN( notar_cnt, 40UL );
  for( ulong i=0UL; i<notar_cnt; i++ ) {
    ag_block_id_t * block = PUSH( out->voted_notar, out->voted_notar_cnt, AG_VOTE_HISTORY_SLOT_MAX );
    LOAD_SLOT( block->slot );
    LOAD_HASH( block->hash );
  }

  ulong notar_fallback_cnt; LOAD_LEN( notar_fallback_cnt, 16UL );
  for( ulong i=0UL; i<notar_fallback_cnt; i++ ) {
    ulong slot;     LOAD_SLOT( slot );
    ulong hash_cnt; LOAD_LEN( hash_cnt, 32UL );
    for( ulong j=0UL; j<hash_cnt; j++ ) {
      ag_block_id_t * block = PUSH( out->voted_notar_fallback, out->voted_notar_fallback_cnt, AG_VOTE_HISTORY_BLOCK_MAX );
      block->slot = slot;
      LOAD_HASH( block->hash );
    }
  }

  LOAD_SLOTS( out->voted_skip_fallback, out->voted_skip_fallback_cnt );
  LOAD_SLOTS( out->skipped,             out->skipped_cnt             );
  LOAD_SLOTS( out->its_over,            out->its_over_cnt            );

  ulong votes_slot_cnt; LOAD_LEN( votes_slot_cnt, 16UL );
  for( ulong i=0UL; i<votes_slot_cnt; i++ ) {
    ulong slot;     LOAD_SLOT( slot );
    ulong vote_cnt; LOAD_LEN( vote_cnt, 11UL );
    for( ulong j=0UL; j<vote_cnt; j++ ) {
      ag_vote_history_vote_t * vote = PUSH( out->votes_cast, out->votes_cast_cnt, AG_VOTE_HISTORY_VOTE_MAX );
      uchar tag; LOAD( uchar, tag );
      switch( tag ) {
      case AG_VOTE_HISTORY_KIND_NOTAR:
      case AG_VOTE_HISTORY_KIND_NOTAR_FALLBACK:
      case AG_VOTE_HISTORY_KIND_GENESIS:
        LOAD_BLOCK( &vote->block );
        break;
      case AG_VOTE_HISTORY_KIND_FINAL:
      case AG_VOTE_HISTORY_KIND_SKIP:
      case AG_VOTE_HISTORY_KIND_SKIP_FALLBACK:
        LOAD( ulong, vote->block.slot );
        fd_memset( vote->block.hash, 0, 32UL );
        break;
      default:
        return AG_VOTE_HISTORY_FILE_ERR_HISTORY;
      }
      LOAD( ushort, vote->shred_version );
      vote->kind = tag;
      if( FD_UNLIKELY( vote->block.slot!=slot ) ) return AG_VOTE_HISTORY_FILE_ERR_HISTORY;
    }
  }

  ulong notarized_cnt; LOAD_LEN( notarized_cnt, 40UL );
  for( ulong i=0UL; i<notarized_cnt; i++ ) {
    ag_block_id_t * block = PUSH( out->notarized_blocks, out->notarized_blocks_cnt, AG_VOTE_HISTORY_BLOCK_MAX );
    LOAD_SLOT( block->slot );
    LOAD_HASH( block->hash );
  }

  ulong parent_ready_slot_cnt; LOAD_LEN( parent_ready_slot_cnt, 16UL );
  for( ulong i=0UL; i<parent_ready_slot_cnt; i++ ) {
    ulong slot;      LOAD_SLOT( slot );
    ulong block_cnt; LOAD_LEN( block_cnt, 40UL );
    if( slot<out->parent_ready_slot ) { off += block_cnt*40UL; continue; }
    if( slot>out->parent_ready_slot ) { out->parent_ready_slot = slot; out->parent_ready_cnt = 0UL; }
    for( ulong j=0UL; j<block_cnt; j++ ) LOAD_BLOCK( PUSH( out->parent_ready, out->parent_ready_cnt, AG_VOTE_HISTORY_BLOCK_MAX ) );
  }

  LOAD( ulong, out->root );
  if( FD_UNLIKELY( off!=buf_sz        ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;
  if( FD_UNLIKELY( min_slot<out->root ) ) return AG_VOTE_HISTORY_FILE_ERR_HISTORY;

  return AG_VOTE_HISTORY_FILE_SUCCESS;
}

#undef LOAD
#undef LOAD_HASH
#undef LOAD_LEN
#undef PUSH
#undef LOAD_SLOT
#undef LOAD_SLOTS
#undef LOAD_BLOCK
