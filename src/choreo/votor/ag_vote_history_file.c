#include "ag_vote_history_file.h"

#include "../../ballet/ed25519/fd_ed25519.h"

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

#define LOAD_SLOTS( arr, cnt ) do {                                                              \
    ulong n_; LOAD_LEN( n_, 8UL );                                                               \
    for( ulong i_=0UL; i_<n_; i_++ ) LOAD( ulong, *PUSH( arr, cnt, AG_VOTE_HISTORY_SLOT_MAX ) ); \
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
  if( FD_UNLIKELY( kind!=AG_VOTE_HISTORY_FILE_KIND ) ) return AG_VOTE_HISTORY_FILE_ERR_VERSION;

  if( FD_UNLIKELY( buf_sz<AG_VOTE_HISTORY_FILE_DATA_OFF ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;
  uchar const * sig = buf+AG_VOTE_HISTORY_FILE_SIG_OFF;
  off = AG_VOTE_HISTORY_FILE_SIG_OFF+64UL;
  ulong data_sz; LOAD( ulong, data_sz );
  if( FD_UNLIKELY( data_sz!=buf_sz-AG_VOTE_HISTORY_FILE_DATA_OFF ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;

  fd_sha512_t sha[ 1 ];
  if( FD_UNLIKELY( FD_ED25519_SUCCESS!=fd_ed25519_verify( buf+AG_VOTE_HISTORY_FILE_DATA_OFF, data_sz, sig, identity, sha ) ) ) return AG_VOTE_HISTORY_FILE_ERR_SIG;

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
  out->parent_ready_cnt         = 0UL;
  out->votes_cast_cnt           = 0UL;

  /* Map keys are checked against root too, even with no entries. */
  ulong min_key = ULONG_MAX;

  LOAD_SLOTS( out->voted, out->voted_cnt );

  ulong notar_cnt; LOAD_LEN( notar_cnt, 40UL );
  for( ulong i=0UL; i<notar_cnt; i++ ) {
    LOAD_BLOCK( PUSH( out->voted_notar, out->voted_notar_cnt, AG_VOTE_HISTORY_BLOCK_MAX ) );
  }

  ulong notar_fallback_cnt; LOAD_LEN( notar_fallback_cnt, 16UL );
  for( ulong i=0UL; i<notar_fallback_cnt; i++ ) {
    ulong slot;     LOAD( ulong, slot );
    ulong hash_cnt; LOAD_LEN( hash_cnt, 32UL );
    min_key = fd_ulong_min( min_key, slot );
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
    ulong slot;     LOAD( ulong, slot );
    ulong vote_cnt; LOAD_LEN( vote_cnt, 11UL );
    min_key = fd_ulong_min( min_key, slot );
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
    LOAD_BLOCK( PUSH( out->notarized_blocks, out->notarized_blocks_cnt, AG_VOTE_HISTORY_BLOCK_MAX ) );
  }

  ulong parent_ready_slot_cnt; LOAD_LEN( parent_ready_slot_cnt, 16UL );
  for( ulong i=0UL; i<parent_ready_slot_cnt; i++ ) {
    ulong slot;      LOAD( ulong, slot );
    ulong block_cnt; LOAD_LEN( block_cnt, 40UL );
    min_key = fd_ulong_min( min_key, slot );
    for( ulong j=0UL; j<block_cnt; j++ ) {
      ag_vote_history_parent_ready_t * pr = PUSH( out->parent_ready, out->parent_ready_cnt, AG_VOTE_HISTORY_PARENT_READY_MAX );
      pr->slot = slot;
      LOAD_BLOCK( &pr->block );
    }
  }

  LOAD( ulong, out->root );
  if( FD_UNLIKELY( off!=buf_sz ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;

  ulong root = out->root;
  if( FD_UNLIKELY( min_key<root ) ) return AG_VOTE_HISTORY_FILE_ERR_HISTORY;
  for( ulong i=0UL; i<out->voted_cnt;                i++ ) if( FD_UNLIKELY( out->voted[ i ]                     <root ) ) return AG_VOTE_HISTORY_FILE_ERR_HISTORY;
  for( ulong i=0UL; i<out->voted_skip_fallback_cnt;  i++ ) if( FD_UNLIKELY( out->voted_skip_fallback[ i ]       <root ) ) return AG_VOTE_HISTORY_FILE_ERR_HISTORY;
  for( ulong i=0UL; i<out->skipped_cnt;              i++ ) if( FD_UNLIKELY( out->skipped[ i ]                   <root ) ) return AG_VOTE_HISTORY_FILE_ERR_HISTORY;
  for( ulong i=0UL; i<out->its_over_cnt;             i++ ) if( FD_UNLIKELY( out->its_over[ i ]                  <root ) ) return AG_VOTE_HISTORY_FILE_ERR_HISTORY;
  for( ulong i=0UL; i<out->voted_notar_cnt;          i++ ) if( FD_UNLIKELY( out->voted_notar[ i ].slot          <root ) ) return AG_VOTE_HISTORY_FILE_ERR_HISTORY;
  for( ulong i=0UL; i<out->notarized_blocks_cnt;     i++ ) if( FD_UNLIKELY( out->notarized_blocks[ i ].slot     <root ) ) return AG_VOTE_HISTORY_FILE_ERR_HISTORY;

  return AG_VOTE_HISTORY_FILE_SUCCESS;
}

#define SKIP( sz ) do {                                                        \
    if( FD_UNLIKELY( (sz)>buf_sz-off ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE; \
    off += (sz);                                                               \
  } while(0)

/* LOAD_SLOT loads a slot that must not be below root.  root comes
   last, so slots are folded into min_slot and checked at the end.
   LOAD_VOTE also folds a slot we voted in into max_vote. */
#define LOAD_SLOT( dst ) do {                   \
    LOAD( ulong, dst );                         \
    min_slot = fd_ulong_min( min_slot, (dst) ); \
  } while(0)

#define LOAD_VOTE( dst ) do {                   \
    LOAD_SLOT( dst );                           \
    max_vote = fd_ulong_max( max_vote, (dst) ); \
  } while(0)

#define LOAD_VOTES() do {                                           \
    ulong n_; LOAD_LEN( n_, 8UL );                                  \
    for( ulong i_=0UL; i_<n_; i_++ ) { ulong s_; LOAD_VOTE( s_ ); } \
  } while(0)

int
ag_vote_history_file_scan( uchar const * buf,
                           ulong         buf_sz,
                           uchar const   identity[ static 32 ],
                           ulong *       wait_to_vote_slot ) {
  if( FD_UNLIKELY( buf_sz>AG_VOTE_HISTORY_FILE_MAX ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;
  ulong off = 0UL;

  uint kind; LOAD( uint, kind );
  if( FD_UNLIKELY( kind!=AG_VOTE_HISTORY_FILE_KIND ) ) return AG_VOTE_HISTORY_FILE_ERR_VERSION;

  if( FD_UNLIKELY( buf_sz<AG_VOTE_HISTORY_FILE_DATA_OFF ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;
  uchar const * sig = buf+AG_VOTE_HISTORY_FILE_SIG_OFF;
  off = AG_VOTE_HISTORY_FILE_SIG_OFF+64UL;
  ulong data_sz; LOAD( ulong, data_sz );
  if( FD_UNLIKELY( data_sz!=buf_sz-AG_VOTE_HISTORY_FILE_DATA_OFF ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;

  fd_sha512_t sha[ 1 ];
  if( FD_UNLIKELY( FD_ED25519_SUCCESS!=fd_ed25519_verify( buf+AG_VOTE_HISTORY_FILE_DATA_OFF, data_sz, sig, identity, sha ) ) ) return AG_VOTE_HISTORY_FILE_ERR_SIG;

  if( FD_UNLIKELY( 32UL>buf_sz-off ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;
  if( FD_UNLIKELY( !fd_memeq( buf+off, identity, 32UL ) ) ) return AG_VOTE_HISTORY_FILE_ERR_IDENTITY;
  off += 32UL;

  ulong min_slot = ULONG_MAX;
  ulong max_vote = 0UL;

  LOAD_VOTES(); /* voted */

  ulong notar_cnt; LOAD_LEN( notar_cnt, 40UL );
  for( ulong i=0UL; i<notar_cnt; i++ ) {
    ulong slot; LOAD_VOTE( slot );
    SKIP( 32UL );
  }

  ulong notar_fallback_cnt; LOAD_LEN( notar_fallback_cnt, 16UL );
  for( ulong i=0UL; i<notar_fallback_cnt; i++ ) {
    ulong slot;     LOAD_VOTE( slot );
    ulong hash_cnt; LOAD_LEN( hash_cnt, 32UL );
    SKIP( hash_cnt*32UL );
  }

  LOAD_VOTES(); /* voted_skip_fallback */
  LOAD_VOTES(); /* skipped */
  LOAD_VOTES(); /* its_over */

  ulong votes_slot_cnt; LOAD_LEN( votes_slot_cnt, 16UL );
  for( ulong i=0UL; i<votes_slot_cnt; i++ ) {
    ulong slot;     LOAD_VOTE( slot );
    ulong vote_cnt; LOAD_LEN( vote_cnt, 11UL );
    for( ulong j=0UL; j<vote_cnt; j++ ) {
      uchar tag; LOAD( uchar, tag );
      ulong hash_sz;
      switch( tag ) {
      case AG_VOTE_HISTORY_KIND_NOTAR:
      case AG_VOTE_HISTORY_KIND_NOTAR_FALLBACK:
      case AG_VOTE_HISTORY_KIND_GENESIS:       hash_sz = 32UL; break;
      case AG_VOTE_HISTORY_KIND_FINAL:
      case AG_VOTE_HISTORY_KIND_SKIP:
      case AG_VOTE_HISTORY_KIND_SKIP_FALLBACK: hash_sz = 0UL;  break;
      default:                                 return AG_VOTE_HISTORY_FILE_ERR_HISTORY;
      }
      ulong vote_slot; LOAD( ulong, vote_slot );
      SKIP( hash_sz+2UL ); /* block hash, shred_version */
      if( FD_UNLIKELY( vote_slot!=slot ) ) return AG_VOTE_HISTORY_FILE_ERR_HISTORY;
    }
  }

  ulong notarized_cnt; LOAD_LEN( notarized_cnt, 40UL );
  for( ulong i=0UL; i<notarized_cnt; i++ ) {
    ulong slot; LOAD_SLOT( slot );
    SKIP( 32UL );
  }

  ulong parent_ready_slot_cnt; LOAD_LEN( parent_ready_slot_cnt, 16UL );
  for( ulong i=0UL; i<parent_ready_slot_cnt; i++ ) {
    ulong slot;      LOAD_SLOT( slot );
    ulong block_cnt; LOAD_LEN( block_cnt, 40UL );
    SKIP( block_cnt*40UL );
  }

  ulong root; LOAD( ulong, root );
  if( FD_UNLIKELY( off!=buf_sz    ) ) return AG_VOTE_HISTORY_FILE_ERR_SIZE;
  if( FD_UNLIKELY( min_slot<root ) ) return AG_VOTE_HISTORY_FILE_ERR_HISTORY;

  *wait_to_vote_slot = fd_ulong_sat_add( ag_first_slot_in_window( fd_ulong_max( max_vote, root ) ), AG_SLOTS_PER_WINDOW );
  return AG_VOTE_HISTORY_FILE_SUCCESS;
}

#undef LOAD
#undef LOAD_HASH
#undef LOAD_LEN
#undef PUSH
#undef LOAD_SLOTS
#undef LOAD_BLOCK
#undef SKIP
#undef LOAD_SLOT
#undef LOAD_VOTE
#undef LOAD_VOTES

#define PUT( T, v ) do {                                    \
    if( FD_UNLIKELY( sizeof(T)>buf_max-off ) ) return 0UL; \
    FD_STORE( T, buf+off, (v) );                           \
    off += sizeof(T);                                      \
  } while(0)

#define PUT_HASH( h ) do {                                  \
    if( FD_UNLIKELY( 32UL>buf_max-off ) ) return 0UL;      \
    fd_memcpy( buf+off, (h), 32UL );                       \
    off += 32UL;                                           \
  } while(0)

/* SEQ_BEGIN reserves a u64 sequence length, which SEQ_END sets to the
   number of entries counted in seq_cnt. */
#define SEQ_BEGIN() do { seq_off = off; seq_cnt = 0UL; PUT( ulong, 0UL ); } while(0)
#define SEQ_END()   FD_STORE( ulong, buf+seq_off, seq_cnt )

#define PUT_SLOTS( arr, cnt ) do {                                    \
    PUT( ulong, (cnt) );                                              \
    for( ulong i_=0UL; i_<(cnt); i_++ ) PUT( ulong, (arr)[ i_ ] );    \
  } while(0)

#define PUT_BLOCK( b ) do { PUT( ulong, (b).slot ); PUT_HASH( (b).hash ); } while(0)

#define PUT_BLOCKS( arr, cnt ) do {                                   \
    PUT( ulong, (cnt) );                                              \
    for( ulong i_=0UL; i_<(cnt); i_++ ) PUT_BLOCK( (arr)[ i_ ] );     \
  } while(0)

/* RUN_END returns where the run of entries of arr from i on with the
   same KEY ends.  The maps of a VoteHistory are flattened into such
   runs of (slot, value) entries. */
#define RUN_END( arr, cnt, i, KEY ) ( __extension__({                 \
    ulong j_ = (i);                                                   \
    while( j_<(cnt) && (arr)[ j_ ].KEY==(arr)[ (i) ].KEY ) j_++;       \
    j_;                                                               \
  }))

ulong
ag_vote_history_file_ser( ag_vote_history_file_t const * vh,
                          uchar const                    identity[ static 32 ],
                          uchar *                        buf,
                          ulong                          buf_max ) {
  if( FD_UNLIKELY( buf_max<AG_VOTE_HISTORY_FILE_DATA_OFF ) ) return 0UL;
  ulong off = AG_VOTE_HISTORY_FILE_DATA_OFF;
  ulong seq_off;
  ulong seq_cnt;

  PUT_HASH( identity );

  PUT_SLOTS( vh->voted, vh->voted_cnt );

  PUT_BLOCKS( vh->voted_notar, vh->voted_notar_cnt );

  SEQ_BEGIN(); /* voted_notar_fallback */
  for( ulong i=0UL; i<vh->voted_notar_fallback_cnt; seq_cnt++ ) {
    ulong end = RUN_END( vh->voted_notar_fallback, vh->voted_notar_fallback_cnt, i, slot );
    PUT( ulong, vh->voted_notar_fallback[ i ].slot ); PUT( ulong, end-i );
    for( ; i<end; i++ ) PUT_HASH( vh->voted_notar_fallback[ i ].hash );
  }
  SEQ_END();

  PUT_SLOTS( vh->voted_skip_fallback, vh->voted_skip_fallback_cnt );
  PUT_SLOTS( vh->skipped,             vh->skipped_cnt             );
  PUT_SLOTS( vh->its_over,            vh->its_over_cnt            );

  SEQ_BEGIN(); /* votes_cast */
  for( ulong i=0UL; i<vh->votes_cast_cnt; seq_cnt++ ) {
    ulong end = RUN_END( vh->votes_cast, vh->votes_cast_cnt, i, block.slot );
    PUT( ulong, vh->votes_cast[ i ].block.slot ); PUT( ulong, end-i );
    for( ; i<end; i++ ) {
      ag_vote_history_vote_t const * vote = vh->votes_cast+i;
      PUT( uchar, (uchar)vote->kind );
      PUT( ulong, vote->block.slot );
      if( vote->kind==AG_VOTE_HISTORY_KIND_NOTAR || vote->kind==AG_VOTE_HISTORY_KIND_NOTAR_FALLBACK || vote->kind==AG_VOTE_HISTORY_KIND_GENESIS ) PUT_HASH( vote->block.hash );
      PUT( ushort, vote->shred_version );
    }
  }
  SEQ_END();

  PUT_BLOCKS( vh->notarized_blocks, vh->notarized_blocks_cnt );

  SEQ_BEGIN(); /* parent_ready_slots */
  for( ulong i=0UL; i<vh->parent_ready_cnt; seq_cnt++ ) {
    ulong end = RUN_END( vh->parent_ready, vh->parent_ready_cnt, i, slot );
    PUT( ulong, vh->parent_ready[ i ].slot ); PUT( ulong, end-i );
    for( ; i<end; i++ ) PUT_BLOCK( vh->parent_ready[ i ].block );
  }
  SEQ_END();

  PUT( ulong, vh->root );

  FD_STORE( uint,  buf,                                   AG_VOTE_HISTORY_FILE_KIND        );
  FD_STORE( ulong, buf+AG_VOTE_HISTORY_FILE_SIG_OFF+64UL, off-AG_VOTE_HISTORY_FILE_DATA_OFF );
  return off;
}

#undef PUT
#undef PUT_HASH
#undef SEQ_BEGIN
#undef SEQ_END
#undef PUT_SLOTS
#undef PUT_BLOCK
#undef PUT_BLOCKS
#undef RUN_END
