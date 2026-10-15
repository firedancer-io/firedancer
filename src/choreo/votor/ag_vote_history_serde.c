#include "ag_vote_history_serde.h"

#include "../../ballet/ed25519/fd_ed25519.h"

void
ag_vote_history_ser( uchar const identity[ static 32 ],
                     ulong       root,
                     uchar       buf[ static AG_VOTE_HISTORY_SER_SZ ] ) {
  FD_STORE( uint,  buf,                                    AG_VOTE_HISTORY_SERDE_KIND                            );
  FD_STORE( ulong, buf+AG_VOTE_HISTORY_SERDE_SIG_OFF+64UL, AG_VOTE_HISTORY_SER_SZ-AG_VOTE_HISTORY_SERDE_DATA_OFF );
  memcpy( buf+AG_VOTE_HISTORY_SERDE_DATA_OFF,      identity, 32UL    );
  memset( buf+AG_VOTE_HISTORY_SERDE_DATA_OFF+32UL, 0,        9UL*8UL );
  FD_STORE( ulong, buf+AG_VOTE_HISTORY_SER_SZ-8UL, root );
}

#define LOAD( T, dst ) do {                                                         \
    if( FD_UNLIKELY( sizeof(T)>buf_sz-off ) ) return AG_VOTE_HISTORY_DE_ERR_SIZE; \
    (dst) = FD_LOAD( T, buf+off );                                                  \
    off += sizeof(T);                                                               \
  } while(0)

/* LOAD_LEN loads a u64 sequence length of elements at least min_sz
   bytes each, rejecting lengths the rest of the buffer cannot hold. */
#define LOAD_LEN( dst, min_sz ) do {                                                       \
    LOAD( ulong, dst );                                                                    \
    if( FD_UNLIKELY( (dst)>(buf_sz-off)/(min_sz) ) ) return AG_VOTE_HISTORY_DE_ERR_SIZE; \
  } while(0)

#define SKIP( sz ) do {                                                        \
    if( FD_UNLIKELY( (sz)>buf_sz-off ) ) return AG_VOTE_HISTORY_DE_ERR_SIZE; \
    off += (sz);                                                               \
  } while(0)

/* LOAD_VOTE loads a slot voted in and folds it into max_vote. */
#define LOAD_VOTE( dst ) do {                   \
    LOAD( ulong, dst );                         \
    max_vote = fd_ulong_max( max_vote, (dst) ); \
  } while(0)

#define LOAD_VOTES() do {                                           \
    ulong n_; LOAD_LEN( n_, 8UL );                                  \
    for( ulong i_=0UL; i_<n_; i_++ ) { ulong s_; LOAD_VOTE( s_ ); } \
  } while(0)

int
ag_vote_history_de( uchar const * buf,
                    ulong         buf_sz,
                    uchar const   identity[ static 32 ],
                    ulong *       wait_to_vote_slot ) {
  ulong off = 0UL;

  uint kind; LOAD( uint, kind );
  if( FD_UNLIKELY( kind!=AG_VOTE_HISTORY_SERDE_KIND ) ) return AG_VOTE_HISTORY_DE_ERR_VERSION;

  if( FD_UNLIKELY( buf_sz<AG_VOTE_HISTORY_SERDE_DATA_OFF ) ) return AG_VOTE_HISTORY_DE_ERR_SIZE;
  uchar const * sig = buf+AG_VOTE_HISTORY_SERDE_SIG_OFF;
  off = AG_VOTE_HISTORY_SERDE_SIG_OFF+64UL;
  ulong data_sz; LOAD( ulong, data_sz );
  if( FD_UNLIKELY( data_sz>buf_sz-AG_VOTE_HISTORY_SERDE_DATA_OFF                  ) ) return AG_VOTE_HISTORY_DE_ERR_SIZE;
  if( FD_UNLIKELY( data_sz>AG_VOTE_HISTORY_DE_MAX-AG_VOTE_HISTORY_SERDE_DATA_OFF ) ) return AG_VOTE_HISTORY_DE_ERR_SIZE;
  buf_sz = AG_VOTE_HISTORY_SERDE_DATA_OFF+data_sz; /* bytes after the history are ignored, as Agave does */

  fd_sha512_t sha[ 1 ];
  if( FD_UNLIKELY( FD_ED25519_SUCCESS!=fd_ed25519_verify( buf+AG_VOTE_HISTORY_SERDE_DATA_OFF, data_sz, sig, identity, sha ) ) ) return AG_VOTE_HISTORY_DE_ERR_SIG;

  if( FD_UNLIKELY( 32UL>buf_sz-off ) ) return AG_VOTE_HISTORY_DE_ERR_SIZE;
  if( FD_UNLIKELY( !fd_memeq( buf+off, identity, 32UL ) ) ) return AG_VOTE_HISTORY_DE_ERR_IDENTITY;
  off += 32UL;

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
      case AG_VOTE_HISTORY_SERDE_TAG_NOTAR:
      case AG_VOTE_HISTORY_SERDE_TAG_NOTAR_FALLBACK:
      case AG_VOTE_HISTORY_SERDE_TAG_GENESIS:       hash_sz = 32UL; break;
      case AG_VOTE_HISTORY_SERDE_TAG_FINAL:
      case AG_VOTE_HISTORY_SERDE_TAG_SKIP:
      case AG_VOTE_HISTORY_SERDE_TAG_SKIP_FALLBACK: hash_sz = 0UL;  break;
      default:                                 return AG_VOTE_HISTORY_DE_ERR_HISTORY;
      }
      ulong vote_slot; LOAD_VOTE( vote_slot );
      SKIP( hash_sz+2UL ); /* block hash, shred_version */
    }
  }

  ulong notarized_cnt; LOAD_LEN( notarized_cnt, 40UL );
  for( ulong i=0UL; i<notarized_cnt; i++ ) {
    SKIP( 40UL ); /* slot, block hash */
  }

  ulong parent_ready_slot_cnt; LOAD_LEN( parent_ready_slot_cnt, 16UL );
  for( ulong i=0UL; i<parent_ready_slot_cnt; i++ ) {
    SKIP( 8UL ); /* slot */
    ulong block_cnt; LOAD_LEN( block_cnt, 40UL );
    SKIP( block_cnt*40UL );
  }

  ulong root; LOAD( ulong, root );

  *wait_to_vote_slot = fd_ulong_sat_add( ag_first_slot_in_window( fd_ulong_max( max_vote, root ) ), AG_SLOTS_PER_WINDOW );
  return AG_VOTE_HISTORY_DE_SUCCESS;
}

#undef LOAD
#undef LOAD_LEN
#undef SKIP
#undef LOAD_VOTE
#undef LOAD_VOTES
