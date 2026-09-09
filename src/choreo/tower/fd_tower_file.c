#include "fd_tower_file.h"

#include "../../ballet/ed25519/fd_ed25519.h"

#include <string.h>

#define SAVED_TOWER_KIND (1U) /* SavedTowerVersions::Current */
#define LAST_VOTE_KIND   (3U) /* VoteTransaction::TowerSync */
#define THRESHOLD_DEPTH  (8UL)
#define THRESHOLD_SIZE   (2.0/3.0)
#define TOWER_SYNC_MAX   (512UL)

#define SIG_OFF  (4UL)          /* u32 kind precedes the signature */
#define DATA_OFF (4UL+64UL+8UL) /* kind, signature, data_sz */

#define STORE( T, val ) do {                               \
    if( FD_UNLIKELY( sizeof(T)>buf_max-off ) ) return -1L; \
    FD_STORE( T, buf+off, (val) );                         \
    off += sizeof(T);                                      \
  } while(0)

#define STORE_BYTES( ptr, sz ) do {                        \
    if( FD_UNLIKELY( (sz)>buf_max-off ) ) return -1L;      \
    memcpy( buf+off, (ptr), (sz) );                        \
    off += (sz);                                           \
  } while(0)

#define STORE_ZERO( sz ) do {                              \
    if( FD_UNLIKELY( (sz)>buf_max-off ) ) return -1L;      \
    memset( buf+off, 0, (sz) );                            \
    off += (sz);                                           \
  } while(0)

static int
tower_sync_set_votes( fd_compact_tower_sync_serde_t * serde,
                      fd_tower_vote_t const *         votes,
                      ulong                           votes_cnt,
                      ulong                           root ) {
  if( FD_UNLIKELY( !votes_cnt || votes_cnt>FD_TOWER_VOTE_MAX ) ) return -1;

  serde->root         = root;
  serde->lockouts_cnt = (ushort)votes_cnt;

  ulong prev = root==ULONG_MAX ? 0UL : root;
  for( ulong i=0UL; i<votes_cnt; i++ ) {
    ulong slot = votes[ i ].slot;
    ulong conf = votes[ i ].conf;
    int repeats_slot = slot==prev && ( i || root!=ULONG_MAX );
    if( FD_UNLIKELY( slot==ULONG_MAX || slot<prev || repeats_slot || conf>FD_TOWER_VOTE_MAX ) ) return -1;
    serde->lockouts[ i ].offset             = slot-prev;
    serde->lockouts[ i ].confirmation_count = (uchar)conf;
    prev = slot;
  }

  fd_tower_vote_t decoded[ FD_TOWER_VOTE_MAX ];
  ulong           decoded_cnt;
  ulong           decoded_root;
  if( FD_UNLIKELY( fd_compact_tower_sync_to_votes( serde, decoded, &decoded_cnt, &decoded_root ) ) ) return -1;
  if( FD_UNLIKELY( decoded_cnt!=votes_cnt || decoded_root!=root ||
                   memcmp( decoded, votes, votes_cnt*sizeof(fd_tower_vote_t) ) ) ) return -1;
  return 0;
}

long
fd_tower_file_ser( fd_tower_vote_t const * votes,
                   ulong                   root,
                   fd_hash_t const *       bank_hash,
                   fd_hash_t const *       block_id,
                   long                    now_secs,
                   fd_pubkey_t const *     identity,
                   fd_tower_sign_fn *      sign_fn,
                   void *                  sign_ctx,
                   uchar *                 buf,
                   ulong                   buf_max ) {
  ulong           votes_cnt = fd_tower_vote_cnt( votes );
  fd_tower_vote_t vote[ FD_TOWER_VOTE_MAX ];
  ulong           vote_idx = 0UL;
  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init( votes );
       !fd_tower_vote_iter_done( votes, iter );
       iter = fd_tower_vote_iter_next( votes, iter ) )
  {
    if( FD_UNLIKELY( vote_idx>=FD_TOWER_VOTE_MAX ) ) return -1L;
    vote[ vote_idx++ ] = *fd_tower_vote_iter_ele_const( votes, iter );
  }
  if( FD_UNLIKELY( vote_idx!=votes_cnt ) ) return -1L;

  fd_compact_tower_sync_serde_t serde = {
    .hash             = *bank_hash,
    .timestamp_option = 1,
    .timestamp        = now_secs,
    .block_id         = *block_id,
  };
  if( FD_UNLIKELY( tower_sync_set_votes( &serde, vote, votes_cnt, root ) ) ) return -1L;

  ulong off = 0UL;

  STORE( uint, SAVED_TOWER_KIND );
  STORE_ZERO( 64UL );
  STORE( ulong, 0UL );

  STORE_BYTES( identity->uc, 32UL );
  STORE( ulong,  THRESHOLD_DEPTH );
  STORE( double, THRESHOLD_SIZE  );

  STORE_ZERO( 32UL ); /* node_pubkey */
  STORE_ZERO( 32UL ); /* authorized_withdrawer */
  STORE( uchar, 0 );  /* commission */

  STORE( ulong, votes_cnt );
  for( ulong i=0UL; i<votes_cnt; i++ ) {
    STORE( ulong, vote[ i ].slot       );
    STORE( uint,  (uint)vote[ i ].conf );
  }

  int has_root = root!=ULONG_MAX;
  STORE( uchar, (uchar)has_root );
  if( FD_LIKELY( has_root ) ) STORE( ulong, root );

  STORE( ulong, 0UL ); /* authorized_voters_cnt */
  for( ulong i=0UL; i<32UL; i++ ) { /* prior_voters buf */
    STORE_ZERO( 32UL );
    STORE( ulong, 0UL );
    STORE( ulong, 0UL );
  }
  STORE( ulong, 31UL ); /* prior_voters idx */
  STORE( uchar, 1 );    /* prior_voters is_empty */
  STORE( ulong, 0UL );  /* epoch_credits_cnt */
  STORE( ulong, 0UL );  /* last_timestamp slot */
  STORE( long,  0L  );  /* last_timestamp ts */

  STORE( uint, LAST_VOTE_KIND );
  uchar sync_buf[ TOWER_SYNC_MAX ];
  ulong sync_sz = 0UL;
  if( FD_UNLIKELY( fd_compact_tower_sync_ser( &serde, sync_buf, sizeof(sync_buf), &sync_sz ) ) ) return -1L;
  STORE_BYTES( sync_buf, sync_sz );

  STORE( ulong, vote[ votes_cnt-1UL ].slot );
  STORE( long,  now_secs       );

  ulong data_sz = off-DATA_OFF;
  FD_STORE( ulong, buf+SIG_OFF+64UL, data_sz );
  sign_fn( sign_ctx, buf+SIG_OFF, buf+DATA_OFF, data_sz );

  return (long)off;
}

#undef STORE
#undef STORE_BYTES
#undef STORE_ZERO

#define LOAD( T, dst ) do {                              \
    if( FD_UNLIKELY( sizeof(T)>buf_sz-off ) ) return -1; \
    (dst) = FD_LOAD( T, buf+off );                       \
    off += sizeof(T);                                    \
  } while(0)

#define SKIP( sz ) do {                                  \
    if( FD_UNLIKELY( (sz)>buf_sz-off ) ) return -1;      \
    off += (sz);                                         \
  } while(0)

int
fd_tower_file_de( uchar const *       buf,
                  ulong               buf_sz,
                  fd_pubkey_t const * identity,
                  fd_tower_vote_t *   out_votes,
                  ulong *             out_votes_cnt,
                  ulong *             out_root,
                  long *              out_ts ) {
  if( FD_UNLIKELY( buf_sz>FD_TOWER_FILE_MAX ) ) return -1;
  ulong off = 0UL;

  uint kind;    LOAD( uint, kind );
  if( FD_UNLIKELY( kind!=SAVED_TOWER_KIND ) ) return -1;

  if( FD_UNLIKELY( buf_sz<DATA_OFF ) ) return -1;
  uchar const * sig = buf+SIG_OFF;
  off = SIG_OFF+64UL;
  ulong data_sz; LOAD( ulong, data_sz );
  if( FD_UNLIKELY( data_sz!=buf_sz-DATA_OFF ) ) return -1;

  fd_sha512_t sha[ 1 ];
  if( FD_UNLIKELY( FD_ED25519_SUCCESS!=fd_ed25519_verify( buf+DATA_OFF, data_sz, sig, identity->uc, sha ) ) ) return -1;

  if( FD_UNLIKELY( 32UL>buf_sz-off ) ) return -1;
  if( FD_UNLIKELY( memcmp( buf+off, identity->uc, 32UL ) ) ) return -1;
  off += 32UL;

  ulong  threshold_depth; LOAD( ulong,  threshold_depth );
  double threshold_size;  LOAD( double, threshold_size  );
  if( FD_UNLIKELY( threshold_depth!=THRESHOLD_DEPTH ) ) return -1;
  if( FD_UNLIKELY( threshold_size !=THRESHOLD_SIZE  ) ) return -1;

  SKIP( 32UL ); /* node_pubkey */
  SKIP( 32UL ); /* authorized_withdrawer */
  SKIP( 1UL  ); /* commission */

  ulong votes_cnt; LOAD( ulong, votes_cnt );
  if( FD_UNLIKELY( !votes_cnt || votes_cnt>FD_TOWER_VOTE_MAX ) ) return -1;
  fd_tower_vote_t votes[ FD_TOWER_VOTE_MAX ];
  for( ulong i=0UL; i<votes_cnt; i++ ) {
    ulong slot; LOAD( ulong, slot );
    uint  conf; LOAD( uint,  conf );
    votes[ i ].slot = slot;
    votes[ i ].conf = conf;
  }

  uchar has_root; LOAD( uchar, has_root );
  if( FD_UNLIKELY( has_root>1 ) ) return -1;
  ulong root = ULONG_MAX;
  if( FD_LIKELY( has_root ) ) LOAD( ulong, root );
  if( FD_UNLIKELY( has_root && root==ULONG_MAX ) ) return -1;

  ulong authorized_voters_cnt; LOAD( ulong, authorized_voters_cnt );
  if( FD_UNLIKELY( authorized_voters_cnt>(buf_sz-off)/40UL ) ) return -1;
  SKIP( authorized_voters_cnt*40UL );
  SKIP( 32UL*48UL+8UL ); /* prior_voters buf, idx */
  uchar prior_voters_empty; LOAD( uchar, prior_voters_empty );
  if( FD_UNLIKELY( prior_voters_empty>1U ) ) return -1;
  ulong epoch_credits_cnt; LOAD( ulong, epoch_credits_cnt );
  if( FD_UNLIKELY( epoch_credits_cnt>(buf_sz-off)/24UL ) ) return -1;
  SKIP( epoch_credits_cnt*24UL );
  SKIP( 8UL ); /* last_timestamp slot */
  SKIP( 8UL ); /* last_timestamp ts */

  uint last_vote_kind; LOAD( uint, last_vote_kind );
  if( FD_UNLIKELY( last_vote_kind!=LAST_VOTE_KIND ) ) return -1;

  if( FD_UNLIKELY( off>buf_sz || buf_sz-off<16UL ) ) return -1;
  ulong sync_sz = buf_sz-off-16UL;
  fd_compact_tower_sync_serde_t sync;
  if( FD_UNLIKELY( fd_compact_tower_sync_de( &sync, buf+off, sync_sz ) ) ) return -1;

  uchar sync_buf[ TOWER_SYNC_MAX ];
  ulong canonical_sz;
  if( FD_UNLIKELY( fd_compact_tower_sync_ser( &sync, sync_buf, sizeof(sync_buf), &canonical_sz ) ) ) return -1;
  if( FD_UNLIKELY( canonical_sz!=sync_sz || memcmp( sync_buf, buf+off, sync_sz ) ) ) return -1;
  if( FD_UNLIKELY( sync.root!=root || sync.lockouts_cnt!=votes_cnt ) ) return -1;

  fd_tower_vote_t decoded[ FD_TOWER_VOTE_MAX ];
  ulong           decoded_cnt;
  ulong           decoded_root;
  if( FD_UNLIKELY( fd_compact_tower_sync_to_votes( &sync, decoded, &decoded_cnt, &decoded_root ) ) ) return -1;
  if( FD_UNLIKELY( decoded_cnt!=votes_cnt || decoded_root!=root ||
                   memcmp( decoded, votes, votes_cnt*sizeof(fd_tower_vote_t) ) ) ) return -1;
  if( FD_UNLIKELY( votes[ votes_cnt-1UL ].slot==ULONG_MAX ) ) return -1;

  off += sync_sz;
  ulong last_timestamp_slot; LOAD( ulong, last_timestamp_slot );
  long  last_timestamp;      LOAD( long,  last_timestamp      );
  if( FD_UNLIKELY( off!=buf_sz || last_timestamp_slot>votes[votes_cnt-1UL].slot ) ) return -1;
  if( FD_UNLIKELY( sync.timestamp_option &&
                   (last_timestamp_slot!=votes[votes_cnt-1UL].slot || last_timestamp!=sync.timestamp) ) ) return -1;

  memcpy( out_votes, votes, votes_cnt*sizeof(fd_tower_vote_t) );
  *out_votes_cnt = votes_cnt;
  *out_root      = root;
  *out_ts        = last_timestamp;

  return 0;
}

#undef LOAD
#undef SKIP
