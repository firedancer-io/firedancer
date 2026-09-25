#include "fd_tower_file.h"

#include "../../ballet/ed25519/fd_ed25519.h"

#define SAVED_TOWER_KIND (1U) /* SavedTowerVersions::Current */
#define LAST_VOTE_KIND   (3U) /* VoteTransaction::TowerSync */
#define THRESHOLD_DEPTH  (8UL)
#define THRESHOLD_SIZE   (2.0/3.0)
#define TOWER_SYNC_MAX   (512UL)

#define SIG_OFF  (4UL)          /* u32 kind precedes the signature */
#define DATA_OFF (4UL+64UL+8UL) /* kind, signature, data_sz */

#define LOAD( T, dst ) do {                              \
    if( FD_UNLIKELY( sizeof(T)>buf_sz-off ) ) return FD_TOWER_FILE_ERR_SIZE; \
    (dst) = FD_LOAD( T, buf+off );                       \
    off += sizeof(T);                                    \
  } while(0)

#define SKIP( sz ) do {                                  \
    if( FD_UNLIKELY( (sz)>buf_sz-off ) ) return FD_TOWER_FILE_ERR_SIZE; \
    off += (sz);                                         \
  } while(0)

int
fd_tower_file_de( uchar const *       buf,
                  ulong               buf_sz,
                  fd_pubkey_t const * identity,
                  fd_tower_file_t *   out ) {
  if( FD_UNLIKELY( buf_sz>FD_TOWER_FILE_MAX ) ) return FD_TOWER_FILE_ERR_SIZE;
  ulong off = 0UL;

  uint kind;    LOAD( uint, kind );
  if( FD_UNLIKELY( kind!=SAVED_TOWER_KIND ) ) return FD_TOWER_FILE_ERR_VERSION;

  if( FD_UNLIKELY( buf_sz<DATA_OFF ) ) return FD_TOWER_FILE_ERR_SIZE;
  uchar const * sig = buf+SIG_OFF;
  off = SIG_OFF+64UL;
  ulong data_sz; LOAD( ulong, data_sz );
  if( FD_UNLIKELY( data_sz!=buf_sz-DATA_OFF ) ) return FD_TOWER_FILE_ERR_SIZE;

  fd_sha512_t sha[ 1 ];
  if( FD_UNLIKELY( FD_ED25519_SUCCESS!=fd_ed25519_verify( buf+DATA_OFF, data_sz, sig, identity->uc, sha ) ) ) return FD_TOWER_FILE_ERR_SIG;

  if( FD_UNLIKELY( 32UL>buf_sz-off ) ) return FD_TOWER_FILE_ERR_SIZE;
  if( FD_UNLIKELY( !fd_memeq( buf+off, identity->uc, 32UL ) ) ) return FD_TOWER_FILE_ERR_IDENTITY;
  off += 32UL;

  ulong  threshold_depth; LOAD( ulong,  threshold_depth );
  double threshold_size;  LOAD( double, threshold_size  );
  if( FD_UNLIKELY( threshold_depth!=THRESHOLD_DEPTH ) ) return FD_TOWER_FILE_ERR_TOWER;
  if( FD_UNLIKELY( threshold_size !=THRESHOLD_SIZE  ) ) return FD_TOWER_FILE_ERR_TOWER;

  SKIP( 32UL ); /* node_pubkey */
  SKIP( 32UL ); /* authorized_withdrawer */
  SKIP( 1UL  ); /* commission */

  ulong votes_cnt; LOAD( ulong, votes_cnt );
  if( FD_UNLIKELY( !votes_cnt || votes_cnt>FD_TOWER_VOTE_MAX ) ) return FD_TOWER_FILE_ERR_TOWER;
  fd_tower_vote_t votes[ FD_TOWER_VOTE_MAX ];
  for( ulong i=0UL; i<votes_cnt; i++ ) {
    ulong slot; LOAD( ulong, slot );
    uint  conf; LOAD( uint,  conf );
    votes[ i ].slot = slot;
    votes[ i ].conf = conf;
  }

  uchar has_root; LOAD( uchar, has_root );
  if( FD_UNLIKELY( has_root>1 ) ) return FD_TOWER_FILE_ERR_TOWER;
  ulong root = ULONG_MAX;
  if( FD_LIKELY( has_root ) ) LOAD( ulong, root );
  if( FD_UNLIKELY( has_root && root==ULONG_MAX ) ) return FD_TOWER_FILE_ERR_TOWER;

  ulong authorized_voters_cnt; LOAD( ulong, authorized_voters_cnt );
  if( FD_UNLIKELY( authorized_voters_cnt>(buf_sz-off)/40UL ) ) return FD_TOWER_FILE_ERR_SIZE;
  SKIP( authorized_voters_cnt*40UL );
  SKIP( 32UL*48UL+8UL ); /* prior_voters buf, idx */
  uchar prior_voters_empty; LOAD( uchar, prior_voters_empty );
  if( FD_UNLIKELY( prior_voters_empty>1U ) ) return FD_TOWER_FILE_ERR_TOWER;
  ulong epoch_credits_cnt; LOAD( ulong, epoch_credits_cnt );
  if( FD_UNLIKELY( epoch_credits_cnt>(buf_sz-off)/24UL ) ) return FD_TOWER_FILE_ERR_SIZE;
  SKIP( epoch_credits_cnt*24UL );
  SKIP( 8UL ); /* last_timestamp slot */
  SKIP( 8UL ); /* last_timestamp ts */

  uint last_vote_kind; LOAD( uint, last_vote_kind );
  if( FD_UNLIKELY( last_vote_kind!=LAST_VOTE_KIND ) ) return FD_TOWER_FILE_ERR_VERSION;

  if( FD_UNLIKELY( off>buf_sz || buf_sz-off<16UL ) ) return FD_TOWER_FILE_ERR_SIZE;
  ulong sync_sz = buf_sz-off-16UL;
  fd_compact_tower_sync_serde_t sync;
  if( FD_UNLIKELY( fd_compact_tower_sync_de( &sync, buf+off, sync_sz ) ) ) return FD_TOWER_FILE_ERR_TOWER;

  uchar sync_buf[ TOWER_SYNC_MAX ];
  ulong canonical_sz;
  if( FD_UNLIKELY( fd_compact_tower_sync_ser( &sync, sync_buf, sizeof(sync_buf), &canonical_sz ) ) ) return FD_TOWER_FILE_ERR_TOWER;
  if( FD_UNLIKELY( canonical_sz!=sync_sz || !fd_memeq( sync_buf, buf+off, sync_sz ) ) ) return FD_TOWER_FILE_ERR_SIZE;
  if( FD_UNLIKELY( sync.root!=root || sync.lockouts_cnt!=votes_cnt ) ) return FD_TOWER_FILE_ERR_TOWER;

  fd_tower_vote_t decoded[ FD_TOWER_VOTE_MAX ];
  ulong           decoded_cnt;
  ulong           decoded_root;
  if( FD_UNLIKELY( fd_compact_tower_sync_to_votes( &sync, decoded, &decoded_cnt, &decoded_root ) ) ) return FD_TOWER_FILE_ERR_TOWER;
  if( FD_UNLIKELY( decoded_cnt!=votes_cnt || decoded_root!=root ||
                   !fd_memeq( decoded, votes, votes_cnt*sizeof(fd_tower_vote_t) ) ) ) return FD_TOWER_FILE_ERR_TOWER;
  if( FD_UNLIKELY( votes[ votes_cnt-1UL ].slot==ULONG_MAX ) ) return FD_TOWER_FILE_ERR_TOWER;

  off += sync_sz;
  ulong last_timestamp_slot; LOAD( ulong, last_timestamp_slot );
  long  last_timestamp;      LOAD( long,  last_timestamp      );
  if( FD_UNLIKELY( off!=buf_sz ) ) return FD_TOWER_FILE_ERR_SIZE;

  fd_memset( out, 0, sizeof(fd_tower_file_t) );
  fd_memcpy( out->votes, votes, votes_cnt*sizeof(fd_tower_vote_t) );
  out->votes_cnt      = votes_cnt;
  out->root           = root;
  out->bank_hash      = sync.hash;
  out->block_id       = sync.block_id;
  out->timestamp_slot = last_timestamp_slot;
  out->timestamp      = last_timestamp;

  return FD_TOWER_FILE_SUCCESS;
}

#undef LOAD
#undef SKIP
