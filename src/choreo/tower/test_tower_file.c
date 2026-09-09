#include "fd_tower_file.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../util/fd_util.h"

#include <string.h>

static uchar deque_mem[ FD_TOWER_VOTE_FOOTPRINT ] __attribute__((aligned(FD_TOWER_VOTE_ALIGN)));
static uchar file_buf[ FD_TOWER_FILE_MAX ];

struct signer {
  uchar       prv[ 32 ];
  fd_pubkey_t pub;
};

typedef struct signer signer_t;

static void
test_sign( void *        _signer,
           uchar         sig[ 64 ],
           uchar const * msg,
           ulong         msg_sz ) {
  signer_t *  signer = (signer_t *)_signer;
  fd_sha512_t sha[ 1 ];
  uchar       m[ 32 ];
  fd_tower_file_sign_msg( msg, msg_sz, m );
  fd_ed25519_sign( sig, m, 32UL, signer->pub.uc, signer->prv, sha );
}

static void
resign( signer_t * signer,
        uchar *    buf,
        ulong      sz ) {
  ulong const data_off = 4UL+64UL+8UL;
  FD_STORE( ulong, buf+4UL+64UL, sz-data_off );
  test_sign( signer, buf+4UL, buf+data_off, sz-data_off );
}

static void
assert_rejected( signer_t const * signer,
                 uchar const *    buf,
                 ulong            sz ) {
  fd_tower_file_t out;
  fd_tower_file_t expected;
  fd_memset( &out, 0xA5, sizeof(out) );
  fd_memcpy( &expected, &out, sizeof(expected) );
  FD_TEST( -1==fd_tower_file_de( buf, sz, &signer->pub, &out ) );
  FD_TEST( !memcmp( &out, &expected, sizeof(out) ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  signer_t signer;
  memset( signer.prv, 0x42, 32UL );
  fd_sha512_t sha[ 1 ];
  fd_ed25519_public_from_private( signer.pub.uc, signer.prv, sha );

  fd_tower_vote_t * votes = fd_tower_vote_join( fd_tower_vote_new( deque_mem ) );
  FD_TEST( votes );
  fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot=100UL, .conf=3UL } );
  fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot=101UL, .conf=2UL } );
  fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot=105UL, .conf=1UL } );

  fd_hash_t bank_hash; memset( &bank_hash, 0xAB, sizeof(bank_hash) );
  fd_hash_t block_id;  memset( &block_id,  0xCD, sizeof(block_id)  );

  long sz = fd_tower_file_ser( votes, 90UL, &bank_hash, &block_id, 1234567L,
                               &signer.pub, test_sign, &signer, file_buf, sizeof(file_buf) );
  FD_TEST( sz==1927L );

  /* SHA-256 of the equivalent Agave bincode serialization. */
  static uchar const expected_hash[ 32 ] = {
    0x74, 0x73, 0x60, 0x3e, 0x7d, 0xde, 0xd9, 0xde,
    0xc0, 0xb7, 0xb6, 0x00, 0x0d, 0x37, 0x7f, 0x2b,
    0x1b, 0x18, 0xef, 0xce, 0x0d, 0xcb, 0x7c, 0x57,
    0x84, 0x38, 0xc0, 0xcb, 0x43, 0x5d, 0x44, 0x0f,
  };
  /* Agave signs the body directly.  Splice its signature into a copy
     so the whole file compares against the Agave fixture, our own
     signature is checked by fd_tower_file_de below. */
  uchar agave[ sizeof(file_buf) ];
  memcpy( agave, file_buf, (ulong)sz );
  fd_sha512_t agave_sha[ 1 ];
  fd_ed25519_sign( agave+4UL, agave+76UL, (ulong)sz-76UL, signer.pub.uc, signer.prv, agave_sha );
  uchar hash[ 32 ];
  FD_TEST( !memcmp( fd_sha256_hash( agave, (ulong)sz, hash ), expected_hash, 32UL ) );

  fd_tower_file_t out;
  FD_TEST( !fd_tower_file_de( file_buf, (ulong)sz, &signer.pub, &out ) );
  FD_TEST( out.votes_cnt==3UL );
  FD_TEST( out.votes[ 0 ].slot==100UL && out.votes[ 0 ].conf==3UL );
  FD_TEST( out.votes[ 2 ].slot==105UL && out.votes[ 2 ].conf==1UL );
  FD_TEST( out.root==90UL );
  FD_TEST( out.timestamp==1234567L );
  FD_TEST( out.timestamp_slot==105UL );
  FD_TEST( !memcmp( &out.bank_hash, &bank_hash, sizeof(fd_hash_t) ) );
  FD_TEST( !memcmp( &out.block_id,  &block_id,  sizeof(fd_hash_t) ) );

  uchar valid_buf[ FD_TOWER_FILE_MAX ];
  memcpy( valid_buf, file_buf, (ulong)sz );

  uchar bounded[ FD_TOWER_FILE_MAX ];
  for( ulong cap=0UL; cap<(ulong)sz; cap++ ) {
    fd_memset( bounded, 0xA5, sizeof(bounded) );
    FD_TEST( -1L==fd_tower_file_ser( votes, 90UL, &bank_hash, &block_id, 1234567L,
                                     &signer.pub, test_sign, &signer, bounded, cap ) );
    for( ulong i=cap; i<sizeof(bounded); i++ ) FD_TEST( bounded[ i ]==0xA5U );
  }

  file_buf[ 100 ] ^= 1;
  assert_rejected( &signer, file_buf, (ulong)sz );
  file_buf[ 100 ] ^= 1;
  fd_pubkey_t other; memset( &other, 0x77, sizeof(other) );
  FD_TEST( -1==fd_tower_file_de( file_buf, (ulong)sz, &other, &out ) );
  for( ulong trunc=0UL; trunc<(ulong)sz; trunc++ ) assert_rejected( &signer, file_buf, trunc );

  ulong const data_off         = 4UL+64UL+8UL;
  ulong const first_vote_slot  = data_off+121UL;
  ulong const second_vote_slot = first_vote_slot+12UL;
  ulong const third_vote_slot  = second_vote_slot+12UL;
  ulong const vote_root        = data_off+158UL;
  ulong const prior_voters_empty = data_off+1718UL;
  ulong const compact_root     = data_off+1747UL;
  ulong const compact_first_off = compact_root+9UL;
  ulong const compact_third_off = compact_first_off+4UL;
  ulong const compact_hash      = compact_first_off+6UL;
  ulong const compact_block_id  = compact_hash+32UL+1UL+8UL;

  /* Both block identifiers are authenticated.  The decoder returns
     the signed values, not values inferred from replay at the slot. */
  file_buf[ compact_hash ] ^= 1U;
  assert_rejected( &signer, file_buf, (ulong)sz );
  resign( &signer, file_buf, (ulong)sz );
  FD_TEST( !fd_tower_file_de( file_buf, (ulong)sz, &signer.pub, &out ) );
  FD_TEST( out.bank_hash.uc[ 0 ]==(uchar)(bank_hash.uc[ 0 ]^1U) );
  FD_TEST( !memcmp( &out.block_id, &block_id, sizeof(fd_hash_t) ) );

  memcpy( file_buf, valid_buf, (ulong)sz );
  file_buf[ compact_block_id ] ^= 1U;
  assert_rejected( &signer, file_buf, (ulong)sz );
  resign( &signer, file_buf, (ulong)sz );
  FD_TEST( !fd_tower_file_de( file_buf, (ulong)sz, &signer.pub, &out ) );
  FD_TEST( out.block_id.uc[ 0 ]==(uchar)(block_id.uc[ 0 ]^1U) );
  FD_TEST( !memcmp( &out.bank_hash, &bank_hash, sizeof(fd_hash_t) ) );

  memcpy( file_buf, valid_buf, (ulong)sz );

  FD_STORE( ulong, file_buf+second_vote_slot, 100UL );
  resign( &signer, file_buf, (ulong)sz );
  assert_rejected( &signer, file_buf, (ulong)sz );

  memcpy( file_buf, valid_buf, (ulong)sz );
  file_buf[ prior_voters_empty ] = 2U;
  resign( &signer, file_buf, (ulong)sz );
  assert_rejected( &signer, file_buf, (ulong)sz );

  memcpy( file_buf, valid_buf, (ulong)sz );
  FD_STORE( ulong, file_buf+compact_root, 91UL );
  resign( &signer, file_buf, (ulong)sz );
  assert_rejected( &signer, file_buf, (ulong)sz );

  memcpy( file_buf, valid_buf, (ulong)sz );
  FD_STORE( ulong, file_buf+vote_root, ULONG_MAX );
  FD_STORE( ulong, file_buf+compact_root, ULONG_MAX );
  file_buf[ compact_first_off ] = 100U;
  resign( &signer, file_buf, (ulong)sz );
  assert_rejected( &signer, file_buf, (ulong)sz );

  memcpy( file_buf, valid_buf, (ulong)sz );
  file_buf[ compact_first_off ] = 0U;
  resign( &signer, file_buf, (ulong)sz );
  assert_rejected( &signer, file_buf, (ulong)sz );

  memcpy( file_buf, valid_buf, (ulong)sz );
  FD_STORE( ulong, file_buf+third_vote_slot, 106UL );
  file_buf[ compact_third_off ] = 5U;
  FD_STORE( ulong, file_buf+(ulong)sz-16UL, 106UL );
  resign( &signer, file_buf, (ulong)sz );
  assert_rejected( &signer, file_buf, (ulong)sz );

  memcpy( file_buf, valid_buf, (ulong)sz );
  FD_STORE( long, file_buf+(ulong)sz-8UL, 1234568L );
  resign( &signer, file_buf, (ulong)sz );
  assert_rejected( &signer, file_buf, (ulong)sz );

  memcpy( file_buf, valid_buf, (ulong)sz );
  memmove( file_buf+compact_first_off+2UL,
           file_buf+compact_first_off+1UL,
           (ulong)sz-compact_first_off-1UL );
  file_buf[ compact_first_off     ] = 0x8AU;
  file_buf[ compact_first_off+1UL ] = 0U;
  resign( &signer, file_buf, (ulong)sz+1UL );
  assert_rejected( &signer, file_buf, (ulong)sz+1UL );

  memcpy( file_buf, valid_buf, (ulong)sz );

  fd_tower_vote_t * second_vote = fd_tower_vote_peek_index( votes, 1UL );
  second_vote->slot = 100UL;
  FD_TEST( -1L==fd_tower_file_ser( votes, 90UL, &bank_hash, &block_id, 1234567L,
                                   &signer.pub, test_sign, &signer, file_buf, sizeof(file_buf) ) );
  second_vote->slot = 101UL;
  second_vote->conf = 3UL;
  FD_TEST( -1L==fd_tower_file_ser( votes, 90UL, &bank_hash, &block_id, 1234567L,
                                   &signer.pub, test_sign, &signer, file_buf, sizeof(file_buf) ) );
  second_vote->conf = 2UL;
  FD_TEST( -1L==fd_tower_file_ser( votes, 100UL, &bank_hash, &block_id, 1234567L,
                                   &signer.pub, test_sign, &signer, file_buf, sizeof(file_buf) ) );

  fd_tower_vote_t * third_vote = fd_tower_vote_peek_index( votes, 2UL );
  third_vote->slot = 106UL;
  FD_TEST( -1L==fd_tower_file_ser( votes, 90UL, &bank_hash, &block_id, 1234567L,
                                   &signer.pub, test_sign, &signer, file_buf, sizeof(file_buf) ) );
  third_vote->slot = 105UL;

  second_vote->slot = 107UL;
  third_vote->slot  = 111UL;
  FD_TEST( -1L==fd_tower_file_ser( votes, 90UL, &bank_hash, &block_id, 1234567L,
                                   &signer.pub, test_sign, &signer, file_buf, sizeof(file_buf) ) );
  second_vote->slot = 101UL;
  third_vote->slot  = 105UL;

  long sz2 = fd_tower_file_ser( votes, ULONG_MAX, &bank_hash, &block_id, 7L,
                                &signer.pub, test_sign, &signer, file_buf, sizeof(file_buf) );
  FD_TEST( sz2>0L );
  FD_TEST( !fd_tower_file_de( file_buf, (ulong)sz2, &signer.pub, &out ) );
  FD_TEST( out.root==ULONG_MAX );

  fd_tower_vote_t * first_vote = fd_tower_vote_peek_index( votes, 0UL );
  fd_tower_vote_t * second_vote_zero_root = fd_tower_vote_peek_index( votes, 1UL );
  fd_tower_vote_t * third_vote_zero_root  = fd_tower_vote_peek_index( votes, 2UL );
  first_vote->slot = 0UL;
  second_vote_zero_root->slot = 1UL;
  third_vote_zero_root->slot  = 5UL;
  sz2 = fd_tower_file_ser( votes, ULONG_MAX, &bank_hash, &block_id, 7L,
                           &signer.pub, test_sign, &signer, file_buf, sizeof(file_buf) );
  FD_TEST( sz2>0L );
  static uchar const expected_no_root_hash[ 32 ] = {
    0xef, 0x23, 0x8c, 0x97, 0x71, 0xc0, 0xba, 0x9e,
    0x3d, 0x02, 0x9b, 0xf8, 0x48, 0x22, 0xf9, 0x8f,
    0xda, 0x63, 0x99, 0xd5, 0xd2, 0x5c, 0xc9, 0x68,
    0x0a, 0x93, 0xf5, 0x5c, 0x55, 0x9c, 0x41, 0xc0,
  };
  uchar agave2[ sizeof(file_buf) ];
  memcpy( agave2, file_buf, (ulong)sz2 );
  fd_sha512_t agave2_sha[ 1 ];
  fd_ed25519_sign( agave2+4UL, agave2+76UL, (ulong)sz2-76UL, signer.pub.uc, signer.prv, agave2_sha );
  FD_TEST( !memcmp( fd_sha256_hash( agave2, (ulong)sz2, hash ), expected_no_root_hash, 32UL ) );
  FD_TEST( !fd_tower_file_de( file_buf, (ulong)sz2, &signer.pub, &out ) );
  FD_TEST( out.root==ULONG_MAX && out.votes[0].slot==0UL );
  FD_TEST( -1L==fd_tower_file_ser( votes, 0UL, &bank_hash, &block_id, 7L,
                                   &signer.pub, test_sign, &signer, file_buf, sizeof(file_buf) ) );

  fd_tower_vote_remove_all( votes );
  for( ulong i=0UL; i<FD_TOWER_VOTE_MAX; i++ )
    fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot=100UL+i, .conf=FD_TOWER_VOTE_MAX-i } );
  sz2 = fd_tower_file_ser( votes, 99UL, &bank_hash, &block_id, 8L,
                           &signer.pub, test_sign, &signer, file_buf, sizeof(file_buf) );
  FD_TEST( sz2>0L && (ulong)sz2<=FD_TOWER_FILE_MAX );
  FD_TEST( !fd_tower_file_de( file_buf, (ulong)sz2, &signer.pub, &out ) );
  FD_TEST( out.votes_cnt==FD_TOWER_VOTE_MAX && out.root==99UL && out.timestamp==8L );
  for( ulong i=0UL; i<out.votes_cnt; i++ )
    FD_TEST( out.votes[i].slot==100UL+i && out.votes[i].conf==FD_TOWER_VOTE_MAX-i );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
