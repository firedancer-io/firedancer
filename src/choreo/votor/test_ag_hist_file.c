#include "ag_hist_file.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#define TEST_ANCHOR (1000UL)
#define SIG_SZ      (64UL)

static uchar file_buf[ AG_HIST_FILE_MAX+1UL ]; /* one spare byte for the oversized case */
static uchar valid_buf[ AG_HIST_FILE_MAX ];
static uchar bounded[ AG_HIST_FILE_MAX ];

struct signer {
  uchar       prv[ 32 ];
  fd_pubkey_t pub;
};

typedef struct signer signer_t;

/* test_sign does what the votor tile does through the keyguard, hash
   the body under the prefix and sign the 48 byte message */

static void
test_sign( void *        _signer,
           uchar         sig[ 64 ],
           uchar const * msg,
           ulong         msg_sz ) {
  signer_t *  signer = (signer_t *)_signer;
  fd_sha512_t sha[ 1 ];
  uchar       m[ FD_KEYGUARD_VOTOR_HIST_MSG_SZ ];
  ag_hist_file_sign_msg( msg, msg_sz, m );
  fd_ed25519_sign( sig, m, sizeof(m), signer->pub.uc, signer->prv, sha );
}

static void
resign( signer_t * signer,
        uchar *    buf,
        ulong      sz ) {
  test_sign( signer, buf+sz-SIG_SZ, buf, sz-SIG_SZ );
}

static void
fill_hash( ag_block_hash_t hash,
           uchar           seed ) {
  for( ulong i=0UL; i<sizeof(ag_block_hash_t); i++ ) hash[ i ] = (uchar)( seed+i );
}

static int
hist_eq( ag_hist_t const * a,
         ag_hist_t const * b ) {
  if( a->anchor!=b->anchor || a->last_leader_slot!=b->last_leader_slot || a->rec_cnt!=b->rec_cnt ) return 0;
  for( ulong i=0UL; i<a->rec_cnt; i++ ) {
    if( a->rec[ i ].slot!=b->rec[ i ].slot || a->rec[ i ].flags!=b->rec[ i ].flags ) return 0;
    if( ( a->rec[ i ].flags & AG_HIST_FLAG_VOTED_NOTAR ) && !fd_memeq( a->rec[ i ].notar_hash, b->rec[ i ].notar_hash, sizeof(ag_block_hash_t) ) ) return 0;
  }
  return 1;
}

/* assert_rejected checks the decoder refuses buf and leaves out and
   the timestamp untouched */

static void
assert_rejected( signer_t const * signer,
                 uchar const *    buf,
                 ulong            sz ) {
  ag_hist_t out; fd_memset( &out, 0xA5, sizeof(out) );
  ag_hist_t ref; fd_memset( &ref, 0xA5, sizeof(ref) );
  long      timestamp = 42L;
  FD_TEST( -1==ag_hist_file_de( buf, sz, &signer->pub, &out, &timestamp ) );
  FD_TEST( fd_memeq( &out, &ref, sizeof(out) ) );
  FD_TEST( timestamp==42L );
}

/* round_trip writes hist, decodes it back and checks the history and
   timestamp survived, returning the file size */

static ulong
round_trip( signer_t *        signer,
            ag_hist_t const * hist,
            long              now_secs,
            uchar *           buf ) {
  long sz = ag_hist_file_ser( hist, &signer->pub, now_secs, test_sign, signer, buf, AG_HIST_FILE_MAX );
  FD_TEST( sz>0L && (ulong)sz<=AG_HIST_FILE_MAX );

  ag_hist_t out; fd_memset( &out, 0xA5, sizeof(out) );
  long      timestamp = 0L;
  FD_TEST( !ag_hist_file_de( buf, (ulong)sz, &signer->pub, &out, &timestamp ) );
  FD_TEST( hist_eq( &out, hist ) );
  FD_TEST( timestamp==now_secs );
  FD_TEST( !ag_hist_file_de( buf, (ulong)sz, &signer->pub, &out, NULL ) );
  return (ulong)sz;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  signer_t    signer;
  fd_sha512_t sha[ 1 ];
  fd_memset( signer.prv, 0x42, 32UL );
  fd_ed25519_public_from_private( signer.pub.uc, signer.prv, sha );

  ulong     first = ag_hist_first_slot( TEST_ANCHOR );
  ag_hist_t hist  = { .anchor = TEST_ANCHOR, .last_leader_slot = first+4UL, .rec_cnt = 3UL };
  hist.rec[ 0 ] = (ag_hist_rec_t){ .slot = first,     .flags = AG_HIST_FLAG_VOTED | AG_HIST_FLAG_VOTED_NOTAR };
  hist.rec[ 1 ] = (ag_hist_rec_t){ .slot = first+1UL, .flags = AG_HIST_FLAG_VOTED | AG_HIST_FLAG_BAD_WINDOW  };
  hist.rec[ 2 ] = (ag_hist_rec_t){ .slot = first+5UL, .flags = AG_HIST_FLAG_VOTED | AG_HIST_FLAG_RETIRED     };
  fill_hash( hist.rec[ 0 ].notar_hash, 0x10 );

  ulong sz = round_trip( &signer, &hist, 1234567L, file_buf );
  FD_TEST( sz==AG_HIST_FILE_HDR_SZ+AG_HIST_HDR_SZ+3UL*AG_HIST_REC_MIN_SZ+sizeof(ag_block_hash_t)+SIG_SZ );
  FD_TEST( FD_LOAD( uint, file_buf      )==AG_HIST_FILE_MAGIC   );
  FD_TEST( FD_LOAD( uint, file_buf+4UL  )==AG_HIST_FILE_VERSION );
  FD_TEST( FD_LOAD( long, file_buf+40UL )==1234567L             );
  FD_TEST( fd_memeq( file_buf+8UL, signer.pub.uc, 32UL ) );
  fd_memcpy( valid_buf, file_buf, sz );

  /* wrong identity */
  ag_hist_t   out;
  fd_pubkey_t other; fd_memset( &other, 0x77, sizeof(other) );
  FD_TEST( -1==ag_hist_file_de( file_buf, sz, &other, &out, NULL ) );

  /* one flipped byte in the magic, version, pubkey, history, first
     and last signature byte, each fails */
  ulong const tamper_off[ 6 ] = { 0UL, 4UL, 8UL, AG_HIST_FILE_HDR_SZ, sz-SIG_SZ, sz-1UL };
  for( ulong i=0UL; i<6UL; i++ ) {
    file_buf[ tamper_off[ i ] ] ^= 1;
    assert_rejected( &signer, file_buf, sz );
    file_buf[ tamper_off[ i ] ] ^= 1;
  }

  /* magic, version and pubkey are checked on their own, a fresh
     signature does not rescue them */
  for( ulong i=0UL; i<3UL; i++ ) {
    file_buf[ tamper_off[ i ] ] ^= 1;
    resign( &signer, file_buf, sz );
    assert_rejected( &signer, file_buf, sz );
    fd_memcpy( file_buf, valid_buf, sz );
  }

  /* a resigned history the decoder rejects, the first record loses
     VOTED but keeps its hash so the size does not change */
  file_buf[ AG_HIST_FILE_HDR_SZ+AG_HIST_HDR_SZ+sizeof(ulong) ] = AG_HIST_FLAG_VOTED_NOTAR;
  resign( &signer, file_buf, sz );
  assert_rejected( &signer, file_buf, sz );
  fd_memcpy( file_buf, valid_buf, sz );

  /* a resigned timestamp change is accepted, it is part of the body */
  FD_STORE( long, file_buf+40UL, 7L );
  resign( &signer, file_buf, sz );
  long timestamp = 0L;
  FD_TEST( !ag_hist_file_de( file_buf, sz, &signer.pub, &out, &timestamp ) );
  FD_TEST( timestamp==7L && hist_eq( &out, &hist ) );
  fd_memcpy( file_buf, valid_buf, sz );

  /* truncated and oversized, with and without a matching signature */
  for( ulong trunc=0UL; trunc<sz; trunc++ ) assert_rejected( &signer, file_buf, trunc );
  file_buf[ sz ] = 0;
  assert_rejected( &signer, file_buf, sz+1UL );
  resign( &signer, file_buf, sz+1UL );
  assert_rejected( &signer, file_buf, sz+1UL );
  fd_memcpy( file_buf, valid_buf, sz );
  assert_rejected( &signer, file_buf, AG_HIST_FILE_MAX+1UL );

  /* a buffer too small for the whole file gets nothing written */
  for( ulong cap=0UL; cap<sz; cap++ ) {
    fd_memset( bounded, 0xA5, sizeof(bounded) );
    FD_TEST( -1L==ag_hist_file_ser( &hist, &signer.pub, 1234567L, test_sign, &signer, bounded, cap ) );
    for( ulong i=0UL; i<sizeof(bounded); i++ ) FD_TEST( bounded[ i ]==0xA5U );
  }
  FD_TEST( (long)sz==ag_hist_file_ser( &hist, &signer.pub, 1234567L, test_sign, &signer, bounded, sz ) );
  FD_TEST( fd_memeq( bounded, valid_buf, sz ) );

  /* a history ag_hist_ser refuses is refused here too */
  hist.anchor = ULONG_MAX;
  FD_TEST( -1L==ag_hist_file_ser( &hist, &signer.pub, 1234567L, test_sign, &signer, file_buf, AG_HIST_FILE_MAX ) );
  hist.anchor = TEST_ANCHOR;

  /* an empty history is the smallest file */
  ag_hist_t empty = { .anchor = TEST_ANCHOR, .last_leader_slot = ULONG_MAX, .rec_cnt = 0UL };
  FD_TEST( round_trip( &signer, &empty, 0L, file_buf )==AG_HIST_FILE_HDR_SZ+AG_HIST_HDR_SZ+SIG_SZ );

  /* a full history of notar records is the largest */
  static ag_hist_t full;
  full.anchor           = TEST_ANCHOR;
  full.last_leader_slot = first+AG_HIST_MAX-4UL;
  full.rec_cnt          = AG_HIST_MAX;
  for( ulong i=0UL; i<AG_HIST_MAX; i++ ) {
    full.rec[ i ].slot  = first+i;
    full.rec[ i ].flags = AG_HIST_FLAG_VOTED | AG_HIST_FLAG_VOTED_NOTAR;
    fill_hash( full.rec[ i ].notar_hash, (uchar)i );
  }
  FD_TEST( round_trip( &signer, &full, LONG_MAX, file_buf )==AG_HIST_FILE_HDR_SZ+AG_HIST_SER_MAX+SIG_SZ );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
