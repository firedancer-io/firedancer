#include "../fd_ballet.h"
#include "fd_ed25519_verifier.h"
#include <stdlib.h>

/* fd_ed25519_verify is the oracle for every form; the signer cache
   does not change results, so each verifier form is checked with the
   default cache, with the cache off and with a small cache that
   thrashes, against the same inputs. */

#define KEY_CNT   (16UL)
#define ITEM_CNT  (64UL)
#define MSG_MAX   (300UL)

static uchar  pub [ KEY_CNT ][ 32 ];
static uchar  priv[ KEY_CNT ][ 32 ];

/* a signed item: a message, a signature and a public key, possibly
   corrupted so that the oracle returns each error code */

struct item {
  uchar msg[ MSG_MAX ];
  ulong msg_sz;
  uchar sig[ 64 ];
  uchar pub[ 32 ];
};
typedef struct item item_t;

static item_t items[ ITEM_CNT ];

static fd_sha512_t _sha[ 1 ];
static fd_sha512_t * sha;

static void
corrupt( fd_rng_t * rng,
         uchar      sig[ 64 ],
         uchar      pubkey[ 32 ],
         uchar      msg[],
         ulong      msg_sz ) {
  switch( fd_rng_uint( rng ) % 8U ) {
  case 0: sig[ 63 ] |= 0x80; break;                                 /* S out of range */
  case 1: memset( pubkey, 0xff, 32UL ); break;                        /* A does not decode */
  case 2: sig[ fd_rng_ulong_roll( rng, 32UL ) ] ^= (uchar)(1U<<(fd_rng_uint( rng )&7U)); break; /* R */
  case 3: if( msg_sz ) msg[ fd_rng_ulong_roll( rng, msg_sz ) ]++; break;
  default: break;                                                   /* valid */
  }
}

static void
make_items( fd_rng_t * rng ) {
  for( ulong i=0UL; i<ITEM_CNT; i++ ) {
    item_t * it = items+i;
    ulong k = fd_rng_ulong_roll( rng, KEY_CNT );
    it->msg_sz = fd_rng_ulong_roll( rng, MSG_MAX+1UL );
    for( ulong b=0UL; b<it->msg_sz; b++ ) it->msg[ b ] = fd_rng_uchar( rng );
    memcpy( it->pub, pub[ k ], 32UL );
    fd_ed25519_sign( it->sig, it->msg, it->msg_sz, pub[ k ], priv[ k ], sha );
    corrupt( rng, it->sig, it->pub, it->msg, it->msg_sz );
  }
}

static void
test_verifier( fd_rng_t * rng,
               ulong      cache_ent_cnt ) {
  ulong fp = fd_ed25519_verifier_footprint( cache_ent_cnt );
  FD_TEST( fp );
  void * mem = aligned_alloc( fd_ed25519_verifier_align(), fp );
  FD_TEST( mem );
  fd_ed25519_verifier_t * v = fd_ed25519_verifier_join( fd_ed25519_verifier_new( mem, cache_ent_cnt, fd_rng_ulong( rng ) ) );
  FD_TEST( v );

  /* single */
  for( ulong rep=0UL; rep<4UL; rep++ ) {
    for( ulong i=0UL; i<ITEM_CNT; i++ ) {
      item_t * it = items+i;
      int expected = fd_ed25519_verify( it->msg, it->msg_sz, it->sig, it->pub, sha );
      FD_TEST( fd_ed25519_verifier_verify( v, it->msg, it->msg_sz, it->sig, it->pub )==expected );
    }
  }

  /* sets of random size, mixing keys so that both hits and misses land
     in the same call */
  for( ulong rep=0UL; rep<64UL; rep++ ) {
    ulong cnt = 1UL + fd_rng_ulong_roll( rng, FD_ED25519_VERIFIER_SIG_MAX );
    uchar const * msgs[ FD_ED25519_VERIFIER_SIG_MAX ]; ulong msg_szs[ FD_ED25519_VERIFIER_SIG_MAX ];
    uchar const * sigs[ FD_ED25519_VERIFIER_SIG_MAX ]; uchar const * pubs[ FD_ED25519_VERIFIER_SIG_MAX ];
    int results[ FD_ED25519_VERIFIER_SIG_MAX ];
    for( ulong j=0UL; j<cnt; j++ ) {
      item_t * it = items + fd_rng_ulong_roll( rng, ITEM_CNT );
      msgs[ j ] = it->msg; msg_szs[ j ] = it->msg_sz; sigs[ j ] = it->sig; pubs[ j ] = it->pub;
      results[ j ] = 12345;
    }
    fd_ed25519_verifier_verify_sigs( v, msgs, msg_szs, sigs, pubs, results, cnt );
    for( ulong j=0UL; j<cnt; j++ ) FD_TEST( results[ j ]==fd_ed25519_verify( msgs[ j ], msg_szs[ j ], sigs[ j ], pubs[ j ], sha ) );
  }

  if( cache_ent_cnt==FD_ED25519_VERIFIER_CACHE_OFF ) {
    FD_TEST( !fd_ed25519_verifier_hit_cnt( v ) && !fd_ed25519_verifier_miss_cnt( v ) && !fd_ed25519_verifier_insert_cnt( v ) );
  } else {
    FD_TEST( fd_ed25519_verifier_hit_cnt( v )+fd_ed25519_verifier_miss_cnt( v ) );
    FD_LOG_NOTICE(( "cache %lu: hit %lu miss %lu insert %lu", cache_ent_cnt,
                    fd_ed25519_verifier_hit_cnt( v ), fd_ed25519_verifier_miss_cnt( v ), fd_ed25519_verifier_insert_cnt( v ) ));
  }

  FD_TEST( fd_ed25519_verifier_delete( fd_ed25519_verifier_leave( v ) )==mem );
  free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[ 1 ]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  sha = fd_sha512_join( fd_sha512_new( _sha ) );

  for( ulong k=0UL; k<KEY_CNT; k++ ) {
    for( ulong b=0UL; b<32UL; b++ ) priv[ k ][ b ] = fd_rng_uchar( rng );
    fd_ed25519_public_from_private( pub[ k ], priv[ k ], sha );
  }
  make_items( rng );

  FD_TEST( !fd_ed25519_verifier_footprint( 3UL ) );
  FD_TEST( !fd_ed25519_verifier_footprint( 1000UL ) );
  FD_TEST( fd_ed25519_verifier_footprint( FD_ED25519_VERIFIER_CACHE_OFF )<fd_ed25519_verifier_footprint( FD_ED25519_VERIFIER_CACHE_DEFAULT ) );

  test_verifier( rng, FD_ED25519_VERIFIER_CACHE_DEFAULT );
  test_verifier( rng, FD_ED25519_VERIFIER_CACHE_OFF );
  test_verifier( rng, 16UL );

  fd_sha512_delete( fd_sha512_leave( sha ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
