#include "../fd_ballet.h"
#include "fd_ed25519_verifier.h"
#include "../txn/fd_txn.h"
#include <stdlib.h>

/* fd_ed25519_verify is the oracle for every form; the signer cache
   does not change results, so each verifier form is checked with the
   default cache and with the cache off against the same inputs. */

#define KEY_CNT   (16UL)
#define ITEM_CNT  (64UL)
#define TXN_CNT   (64UL)
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

/* a hand-built legacy transaction: sig_cnt, sigs, header, account
   count, accounts, blockhash, zero instructions; the signers are the
   first accounts */

struct txn {
  uchar    payload[ FD_TXN_MTU_V0 ];
  ulong    payload_sz;
  uchar    txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_txn_t * txn;
  int      expected;                 /* oracle verdict */
  int      sig_ok[ FD_TXN_SIG_MAX ]; /* oracle per signature */
};
typedef struct txn txn_t;

static txn_t txns[ TXN_CNT ];

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
make_txn( fd_rng_t * rng,
          txn_t *    t ) {
  ulong sig_cnt = 1UL + fd_rng_ulong_roll( rng, FD_TXN_SIG_MAX );
  ulong fixed   = 1UL + 64UL*sig_cnt + 3UL + 1UL + 32UL + 1UL;
  ulong extra   = fd_ulong_min( fd_rng_ulong_roll( rng, 3UL ), (FD_TXN_MTU_V0-fixed)/32UL - sig_cnt );
  ulong acct_cnt = sig_cnt + extra;
  ulong signer[ FD_TXN_SIG_MAX ];

  uchar * p = t->payload;
  *(p++) = (uchar)sig_cnt;
  uchar * sigs = p; p += 64UL*sig_cnt;
  uchar * msg  = p;
  *(p++) = (uchar)sig_cnt; *(p++) = 0; *(p++) = 0;
  *(p++) = (uchar)acct_cnt;
  uchar * accts = p;
  for( ulong a=0UL; a<acct_cnt; a++ ) {
    ulong k = fd_rng_ulong_roll( rng, KEY_CNT );
    if( a<sig_cnt ) signer[ a ] = k;
    memcpy( p, pub[ k ], 32UL ); p += 32UL;
  }
  for( ulong b=0UL; b<32UL; b++ ) *(p++) = fd_rng_uchar( rng );
  *(p++) = 0;
  t->payload_sz = (ulong)(p-t->payload);
  ulong msg_sz = (ulong)(p-msg);

  for( ulong j=0UL; j<sig_cnt; j++ ) fd_ed25519_sign( sigs+64UL*j, msg, msg_sz, pub[ signer[ j ] ], priv[ signer[ j ] ], sha );
  /* at most one corruption per txn, after signing, so the message of
     the other signatures stays what they signed only when the
     corruption is not of the message */
  if( fd_rng_uint( rng ) % 4U == 0U ) {
    ulong j = fd_rng_ulong_roll( rng, sig_cnt );
    corrupt( rng, sigs+64UL*j, accts+32UL*j, msg, msg_sz );
  }

  FD_TEST( fd_txn_parse( t->payload, t->payload_sz, t->txn_mem, NULL ) );
  t->txn = (fd_txn_t *)t->txn_mem;
  FD_TEST( t->txn->signature_cnt==sig_cnt );

  int expected = FD_ED25519_SUCCESS;
  for( ulong j=0UL; j<sig_cnt; j++ ) {
    int r = fd_ed25519_verify( msg, msg_sz, sigs+64UL*j, accts+32UL*j, sha );
    t->sig_ok[ j ] = (r==FD_ED25519_SUCCESS);
    if( r==FD_ED25519_SUCCESS ) continue;
    if( expected==FD_ED25519_SUCCESS || expected==FD_ED25519_ERR_MSG ) {
      if( r!=FD_ED25519_ERR_MSG ) expected = r;
      else                        expected = FD_ED25519_ERR_MSG;
    }
  }
  t->expected = expected;
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

  /* batch of random size, including empty and longer than a run */
  for( ulong rep=0UL; rep<64UL; rep++ ) {
    ulong cnt = fd_rng_ulong_roll( rng, 2UL*FD_ED25519_VERIFIER_SIG_MAX+2UL );
    uchar const * msgs[ 2UL*FD_ED25519_VERIFIER_SIG_MAX+2UL ]; ulong msg_szs[ 2UL*FD_ED25519_VERIFIER_SIG_MAX+2UL ];
    uchar const * sigs[ 2UL*FD_ED25519_VERIFIER_SIG_MAX+2UL ]; uchar const * pubs[ 2UL*FD_ED25519_VERIFIER_SIG_MAX+2UL ];
    int results[ 2UL*FD_ED25519_VERIFIER_SIG_MAX+2UL ];
    for( ulong j=0UL; j<cnt; j++ ) {
      item_t * it = items + fd_rng_ulong_roll( rng, ITEM_CNT );
      msgs[ j ] = it->msg; msg_szs[ j ] = it->msg_sz; sigs[ j ] = it->sig; pubs[ j ] = it->pub;
      results[ j ] = 12345;
    }
    fd_ed25519_verifier_verify_batch( v, msgs, msg_szs, sigs, pubs, results, cnt );
    for( ulong j=0UL; j<cnt; j++ ) FD_TEST( results[ j ]==fd_ed25519_verify( msgs[ j ], msg_szs[ j ], sigs[ j ], pubs[ j ], sha ) );
  }

  /* transactions, one at a time and in random runs */
  for( ulong rep=0UL; rep<2UL; rep++ ) {
    for( ulong i=0UL; i<TXN_CNT; i++ ) FD_TEST( fd_ed25519_verifier_verify_txn( v, txns[ i ].txn, txns[ i ].payload, txns[ i ].payload_sz )==txns[ i ].expected );
  }
  for( ulong rep=0UL; rep<64UL; rep++ ) {
    ulong cnt = fd_rng_ulong_roll( rng, 33UL );
    fd_txn_t const * ts[ 32 ]; uchar const * ps[ 32 ]; ulong szs[ 32 ]; ulong idx[ 32 ]; int results[ 33 ];
    for( ulong i=0UL; i<cnt; i++ ) {
      idx[ i ] = fd_rng_ulong_roll( rng, TXN_CNT );
      txn_t * t = txns + idx[ i ];
      ts[ i ] = t->txn; ps[ i ] = t->payload; szs[ i ] = t->payload_sz;
    }
    results[ cnt ] = 12345;
    fd_ed25519_verifier_verify_txns( v, ts, ps, szs, results, cnt );
    for( ulong i=0UL; i<cnt; i++ ) FD_TEST( results[ i ]==txns[ idx[ i ] ].expected );
    FD_TEST( results[ cnt ]==12345 );
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

/* The batch verifier is checked against a model of its contract with
   group size G: signatures are appended to a pending list and every
   time it holds G they are verified together; G is 8 on the builds
   that delay and 1 on the others (every call verifies at once).  The
   model is learned from the first call. */

static void
test_batch_verifier( fd_rng_t * rng,
                     ulong      cache_ent_cnt ) {
  ulong fp = fd_ed25519_batch_verifier_footprint( cache_ent_cnt );
  FD_TEST( fp );
  void * mem = aligned_alloc( fd_ed25519_batch_verifier_align(), fp );
  FD_TEST( mem );
  fd_ed25519_batch_verifier_t * bv = fd_ed25519_batch_verifier_join( fd_ed25519_batch_verifier_new( mem, cache_ent_cnt, fd_rng_ulong( rng ) ) );
  FD_TEST( bv );

  ulong G = 0UL;
  for( ulong i=0UL; i<TXN_CNT && !G; i++ ) {
    txn_t * t = txns+i;
    if( t->txn->signature_cnt!=1UL ) continue;
    int rc = fd_ed25519_batch_verifier_verify_txn( bv, t->txn, t->payload, t->payload_sz );
    ulong pending = fd_ed25519_batch_verifier_pending_cnt( bv );
    FD_TEST( (rc==1 && pending==1UL) || (rc!=1 && pending==0UL) );
    G = rc==1 ? FD_ED25519_BATCH_VERIFIER_GROUP : 1UL;
    fd_ed25519_batch_verifier_clear( bv );
    FD_TEST( !fd_ed25519_batch_verifier_pending_cnt( bv ) );
  }
  FD_TEST( G );
  FD_LOG_NOTICE(( "batch verifier group %lu", G ));

  int   pend_ok[ FD_ED25519_BATCH_VERIFIER_GROUP ];
  ulong pend_cnt = 0UL;
  uchar scratch[ FD_TXN_MTU_V0 ];
  ulong delayed = 0UL, cuts = 0UL, fails = 0UL;

  for( ulong step=0UL; step<4096UL; step++ ) {
    uint op = fd_rng_uint( rng ) % 64U;
    if( op==0U ) {
      int rc = fd_ed25519_batch_verifier_flush( bv );
      int expected = 1;
      if( pend_cnt ) { expected = 0; for( ulong l=0UL; l<pend_cnt; l++ ) if( !pend_ok[ l ] ) expected = -1; }
      FD_TEST( rc==expected );
      pend_cnt = 0UL;
      FD_TEST( !fd_ed25519_batch_verifier_pending_cnt( bv ) );
      continue;
    }
    if( op==1U ) {
      fd_ed25519_batch_verifier_clear( bv );
      pend_cnt = 0UL;
      FD_TEST( !fd_ed25519_batch_verifier_pending_cnt( bv ) );
      continue;
    }

    txn_t * t = txns + fd_rng_ulong_roll( rng, TXN_CNT );
    /* the payload passed is a copy that is scribbled after the call:
       the verifier must have copied what it keeps pending */
    memcpy( scratch, t->payload, t->payload_sz );
    int rc = fd_ed25519_batch_verifier_verify_txn( bv, t->txn, scratch, t->payload_sz );
    memset( scratch, 0x5a, t->payload_sz );

    int expected = 1;
    for( ulong j=0UL; j<t->txn->signature_cnt; j++ ) {
      pend_ok[ pend_cnt++ ] = t->sig_ok[ j ];
      if( pend_cnt<G ) continue;
      int cut_ok = 1;
      for( ulong l=0UL; l<pend_cnt; l++ ) cut_ok &= pend_ok[ l ];
      expected = (expected==-1 || !cut_ok) ? -1 : 0;
      pend_cnt = 0UL;
      cuts++;
    }
    if( rc!=expected ) FD_LOG_ERR(( "step %lu: sig_cnt %lu verdict %d: rc %d expected %d", step, (ulong)t->txn->signature_cnt, t->expected, rc, expected ));
    FD_TEST( fd_ed25519_batch_verifier_pending_cnt( bv )==pend_cnt );
    FD_TEST( pend_cnt<FD_ED25519_BATCH_VERIFIER_GROUP );
    delayed += (rc==1); fails += (rc==-1);
  }
  FD_LOG_NOTICE(( "batch verifier: %lu delayed, %lu cuts, %lu failed calls", delayed, cuts, fails ));
  FD_TEST( cuts && fails );
  if( G>1UL ) FD_TEST( delayed );

  FD_TEST( fd_ed25519_batch_verifier_delete( fd_ed25519_batch_verifier_leave( bv ) )==mem );
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
  for( ulong i=0UL; i<TXN_CNT; i++ ) make_txn( rng, txns+i );

  FD_TEST( !fd_ed25519_verifier_footprint( 3UL ) );
  FD_TEST( !fd_ed25519_verifier_footprint( 1000UL ) );
  FD_TEST( !fd_ed25519_batch_verifier_footprint( 1000UL ) );
  FD_TEST( fd_ed25519_verifier_footprint( FD_ED25519_VERIFIER_CACHE_OFF )<fd_ed25519_verifier_footprint( FD_ED25519_VERIFIER_CACHE_DEFAULT ) );

  test_verifier( rng, FD_ED25519_VERIFIER_CACHE_DEFAULT );
  test_verifier( rng, FD_ED25519_VERIFIER_CACHE_OFF );
  test_verifier( rng, 16UL );
  test_batch_verifier( rng, FD_ED25519_VERIFIER_CACHE_DEFAULT );
  test_batch_verifier( rng, FD_ED25519_VERIFIER_CACHE_OFF );

  fd_sha512_delete( fd_sha512_leave( sha ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
