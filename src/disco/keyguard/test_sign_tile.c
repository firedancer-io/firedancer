#include "fd_sign_tile.c"
#include "fd_keyguard_client.h"
#include "../../util/sandbox/fd_sandbox_private.h"
#include "../../waltz/tls/fd_tls.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_DEPTH (128UL)

static uchar request_mcache_mem [ FD_MCACHE_FOOTPRINT( TEST_DEPTH, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar response_mcache_mem[ FD_MCACHE_FOOTPRINT( TEST_DEPTH, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar request_data [ FD_KEYGUARD_SIGN_REQ_MTU ] __attribute__((aligned(FD_CHUNK_ALIGN)));
static uchar response_data[ FD_KEYGUARD_BLS_SIG_SZ   ] __attribute__((aligned(FD_CHUNK_ALIGN)));

static fd_sign_ctx_t         ctx;
static fd_keyguard_client_t  client;
static fd_keyguard_bls_key_t  keys[ FD_KEYGUARD_BLS_KEY_MAX ];
static fd_stem_context_t     stem;
static uchar                identity_key[ 64 ];
static ulong                response_seq;
static ulong                response_depth = TEST_DEPTH;
static int                  out_reliable;

static void
setup( void ) {
  memset( &ctx, 0, sizeof(ctx) );
  memset( &client, 0, sizeof(client) );
  memset( &stem, 0, sizeof(stem) );
  memset( keys, 0, sizeof(keys) );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx.sha512 ) ) );
  memset( identity_key, 0x11, 32UL );
  fd_ed25519_public_from_private( identity_key+32UL, identity_key, ctx.sha512 );
  ctx.private_key = identity_key;
  ctx.public_key  = identity_key+32UL;
  ctx.bls_keys    = keys;
  derive_fields( &ctx );
  FD_TEST( fd_histf_join( fd_histf_new( ctx.sign_duration, FD_MHIST_SECONDS_MIN( SIGN, SIGN_DURATION_SECONDS ),
                                                         FD_MHIST_SECONDS_MAX( SIGN, SIGN_DURATION_SECONDS ) ) ) );

  client.request        = fd_mcache_join( fd_mcache_new( request_mcache_mem, TEST_DEPTH, 0UL, 0UL ) );
  client.response       = fd_mcache_join( fd_mcache_new( response_mcache_mem, TEST_DEPTH, 0UL, 0UL ) );
  FD_TEST( client.request && client.response );
  client.request_depth  = TEST_DEPTH;
  client.response_depth = TEST_DEPTH;
  client.request_mem    = (fd_wksp_t *)request_data;
  client.response_mem   = (fd_wksp_t *)response_data;
  client.request_mtu    = FD_KEYGUARD_SIGN_REQ_MTU;
  client.response_mtu   = FD_KEYGUARD_BLS_SIG_SZ;
  ctx.in[0].role        = FD_KEYGUARD_ROLE_VOTOR;
  ctx.in[0].mem         = client.request_mem;
  ctx.in[0].mtu         = client.request_mtu;
  ctx.out[0].out_mem    = client.response_mem;

  /* One request at a time, so each data ring reuses chunk zero. */
  response_seq      = 0UL;
  stem.mcaches      = &client.response;
  stem.seqs         = &response_seq;
  stem.depths       = &response_depth;
  stem.out_reliable = &out_reliable;
}

static void *
sign_requests( void * arg ) {
  ulong cnt = *(ulong *)arg;
  for( ulong seq=0UL; seq<cnt; seq++ ) {
    fd_frag_meta_t const * line = client.request+fd_mcache_line_idx( seq, TEST_DEPTH );
    while( fd_frag_meta_seq_query( line )!=seq ) FD_SPIN_PAUSE();
    FD_COMPILER_MFENCE();
    ulong sig   = line->sig;
    ulong chunk = line->chunk;
    ulong sz    = line->sz;
    during_frag( &ctx, 0UL, seq, sig, chunk, sz, 0UL );
    after_frag( &ctx, 0UL, seq, sig, sz, 0UL, 0UL, &stem );
  }
  return NULL;
}

static void
test_bls_request_signing( void ) {
  setup();

  /* Generated independently by Agave 4.1.0 `solana-keygen
     bls_pubkey`.  The keypair is private seed followed by Ed25519
     public key. */
  static uchar const agave_keypair[ 64 ] = {
    149, 138, 120, 246, 229, 211,  77, 206, 163,  78,  57, 172, 248,  93, 205, 236,
     20,  90,   0,   7, 157, 121,  25,  54, 212, 189,  91,  26, 164, 253, 110, 203,
     51, 129, 127, 165, 142,   4, 248, 195,  91,  93,  33,  19,  91, 130, 175,   9,
    229, 142, 180, 156,  23, 173, 190, 249, 207,   5, 181,  31, 251,  76,   2, 208
  };
  static uchar const expected_public_key[ FD_KEYGUARD_BLS_PUBKEY_SZ ] = {
    149, 157, 254, 148, 170,  68,   3,  78,  50,  10,   2, 167,  49,  36, 104, 157,
    220, 152, 181, 228,  47, 146, 210, 186, 254, 247,  17,  30, 130, 234, 224, 119,
    213, 125,  40, 244,  22,  34,  81,   8, 254, 105, 239,  43, 186, 178, 113,   1
  };

  fd_keyswitch_t identity_switch[1];
  fd_keyswitch_t voter_switch[1];
  ctx.keyswitch    = fd_keyswitch_join( fd_keyswitch_new( identity_switch, FD_KEYSWITCH_STATE_UNLOCKED ) );
  ctx.av_keyswitch = fd_keyswitch_join( fd_keyswitch_new( voter_switch, FD_KEYSWITCH_STATE_SWITCH_PENDING ) );
  FD_TEST( ctx.keyswitch && ctx.av_keyswitch );
  memcpy( voter_switch->bytes, agave_keypair, sizeof(agave_keypair) );
  voter_switch->param = FD_KEYSWITCH_PARAM_AV_ADD;
  during_housekeeping( &ctx );
  FD_TEST( fd_keyswitch_state_query( voter_switch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx.authorized_voters_cnt==1UL );
  FD_TEST( !memcmp( keys[1].public_key, expected_public_key, sizeof(expected_public_key) ) );

  fd_bls_pub_t public_keys[2];
  FD_TEST( !fd_bls_pub_de( &public_keys[0], keys[0].public_key, FD_KEYGUARD_BLS_PUBKEY_SZ ) );
  FD_TEST( !fd_bls_pub_de( &public_keys[1], expected_public_key, sizeof(expected_public_key) ) );

  ulong     request_cnt = 12UL;
  pthread_t signer;
  FD_TEST( !pthread_create( &signer, NULL, sign_requests, &request_cnt ) );
  for( ulong i=0UL; i<2UL; i++ ) {
    ulong authority_idx = i ? 0UL : ULONG_MAX;
    uchar public_key[ FD_KEYGUARD_BLS_PUBKEY_SZ+16UL ];
    memset( public_key, 0xA5, sizeof(public_key) );
    fd_keyguard_client_bls_pubkey( &client, public_key, authority_idx );
    FD_TEST( FD_LOAD( ulong, request_data )==authority_idx );
    fd_frag_meta_t const * response = client.response+fd_mcache_line_idx( client.response_seq-1UL, TEST_DEPTH );
    FD_TEST( response->sig==FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY && response->sz==FD_KEYGUARD_BLS_PUBKEY_SZ );
    FD_TEST( !memcmp( public_key, keys[i].public_key, FD_KEYGUARD_BLS_PUBKEY_SZ ) );
    for( ulong j=FD_KEYGUARD_BLS_PUBKEY_SZ; j<sizeof(public_key); j++ ) FD_TEST( public_key[j]==0xA5 );
    for( uchar tag=1U; tag<=5U; tag++ ) {
      uchar payload[43];
      for( ulong j=0UL; j<sizeof(payload); j++ ) payload[j] = (uchar)(0x20UL+j);
      payload[0] = tag;
      ulong payload_sz = ( tag==1U || tag==4U ) ? 43UL : 11UL;
      uchar signature[ FD_KEYGUARD_BLS_SIG_SZ ];
      fd_keyguard_client_ag_vote_sign( &client, signature, authority_idx, payload, payload_sz );
      FD_TEST( !memcmp( request_data, payload, payload_sz ) );
      fd_bls_sig_t sig[1];
      FD_TEST( !fd_bls_sig_de( sig, signature ) );
      FD_TEST(  fd_bls_agg_verify( payload, payload_sz, &public_keys[i], sig ) );
      FD_TEST( !fd_bls_agg_verify( payload, payload_sz, &public_keys[1UL-i], sig ) );
    }
  }
  FD_TEST( !pthread_join( signer, NULL ) );

  fd_keyguard_bls_key_t identity_bls_key = keys[0];
  voter_switch->param = FD_KEYSWITCH_PARAM_AV_CLEAR;
  fd_keyswitch_state( voter_switch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( !ctx.authorized_voters_cnt );
  FD_TEST( !memcmp( &keys[0], &identity_bls_key, sizeof(identity_bls_key) ) );
  for( ulong i=sizeof(keys[0]); i<sizeof(keys); i++ ) FD_TEST( !((uchar *)keys)[i] );
}

static void
test_ed25519_request_signing( void ) {
  setup();
  ctx.in[0].role      = FD_KEYGUARD_ROLE_LEADER;
  client.response_mtu = FD_ED25519_SIG_SZ;
  uchar payload[32];
  memset( payload, 0x42, sizeof(payload) );
  uchar signature[ FD_ED25519_SIG_SZ+16UL ];
  memset( signature, 0xA5, sizeof(signature) );

  ulong     request_cnt = 1UL;
  pthread_t signer;
  FD_TEST( !pthread_create( &signer, NULL, sign_requests, &request_cnt ) );
  fd_keyguard_client_sign( &client, signature, payload, sizeof(payload), FD_KEYGUARD_SIGN_TYPE_ED25519 );
  FD_TEST( !pthread_join( signer, NULL ) );
  FD_TEST( !fd_ed25519_verify( payload, sizeof(payload), signature, ctx.public_key, ctx.sha512 ) );
  for( ulong i=FD_ED25519_SIG_SZ; i<sizeof(signature); i++ ) FD_TEST( signature[i]==0xA5 );
}

static void
test_vote_txn_sign_request( ulong authority_idx ) {
  setup();
  client.response_mtu = 2UL*FD_ED25519_SIG_SZ;
  uchar payload[32];
  memset( payload, 0x42, sizeof(payload) );

  /* Prepublish the signer's response so the blocking call returns.
     Inspect the request it publishes below. */
  for( ulong i=0UL; i<2UL*FD_ED25519_SIG_SZ; i++ ) response_data[i] = (uchar)i;
  fd_mcache_publish( client.response, TEST_DEPTH, 0UL, 0UL, 0UL, 2UL*FD_ED25519_SIG_SZ, 0UL, 0UL, 0UL );

  uchar signatures[ 2UL*FD_ED25519_SIG_SZ+16UL ];
  memset( signatures, 0xA5, sizeof(signatures) );
  fd_keyguard_client_vote_txn_sign( &client, signatures, authority_idx, payload, sizeof(payload) );

  fd_frag_meta_t const * request = client.request+fd_mcache_line_idx( 0UL, TEST_DEPTH );
  FD_TEST( request->sig==( authority_idx==ULONG_MAX ? 0UL : (1UL<<32) | (authority_idx<<33) ) );
  FD_TEST( request->sz==sizeof(payload) );
  FD_TEST( !memcmp( request_data, payload, sizeof(payload) ) );

  ulong signatures_sz = authority_idx==ULONG_MAX ? FD_ED25519_SIG_SZ : 2UL*FD_ED25519_SIG_SZ;
  for( ulong i=0UL;           i<signatures_sz;      i++ ) FD_TEST( signatures[i]==(uchar)i );
  for( ulong i=signatures_sz; i<sizeof(signatures); i++ ) FD_TEST( signatures[i]==0xA5     );
}

static void
test_bls_keypair_mismatch_rejected( int other_key ) {
  fd_sha512_t sha[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  uchar private_key[32]; memset( private_key, 0x11, sizeof(private_key) );
  uchar public_key[32]; fd_ed25519_public_from_private( public_key, private_key, sha );
  if( other_key ) {
    uchar other_private_key[32]; memset( other_private_key, 0x22, sizeof(other_private_key) );
    fd_ed25519_public_from_private( public_key, other_private_key, sha );
  } else {
    public_key[0] ^= 1U;
  }

  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    fd_log_level_core_set( 8 );
    fd_keyguard_bls_key_t key;
    fd_keyguard_bls_key_derive( &key, public_key, private_key, sha );
    _exit( 0 );
  }
  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );
}

static int
bls_request_exit_status( ulong sig,
                         ulong sz ) {
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    fd_log_level_core_set( 8 );
    after_frag( &ctx, 0UL, 0UL, sig, sz, 0UL, 0UL, &stem );
    _exit( 0 );
  }
  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) );
  return WEXITSTATUS( status );
}

static void
test_bls_pubkey_generic_client( void ) {
  setup();
  ulong authority_idx = ULONG_MAX;
  uchar public_key[ FD_KEYGUARD_BLS_PUBKEY_SZ+16UL ];
  memset( public_key, 0xA5, sizeof(public_key) );

  ulong     request_cnt = 1UL;
  pthread_t signer;
  FD_TEST( !pthread_create( &signer, NULL, sign_requests, &request_cnt ) );
  fd_keyguard_client_sign( &client, public_key, (uchar const *)&authority_idx, sizeof(authority_idx), FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY );
  FD_TEST( !pthread_join( signer, NULL ) );
  FD_TEST( !memcmp( public_key, keys[0].public_key, FD_KEYGUARD_BLS_PUBKEY_SZ ) );
  for( ulong i=FD_KEYGUARD_BLS_PUBKEY_SZ; i<sizeof(public_key); i++ ) FD_TEST( public_key[i]==0xA5 );
}

static void
test_bls_pubkey_last_authority( void ) {
  setup();
  uchar private_key[32]; memset( private_key, 0x22, sizeof(private_key) );
  uchar public_key[32]; fd_ed25519_public_from_private( public_key, private_key, ctx.sha512 );
  fd_keyguard_bls_key_derive( &keys[16], public_key, private_key, ctx.sha512 );
  ctx.authorized_voters_cnt = 16UL;

  ulong     request_cnt = 1UL;
  pthread_t signer;
  FD_TEST( !pthread_create( &signer, NULL, sign_requests, &request_cnt ) );
  uchar bls_pubkey[ FD_KEYGUARD_BLS_PUBKEY_SZ ];
  fd_keyguard_client_bls_pubkey( &client, bls_pubkey, 15UL );
  FD_TEST( !pthread_join( signer, NULL ) );
  FD_TEST( !memcmp( bls_pubkey, keys[16].public_key, sizeof(bls_pubkey) ) );
}

static void
test_bls_pubkey_request_rejected( void ) {
  setup();
  FD_STORE( ulong, ctx._data, ULONG_MAX );
  FD_TEST( bls_request_exit_status( FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY, sizeof(ulong) )==0 );
  FD_TEST( bls_request_exit_status( FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY, sizeof(ulong)-1UL )==1 );
  FD_TEST( bls_request_exit_status( FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY, sizeof(ulong)+1UL )==1 );
  FD_TEST( bls_request_exit_status( FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY|(1UL<<32), sizeof(ulong) )==1 );
  ctx.in[0].role = FD_KEYGUARD_ROLE_TXSEND;
  FD_TEST( bls_request_exit_status( FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY, sizeof(ulong) )==1 );
  ctx.in[0].role = FD_KEYGUARD_ROLE_VOTOR;
  FD_STORE( ulong, ctx._data, 0UL );
  FD_TEST( bls_request_exit_status( FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY, sizeof(ulong) )==1 );
  FD_STORE( ulong, ctx._data, 16UL );
  FD_TEST( bls_request_exit_status( FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY, sizeof(ulong) )==1 );
}

static void
test_bls_request_rejected( void ) {
  setup();
  ctx._data[ 0 ] = 3U; /* skip */
  FD_TEST( bls_request_exit_status( FD_KEYGUARD_SIGN_TYPE_BLS,           11UL )==0 );
  FD_TEST( bls_request_exit_status( FD_KEYGUARD_SIGN_TYPE_BLS,           10UL )==1 );
  FD_TEST( bls_request_exit_status( FD_KEYGUARD_SIGN_TYPE_BLS|(1UL<<32), 11UL )==1 ); /* authorized voter 0, none loaded */
}

/* Failover: the sign tile holds the junk and staked keypairs it loaded
   at boot and switches between them by public key. */

static uchar junk_key    [ 64 ];
static uchar staked_key  [ 64 ];
static uchar operator_key[ 64 ]; /* the sign tile's page for a set-identity key */

static void
failover_setup( void ) {
  setup();
  fd_memset( junk_key,   0x33, 32UL );
  fd_memset( staked_key, 0x44, 32UL );
  fd_ed25519_public_from_private( junk_key  +32UL, junk_key,   ctx.sha512 );
  fd_ed25519_public_from_private( staked_key+32UL, staked_key, ctx.sha512 );
  fd_memcpy( identity_key, junk_key, 64UL ); /* a failover member boots under the junk key */
  derive_fields( &ctx );
  fd_memset( operator_key, 0, 64UL );
  ctx.failover_junk_key     = junk_key;
  ctx.failover_staked_key   = staked_key;
  ctx.failover_operator_key = operator_key;
  ctx.failover_key          = staked_key;
  ctx.in[0].role          = FD_KEYGUARD_ROLE_FAILOV;
  client.response_mtu     = FD_ED25519_SIG_SZ;
}

static void *
sign_one( void * arg ) {
  ulong seq = *(ulong *)arg;
  fd_frag_meta_t const * line = client.request+fd_mcache_line_idx( seq, TEST_DEPTH );
  while( fd_frag_meta_seq_query( line )!=seq ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
  during_frag( &ctx, 0UL, seq, line->sig, line->chunk, line->sz, 0UL );
  after_frag( &ctx, 0UL, seq, line->sig, line->sz, 0UL, 0UL, &stem );
  return NULL;
}

/* Whether the sign tile signs payload with the key of public_key. */

static int
failover_signed_by( uchar const * payload,
                    ulong         payload_sz,
                    uchar const * public_key ) {
  uchar     signature[ FD_ED25519_SIG_SZ ];
  ulong     seq = client.request_seq;
  pthread_t signer;
  FD_TEST( !pthread_create( &signer, NULL, sign_one, &seq ) );
  fd_keyguard_client_sign( &client, signature, payload, payload_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 );
  FD_TEST( !pthread_join( signer, NULL ) );
  return FD_ED25519_SUCCESS==fd_ed25519_verify( payload, payload_sz, signature, public_key, ctx.sha512 );
}

static void
failover_switch( fd_keyswitch_t * ks,
                 uchar const *    public_key ) {
  fd_memcpy( ks->bytes,      public_key, 32UL );
  fd_memset( ks->bytes+32UL, 0,          32UL );
  ks->param = FD_KEYSWITCH_PARAM_IDENTITY_PUBKEY;
  fd_keyswitch_state( ks, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( fd_keyswitch_state_query( ks )==FD_KEYSWITCH_STATE_COMPLETED );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( !ks->bytes[ i ] );
}

/* Without failover an identity switch takes the keypair whatever the
   param says, the failover key selection never runs. */

static void
test_identity_switch_without_failover( void ) {
  setup();
  fd_keyswitch_t identity_switch[1];
  ctx.keyswitch = fd_keyswitch_join( fd_keyswitch_new( identity_switch, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.keyswitch );
  uchar keypair[ 64 ];
  fd_memset( keypair, 0x55, 32UL );
  fd_ed25519_public_from_private( keypair+32UL, keypair, ctx.sha512 );
  fd_memcpy( ctx.keyswitch->bytes, keypair, 64UL );
  ctx.keyswitch->param = FD_KEYSWITCH_PARAM_IDENTITY_PUBKEY;
  fd_keyswitch_state( ctx.keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( fd_keyswitch_state_query( ctx.keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( fd_memeq( ctx.private_key, keypair, 32UL ) && fd_memeq( ctx.public_key, keypair+32UL, 32UL ) );

  /* Adding an authorized voter takes the upstream path, whatever its
     key. */
  fd_keyswitch_t voter_switch[1];
  ctx.av_keyswitch = fd_keyswitch_join( fd_keyswitch_new( voter_switch, FD_KEYSWITCH_STATE_SWITCH_PENDING ) );
  FD_TEST( ctx.av_keyswitch );
  fd_memcpy( voter_switch->bytes, keypair, 64UL );
  voter_switch->param = FD_KEYSWITCH_PARAM_AV_ADD;
  during_housekeeping( &ctx );
  FD_TEST( fd_keyswitch_state_query( voter_switch )==FD_KEYSWITCH_STATE_COMPLETED && ctx.authorized_voters_cnt==1UL );
}

static void
test_failover_keys( void ) {
  failover_setup();
  fd_keyswitch_t identity_switch[1];
  ctx.keyswitch = fd_keyswitch_join( fd_keyswitch_new( identity_switch, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.keyswitch );

  uchar cert[ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  fd_memcpy( cert,                                    FD_KEYGUARD_MEMBER_CERT_PREFIX, FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ );
  fd_memcpy( cert+FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ, junk_key+32UL,                  32UL                              );
  uchar cv[ FD_TLS_CV_SIGN_SZ ];
  fd_memcpy( cv, fd_tls13_cli_sign_prefix, sizeof(fd_tls13_cli_sign_prefix) );
  fd_memset( cv+sizeof(fd_tls13_cli_sign_prefix), 0x5A, sizeof(cv)-sizeof(fd_tls13_cli_sign_prefix) );

  fd_keyguard_bls_key_t junk_bls[1], staked_bls[1];
  fd_keyguard_bls_key_derive( junk_bls,   junk_key  +32UL, junk_key,   ctx.sha512 );
  fd_keyguard_bls_key_derive( staked_bls, staked_key+32UL, staked_key, ctx.sha512 );

  /* Junk, staked, then junk again.  Whichever is installed, the staked
     key signs the certificate and the junk key the handshake, and BLS
     key 0 follows the installed identity. */
  for( ulong i=0UL; i<3UL; i++ ) {
    uchar const *                 installed = i==1UL ? staked_key : junk_key;
    fd_keyguard_bls_key_t const * bls       = i==1UL ? staked_bls : junk_bls;
    if( i ) failover_switch( identity_switch, installed+32UL );
    FD_TEST( fd_memeq( ctx.public_key,     installed+32UL,  32UL                      ) );
    FD_TEST( fd_memeq( ctx.private_key,    installed,       32UL                      ) );
    FD_TEST( fd_memeq( keys[0].public_key, bls->public_key, FD_KEYGUARD_BLS_PUBKEY_SZ ) );
    FD_TEST( failover_signed_by( cert, sizeof(cert), staked_key+32UL ) );
    FD_TEST( failover_signed_by( cv,   sizeof(cv),   junk_key  +32UL ) );
  }

  /* The staked key is never an authorized voter under failover. */
  fd_keyswitch_t voter_switch[1];
  ctx.av_keyswitch = fd_keyswitch_join( fd_keyswitch_new( voter_switch, FD_KEYSWITCH_STATE_SWITCH_PENDING ) );
  FD_TEST( ctx.av_keyswitch );
  fd_memcpy( voter_switch->bytes, staked_key, 64UL );
  voter_switch->param = FD_KEYSWITCH_PARAM_AV_ADD;
  during_housekeeping( &ctx );
  FD_TEST( fd_keyswitch_state_query( voter_switch )==FD_KEYSWITCH_STATE_FAILED );
  FD_TEST( voter_switch->result==FD_ADMINCTL_RESULT_UNSUPPORTED );
  FD_TEST( !ctx.authorized_voters_cnt );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( !voter_switch->bytes[ i ] );
  FD_LOG_NOTICE(( "pass: failover keys" ));
}

/* A set-identity keypair other than the junk key becomes the failover
   identity, it signs the member certificate and is never an authorized
   voter.  The staked key keeps its boot page, another key goes in the
   operator page. */

static void
operator_switch( fd_keyswitch_t * ks,
                 uchar const *    keypair ) {
  fd_memcpy( ks->bytes, keypair, 64UL );
  ks->param = FD_KEYSWITCH_PARAM_IDENTITY_KEYPAIR;
  fd_keyswitch_state( ks, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( &ctx );
  FD_TEST( fd_keyswitch_state_query( ks )==FD_KEYSWITCH_STATE_COMPLETED );
}

static void
test_failover_operator_key( void ) {
  failover_setup();
  fd_keyswitch_t identity_switch[1];
  ctx.keyswitch = fd_keyswitch_join( fd_keyswitch_new( identity_switch, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.keyswitch );
  uchar third[ 64 ];
  fd_memset( third, 0x66, 32UL );
  fd_ed25519_public_from_private( third+32UL, third, ctx.sha512 );
  uchar cert[ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  fd_memcpy( cert,                                    FD_KEYGUARD_MEMBER_CERT_PREFIX, FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ );
  fd_memcpy( cert+FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ, junk_key+32UL,                  32UL                              );

  uchar staked_copy[ 64 ];
  fd_memcpy( staked_copy, staked_key, 64UL );
  operator_switch( identity_switch, third );
  FD_TEST( fd_memeq( ctx.public_key, third+32UL, 32UL ) && fd_memeq( operator_key, third, 64UL ) );
  FD_TEST( ctx.failover_key==operator_key && fd_memeq( staked_key, staked_copy, 64UL ) );
  FD_TEST( failover_signed_by( cert, sizeof(cert), third+32UL ) );

  /* A failover switch can now select the new key and the junk key. */
  failover_switch( identity_switch, junk_key+32UL );
  FD_TEST( fd_memeq( ctx.public_key, junk_key+32UL, 32UL ) );
  failover_switch( identity_switch, third+32UL );
  FD_TEST( fd_memeq( ctx.public_key, third+32UL, 32UL ) );

  /* set-identity to the junk key keeps the failover identity. */
  operator_switch( identity_switch, junk_key );
  FD_TEST( fd_memeq( ctx.public_key, junk_key+32UL, 32UL ) && ctx.failover_key==operator_key && fd_memeq( operator_key, third, 64UL ) );
  FD_TEST( failover_signed_by( cert, sizeof(cert), third+32UL ) );

  /* The failover identity is never an authorized voter, the configured
     key may be one now. */
  fd_keyswitch_t voter_switch[1];
  ctx.av_keyswitch = fd_keyswitch_join( fd_keyswitch_new( voter_switch, FD_KEYSWITCH_STATE_SWITCH_PENDING ) );
  FD_TEST( ctx.av_keyswitch );
  fd_memcpy( voter_switch->bytes, third, 64UL );
  voter_switch->param = FD_KEYSWITCH_PARAM_AV_ADD;
  during_housekeeping( &ctx );
  FD_TEST( fd_keyswitch_state_query( voter_switch )==FD_KEYSWITCH_STATE_FAILED && !ctx.authorized_voters_cnt );
  fd_keyswitch_state( voter_switch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  fd_memcpy( voter_switch->bytes, staked_key, 64UL );
  voter_switch->param = FD_KEYSWITCH_PARAM_AV_ADD;
  during_housekeeping( &ctx );
  FD_TEST( fd_keyswitch_state_query( voter_switch )==FD_KEYSWITCH_STATE_COMPLETED && ctx.authorized_voters_cnt==1UL );

  /* set-identity to the staked key goes back to its boot page and clears
     the operator page. */
  operator_switch( identity_switch, staked_key );
  uchar zero[ 64 ] = {0};
  FD_TEST( ctx.failover_key==staked_key && fd_memeq( operator_key, zero, 64UL ) );
  FD_TEST( failover_signed_by( cert, sizeof(cert), staked_key+32UL ) );
  failover_switch( identity_switch, junk_key+32UL );
  failover_switch( identity_switch, staked_key+32UL );
  FD_TEST( fd_memeq( ctx.public_key, staked_key+32UL, 32UL ) );
  FD_LOG_NOTICE(( "pass: failover operator key" ));
}

static fd_keyswitch_t failover_ks[1];

static void
switch_to_unknown_key( void ) {
  uchar other[ 64 ];
  fd_memset( other, 0x55, 32UL );
  fd_ed25519_public_from_private( other+32UL, other, ctx.sha512 );
  failover_switch( failover_ks, other+32UL );
}

static void
sign_foreign_cert( void ) {
  fd_memcpy( ctx._data,                                    FD_KEYGUARD_MEMBER_CERT_PREFIX, FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ );
  fd_memcpy( ctx._data+FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ, staked_key+32UL,                32UL                              );
  after_frag( &ctx, 0UL, 0UL, FD_KEYGUARD_SIGN_TYPE_ED25519, FD_KEYGUARD_MEMBER_CERT_MSG_SZ, 0UL, 0UL, &stem );
}

static int
child_exit_status( void (*fn)( void ) ) {
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    fd_log_level_core_set( 8 );
    fn();
    _exit( 0 );
  }
  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) );
  return WEXITSTATUS( status );
}

/* A switch to a key not loaded at boot, and a certificate over another
   junk key, stop the validator. */

static void
test_failover_refusals( void ) {
  failover_setup();
  ctx.keyswitch = fd_keyswitch_join( fd_keyswitch_new( failover_ks, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.keyswitch );
  FD_TEST( child_exit_status( switch_to_unknown_key )==1 );
  FD_TEST( child_exit_status( sign_foreign_cert     )==1 );
  FD_LOG_NOTICE(( "pass: failover refusals" ));
}

/* Failover boot: load_keys reads the junk and staked key files, and
   each case below runs in a child. */

static fd_topo_tile_t tile;
static fd_keyswitch_t boot_identity_switch;
static fd_keyswitch_t boot_voter_switch;
static uchar          file_junk  [ 64 ];
static uchar          file_staked[ 64 ];
static uchar          file_other [ 64 ];
static char           junk_path  [ 256 ];
static char           staked_path[ 256 ];

static void
write_key( char const *  path,
           uchar const * key ) {
  FILE * file = fopen( path, "w" );
  FD_TEST( file );
  FD_TEST( fputc( '[', file )!=EOF );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( fprintf( file, "%s%u", i ? "," : "", (uint)key[ i ] )>0 );
  FD_TEST( fputc( ']', file )!=EOF );
  FD_TEST( !fclose( file ) );
}

/* Load the keys like privileged_init and join the rest of the ctx that
   the tests use.  We always boot with the junk key. */

static void
boot_signer( int failover ) {
  fd_memset( &ctx, 0, sizeof(ctx) );
  /* Stale pointers, load_keys has to reset them. */
  ctx.failover_junk_key   = file_other;
  ctx.failover_staked_key = file_other;
  tile.sign.failover_enabled = failover;
  load_keys( &ctx, &tile );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx.sha512 ) ) );
  ctx.keyswitch    = fd_keyswitch_join( fd_keyswitch_new( &boot_identity_switch, FD_KEYSWITCH_STATE_UNLOCKED ) );
  ctx.av_keyswitch = fd_keyswitch_join( fd_keyswitch_new( &boot_voter_switch,    FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx.keyswitch && ctx.av_keyswitch );
  FD_TEST( fd_histf_join( fd_histf_new( ctx.sign_duration, 1UL, 1000000000UL ) ) );
  derive_fields( &ctx );
  FD_TEST( fd_memeq( ctx.public_key, file_junk+32UL, 32UL ) );
}

/* Sign a shred root and a bundle challenge through after_frag and
   check both verify with key and not with wrong_key.  Also check the
   BLS key was derived from key. */

static void
check_signatures( uchar const * key,
                  uchar const * wrong_key ) {
  static uchar output[ 128 ] __attribute__((aligned(128)));
  static fd_frag_meta_t mcache[ 8 ];
  fd_frag_meta_t * mcaches[]    = { mcache };
  ulong            seqs[]       = { 0UL };
  ulong            depths[]     = { 8UL };
  ulong            cr_avail     = 64UL;
  ulong            min_cr_avail = 64UL;
  int              reliable     = 0;
  fd_stem_context_t boot_stem = {
    .mcaches=mcaches, .seqs=seqs, .depths=depths,
    .cr_avail=&cr_avail, .min_cr_avail=&min_cr_avail,
    .cr_decrement_amount=1UL, .out_reliable=&reliable
  };
  ctx.out[ 0 ] = (fd_sign_out_ctx_t){ .out_mem=(fd_wksp_t *)output };

  ctx.in[ 0 ].role = FD_KEYGUARD_ROLE_LEADER;
  fd_memset( ctx._data, 0x5A, 32UL );
  after_frag_sensitive( &ctx, 0UL, 0UL, FD_KEYGUARD_SIGN_TYPE_ED25519, 32UL, 0UL, 0UL, &boot_stem );
  FD_TEST( mcache[ 0 ].sz==64UL );
  FD_TEST( fd_ed25519_verify( ctx._data, 32UL, output, key+32UL,       ctx.sha512 )==FD_ED25519_SUCCESS );
  FD_TEST( fd_ed25519_verify( ctx._data, 32UL, output, wrong_key+32UL, ctx.sha512 )!=FD_ED25519_SUCCESS );

  ctx.in[ 0 ].role = FD_KEYGUARD_ROLE_BUNDLE;
  fd_memcpy( ctx._data, "challenge", 9UL );
  after_frag_sensitive( &ctx, 0UL, 1UL, FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519, 9UL, 0UL, 0UL, &boot_stem );
  char  message[ FD_BASE58_ENCODED_32_SZ+10UL ];
  ulong len;
  fd_base58_encode_32( key+32UL, &len, message );
  fd_memcpy( message+len, "-challenge", 10UL );
  FD_TEST( fd_ed25519_verify( (uchar const *)message, len+10UL, output, key+32UL,       ctx.sha512 )==FD_ED25519_SUCCESS );
  FD_TEST( fd_ed25519_verify( (uchar const *)message, len+10UL, output, wrong_key+32UL, ctx.sha512 )!=FD_ED25519_SUCCESS );

  static char const derive_msg[] = "bls-key-derive-alpenglow";
  uchar        ikm[ 64 ];
  fd_bls_sec_t bls_key[ 1 ];
  fd_ed25519_sign( ikm, (uchar const *)derive_msg, sizeof(derive_msg)-1UL, key+32UL, key, ctx.sha512 );
  fd_bls_sec_derive( bls_key, ikm, sizeof(ikm) );
  FD_TEST( fd_memeq( &ctx.bls_keys[ 0 ].secret_key, bls_key, sizeof(bls_key) ) );
}

/* Request a failov signature over data through after_frag and return
   it in sig. */

static void
failov_request( uchar const * data,
                ulong         sz,
                uchar *       sig ) {
  static uchar output[ 128 ] __attribute__((aligned(128)));
  static fd_frag_meta_t mcache[ 8 ];
  fd_frag_meta_t * mcaches[]    = { mcache };
  ulong            seqs[]       = { 0UL };
  ulong            depths[]     = { 8UL };
  ulong            cr_avail     = 64UL;
  ulong            min_cr_avail = 64UL;
  int              reliable     = 0;
  fd_stem_context_t boot_stem = {
    .mcaches=mcaches, .seqs=seqs, .depths=depths,
    .cr_avail=&cr_avail, .min_cr_avail=&min_cr_avail,
    .cr_decrement_amount=1UL, .out_reliable=&reliable
  };
  ctx.out[ 0 ] = (fd_sign_out_ctx_t){ .out_mem=(fd_wksp_t *)output };

  ctx.in[ 0 ].role = FD_KEYGUARD_ROLE_FAILOV;
  fd_memcpy( ctx._data, data, sz );
  after_frag_sensitive( &ctx, 0UL, 0UL, FD_KEYGUARD_SIGN_TYPE_ED25519, sz, 0UL, 0UL, &boot_stem );
  FD_TEST( mcache[ 0 ].sz==64UL );
  fd_memcpy( sig, output, 64UL );
}

/* Request the member certificate over pubkey and return the signature
   in sig. */

static void
member_cert( uchar const * pubkey,
             uchar *       sig ) {
  uchar msg[ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  fd_memcpy( msg, FD_KEYGUARD_MEMBER_CERT_PREFIX, FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ );
  fd_memcpy( msg+FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ, pubkey, 32UL );
  failov_request( msg, sizeof(msg), sig );
}

static void
select_identity( uchar const * public_key ) {
  ctx.keyswitch->param = FD_KEYSWITCH_PARAM_IDENTITY_PUBKEY;
  fd_memset( ctx.keyswitch->bytes, 0xA5, 64UL );
  fd_memcpy( ctx.keyswitch->bytes, public_key, 32UL );
  fd_keyswitch_state( ctx.keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping_sensitive( &ctx );
  FD_TEST( fd_keyswitch_state_query( ctx.keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( !ctx.keyswitch->bytes[ i ] );
}

/* Install a keypair the way set-identity does. */

static void
install_keypair( uchar const * key ) {
  ctx.keyswitch->param = FD_KEYSWITCH_PARAM_IDENTITY_KEYPAIR;
  fd_memcpy( ctx.keyswitch->bytes, key, 64UL );
  fd_keyswitch_state( ctx.keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping_sensitive( &ctx );
  FD_TEST( fd_keyswitch_state_query( ctx.keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  for( ulong i=0UL; i<32UL; i++ ) FD_TEST( !ctx.keyswitch->bytes[ i ] );
}

/* test_failover_selection: under failover and the sign tile seccomp
   filter we switch between the junk and staked keys by public key and
   sign with each, without the key files. */

static void
test_failover_selection( volatile int * progress ) {
  boot_signer( 1 );
  /* The installed identity is a writable copy, apart from the read
     only boot copies. */
  FD_TEST( ctx.failover_junk_key && ctx.failover_staked_key );
  FD_TEST( ctx.private_key!=ctx.failover_junk_key && ctx.private_key!=ctx.failover_staked_key );
  /* Switching must not read the key files. */
  FD_TEST( !unlink( junk_path ) && !unlink( staked_path ) );

  struct sock_filter filter[ 128 ];
  ulong filter_cnt = populate_allowed_seccomp( NULL, NULL, 128UL, filter );
  FD_TEST( !prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) );
  fd_sandbox_private_set_seccomp_filter( (ushort)filter_cnt, filter );
  check_signatures( file_junk, file_staked );
  for( ulong i=0UL; i<3UL; i++ ) {
    select_identity( file_staked+32UL );
    check_signatures( file_staked, file_junk );
    select_identity( file_junk+32UL );
    check_signatures( file_junk, file_staked );
  }
  *progress = 1;
  /* The filter is still on, so this read kills us. */
  uchar byte;
  (void)syscall( SYS_read, -1, &byte, 1UL );
  __builtin_trap();
}

/* test_keypair_switch: without failover a switch still installs the
   keypair passed in the keyswitch. */

static void
test_keypair_switch( void ) {
  boot_signer( 0 );
  FD_TEST( !ctx.failover_junk_key && !ctx.failover_staked_key );
  check_signatures( file_junk, file_staked );
  for( ulong i=0UL; i<3UL; i++ ) {
    uchar const * key       = i & 1UL ? file_junk   : file_staked;
    uchar const * wrong_key = i & 1UL ? file_staked : file_junk;
    install_keypair( key );
    check_signatures( key, wrong_key );
  }
}

/* test_keypair_in_failover: set-identity sends a keypair under failover
   too, and it is installed and becomes the failover identity on its own
   page, the staked page from boot is unchanged.  It signs the member
   certificate, the junk key still signs the pair TLS, and a switch by
   public key selects the junk key or the new one. */

static void
test_keypair_in_failover( void ) {
  boot_signer( 1 );
  install_keypair( file_other );
  check_signatures( file_other, file_junk );

  uchar msg[ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  fd_memcpy( msg, FD_KEYGUARD_MEMBER_CERT_PREFIX, FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ );
  fd_memcpy( msg+FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ, file_junk+32UL, 32UL );
  uchar sig[ 64 ];
  member_cert( file_junk+32UL, sig );
  FD_TEST( fd_ed25519_verify( msg, sizeof(msg), sig, file_other+32UL, ctx.sha512 )==FD_ED25519_SUCCESS );

  uchar cv[ FD_TLS_CV_SIGN_SZ ];
  fd_memcpy( cv, fd_tls13_cli_sign_prefix, sizeof(fd_tls13_cli_sign_prefix) );
  fd_memset( cv+sizeof(fd_tls13_cli_sign_prefix), 0x5a, 32UL );
  failov_request( cv, sizeof(cv), sig );
  FD_TEST( fd_ed25519_verify( cv, sizeof(cv), sig, file_junk+32UL, ctx.sha512 )==FD_ED25519_SUCCESS );

  FD_TEST( fd_memeq( ctx.failover_junk_key,     file_junk,   64UL ) );
  FD_TEST( fd_memeq( ctx.failover_staked_key,   file_staked, 64UL ) );
  FD_TEST( fd_memeq( ctx.failover_operator_key, file_other,  64UL ) && ctx.failover_key==ctx.failover_operator_key );
  select_identity( file_junk+32UL );
  check_signatures( file_junk, file_other );
  select_identity( file_other+32UL );
  check_signatures( file_other, file_junk );

  /* set-identity with the junk key keeps the failover identity. */
  install_keypair( file_junk );
  FD_TEST( ctx.failover_key==ctx.failover_operator_key && fd_memeq( ctx.failover_operator_key, file_other, 64UL ) );
}

/* test_staked_voter_add: under failover adding the staked key as an
   authorized voter fails, and another key can still be added. */

static void
test_staked_voter_add( void ) {
  boot_signer( 1 );
  ctx.av_keyswitch->param = FD_KEYSWITCH_PARAM_AV_ADD;
  fd_memcpy( ctx.av_keyswitch->bytes, file_staked, 64UL );
  fd_keyswitch_state( ctx.av_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping_sensitive( &ctx );
  FD_TEST( fd_keyswitch_state_query( ctx.av_keyswitch )==FD_KEYSWITCH_STATE_FAILED );
  FD_TEST( ctx.av_keyswitch->result==FD_ADMINCTL_RESULT_UNSUPPORTED );
  FD_TEST( !ctx.authorized_voters_cnt );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( !ctx.av_keyswitch->bytes[ i ] );
  check_signatures( file_junk, file_staked );

  fd_memcpy( ctx.av_keyswitch->bytes, file_other, 64UL );
  fd_keyswitch_state( ctx.av_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping_sensitive( &ctx );
  FD_TEST( fd_keyswitch_state_query( ctx.av_keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx.authorized_voters_cnt==1UL );
  FD_TEST( fd_memeq( ctx.authorized_voter_pubkeys[ 0 ], file_other+32UL, 32UL ) );
  ctx.av_keyswitch->param = FD_KEYSWITCH_PARAM_AV_CLEAR;
  fd_keyswitch_state( ctx.av_keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping_sensitive( &ctx );
  FD_TEST( !ctx.authorized_voters_cnt );
}

/* test_member_cert: the failov role gets the staked key's signature
   over our junk pubkey and the junk key's signature over a TLS
   CertificateVerify, whichever key is installed. */

static void
test_member_cert( void ) {
  boot_signer( 1 );
  uchar msg[ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  fd_memcpy( msg, FD_KEYGUARD_MEMBER_CERT_PREFIX, FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ );
  fd_memcpy( msg+FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ, file_junk+32UL, 32UL );

  uchar cv[ FD_TLS_CV_SIGN_SZ ];
  fd_memcpy( cv, fd_tls13_srv_sign_prefix, sizeof(fd_tls13_srv_sign_prefix) );
  fd_memset( cv+sizeof(fd_tls13_srv_sign_prefix), 0x5a, 32UL );

  uchar sig[ 64 ], cv_sig[ 64 ];
  member_cert( file_junk+32UL, sig );
  FD_TEST( fd_ed25519_verify( msg, sizeof(msg), sig, file_staked+32UL, ctx.sha512 )==FD_ED25519_SUCCESS );
  FD_TEST( fd_ed25519_verify( msg, sizeof(msg), sig, file_junk+32UL,   ctx.sha512 )!=FD_ED25519_SUCCESS );
  failov_request( cv, sizeof(cv), cv_sig );
  FD_TEST( fd_ed25519_verify( cv, sizeof(cv), cv_sig, file_junk+32UL,   ctx.sha512 )==FD_ED25519_SUCCESS );
  FD_TEST( fd_ed25519_verify( cv, sizeof(cv), cv_sig, file_staked+32UL, ctx.sha512 )!=FD_ED25519_SUCCESS );
  check_signatures( file_junk, file_staked );

  select_identity( file_staked+32UL );
  uchar switched_sig[ 64 ], switched_cv_sig[ 64 ];
  member_cert( file_junk+32UL, switched_sig );
  FD_TEST( fd_memeq( switched_sig, sig, 64UL ) );
  failov_request( cv, sizeof(cv), switched_cv_sig );
  FD_TEST( fd_memeq( switched_cv_sig, cv_sig, 64UL ) );
  check_signatures( file_staked, file_junk );
}

/* FAILOVER_SELECTION dies on the seccomp filter, READONLY_* die on the
   write, the cases up to MEMBER_CERT exit cleanly, and the rest exit
   with status 1. */

enum {
  FAILOVER_SELECTION, READONLY_JUNK, READONLY_STAKED,
  KEYPAIR_SWITCH, KEYPAIR_IN_FAILOVER, STAKED_VOTER_ADD, MEMBER_CERT,
  SAME_KEYS, BAD_STAKED, BAD_STAKED_LAST_BYTE, MISSING_STAKED, BAD_JUNK, STAKED_VOTER,
  FOREIGN_SELECTION, FOREIGN_SELECTION_LAST_BYTE, SELECTION_WITHOUT_FAILOVER,
  FOREIGN_CERT, FOREIGN_CERT_LAST_BYTE, BOOT_CASE_CNT
};

static void
run_boot_case( int test,
               volatile int * progress ) {
  fd_log_level_core_set( 8 );
  switch( test ) {
  case FAILOVER_SELECTION:  test_failover_selection( progress ); break;
  case KEYPAIR_SWITCH:      test_keypair_switch();               break;
  case KEYPAIR_IN_FAILOVER: test_keypair_in_failover();          break;
  case STAKED_VOTER_ADD:    test_staked_voter_add();             break;
  case MEMBER_CERT:         test_member_cert();                  break;
  case READONLY_JUNK:
  case READONLY_STAKED: {
    boot_signer( 1 );
    *progress = 1;
    uchar const * key = test==READONLY_JUNK ? ctx.failover_junk_key : ctx.failover_staked_key;
    FD_VOLATILE( *(uchar *)key ) = 0;
    break;
  }
  case SAME_KEYS:            write_key( staked_path, file_junk ); boot_signer( 1 ); break;
  case BAD_STAKED:           file_staked[ 32 ] ^= 1; write_key( staked_path, file_staked ); boot_signer( 1 ); break;
  case BAD_STAKED_LAST_BYTE: file_staked[ 63 ] ^= 1; write_key( staked_path, file_staked ); boot_signer( 1 ); break;
  case MISSING_STAKED:       FD_TEST( !unlink( staked_path ) ); boot_signer( 1 ); break;
  case BAD_JUNK:             file_junk[ 32 ] ^= 1; write_key( junk_path, file_junk ); boot_signer( 1 ); break;
  case STAKED_VOTER:
    tile.sign.authorized_voter_paths_cnt = 1UL;
    fd_cstr_ncpy( tile.sign.authorized_voter_paths[ 0 ], staked_path, PATH_MAX );
    boot_signer( 1 );
    break;
  case FOREIGN_SELECTION: boot_signer( 1 ); select_identity( file_other+32UL ); break;
  case FOREIGN_SELECTION_LAST_BYTE: {
    boot_signer( 1 );
    uchar pubkey[ 32 ];
    fd_memcpy( pubkey, file_staked+32UL, 32UL );
    pubkey[ 31 ] ^= 1;
    select_identity( pubkey );
    break;
  }
  case SELECTION_WITHOUT_FAILOVER: boot_signer( 0 ); select_identity( file_staked+32UL ); break;
  case FOREIGN_CERT: {
    boot_signer( 1 );
    uchar sig[ 64 ];
    member_cert( file_other+32UL, sig );
    break;
  }
  case FOREIGN_CERT_LAST_BYTE: {
    boot_signer( 1 );
    uchar pubkey[ 32 ];
    fd_memcpy( pubkey, file_junk+32UL, 32UL );
    pubkey[ 31 ] ^= 1;
    uchar sig[ 64 ];
    member_cert( pubkey, sig );
    break;
  }
  }
}

static void
test_failover_boot( void ) {
  char dir[ PATH_MAX ];
  char const * tmp_dir = getenv( "TMPDIR" );
  FD_TEST( fd_cstr_printf_check( dir, sizeof(dir), NULL, "%s/fd-sign-failover-XXXXXX",
                                 tmp_dir && tmp_dir[0] ? tmp_dir : "/tmp" ) );
  FD_TEST( mkdtemp( dir ) );
  FD_TEST( fd_cstr_printf_check( junk_path,   sizeof(junk_path),   NULL, "%s/junk.json",   dir ) );
  FD_TEST( fd_cstr_printf_check( staked_path, sizeof(staked_path), NULL, "%s/staked.json", dir ) );
  fd_cstr_ncpy( tile.sign.identity_key_path,        junk_path,   sizeof(tile.sign.identity_key_path)        );
  fd_cstr_ncpy( tile.sign.failover_staked_key_path, staked_path, sizeof(tile.sign.failover_staked_key_path) );

  fd_sha512_t sha[ 1 ];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  fd_memset( file_junk,   1, 32UL );
  fd_memset( file_staked, 2, 32UL );
  fd_memset( file_other,  3, 32UL );
  fd_ed25519_public_from_private( file_junk  +32UL, file_junk,   sha );
  fd_ed25519_public_from_private( file_staked+32UL, file_staked, sha );
  fd_ed25519_public_from_private( file_other +32UL, file_other,  sha );

  volatile int * progress = mmap( NULL, 4096UL, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( progress!=MAP_FAILED );

  for( int test=0; test<BOOT_CASE_CNT; test++ ) {
    write_key( junk_path,   file_junk   );
    write_key( staked_path, file_staked );
    *progress = 0;
    pid_t pid = fork();
    FD_TEST( pid>=0 );
    if( !pid ) {
      FD_TEST( signal( SIGILL,  SIG_DFL )!=SIG_ERR );
      FD_TEST( signal( SIGSEGV, SIG_DFL )!=SIG_ERR );
      run_boot_case( test, progress );
      _exit( 0 );
    }
    int status;
    FD_TEST( waitpid( pid, &status, 0 )==pid );
    if( test==FAILOVER_SELECTION ) {
      FD_TEST( *progress==1 && WIFSIGNALED( status ) && WTERMSIG( status )==SIGSYS );
    } else if( test==READONLY_JUNK || test==READONLY_STAKED ) {
      FD_TEST( *progress==1 && WIFSIGNALED( status ) && WTERMSIG( status )==SIGSEGV );
    } else if( test<=MEMBER_CERT ) {
      FD_TEST( WIFEXITED( status ) && !WEXITSTATUS( status ) );
    } else {
      FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );
    }
  }

  FD_TEST( !munmap( (void *)progress, 4096UL ) );
  FD_TEST( !unlink( junk_path ) && !unlink( staked_path ) && !rmdir( dir ) );
  FD_LOG_NOTICE(( "pass: failover boot" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_bls_request_signing();
  test_ed25519_request_signing();
  test_vote_txn_sign_request( ULONG_MAX );
  test_vote_txn_sign_request( 5UL );
  test_bls_keypair_mismatch_rejected( 0 );
  test_bls_keypair_mismatch_rejected( 1 );
  test_bls_pubkey_generic_client();
  test_bls_pubkey_last_authority();
  test_bls_pubkey_request_rejected();
  test_bls_request_rejected();
  test_identity_switch_without_failover();
  test_failover_keys();
  test_failover_operator_key();
  test_failover_refusals();
  test_failover_boot();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
