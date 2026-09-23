#include "fd_sign_tile.c"
#include "fd_keyguard_client.h"
#include "../../waltz/tls/fd_tls.h"

#include <pthread.h>
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

static uchar junk_key  [ 64 ];
static uchar staked_key[ 64 ];

static void
failover_setup( void ) {
  setup();
  fd_memset( junk_key,   0x33, 32UL );
  fd_memset( staked_key, 0x44, 32UL );
  fd_ed25519_public_from_private( junk_key  +32UL, junk_key,   ctx.sha512 );
  fd_ed25519_public_from_private( staked_key+32UL, staked_key, ctx.sha512 );
  fd_memcpy( identity_key, junk_key, 64UL ); /* a failover member boots under the junk key */
  derive_fields( &ctx );
  ctx.failover_junk_key   = junk_key;
  ctx.failover_staked_key = staked_key;
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
  test_failover_refusals();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
