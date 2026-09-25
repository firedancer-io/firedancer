#include "fd_sign_tile.c"
#include "fd_keyguard_client.h"

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
  static uchar const expected_selector[ FD_KEYGUARD_BLS_PUBKEY_SZ ] = {
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
  FD_TEST( !memcmp( keys[1].public_key, expected_selector, sizeof(expected_selector) ) );

  fd_bls_pub_t public_keys[2];
  FD_TEST( !fd_bls_pub_de( &public_keys[0], keys[0].public_key, FD_KEYGUARD_BLS_PUBKEY_SZ ) );
  FD_TEST( !fd_bls_pub_de( &public_keys[1], expected_selector, sizeof(expected_selector) ) );

  ulong     request_cnt = 10UL;
  pthread_t signer;
  FD_TEST( !pthread_create( &signer, NULL, sign_requests, &request_cnt ) );
  for( ulong i=0UL; i<2UL; i++ ) {
    for( uchar tag=1U; tag<=5U; tag++ ) {
      uchar payload[43];
      for( ulong j=0UL; j<sizeof(payload); j++ ) payload[j] = (uchar)(0x20UL+j);
      payload[0] = tag;
      ulong payload_sz = ( tag==1U || tag==4U ) ? 43UL : 11UL;
      uchar request[ FD_KEYGUARD_BLS_PUBKEY_SZ+sizeof(payload) ];
      memcpy( request, keys[i].public_key, FD_KEYGUARD_BLS_PUBKEY_SZ );
      memcpy( request+FD_KEYGUARD_BLS_PUBKEY_SZ, payload, payload_sz );
      uchar signature[ FD_KEYGUARD_BLS_SIG_SZ ];
      fd_keyguard_client_sign( &client, signature, request, FD_KEYGUARD_BLS_PUBKEY_SZ+payload_sz, FD_KEYGUARD_SIGN_TYPE_BLS );
      FD_TEST( !memcmp( request_data, keys[i].public_key, FD_KEYGUARD_BLS_PUBKEY_SZ ) );
      FD_TEST( !memcmp( request_data+FD_KEYGUARD_BLS_PUBKEY_SZ, payload, payload_sz ) );
      fd_bls_sig_t sig[1];
      FD_TEST( !fd_bls_sig_de( sig, signature ) );
      FD_TEST(  fd_bls_agg_verify( payload, payload_sz, &public_keys[i], sig ) );
      FD_TEST( !fd_bls_agg_verify( payload, payload_sz, &public_keys[1UL-i], sig ) );
      FD_TEST( !fd_bls_agg_verify( request_data, FD_KEYGUARD_BLS_PUBKEY_SZ+payload_sz, &public_keys[i], sig ) );
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
test_bls_request_rejected( int truncated ) {
  setup();
  memcpy( ctx._data, keys[0].public_key, FD_KEYGUARD_BLS_PUBKEY_SZ );
  if( !truncated ) ctx._data[0] ^= 1U;
  ctx._data[ FD_KEYGUARD_BLS_PUBKEY_SZ ] = 3U;
  ulong sz = truncated ? FD_KEYGUARD_BLS_PUBKEY_SZ-1UL : FD_KEYGUARD_BLS_PUBKEY_SZ+11UL;

  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    fd_log_level_core_set( 8 );
    after_frag( &ctx, 0UL, 0UL, FD_KEYGUARD_SIGN_TYPE_BLS, sz, 0UL, 0UL, &stem );
    _exit( 0 );
  }
  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_bls_request_signing();
  test_ed25519_request_signing();
  test_bls_request_rejected( 0 );
  test_bls_request_rejected( 1 );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
