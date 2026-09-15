#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

/* fuzz_tls parses fd_tls handshaking.  The first few bytes are used as
   entropy to reconstruct a fake state. */

#include "fd_tls.h"
#include "fd_tls_estate.h"
#include "test_tls_helper.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_mock.h"
#include "../../util/sanitize/fd_fuzz.h"

#include <assert.h>
#include <stdlib.h>

static void
_tls_secrets( void const * handshake,
              void const * recv_secret,
              void const * send_secret,
              uint         encryption_level ) {
  (void)handshake;
  (void)recv_secret;
  (void)send_secret;
  (void)encryption_level;
}

static int
_tls_sendmsg( void const * handshake,
              void const * record,
              ulong        record_sz,
              uint         encryption_level,
              int          flush ) {
  (void)handshake;
  (void)record;
  (void)record_sz;
  (void)encryption_level;
  (void)flush;
  return 1;
}

static ulong
_tls_quic_tp_self( void *  handshake,
                   uchar * quic_tp,
                   ulong   quic_tp_bufsz ) {
  (void)handshake;
  static uchar const tp_buf[] = { 0x01, 0x02, 0x47, 0xd0 };
  assert( quic_tp_bufsz >= sizeof(tp_buf) );
  fd_memcpy( quic_tp, tp_buf, sizeof(tp_buf) );
  return sizeof(tp_buf);
}

static void
_tls_quic_tp_peer( void  *       handshake,
                   uchar const * quic_tp,
                   ulong         quic_tp_sz ) {
  (void)handshake;
  (void)quic_tp;
  (void)quic_tp_sz;
}

static fd_tls_t tls_tmpl[1] = {{
  .secrets_fn      = _tls_secrets,
  .sendmsg_fn      = _tls_sendmsg,
  .quic_tp_self_fn = _tls_quic_tp_self,
  .quic_tp_peer_fn = _tls_quic_tp_peer,

  .alpn    = "\xasolana-tpu",
  .alpn_sz = 11U,
}};

/* Uncompressed P-256 generator point, used as a well-formed ECDSA
   server public key */

static uchar const p256_g[ 65 ] = {
  0x04,
  0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
  0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
  0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
  0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5,
};

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set(3); /* crash on warning log */

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1000U, 0UL ) );

  for( ulong b=0; b<32UL; b++ ) tls_tmpl->kex_private_key[b] = fd_rng_uchar( rng );
  fd_x25519_public( tls_tmpl->kex_public_key, tls_tmpl->kex_private_key );

  static fd_tls_test_sign_ctx_t sign_ctx[1];
  fd_tls_test_sign_ctx( sign_ctx, rng );
  tls_tmpl->sign = fd_tls_test_sign( sign_ctx );
  fd_memcpy( tls_tmpl->cert_public_key, sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( tls_tmpl->cert_x509, tls_tmpl->cert_public_key );
  tls_tmpl->cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

/* Could be a bitmap */

static uchar
_tls_valid_srv_hs_state[ 16 ] = {
  [FD_TLS_HS_FAIL         ] = 1,
  [FD_TLS_HS_CONNECTED    ] = 1,
  [FD_TLS_HS_START        ] = 1,
  [FD_TLS_HS_WAIT_CERT    ] = 1,
  [FD_TLS_HS_WAIT_CV      ] = 1,
  [FD_TLS_HS_WAIT_FINISHED] = 1
};

static uchar
_tls_valid_cli_hs_state[ 16 ] = {
  [FD_TLS_HS_FAIL         ] = 1,
  [FD_TLS_HS_CONNECTED    ] = 1,
  [FD_TLS_HS_START        ] = 1,
  [FD_TLS_HS_WAIT_SH      ] = 1,
  [FD_TLS_HS_WAIT_EE      ] = 1,
  [FD_TLS_HS_WAIT_CERT_CR ] = 1,
  [FD_TLS_HS_WAIT_CERT    ] = 1,
  [FD_TLS_HS_WAIT_CV      ] = 1,
  [FD_TLS_HS_WAIT_FINISHED] = 1
};

int
LLVMFuzzerTestOneInput( uchar const * input,
                        ulong         input_sz ) {

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1001U, 0UL ) );

  if( input_sz<8UL ) return -1;
  ulong state = FD_LOAD( ulong, input );

  uchar const * payload    = input    + 8UL;
  ulong         payload_sz = input_sz - 8UL;

  int   is_server   = !!( state & (1UL<< 0) );
  int   has_alpn    = !!( state & (1UL<< 1) );
  int   has_x509    = !!( state & (1UL<< 2) );
  int   is_quic     = !!( state & (1UL<< 3) );
  uchar hs_state    = (uchar)( ( state>> 4 )&0xFUL );
  int   cli_cert    = !!( state & (1UL<<10) );
  uint  enc_lvl     = (uint)(  ( state>>11 )&0x3UL );
  int   pubkey_pin  = !!( state & (1UL<<13) );
  int   key_p256    = !!( state & (1UL<<14) );
  int   session_id  = !!( state & (1UL<<15) );
  int   has_sni     = !!( state & (1UL<<16) );
  int   hello_retry = !!( state & (1UL<<17) );
  int   alpn_neg    = !!( state & (1UL<<18) );
  int   cert_verify = !!( state & (1UL<<19) );
  int   no_signer   = !!( state & (1UL<<21) );
  int   cert_empty  = !!( state & (1UL<<22) );

  fd_tls_t tls[1]; fd_memcpy( tls, tls_tmpl, sizeof(fd_tls_t) );
  fd_chacha_rng_t chacha[1];
  tls->rng = fd_tls_test_rand( chacha, rng );
  tls->quic = (uchar)(is_quic&1);
  if( !has_alpn  ) tls->alpn_sz      = 0UL;
  if( !has_x509  ) tls->cert_x509_sz = 0UL;
  if( no_signer && !is_server ) tls->sign.sign_fn = NULL;  /* servers must always have a signer */
  if( has_sni ) {
    char const * name = "fuzz.example.com";
    tls->server_name_len = (ushort)strlen( name );
    fd_memcpy( tls->server_name, name, tls->server_name_len+1UL );
  }
  static fd_x509_ca_store_t const empty_ca_store;
  if( cert_verify ) tls->ca_store = &empty_ca_store;

  fd_tls_estate_base_t base = {
    .state    = hs_state,
    .server   = (uchar)( is_server&1 ),
  };
  for( ulong b=0; b<32UL; b++ ) base.client_random[b] = fd_rng_uchar( rng );

  if( is_server ) {
    if( !_tls_valid_srv_hs_state[ hs_state ] ) return -1;
    fd_tls_estate_srv_t hs[1] = {{
      .base        = base,
      .client_cert = (uchar)(cli_cert&1),
      .hello_retry = (uchar)(hello_retry&1),
    }};
    for( ulong b=0; b<32UL; b++ ) hs->client_pubkey[b] = fd_rng_uchar( rng );
    fd_tls_server_handshake( tls, hs, payload, payload_sz, enc_lvl );
  } else {
    if( !_tls_valid_cli_hs_state[ hs_state ] ) return -1;
    fd_tls_estate_cli_t hs[1] = {{
      .base              = base,
      .client_cert       = (uchar)(cli_cert&1),
      .client_cert_empty = (uchar)(cert_empty&1),
      .server_pubkey_pin = (uchar)(pubkey_pin&1),
      .alpn_negotiated   = (uchar)(alpn_neg&1),
    }};
    if( key_p256 ) {
      fd_memcpy( hs->server_pubkey, p256_g, 65UL );
      hs->server_pubkey_len = 65UL;
      hs->server_key_type   = FD_TLS_KEY_ECDSA_P256;
    } else {
      fd_memcpy( hs->server_pubkey, tls->cert_public_key, 32UL );
      hs->server_pubkey_len = 32UL;
      hs->server_key_type   = FD_TLS_KEY_ED25519;
    }
    if( session_id ) {
      for( ulong b=0; b<32UL; b++ ) hs->session_id[b] = fd_rng_uchar( rng );
      hs->session_id_sz = 32;
    }
    fd_sha256_init( &hs->transcript );
    fd_tls_client_handshake( tls, hs, payload, payload_sz, enc_lvl );
  }

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
