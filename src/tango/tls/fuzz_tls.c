#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

/* fuzz_tls parses fd_tls handshaking.  The first few bytes are used as
   entropy to reconstruct a fake state. */

#include "fd_tls.h"
#include "fd_tls_estate.h"
#include "test_tls_helper.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_mock.h"

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

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  fd_boot( argc, argv );
  atexit( fd_halt );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1000U, 0UL ) );

  for( ulong b=0; b<32UL; b++ ) tls_tmpl->kex_private_key[b] = fd_rng_uchar( rng );
  fd_x25519_public( tls_tmpl->kex_public_key, tls_tmpl->kex_private_key );

  for( ulong b=0; b<32UL; b++ ) tls_tmpl->cert_private_key[b] = fd_rng_uchar( rng );
  fd_sha512_t _sha[1];
  fd_ed25519_public_from_private( tls_tmpl->cert_public_key, tls_tmpl->cert_private_key, _sha );
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

  int   is_server = !!( state & (1UL<< 0) );
  int   has_alpn  = !!( state & (1UL<< 1) );
  int   has_x509  = !!( state & (1UL<< 2) );
  int   is_quic   = !!( state & (1UL<< 3) );
  uchar hs_state  = (uchar)( ( state>> 4 )&0xFUL );
  int   srv_rpk   = !!( state & (1UL<< 8) );
  int   cli_rpk   = !!( state & (1UL<< 9) );
  int   cli_cert  = !!( state & (1UL<<10) );
  uint  enc_lvl   = (uint)(  ( state>>11 )&0x3UL );

  fd_tls_t tls[1]; fd_memcpy( tls, tls_tmpl, sizeof(fd_tls_t) );
  tls->rand = fd_tls_test_rand( rng );
  tls->quic = is_quic&1;
  if( !has_alpn ) tls->alpn_sz      = 0UL;
  if( !has_x509 ) tls->cert_x509_sz = 0UL;

  fd_tls_estate_base_t base = {
    .state  = hs_state,
    .server = is_server&1,
  };
  for( ulong b=0; b<32UL; b++ ) base.client_random[b] = fd_rng_uchar( rng );

  if( is_server ) {
    if( !_tls_valid_srv_hs_state[ hs_state ] ) return -1;
    fd_tls_estate_srv_t hs[1] = {{
      .base            = base,
      .server_cert_rpk = srv_rpk &1,
      .client_cert     = cli_cert&1,
      .client_cert_rpk = cli_rpk &1,
    }};
    fd_tls_server_handshake( tls, hs, payload, payload_sz, enc_lvl );
  } else {
    if( !_tls_valid_cli_hs_state[ hs_state ] ) return -1;
    fd_tls_estate_cli_t hs[1] = {{
      .base            = base,
      .server_cert_rpk = srv_rpk &1,
      .client_cert     = cli_cert&1,
      .client_cert_rpk = cli_rpk &1,
    }};
    fd_tls_client_handshake( tls, hs, payload, payload_sz, enc_lvl );
  }

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}
