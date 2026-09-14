#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

/* fuzz_tlsrec drives a client and a server fd_tlsrec conn against each
   other.  The fuzz input is a script of operations.  Each op controls
   how the next chunk of wire data is fragmented and optionally corrupts
   or injects wire bytes before delivery.  Oracle: if the wire was never
   tampered with, the handshake must complete and app data must round
   trip byte-exact. */

#include "fd_tlsrec.h"
#include "../tls/test_tls_helper.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_mock.h"
#include "../../util/sanitize/fd_fuzz.h"

#include <assert.h>
#include <stdlib.h>

static int      last_rc;
static fd_tls_t client_tmpl[1];
static fd_tls_t server_tmpl[1];

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  /* fd_tlsrec logs a WARNING on every protocol failure, which is the
     expected outcome for tampered inputs.  Only crash on ERR+. */
  fd_log_level_logfile_set(4);
  fd_log_level_stderr_set(4);
  fd_log_level_core_set(4);

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1000U, 0UL ) );

  static fd_tls_test_sign_ctx_t client_sign_ctx[1];
  static fd_tls_test_sign_ctx_t server_sign_ctx[1];
  fd_tls_test_sign_ctx( client_sign_ctx, rng );
  fd_tls_test_sign_ctx( server_sign_ctx, rng );

  client_tmpl->sign = fd_tls_test_sign( client_sign_ctx );
  server_tmpl->sign = fd_tls_test_sign( server_sign_ctx );

  for( ulong j=0UL; j<32UL; j++ ) {
    client_tmpl->kex_private_key[j] = fd_rng_uchar( rng );
    server_tmpl->kex_private_key[j] = fd_rng_uchar( rng );
  }
  fd_x25519_public( client_tmpl->kex_public_key, client_tmpl->kex_private_key );
  fd_x25519_public( server_tmpl->kex_public_key, server_tmpl->kex_private_key );

  fd_memcpy( client_tmpl->cert_public_key, client_sign_ctx->public_key, 32UL );
  fd_memcpy( server_tmpl->cert_public_key, server_sign_ctx->public_key, 32UL );
  fd_x509_mock_cert( client_tmpl->cert_x509, client_tmpl->cert_public_key );
  fd_x509_mock_cert( server_tmpl->cert_x509, server_tmpl->cert_public_key );
  client_tmpl->cert_x509_sz = FD_X509_MOCK_CERT_SZ;
  server_tmpl->cert_x509_sz = FD_X509_MOCK_CERT_SZ;

  fd_memcpy( client_tmpl->alpn, "\x02h2", 3UL ); client_tmpl->alpn_sz = 3UL;
  fd_memcpy( server_tmpl->alpn, "\x02h2", 3UL ); server_tmpl->alpn_sz = 3UL;

  fd_rng_delete( fd_rng_leave( rng ) );
  return 0;
}

/* Simulated TCP byte streams (one per direction) */

struct wire {
  uchar buf[ 4UL*FD_TLSREC_CAP ];
  ulong head;  /* next byte to deliver */
  ulong tail;  /* end of queued bytes */
};
typedef struct wire wire_t;

static int
wire_push( wire_t *      w,
           uchar const * data,
           ulong         sz ) {
  if( w->tail + sz > sizeof(w->buf) ) {
    memmove( w->buf, w->buf + w->head, w->tail - w->head );
    w->tail -= w->head; w->head = 0UL;
    if( w->tail + sz > sizeof(w->buf) ) return 0;
  }
  fd_memcpy( w->buf + w->tail, data, sz );
  w->tail += sz;
  return 1;
}

struct script {
  uchar const * cur;
  uchar const * end;
};
typedef struct script script_t;

static uchar
script_u8( script_t * s ) {
  if( s->cur >= s->end ) return 0;
  return *(s->cur++);
}

static ushort
script_u16( script_t * s ) {
  ushort lo = script_u8( s );
  ushort hi = script_u8( s );
  return (ushort)( lo | (hi<<8) );
}

/* deliver feeds up to frag_sz queued bytes from in to conn and queues
   whatever conn wants to send onto out.  Returns the tlsrec rc. */

static int
deliver( fd_tlsrec_conn_t * conn,
         wire_t *           in,
         wire_t *           out,
         ulong              frag_sz,
         uchar *            app_rx,
         ulong *            app_rx_sz,
         int *              oom ) {
  ulong avail = in->tail - in->head;
  ulong sz    = fd_ulong_min( avail, frag_sz );
  fd_tlsrec_slice_t tcp_rx[1];
  fd_tlsrec_slice_init( tcp_rx, in->buf + in->head, sz );

  uchar tcp_tx[ FD_TLSREC_CAP ];
  ulong tcp_tx_sz = sizeof(tcp_tx);
  *app_rx_sz = sz + FD_TLSREC_CAP;  /* documented worst case for one rx call */
  int rc = fd_tlsrec_conn_rx( conn, sz ? tcp_rx : NULL, tcp_tx, &tcp_tx_sz, app_rx, app_rx_sz );
  last_rc = rc;
  in->head += (ulong)( tcp_rx->data - (in->buf + in->head) );
  assert( in->head <= in->tail );
  if( rc==FD_TLSREC_SUCCESS ) assert( fd_tlsrec_slice_is_empty( tcp_rx ) );
  assert( tcp_tx_sz  <= FD_TLSREC_CAP );
  assert( *app_rx_sz <= sz + FD_TLSREC_CAP );
  if( !wire_push( out, tcp_tx, tcp_tx_sz ) ) *oom = 1;
  return rc;
}

int
LLVMFuzzerTestOneInput( uchar const * input,
                        ulong         input_sz ) {

  if( input_sz < 2UL ) return -1;
  script_t s[1] = {{ .cur = input, .end = input + input_sz }};

  uchar flags = script_u8( s );
  int client_cert = !!( flags & 1 );
  int pin_pubkey  = !!( flags & 2 );
  int wrong_pin   = !!( flags & 4 );
  int use_sni     = !!( flags & 8 );
  int no_alpn     = !!( flags & 16 );

  static FD_TL fd_tlsrec_conn_t client[1];
  static FD_TL fd_tlsrec_conn_t server[1];
  static FD_TL wire_t c2s[1], s2c[1];
  static FD_TL uchar app_rx[ 2UL*FD_TLSREC_CAP ];
  static FD_TL uchar app_tx[ FD_TLSREC_PLAINTEXT_MAX ];
  c2s->head = c2s->tail = 0UL;
  s2c->head = s2c->tail = 0UL;

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1001U, 0UL ) );
  fd_chacha_rng_t client_chacha[1], server_chacha[1];

  fd_tls_t client_tls[1]; fd_memcpy( client_tls, client_tmpl, sizeof(fd_tls_t) );
  fd_tls_t server_tls[1]; fd_memcpy( server_tls, server_tmpl, sizeof(fd_tls_t) );
  client_tls->rng = fd_tls_test_rand( client_chacha, rng );
  server_tls->rng = fd_tls_test_rand( server_chacha, rng );
  if( !client_cert ) { client_tls->cert_x509_sz = 0UL; client_tls->sign.sign_fn = NULL; }
  if( no_alpn ) {
    client_tls->alpn_sz = 0UL;
    server_tls->alpn_sz = 0UL; fd_memset( server_tls->alpn, 0, sizeof(server_tls->alpn) );
  }
  if( use_sni ) {
    char const * name = "fuzz.example.com";
    client_tls->server_name_len = (ushort)strlen( name );
    fd_memcpy( client_tls->server_name, name, client_tls->server_name_len+1UL );
  }

  assert( fd_tlsrec_conn_init( client, client_tls, 0 )==client );
  assert( fd_tlsrec_conn_init( server, server_tls, 1 )==server );
  if( pin_pubkey ) {
    fd_memcpy( client->hs.cli.server_pubkey, server_tls->cert_public_key, 32UL );
    if( wrong_pin ) client->hs.cli.server_pubkey[0] ^= 0x01;
    client->hs.cli.server_pubkey_len = 32UL;
    client->hs.cli.server_pubkey_pin = 1;
  }
  /* fd_tls servers always request client auth.  A client without a
     cert answers with an empty Certificate and may consider itself
     connected, but the server rejects it. */
  int expect_fail = ( pin_pubkey && wrong_pin ) || !client_cert;

  int tampered = 0;
  int oom      = 0;
  int failed   = 0;
  ulong app_c2s_sent = 0UL, app_c2s_recv = 0UL;
  ulong app_s2c_sent = 0UL, app_s2c_recv = 0UL;

  /* Kick off: ClientHello */
  ulong app_rx_sz;
  if( deliver( client, s2c, c2s, 0UL, app_rx, &app_rx_sz, &oom ) ) failed = 1;

  for( ulong step=0UL; step<512UL && !failed && !oom; step++ ) {
    uchar op = script_u8( s );
    switch( op & 7 ) {

    case 0: case 1: { /* deliver wire -> server */
      ulong frag = (op & 8) ? FD_TLSREC_CAP : (ulong)script_u16( s ) + 1UL;
      int rc = deliver( server, c2s, s2c, frag, app_rx, &app_rx_sz, &oom );
      if( rc ) failed = 1;
      else app_c2s_recv += app_rx_sz;
      break;
    }

    case 2: case 3: { /* deliver wire -> client */
      ulong frag = (op & 8) ? FD_TLSREC_CAP : (ulong)script_u16( s ) + 1UL;
      int rc = deliver( client, s2c, c2s, frag, app_rx, &app_rx_sz, &oom );
      if( rc ) failed = 1;
      else app_s2c_recv += app_rx_sz;
      break;
    }

    case 4: { /* flip bits in a queued wire byte */
      wire_t * w = (op & 8) ? s2c : c2s;
      ulong avail = w->tail - w->head;
      if( !avail ) break;
      ulong off = (ulong)script_u16( s ) % avail;
      uchar x   = script_u8( s );
      if( !x ) x = 0xff;
      w->buf[ w->head + off ] ^= x;
      tampered = 1;
      break;
    }

    case 5: { /* inject raw bytes into wire */
      wire_t * w = (op & 8) ? s2c : c2s;
      ulong n = script_u8( s );
      n = fd_ulong_min( n, (ulong)(s->end - s->cur) );
      if( !n ) break;
      if( !wire_push( w, s->cur, n ) ) oom = 1;
      s->cur += n;
      tampered = 1;
      break;
    }

    case 6: { /* send app data */
      fd_tlsrec_conn_t * c = (op & 8) ? server : client;
      wire_t *           w = (op & 8) ? s2c    : c2s;
      if( !fd_tlsrec_conn_is_ready( c ) ) break;
      ulong n = (ulong)script_u16( s ) % sizeof(app_tx) + 1UL;
      if( op & 16 ) n = FD_TLSREC_PLAINTEXT_MAX;
      if( (op & 32) && w->head==w->tail ) {
        /* Jump both ends to the record limit so this send is preceded
           by a KeyUpdate.  Only valid with no ciphertext in flight. */
        fd_tlsrec_conn_t * peer = (op & 8) ? client : server;
        if( !peer->rec_buf.sz ) { c->write_seq = FD_TLSREC_KEY_UPDATE_SEQ; peer->read_seq = FD_TLSREC_KEY_UPDATE_SEQ; }
      }
      for( ulong i=0UL; i<n; i++ ) app_tx[i] = (uchar)i;
      fd_tlsrec_slice_t app[1]; fd_tlsrec_slice_init( app, app_tx, n );
      uchar tcp_tx[ FD_TLSREC_CAP ];
      ulong tcp_tx_sz = sizeof(tcp_tx);
      int rc = fd_tlsrec_conn_tx( c, tcp_tx, &tcp_tx_sz, app );
      assert( rc==FD_TLSREC_SUCCESS );
      ulong sent = n - fd_tlsrec_slice_sz( app );
      if( op & 8 ) app_s2c_sent += sent; else app_c2s_sent += sent;
      if( !wire_push( w, tcp_tx, tcp_tx_sz ) ) oom = 1;
      break;
    }

    case 7: { /* key update */
      fd_tlsrec_conn_t * c = (op & 8) ? server : client;
      wire_t *           w = (op & 8) ? s2c    : c2s;
      if( !fd_tlsrec_conn_is_ready( c ) ) break;
      uchar tcp_tx[ 64 ];
      ulong tcp_tx_sz = sizeof(tcp_tx);
      int rc = fd_tlsrec_conn_key_update( c, tcp_tx, &tcp_tx_sz, !!(op & 16) );
      assert( rc==FD_TLSREC_SUCCESS );
      if( !wire_push( w, tcp_tx, tcp_tx_sz ) ) oom = 1;
      break;
    }

    }
  }

  if( !tampered && !expect_fail ) {
    /* Drain both directions.  A clean run must converge. */
    for( ulong i=0UL; i<16UL && !oom && !failed; i++ ) {
      if( deliver( server, c2s, s2c, FD_TLSREC_CAP, app_rx, &app_rx_sz, &oom ) ) { failed = 1; break; }
      app_c2s_recv += app_rx_sz;
      if( deliver( client, s2c, c2s, FD_TLSREC_CAP, app_rx, &app_rx_sz, &oom ) ) { failed = 1; break; }
      app_s2c_recv += app_rx_sz;
      if( c2s->head==c2s->tail && s2c->head==s2c->tail ) break;
    }
    if( failed ) {
      FD_LOG_ERR(( "clean run failed: rc=%d-%s client state=%u reason=%u-%s server state=%u reason=%u-%s",
                   last_rc, fd_tlsrec_strerror( last_rc ),
                   client->hs.base.state, client->hs.base.reason, fd_tls_reason_cstr( client->hs.base.reason ),
                   server->hs.base.state, server->hs.base.reason, fd_tls_reason_cstr( server->hs.base.reason ) ));
    }
    if( !oom ) {
      assert( fd_tlsrec_conn_is_ready( client ) );
      assert( fd_tlsrec_conn_is_ready( server ) );
      assert( c2s->head==c2s->tail );
      assert( s2c->head==s2c->tail );
      assert( app_c2s_sent==app_c2s_recv );
      assert( app_s2c_sent==app_s2c_recv );
      assert( client->hs.cli.alpn_negotiated == !no_alpn );
      assert( client->hs.cli.server_pubkey_len==32UL );
      assert( 0==memcmp( client->hs.cli.server_pubkey, server_tls->cert_public_key, 32UL ) );
    }
  }
  if( pin_pubkey && wrong_pin ) assert( !fd_tlsrec_conn_is_ready( client ) );
  if( !client_cert )             assert( !fd_tlsrec_conn_is_ready( server ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
