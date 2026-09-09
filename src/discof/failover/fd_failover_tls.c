#include "fd_failover_tls.h"

#include "../../disco/keyguard/fd_keyload.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_mock.h"

#include <string.h>

/* ALPN id, TLS length-prefixed */
static uchar const ALPN[] = { 13, 'f','d','-','f','a','i','l','o','v','e','r','/','2' };

static void
sign_fn( void *      _ctx,
         uchar       sig[ static 64 ],
         uchar const payload[ static 130 ] ) {
  fd_failover_tls_ctx_t * ctx = _ctx;
  fd_ed25519_sign( sig, payload, 130UL, ctx->public_key, ctx->private_key, ctx->sha );
}

int
fd_failover_tls_ctx_init( fd_failover_tls_ctx_t * ctx,
                          uchar const *           keypair,
                          uchar const *           peer_pubkey ) {
  fd_failover_tls_ctx_fini( ctx );
  if( FD_UNLIKELY( !ctx->private_key ) ) ctx->private_key = fd_keyload_alloc_protected_pages( 1UL, 2UL );

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha ) ) );

  uchar public_key[ 32 ];
  fd_ed25519_public_from_private( public_key, keypair, ctx->sha );
  if( FD_UNLIKELY( memcmp( public_key, keypair+32UL, 32UL ) || !memcmp( public_key, peer_pubkey, 32UL ) ) ) return -1;

  memcpy( ctx->private_key, keypair,      32UL );
  memcpy( ctx->public_key,  keypair+32UL, 32UL );
  memcpy( ctx->peer_pubkey, peer_pubkey,  32UL );

  uchar seed[ 32 ];
  if( FD_UNLIKELY( !fd_rng_secure( seed, 32UL ) ) ) { fd_failover_tls_ctx_fini( ctx ); return -1; }
  fd_chacha_rng_t * rng = fd_chacha_rng_join( fd_chacha_rng_new( ctx->rng, FD_CHACHA_RNG_MODE_MOD ) );
  FD_TEST( rng );
  fd_chacha_rng_init( rng, seed, FD_CHACHA_RNG_ALGO_CHACHA20 );
  fd_memzero_explicit( seed, sizeof(seed) );

  fd_tls_t * tls = fd_tls_join( fd_tls_new( &ctx->tls ) );
  FD_TEST( tls );
  tls->rng  = rng;
  tls->sign = (fd_tls_sign_t){ .ctx=ctx, .sign_fn=sign_fn };
  if( FD_UNLIKELY( !fd_rng_secure( tls->kex_private_key, 32UL ) ) ) { fd_failover_tls_ctx_fini( ctx ); return -1; }
  fd_x25519_public( tls->kex_public_key, tls->kex_private_key );
  memcpy( tls->cert_public_key, ctx->public_key, 32UL );
  fd_x509_mock_cert( tls->cert_x509, tls->cert_public_key );
  tls->cert_x509_sz = FD_X509_MOCK_CERT_SZ;
  memcpy( tls->alpn, ALPN, sizeof(ALPN) );
  tls->alpn_sz = sizeof(ALPN);
  tls->quic    = 0;

  ctx->ready = 1;
  return 0;
}

void
fd_failover_tls_ctx_fini( fd_failover_tls_ctx_t * ctx ) {
  uchar * private_key = ctx->private_key;
  if( FD_LIKELY( private_key ) ) fd_memzero_explicit( private_key, 32UL );
  fd_memzero_explicit( ctx, sizeof(*ctx) );
  ctx->private_key = private_key;
}

int
fd_failover_tls_new( fd_failover_tls_t *     tls,
                     fd_failover_tls_ctx_t * ctx,
                     int                     fd,
                     int                     dial_peer ) {
  if( FD_UNLIKELY( !ctx->ready ) ) return -1;
  fd_memset( tls, 0, sizeof(*tls) );
  tls->ctx       = ctx;
  tls->fd        = fd;
  tls->dial_peer = dial_peer;
  fd_tlsrec_conn_init( &tls->conn, &ctx->tls, !dial_peer );
  /* Fresh X25519 key share per connection.  The template key would
     otherwise serve every session of this process. */
  fd_chacha_rng_read32( tls->conn.tls.rng, tls->conn.tls.kex_private_key );
  fd_x25519_public( tls->conn.tls.kex_public_key, tls->conn.tls.kex_private_key );
  if( FD_LIKELY( dial_peer ) ) {
    /* Pin before ClientHello so a wrong server fails in the handshake */
    tls->conn.hs.cli.server_pubkey_pin = 1;
    tls->conn.hs.cli.server_pubkey_len = 32UL;
    memcpy( tls->conn.hs.cli.server_pubkey, ctx->peer_pubkey, 32UL );
  }
  fd_tlsrec_sock_init( &tls->sock );
  fd_failover_tls_budget( tls );
  return 0;
}

void
fd_failover_tls_fini( fd_failover_tls_t * tls ) {
  if( FD_LIKELY( tls->fd!=-1 && fd_tlsrec_conn_is_ready( &tls->conn ) && !tls->conn.tx_closed ) ) {
    (void)fd_tlsrec_sock_close( &tls->sock, &tls->conn, tls->fd );
  }
  fd_memzero_explicit( &tls->conn, sizeof(tls->conn) );
  fd_memzero_explicit( &tls->sock, sizeof(tls->sock) );
  tls->fd       = -1;
  tls->verified = 0;
  tls->paired   = 0;
  tls->received = 0UL;
}

void
fd_failover_tls_budget( fd_failover_tls_t * tls ) {
  tls->read_budget  = 1;
  tls->write_budget = 1;
}

/* flush: 0 if nothing is parked, 1 if send would block, -1 on error */

static int
flush( fd_failover_tls_t * tls ) {
  int rc = fd_tlsrec_sock_flush( &tls->sock, tls->fd );
  return rc<0 ? -1 : rc;
}

/* pull reads one batch of ciphertext into the record layer.  Charges
   the read budget and the pre-pair limit.  Returns 0 (maybe nothing
   read) or -1 on error or peer close. */

static int
pull( fd_failover_tls_t * tls ) {
  if( FD_UNLIKELY( !tls->read_budget ) ) return 0;
  tls->read_budget--;
  ulong rx_sz = 0UL;
  if( FD_UNLIKELY( fd_tlsrec_sock_rx( &tls->sock, &tls->conn, tls->fd, &rx_sz ) ) ) return -1;
  if( FD_LIKELY( !tls->paired ) ) {
    tls->received += rx_sz;
    if( FD_UNLIKELY( tls->received>FD_FAILOVER_TLS_PREPAIR_MAX ) ) return -1;
  }
  return 0;
}

int
fd_failover_tls_handshake( fd_failover_tls_t * tls ) {
  if( FD_LIKELY( tls->verified ) ) return 1;
  if( FD_UNLIKELY( fd_tlsrec_conn_is_failed( &tls->conn ) ) ) {
    FD_LOG_DEBUG(( "failover TLS handshake failed: %s", fd_tls_reason_cstr( tls->conn.hs.base.reason ) ));
    return -1;
  }
  if( FD_UNLIKELY( flush( tls )<0 ) ) return -1;
  if( FD_LIKELY( !fd_tlsrec_conn_is_ready( &tls->conn ) ) ) {
    if( FD_UNLIKELY( pull( tls ) ) ) return -1;
    if( FD_UNLIKELY( fd_tlsrec_conn_is_failed( &tls->conn ) ) ) {
      FD_LOG_DEBUG(( "failover TLS handshake failed: %s", fd_tls_reason_cstr( tls->conn.hs.base.reason ) ));
      return -1;
    }
    if( FD_LIKELY( !fd_tlsrec_conn_is_ready( &tls->conn ) ) ) return 0;
  }

  /* Handshake done: the peer signed with some key and agreed on our
     ALPN.  Require that key to be the pin. */

  fd_failover_tls_ctx_t const * ctx = tls->ctx;
  if( tls->dial_peer ) {
    fd_tls_estate_cli_t const * cli = &tls->conn.hs.cli;
    if( FD_UNLIKELY( !cli->server_pubkey_pin || cli->server_pubkey_len!=32UL || !cli->alpn_negotiated ||
                     memcmp( cli->server_pubkey, ctx->peer_pubkey, 32UL ) ) ) return -1;
  } else {
    /* fd_tls already verified CertificateVerify against client_pubkey
       (zero if the client sent no cert), so only the pin check remains. */
    fd_tls_estate_srv_t const * srv = &tls->conn.hs.srv;
    if( FD_UNLIKELY( memcmp( srv->client_pubkey, ctx->peer_pubkey, 32UL ) ) ) return -1;
  }
  tls->verified = 1;
  return 1;
}

long
fd_failover_tls_read( fd_failover_tls_t * tls,
                      void *              buf,
                      ulong               sz ) {
  if( FD_UNLIKELY( fd_tlsrec_conn_is_failed( &tls->conn ) ) ) return -1L;
  if( FD_LIKELY( !fd_tlsrec_sock_rx_avail( &tls->sock ) ) ) {
    if( FD_UNLIKELY( tls->conn.rx_closed ) ) return -1L;
    if( FD_UNLIKELY( flush( tls )<0 ) ) return -1L;
    if( FD_UNLIKELY( pull( tls ) ) ) return -1L;
  }
  return (long)fd_tlsrec_sock_rx_pop( &tls->sock, buf, sz );
}

long
fd_failover_tls_write( fd_failover_tls_t * tls,
                       void const *        buf,
                       ulong               sz ) {
  if( FD_UNLIKELY( fd_tlsrec_conn_is_failed( &tls->conn ) || tls->conn.tx_closed ) ) return -1L;
  if( FD_UNLIKELY( fd_tlsrec_sock_tx_pending( &tls->sock ) ) ) {
    int rc = flush( tls );
    if( rc ) return rc<0 ? -1L : 0L;
  }
  if( FD_UNLIKELY( !tls->write_budget ) ) return 0L;
  tls->write_budget--;
  ulong consumed = 0UL;
  if( FD_UNLIKELY( fd_tlsrec_sock_tx( &tls->sock, &tls->conn, tls->fd, buf, sz, &consumed ) ) ) return -1L;
  return (long)consumed;
}
