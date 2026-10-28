#include "fd_failover_tls.h"

#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_mock.h"

#include <string.h>

/* ALPN id, TLS length-prefixed */
static uchar const ALPN[] = "\x17" "fd-failover/on-demand/1";

FD_STATIC_ASSERT( sizeof(ALPN)==25UL, alpn_size );

int
fd_failover_tls_ctx_init( fd_failover_tls_ctx_t * ctx,
                          uchar const             public_key[ 32 ],
                          fd_tls_sign_t           signer ) {
  fd_failover_tls_ctx_fini( ctx );

  uchar seed[ 32 ];
  if( FD_UNLIKELY( !fd_rng_secure( seed, 32UL ) ) ) return -1;
  fd_chacha_rng_t * rng = fd_chacha_rng_join( fd_chacha_rng_new( ctx->rng, FD_CHACHA_RNG_MODE_MOD ) );
  FD_TEST( rng );
  fd_chacha_rng_init( rng, seed, FD_CHACHA_RNG_ALGO_CHACHA20 );
  fd_memzero_explicit( seed, sizeof(seed) );

  fd_tls_t * tls = fd_tls_join( fd_tls_new( &ctx->tls ) );
  FD_TEST( tls );
  tls->rng  = rng;
  tls->sign = signer;
  fd_memcpy( tls->cert_public_key, public_key, 32UL );
  fd_x509_mock_cert( tls->cert_x509, tls->cert_public_key );
  tls->cert_x509_sz = FD_X509_MOCK_CERT_SZ;
  fd_memcpy( tls->alpn, ALPN, sizeof(ALPN)-1UL );
  tls->alpn_sz = sizeof(ALPN)-1UL;
  tls->quic    = 0;
  tls->req_client_cert = 1;

  /* The TLS configuration is ready for new connections. */
  ctx->ready = 1;
  return 0;
}

void
fd_failover_tls_ctx_fini( fd_failover_tls_ctx_t * ctx ) {
  /* Wiping the context prevents new connections until reinitialization. */
  fd_memzero_explicit( ctx, sizeof(*ctx) );
}

int
fd_failover_tls_new( fd_failover_tls_t *     tls,
                     fd_failover_tls_ctx_t * ctx,
                     int                     fd,
                     int                     dial_peer ) {
  if( FD_UNLIKELY( !ctx->ready ) ) return -1;
  /* Start an unverified, unpaired connection. */
  fd_memset( tls, 0, sizeof(*tls) );
  tls->fd = fd;
  fd_tlsrec_conn_init( &tls->conn, &ctx->tls, !dial_peer );
  /* Fresh X25519 key share per connection, straight from the kernel. */
  uchar seed[ 32 ];
  if( FD_UNLIKELY( !fd_rng_secure( seed, 32UL ) ) ) return -1;
  fd_chacha_rng_init( ctx->rng, seed, FD_CHACHA_RNG_ALGO_CHACHA20 );
  fd_memzero_explicit( seed, sizeof(seed) );
  if( FD_UNLIKELY( !fd_rng_secure( tls->conn.tls.kex_private_key, 32UL ) ) ) return -1;
  fd_x25519_public( tls->conn.tls.kex_public_key, tls->conn.tls.kex_private_key );
  fd_tlsrec_sock_init( &tls->sock );
  return 0;
}

int
fd_failover_tls_client_hello( fd_failover_tls_t * tls, uchar * out, ulong * out_sz ) {
  ulong app_sz = 0UL;
  return fd_tlsrec_conn_rx( &tls->conn, NULL, out, out_sz, NULL, &app_sz );
}

int
fd_failover_tls_accept_flight( fd_failover_tls_t * tls, uchar const * data, ulong sz ) {
  if( fd_tlsrec_sock_tx_pending( &tls->sock ) || tls->received>FD_FAILOVER_TLS_PREPAIR_MAX ||
      sz>FD_FAILOVER_TLS_PREPAIR_MAX-tls->received ) return -1;
  fd_tlsrec_slice_t rx[1];
  fd_tlsrec_slice_init( rx, (uchar *)data, sz );
  ulong tx_sz = sizeof(tls->sock.tx_buf);
  ulong app_sz = 0UL;
  int rc = fd_tlsrec_conn_rx( &tls->conn, rx, tls->sock.tx_buf, &tx_sz, NULL, &app_sz );
  tls->sock.tx_sz = tx_sz;
  tls->received += sz;
  return rc || !fd_tlsrec_slice_is_empty( rx ) || app_sz ? -1 : 0;
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

static int
pull( fd_failover_tls_t * tls ) {
  if( !tls->paired && tls->received>=FD_FAILOVER_TLS_PREPAIR_MAX ) return -1;
  ulong rx_sz = 0UL;
  int   err   = fd_tlsrec_sock_rx( &tls->sock, &tls->conn, tls->fd, &rx_sz );
  if( !tls->paired ) tls->received += rx_sz;
  if( FD_LIKELY( !err ) ) return 0;
  if( err==FD_TLSREC_SOCK_ERR_EOF ) tls->peer_closed = 1;
  return -1;
}

int
fd_failover_tls_handshake( fd_failover_tls_t * tls ) {
  if( FD_LIKELY( tls->verified ) ) return 1; /* Verification is final for this connection. */
  /* A failed handshake stays failed until the channel closes it. */
  if( FD_UNLIKELY( fd_tlsrec_conn_is_failed( &tls->conn ) ) ) {
    FD_LOG_DEBUG(( "failover TLS handshake failed: %s", fd_tls_reason_cstr( tls->conn.hs.base.reason ) ));
    return -1;
  }
  if( FD_UNLIKELY( fd_tlsrec_sock_flush( &tls->sock, tls->fd )<0 ) ) return -1;
  if( FD_LIKELY( !fd_tlsrec_conn_is_ready( &tls->conn ) ) ) {
    if( FD_UNLIKELY( pull( tls ) ) ) return -1;
    if( FD_UNLIKELY( fd_tlsrec_conn_is_failed( &tls->conn ) ) ) {
      FD_LOG_DEBUG(( "failover TLS handshake failed: %s", fd_tls_reason_cstr( tls->conn.hs.base.reason ) ));
      return -1;
    }
    if( FD_LIKELY( !fd_tlsrec_conn_is_ready( &tls->conn ) ) ) return 0; /* Continue on a later poll. */
  }

  /* Handshake done, the peer signed with some key and agreed on our ALPN.
     We keep that key, the channel checks it against HELLO. */

  if( !fd_tlsrec_conn_is_server( &tls->conn ) ) {
    fd_tls_estate_cli_t const * cli = &tls->conn.hs.cli;
    if( FD_UNLIKELY( cli->server_key_type!=FD_TLS_KEY_ED25519 ||
                     cli->server_pubkey_len!=32UL || !cli->alpn_negotiated ) ) return -1;
    fd_memcpy( tls->peer_pubkey, cli->server_pubkey, 32UL );
  } else {
    fd_tls_estate_srv_t const * srv = &tls->conn.hs.srv;
    fd_memcpy( tls->peer_pubkey, srv->client_pubkey, 32UL );
  }
  /* TLS verified the peer key, HELLO must still authorize the member. */
  tls->verified = 1;
  return 1;
}

long
fd_failover_tls_read( fd_failover_tls_t * tls,
                      void *              buf,
                      ulong               sz ) {
  if( FD_UNLIKELY( fd_tlsrec_conn_is_failed( &tls->conn ) ) ) return -1L;
  if( FD_LIKELY( !fd_tlsrec_sock_rx_avail( &tls->sock ) ) ) {
    if( FD_UNLIKELY( fd_tlsrec_sock_flush( &tls->sock, tls->fd )<0 ) ) return -1L;
    if( FD_UNLIKELY( pull( tls ) ) ) return -1L;
  }
  return (long)fd_tlsrec_sock_rx_pop( &tls->sock, buf, sz );
}

long
fd_failover_tls_write( fd_failover_tls_t * tls,
                       void const *        buf,
                       ulong               sz ) {
  if( FD_UNLIKELY( fd_tlsrec_conn_is_failed( &tls->conn ) || tls->conn.tx_closed ) ) return -1L;
  int rc = fd_tlsrec_sock_flush( &tls->sock, tls->fd );
  if( FD_UNLIKELY( rc ) ) return rc<0 ? -1L : 0L; /* Earlier output is still parked. */
  ulong consumed = 0UL;
  if( FD_UNLIKELY( fd_tlsrec_sock_tx( &tls->sock, &tls->conn, tls->fd, buf, sz, &consumed ) ) ) return -1L;
  return (long)consumed;
}
