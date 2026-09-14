/* test_tls_web: live TLS v1.3 client handshake against public servers.

   fd_tls is TLS1.3/X25519/AES_128_GCM only, ECDSA/Ed25519 chains only.

   This test needs network egress and is NOT part of the automatic
   unit-test set.  Run it by hand:

     build/.../unit-test/test_tls_web */

#include "fd_tls.h"
#include "fd_tls_proto.h"
#include "../tlsrec/fd_tlsrec.h"
#include "../resolv/fd_netdb.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_verify.h"
#include "../../ballet/x509/fd_x509_ca_store.h"
#include "../../util/log/fd_log.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>

static char const * const hosts[] = {
  "www.google.com",
  "www.gstatic.com",
  "mail.google.com",
  "dns.google",
  "www.cloudflare.com",
  "cloudflare.com",
  "crypto.cloudflare.com",
  "one.one.one.one",
  "www.facebook.com",
  "www.instagram.com",
  "www.akamai.com",
  "aws.amazon.com",
  "s3.amazonaws.com",
  "www.apple.com",
  "www.microsoft.com",
  "github.com",
  "www.fastly.com",
  "stackoverflow.com",
  "nginx.org",
  "www.openssl.org",
  "acme-v02.api.letsencrypt.org",
};

#define FD_TLS_WEB_PORT       (443)
#define FD_TLS_WEB_TIMEOUT_MS (10000)

enum { FD_TLS_WEB_OK=0, FD_TLS_WEB_UNREACHABLE=1, FD_TLS_WEB_FAIL=2 };

/* fd_tls_web_result describes the outcome of one probe.  verify_err
   is meaningful whenever verify_called is set, i.e. fd_tls got as far
   as checking the chain, regardless of whether the handshake completed
   (a rejected chain aborts the handshake). */

struct fd_tls_web_result {
  int    hs_ok;
  int    verify_called;
  int    verify_err;        /* FD_X509_VERIFY_{...} */
  int    tlsrec_err;        /* FD_TLSREC_{...} */
  uint   hs_reason;         /* FD_TLS_REASON_{...} */
  int    io_err;            /* errno of the socket op that broke the loop, 0 if none */
  int    timed_out;
  uchar  server_key_type;
  ulong  server_pubkey_len;
  int    alpn_negotiated;
  int    peer_alert;        /* plaintext alert description from the server, -1 if none */
  uchar  hs_state;          /* FD_TLS_HS_{...} at the end of the probe */
};

static long
fd_tls_web_now_ms( void ) {
  return fd_log_wallclock() / 1000000L;
}

static int
fd_tls_web_poll_ms( long deadline_ms ) {
  long ms = deadline_ms - fd_tls_web_now_ms();
  if( ms<=0L ) return 0;
  return (int)fd_long_min( ms, (long)FD_TLS_WEB_TIMEOUT_MS );
}

/* fd_tls_web_send_all writes sz bytes to fd before deadline_ms.
   Returns 0 on success, or a positive errno (ETIMEDOUT on deadline). */

static int
fd_tls_web_send_all( int           fd,
                     uchar const * buf,
                     ulong         sz,
                     long          deadline_ms ) {
  ulong off = 0UL;
  while( off<sz ) {
    ssize_t sent = send( fd, buf+off, sz-off, MSG_NOSIGNAL );
    if( FD_LIKELY( sent>0 ) ) { off += (ulong)sent; continue; }
    if( FD_UNLIKELY( sent<0 && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( sent<0 && errno!=EAGAIN && errno!=EWOULDBLOCK ) ) return errno;
    int ms = fd_tls_web_poll_ms( deadline_ms );
    if( FD_UNLIKELY( ms<=0 ) ) return ETIMEDOUT;
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    (void)poll( &pfd, 1, ms );
  }
  return 0;
}

/* fd_tls_web_connect_one attempts a non-blocking connect to one
   address.  Returns a connected fd, or -1. */

static int
fd_tls_web_connect_one( struct sockaddr const * sa,
                        socklen_t               sa_len,
                        long                    deadline_ms ) {
  int fd = socket( sa->sa_family, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( fd<0 ) ) return -1;

  if( FD_UNLIKELY( connect( fd, sa, sa_len )==-1 && errno!=EINPROGRESS ) ) {
    close( fd );
    return -1;
  }

  for(;;) {
    int ms = fd_tls_web_poll_ms( deadline_ms );
    if( FD_UNLIKELY( ms<=0 ) ) { close( fd ); return -1; }
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    int pr = poll( &pfd, 1, ms );
    if( FD_UNLIKELY( pr<0 && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( pr<=0 ) ) { close( fd ); return -1; }
    int so_err = 0; socklen_t so_err_sz = sizeof(so_err);
    if( FD_UNLIKELY( 0!=getsockopt( fd, SOL_SOCKET, SO_ERROR, &so_err, &so_err_sz ) || so_err ) ) {
      close( fd );
      return -1;
    }
    return fd;
  }
}

/* fd_tls_web_connect_tcp resolves host and tries every returned
   address (IPv4 and IPv6) in order until one connects.  Returns a
   connected fd, or -1 if resolution failed or no address answered. */

static int
fd_tls_web_connect_tcp( char const * host,
                        long         deadline_ms ) {
  fd_addrinfo_t hints = {0};
  hints.ai_family = AF_UNSPEC;

  fd_addrinfo_t * res = NULL;
  static uchar scratch[ 4096 ] __attribute__((aligned(16)));
  void * pscratch = scratch;
  if( FD_UNLIKELY( fd_getaddrinfo( host, &hints, &res, &pscratch, sizeof(scratch) ) || !res ) )
    return -1;

  for( fd_addrinfo_t * ai=res; ai; ai=ai->ai_next ) {
    struct sockaddr_storage ss;
    socklen_t sa_len;
    switch( ai->ai_family ) {
    case AF_INET: {
      struct sockaddr_in * in4 = fd_type_pun( &ss );
      *in4 = *(struct sockaddr_in *)fd_type_pun( ai->ai_addr );
      in4->sin_port = fd_ushort_bswap( FD_TLS_WEB_PORT );
      sa_len = sizeof(struct sockaddr_in);
      break;
    }
    case AF_INET6: {
      struct sockaddr_in6 * in6 = fd_type_pun( &ss );
      *in6 = *(struct sockaddr_in6 *)fd_type_pun( ai->ai_addr );
      in6->sin6_port = fd_ushort_bswap( FD_TLS_WEB_PORT );
      sa_len = sizeof(struct sockaddr_in6);
      break;
    }
    default:
      continue;
    }
    int fd = fd_tls_web_connect_one( fd_type_pun( &ss ), sa_len, deadline_ms );
    if( fd>=0 ) return fd;
  }
  return -1;
}

/* Connection state lives in the caller's frame (not static) so the
   probe is reentrant and nothing outlives the call. */

struct fd_tls_web_conn {
  fd_tlsrec_conn_t conn[1];
  fd_chacha_rng_t  chacha[1];
  uchar            tcp_tx[ FD_TLSREC_CAP ];
  uchar            tcp_rx[ FD_TLSREC_CAP ];
  uchar            app_rx[ FD_TLSREC_CAP ];
};

static int
fd_tls_web_probe( struct fd_tls_web_conn *   c,
                  char const *               host,
                  fd_x509_ca_store_t const * ca_store,
                  struct fd_tls_web_result * result ) {
  fd_memset( result, 0, sizeof(*result) );
  result->peer_alert = -1;

  fd_tls_t tls = {0};

  /* Guard the SNI copy (server_name is a fixed-size buffer) */
  ulong host_len = strlen( host );
  if( FD_UNLIKELY( host_len==0UL || host_len>=sizeof(tls.server_name) ) ) {
    FD_LOG_WARNING(( "host name \"%s\" has invalid length %lu", host, host_len ));
    return FD_TLS_WEB_FAIL;
  }

  long deadline_ms = fd_tls_web_now_ms() + FD_TLS_WEB_TIMEOUT_MS;

  int fd = fd_tls_web_connect_tcp( host, deadline_ms );
  if( FD_UNLIKELY( fd<0 ) ) return FD_TLS_WEB_UNREACHABLE;

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)fd_log_wallclock(), 0UL ) );

  uchar rng_key[32];
  for( ulong i=0UL; i<32UL; i++ ) rng_key[i] = fd_rng_uchar( rng );

  tls.rng = fd_chacha_rng_init(
      fd_chacha_rng_join( fd_chacha_rng_new( c->chacha, FD_CHACHA_RNG_MODE_SHIFT ) ),
      rng_key, FD_CHACHA_RNG_ALGO_CHACHA8 );
  tls.ca_store = ca_store;

  fd_memcpy( tls.server_name, host, host_len+1UL );
  tls.server_name_len = (ushort)host_len;

  for( ulong i=0UL; i<32UL; i++ ) tls.kex_private_key[i] = fd_rng_uchar( rng );
  fd_x25519_public( tls.kex_public_key, tls.kex_private_key );

  fd_tlsrec_conn_t * conn = fd_tlsrec_conn_init( c->conn, &tls, 0 );

  ulong tx_sz = sizeof(c->tcp_tx);
  ulong ar_sz = sizeof(c->app_rx);
  int err = fd_tlsrec_conn_rx( conn, NULL, c->tcp_tx, &tx_sz, c->app_rx, &ar_sz );

  if( FD_UNLIKELY( err!=FD_TLSREC_SUCCESS ) ) {
    result->tlsrec_err = err;
  } else if( FD_UNLIKELY( !tx_sz ) ) {
    result->tlsrec_err = FD_TLSREC_ERR_STATE;  /* client produced no ClientHello */
  } else if( FD_UNLIKELY( (result->io_err = fd_tls_web_send_all( fd, c->tcp_tx, tx_sz, deadline_ms )) ) ) {
    result->timed_out = ( result->io_err==ETIMEDOUT );
  } else {
    for(;;) {
      if( FD_UNLIKELY( fd_tlsrec_conn_is_failed( conn ) ) ) break;
      if( FD_UNLIKELY( fd_tlsrec_conn_is_ready ( conn ) ) ) { result->hs_ok = 1; break; }

      int ms = fd_tls_web_poll_ms( deadline_ms );
      if( FD_UNLIKELY( ms<=0 ) ) { result->timed_out = 1; break; }
      struct pollfd pfd = { .fd = fd, .events = POLLIN };
      int pr = poll( &pfd, 1, ms );
      if( FD_UNLIKELY( pr<0 ) ) {
        if( errno==EINTR ) continue;
        result->io_err = errno;
        break;
      }
      if( FD_UNLIKELY( pr==0 ) ) continue;

      ssize_t n = recv( fd, c->tcp_rx, sizeof(c->tcp_rx), 0 );
      if( FD_UNLIKELY( n==0 ) ) { result->io_err = ECONNRESET; break; }  /* peer closed mid-handshake */
      if( FD_UNLIKELY( n<0 ) ) {
        if( errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR ) continue;
        result->io_err = errno;
        break;
      }

      /* A server that rejects the ClientHello answers with a plaintext
         alert record: type 21, version, length 2, level, description. */
      if( n>=7L && c->tcp_rx[0]==FD_TLS_REC_ALERT && c->tcp_rx[3]==0 && c->tcp_rx[4]==2 )
        result->peer_alert = c->tcp_rx[6];

      fd_tlsrec_slice_t rx[1];
      fd_tlsrec_slice_init( rx, c->tcp_rx, (ulong)n );
      tx_sz = sizeof(c->tcp_tx);
      ar_sz = sizeof(c->app_rx);
      err = fd_tlsrec_conn_rx( conn, rx, c->tcp_tx, &tx_sz, c->app_rx, &ar_sz );
      if( FD_UNLIKELY( err!=FD_TLSREC_SUCCESS || !fd_tlsrec_slice_is_empty( rx ) ) ) {
        result->tlsrec_err = err ? err : FD_TLSREC_ERR_PROTO;
        break;
      }
      if( tx_sz ) {
        result->io_err = fd_tls_web_send_all( fd, c->tcp_tx, tx_sz, deadline_ms );
        if( FD_UNLIKELY( result->io_err ) ) {
          result->timed_out = ( result->io_err==ETIMEDOUT );
          break;
        }
      }
    }
  }

  close( fd );
  fd_rng_delete( fd_rng_leave( rng ) );

  /* Capture everything we know before deciding pass/fail, so a failed
     handshake still reports why (verify_err, hs_reason, ...). */
  result->hs_reason         = conn->hs.base.reason;
  result->hs_state          = conn->hs.base.state;
  result->verify_called     = result->hs_ok || result->hs_reason==FD_TLS_REASON_CERT_VERIFY;
  result->verify_err        = conn->hs.cli.cert_verify_err;
  result->server_key_type   = conn->hs.cli.server_key_type;
  result->server_pubkey_len = conn->hs.cli.server_pubkey_len;
  result->alpn_negotiated   = conn->hs.cli.alpn_negotiated;

  if( !result->hs_ok ) return FD_TLS_WEB_FAIL;
  if( !result->verify_called || result->verify_err!=FD_X509_VERIFY_OK ) return FD_TLS_WEB_FAIL;
  return FD_TLS_WEB_OK;
}

#if FD_HAS_HOSTED

static char const *
fd_tls_web_outcome_str( int o ) {
  switch( o ) {
  case FD_TLS_WEB_OK:          return "ok";
  case FD_TLS_WEB_UNREACHABLE: return "unreachable";
  default:                     return "FAIL";
  }
}

/* fd_tls_web_why formats the most specific failure cause we have.
   Most real-world failures come down to one thing: fd_tls / fd_x509
   have no RSA, so say that in plain words rather than "parse error". */

static char const *
fd_tls_web_why( struct fd_tls_web_result const * r,
                char *                           buf,
                ulong                            buf_sz ) {
  buf[0] = '\0';
  if( r->hs_ok && r->verify_called && r->verify_err==FD_X509_VERIFY_OK ) return buf;

  /* Chain rejected by fd_x509 */
  if( r->verify_called && r->verify_err!=FD_X509_VERIFY_OK ) {
    switch( r->verify_err ) {
    case FD_X509_VERIFY_ERR_PARSE:
    case FD_X509_VERIFY_ERR_UNSUPPORTED:
      fd_cstr_printf( buf, buf_sz, NULL, "cert verify failed (x509 err %d): a cert in the chain has an RSA key or RSA signature; fd_x509 does not support RSA", r->verify_err );
      break;
    default:
      fd_cstr_printf( buf, buf_sz, NULL, "cert verify failed (x509 err %d)", r->verify_err );
      break;
    }
    return buf;
  }

  /* Server refused our ClientHello before sending a certificate.  We
     offer only TLS 1.3, X25519, AES-128-GCM, and Ed25519 / ECDSA-P256
     signatures, so the usual causes are known. */
  if( r->peer_alert>=0 ) {
    switch( r->peer_alert ) {
    case FD_TLS_ALERT_HANDSHAKE_FAILURE:
      fd_cstr_printf( buf, buf_sz, NULL, "server alert handshake_failure: no Ed25519/ECDSA-P256 certificate for our sigalgs (RSA-only site?) or X25519 not accepted" );
      return buf;
    case FD_TLS_ALERT_PROTOCOL_VERSION:
      fd_cstr_printf( buf, buf_sz, NULL, "server alert protocol_version: server does not speak TLS 1.3" );
      return buf;
    default:
      fd_cstr_printf( buf, buf_sz, NULL, "server alert %d-%s", r->peer_alert, fd_tls_alert_cstr( (uint)r->peer_alert ) );
      return buf;
    }
  }

  switch( r->hs_reason ) {
  case 0: break;
  case FD_TLS_REASON_CERT_CR_PARSE:
  case FD_TLS_REASON_CERT_PARSE:
  case FD_TLS_REASON_X509_PARSE:
    /* fd_tls rejects the leaf before chain verification when its key
       is not Ed25519 / P-256 / P-384.  On the public web that is RSA. */
    if( !r->verify_called ) {
      fd_cstr_printf( buf, buf_sz, NULL, "server certificate rejected before verification (hs reason %u): leaf key is not Ed25519/P-256/P-384, i.e. RSA; fd_tls does not support RSA", r->hs_reason );
      return buf;
    }
    break;
  case FD_TLS_REASON_CERT_KEY_TYPE:
    fd_cstr_printf( buf, buf_sz, NULL, "server certificate key type unsupported (RSA); fd_tls supports Ed25519, P-256, P-384 only" );
    return buf;
  case FD_TLS_REASON_CV_SIGALG:
    fd_cstr_printf( buf, buf_sz, NULL, "server signed CertificateVerify with an unsupported scheme (P-384 or RSA-PSS); fd_tls accepts Ed25519 and ECDSA-P256 only" );
    return buf;
  case FD_TLS_REASON_SH_NEG_CIPHER:
    fd_cstr_printf( buf, buf_sz, NULL, "server picked a cipher suite we did not offer (we offer TLS_AES_128_GCM_SHA256 only)" );
    return buf;
  default:
    fd_cstr_printf( buf, buf_sz, NULL, "hs reason %u-%s", r->hs_reason, fd_tls_reason_cstr( r->hs_reason ) );
    return buf;
  }

  if( r->tlsrec_err==FD_TLSREC_ERR_PROTO && r->hs_state<=FD_TLS_HS_WAIT_SH ) {
    fd_cstr_printf( buf, buf_sz, NULL, "server answered our ClientHello with a non-handshake record (encrypted alert) instead of ServerHello: no compatible certificate for our sigalgs (RSA-only site?)" );
  } else if( r->io_err==ECONNRESET && !r->tlsrec_err ) {
    fd_cstr_printf( buf, buf_sz, NULL, "server closed the connection after our ClientHello without an alert (RSA-only site or X25519 not accepted?)" );
  } else if( r->tlsrec_err ) {
    fd_cstr_printf( buf, buf_sz, NULL, "tlsrec %d-%s", r->tlsrec_err, fd_tlsrec_strerror( r->tlsrec_err ) );
  } else if( r->timed_out ) {
    fd_cstr_printf( buf, buf_sz, NULL, "timeout" );
  } else if( r->io_err ) {
    fd_cstr_printf( buf, buf_sz, NULL, "io %d-%s", r->io_err, fd_io_strerror( r->io_err ) );
  } else {
    fd_cstr_printf( buf, buf_sz, NULL, "unknown" );
  }
  return buf;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_netdb_open_fds( NULL );

  /* Verification is the point of this test: refuse to run without a
     trust store rather than silently reporting everything as verified. */
  static fd_x509_ca_store_t ca_store[1];
  long ca_cnt = fd_x509_ca_store_load_system( ca_store );
  if( FD_UNLIKELY( ca_cnt<=0L ) )
    FD_LOG_ERR(( "fd_x509_ca_store_load_system failed (%ld): no system CA bundle", ca_cnt ));
  FD_LOG_NOTICE(( "loaded %ld trust anchors", ca_cnt ));

  static struct fd_tls_web_conn c[1];

  ulong n_ok = 0UL, n_unreachable = 0UL, n_fail = 0UL, n_total = 0UL;

  for( ulong i=0UL; i<sizeof(hosts)/sizeof(hosts[0]); i++ ) {
    char const * host = hosts[ i ];
    n_total++;

    struct fd_tls_web_result result;
    int outcome = fd_tls_web_probe( c, host, ca_store, &result );

    if( outcome==FD_TLS_WEB_UNREACHABLE ) {
      n_unreachable++;
    } else if( outcome==FD_TLS_WEB_OK ) {
      n_ok++;
    } else {
      n_fail++;
    }

    char why[ 192 ];
    FD_LOG_NOTICE(( "%-30s %-11s key=%u/%lu alpn=%d %s",
                    host, fd_tls_web_outcome_str( outcome ),
                    result.server_key_type, result.server_pubkey_len,
                    result.alpn_negotiated,
                    outcome==FD_TLS_WEB_UNREACHABLE ? "" : fd_tls_web_why( &result, why, sizeof(why) ) ));
  }

  if( FD_UNLIKELY( n_fail ) )
    FD_LOG_ERR(( "%lu/%lu targets failed (%lu ok, %lu unreachable)",
                 n_fail, n_total, n_ok, n_unreachable ));

  if( FD_UNLIKELY( !n_ok ) )
    FD_LOG_NOTICE(( "no target reachable (%lu/%lu unreachable); skipping", n_unreachable, n_total ));
  else
    FD_LOG_NOTICE(( "pass (%lu ok, %lu unreachable, %lu total)", n_ok, n_unreachable, n_total ));

  fd_halt();
  return 0;
}

#else /* !FD_HAS_HOSTED */

int
main( int     argc,
      char ** argv ) {
  (void)argc; (void)argv;
  return 0;
}

#endif
