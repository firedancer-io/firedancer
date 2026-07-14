#define _GNU_SOURCE
#include "fd_sshttp_private.h"
#include "fd_ssarchive.h"

#include "../../../third_party/picohttpparser/picohttpparser.h"
#include "../../../util/log/fd_log.h"
#include "../../../util/fd_util.h"
#include "../../../waltz/http/fd_http.h"
#include "../../../ballet/ed25519/fd_x25519.h"

FD_STATIC_ASSERT( FD_HASH_FOOTPRINT==32UL, resolved_hash_sz );

#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/random.h>
#include <netinet/in.h>

_Bool fd_sshttp_fuzz = 0;

static void *
fd_sshttp_tls_rand( void * ctx, void * buf, ulong bufsz ) {
  (void)ctx;
  return fd_rng_secure( buf, bufsz );
}

static int
fd_sshttp_cert_verify_cb( void *        ctx,
                          uchar const * cert_chain,
                          ulong         cert_chain_sz,
                          void const *  handshake ) {
  (void)handshake;
  fd_sshttp_t * http = (fd_sshttp_t *)ctx;

  if( !http->ca_store_loaded ) return 0;

  ulong hostname_len = http->hostname ? strlen( http->hostname ) : 0UL;
  int err = fd_x509_verify_tls_cert_msg( cert_chain, cert_chain_sz, &http->ca_store,
                                         http->hostname, hostname_len );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Certificate chain verification failed (err=%d) for %s", err,
                     http->hostname ? http->hostname : "(unknown)" ));
  }
  return err;
}

static void
fd_sshttp_tls_init( fd_tls_t * tls, fd_sshttp_t * http ) {
  fd_memset( tls, 0, sizeof(fd_tls_t) );

  tls->rand.ctx = NULL;
  tls->rand.rand_fn = fd_sshttp_tls_rand;

  fd_sshttp_tls_rand( NULL, tls->key_share_private, 32UL );
  fd_x25519_public( tls->key_share_public, tls->key_share_private );

  static uchar const alpn[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
  fd_memcpy( tls->alpn, alpn, sizeof(alpn) );
  tls->alpn_sz = sizeof(alpn);

  tls->quic = 0;

  tls->cert_verify_fn  = fd_sshttp_cert_verify_cb;
  tls->cert_verify_ctx = http;
}

static int
http_init_tls( fd_sshttp_t * http ) {
  ulong hostname_len = strlen( http->hostname );
  if( FD_UNLIKELY( hostname_len >= sizeof(http->tls.server_name) ) ) {
    FD_LOG_WARNING(( "hostname too long for SNI: %s", http->hostname ));
    return -1;
  }
  fd_memcpy( http->tls.server_name, http->hostname, hostname_len );
  http->tls.server_name[ hostname_len ] = '\0';
  http->tls.server_name_len = (ushort)hostname_len;

  fd_sshttp_tls_rand( NULL, http->tls.key_share_private, 32UL );
  fd_x25519_public( http->tls.key_share_public, http->tls.key_share_private );

  fd_tlsrec_conn_init( &http->tls_conn, &http->tls, 0 );

  http->tls_app_buf_off = 0UL;
  http->tls_app_buf_sz  = 0UL;
  http->tls_tx_buf_off  = 0UL;
  http->tls_tx_buf_sz   = 0UL;

  return 0;
}

static int
http_flush_tls_tx( fd_sshttp_t * http ) {
  while( http->tls_tx_buf_sz > http->tls_tx_buf_off ) {
    ulong remain = http->tls_tx_buf_sz - http->tls_tx_buf_off;
    long sent = sendto( http->sockfd, http->tls_tx_buf + http->tls_tx_buf_off,
                        remain, MSG_NOSIGNAL, NULL, 0 );
    if( sent < 0 && errno == EAGAIN ) return 0;
    if( sent < 0 ) return -1;
    http->tls_tx_buf_off += (ulong)sent;
  }
  http->tls_tx_buf_off = 0UL;
  http->tls_tx_buf_sz  = 0UL;
  return 1;
}

static int
http_connect_tls( fd_sshttp_t * http,
                  long          now ) {
  if( FD_UNLIKELY( now>http->deadline ) ) {
    FD_LOG_WARNING(( "deadline exceeded during TLS connect to " FD_IP4_ADDR_FMT ":%hu",
                      FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  {
    int flush = http_flush_tls_tx( http );
    if( flush < 0 ) {
      fd_sshttp_cancel( http );
      return FD_SSHTTP_ADVANCE_ERROR;
    }
    if( !flush ) return FD_SSHTTP_ADVANCE_AGAIN;
  }

  uchar tcp_rx_buf[ FD_SSHTTP_TLS_BUF_SZ ];
  long tcp_rx_sz = recvfrom( http->sockfd, tcp_rx_buf, sizeof(tcp_rx_buf), 0, NULL, NULL );
  if( tcp_rx_sz < 0 && errno != EAGAIN ) {
    FD_LOG_WARNING(( "recvfrom() failed (%d-%s) during TLS connect to " FD_IP4_ADDR_FMT ":%hu",
                     errno, fd_io_strerror( errno ),
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }
  if( tcp_rx_sz < 0 ) tcp_rx_sz = 0;

  fd_tlsrec_slice_t tcp_rx_slice[1];
  fd_tlsrec_slice_init( tcp_rx_slice, tcp_rx_buf, (ulong)tcp_rx_sz );

  uchar tcp_tx_buf[ FD_SSHTTP_TLS_BUF_SZ ];
  ulong tcp_tx_sz = sizeof(tcp_tx_buf);
  uchar app_rx_buf[ FD_SSHTTP_TLS_BUF_SZ ];
  ulong app_rx_sz = sizeof(app_rx_buf);

  int rc = fd_tlsrec_conn_rx( &http->tls_conn, tcp_rx_sz ? tcp_rx_slice : NULL,
                              tcp_tx_buf, &tcp_tx_sz,
                              app_rx_buf, &app_rx_sz );
  if( FD_UNLIKELY( rc != FD_TLSREC_SUCCESS ) ) {
    FD_LOG_WARNING(( "fd_tlsrec handshake failed (%d-%s) to " FD_IP4_ADDR_FMT ":%hu",
                     rc, fd_tlsrec_strerror( rc ),
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  if( tcp_tx_sz > 0 ) {
    long sent = sendto( http->sockfd, tcp_tx_buf, tcp_tx_sz, MSG_NOSIGNAL, NULL, 0 );
    if( sent < 0 && errno == EAGAIN ) {
      fd_memcpy( http->tls_tx_buf, tcp_tx_buf, tcp_tx_sz );
      http->tls_tx_buf_off = 0UL;
      http->tls_tx_buf_sz  = tcp_tx_sz;
    } else if( sent < 0 ) {
      fd_sshttp_cancel( http );
      return FD_SSHTTP_ADVANCE_ERROR;
    } else if( (ulong)sent < tcp_tx_sz ) {
      ulong remain = tcp_tx_sz - (ulong)sent;
      fd_memcpy( http->tls_tx_buf, tcp_tx_buf + sent, remain );
      http->tls_tx_buf_off = 0UL;
      http->tls_tx_buf_sz  = remain;
    }
  }

  if( fd_tlsrec_conn_is_ready( &http->tls_conn ) ) {
    if( app_rx_sz > 0 ) {
      ulong copy = fd_ulong_min( app_rx_sz, sizeof(http->tls_app_buf) );
      fd_memcpy( http->tls_app_buf, app_rx_buf, copy );
      http->tls_app_buf_off = 0UL;
      http->tls_app_buf_sz  = copy;
    }

    http->state    = FD_SSHTTP_STATE_REQ;
    http->deadline = now + FD_SSHTTP_DEADLINE_NANOS;
    return FD_SSHTTP_ADVANCE_AGAIN;
  }

  if( fd_tlsrec_conn_is_failed( &http->tls_conn ) ) {
    FD_LOG_WARNING(( "TLS handshake failed to " FD_IP4_ADDR_FMT ":%hu",
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  return FD_SSHTTP_ADVANCE_AGAIN;
}

static long
http_send_tls( fd_sshttp_t * http,
               void *        buf,
               ulong         bufsz ) {
  int flush = http_flush_tls_tx( http );
  if( flush < 0 ) return FD_SSHTTP_ADVANCE_ERROR;
  if( !flush ) return FD_SSHTTP_ADVANCE_AGAIN;

  fd_tlsrec_slice_t app_tx[1];
  fd_tlsrec_slice_init( app_tx, buf, bufsz );

  uchar tcp_tx_buf[ FD_SSHTTP_TLS_BUF_SZ ];
  ulong tcp_tx_sz = sizeof(tcp_tx_buf);

  int rc = fd_tlsrec_conn_tx( &http->tls_conn, tcp_tx_buf, &tcp_tx_sz, app_tx );
  if( FD_UNLIKELY( rc != FD_TLSREC_SUCCESS ) ) {
    FD_LOG_WARNING(( "fd_tlsrec_conn_tx failed (%d-%s)", rc, fd_tlsrec_strerror( rc ) ));
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  if( tcp_tx_sz > 0 ) {
    long sent = sendto( http->sockfd, tcp_tx_buf, tcp_tx_sz, MSG_NOSIGNAL, NULL, 0 );
    if( sent < 0 && errno == EAGAIN ) {
      fd_memcpy( http->tls_tx_buf, tcp_tx_buf, tcp_tx_sz );
      http->tls_tx_buf_off = 0UL;
      http->tls_tx_buf_sz  = tcp_tx_sz;
      return FD_SSHTTP_ADVANCE_AGAIN;
    }
    if( FD_UNLIKELY( sent < 0 ) ) {
      FD_LOG_WARNING(( "sendto() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      return FD_SSHTTP_ADVANCE_ERROR;
    }
    if( (ulong)sent < tcp_tx_sz ) {
      ulong remain = tcp_tx_sz - (ulong)sent;
      fd_memcpy( http->tls_tx_buf, tcp_tx_buf + sent, remain );
      http->tls_tx_buf_off = 0UL;
      http->tls_tx_buf_sz  = remain;
    }
  }

  return (long)( bufsz - fd_tlsrec_slice_sz( app_tx ) );
}

static long
http_recv_tls( fd_sshttp_t * http,
               void *        buf,
               ulong         bufsz ) {
  if( http->tls_app_buf_sz > http->tls_app_buf_off ) {
    ulong avail = http->tls_app_buf_sz - http->tls_app_buf_off;
    ulong copy  = fd_ulong_min( avail, bufsz );
    fd_memcpy( buf, http->tls_app_buf + http->tls_app_buf_off, copy );
    http->tls_app_buf_off += copy;
    if( http->tls_app_buf_off >= http->tls_app_buf_sz ) {
      http->tls_app_buf_off = 0UL;
      http->tls_app_buf_sz  = 0UL;
    }
    return (long)copy;
  }

  uchar tcp_rx_buf[ FD_SSHTTP_TLS_BUF_SZ ];
  long tcp_rx_sz = recvfrom( http->sockfd, tcp_rx_buf, sizeof(tcp_rx_buf), 0, NULL, NULL );
  if( tcp_rx_sz < 0 && errno == EAGAIN ) return FD_SSHTTP_ADVANCE_AGAIN;
  if( tcp_rx_sz < 0 ) {
    FD_LOG_WARNING(( "recvfrom() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    return FD_SSHTTP_ADVANCE_ERROR;
  }
  if( tcp_rx_sz == 0 ) return FD_SSHTTP_ADVANCE_AGAIN;

  fd_tlsrec_slice_t tcp_rx_slice[1];
  fd_tlsrec_slice_init( tcp_rx_slice, tcp_rx_buf, (ulong)tcp_rx_sz );

  uchar tcp_tx_buf[ FD_SSHTTP_TLS_BUF_SZ ];
  ulong tcp_tx_sz = sizeof(tcp_tx_buf);
  uchar app_rx_buf[ FD_SSHTTP_TLS_BUF_SZ ];
  ulong app_rx_sz = sizeof(app_rx_buf);

  int rc = fd_tlsrec_conn_rx( &http->tls_conn, tcp_rx_slice,
                              tcp_tx_buf, &tcp_tx_sz,
                              app_rx_buf, &app_rx_sz );
  if( FD_UNLIKELY( rc != FD_TLSREC_SUCCESS ) ) {
    FD_LOG_WARNING(( "fd_tlsrec_conn_rx failed (%d-%s)", rc, fd_tlsrec_strerror( rc ) ));
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  if( tcp_tx_sz > 0 ) {
    long sent = sendto( http->sockfd, tcp_tx_buf, tcp_tx_sz, MSG_NOSIGNAL, NULL, 0 );
    (void)sent;
  }

  if( app_rx_sz == 0 ) return FD_SSHTTP_ADVANCE_AGAIN;

  ulong copy = fd_ulong_min( app_rx_sz, bufsz );
  fd_memcpy( buf, app_rx_buf, copy );

  if( copy < app_rx_sz ) {
    ulong remain = app_rx_sz - copy;
    fd_memcpy( http->tls_app_buf, app_rx_buf + copy, remain );
    http->tls_app_buf_off = 0UL;
    http->tls_app_buf_sz  = remain;
  }

  return (long)copy;
}

static int
setup_redirect_tls( fd_sshttp_t * http,
                    long          now ) {
  fd_sshttp_cancel( http );
  if( FD_UNLIKELY( fd_sshttp_init( http, http->addr, http->hostname, http->is_https, http->location, http->location_len, ULONG_MAX, now ) ) ) {
    return FD_SSHTTP_ADVANCE_ERROR;
  }
  return FD_SSHTTP_ADVANCE_AGAIN;
}

static int
http_shutdown_tls( fd_sshttp_t * http,
                   long          now ) {
  (void)now;
  http->state = http->next_state;
  return FD_SSHTTP_ADVANCE_AGAIN;
}

FD_FN_CONST ulong
fd_sshttp_align( void ) {
  return alignof(fd_sshttp_t);
}

FD_FN_CONST ulong
fd_sshttp_footprint( void ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_sshttp_t), sizeof(fd_sshttp_t) );
  return FD_LAYOUT_FINI( l, fd_sshttp_align() );
}

void *
fd_sshttp_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_sshttp_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_sshttp_t * sshttp = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sshttp_t), sizeof(fd_sshttp_t) );

  sshttp->state = FD_SSHTTP_STATE_INIT;
  sshttp->sockfd = -1;
  sshttp->content_len = 0UL;
  fd_cstr_fini( sshttp->snapshot_name );
  sshttp->resolved_slot = 0UL;
  fd_memset( sshttp->resolved_hash, 0, FD_HASH_FOOTPRINT );

  sshttp->tls_app_buf_off = 0UL;
  sshttp->tls_app_buf_sz  = 0UL;
  fd_sshttp_tls_init( &sshttp->tls, sshttp );

  sshttp->ca_store_loaded = 0;
  if( !fd_sshttp_fuzz ) {
    static char const * ca_paths[] = {
      "/etc/ssl/certs/ca-certificates.crt",
      "/etc/pki/tls/certs/ca-bundle.crt",
      "/etc/ssl/cert.pem",
      NULL
    };
    for( int i = 0; ca_paths[i]; i++ ) {
      long loaded = fd_x509_ca_store_load( &sshttp->ca_store, ca_paths[i] );
      if( loaded >= 0 ) {
        FD_LOG_INFO(( "Loaded %ld CA certificates from %s", loaded, ca_paths[i] ));
        sshttp->ca_store_loaded = 1;
        break;
      }
    }
    if( !sshttp->ca_store_loaded ) {
      FD_LOG_WARNING(( "No CA certificate bundle found — TLS certificate "
                       "chain validation will be skipped" ));
    }
  }

  FD_COMPILER_MFENCE();
  sshttp->magic = FD_SSHTTP_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)sshttp;
}

fd_sshttp_t *
fd_sshttp_join( void * shhttp ) {
  if( FD_UNLIKELY( !shhttp ) ) {
    FD_LOG_WARNING(( "NULL shhttp" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shhttp, fd_sshttp_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shhttp" ));
    return NULL;
  }

  fd_sshttp_t * sshttp = (fd_sshttp_t *)shhttp;

  if( FD_UNLIKELY( sshttp->magic!=FD_SSHTTP_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sshttp;
}

int
fd_sshttp_init( fd_sshttp_t * http,
                fd_ip4_port_t addr,
                char const *  hostname,
                int           is_https,
                char const *  path,
                ulong         path_len,
                ulong         hops,
                long          now ) {
  FD_TEST( http->state==FD_SSHTTP_STATE_INIT );

  http->hostname = hostname;
  http->is_https = is_https;

  if( FD_LIKELY( is_https ) ) {
    if( FD_UNLIKELY( http_init_tls( http ) ) ) return -1;
  }

  if( hops!=ULONG_MAX ) {
    http->hops = hops;
    fd_cstr_fini( http->snapshot_name );
    http->resolved_slot = 0UL;
    fd_memset( http->resolved_hash, 0, FD_HASH_FOOTPRINT );
  }
  http->request_sent = 0UL;
  int fmt_ok;
  if( FD_LIKELY( is_https ) ) {
    fmt_ok = fd_cstr_printf_check( http->request, sizeof(http->request), &http->request_len,
      "GET %.*s HTTP/1.1\r\n"
      "User-Agent: Firedancer\r\n"
      "Accept: */*\r\n"
      "Accept-Encoding: identity\r\n"
      "Host: %s\r\n\r\n",
      (int)path_len, path, hostname );
  } else {
    fmt_ok = fd_cstr_printf_check( http->request, sizeof(http->request), &http->request_len,
      "GET %.*s HTTP/1.1\r\n"
      "User-Agent: Firedancer\r\n"
      "Accept: */*\r\n"
      "Accept-Encoding: identity\r\n"
      "Host: " FD_IP4_ADDR_FMT "\r\n\r\n",
      (int)path_len, path, FD_IP4_ADDR_FMT_ARGS( addr.addr ) );
  }
  if( FD_UNLIKELY( !fmt_ok ) ) {
    FD_LOG_WARNING(( "HTTP request too long for %.*s", (int)path_len, path ));
    return -1;
  }

  http->response_len = 0UL;
  http->content_len  = 0UL;
  http->content_read = 0UL;
  http->empty_recvs  = 0UL;

  http->addr   = addr;
  http->sockfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==http->sockfd ) ) {
    FD_LOG_WARNING(( "socket() failed (%d-%s) for " FD_IP4_ADDR_FMT ":%hu", errno, fd_io_strerror( errno ),
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    return -1;
  }

  struct sockaddr_in addr_in = {
    .sin_family = AF_INET,
    .sin_port   = addr.port,
    .sin_addr   = { .s_addr = addr.addr }
  };

  if( FD_LIKELY( -1==connect( http->sockfd, fd_type_pun_const( &addr_in ), sizeof(addr_in) ) ) ) {
    if( FD_UNLIKELY( errno!=EINPROGRESS ) ) {
      FD_LOG_WARNING(( "connect() failed (%d-%s) to " FD_IP4_ADDR_FMT ":%hu", errno, fd_io_strerror( errno ),
                       FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
      if( FD_UNLIKELY( -1==close( http->sockfd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s) for " FD_IP4_ADDR_FMT ":%hu", errno, fd_io_strerror( errno ),
                                                                  FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
      http->sockfd = -1;
      return -1;
    }
  }

  if( FD_LIKELY( is_https ) ) {
    http->state    = FD_SSHTTP_STATE_CONNECT;
    http->deadline = now + FD_SSHTTP_DEADLINE_NANOS;
  } else {
    http->state    = FD_SSHTTP_STATE_REQ;
    http->deadline = now + FD_SSHTTP_DEADLINE_NANOS;
  }

  return 0;
}


void
fd_sshttp_cancel( fd_sshttp_t * http ) {
  if( FD_LIKELY( http->state!=FD_SSHTTP_STATE_INIT && -1!=http->sockfd ) ) {
    if( FD_UNLIKELY( -1==close( http->sockfd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s) for " FD_IP4_ADDR_FMT ":%hu", errno, fd_io_strerror( errno ),
                                                                FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    http->sockfd = -1;
  }
  http->state = FD_SSHTTP_STATE_INIT;

  http->tls_app_buf_off = 0UL;
  http->tls_app_buf_sz  = 0UL;
  http->tls_tx_buf_off  = 0UL;
  http->tls_tx_buf_sz   = 0UL;

}

static long
http_send( fd_sshttp_t * http,
           void *        buf,
           ulong         bufsz ) {
  if( FD_LIKELY( http->is_https ) )
    return http_send_tls( http, buf, bufsz );

  long sent = sendto( http->sockfd, buf, bufsz, MSG_NOSIGNAL, NULL, 0 );
  if( FD_UNLIKELY( -1==sent && errno==EAGAIN ) ) return FD_SSHTTP_ADVANCE_AGAIN;
  else if( FD_UNLIKELY( -1==sent ) ) {
    FD_LOG_WARNING(( "sendto() failed (%d-%s) to " FD_IP4_ADDR_FMT ":%hu", errno, fd_io_strerror( errno ),
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  return sent;
}

static long
http_recv( fd_sshttp_t * http,
           void *        buf,
           ulong         bufsz ) {
  if( FD_LIKELY( http->is_https ) )
    return http_recv_tls( http, buf, bufsz );

  long read = recvfrom( http->sockfd, buf, bufsz, 0, NULL, NULL );
  if( FD_UNLIKELY( -1==read && errno==EAGAIN ) ) {
    if( FD_UNLIKELY( ++http->empty_recvs>8UL && !fd_sshttp_fuzz ) ) {
      /* If we have gone several iterations without having any data to
         read, sleep the thread for up to one millisecond, or until
         the socket is readable again, whichever comes first. */
      struct pollfd pfd = {
        .fd = http->sockfd,
        .events = POLLIN,
      };
      if( FD_UNLIKELY( -1==fd_syscall_poll( &pfd, 1 /*fds*/, 1 /*ms*/ ) ) ) {
        if( FD_UNLIKELY( errno!=EINTR ) ) {
          FD_LOG_WARNING(( "fd_syscall_poll() failed (%d-%s) for " FD_IP4_ADDR_FMT ":%hu", errno, fd_io_strerror( errno ),
                           FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
          fd_sshttp_cancel( http );
          return FD_SSHTTP_ADVANCE_ERROR;
        }
      }
    }
    return FD_SSHTTP_ADVANCE_AGAIN;
  } else if( FD_UNLIKELY( -1==read ) ) {
    FD_LOG_WARNING(( "recvfrom() failed (%d-%s) from " FD_IP4_ADDR_FMT ":%hu", errno, fd_io_strerror( errno ),
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }
  http->empty_recvs = 0UL;

  return read;
}

static int
send_request( fd_sshttp_t * http,
              long          now ) {
  if( FD_UNLIKELY( now>http->deadline ) ) {
    FD_LOG_WARNING(( "timeout sending request to " FD_IP4_ADDR_FMT ":%hu",
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  long sent = http_send( http, http->request+http->request_sent, http->request_len-http->request_sent );
  if( FD_UNLIKELY( sent<=0 ) ) return (int)sent;

  http->request_sent += (ulong)sent;
  if( FD_UNLIKELY( http->request_sent==http->request_len ) ) {
    http->state        = FD_SSHTTP_STATE_RESP;
    http->response_len = 0UL;
    http->deadline     = now + FD_SSHTTP_DEADLINE_NANOS;
  }

  return FD_SSHTTP_ADVANCE_AGAIN;
}

static int
follow_redirect( fd_sshttp_t *        http,
                  struct phr_header * headers,
                  ulong               header_cnt,
                  long                now ) {
  if( FD_UNLIKELY( !http->hops ) ) {
    FD_LOG_WARNING(( "too many redirects (remaining %lu) from " FD_IP4_ADDR_FMT ":%hu", http->hops,
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }
  /* The check above guarantees hops>0. */
  http->hops--;

  ulong        location_len = 0UL;
  char const * location     = NULL;

  for( ulong i=0UL; i<header_cnt; i++ ) {
    if( FD_UNLIKELY( headers[ i ].name_len == 8 && !strncasecmp( headers[ i ].name, "location", headers[ i ].name_len ) ) ) {
      if( FD_UNLIKELY( !headers [ i ].value_len || headers[ i ].value[ 0 ]!='/' ) ) {
        FD_LOG_WARNING(( "invalid location header `%.*s` from " FD_IP4_ADDR_FMT ":%hu", (int)headers[ i ].value_len, headers[ i ].value,
                         FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
        fd_sshttp_cancel( http );
        return FD_SSHTTP_ADVANCE_ERROR;
      }

      location_len = headers[ i ].value_len;
      location     = headers[ i ].value;

      if( FD_UNLIKELY( location_len>=PATH_MAX-1UL ) ) {
        FD_LOG_WARNING(( "location header too long `%.*s` from " FD_IP4_ADDR_FMT ":%hu", (int)location_len, location,
                         FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
        fd_sshttp_cancel( http );
        return FD_SSHTTP_ADVANCE_ERROR;
      }

      char snapshot_name[ PATH_MAX ];
      fd_memcpy( snapshot_name, location+1UL, location_len-1UL );
      snapshot_name[ location_len-1UL ] = '\0';

      int is_zstd;
      ulong full_entry_slot, incremental_entry_slot;
      uchar decoded_hash[ FD_HASH_FOOTPRINT ];
      int err = fd_ssarchive_parse_filename( snapshot_name, &full_entry_slot, &incremental_entry_slot, decoded_hash, &is_zstd );

      if( FD_UNLIKELY( err || !is_zstd ) ) {
        FD_LOG_WARNING(( "unrecognized snapshot file `%s` in redirect location header from " FD_IP4_ADDR_FMT ":%hu", snapshot_name,
                         FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
        fd_sshttp_cancel( http );
        return FD_SSHTTP_ADVANCE_ERROR;
      }

      http->resolved_slot = (incremental_entry_slot!=ULONG_MAX)
                            ? incremental_entry_slot : full_entry_slot;
      fd_memcpy( http->resolved_hash, decoded_hash, FD_HASH_FOOTPRINT );

      char encoded_hash[ FD_BASE58_ENCODED_32_SZ ];
      fd_base58_encode_32( decoded_hash, NULL, encoded_hash );

      if( FD_LIKELY( incremental_entry_slot!=ULONG_MAX ) ) {
        FD_TEST( fd_cstr_printf_check( http->snapshot_name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-%s.tar.zst", full_entry_slot, incremental_entry_slot, encoded_hash ) );
      } else {
        FD_TEST( fd_cstr_printf_check( http->snapshot_name, PATH_MAX, NULL, "snapshot-%lu-%s.tar.zst", full_entry_slot, encoded_hash ) );
      }
      break;
    }
  }

  if( FD_UNLIKELY( !location_len ) ) {
    FD_LOG_WARNING(( "no location header in redirect response from " FD_IP4_ADDR_FMT ":%hu",
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  /* Pre-validate that the redirect request will fit in the request
     buffer.  The request is rebuilt from scratch by fd_sshttp_init
     during the redirect, but the format must match so that a path
     accepted here will not overflow in fd_sshttp_init. */
  int pre_check;
  if( FD_LIKELY( http->is_https ) ) {
    pre_check = fd_cstr_printf_check( http->request, sizeof(http->request), &http->request_len,
      "GET %.*s HTTP/1.1\r\n"
      "User-Agent: Firedancer\r\n"
      "Accept: */*\r\n"
      "Accept-Encoding: identity\r\n"
      "Host: %s\r\n\r\n",
      (int)location_len, location, http->hostname );
  } else {
    pre_check = fd_cstr_printf_check( http->request, sizeof(http->request), &http->request_len,
      "GET %.*s HTTP/1.1\r\n"
      "User-Agent: Firedancer\r\n"
      "Accept: */*\r\n"
      "Accept-Encoding: identity\r\n"
      "Host: " FD_IP4_ADDR_FMT "\r\n\r\n",
      (int)location_len, location, FD_IP4_ADDR_FMT_ARGS( http->addr.addr ) );
  }
  if( FD_UNLIKELY( !pre_check ) ) {
    FD_LOG_WARNING(( "redirect request too long `%.*s` from " FD_IP4_ADDR_FMT ":%hu", (int)location_len, location,
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  FD_LOG_INFO(( "following redirect to %s://" FD_IP4_ADDR_FMT ":%hu%.*s", http->is_https ? "https" : "http",
                FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ),
                (int)location_len, location ));

  if( FD_UNLIKELY( http->is_https ) ) {
    http->next_state   = FD_SSHTTP_STATE_REDIRECT;
    http->state        = FD_SSHTTP_STATE_SHUTTING_DOWN;
    http->location_len = location_len;
    FD_TEST( location_len<PATH_MAX-1UL );
    fd_memcpy( http->location, location, location_len );
    http->location[ location_len ] = '\0';
  } else {
    if( FD_LIKELY( !fd_sshttp_fuzz ) ) {
      fd_sshttp_cancel( http );
      if( FD_UNLIKELY( fd_sshttp_init( http, http->addr, http->hostname, http->is_https, location, location_len, ULONG_MAX, now ) ) ) {
        return FD_SSHTTP_ADVANCE_ERROR;
      }
    } else {
      http->state = FD_SSHTTP_STATE_RESP;
      http->response_len = 0UL;
    }
  }

  return FD_SSHTTP_ADVANCE_AGAIN;
}

static int
read_response( fd_sshttp_t * http,
               ulong *       data_len,
               uchar *       data,
               long          now ) {
  if( FD_UNLIKELY( now>http->deadline ) ) {
    FD_LOG_WARNING(( "timeout reading response from " FD_IP4_ADDR_FMT ":%hu",
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  long read = http_recv( http, http->response+http->response_len, sizeof(http->response)-http->response_len );
  if( FD_UNLIKELY( read<=0 ) ) return (int)read;

  http->response_len += (ulong)read;

  int               minor_version;
  int               status;
  const char *      message;
  ulong             message_len;
  struct phr_header headers[ 128UL ];
  ulong             header_cnt = 128UL;
  int parsed = phr_parse_response( http->response,
                                    http->response_len,
                                    &minor_version,
                                    &status,
                                    &message,
                                    &message_len,
                                    headers,
                                    &header_cnt,
                                    http->response_len - (ulong)read );
  if( FD_UNLIKELY( parsed==-1 ) ) {
    FD_LOG_WARNING(( "malformed response headers from " FD_IP4_ADDR_FMT ":%hu",
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  } else if( parsed==-2 ) {
    return FD_SSHTTP_ADVANCE_AGAIN;
  }

  int is_redirect = (status==301) | (status==302) | (status==303) | (status==307) | (status==308);
  if( FD_UNLIKELY( is_redirect ) ) {
    return follow_redirect( http, headers, header_cnt, now );
  }

  if( FD_UNLIKELY( status!=200 ) ) {
    FD_LOG_WARNING(( "unexpected response status %d %.*s from " FD_IP4_ADDR_FMT ":%hu", status, (int)message_len, message,
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  http->content_read = 0UL;
  http->content_len = ULONG_MAX;
  for( ulong i=0UL; i<header_cnt; i++ ) {
    if( FD_LIKELY( headers[i].name_len!=14UL ) ) continue;
    if( FD_LIKELY( strncasecmp( headers[i].name, "content-length", 14UL ) ) ) continue;

    ulong val = 0UL;
    if( FD_UNLIKELY( fd_http_parse_content_len( headers[i].value, (ulong)headers[i].value_len, &val ) || val==0UL ) ) {
      FD_LOG_WARNING(( "invalid content-length in response from " FD_IP4_ADDR_FMT ":%hu", FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
      fd_sshttp_cancel( http );
      return FD_SSHTTP_ADVANCE_ERROR;
    }
    http->content_len = val;
    break;
  }

  if( FD_UNLIKELY( http->content_len==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "no content-length header in response from " FD_IP4_ADDR_FMT ":%hu",
                     FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  http->state = FD_SSHTTP_STATE_DL;
  if( FD_UNLIKELY( (ulong)parsed<http->response_len ) ) {
    /* Body bytes past the caller's buffer are kept in response, with
       response_len repurposed as the residual length, drained by
       read_body before it reads the socket again. */
    ulong leftover = fd_ulong_min( http->response_len - (ulong)parsed, http->content_len );
    ulong copy_len = fd_ulong_min( leftover, *data_len );
    fd_memcpy( data, http->response+parsed, copy_len );
    memmove( http->response, http->response+(ulong)parsed+copy_len, leftover-copy_len );
    http->response_len  = leftover-copy_len;
    http->content_read += copy_len;
    *data_len = copy_len;
    return FD_SSHTTP_ADVANCE_DATA;
  } else {
    FD_TEST( http->response_len==(ulong)parsed );
    http->response_len = 0UL;
    return FD_SSHTTP_ADVANCE_AGAIN;
  }
}

static int
read_body( fd_sshttp_t * http,
           ulong *       data_len,
           uchar *       data,
           long          now ) {
  if( FD_UNLIKELY( http->content_read>=http->content_len ) ) {
    if( FD_UNLIKELY( http->is_https ) ) {
      http->next_state = FD_SSHTTP_STATE_DONE;
      http->state = FD_SSHTTP_STATE_SHUTTING_DOWN;
      http->deadline = now + FD_SSHTTP_DEADLINE_NANOS;
      return FD_SSHTTP_ADVANCE_AGAIN;
    } else {
      fd_sshttp_cancel( http );
      http->state = FD_SSHTTP_STATE_INIT;
      return FD_SSHTTP_ADVANCE_DONE;
    }
  }

  FD_TEST( http->content_read<http->content_len );

  if( FD_UNLIKELY( http->response_len ) ) { /* residual body bytes from read_response */
    ulong copy_len = fd_ulong_min( http->response_len, *data_len );
    fd_memcpy( data, http->response, copy_len );
    memmove( http->response, http->response+copy_len, http->response_len-copy_len );
    http->response_len  -= copy_len;
    http->content_read  += copy_len;
    *data_len = copy_len;
    return FD_SSHTTP_ADVANCE_DATA;
  }

  long read = http_recv( http, data, fd_ulong_min( *data_len, http->content_len-http->content_read ) );
  if( FD_UNLIKELY( read<=0 ) ) return (int)read;

  *data_len = (ulong)read;
  http->content_read += (ulong)read;

  return FD_SSHTTP_ADVANCE_DATA;
}

char const *
fd_sshttp_snapshot_name( fd_sshttp_t const * http ) {
  return http->snapshot_name;
}

ulong
fd_sshttp_content_len( fd_sshttp_t const * http ) {
  return http->content_len;
}

ulong
fd_sshttp_resolved_slot( fd_sshttp_t const * http ) {
  return http->resolved_slot;
}

uchar const *
fd_sshttp_resolved_hash( fd_sshttp_t const * http ) {
  return http->resolved_hash;
}

int
fd_sshttp_advance( fd_sshttp_t * http,
                   ulong *       data_len,
                   uchar *       data,
                   int *         downloading,
                   long          now ) {
  *downloading = 0;
  switch( http->state ) {
    case FD_SSHTTP_STATE_INIT:          return FD_SSHTTP_ADVANCE_AGAIN;
    case FD_SSHTTP_STATE_CONNECT:
      return http_connect_tls( http, now );
    case FD_SSHTTP_STATE_SHUTTING_DOWN:
      return http_shutdown_tls( http, now );
    case FD_SSHTTP_STATE_REDIRECT:
      return setup_redirect_tls( http, now );
    case FD_SSHTTP_STATE_REQ:           return send_request( http, now );
    case FD_SSHTTP_STATE_RESP:          return read_response( http, data_len, data, now );
    case FD_SSHTTP_STATE_DL:            *downloading = 1; return read_body( http, data_len, data, now );
    case FD_SSHTTP_STATE_DONE:
      fd_sshttp_cancel( http );
      http->state = FD_SSHTTP_STATE_INIT;
      return FD_SSHTTP_ADVANCE_DONE;
    default:                            return FD_SSHTTP_ADVANCE_ERROR;
  }
}
