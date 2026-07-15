#include <linux/limits.h>  /* PATH_MAX — needed before fd_ssarchive.h */
#include "fd_ssresolve.h"
#include "fd_ssarchive.h"

#include "../../../third_party/picohttpparser/picohttpparser.h"
#include "../../../waltz/tlsrec/fd_tlsrec.h"
#include "../../../ballet/ed25519/fd_x25519.h"
#include "../../../util/log/fd_log.h"

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <limits.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#define FD_SSRESOLVE_IO_BUF_SZ (16384UL+256UL)  /* Must hold a full TLS record (RFC 8446 §5.1) */

#define FD_SSRESOLVE_CONNECT             (0) /* TLS handshake in progress */
#define FD_SSRESOLVE_STATE_REQ           (1) /* sending request for snapshot */
#define FD_SSRESOLVE_STATE_RESP          (2) /* receiving snapshot response */
#define FD_SSRESOLVE_STATE_SHUTTING_DOWN (3) /* shutting down TLS */
#define FD_SSRESOLVE_STATE_DONE          (4) /* done */

struct fd_ssresolve_private {
  int  state;
  long deadline;

  fd_ip4_port_t addr;
  int           sockfd;
  int           full;
  int           is_https;
  char const *  hostname;

  char  request[ 4096UL ];
  ulong request_sent;
  ulong request_len;

  ulong response_len;
  char  response[ USHORT_MAX ];

  /* Native TLS state */
  fd_tlsrec_conn_t tls_conn;

  /* Decrypted app data buffer */
  uchar tls_app_buf[ FD_TLSREC_CAP ];
  ulong tls_app_buf_off;
  ulong tls_app_buf_sz;

  ulong magic;
};

FD_FN_CONST ulong
fd_ssresolve_align( void ) {
  return FD_SSRESOLVE_ALIGN;
}

FD_FN_CONST ulong
fd_ssresolve_footprint( void ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_SSRESOLVE_ALIGN, sizeof(fd_ssresolve_t) );
  return FD_LAYOUT_FINI( l, FD_SSRESOLVE_ALIGN );
}

void *
fd_ssresolve_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ssresolve_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ssresolve_t * ssresolve = FD_SCRATCH_ALLOC_APPEND( l, FD_SSRESOLVE_ALIGN, sizeof(fd_ssresolve_t) );

  ssresolve->state           = FD_SSRESOLVE_STATE_REQ;
  ssresolve->request_sent    = 0UL;
  ssresolve->request_len     = 0UL;
  ssresolve->response_len    = 0UL;
  ssresolve->sockfd          = -1;
  ssresolve->tls_app_buf_off = 0UL;
  ssresolve->tls_app_buf_sz  = 0UL;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( ssresolve->magic ) = FD_SSRESOLVE_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)ssresolve;
}

fd_ssresolve_t *
fd_ssresolve_join( void * _ssresolve ) {
  if( FD_UNLIKELY( !_ssresolve ) ) {
    FD_LOG_WARNING(( "NULL ssresolve" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)_ssresolve, fd_ssresolve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ssresolve" ));
    return NULL;
  }

  fd_ssresolve_t * ssresolve = (fd_ssresolve_t *)_ssresolve;

  if( FD_UNLIKELY( ssresolve->magic!=FD_SSRESOLVE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ssresolve;
}

void
fd_ssresolve_init( fd_ssresolve_t * ssresolve,
                   fd_ip4_port_t    addr,
                   int              sockfd,
                   int              full,
                   char const *     hostname ) {
  ssresolve->addr   = addr;
  ssresolve->sockfd = sockfd;
  ssresolve->full   = full;

  ssresolve->state           = FD_SSRESOLVE_STATE_REQ;
  ssresolve->request_sent    = 0UL;
  ssresolve->request_len     = 0UL;
  ssresolve->response_len    = 0UL;
  ssresolve->is_https        = 0;
  ssresolve->hostname        = hostname;
  ssresolve->tls_app_buf_off = 0UL;
  ssresolve->tls_app_buf_sz  = 0UL;
}

void
fd_ssresolve_init_https( fd_ssresolve_t * ssresolve,
                         fd_ip4_port_t    addr,
                         int              sockfd,
                         int              full,
                         char const *     hostname,
                         fd_tls_t const * tls ) {
  ssresolve->addr   = addr;
  ssresolve->sockfd = sockfd;
  ssresolve->full   = full;

  ssresolve->state        = FD_SSRESOLVE_CONNECT;
  ssresolve->request_sent = 0UL;
  ssresolve->request_len  = 0UL;
  ssresolve->response_len = 0UL;
  ssresolve->is_https     = 1;
  ssresolve->hostname     = hostname;

  /* Copy and configure fd_tls for this connection */
  fd_tlsrec_conn_init( &ssresolve->tls_conn, tls, 0 );

  FD_TEST( hostname && hostname[0] != '\0' );
  ulong hostname_len = strlen( hostname );
  if( hostname_len < sizeof(ssresolve->tls_conn.tls.server_name) ) {
    fd_memcpy( ssresolve->tls_conn.tls.server_name, hostname, hostname_len );
    ssresolve->tls_conn.tls.server_name[ hostname_len ] = '\0';
    ssresolve->tls_conn.tls.server_name_len = (ushort)hostname_len;
  }

  /* Re-generate ephemeral X25519 key pair for this connection */
  fd_tls_rand( &ssresolve->tls_conn.tls.rand,
               ssresolve->tls_conn.tls.key_share_private, 32UL );
  fd_x25519_public( ssresolve->tls_conn.tls.key_share_public,
                    ssresolve->tls_conn.tls.key_share_private );

  ssresolve->tls_app_buf_off = 0UL;
  ssresolve->tls_app_buf_sz  = 0UL;
}

static void
fd_ssresolve_render_req( fd_ssresolve_t * ssresolve ) {
  char const * path = ssresolve->full ? "/snapshot.tar.bz2" : "/incremental-snapshot.tar.bz2";

  if( FD_LIKELY( ssresolve->hostname && ssresolve->hostname[ 0 ]!='\0' ) ) {
    FD_TEST( fd_cstr_printf_check( ssresolve->request, sizeof(ssresolve->request), &ssresolve->request_len,
           "HEAD %s HTTP/1.1\r\n"
           "User-Agent: Firedancer\r\n"
           "Accept: */*\r\n"
           "Accept-Encoding: identity\r\n"
           "Host: %s\r\n\r\n",
           path, ssresolve->hostname ) );
  } else {
    FD_TEST( fd_cstr_printf_check( ssresolve->request, sizeof(ssresolve->request), &ssresolve->request_len,
           "HEAD %s HTTP/1.1\r\n"
           "User-Agent: Firedancer\r\n"
           "Accept: */*\r\n"
           "Accept-Encoding: identity\r\n"
           "Host: " FD_IP4_ADDR_FMT "\r\n\r\n",
           path, FD_IP4_ADDR_FMT_ARGS( ssresolve->addr.addr ) ) );
  }
}

/* Native TLS send/recv helpers */

static long
ssresolve_send_tls( fd_ssresolve_t * ssresolve,
                    void *           buf,
                    ulong            bufsz ) {
  fd_tlsrec_slice_t app_tx[1];
  fd_tlsrec_slice_init( app_tx, buf, bufsz );

  uchar tcp_tx_buf[ FD_SSRESOLVE_IO_BUF_SZ ];
  ulong tcp_tx_sz = sizeof(tcp_tx_buf);

  int rc = fd_tlsrec_conn_tx( &ssresolve->tls_conn, tcp_tx_buf, &tcp_tx_sz, app_tx );
  if( FD_UNLIKELY( rc != FD_TLSREC_SUCCESS ) ) return FD_SSRESOLVE_ADVANCE_ERROR;

  if( tcp_tx_sz > 0 ) {
    long sent = sendto( ssresolve->sockfd, tcp_tx_buf, tcp_tx_sz, MSG_NOSIGNAL, NULL, 0 );
    if( sent < 0 && errno == EAGAIN ) return FD_SSRESOLVE_ADVANCE_AGAIN;
    if( sent < 0 ) return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  return (long)( bufsz - fd_tlsrec_slice_sz( app_tx ) );
}

static long
ssresolve_recv_tls( fd_ssresolve_t * ssresolve,
                    void *           buf,
                    ulong            bufsz ) {
  /* Drain buffered decrypted data */
  if( ssresolve->tls_app_buf_sz > ssresolve->tls_app_buf_off ) {
    ulong avail = ssresolve->tls_app_buf_sz - ssresolve->tls_app_buf_off;
    ulong copy  = fd_ulong_min( avail, bufsz );
    fd_memcpy( buf, ssresolve->tls_app_buf + ssresolve->tls_app_buf_off, copy );
    ssresolve->tls_app_buf_off += copy;
    if( ssresolve->tls_app_buf_off >= ssresolve->tls_app_buf_sz ) {
      ssresolve->tls_app_buf_off = 0UL;
      ssresolve->tls_app_buf_sz  = 0UL;
    }
    return (long)copy;
  }

  uchar tcp_rx_buf[ FD_SSRESOLVE_IO_BUF_SZ ];
  long tcp_rx_sz = recvfrom( ssresolve->sockfd, tcp_rx_buf, sizeof(tcp_rx_buf), 0, NULL, NULL );
  if( tcp_rx_sz < 0 && errno == EAGAIN ) return FD_SSRESOLVE_ADVANCE_AGAIN;
  if( tcp_rx_sz <= 0 ) return ( tcp_rx_sz == 0 ) ? FD_SSRESOLVE_ADVANCE_AGAIN : FD_SSRESOLVE_ADVANCE_ERROR;

  fd_tlsrec_slice_t tcp_rx_slice[1];
  fd_tlsrec_slice_init( tcp_rx_slice, tcp_rx_buf, (ulong)tcp_rx_sz );

  uchar tcp_tx_buf[ FD_SSRESOLVE_IO_BUF_SZ ];
  ulong tcp_tx_sz = sizeof(tcp_tx_buf);
  uchar app_rx_buf[ FD_SSRESOLVE_IO_BUF_SZ ];
  ulong app_rx_sz = sizeof(app_rx_buf);

  int rc = fd_tlsrec_conn_rx( &ssresolve->tls_conn, tcp_rx_slice,
                              tcp_tx_buf, &tcp_tx_sz,
                              app_rx_buf, &app_rx_sz );
  if( FD_UNLIKELY( rc != FD_TLSREC_SUCCESS ) ) return FD_SSRESOLVE_ADVANCE_ERROR;

  if( tcp_tx_sz > 0 ) {
    long sent = sendto( ssresolve->sockfd, tcp_tx_buf, tcp_tx_sz, MSG_NOSIGNAL, NULL, 0 );
    (void)sent;
  }

  if( app_rx_sz == 0 ) return FD_SSRESOLVE_ADVANCE_AGAIN;

  ulong copy = fd_ulong_min( app_rx_sz, bufsz );
  fd_memcpy( buf, app_rx_buf, copy );

  if( copy < app_rx_sz ) {
    ulong remain = app_rx_sz - copy;
    fd_memcpy( ssresolve->tls_app_buf, app_rx_buf + copy, remain );
    ssresolve->tls_app_buf_off = 0UL;
    ssresolve->tls_app_buf_sz  = remain;
  }

  return (long)copy;
}

static int
fd_ssresolve_send_request( fd_ssresolve_t * ssresolve ) {
  FD_TEST( ssresolve->state==FD_SSRESOLVE_STATE_REQ );

  if( FD_UNLIKELY( !ssresolve->request_len ) ) {
    fd_ssresolve_render_req( ssresolve );
  }

  long sent;
  if( FD_LIKELY( ssresolve->is_https ) ) {
    sent = ssresolve_send_tls( ssresolve,
                               ssresolve->request + ssresolve->request_sent,
                               ssresolve->request_len - ssresolve->request_sent );
    if( FD_UNLIKELY( sent <= 0 ) ) return (int)sent;
  } else {
    sent = sendto( ssresolve->sockfd, ssresolve->request+ssresolve->request_sent, ssresolve->request_len-ssresolve->request_sent, MSG_NOSIGNAL, NULL, 0 );
    if( FD_UNLIKELY( -1==sent && errno==EAGAIN ) ) return FD_SSRESOLVE_ADVANCE_AGAIN;
    else if( FD_UNLIKELY( -1==sent ) ) {
      FD_LOG_WARNING(( "sendto() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      return FD_SSRESOLVE_ADVANCE_ERROR;
    }
  }

  ssresolve->request_sent += (ulong)sent;
  if( FD_UNLIKELY( ssresolve->request_sent==ssresolve->request_len ) ) {
    ssresolve->state = FD_SSRESOLVE_STATE_RESP;
    return FD_SSRESOLVE_ADVANCE_SUCCESS;
  }

  return FD_SSRESOLVE_ADVANCE_AGAIN;
}

static int
fd_ssresolve_parse_redirect( fd_ssresolve_t *        ssresolve,
                             struct phr_header *     headers,
                             ulong                   header_cnt,
                             fd_ssresolve_result_t * result ) {
  ulong        location_len = 0UL;
  char const * location     = NULL;

  for( ulong i=0UL; i<header_cnt; i++ ) {
    if( FD_UNLIKELY( headers[ i ].name_len == 8 && !strncasecmp( headers[ i ].name, "location", headers[ i ].name_len ) ) ) {
      if( FD_UNLIKELY( !headers [ i ].value_len || headers[ i ].value[ 0 ]!='/' ) ) {
        FD_LOG_WARNING(( "invalid location header `%.*s`", (int)headers[ i ].value_len, headers[ i ].value ));
        return FD_SSRESOLVE_ADVANCE_ERROR;
      }

      location_len = headers[ i ].value_len;
      location = headers[ i ].value;
      break;
    }
  }

  if( FD_UNLIKELY( !location_len ) ) {
    FD_LOG_WARNING(( "no location header in redirect response" ));
    return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  if( FD_UNLIKELY( location_len>=PATH_MAX-1UL ) ) {
    FD_LOG_WARNING(( "redirect location header too long (%lu)", location_len ));
    return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  char snapshot_name[ PATH_MAX ];
  fd_memcpy( snapshot_name, location+1UL, location_len-1UL );
  snapshot_name[ location_len-1UL ] = '\0';

  int is_zstd;
  ulong full_entry_slot, incremental_entry_slot;
  uchar decoded_hash[ FD_HASH_FOOTPRINT ];
  int err = fd_ssarchive_parse_filename( snapshot_name, &full_entry_slot, &incremental_entry_slot, decoded_hash, &is_zstd );

  if( FD_UNLIKELY( err || !is_zstd ) ) {
    FD_LOG_WARNING(( "unrecognized snapshot file `%s` in redirect location header", snapshot_name ));
    return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  fd_memcpy( result->hash, decoded_hash, FD_HASH_FOOTPRINT );
  if( FD_LIKELY( incremental_entry_slot==ULONG_MAX ) ) {
    result->slot      = full_entry_slot;
    result->base_slot = ULONG_MAX;
  } else {
    result->slot      = incremental_entry_slot;
    result->base_slot = full_entry_slot;
  }

  if( FD_UNLIKELY( ssresolve->is_https ) ) ssresolve->state = FD_SSRESOLVE_STATE_SHUTTING_DOWN;
  else                                     ssresolve->state = FD_SSRESOLVE_STATE_DONE;
  return FD_SSRESOLVE_ADVANCE_RESULT;
}

static int
fd_ssresolve_read_response( fd_ssresolve_t *        ssresolve,
                            fd_ssresolve_result_t * result ) {
  FD_TEST( ssresolve->state==FD_SSRESOLVE_STATE_RESP );

  long read;
  if( FD_LIKELY( ssresolve->is_https ) ) {
    read = ssresolve_recv_tls( ssresolve,
                               ssresolve->response + ssresolve->response_len,
                               sizeof(ssresolve->response) - ssresolve->response_len );
    if( FD_UNLIKELY( read <= 0 ) ) return (int)read;
  } else {
    read = recvfrom( ssresolve->sockfd, ssresolve->response+ssresolve->response_len, sizeof(ssresolve->response)-ssresolve->response_len, 0, NULL, NULL );
    if( FD_UNLIKELY( -1==read && errno==EAGAIN ) ) return FD_SSRESOLVE_ADVANCE_AGAIN;
    else if( FD_UNLIKELY( -1==read ) ) {
      FD_LOG_WARNING(( "recvfrom() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      return FD_SSRESOLVE_ADVANCE_ERROR;
    }
  }

  ssresolve->response_len += (ulong)read;

  int               minor_version;
  int               status;
  const char *      message;
  ulong             message_len;
  struct phr_header headers[ 128UL ];
  ulong             header_cnt = 128UL;
  int parsed = phr_parse_response( ssresolve->response,
                                    ssresolve->response_len,
                                    &minor_version,
                                    &status,
                                    &message,
                                    &message_len,
                                    headers,
                                    &header_cnt,
                                    ssresolve->response_len - (ulong)read );
  if( FD_UNLIKELY( parsed==-1 ) ) {
    FD_LOG_WARNING(( "malformed response body" ));
    return FD_SSRESOLVE_ADVANCE_ERROR;
  } else if( parsed==-2 ) {
    return FD_SSRESOLVE_ADVANCE_AGAIN;
  }

  int is_redirect = (status==301) | (status==302) | (status==303) | (status==307) | (status==308);
  if( FD_UNLIKELY( is_redirect ) ) {
    return fd_ssresolve_parse_redirect( ssresolve, headers, header_cnt, result );
  }

  if( FD_UNLIKELY( status!=200 ) ) {
    char req_path[ 4096UL ];
    if( FD_LIKELY( ssresolve->is_https ) ) {
      FD_TEST( fd_cstr_printf_check( req_path, sizeof(req_path), NULL,
               "https://%s:%u%s", ssresolve->hostname, fd_ushort_bswap( ssresolve->addr.port ), ssresolve->full ? "/snapshot.tar.bz2" : "/incremental-snapshot.tar.bz2" ) );
    } else {
      FD_TEST( fd_cstr_printf_check( req_path, sizeof(req_path), NULL,
               "http://%s:%u%s", ssresolve->hostname, fd_ushort_bswap( ssresolve->addr.port ), ssresolve->full ? "/snapshot.tar.bz2" : "/incremental-snapshot.tar.bz2" ) );
    }
    FD_LOG_WARNING(( "unexpected response code %d accessing %s", status, req_path ));
    return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  return FD_SSRESOLVE_ADVANCE_ERROR;
}

static int
ssresolve_connect_tls( fd_ssresolve_t * ssresolve ) {
  /* Read available TCP data */
  uchar tcp_rx_buf[ FD_SSRESOLVE_IO_BUF_SZ ];
  long tcp_rx_sz = recvfrom( ssresolve->sockfd, tcp_rx_buf, sizeof(tcp_rx_buf), 0, NULL, NULL );
  if( tcp_rx_sz < 0 && errno != EAGAIN ) return FD_SSRESOLVE_ADVANCE_ERROR;
  if( tcp_rx_sz < 0 ) tcp_rx_sz = 0;

  fd_tlsrec_slice_t tcp_rx_slice[1];
  fd_tlsrec_slice_init( tcp_rx_slice, tcp_rx_buf, (ulong)tcp_rx_sz );

  uchar tcp_tx_buf[ FD_SSRESOLVE_IO_BUF_SZ ];
  ulong tcp_tx_sz = sizeof(tcp_tx_buf);
  uchar app_rx_buf[ FD_SSRESOLVE_IO_BUF_SZ ];
  ulong app_rx_sz = sizeof(app_rx_buf);

  int rc = fd_tlsrec_conn_rx( &ssresolve->tls_conn, tcp_rx_sz ? tcp_rx_slice : NULL,
                              tcp_tx_buf, &tcp_tx_sz,
                              app_rx_buf, &app_rx_sz );
  if( FD_UNLIKELY( rc != FD_TLSREC_SUCCESS ) ) {
    FD_LOG_WARNING(( "TLS handshake failed (%d-%s) for %s",
                     rc, fd_tlsrec_strerror( rc ), ssresolve->hostname ));
    return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  if( tcp_tx_sz > 0 ) {
    long sent = sendto( ssresolve->sockfd, tcp_tx_buf, tcp_tx_sz, MSG_NOSIGNAL, NULL, 0 );
    (void)sent;
  }

  if( fd_tlsrec_conn_is_ready( &ssresolve->tls_conn ) ) {
    if( app_rx_sz > 0 ) {
      ulong copy = fd_ulong_min( app_rx_sz, sizeof(ssresolve->tls_app_buf) );
      fd_memcpy( ssresolve->tls_app_buf, app_rx_buf, copy );
      ssresolve->tls_app_buf_off = 0UL;
      ssresolve->tls_app_buf_sz  = copy;
    }
    ssresolve->state = FD_SSRESOLVE_STATE_REQ;
    return FD_SSRESOLVE_ADVANCE_AGAIN;
  }

  if( fd_tlsrec_conn_is_failed( &ssresolve->tls_conn ) ) return FD_SSRESOLVE_ADVANCE_ERROR;
  return FD_SSRESOLVE_ADVANCE_AGAIN;
}

static int
ssresolve_shutdown_tls( fd_ssresolve_t * ssresolve ) {
  /* Just transition to DONE — no graceful TLS shutdown needed */
  ssresolve->state = FD_SSRESOLVE_STATE_DONE;
  return FD_SSRESOLVE_ADVANCE_SUCCESS;
}

int
fd_ssresolve_advance_poll_out( fd_ssresolve_t * ssresolve ) {
  int res;
  switch( ssresolve->state ) {
    case FD_SSRESOLVE_CONNECT:
      res = ssresolve_connect_tls( ssresolve );
      break;
    case FD_SSRESOLVE_STATE_SHUTTING_DOWN:
      res = ssresolve_shutdown_tls( ssresolve );
      break;
    case FD_SSRESOLVE_STATE_REQ:
      res = fd_ssresolve_send_request( ssresolve );
      break;
    case FD_SSRESOLVE_STATE_RESP:
      res = FD_SSRESOLVE_ADVANCE_AGAIN;
      break;
    default:
      FD_LOG_ERR(( "unexpected state %d", ssresolve->state ));
      return FD_SSRESOLVE_ADVANCE_ERROR;
  }
  return res;
}

int
fd_ssresolve_advance_poll_in( fd_ssresolve_t *        ssresolve,
                              fd_ssresolve_result_t * result ) {
  int res;
  switch( ssresolve->state ) {
    case FD_SSRESOLVE_CONNECT:
      res = ssresolve_connect_tls( ssresolve );
      break;
    case FD_SSRESOLVE_STATE_SHUTTING_DOWN:
      res = ssresolve_shutdown_tls( ssresolve );
      break;
    case FD_SSRESOLVE_STATE_RESP:
      res = fd_ssresolve_read_response( ssresolve, result );
      break;
    case FD_SSRESOLVE_STATE_REQ:
      res = FD_SSRESOLVE_ADVANCE_AGAIN;
      break;
    case FD_SSRESOLVE_STATE_DONE:
      res = FD_SSRESOLVE_ADVANCE_SUCCESS;
      break;
    default:
      FD_LOG_ERR(( "unexpected state %d", ssresolve->state ));
      return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  return res;
}

int
fd_ssresolve_is_done( fd_ssresolve_t * ssresolve ) {
  return ssresolve->state==FD_SSRESOLVE_STATE_DONE;
}

void
fd_ssresolve_cancel( fd_ssresolve_t * ssresolve ) {
  if( FD_LIKELY( ssresolve->sockfd!=-1 ) ) {
    if( FD_UNLIKELY( -1==close( ssresolve->sockfd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    ssresolve->sockfd = -1;
  }
  ssresolve->tls_app_buf_off = 0UL;
  ssresolve->tls_app_buf_sz  = 0UL;
}
