#define _GNU_SOURCE
#include "fd_sshttp_private.h"
#include "fd_ssarchive.h"

#include "../../../waltz/http/picohttpparser.h"
#include "../../../waltz/openssl/fd_openssl_tile.h"
#include "../../../util/log/fd_log.h"
#include "../../../flamenco/types/fd_types_custom.h"

#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>

/* FIXME: Cleanup / standardize all the error logging. */

_Bool fd_sshttp_fuzz = 0;

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
  sshttp->content_len = 0UL;
  fd_cstr_fini( sshttp->snapshot_name );

#if FD_HAS_OPENSSL
  sshttp->ssl     = NULL;
  sshttp->ssl_ctx = NULL;

  if( !fd_sshttp_fuzz ) {
    SSL_CTX * ssl_ctx = SSL_CTX_new( TLS_client_method() );
    if( FD_UNLIKELY( !ssl_ctx ) ) {
      FD_LOG_ERR(( "SSL_CTX_new failed" ));
    }

    if( FD_UNLIKELY( !SSL_CTX_set_min_proto_version( ssl_ctx, TLS1_3_VERSION ) ) ) {
      FD_LOG_ERR(( "SSL_CTX_set_min_proto_version(ssl_ctx,TLS1_3_VERSION) failed" ));
    }

    /* transfering ownership of ssl_ctx by assignment */
    sshttp->ssl_ctx = ssl_ctx;

    fd_ossl_load_certs( sshttp->ssl_ctx );
  }
#endif

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

#if FD_HAS_OPENSSL
static void
http_init_ssl( fd_sshttp_t * http ) {
  FD_TEST( http->hostname );
  FD_TEST( http->ssl_ctx );

  http->ssl = SSL_new( http->ssl_ctx );
  if( FD_UNLIKELY( !http->ssl ) ) {
    FD_LOG_ERR(( "SSL_new failed" ));
  }

  static uchar const alpn_protos[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
  int alpn_res = SSL_set_alpn_protos( http->ssl, alpn_protos, sizeof(alpn_protos) );
  if( FD_UNLIKELY( alpn_res!=0 ) ) {
    FD_LOG_ERR(( "SSL_set_alpn_protos failed (%d)", alpn_res ));
  }

  /* set SNI */
  int set1_host_res = SSL_set1_host( http->ssl, http->hostname );
  if( FD_UNLIKELY( !set1_host_res ) ) {
    FD_LOG_ERR(( "SSL_set1_host failed (%d)", set1_host_res ));
  }
}
#endif

void
fd_sshttp_init( fd_sshttp_t * http,
                fd_ip4_port_t addr,
                char const *  hostname,
                int           is_https,
                char const *  path,
                ulong         path_len,
                long          now ) {
  FD_TEST( http->state==FD_SSHTTP_STATE_INIT );

  http->hostname = hostname;
  http->is_https = is_https;

  if( FD_LIKELY( is_https ) ) {
#if FD_HAS_OPENSSL
    http_init_ssl( http );
#else
  FD_LOG_ERR(( "cannot make HTTPS connection without OpenSSL" ));
#endif
  }

  http->hops         = 4UL;
  http->request_sent = 0UL;
  if( FD_LIKELY( is_https ) ) {
    FD_TEST( fd_cstr_printf_check( http->request, sizeof(http->request), &http->request_len,
      "GET %.*s HTTP/1.1\r\n"
      "User-Agent: Firedancer\r\n"
      "Accept: */*\r\n"
      "Accept-Encoding: identity\r\n"
      "Host: %s\r\n\r\n",
      (int)path_len, path, hostname ) );
  } else {
    FD_TEST( fd_cstr_printf_check( http->request, sizeof(http->request), &http->request_len,
      "GET %.*s HTTP/1.1\r\n"
      "User-Agent: Firedancer\r\n"
      "Accept: */*\r\n"
      "Accept-Encoding: identity\r\n"
      "Host: " FD_IP4_ADDR_FMT "\r\n\r\n",
      (int)path_len, path, FD_IP4_ADDR_FMT_ARGS( addr.addr ) ) );
  }

  http->response_len = 0UL;
  http->content_len  = 0UL;
  http->content_read = 0UL;
  http->empty_recvs  = 0UL;

  http->addr   = addr;
  http->sockfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==http->sockfd ) ) FD_LOG_ERR(( "socket() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  struct sockaddr_in addr_in = {
    .sin_family = AF_INET,
    .sin_port   = addr.port,
    .sin_addr   = { .s_addr = addr.addr }
  };

  if( FD_LIKELY( -1==connect( http->sockfd, fd_type_pun_const( &addr_in ), sizeof(addr_in) ) ) ) {
    if( FD_UNLIKELY( errno!=EINPROGRESS ) ) {
      if( FD_UNLIKELY( -1==close( http->sockfd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    }
  }

  if( FD_LIKELY( is_https ) ) {
    http->state    = FD_SSHTTP_STATE_CONNECT;
    http->deadline = now + FD_SSHTTP_DEADLINE_NANOS;
  } else {
    http->state    = FD_SSHTTP_STATE_REQ;
    http->deadline = now + FD_SSHTTP_DEADLINE_NANOS;
  }
}

#if FD_HAS_OPENSSL
static int
http_connect_ssl( fd_sshttp_t * http,
                  long          now ) {
  if( FD_UNLIKELY( now>http->deadline ) ) {
    FD_LOG_WARNING(("deadline exceeded during connect"));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  FD_TEST( http->ssl );
  SSL_set_fd( http->ssl, http->sockfd );
  int ssl_err = SSL_connect( http->ssl );
  if( FD_UNLIKELY( ssl_err!=1 ) ) {
    int ssl_err_code = SSL_get_error( http->ssl, ssl_err );
    if( FD_UNLIKELY( ssl_err_code!=SSL_ERROR_WANT_READ && ssl_err_code!=SSL_ERROR_WANT_WRITE ) ) {
      FD_LOG_WARNING(( "SSL_connect failed (%d)", ssl_err ));
      SSL_free( http->ssl );
      http->ssl = NULL;
      return FD_SSHTTP_ADVANCE_ERROR;
    }
    /* in progress */
    return FD_SSHTTP_ADVANCE_AGAIN;
  }

  http->state    = FD_SSHTTP_STATE_REQ;
  http->deadline = now + FD_SSHTTP_DEADLINE_NANOS;
  return FD_SSHTTP_ADVANCE_AGAIN;
}

static int
http_shutdown_ssl( fd_sshttp_t * http,
                   long          now ) {
  if( FD_UNLIKELY( now>http->deadline ) ) {
    FD_LOG_WARNING(("deadline exceeded during shutdown"));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  int res = SSL_shutdown( http->ssl );
  if( FD_LIKELY( res<=0 ) ) {
    int ssl_err_code = SSL_get_error( http->ssl, res );
    if( FD_UNLIKELY( ssl_err_code!=SSL_ERROR_WANT_READ && ssl_err_code!=SSL_ERROR_WANT_WRITE && res!=0 ) ) {
      FD_LOG_WARNING(( "SSL_shutdown failed (%d)", ssl_err_code ));
      SSL_free( http->ssl );
      http->ssl = NULL;
      return FD_SSHTTP_ADVANCE_ERROR;
    }

    return FD_SSHTTP_ADVANCE_AGAIN;
  }

  http->state = http->next_state;
  return FD_SSHTTP_ADVANCE_AGAIN;
}

static long
http_recv_ssl( fd_sshttp_t * http,
               void *        buf,
               ulong         bufsz ) {
  int read_res = SSL_read( http->ssl, buf, (int)bufsz );
  if( FD_UNLIKELY( read_res<=0 ) ) {
    int ssl_err = SSL_get_error( http->ssl, read_res );

    if( FD_UNLIKELY( ssl_err!=SSL_ERROR_WANT_READ && ssl_err!=SSL_ERROR_WANT_WRITE ) ) {
      FD_LOG_WARNING(( "SSL_read failed (%d)", ssl_err ));
      return FD_SSHTTP_ADVANCE_ERROR;
    }

    return FD_SSHTTP_ADVANCE_AGAIN;
  }

  return (long)read_res;
}

static long
http_send_ssl( fd_sshttp_t * http,
               void *        buf,
               ulong         bufsz ) {
  int write_res = SSL_write( http->ssl, buf, (int)bufsz );
  if( FD_UNLIKELY( write_res<=0 ) ) {
    int ssl_err = SSL_get_error( http->ssl, write_res );

    if( FD_UNLIKELY( ssl_err!=SSL_ERROR_WANT_READ && ssl_err!=SSL_ERROR_WANT_WRITE ) ) {
      FD_LOG_WARNING(( "SSL_write failed (%d)", ssl_err ));
      return FD_SSHTTP_ADVANCE_ERROR;
    }

    return FD_SSHTTP_ADVANCE_AGAIN;
  }

  return (long)write_res;
}

static int
setup_redirect( fd_sshttp_t * http,
              long          now ) {
  fd_sshttp_cancel( http );
  fd_sshttp_init( http, http->addr, http->hostname, http->is_https, http->location, http->location_len, now );
  return FD_SSHTTP_ADVANCE_AGAIN;
}

#endif

void
fd_sshttp_cancel( fd_sshttp_t * http ) {
  if( FD_LIKELY( http->state!=FD_SSHTTP_STATE_INIT && -1!=http->sockfd ) ) {
    if( FD_UNLIKELY( -1==close( http->sockfd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    http->sockfd = -1;
  }
  http->state = FD_SSHTTP_STATE_INIT;

#if FD_HAS_OPENSSL
  if( FD_LIKELY( http->ssl ) ) {
    SSL_free( http->ssl );
    http->ssl = NULL;
  }
#endif
}

static long
http_send( fd_sshttp_t * http,
           void *        buf,
           ulong         bufsz ) {
#if FD_HAS_OPENSSL
  if( FD_LIKELY( http->is_https ) ) return http_send_ssl( http, buf, bufsz );
#endif

  long sent = sendto( http->sockfd, buf, bufsz, 0, NULL, 0 );
  if( FD_UNLIKELY( -1==sent && errno==EAGAIN ) ) return FD_SSHTTP_ADVANCE_AGAIN;
  else if( FD_UNLIKELY( -1==sent ) ) {
    FD_LOG_WARNING(( "sendto() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  return sent;
}

static long
http_recv( fd_sshttp_t * http,
           void *        buf,
           ulong         bufsz ) {
#if FD_HAS_OPENSSL
  if( FD_LIKELY( http->is_https ) ) return http_recv_ssl( http, buf, bufsz );
#endif

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
      if( -1==fd_syscall_poll( &pfd, 1 /*fds*/, 1 /*ms*/ ) ) {
        FD_LOG_ERR(("fd_syscall_poll() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
    }
    return FD_SSHTTP_ADVANCE_AGAIN;
  } else if( FD_UNLIKELY( -1==read ) ) {
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
    FD_LOG_WARNING(( "too many redirects" ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  http->hops--;

  ulong        location_len;
  char const * location = NULL;

  for( ulong i=0UL; i<header_cnt; i++ ) {
    if( FD_UNLIKELY( headers[ i ].name_len == 8 && !strncasecmp( headers[ i ].name, "location", headers[ i ].name_len ) ) ) {
      if( FD_UNLIKELY( !headers [ i ].value_len || headers[ i ].value[ 0 ]!='/' ) ) {
        FD_LOG_WARNING(( "invalid location header `%.*s`", (int)headers[ i ].value_len, headers[ i ].value ));
        fd_sshttp_cancel( http );
        return FD_SSHTTP_ADVANCE_ERROR;
      }

      location_len = headers[ i ].value_len;
      location     = headers[ i ].value;

      if( FD_UNLIKELY( location_len>=PATH_MAX-1UL ) ) {
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
        FD_LOG_WARNING(( "unrecognized snapshot file `%s` in redirect location header", snapshot_name ));
        fd_sshttp_cancel( http );
        return FD_SSHTTP_ADVANCE_ERROR;
      }

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

  if( FD_UNLIKELY( !location ) ) {
    FD_LOG_WARNING(( "no location header in redirect response" ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  if( FD_UNLIKELY( !fd_cstr_printf_check( http->request, sizeof(http->request), &http->request_len,
    "GET %.*s HTTP/1.1\r\n"
    "User-Agent: Firedancer\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: identity\r\n"
    "Host: " FD_IP4_ADDR_FMT "\r\n\r\n",
    (int)location_len, location, FD_IP4_ADDR_FMT_ARGS( http->addr.addr ) ) ) ) {
    FD_LOG_WARNING(( "location header too long `%.*s`", (int)location_len, location ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  FD_LOG_NOTICE(( "following redirect to %s://" FD_IP4_ADDR_FMT ":%hu%.*s",
                  http->is_https ? "https" : "http", FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), fd_ushort_bswap( http->addr.port ),
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
      fd_sshttp_init( http, http->addr, http->hostname, http->is_https, location, location_len, now );
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
    FD_LOG_WARNING(( "timeout reading response" ));
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
    FD_LOG_WARNING(( "malformed response body" ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  } else if( parsed==-2 ) {
    return FD_SSHTTP_ADVANCE_AGAIN;
  }

  int is_redirect = (status==301) | (status==302) | (status==303) | (status==304) | (status==307) | (status==308);
  if( FD_UNLIKELY( is_redirect ) ) {
    return follow_redirect( http, headers, header_cnt, now );
  }

  if( FD_UNLIKELY( status!=200 ) ) {
    FD_LOG_WARNING(( "unexpected response status %d", status ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  http->content_read = 0UL;
  http->content_len = ULONG_MAX;
  for( ulong i=0UL; i<header_cnt; i++ ) {
    if( FD_LIKELY( headers[i].name_len!=14UL ) ) continue;
    if( FD_LIKELY( strncasecmp( headers[i].name, "content-length", 14UL ) ) ) continue;

    http->content_len = strtoul( headers[i].value, NULL, 10 );
    break;
  }

  if( FD_UNLIKELY( http->content_len==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "no content-length header in response" ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  http->state = FD_SSHTTP_STATE_DL;
  if( FD_UNLIKELY( (ulong)parsed<http->response_len ) ) {
    if( FD_UNLIKELY( *data_len<http->response_len-(ulong)parsed ) ) FD_LOG_ERR(( "data buffer too small %lu %lu %lu", *data_len, http->response_len, (ulong)parsed ));
    FD_TEST( *data_len>=http->response_len-(ulong)parsed );
    *data_len = http->response_len - (ulong)parsed;
    fd_memcpy( data, http->response+parsed, *data_len );
    http->content_read += *data_len;
    return FD_SSHTTP_ADVANCE_DATA;
  } else {
    FD_TEST( http->response_len==(ulong)parsed );
    return FD_SSHTTP_ADVANCE_AGAIN;
  }
}

static int
read_body( fd_sshttp_t * http,
           ulong *       data_len,
           uchar *       data,
           long          now ) {
  /* FIXME: Add a forward-progress timeout */

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
  long read = http_recv( http, data, fd_ulong_min( *data_len, http->content_len-http->content_read ) );
  if( FD_UNLIKELY( read<=0 ) ) return (int)read;

  if( FD_UNLIKELY( !read ) ) return FD_SSHTTP_ADVANCE_AGAIN;

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

int
fd_sshttp_advance( fd_sshttp_t * http,
                   ulong *       data_len,
                   uchar *       data,
                   long          now ) {
  switch( http->state ) {
    case FD_SSHTTP_STATE_INIT:          return FD_SSHTTP_ADVANCE_AGAIN;
#if FD_HAS_OPENSSL
    case FD_SSHTTP_STATE_CONNECT:       return http_connect_ssl( http, now );
    case FD_SSHTTP_STATE_SHUTTING_DOWN: return http_shutdown_ssl( http, now );
    case FD_SSHTTP_STATE_REDIRECT:      return setup_redirect( http, now );
#endif
    case FD_SSHTTP_STATE_REQ:           return send_request( http, now );
    case FD_SSHTTP_STATE_RESP:          return read_response( http, data_len, data, now );
    case FD_SSHTTP_STATE_DL:            return read_body( http, data_len, data, now );
    case FD_SSHTTP_STATE_DONE:
      fd_sshttp_cancel( http );
      http->state = FD_SSHTTP_STATE_INIT;
      return FD_SSHTTP_ADVANCE_DONE;
    default:                            return FD_SSHTTP_ADVANCE_ERROR;
  }
}
