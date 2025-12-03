#include "fd_ssresolve.h"
#include "fd_ssarchive.h"

#include "../../../waltz/http/picohttpparser.h"
#include "../../../util/log/fd_log.h"

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

/* TODO: consider refactoring the common http code in ssresolve and
   sshttp into a common library */

#define FD_SSRESOLVE_CONNECT             (0) /* connecting ssl */
#define FD_SSRESOLVE_STATE_REQ           (1) /* sending request for snapshot */
#define FD_SSRESOLVE_STATE_RESP          (2) /* receiving snapshot response */
#define FD_SSRESOLVE_STATE_SHUTTING_DOWN (3) /* shutting down ssl */
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

#if FD_HAS_OPENSSL
  SSL * ssl;
#endif

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

  ssresolve->state        = FD_SSRESOLVE_STATE_REQ;
  ssresolve->request_sent = 0UL;
  ssresolve->request_len  = 0UL;
  ssresolve->response_len = 0UL;
  ssresolve->sockfd       = -1;

#if FD_HAS_OPENSSL
  ssresolve->ssl = NULL;
#endif

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
                   int              full ) {
  ssresolve->addr   = addr;
  ssresolve->sockfd = sockfd;
  ssresolve->full   = full;

  ssresolve->state        = FD_SSRESOLVE_STATE_REQ;
  ssresolve->request_sent = 0UL;
  ssresolve->request_len  = 0UL;
  ssresolve->response_len = 0UL;
  ssresolve->is_https     = 0;
}

#if FD_HAS_OPENSSL
void
fd_ssresolve_init_https( fd_ssresolve_t * ssresolve,
                         fd_ip4_port_t    addr,
                         int              sockfd,
                         int              full,
                         char const *     hostname,
                         SSL_CTX *        ssl_ctx ) {
  ssresolve->addr   = addr;
  ssresolve->sockfd = sockfd;
  ssresolve->full   = full;

  ssresolve->state        = FD_SSRESOLVE_CONNECT;
  ssresolve->request_sent = 0UL;
  ssresolve->request_len  = 0UL;
  ssresolve->response_len = 0UL;
  ssresolve->is_https     = 1;
  ssresolve->hostname     = hostname;

  ssresolve->ssl = SSL_new( ssl_ctx );
  if( FD_UNLIKELY( !ssresolve->ssl ) ) {
    FD_LOG_ERR(( "SSL_new failed" ));
  }

  static uchar const alpn_protos[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
  int alpn_res = SSL_set_alpn_protos( ssresolve->ssl, alpn_protos, sizeof(alpn_protos) );
  if( FD_UNLIKELY( alpn_res!=0 ) ) {
    FD_LOG_ERR(( "SSL_set_alpn_protos failed (%d)", alpn_res ));
  }

  /* set SNI */
  FD_TEST( hostname && hostname[ 0 ]!='\0' );
  int set1_host_res = SSL_set1_host( ssresolve->ssl, hostname );
  if( FD_UNLIKELY( !set1_host_res ) ) {
    FD_LOG_ERR(( "SSL_set1_host failed (%d)", set1_host_res ));
  }
}
#endif

static void
fd_ssresolve_render_req( fd_ssresolve_t * ssresolve ) {
  if( FD_LIKELY( ssresolve->full ) ) {
    if( FD_UNLIKELY( ssresolve->is_https ) ) {
      FD_TEST( fd_cstr_printf_check( ssresolve->request, sizeof(ssresolve->request), &ssresolve->request_len,
             "HEAD /snapshot.tar.bz2 HTTP/1.1\r\n"
             "User-Agent: Firedancer\r\n"
             "Accept: */*\r\n"
             "Accept-Encoding: identity\r\n"
             "Host: %s\r\n\r\n",
             ssresolve->hostname ) );
    } else {
      FD_TEST( fd_cstr_printf_check( ssresolve->request, sizeof(ssresolve->request), &ssresolve->request_len,
             "HEAD /snapshot.tar.bz2 HTTP/1.1\r\n"
             "User-Agent: Firedancer\r\n"
             "Accept: */*\r\n"
             "Accept-Encoding: identity\r\n"
             "Host: " FD_IP4_ADDR_FMT "\r\n\r\n",
             FD_IP4_ADDR_FMT_ARGS( ssresolve->addr.addr ) ) );
    }
  } else {
    if( FD_UNLIKELY( ssresolve->is_https ) ) {
      FD_TEST( fd_cstr_printf_check( ssresolve->request, sizeof(ssresolve->request), &ssresolve->request_len,
             "HEAD /incremental-snapshot.tar.bz2 HTTP/1.1\r\n"
             "User-Agent: Firedancer\r\n"
             "Accept: */*\r\n"
             "Accept-Encoding: identity\r\n"
             "Host: %s\r\n\r\n",
             ssresolve->hostname ) );
    } else {
      FD_TEST( fd_cstr_printf_check( ssresolve->request, sizeof(ssresolve->request), &ssresolve->request_len,
             "HEAD /incremental-snapshot.tar.bz2 HTTP/1.1\r\n"
             "User-Agent: Firedancer\r\n"
             "Accept: */*\r\n"
             "Accept-Encoding: identity\r\n"
             "Host: " FD_IP4_ADDR_FMT "\r\n\r\n",
             FD_IP4_ADDR_FMT_ARGS( ssresolve->addr.addr ) ) );
    }
  }
}

static int
fd_ssresolve_send_request( fd_ssresolve_t * ssresolve ) {
  FD_TEST( ssresolve->state==FD_SSRESOLVE_STATE_REQ );

  if( FD_UNLIKELY( !ssresolve->request_len ) ) {
    fd_ssresolve_render_req( ssresolve );
  }

  long sent = 0L;
  if( FD_LIKELY( ssresolve->is_https ) ) {
#if FD_HAS_OPENSSL
    int write_res = SSL_write( ssresolve->ssl, ssresolve->request+ssresolve->request_sent, (int)(ssresolve->request_len-ssresolve->request_sent) );
    if( FD_UNLIKELY( write_res<=0 ) ) {
      int ssl_err = SSL_get_error( ssresolve->ssl, write_res );

      if( FD_UNLIKELY( ssl_err!=SSL_ERROR_WANT_READ && ssl_err!=SSL_ERROR_WANT_WRITE ) ) {
        FD_LOG_WARNING(( "SSL_write failed (%d)", ssl_err ));
        return FD_SSRESOLVE_ADVANCE_ERROR;
      }

      return FD_SSRESOLVE_ADVANCE_AGAIN;
    }

    sent = (long)write_res;
#else
    FD_LOG_ERR(( "cannot use HTTPS without OpenSSL" ));
#endif
  } else {
    sent = sendto( ssresolve->sockfd, ssresolve->request+ssresolve->request_sent, ssresolve->request_len-ssresolve->request_sent, 0, NULL, 0 );
    if( FD_UNLIKELY( -1==sent && errno==EAGAIN ) ) return FD_SSRESOLVE_ADVANCE_AGAIN;
    else if( FD_UNLIKELY( -1==sent ) )             return FD_SSRESOLVE_ADVANCE_ERROR;
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

  if( FD_UNLIKELY( location_len>=PATH_MAX-1UL ) ) return FD_SSRESOLVE_ADVANCE_ERROR;

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

  long read = 0L;
  if( FD_LIKELY( ssresolve->is_https ) ) {
#if FD_HAS_OPENSSL
    int read_res = SSL_read( ssresolve->ssl, ssresolve->response+ssresolve->response_len, (int)(sizeof(ssresolve->response)-ssresolve->response_len) );
    if( FD_UNLIKELY( read_res<=0 ) ) {
      int ssl_err = SSL_get_error( ssresolve->ssl, read_res );

      if( FD_UNLIKELY( ssl_err!=SSL_ERROR_WANT_READ && ssl_err!=SSL_ERROR_WANT_WRITE ) ) {
        FD_LOG_WARNING(( "SSL_read failed (%d)", ssl_err ));
        return FD_SSRESOLVE_ADVANCE_ERROR;
      }

      return FD_SSRESOLVE_ADVANCE_AGAIN;
    }

    read = (long)read_res;
#else
    FD_LOG_ERR(( "cannot use HTTPS without OpenSSL" ));
#endif
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

  int is_redirect = (status==301) | (status==302) | (status==303) | (status==304) | (status==307) | (status==308);
  if( FD_UNLIKELY( is_redirect ) ) {
    return fd_ssresolve_parse_redirect( ssresolve, headers, header_cnt, result );
  }

  if( FD_UNLIKELY( status!=200 ) ) {
    FD_LOG_WARNING(( "unexpected response status %d", status ));
    return FD_SSRESOLVE_ADVANCE_ERROR;
  }

  return FD_SSRESOLVE_ADVANCE_ERROR;
}

#if FD_HAS_OPENSSL
static int
ssresolve_connect_ssl( fd_ssresolve_t * ssresolve ) {
  FD_TEST( ssresolve->ssl );
  SSL_set_fd( ssresolve->ssl, ssresolve->sockfd );
  int ssl_err = SSL_connect( ssresolve->ssl );
  if( FD_UNLIKELY( ssl_err!=1 ) ) {
    int ssl_err_code = SSL_get_error( ssresolve->ssl, ssl_err );
    if( FD_UNLIKELY( ssl_err_code!=SSL_ERROR_WANT_READ && ssl_err_code!=SSL_ERROR_WANT_WRITE ) ) {
      FD_LOG_WARNING(( "SSL_connect failed (%d)", ssl_err_code ));
      SSL_free( ssresolve->ssl );
      ssresolve->ssl = NULL;
      return FD_SSRESOLVE_ADVANCE_ERROR;
    }
    /* in progress */
    return FD_SSRESOLVE_ADVANCE_AGAIN;
  }

  ssresolve->state = FD_SSRESOLVE_STATE_REQ;
  return FD_SSRESOLVE_ADVANCE_AGAIN;
}

static int
ssresolve_shutdown_ssl( fd_ssresolve_t * ssresolve ) {
  int res = SSL_shutdown( ssresolve->ssl );
  if( FD_LIKELY( res<=0 ) ) {
    int ssl_err_code = SSL_get_error( ssresolve->ssl, res );
    if( FD_UNLIKELY( ssl_err_code!=SSL_ERROR_WANT_READ && ssl_err_code!=SSL_ERROR_WANT_WRITE && res!=0 ) ) {
      FD_LOG_WARNING(( "SSL_shutdown failed (%d)", ssl_err_code ));
      SSL_free( ssresolve->ssl );
      ssresolve->ssl = NULL;
      return FD_SSRESOLVE_ADVANCE_ERROR;
    }

    return FD_SSRESOLVE_ADVANCE_AGAIN;
  }

  ssresolve->state = FD_SSRESOLVE_STATE_DONE;
  return FD_SSRESOLVE_ADVANCE_SUCCESS;
}
#endif

int
fd_ssresolve_advance_poll_out( fd_ssresolve_t * ssresolve ) {
  int res;
  switch( ssresolve->state ) {
#if FD_HAS_OPENSSL
    case FD_SSRESOLVE_CONNECT: {
      res = ssresolve_connect_ssl( ssresolve );
      break;
    }
    case FD_SSRESOLVE_STATE_SHUTTING_DOWN: {
      res = ssresolve_shutdown_ssl( ssresolve );
      break;
    }
#endif
    case FD_SSRESOLVE_STATE_REQ: {
      res = fd_ssresolve_send_request( ssresolve );
      break;
    }
    case FD_SSRESOLVE_STATE_RESP: {
      res = FD_SSRESOLVE_ADVANCE_AGAIN;
      break;
    }
    default: {
      FD_LOG_ERR(( "unexpected state %d", ssresolve->state ));
      return FD_SSRESOLVE_ADVANCE_ERROR;
    }
  }
  return res;
}

int
fd_ssresolve_advance_poll_in( fd_ssresolve_t *        ssresolve,
                              fd_ssresolve_result_t * result ) {
  int res;
  switch( ssresolve->state ) {
#if FD_HAS_OPENSSL
    case FD_SSRESOLVE_CONNECT: {
      res = ssresolve_connect_ssl( ssresolve );
      break;
    }
    case FD_SSRESOLVE_STATE_SHUTTING_DOWN: {
      res = ssresolve_shutdown_ssl( ssresolve );
      break;
    }
#endif
    case FD_SSRESOLVE_STATE_RESP: {
      res = fd_ssresolve_read_response( ssresolve, result );
      break;
    }
    case FD_SSRESOLVE_STATE_REQ: {
      res = FD_SSRESOLVE_ADVANCE_AGAIN;
      break;
    }
    case FD_SSRESOLVE_STATE_DONE: {
      res = FD_SSRESOLVE_ADVANCE_SUCCESS;
      break;
    }
    default: {
      FD_LOG_ERR(( "unexpected state %d", ssresolve->state ));
      return FD_SSRESOLVE_ADVANCE_ERROR;
    }
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
#if FD_HAS_OPENSSL
  if( FD_LIKELY( ssresolve->ssl ) ) {
    SSL_free( ssresolve->ssl );
    ssresolve->ssl = NULL;
  }
#endif
}
