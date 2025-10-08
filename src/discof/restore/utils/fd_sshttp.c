#define _GNU_SOURCE
#include "fd_sshttp.h"
#include "fd_ssarchive.h"

#include "../../../waltz/http/picohttpparser.h"
#include "../../../util/log/fd_log.h"
#include "../../../flamenco/types/fd_types_custom.h"

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#define FD_SSHTTP_STATE_INIT  (0) /* start */
#define FD_SSHTTP_STATE_REQ   (1) /* sending request */
#define FD_SSHTTP_STATE_RESP  (2) /* receiving response headers */
#define FD_SSHTTP_STATE_DL    (3) /* downloading response body */

struct fd_sshttp_private {
  int  state;
  long deadline;
  int  full;

  int   hops;

  fd_ip4_port_t addr;
  int           sockfd;

  char  request[ 4096UL ];
  ulong request_len;
  ulong request_sent;

  ulong response_len;
  char  response[ USHORT_MAX ];

  char  full_snapshot_name[ PATH_MAX ];
  char  incremental_snapshot_name[ PATH_MAX ];

  ulong content_len;
  ulong content_read;

  ulong magic;
};

FD_FN_CONST ulong
fd_sshttp_align( void ) {
  return FD_SSHTTP_ALIGN;
}

FD_FN_CONST ulong
fd_sshttp_footprint( void ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_SSHTTP_ALIGN, sizeof(fd_sshttp_t) );
  return FD_LAYOUT_FINI( l, FD_SSHTTP_ALIGN );
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
  fd_sshttp_t * sshttp = FD_SCRATCH_ALLOC_APPEND( l, FD_SSHTTP_ALIGN, sizeof(fd_sshttp_t) );

  sshttp->state = FD_SSHTTP_STATE_INIT;
  sshttp->full_snapshot_name[ 0 ] = '\0';
  sshttp->incremental_snapshot_name[ 0 ] = '\0';

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sshttp->magic ) = FD_SSHTTP_MAGIC;
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

void
fd_sshttp_init( fd_sshttp_t * http,
                fd_ip4_port_t addr,
                char const *  path,
                ulong         path_len,
                long          now ) {
  FD_TEST( http->state==FD_SSHTTP_STATE_INIT );

  http->hops = 4UL;

  http->request_sent = 0UL;
  FD_TEST( fd_cstr_printf_check( http->request, sizeof(http->request), &http->request_len,
    "GET %.*s HTTP/1.1\r\n"
    "User-Agent: Firedancer\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: identity\r\n"
    "Host: " FD_IP4_ADDR_FMT "\r\n\r\n",
    (int)path_len, path, FD_IP4_ADDR_FMT_ARGS( addr.addr ) ) );

  http->addr = addr;
  http->sockfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==http->sockfd ) ) FD_LOG_ERR(( "socket() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  struct sockaddr_in addr_in = {
    .sin_family = AF_INET,
    .sin_port   = fd_ushort_bswap( addr.port ),
    .sin_addr   = { .s_addr = addr.addr }
  };

  if( FD_UNLIKELY( -1==connect( http->sockfd, fd_type_pun_const( &addr_in ), sizeof(addr_in) ) ) ) {
    if( FD_UNLIKELY( errno!=EINPROGRESS ) ) {
      if( FD_UNLIKELY( -1==close( http->sockfd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      return;
    }
  }

  http->state    = FD_SSHTTP_STATE_REQ;
  http->deadline = now + 500L*1000L*1000L;
}

void
fd_sshttp_cancel( fd_sshttp_t * http ) {
  if( FD_LIKELY( http->state!=FD_SSHTTP_STATE_INIT && -1!=http->sockfd ) ) {
    if( FD_UNLIKELY( -1==close( http->sockfd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    http->sockfd = -1;
  }
  http->state = FD_SSHTTP_STATE_INIT;
}

static int
send_request( fd_sshttp_t * http,
              long          now ) {
  if( FD_UNLIKELY( now>http->deadline ) ) {
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  long sent = sendto( http->sockfd, http->request+http->request_sent, http->request_len-http->request_sent, 0, NULL, 0 );
  if( FD_UNLIKELY( -1==sent && errno==EAGAIN ) ) return FD_SSHTTP_ADVANCE_AGAIN;
  else if( FD_UNLIKELY( -1==sent ) ) {
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  http->request_sent += (ulong)sent;
  if( FD_UNLIKELY( http->request_sent==http->request_len ) ) {
    http->state = FD_SSHTTP_STATE_RESP;
    http->response_len = 0UL;
    http->deadline = now + 500L*1000L*1000L;
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
    if( FD_UNLIKELY( !strncasecmp( headers[ i ].name, "location", headers[ i ].name_len ) ) ) {
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

      ulong full_entry_slot, incremental_entry_slot;
      uchar decoded_hash[ FD_HASH_FOOTPRINT ];
      int err = fd_ssarchive_parse_filename( snapshot_name, &full_entry_slot, &incremental_entry_slot, decoded_hash );

      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "unrecognized snapshot file `%s` in redirect location header", snapshot_name ));
        fd_sshttp_cancel( http );
        return FD_SSHTTP_ADVANCE_ERROR;
      }

      char encoded_hash[ FD_BASE58_ENCODED_32_SZ ];
      fd_base58_encode_32( decoded_hash, NULL, encoded_hash );

      if( FD_LIKELY( incremental_entry_slot!=ULONG_MAX ) ) {
        FD_TEST( fd_cstr_printf_check( http->incremental_snapshot_name, PATH_MAX, NULL, "incremental-snapshot-%lu-%lu-%s.tar.zst", full_entry_slot, incremental_entry_slot, encoded_hash ) );
      } else {
        FD_TEST( fd_cstr_printf_check( http->full_snapshot_name, PATH_MAX, NULL, "snapshot-%lu-%s.tar.zst", full_entry_slot, encoded_hash ) );
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

  FD_LOG_NOTICE(( "following redirect to http://" FD_IP4_ADDR_FMT ":%hu%.*s",
                  FD_IP4_ADDR_FMT_ARGS( http->addr.addr ), http->addr.port,
                  (int)headers[ 0 ].value_len, headers[ 0 ].value ));

  fd_sshttp_cancel( http );
  fd_sshttp_init( http, http->addr, location, location_len, now );

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

  long read = recvfrom( http->sockfd, http->response+http->response_len, sizeof(http->response)-http->response_len, 0, NULL, NULL );
  if( FD_UNLIKELY( -1==read && errno==EAGAIN ) ) return 0;
  else if( FD_UNLIKELY( -1==read ) ) {
    FD_LOG_WARNING(( "recv() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

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
           uchar *       data ) {
  if( FD_UNLIKELY( http->content_read>=http->content_len ) ) {
    fd_sshttp_cancel( http );
    http->state = FD_SSHTTP_STATE_INIT;
    return FD_SSHTTP_ADVANCE_DONE;
  }

  FD_TEST( http->content_read<http->content_len );
  long read = recvfrom( http->sockfd, data, fd_ulong_min( *data_len, http->content_len-http->content_read ), 0, NULL, NULL );
  if( FD_UNLIKELY( -1==read && errno==EAGAIN ) ) return FD_SSHTTP_ADVANCE_AGAIN;
  else if( FD_UNLIKELY( -1==read ) ) {
    fd_sshttp_cancel( http );
    return FD_SSHTTP_ADVANCE_ERROR;
  }

  if( FD_UNLIKELY( !read ) ) return FD_SSHTTP_ADVANCE_AGAIN;

  *data_len = (ulong)read;
  http->content_read += (ulong)read;

  return FD_SSHTTP_ADVANCE_DATA;
}

void
fd_sshttp_snapshot_names( fd_sshttp_t const * http,
                          char const **       full_snapshot_name,
                          char const **       incremental_snapshot_name ) {
  *full_snapshot_name        = http->full_snapshot_name;
  *incremental_snapshot_name = http->incremental_snapshot_name;
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
  /* TODO: Add timeouts ... */

  switch( http->state ) {
    case FD_SSHTTP_STATE_INIT: return FD_SSHTTP_ADVANCE_AGAIN;
    case FD_SSHTTP_STATE_REQ: return send_request( http, now );
    case FD_SSHTTP_STATE_RESP: return read_response( http, data_len, data, now );
    case FD_SSHTTP_STATE_DL: return read_body( http, data_len, data );
    default: return 0;
  }
}
