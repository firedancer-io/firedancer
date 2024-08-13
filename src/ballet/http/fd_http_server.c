#include "fd_http_server.h"

#include "picohttpparser.h"
#include "fd_sha1.h"
#include "../base64/fd_base64.h"

#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define FD_HTTP_SERVER_DEBUG 1

FD_FN_CONST char const *
fd_http_server_connection_close_reason_str( int reason ) {
  switch( reason ) {
    case FD_HTTP_SERVER_CONNECTION_CLOSE_OK:                           return "success";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED:                      return "EVICTED-Connection was evicted to make room for a new one";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_EXPECTED_EOF:                 return "EXPECTED_EOF-Client continued to send data when we expected no more";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET:                   return "PEER_RESET-Connection was reset by peer";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_LARGE_REQUEST:                return "LARGE_REQUEST-Request body was too large";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST:                  return "BAD_REQUEST-Request was malformed";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_MISSING_CONENT_LENGTH_HEADER: return "MISSING_CONENT_LENGTH_HEADER-Missing Content-Length header field";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD:               return "UNKNOWN_METHOD-Request method was not recognized";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_PATH_TOO_LONG:                return "PATH_TOO_LONG-Request path was too long";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_BAD_KEY:                   return "WS_BAD_KEY-Malformed Sec-WebSocket-Key header field";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_UNEXPECTED_VERSION:        return "WS_UNEXPECTED_VERSION-Unexpected Sec-Websocket-Version field";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_KEY_HEADER:        return "WS_MISSING_KEY_HEADER-Missing Sec-WebSocket-Key header field";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_VERSION_HEADER:    return "WS_MISSING_VERSION_HEADER-Missing Sec-WebSocket-Version header field";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_BAD_MASK:                  return "WS_BAD_MASK-Got frame from client without mask flag set";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_UNKNOWN_OPCODE:            return "WS_UNKNOWN_OPCODE-Unknown opcode in websocket frame";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_OVERSIZE_FRAME:            return "WS_OVERSIZE_FRAME-Websocket frame was too large";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CLIENT_TOO_SLOW:           return "WS_CLIENT_TOO_SLOW-Client was too slow to keep up with sender";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_UPGRADE:           return "WS_MISSING_UPGRADE-Missing Upgrade header field";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_EXPECTED_CONT_OPCODE:      return "WS_EXPECTED_CONT_OPCODE-Expected continuation opcode in websocket frame";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_EXPECTED_TEXT_OPCODE:      return "WS_EXPECTED_TEXT_OPCODE-Expected text opcode in websocket frame";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CONTROL_FRAME_TOO_LARGE:   return "WS_CONTROL_FRAME_TOO_LARGE-Websocket control frame was too large";
    default: break;
  }

  return "unknown";
}

FD_FN_CONST char const *
fd_http_server_method_str( uchar method ) {
  switch( method ) {
    case FD_HTTP_SERVER_METHOD_GET:  return "GET";
    case FD_HTTP_SERVER_METHOD_POST: return "POST";
    default: break;
  }

  return "unknown";
}

FD_FN_CONST ulong
fd_http_server_align( void ) {
  return FD_HTTP_SERVER_ALIGN;
}

FD_FN_CONST ulong
fd_http_server_footprint( fd_http_server_params_t params ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( struct fd_http_server_private ),       sizeof( fd_http_server_t )                                                                         );
  l = FD_LAYOUT_APPEND( l, alignof( struct fd_http_server_connection ),    params.max_connection_cnt*sizeof( struct fd_http_server_connection )                               );
  l = FD_LAYOUT_APPEND( l, alignof( struct fd_http_server_ws_connection ), params.max_ws_connection_cnt*sizeof( struct fd_http_server_ws_connection )                         );
  l = FD_LAYOUT_APPEND( l, alignof( struct pollfd ),                       (params.max_connection_cnt+params.max_ws_connection_cnt+1UL)*sizeof( struct pollfd )               );
  l = FD_LAYOUT_APPEND( l, 1UL,                                            params.max_request_len*params.max_connection_cnt                                                   );
  l = FD_LAYOUT_APPEND( l, 1UL,                                            params.max_ws_recv_frame_len*params.max_ws_connection_cnt                                          );
  l = FD_LAYOUT_APPEND( l, alignof( struct fd_http_server_ws_frame ),      params.max_ws_send_frame_cnt*params.max_ws_connection_cnt*sizeof( struct fd_http_server_ws_frame ) );
  return FD_LAYOUT_FINI( l, fd_http_server_align() );
}

void *
fd_http_server_new( void *                     shmem,
                    fd_http_server_params_t    params,
                    fd_http_server_callbacks_t callbacks,
                    void *                     callback_ctx ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_http_server_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_http_server_t * http = FD_SCRATCH_ALLOC_APPEND( l,  FD_HTTP_SERVER_ALIGN,                         sizeof(fd_http_server_t)                                                             );
  http->conns             = FD_SCRATCH_ALLOC_APPEND( l,  alignof(struct fd_http_server_connection),    params.max_connection_cnt*sizeof(struct fd_http_server_connection)                   );
  http->ws_conns          = FD_SCRATCH_ALLOC_APPEND( l,  alignof(struct fd_http_server_ws_connection), params.max_ws_connection_cnt*sizeof(struct fd_http_server_ws_connection)             );
  http->pollfds           = FD_SCRATCH_ALLOC_APPEND( l,  alignof(struct pollfd),                       (params.max_connection_cnt+params.max_ws_connection_cnt+1UL)*sizeof( struct pollfd ) );
  char * _request_bytes   = FD_SCRATCH_ALLOC_APPEND( l,  1UL,                                          params.max_request_len*params.max_connection_cnt                                     );
  uchar * _ws_recv_bytes  = FD_SCRATCH_ALLOC_APPEND( l,  1UL,                                          params.max_ws_recv_frame_len*params.max_ws_connection_cnt                            );
  struct fd_http_server_ws_frame * _ws_send_frames = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct fd_http_server_ws_frame), params.max_ws_send_frame_cnt*params.max_ws_connection_cnt*sizeof(struct fd_http_server_ws_frame) );

  http->callbacks             = callbacks;
  http->callback_ctx          = callback_ctx;
  http->conn_id               = 0UL;
  http->ws_conn_id            = 0UL;
  http->max_conns             = params.max_connection_cnt;
  http->max_ws_conns          = params.max_ws_connection_cnt;
  http->max_request_len       = params.max_request_len;
  http->max_ws_recv_frame_len = params.max_ws_recv_frame_len;
  http->max_ws_send_frame_cnt = params.max_ws_send_frame_cnt;

  for( ulong i=0UL; i<params.max_connection_cnt; i++ ) {
    http->pollfds[ i ].fd = -1;
    http->pollfds[ i ].events = POLLIN | POLLOUT;
    http->conns[ i ] = (struct fd_http_server_connection){
      .request_bytes = _request_bytes+i*params.max_request_len,
    };
  }

  for( ulong i=0UL; i<params.max_ws_connection_cnt; i++ ) {
    http->pollfds[ params.max_connection_cnt+i ].fd = -1;
    http->pollfds[ params.max_connection_cnt+i ].events = POLLIN | POLLOUT;
    http->ws_conns[ i ] = (struct fd_http_server_ws_connection){
      .recv_bytes = _ws_recv_bytes+i*params.max_ws_recv_frame_len,
      .send_frames = _ws_send_frames+i*params.max_ws_send_frame_cnt,
    };
  }

  http->pollfds[ params.max_connection_cnt+params.max_ws_connection_cnt ].fd     = -1;
  http->pollfds[ params.max_connection_cnt+params.max_ws_connection_cnt ].events = POLLIN | POLLOUT;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( http->magic ) = FD_HTTP_SERVER_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)http;
}

fd_http_server_t *
fd_http_server_join( void * shhttp ) {

  if( FD_UNLIKELY( !shhttp ) ) {
    FD_LOG_WARNING(( "NULL shhttp" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shhttp, fd_http_server_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shhttp" ));
    return NULL;
  }

  fd_http_server_t * http = (fd_http_server_t *)shhttp;

  if( FD_UNLIKELY( http->magic!=FD_HTTP_SERVER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return http;
}

void *
fd_http_server_leave( fd_http_server_t * http ) {

  if( FD_UNLIKELY( !http ) ) {
    FD_LOG_WARNING(( "NULL http" ));
    return NULL;
  }

  return (void *)http;
}

void *
fd_http_server_delete( void * shhttp ) {

  if( FD_UNLIKELY( !shhttp ) ) {
    FD_LOG_WARNING(( "NULL shhttp" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shhttp, fd_http_server_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shhttp" ));
    return NULL;
  }

  fd_http_server_t * http = (fd_http_server_t *)shhttp;

  if( FD_UNLIKELY( http->magic!=FD_HTTP_SERVER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( http->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)http;
}

fd_http_server_t *
fd_http_server_listen( fd_http_server_t * http,
                       ushort             port ) {
  int sockfd = socket( AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==sockfd ) ) FD_LOG_ERR(( "socket failed (%i-%s)", errno, strerror( errno ) ));

  int optval = 1;
  if( FD_UNLIKELY( -1==setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof( optval ) ) ) )
    FD_LOG_ERR(( "setsockopt failed (%i-%s)", errno, strerror( errno ) ));

  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_port        = fd_ushort_bswap( port ),
    .sin_addr.s_addr = INADDR_ANY,
  };

  if( FD_UNLIKELY( -1==bind( sockfd, fd_type_pun( &addr ), sizeof( addr ) ) ) ) FD_LOG_ERR(( "bind failed (%i-%s)", errno, strerror( errno ) ));
  if( FD_UNLIKELY( -1==listen( sockfd, (int)http->max_conns ) ) ) FD_LOG_ERR(( "listen failed (%i-%s)", errno, strerror( errno ) ));

  http->socket_fd = sockfd;
  http->pollfds[ http->max_conns+http->max_ws_conns ].fd = http->socket_fd;

  return http;
}

static void
close_conn( fd_http_server_t * http,
            ulong              conn_idx,
            int                reason ) {
  FD_TEST( http->pollfds[ conn_idx ].fd!=-1 );
#ifdef FD_HTTP_SERVER_DEBUG
  FD_LOG_NOTICE(( "Closing connection %lu (fd=%d) (%d-%s)", conn_idx, http->pollfds[ conn_idx ].fd, reason, fd_http_server_connection_close_reason_str( reason ) ));
#endif
  if( FD_UNLIKELY( -1==close( http->pollfds[ conn_idx ].fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, strerror( errno ) ));
  http->pollfds[ conn_idx ].fd = -1;
  if( FD_LIKELY( conn_idx<http->max_conns ) ) {
    if( FD_LIKELY( http->callbacks.close    ) ) http->callbacks.close( conn_idx, reason, http->callback_ctx );
  } else {
    if( FD_LIKELY( http->callbacks.ws_close ) ) http->callbacks.ws_close( conn_idx-http->max_conns, reason, http->callback_ctx );
  }
}

void
fd_http_server_close( fd_http_server_t * http,
                      ulong              conn_id,
                      int                reason ) {
  close_conn( http, conn_id, reason );
}

void
fd_http_server_ws_close( fd_http_server_t * http,
                         ulong              ws_conn_id,
                         int                reason ) {
  close_conn( http, http->max_conns+ws_conn_id, reason );
}

static void
accept_conns( fd_http_server_t * http ) {
  for(;;) {
    int fd = accept( http->socket_fd, NULL, NULL );

    if( FD_UNLIKELY( -1==fd ) ) {
      if( FD_LIKELY( EAGAIN==errno ) ) break;
      else if( FD_LIKELY( ENETDOWN==errno || EPROTO==errno || ENOPROTOOPT==errno || EHOSTDOWN==errno ||
                          ENONET==errno || EHOSTUNREACH==errno || EOPNOTSUPP==errno || ENETUNREACH==errno ) ) continue;
      else FD_LOG_ERR(( "accept failed (%i-%s)", errno, strerror( errno ) ));
    }

    /* Just evict oldest connection if it's still alive, they were too slow. */
    if( FD_UNLIKELY( -1!=http->pollfds[ http->conn_id ].fd ) ) close_conn( http, http->conn_id, FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED );

    http->pollfds[ http->conn_id ].fd = fd;
    http->conns[ http->conn_id ].state                  = FD_HTTP_SERVER_CONNECTION_STATE_READING;
    http->conns[ http->conn_id ].request_bytes_read     = 0UL;
    http->conns[ http->conn_id ].response_bytes_written = 0UL;

    http->conns[ http->conn_id ].response.body_len          = 0UL;
    http->conns[ http->conn_id ].response.content_type      = NULL;
    http->conns[ http->conn_id ].response.upgrade_websocket = 0;
    http->conns[ http->conn_id ].response.status            = 400;

    if( FD_UNLIKELY( http->callbacks.open ) ) {
      http->callbacks.open( http->conn_id, fd, http->callback_ctx );
    }

    http->conn_id = (http->conn_id+1UL) % http->max_conns;

#ifdef FD_HTTP_SERVER_DEBUG
    FD_LOG_NOTICE(( "Accepted connection %lu (fd=%d)", (http->conn_id+http->max_conns-1UL) % http->max_conns, fd ));
#endif
  }
}

static void
read_conn_http( fd_http_server_t * http,
                ulong              conn_idx ) {
  struct fd_http_server_connection * conn = &http->conns[ conn_idx ];

  if( FD_UNLIKELY( conn->state!=FD_HTTP_SERVER_CONNECTION_STATE_READING ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_EXPECTED_EOF );
    return;
  }

  long sz = read( http->pollfds[ conn_idx ].fd, conn->request_bytes+conn->request_bytes_read, http->max_request_len-conn->request_bytes_read );
  if( FD_UNLIKELY( -1==sz && errno==EAGAIN ) ) return; /* No data to read, continue. */
  else if( FD_UNLIKELY( !sz || (-1==sz && errno==ECONNRESET) ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET );
    return;
  }
  else if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "read failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

  /* New data was read... process it */
  conn->request_bytes_read += (ulong)sz;
  if( FD_UNLIKELY( conn->request_bytes_read==http->max_request_len ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_LARGE_REQUEST );
    return;
  }

  char const * method;
  ulong method_len;
  char const * path;
  ulong path_len;
  int minor_version;
  struct phr_header headers[ 32 ];
  ulong num_headers = 32UL;
  int result = phr_parse_request( conn->request_bytes,
                                  conn->request_bytes_read,
                                  &method, &method_len,
                                  &path, &path_len,
                                  &minor_version,
                                  headers, &num_headers,
                                  conn->request_bytes_read - (ulong)sz );
  if( FD_UNLIKELY( -2==result ) ) return; /* Request still partial, wait for more data */
  else if( FD_UNLIKELY( -1==result ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
    return;
  }

  uchar method_enum = UCHAR_MAX;
  if( FD_LIKELY( method_len==3UL && !strncmp( method, "GET", method_len ) ) ) method_enum = FD_HTTP_SERVER_METHOD_GET;
  else if( FD_LIKELY( method_len==4UL && !strncmp( method, "POST", method_len ) ) ) method_enum = FD_HTTP_SERVER_METHOD_POST;

  if( FD_UNLIKELY( method_enum==UCHAR_MAX ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD );
    return;
  }

  ulong content_len = 0UL;
  if( FD_UNLIKELY( method_enum==FD_HTTP_SERVER_METHOD_POST ) ) {
    char const * content_length = NULL;
    for( ulong i=0UL; i<num_headers; i++ ) {
      if( FD_LIKELY( headers[ i ].name_len==14UL && !strncasecmp( headers[ i ].name, "Content-Length", 14UL ) ) ) {
        content_length = headers[ i ].value;
        break;
      }
    }

    if( FD_UNLIKELY( !content_length ) ) {
      close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_MISSING_CONENT_LENGTH_HEADER );
      return;
    }

    errno = 0;
    content_len = strtoul( content_length, NULL, 10 );
    if( FD_UNLIKELY( content_len==ULONG_MAX && errno==ERANGE) ) {
      close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_MISSING_CONENT_LENGTH_HEADER );
      return;
    }

    if( FD_UNLIKELY( conn->request_bytes_read<(ulong)result+content_len ) ) {
      return; /* Request still partial, wait for more data */
    }
  }

  char content_type_nul_terminated[ 128 ] = {0};
  for( ulong i=0UL; i<num_headers; i++ ) {
    if( FD_LIKELY( headers[ i ].name_len==12UL && !strncasecmp( headers[ i ].name, "Content-Type", 12UL ) ) ) {
      if( FD_UNLIKELY( headers[ i ].value_len>(sizeof(content_type_nul_terminated)-1UL) ) ) {
        close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
        return;
      }
      memcpy( content_type_nul_terminated, headers[ i ].value, headers[ i ].value_len );
      break;
    }
  }

  char path_nul_terminated[ 128 ] = {0};
  if( FD_UNLIKELY( path_len>(sizeof( path_nul_terminated )-1UL) ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_PATH_TOO_LONG );
    return;
  }
  memcpy( path_nul_terminated, path, path_len );

  char const * upgrade_key = NULL;
  for( ulong i=0UL; i<num_headers; i++ ) {
    if( FD_LIKELY( headers[ i ].name_len==7UL && !strncasecmp( headers[ i ].name, "Upgrade", 7UL ) && headers[ i ].value_len==9UL ) ) {
      upgrade_key = headers[ i ].value;
      break;
    }
  }

  conn->upgrade_websocket = 0;
  if( FD_UNLIKELY( upgrade_key && !strncmp( upgrade_key, "websocket", 9UL ) ) ) {
    conn->request_bytes_len = (ulong)result;
    conn->upgrade_websocket = 1;

    char const * sec_websocket_key = NULL;
    for( ulong i=0UL; i<num_headers; i++ ) {
      if( FD_LIKELY( headers[ i ].name_len==17UL && !strncasecmp( headers[ i ].name, "Sec-WebSocket-Key", 17UL ) ) ) {
        sec_websocket_key = headers[ i ].value;
        if( FD_UNLIKELY( headers[ i ].value_len!=24 ) ) {
          close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_BAD_KEY );
          return;
        }
        break;
      }
    }

    char const * sec_websocket_version = NULL;
    for( ulong i=0UL; i<num_headers; i++ ) {
      if( FD_LIKELY( headers[ i ].name_len==21UL && !strncasecmp( headers[ i ].name, "Sec-Websocket-Version", 21UL ) ) ) {
        sec_websocket_version = headers[ i ].value;
        if( FD_UNLIKELY( headers[ i ].value_len!=2 || strncmp( sec_websocket_version, "13", 2UL ) ) ) {
          close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_UNEXPECTED_VERSION );
          return;
        }
        break;
      }
    }

    if( FD_UNLIKELY( !sec_websocket_key ) ) {
      close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_KEY_HEADER );
      return;
    }

    if( FD_UNLIKELY( !sec_websocket_version ) ) {
      close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_VERSION_HEADER );
      return;
    }

    conn->sec_websocket_key = sec_websocket_key;
  }

  conn->state    = FD_HTTP_SERVER_CONNECTION_STATE_WRITING_HEADER;

  fd_http_server_request_t request = {
    .connection_id             = conn_idx,

    .method                    = method_enum,
    .path                      = path_nul_terminated,

    .ctx                       = http->callback_ctx,

    .headers.content_type      = content_type_nul_terminated,
    .headers.upgrade_websocket = conn->upgrade_websocket,
  };

  switch( method_enum ) {
    case FD_HTTP_SERVER_METHOD_POST: {
      request.post.body     = (uchar*)conn->request_bytes+result;
      request.post.body_len = content_len;
    } break;
    default: break;
  }

  fd_http_server_response_t response = http->callbacks.request( &request );
  if( FD_LIKELY( http->pollfds[ conn_idx ].fd==-1 ) ) return; /* Connection was closed by callback */

  conn->response = response;

#ifdef FD_HTTP_SERVER_DEBUG
  FD_LOG_NOTICE(( "Received %s request \"%s\" from %lu (fd=%d) response code %lu", fd_http_server_method_str( method_enum ), path_nul_terminated, conn_idx, http->pollfds[ conn_idx ].fd, conn->response.status ));
#endif
}

static void
read_conn_ws( fd_http_server_t * http,
              ulong              conn_idx ) {
  struct fd_http_server_ws_connection * conn = &http->ws_conns[ conn_idx-http->max_conns ];

  long sz = read( http->pollfds[ conn_idx ].fd, conn->recv_bytes+conn->recv_bytes_parsed+conn->recv_bytes_read, http->max_ws_recv_frame_len-conn->recv_bytes_parsed-conn->recv_bytes_read );
  if( FD_UNLIKELY( -1==sz && errno==EAGAIN ) ) return; /* No data to read, continue. */
  else if( FD_UNLIKELY( !sz || (-1==sz && errno==ECONNRESET) ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET );
    return;
  }
  else if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "read failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

  /* New data was read... process it */
  conn->recv_bytes_read += (ulong)sz;
  if( FD_UNLIKELY( conn->recv_bytes_read<2UL ) ) return; /* Need at least 2 bytes to determine frame length */

  int is_mask_set = conn->recv_bytes[ conn->recv_bytes_parsed+1UL ] & 0x80;
  if( FD_UNLIKELY( !is_mask_set ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_BAD_MASK );
    return;
  }

  int opcode = conn->recv_bytes[ conn->recv_bytes_parsed ] & 0x0F;
  if( FD_UNLIKELY( opcode!=0x0 && opcode!=0x1 && opcode!=0x8 && opcode!=0x9 && opcode!=0xA ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_UNKNOWN_OPCODE );
    return;
  }

  ulong payload_len = conn->recv_bytes[ conn->recv_bytes_parsed+1UL ] & 0x7F;
  if( FD_UNLIKELY( (payload_len==126 || payload_len==127) && (opcode==0x8 || opcode==0x9 || opcode==0xA) ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CONTROL_FRAME_TOO_LARGE );
    return;
  }

  ulong len_bytes;
  if( FD_LIKELY( payload_len<126UL ) ) {
    len_bytes = 1UL;
  } else if( FD_LIKELY( payload_len==126 ) ) {
    if( FD_UNLIKELY( conn->recv_bytes_read<4UL ) ) return; /* Need at least 4 bytes to determine frame length */
    payload_len = ((ulong)conn->recv_bytes[ conn->recv_bytes_parsed+2UL ]<<8UL) | (ulong)conn->recv_bytes[ 3 ];
    len_bytes = 3UL;
  } else if( FD_LIKELY( payload_len==127 ) ) {
    if( FD_UNLIKELY( conn->recv_bytes_read<10UL ) ) return; /* Need at least 10 bytes to determine frame length */
    payload_len = ((ulong)conn->recv_bytes[ conn->recv_bytes_parsed+2 ]<<56UL) | ((ulong)conn->recv_bytes[ conn->recv_bytes_parsed+3UL ]<<48UL) | ((ulong)conn->recv_bytes[ conn->recv_bytes_parsed+4UL ]<<40UL) | ((ulong)conn->recv_bytes[ conn->recv_bytes_parsed+5UL ]<<32UL) |
                  ((ulong)conn->recv_bytes[ conn->recv_bytes_parsed+6 ]<<24UL) | ((ulong)conn->recv_bytes[ conn->recv_bytes_parsed+7UL ]<<16UL) | ((ulong)conn->recv_bytes[ conn->recv_bytes_parsed+8UL ]<<8UL ) |  (ulong)conn->recv_bytes[ conn->recv_bytes_parsed+9UL ];
    len_bytes = 9UL;
  } else {
    FD_LOG_ERR(( "unexpected payload_len %lu", payload_len )); /* Silence clang sanitizer, not possible */
    return;
  }

  ulong header_len = 1UL+len_bytes+4UL;
  ulong frame_len  = header_len+payload_len;

  if( FD_UNLIKELY( conn->recv_bytes_parsed+frame_len+1UL>http->max_ws_recv_frame_len ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_OVERSIZE_FRAME );
    return;
  }

  if( FD_UNLIKELY( conn->recv_bytes_read<frame_len ) ) return; /* Need more data to read the full frame */

  /* Data frame, process it */

  int is_fin_set = conn->recv_bytes[ conn->recv_bytes_parsed+0UL ] & 0x80;

  uchar * mask    = conn->recv_bytes+conn->recv_bytes_parsed+1UL+len_bytes;
  uchar   mask_copy[ 4 ] = { mask[ 0 ], mask[ 1 ], mask[ 2 ], mask[ 3 ] }; /* Bytes will be overwritten by the memmove below */

  uchar * payload = conn->recv_bytes+conn->recv_bytes_parsed+header_len;
  for( ulong i=0UL; i<payload_len; i++ ) conn->recv_bytes[ conn->recv_bytes_parsed+i ] = payload[ i ] ^ mask_copy[ i % 4 ];

  /* Frame is complete, process it */

  if( FD_UNLIKELY( opcode==0x8 ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET );
    return;
  } else if( FD_UNLIKELY( opcode==0x9 ) ) {
    /* Ping frame, queue pong unless we are already sending one */
    if( FD_LIKELY( conn->pong_state!=FD_HTTP_SERVER_PONG_STATE_WAITING ) ) {
      conn->pong_state    = FD_HTTP_SERVER_PONG_STATE_WAITING;
      conn->pong_data_len = payload_len;
      memcpy( conn->pong_data, conn->recv_bytes+conn->recv_bytes_parsed, payload_len );
    }
    if( FD_UNLIKELY( conn->recv_bytes_read-frame_len ) ) {
      memmove( conn->recv_bytes, conn->recv_bytes+conn->recv_bytes_parsed+frame_len, conn->recv_bytes_read-frame_len );
    }
    conn->recv_bytes_parsed = 0UL;
    conn->recv_bytes_read -= frame_len;
    return;
  } else if( FD_UNLIKELY( opcode==0xA ) ) {
    /* Pong frame, ignore */
    if( FD_UNLIKELY( conn->recv_bytes_read-frame_len ) ) {
      memmove( conn->recv_bytes, conn->recv_bytes+conn->recv_bytes_parsed+frame_len, conn->recv_bytes_read-frame_len );
    }
    conn->recv_bytes_parsed = 0UL;
    conn->recv_bytes_read -= frame_len;
    return;
  }

  if( FD_UNLIKELY( conn->recv_started_msg && opcode!=0x0 ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_EXPECTED_CONT_OPCODE );
    return;
  }

  if( FD_UNLIKELY( !conn->recv_started_msg && opcode!=0x1 ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_EXPECTED_TEXT_OPCODE );
    return;
  }

  /* Check if this is a complete message */

  if( FD_UNLIKELY( !is_fin_set ) ) {
    conn->recv_started_msg   = 1;
    conn->recv_bytes_read   -= frame_len;
    conn->recv_bytes_parsed += payload_len;
    return; /* Not a complete message yet */
  }

  /* Complete message, process it */

  uchar * trailing_data     = conn->recv_bytes+conn->recv_bytes_parsed+frame_len;
  ulong   trailing_data_len = conn->recv_bytes_read-frame_len;

  conn->recv_bytes_parsed += payload_len;
  conn->recv_bytes_read   -= frame_len;

  uchar tmp = conn->recv_bytes[ conn->recv_bytes_parsed ];
  conn->recv_bytes[ conn->recv_bytes_parsed ] = 0; /* NUL terminate */
  http->callbacks.ws_message( conn_idx-http->max_conns, conn->recv_bytes, conn->recv_bytes_parsed, http->callback_ctx );
  conn->recv_bytes[ conn->recv_bytes_parsed ] = tmp;

  conn->recv_started_msg  = 0;
  conn->recv_bytes_parsed = 0UL;
  if( FD_UNLIKELY( trailing_data_len ) ) {
    memmove( conn->recv_bytes, trailing_data, trailing_data_len );
  }
}

static void
read_conn( fd_http_server_t * http,
           ulong              conn_idx ) {
  if( FD_LIKELY( conn_idx<http->max_conns ) ) read_conn_http( http, conn_idx );
  else                                        read_conn_ws(   http, conn_idx );
}

static void
write_conn_http( fd_http_server_t * http,
                 ulong              conn_idx ) {
  struct fd_http_server_connection * conn = &http->conns[ conn_idx ];

  char header_buf[ 256 ];
  uchar const * response;
  ulong         response_len;
  switch( conn->state ) {
    case FD_HTTP_SERVER_CONNECTION_STATE_READING:
      return; /* No data staged for write yet. */
    case FD_HTTP_SERVER_CONNECTION_STATE_WRITING_HEADER:
      switch( conn->response.status ) {
        case 200:
          if( FD_UNLIKELY( conn->response.upgrade_websocket ) ) {
            if( FD_UNLIKELY( !conn->upgrade_websocket ) ) {
              close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_UPGRADE );
              return;
            }

            uchar sec_websocket_key[ 60 ];
            fd_memcpy( sec_websocket_key, conn->sec_websocket_key, 24 );
            fd_memcpy( sec_websocket_key+24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36 );

            uchar sec_websocket_accept[ 20 ];
            fd_sha1_hash( sec_websocket_key, 60, sec_websocket_accept );
            char sec_websocket_accept_base64[ FD_BASE64_ENC_SZ( 20 ) ];
            ulong encoded_len = fd_base64_encode( sec_websocket_accept_base64, sec_websocket_accept, 20 );
            FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %.*s\r\n\r\n", (int)encoded_len, sec_websocket_accept_base64 ) );
          } else {
            FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\nContent-Type: %s\r\n\r\n", conn->response.body_len, conn->response.content_type ) );
          }
          break;
        case 400:
          FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 400 Bad Request\r\nContent-Length: %lu\r\nContent-Type: %s\r\n\r\n", conn->response.body_len, conn->response.content_type ) );
          break;
        case 404:
          FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" ) );
          break;
        case 500:
          FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n" ) );
          break;
        default:
          FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n" ) );
          break;
      }
      response = (uchar const *)header_buf;
      break;
    case FD_HTTP_SERVER_CONNECTION_STATE_WRITING_BODY:
      response_len = conn->response.body_len;
      response     = conn->response.body;
      break;
    default:
      FD_LOG_ERR(( "invalid server state" ));
      return;
  }

  long sz = write( http->pollfds[ conn_idx ].fd, response+conn->response_bytes_written, response_len-conn->response_bytes_written );
  if( FD_UNLIKELY( -1==sz && (errno==EAGAIN || errno==EINTR) ) ) return; /* No data was written, continue. */
  if( FD_UNLIKELY( -1==sz && (errno==EPIPE || errno==ECONNRESET) ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET );
    return;
  }
  if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "write failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

  conn->response_bytes_written += (ulong)sz;
  if( FD_UNLIKELY( conn->response_bytes_written==response_len ) ) {
    switch( conn->state ) {
      case FD_HTTP_SERVER_CONNECTION_STATE_WRITING_HEADER:
        if( FD_UNLIKELY( conn->response.upgrade_websocket ) ) {
          int fd = http->pollfds[ conn_idx ].fd;
          http->pollfds[ conn_idx ].fd = -1;

          /* Just evict oldest ws connection if it's still alive, they
             were too slow. */
          ulong ws_conn_id = http->ws_conn_id;
          if( FD_UNLIKELY( -1!=http->pollfds[ http->max_conns+ws_conn_id ].fd ) ) close_conn( http, http->max_conns+ws_conn_id, FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED );
          http->pollfds[ http->max_conns+ws_conn_id ].fd = fd;
          http->ws_conn_id = (http->ws_conn_id+1UL) % http->max_ws_conns;

          http->ws_conns[ ws_conn_id ].pong_state               = FD_HTTP_SERVER_PONG_STATE_NONE;
          http->ws_conns[ ws_conn_id ].send_frame_cnt           = 0UL;
          http->ws_conns[ ws_conn_id ].send_frame_state         = FD_HTTP_SERVER_SEND_FRAME_STATE_HEADER;
          http->ws_conns[ ws_conn_id ].send_frame_idx           = 0UL;
          http->ws_conns[ ws_conn_id ].recv_started_msg         = 0;
          http->ws_conns[ ws_conn_id ].recv_bytes_parsed        = 0UL;
          http->ws_conns[ ws_conn_id ].recv_bytes_read          = 0UL;
          http->ws_conns[ ws_conn_id ].send_frame_bytes_written = 0UL;
          if( FD_UNLIKELY( conn->request_bytes_read-conn->request_bytes_len>0UL ) ) {
            /* Client might have already started sending data prior to
               response, so make sure to move it to the recv buffer. */
            fd_memcpy( http->ws_conns[ ws_conn_id ].recv_bytes, conn->request_bytes+conn->request_bytes_len, conn->request_bytes_read-conn->request_bytes_len );
            http->ws_conns[ ws_conn_id ].recv_bytes_read = conn->request_bytes_read-conn->request_bytes_len;
          }

#ifdef FD_HTTP_SERVER_DEBUG
          FD_LOG_WARNING(( "Upgraded connection %lu (fd=%d) to websocket connection %lu", conn_idx, fd, ws_conn_id ));
#endif

          if( FD_LIKELY( http->callbacks.ws_open ) ) http->callbacks.ws_open( ws_conn_id, http->callback_ctx );
        } else {
          conn->state                  = FD_HTTP_SERVER_CONNECTION_STATE_WRITING_BODY;
          conn->response_bytes_written = 0UL;
        }
        break;
      case FD_HTTP_SERVER_CONNECTION_STATE_WRITING_BODY:
        close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_OK );
        break;
    }
  }
}

static int
maybe_write_pong( fd_http_server_t * http,
                  ulong              conn_idx ) {
  struct fd_http_server_ws_connection * conn = &http->ws_conns[ conn_idx-http->max_conns ];

  /* No need to pong if ....

      Client has not sent a ping */
  if( FD_LIKELY( conn->pong_state==FD_HTTP_SERVER_PONG_STATE_NONE ) )       return 0;
  /*  We are in the middle of writing a data frame */
  if( FD_LIKELY( conn->send_frame_cnt && conn->send_frame_bytes_written ) ) return 0;

  /* Otherwise, we need to pong */
  if( FD_LIKELY( conn->pong_state==FD_HTTP_SERVER_PONG_STATE_WAITING ) ) {
    conn->pong_state         = FD_HTTP_SERVER_PONG_STATE_WRITING;
    conn->pong_bytes_written = 0UL;
  }

  uchar frame[ 2UL+125UL ];
  frame[ 0 ] = 0x80 | 0x0A; /* FIN, 0xA for pong. */
  frame[ 1 ] = (uchar)conn->pong_data_len;
  fd_memcpy( frame+2UL, conn->pong_data, conn->pong_data_len );

  long sz = write( http->pollfds[ conn_idx ].fd, frame+conn->pong_bytes_written, 2UL+conn->pong_data_len-conn->pong_bytes_written );
  if( FD_UNLIKELY( -1==sz && (errno==EAGAIN || errno==EINTR) ) ) return 1; /* No data was written, continue. */
  else if( FD_UNLIKELY( -1==sz && (errno==EPIPE || errno==ECONNRESET) ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET );
    return 1;
  }
  else if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "write failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

  conn->pong_bytes_written += (ulong)sz;
  if( FD_UNLIKELY( conn->pong_bytes_written==2UL+conn->pong_data_len ) ) {
    conn->pong_state = FD_HTTP_SERVER_PONG_STATE_NONE;
    return 0;
  }

  return 1;
}

static void
write_conn_ws( fd_http_server_t * http,
               ulong              conn_idx ) {
  struct fd_http_server_ws_connection * conn = &http->ws_conns[ conn_idx-http->max_conns ];

  if( FD_UNLIKELY( maybe_write_pong( http, conn_idx ) ) ) return;
  if( FD_UNLIKELY( !conn->send_frame_cnt ) ) return;

  fd_http_server_ws_frame_t * frame = &conn->send_frames[ conn->send_frame_idx ];
  switch( conn->send_frame_state ) {
    case FD_HTTP_SERVER_SEND_FRAME_STATE_HEADER: {
      uchar header[ 10 ];
      ulong header_len;
      header[ 0 ] = 0x80 | 0x01; /* FIN, 0x1 for text. */
      if( FD_LIKELY( frame->data_len<126UL ) ) {
        header[ 1 ] = (uchar)frame->data_len;
        header_len = 2UL;
      } else if( FD_LIKELY( frame->data_len<65536UL ) ) {
        header[ 1 ] = 126;
        header[ 2 ] = (uchar)(frame->data_len>>8);
        header[ 3 ] = (uchar)(frame->data_len);
        header_len = 4UL;
      } else {
        header[ 1 ] = 127;
        header[ 2 ] = (uchar)(frame->data_len>>56);
        header[ 3 ] = (uchar)(frame->data_len>>48);
        header[ 4 ] = (uchar)(frame->data_len>>40);
        header[ 5 ] = (uchar)(frame->data_len>>32);
        header[ 6 ] = (uchar)(frame->data_len>>24);
        header[ 7 ] = (uchar)(frame->data_len>>16);
        header[ 8 ] = (uchar)(frame->data_len>>8);
        header[ 9 ] = (uchar)(frame->data_len);
        header_len = 10UL;
      }

      long sz = write( http->pollfds[ conn_idx ].fd, header+conn->send_frame_bytes_written, header_len-conn->send_frame_bytes_written );
      if( FD_UNLIKELY( -1==sz && (errno==EAGAIN || errno==EINTR) ) ) return; /* No data was written, continue. */
      else if( FD_UNLIKELY( -1==sz && (errno==EPIPE || errno==ECONNRESET) ) ) {
        close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET );
        return;
      }
      else if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "write failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

      conn->send_frame_bytes_written += (ulong)sz;
      if( FD_UNLIKELY( conn->send_frame_bytes_written==header_len ) ) {
        conn->send_frame_state         = FD_HTTP_SERVER_SEND_FRAME_STATE_DATA;
        conn->send_frame_bytes_written = 0UL;
      }
      break;
    }
    case FD_HTTP_SERVER_SEND_FRAME_STATE_DATA: {
      long sz = write( http->pollfds[ conn_idx ].fd, frame->data+conn->send_frame_bytes_written, frame->data_len-conn->send_frame_bytes_written );
      if( FD_UNLIKELY( -1==sz && (errno==EAGAIN || errno==EINTR) ) ) return; /* No data was written, continue. */
      else if( FD_UNLIKELY( -1==sz && (errno==EPIPE || errno==ECONNRESET) ) ) {
        close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET );
        return;
      }
      else if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "write failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

      conn->send_frame_bytes_written += (ulong)sz;
      if( FD_UNLIKELY( conn->send_frame_bytes_written==frame->data_len ) ) {
        conn->send_frame_state = FD_HTTP_SERVER_SEND_FRAME_STATE_HEADER;
        conn->send_frame_idx   = (conn->send_frame_idx+1UL) % http->max_ws_send_frame_cnt;
        conn->send_frame_cnt--;
        conn->send_frame_bytes_written = 0UL;
      }
      break;
    }
  }
}

void
fd_http_server_ws_send( fd_http_server_t * http,
                        ulong              ws_conn_id,
                        fd_http_server_ws_frame_t frame ) {
  struct fd_http_server_ws_connection * conn = &http->ws_conns[ ws_conn_id ];

  if( FD_UNLIKELY( conn->send_frame_cnt==http->max_ws_send_frame_cnt ) ) {
    close_conn( http, ws_conn_id+http->max_conns, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CLIENT_TOO_SLOW );
    return;
  }

  conn->send_frames[ (conn->send_frame_idx+conn->send_frame_cnt) % http->max_ws_send_frame_cnt ] = frame;
  conn->send_frame_cnt++;
}

void
fd_http_server_ws_broadcast( fd_http_server_t *        http,
                             fd_http_server_ws_frame_t frame ) {
  for( ulong i=0UL; i<http->max_ws_conns; i++ ) {
    if( FD_LIKELY( http->pollfds[ http->max_conns+i ].fd==-1 ) ) continue;

    fd_http_server_ws_send( http, i, frame );
  }
}

static void
write_conn( fd_http_server_t * http,
            ulong              conn_idx ) {
  if( FD_LIKELY( conn_idx<http->max_conns ) ) write_conn_http( http, conn_idx );
  else                                        write_conn_ws(   http, conn_idx );
}

void
fd_http_server_poll( fd_http_server_t * http ) {
  int nfds = poll( http->pollfds, http->max_conns+http->max_ws_conns+1UL, 0 );
  if( FD_UNLIKELY( 0==nfds ) ) return;
  else if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) return;
  else if( FD_UNLIKELY( -1==nfds ) ) FD_LOG_ERR(( "poll failed (%i-%s)", errno, strerror( errno ) ));

  /* Poll existing connections for new data. */
  for( ulong i=0UL; i<http->max_conns+http->max_ws_conns+1UL; i++ ) {
    if( FD_UNLIKELY( -1==http->pollfds[ i ].fd ) ) continue;
    if( FD_UNLIKELY( i==http->max_conns+http->max_ws_conns ) ) {
      accept_conns( http );
    } else {
      if( FD_LIKELY( http->pollfds[ i ].revents & POLLIN  ) ) read_conn(  http, i );
      if( FD_UNLIKELY( -1==http->pollfds[ i ].fd ) ) continue;
      if( FD_LIKELY( http->pollfds[ i ].revents & POLLOUT ) ) write_conn( http, i );
      /* No need to handle POLLHUP, read() will return 0 soon enough. */
    }
  }
}
