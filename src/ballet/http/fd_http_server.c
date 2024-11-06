#define _GNU_SOURCE
#include "fd_http_server_private.h"

#include "picohttpparser.h"
#include "fd_sha1.h"
#include "../base64/fd_base64.h"

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define POOL_NAME       ws_conn_pool
#define POOL_T          struct fd_http_server_ws_connection
#define POOL_IDX_T      ushort
#define POOL_NEXT       parent
#include "../../util/tmpl/fd_pool.c"

#define POOL_NAME       conn_pool
#define POOL_T          struct fd_http_server_connection
#define POOL_IDX_T      ushort
#define POOL_NEXT       parent
#include "../../util/tmpl/fd_pool.c"

#define TREAP_NAME      ws_conn_treap
#define TREAP_T         struct fd_http_server_ws_connection
#define TREAP_QUERY_T   void *                                         /* We don't use query ... */
#define TREAP_CMP(q,e)  (__extension__({ (void)(q); (void)(e); -1; })) /* which means we don't need to give a real
                                                                          implementation to cmp either */
#define TREAP_IDX_T     ushort
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_LT(e0,e1) ((e0)->send_frames[ (e0)->send_frame_idx ].off<(e1)->send_frames[ (e1)->send_frame_idx ].off)

#include "../../util/tmpl/fd_treap.c"

#define TREAP_NAME      conn_treap
#define TREAP_T         struct fd_http_server_connection
#define TREAP_QUERY_T   void *                                         /* We don't use query ... */
#define TREAP_CMP(q,e)  (__extension__({ (void)(q); (void)(e); -1; })) /* which means we don't need to give a real
                                                                          implementation to cmp either */
#define TREAP_IDX_T     ushort
#define TREAP_OPTIMIZE_ITERATION 1
#define TREAP_LT(e0,e1) ((e0)->response._body_off<(e1)->response._body_off)

#include "../../util/tmpl/fd_treap.c"

#define FD_HTTP_SERVER_DEBUG 0

FD_FN_CONST char const *
fd_http_server_connection_close_reason_str( int reason ) {
  switch( reason ) {
    case FD_HTTP_SERVER_CONNECTION_CLOSE_OK:                           return "OK-Connection was closed normally";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED:                      return "EVICTED-Connection was evicted to make room for a new one";
    case FD_HTTP_SERVER_CONNECTION_CLOSE_TOO_SLOW:                     return "TOO_SLOW-Client was too slow and did not read the reponse in time";
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
    case FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CHANGED_OPCODE:            return "FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CHANGED_OPCODE-Websocket frame type changed unexpectedly";
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
  l = FD_LAYOUT_APPEND( l, FD_HTTP_SERVER_ALIGN,                           sizeof( fd_http_server_t )                                                                         );
  l = FD_LAYOUT_APPEND( l, conn_pool_align(),                              conn_pool_footprint( params.max_connection_cnt )                                                   );
  l = FD_LAYOUT_APPEND( l, ws_conn_pool_align(),                           ws_conn_pool_footprint( params.max_ws_connection_cnt )                                             );
  l = FD_LAYOUT_APPEND( l, conn_treap_align(),                             conn_treap_footprint( params.max_connection_cnt )                                                  );
  l = FD_LAYOUT_APPEND( l, ws_conn_treap_align(),                          ws_conn_treap_footprint( params.max_ws_connection_cnt )                                            );
  l = FD_LAYOUT_APPEND( l, alignof( struct pollfd ),                       (params.max_connection_cnt+params.max_ws_connection_cnt+1UL)*sizeof( struct pollfd )               );
  l = FD_LAYOUT_APPEND( l, 1UL,                                            params.max_request_len*params.max_connection_cnt                                                   );
  l = FD_LAYOUT_APPEND( l, 1UL,                                            params.max_ws_recv_frame_len*params.max_ws_connection_cnt                                          );
  l = FD_LAYOUT_APPEND( l, alignof( struct fd_http_server_ws_frame ),      params.max_ws_send_frame_cnt*params.max_ws_connection_cnt*sizeof( struct fd_http_server_ws_frame ) );
  l = FD_LAYOUT_APPEND( l, 1UL,                                            params.outgoing_buffer_sz                                                                          );
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

  if( FD_UNLIKELY( params.max_ws_connection_cnt && params.max_ws_recv_frame_len<params.max_request_len ) ) {
    FD_LOG_WARNING(( "max_ws_recv_frame_len<max_request_len" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_http_server_t * http = FD_SCRATCH_ALLOC_APPEND( l,  FD_HTTP_SERVER_ALIGN,                         sizeof(fd_http_server_t)                                                             );
  void * conn_pool        = FD_SCRATCH_ALLOC_APPEND( l,  conn_pool_align(),                            conn_pool_footprint( params.max_connection_cnt )                                     );
  void * ws_conn_pool     = FD_SCRATCH_ALLOC_APPEND( l,  ws_conn_pool_align(),                         ws_conn_pool_footprint( params.max_ws_connection_cnt )                               );
  http->conn_treap        = FD_SCRATCH_ALLOC_APPEND( l,  conn_treap_align(),                           conn_treap_footprint( params.max_connection_cnt )                                    );
  http->ws_conn_treap     = FD_SCRATCH_ALLOC_APPEND( l,  ws_conn_treap_align(),                        ws_conn_treap_footprint( params.max_ws_connection_cnt )                              );
  http->pollfds           = FD_SCRATCH_ALLOC_APPEND( l,  alignof(struct pollfd),                       (params.max_connection_cnt+params.max_ws_connection_cnt+1UL)*sizeof( struct pollfd ) );
  char * _request_bytes   = FD_SCRATCH_ALLOC_APPEND( l,  1UL,                                          params.max_request_len*params.max_connection_cnt                                     );
  uchar * _ws_recv_bytes  = FD_SCRATCH_ALLOC_APPEND( l,  1UL,                                          params.max_ws_recv_frame_len*params.max_ws_connection_cnt                            );
  struct fd_http_server_ws_frame * _ws_send_frames = FD_SCRATCH_ALLOC_APPEND( l, alignof(struct fd_http_server_ws_frame), params.max_ws_send_frame_cnt*params.max_ws_connection_cnt*sizeof(struct fd_http_server_ws_frame) );
  http->oring             = FD_SCRATCH_ALLOC_APPEND( l,  1UL,                                          params.outgoing_buffer_sz                                                            );

  http->oring_sz  = params.outgoing_buffer_sz;
  http->stage_err = 0;
  http->stage_off = 0UL;
  http->stage_len = 0UL;

  http->callbacks             = callbacks;
  http->callback_ctx          = callback_ctx;
  http->evict_conn_id         = 0UL;
  http->evict_ws_conn_id      = 0UL;
  http->max_conns             = params.max_connection_cnt;
  http->max_ws_conns          = params.max_ws_connection_cnt;
  http->max_request_len       = params.max_request_len;
  http->max_ws_recv_frame_len = params.max_ws_recv_frame_len;
  http->max_ws_send_frame_cnt = params.max_ws_send_frame_cnt;

  http->conns = conn_pool_join( conn_pool_new( conn_pool, params.max_connection_cnt ) );
  conn_treap_join( conn_treap_new( http->conn_treap, params.max_connection_cnt ) );
  conn_treap_seed( http->conns, params.max_connection_cnt, 42UL );

  http->ws_conns = ws_conn_pool_join( ws_conn_pool_new( ws_conn_pool, params.max_ws_connection_cnt ) );
  ws_conn_treap_join( ws_conn_treap_new( http->ws_conn_treap, params.max_ws_connection_cnt ) );
  ws_conn_treap_seed( http->ws_conns, params.max_ws_connection_cnt, 42UL );

  for( ulong i=0UL; i<params.max_connection_cnt; i++ ) {
    http->pollfds[ i ].fd = -1;
    http->pollfds[ i ].events = POLLIN | POLLOUT;
    http->conns[ i ] = (struct fd_http_server_connection){
      .request_bytes = _request_bytes+i*params.max_request_len,
      .parent = http->conns[ i ].parent,
    };
  }

  for( ulong i=0UL; i<params.max_ws_connection_cnt; i++ ) {
    http->pollfds[ params.max_connection_cnt+i ].fd = -1;
    http->pollfds[ params.max_connection_cnt+i ].events = POLLIN | POLLOUT;
    http->ws_conns[ i ] = (struct fd_http_server_ws_connection){
      .recv_bytes = _ws_recv_bytes+i*params.max_ws_recv_frame_len,
      .send_frames = _ws_send_frames+i*params.max_ws_send_frame_cnt,
      .parent = http->ws_conns[ i ].parent,
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

int
fd_http_server_fd( fd_http_server_t * http ) {
  return http->socket_fd;
}

fd_http_server_t *
fd_http_server_listen( fd_http_server_t * http,
                       uint               address,
                       ushort             port ) {
  int sockfd = socket( AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==sockfd ) ) FD_LOG_ERR(( "socket failed (%i-%s)", errno, strerror( errno ) ));

  int optval = 1;
  if( FD_UNLIKELY( -1==setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof( optval ) ) ) )
    FD_LOG_ERR(( "setsockopt failed (%i-%s)", errno, strerror( errno ) ));

  struct sockaddr_in addr = {
    .sin_family      = AF_INET,
    .sin_port        = fd_ushort_bswap( port ),
    .sin_addr.s_addr = address,
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
#if FD_HTTP_SERVER_DEBUG
  FD_LOG_NOTICE(( "Closing connection %lu (fd=%d) (%d-%s)", conn_idx, http->pollfds[ conn_idx ].fd, reason, fd_http_server_connection_close_reason_str( reason ) ));
#endif

  if( FD_UNLIKELY( -1==close( http->pollfds[ conn_idx ].fd ) ) ) FD_LOG_ERR(( "close failed (%i-%s)", errno, strerror( errno ) ));

  http->pollfds[ conn_idx ].fd = -1;
  if( FD_LIKELY( conn_idx<http->max_conns ) ) {
    if( FD_LIKELY( http->callbacks.close    ) ) http->callbacks.close( conn_idx, reason, http->callback_ctx );
  } else {
    if( FD_LIKELY( http->callbacks.ws_close ) ) http->callbacks.ws_close( conn_idx-http->max_conns, reason, http->callback_ctx );
  }

  if( FD_UNLIKELY( conn_idx<http->max_conns ) ) {
    struct fd_http_server_connection * conn = &http->conns[ conn_idx ];
    if( FD_LIKELY( (conn->state==FD_HTTP_SERVER_CONNECTION_STATE_WRITING_HEADER || conn->state==FD_HTTP_SERVER_CONNECTION_STATE_WRITING_BODY)
                    && !conn->response.static_body ) ) {
      conn_treap_ele_remove( http->conn_treap, conn, http->conns );
    }
    conn_pool_ele_release( http->conns, conn );
  } else {
    struct fd_http_server_ws_connection * ws_conn = &http->ws_conns[ conn_idx-http->max_conns ];
    if( FD_LIKELY( ws_conn->send_frame_cnt ) ) ws_conn_treap_ele_remove( http->ws_conn_treap, ws_conn, http->ws_conns );
    ws_conn_pool_ele_release( http->ws_conns, ws_conn );
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

/* These are the expected network errors which just mean the connection
   should be closed.  Any errors from an accept(2), read(2), or send(2)
   that are not expected here will be considered fatal and terminate the
   server. */

static inline int
is_expected_network_error( int err ) {
  return
    err==ENETDOWN ||
    err==EPROTO ||
    err==ENOPROTOOPT ||
    err==EHOSTDOWN ||
    err==ENONET ||
    err==EHOSTUNREACH ||
    err==EOPNOTSUPP ||
    err==ENETUNREACH ||
    err==ETIMEDOUT ||
    err==ENETRESET ||
    err==ECONNABORTED ||
    err==ECONNRESET ||
    err==EPIPE;
}

static void
accept_conns( fd_http_server_t * http ) {
  for(;;) {
    int fd = accept4( http->socket_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC );

    if( FD_UNLIKELY( -1==fd ) ) {
      if( FD_LIKELY( EAGAIN==errno ) ) break;
      else if( FD_LIKELY( is_expected_network_error( errno ) ) ) continue;
      else FD_LOG_ERR(( "accept failed (%i-%s)", errno, strerror( errno ) ));
    }

    if( FD_UNLIKELY( !conn_pool_free( http->conns ) ) ) {
      conn_treap_rev_iter_t it = conn_treap_fwd_iter_init( http->conn_treap, http->conns );
      if( FD_LIKELY( !conn_treap_fwd_iter_done( it ) ) ) {
        ulong conn_id = conn_treap_fwd_iter_idx( it );
        close_conn( http, conn_id, FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED );
      } else {
        /* If nobody is slow to read, just evict round robin */
        close_conn( http, http->evict_conn_id, FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED );
        http->evict_conn_id = (http->evict_conn_id+1UL) % http->max_conns;
      }
    }

    ulong conn_id = conn_pool_idx_acquire( http->conns );

    http->pollfds[ conn_id ].fd = fd;
    http->conns[ conn_id ].state                  = FD_HTTP_SERVER_CONNECTION_STATE_READING;
    http->conns[ conn_id ].request_bytes_read     = 0UL;
    http->conns[ conn_id ].response_bytes_written = 0UL;

    if( FD_UNLIKELY( http->callbacks.open ) ) {
      http->callbacks.open( conn_id, fd, http->callback_ctx );
    }

#if FD_HTTP_SERVER_DEBUG
    FD_LOG_NOTICE(( "Accepted connection %lu (fd=%d)", conn_id, fd ));
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
  else if( FD_UNLIKELY( !sz || (-1==sz && is_expected_network_error( errno ) ) ) ) {
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

  FD_TEST( result>0 && (ulong)result<=conn->request_bytes_read );

  uchar method_enum = UCHAR_MAX;
  if( FD_LIKELY( method_len==3UL && !strncmp( method, "GET", method_len ) ) ) method_enum = FD_HTTP_SERVER_METHOD_GET;
  else if( FD_LIKELY( method_len==4UL && !strncmp( method, "POST", method_len ) ) ) method_enum = FD_HTTP_SERVER_METHOD_POST;
  else if( FD_LIKELY( method_len==7UL && !strncmp( method, "OPTIONS", method_len ) ) ) method_enum = FD_HTTP_SERVER_METHOD_OPTIONS;

  if( FD_UNLIKELY( method_enum==UCHAR_MAX ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD );
    return;
  }

  ulong content_len = 0UL;
  ulong content_length_len = 0UL;
  if( FD_UNLIKELY( method_enum==FD_HTTP_SERVER_METHOD_POST ) ) {
    char const * content_length = NULL;
    for( ulong i=0UL; i<num_headers; i++ ) {
      if( FD_LIKELY( headers[ i ].name_len==14UL && !strncasecmp( headers[ i ].name, "Content-Length", 14UL ) && headers[ i ].value_len>0UL ) ) {
        content_length = headers[ i ].value;
        content_length_len = headers[ i ].value_len;
        break;
      }
    }

    if( FD_UNLIKELY( !content_length ) ) {
      close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_MISSING_CONENT_LENGTH_HEADER );
      return;
    }

    for( ulong i=0UL; i<content_length_len; i++ ) {
      if( FD_UNLIKELY( content_length[ i ]<'0' || content_length[ i ]>'9' ) ) {
        close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
        return;
      }

      ulong next = content_len*10UL + (ulong)(content_length[ i ]-'0');
      if( FD_UNLIKELY( next<content_len ) ) { /* Overflow */
        close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_LARGE_REQUEST );
        return;
      }

      content_len = next;
    }

    ulong total_len = (ulong)result+content_len;

    if( FD_UNLIKELY( total_len<content_len ) ) { /* Overflow */
      close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_LARGE_REQUEST );
      return;
    }


    if( FD_UNLIKELY( conn->request_bytes_read<(ulong)result+content_len ) ) {
      return; /* Request still partial, wait for more data */
    }
  }

  char content_type_nul_terminated[ 128 ] = {0};
  char accept_encoding_nul_terminated[ 128 ] = {0};
  for( ulong i=0UL; i<num_headers; i++ ) {
    if( FD_LIKELY( headers[ i ].name_len==12UL && !strncasecmp( headers[ i ].name, "Content-Type", 12UL ) ) ) {
      if( FD_UNLIKELY( headers[ i ].value_len>(sizeof(content_type_nul_terminated)-1UL) ) ) {
        close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
        return;
      }
      memcpy( content_type_nul_terminated, headers[ i ].value, headers[ i ].value_len );
      break;
    }

    if( FD_LIKELY( headers[ i ].name_len==15UL && !strncasecmp( headers[ i ].name, "Accept-Encoding", 15UL ) ) ) {
      if( FD_UNLIKELY( headers[ i ].value_len>(sizeof(accept_encoding_nul_terminated)-1UL) ) ) {
        close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
        return;
      }
      memcpy( accept_encoding_nul_terminated, headers[ i ].value, headers[ i ].value_len );
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
    .headers.accept_encoding   = accept_encoding_nul_terminated,
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

#if FD_HTTP_SERVER_DEBUG
  FD_LOG_NOTICE(( "Received %s request \"%s\" from %lu (fd=%d) response code %lu", fd_http_server_method_str( method_enum ), path_nul_terminated, conn_idx, http->pollfds[ conn_idx ].fd, conn->response.status ));
#endif

  if( FD_LIKELY( !conn->response.static_body ) ) conn_treap_ele_insert( http->conn_treap, conn, http->conns );
}

static void
read_conn_ws( fd_http_server_t * http,
              ulong              conn_idx ) {
  struct fd_http_server_ws_connection * conn = &http->ws_conns[ conn_idx-http->max_conns ];

  long sz = read( http->pollfds[ conn_idx ].fd, conn->recv_bytes+conn->recv_bytes_parsed+conn->recv_bytes_read, http->max_ws_recv_frame_len-conn->recv_bytes_parsed-conn->recv_bytes_read );
  if( FD_UNLIKELY( -1==sz && errno==EAGAIN ) ) return; /* No data to read, continue. */
  else if( FD_UNLIKELY( !sz || (-1==sz && is_expected_network_error( errno ) ) ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET );
    return;
  }
  else if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "read failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

  /* New data was read... process it */
  conn->recv_bytes_read += (ulong)sz;
again:
  if( FD_UNLIKELY( conn->recv_bytes_read<2UL ) ) return; /* Need at least 2 bytes to determine frame length */

  int is_mask_set = conn->recv_bytes[ conn->recv_bytes_parsed+1UL ] & 0x80;
  if( FD_UNLIKELY( !is_mask_set ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_BAD_MASK );
    return;
  }

  int opcode = conn->recv_bytes[ conn->recv_bytes_parsed ] & 0x0F;
  if( FD_UNLIKELY( opcode!=0x0 && opcode!=0x1 && opcode!=0x2 && opcode!=0x8 && opcode!=0x9 && opcode!=0xA ) ) {
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
    payload_len = ((ulong)conn->recv_bytes[ conn->recv_bytes_parsed+2UL ]<<8UL) | (ulong)conn->recv_bytes[ conn->recv_bytes_parsed+3UL ];
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
  if( FD_UNLIKELY( frame_len<header_len ) ) { /* Overflow */
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_OVERSIZE_FRAME );
    return;
  }

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
      FD_TEST( payload_len<=125UL );
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

  if( FD_UNLIKELY( !conn->recv_started_msg && opcode!=0x1 && opcode!=0x2 ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_EXPECTED_TEXT_OPCODE );
    return;
  }

  if( FD_UNLIKELY( conn->recv_started_msg && opcode!=conn->recv_last_opcode ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CHANGED_OPCODE );
    return;
  }
  conn->recv_last_opcode = opcode;

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
  if( FD_UNLIKELY( -1==http->pollfds[ conn_idx ].fd ) ) return; /* Connection was closed by callback */
  conn->recv_bytes[ conn->recv_bytes_parsed ] = tmp;

  conn->recv_started_msg  = 0;
  conn->recv_bytes_parsed = 0UL;
  if( FD_UNLIKELY( trailing_data_len ) ) {
    memmove( conn->recv_bytes, trailing_data, trailing_data_len );
    goto again; /* Might be another message in the buffer to process */
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

  char header_buf[ 1024 ];

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
            FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %.*s\r\n", (int)encoded_len, sec_websocket_accept_base64 ) );
          } else {
            ulong body_len = conn->response.static_body ? conn->response.static_body_len : conn->response._body_len;
            FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\nConnection: close\r\n", body_len ) );
          }
          break;
        case 204: {
          ulong body_len = conn->response.static_body ? conn->response.static_body_len : conn->response._body_len;
          FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 204 No Content\r\nContent-Length: %lu\r\n", body_len ) );
          break;
        }
        case 400: {
          ulong body_len = conn->response.static_body ? conn->response.static_body_len : conn->response._body_len;
          FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 400 Bad Request\r\nContent-Length: %lu\r\n", body_len ) );
          break;
        }
        case 404:
          FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n" ) );
          break;
        case 405:
          FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n" ) );
          break;
        case 500:
          FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n" ) );
          break;
        default:
          FD_TEST( fd_cstr_printf_check( header_buf, sizeof( header_buf ), &response_len, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n" ) );
          break;
      }

      if( FD_LIKELY( conn->response.content_type ) ) {
        ulong content_type_len;
        FD_TEST( fd_cstr_printf_check( header_buf+response_len, sizeof( header_buf )-response_len, &content_type_len, "Content-Type: %s\r\n", conn->response.content_type ) );
        response_len += content_type_len;
      }
      if( FD_LIKELY( conn->response.cache_control ) ) {
        ulong cache_control_len;
        FD_TEST( fd_cstr_printf_check( header_buf+response_len, sizeof( header_buf )-response_len, &cache_control_len, "Cache-Control: %s\r\n", conn->response.cache_control ) );
        response_len += cache_control_len;
      }
      if( FD_LIKELY( conn->response.content_encoding ) ) {
        ulong content_encoding_len;
        FD_TEST( fd_cstr_printf_check( header_buf+response_len, sizeof( header_buf )-response_len, &content_encoding_len, "Content-Encoding: %s\r\n", conn->response.content_encoding ) );
        response_len += content_encoding_len;
      }
      if( FD_LIKELY( conn->response.access_control_allow_origin ) ) {
        ulong access_control_allow_origin_len;
        FD_TEST( fd_cstr_printf_check( header_buf+response_len, sizeof( header_buf )-response_len, &access_control_allow_origin_len, "Access-Control-Allow-Origin: %s\r\n", conn->response.access_control_allow_origin ) );
        response_len += access_control_allow_origin_len;
      }
      if( FD_LIKELY( conn->response.access_control_allow_methods ) ) {
        ulong access_control_allow_methods_len;
        FD_TEST( fd_cstr_printf_check( header_buf+response_len, sizeof( header_buf )-response_len, &access_control_allow_methods_len, "Access-Control-Allow-Methods: %s\r\n", conn->response.access_control_allow_methods ) );
        response_len += access_control_allow_methods_len;
      }
      if( FD_LIKELY( conn->response.access_control_allow_headers ) ) {
        ulong access_control_allow_headers_len;
        FD_TEST( fd_cstr_printf_check( header_buf+response_len, sizeof( header_buf )-response_len, &access_control_allow_headers_len, "Access-Control-Allow-Headers: %s\r\n", conn->response.access_control_allow_headers ) );
        response_len += access_control_allow_headers_len;
      }
      if( FD_LIKELY( conn->response.access_control_max_age ) ) {
        ulong access_control_max_age_len;
        FD_TEST( fd_cstr_printf_check( header_buf+response_len, sizeof( header_buf )-response_len, &access_control_max_age_len, "Access-Control-Max-Age: %lu\r\n", conn->response.access_control_max_age ) );
        response_len += access_control_max_age_len;
      }
      FD_TEST( fd_cstr_printf_check( header_buf+response_len, sizeof( header_buf )-response_len, NULL, "\r\n" ) );
      response_len += 2UL;

      response = (uchar const *)header_buf;
      break;
    case FD_HTTP_SERVER_CONNECTION_STATE_WRITING_BODY:
      if( FD_UNLIKELY( conn->response.static_body ) ) {
        response     = conn->response.static_body;
        response_len = conn->response.static_body_len;
      } else {
        response = http->oring+(conn->response._body_off%http->oring_sz);
        response_len = conn->response._body_len;
      }
      break;
    default:
      FD_LOG_ERR(( "invalid server state" ));
      return;
  }

  long sz = send( http->pollfds[ conn_idx ].fd, response+conn->response_bytes_written, response_len-conn->response_bytes_written, MSG_NOSIGNAL );
  if( FD_UNLIKELY( -1==sz && errno==EAGAIN ) ) return; /* No data was written, continue. */
  if( FD_UNLIKELY( -1==sz && is_expected_network_error( errno ) ) ) {
    close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET );
    return;
  }
  if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "write failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

  conn->response_bytes_written += (ulong)sz;
  if( FD_UNLIKELY( conn->response_bytes_written==response_len ) ) {
    switch( conn->state ) {
      case FD_HTTP_SERVER_CONNECTION_STATE_WRITING_HEADER:
        if( FD_UNLIKELY( conn->response.upgrade_websocket ) ) {
          if( FD_UNLIKELY( !conn->upgrade_websocket ) ) {
            close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_MISSING_UPGRADE );
            return;
          }

          int fd = http->pollfds[ conn_idx ].fd;
          http->pollfds[ conn_idx ].fd = -1;

          struct fd_http_server_connection * conn = &http->conns[ conn_idx ];
          if( FD_LIKELY( !conn->response.static_body ) ) conn_treap_ele_remove( http->conn_treap, conn, http->conns );
          conn_pool_ele_release( http->conns, conn );

          if( FD_UNLIKELY( !ws_conn_pool_free( http->ws_conns ) ) ) {
            ws_conn_treap_rev_iter_t it = ws_conn_treap_rev_iter_init( http->ws_conn_treap, http->ws_conns );
            if( FD_LIKELY( !ws_conn_treap_rev_iter_done( it ) ) ) {
              ulong ws_conn_id = ws_conn_treap_rev_iter_idx( it );
              close_conn( http, http->max_conns+ws_conn_id, FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED );
            } else {
              close_conn( http, http->max_conns+http->evict_ws_conn_id, FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED );
              http->evict_ws_conn_id = (http->evict_ws_conn_id+1UL) % http->max_ws_conns;
            }
          }

          ulong ws_conn_id = ws_conn_pool_idx_acquire( http->ws_conns );
          http->pollfds[ http->max_conns+ws_conn_id ].fd = fd;

          http->ws_conns[ ws_conn_id ].pong_state               = FD_HTTP_SERVER_PONG_STATE_NONE;
          http->ws_conns[ ws_conn_id ].send_frame_cnt           = 0UL;
          http->ws_conns[ ws_conn_id ].send_frame_state         = FD_HTTP_SERVER_SEND_FRAME_STATE_HEADER;
          http->ws_conns[ ws_conn_id ].send_frame_idx           = 0UL;
          http->ws_conns[ ws_conn_id ].recv_started_msg         = 0;
          http->ws_conns[ ws_conn_id ].recv_bytes_parsed        = 0UL;
          http->ws_conns[ ws_conn_id ].recv_bytes_read          = 0UL;
          http->ws_conns[ ws_conn_id ].send_frame_bytes_written = 0UL;

          FD_TEST( conn->request_bytes_read>=conn->request_bytes_len );
          if( FD_UNLIKELY( conn->request_bytes_read-conn->request_bytes_len>0UL ) ) {
            /* Client might have already started sending data prior to
               response, so make sure to move it to the recv buffer. */
            FD_TEST( conn->request_bytes_read-conn->request_bytes_len<=http->max_ws_recv_frame_len );
            fd_memcpy( http->ws_conns[ ws_conn_id ].recv_bytes, conn->request_bytes+conn->request_bytes_len, conn->request_bytes_read-conn->request_bytes_len );
            http->ws_conns[ ws_conn_id ].recv_bytes_read = conn->request_bytes_read-conn->request_bytes_len;
          }

#if FD_HTTP_SERVER_DEBUG
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
  if( FD_LIKELY( conn->pong_state==FD_HTTP_SERVER_PONG_STATE_NONE ) ) return 0;
  /*  We are in the middle of writing a data frame */
  if( FD_LIKELY( conn->send_frame_cnt && (conn->send_frame_state==FD_HTTP_SERVER_SEND_FRAME_STATE_DATA || conn->send_frame_bytes_written ) ) ) return 0;

  /* Otherwise, we need to pong */
  if( FD_LIKELY( conn->pong_state==FD_HTTP_SERVER_PONG_STATE_WAITING ) ) {
    conn->pong_state         = FD_HTTP_SERVER_PONG_STATE_WRITING;
    conn->pong_bytes_written = 0UL;
  }

  uchar frame[ 2UL+125UL ];
  frame[ 0 ] = 0x80 | 0x0A; /* FIN, 0xA for pong. */
  frame[ 1 ] = (uchar)conn->pong_data_len;
  fd_memcpy( frame+2UL, conn->pong_data, conn->pong_data_len );

  long sz = send( http->pollfds[ conn_idx ].fd, frame+conn->pong_bytes_written, 2UL+conn->pong_data_len-conn->pong_bytes_written, MSG_NOSIGNAL );
  if( FD_UNLIKELY( -1==sz && errno==EAGAIN ) ) return 1; /* No data was written, continue. */
  else if( FD_UNLIKELY( -1==sz && is_expected_network_error( errno ) ) ) {
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
      if( FD_LIKELY( frame->len<126UL ) ) {
        header[ 1 ] = (uchar)frame->len;
        header_len = 2UL;
      } else if( FD_LIKELY( frame->len<65536UL ) ) {
        header[ 1 ] = 126;
        header[ 2 ] = (uchar)(frame->len>>8);
        header[ 3 ] = (uchar)(frame->len);
        header_len = 4UL;
      } else {
        header[ 1 ] = 127;
        header[ 2 ] = (uchar)(frame->len>>56);
        header[ 3 ] = (uchar)(frame->len>>48);
        header[ 4 ] = (uchar)(frame->len>>40);
        header[ 5 ] = (uchar)(frame->len>>32);
        header[ 6 ] = (uchar)(frame->len>>24);
        header[ 7 ] = (uchar)(frame->len>>16);
        header[ 8 ] = (uchar)(frame->len>>8);
        header[ 9 ] = (uchar)(frame->len);
        header_len = 10UL;
      }

      long sz = send( http->pollfds[ conn_idx ].fd, header+conn->send_frame_bytes_written, header_len-conn->send_frame_bytes_written, MSG_NOSIGNAL );
      if( FD_UNLIKELY( -1==sz && errno==EAGAIN ) ) return; /* No data was written, continue. */
      else if( FD_UNLIKELY( -1==sz && is_expected_network_error( errno ) ) ) {
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
      uchar const * data = http->oring+(frame->off%http->oring_sz);
      long sz = send( http->pollfds[ conn_idx ].fd, data+conn->send_frame_bytes_written, frame->len-conn->send_frame_bytes_written, MSG_NOSIGNAL );
      if( FD_UNLIKELY( -1==sz && errno==EAGAIN ) ) return; /* No data was written, continue. */
      else if( FD_UNLIKELY( -1==sz && is_expected_network_error( errno ) ) ) {
        close_conn( http, conn_idx, FD_HTTP_SERVER_CONNECTION_CLOSE_PEER_RESET );
        return;
      }
      else if( FD_UNLIKELY( -1==sz ) ) FD_LOG_ERR(( "write failed (%i-%s)", errno, strerror( errno ) )); /* Unexpected programmer error, abort */

      conn->send_frame_bytes_written += (ulong)sz;
      if( FD_UNLIKELY( conn->send_frame_bytes_written==frame->len ) ) {
        conn->send_frame_state = FD_HTTP_SERVER_SEND_FRAME_STATE_HEADER;
        conn->send_frame_idx   = (conn->send_frame_idx+1UL) % http->max_ws_send_frame_cnt;
        conn->send_frame_cnt--;
        conn->send_frame_bytes_written = 0UL;

        ws_conn_treap_ele_remove( http->ws_conn_treap, conn, http->ws_conns );
        if( FD_LIKELY( conn->send_frame_cnt ) ) ws_conn_treap_ele_insert( http->ws_conn_treap, conn, http->ws_conns );
      }
      break;
    }
  }
}

int
fd_http_server_ws_send( fd_http_server_t * http,
                        ulong              ws_conn_id ) {
  struct fd_http_server_ws_connection * conn = &http->ws_conns[ ws_conn_id ];

  if( FD_UNLIKELY( http->stage_err ) ) {
    http->stage_err = 0;
    http->stage_len = 0;
    return -1;
  }

  if( FD_UNLIKELY( conn->send_frame_cnt==http->max_ws_send_frame_cnt ) ) {
    close_conn( http, ws_conn_id+http->max_conns, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CLIENT_TOO_SLOW );
    return 0;
  }

  fd_http_server_ws_frame_t frame = {
    .off      = http->stage_off,
    .len      = http->stage_len,
  };

  conn->send_frames[ (conn->send_frame_idx+conn->send_frame_cnt) % http->max_ws_send_frame_cnt ] = frame;
  conn->send_frame_cnt++;

  if( FD_LIKELY( conn->send_frame_cnt==1UL ) ) {
    ws_conn_treap_ele_insert( http->ws_conn_treap, conn, http->ws_conns );
  }

  http->stage_off += http->stage_len;
  http->stage_len = 0;

  return 0;
}

int
fd_http_server_ws_broadcast( fd_http_server_t * http ) {
  if( FD_UNLIKELY( http->stage_err ) ) {
    http->stage_err = 0;
    http->stage_len = 0;
    return -1;
  }

  fd_http_server_ws_frame_t frame = {
    .off = http->stage_off,
    .len = http->stage_len,
  };

  for( ulong i=0UL; i<http->max_ws_conns; i++ ) {
    if( FD_LIKELY( http->pollfds[ http->max_conns+i ].fd==-1 ) ) continue;

    struct fd_http_server_ws_connection * conn = &http->ws_conns[ i ];
    if( FD_UNLIKELY( conn->send_frame_cnt==http->max_ws_send_frame_cnt ) ) {
      close_conn( http, i+http->max_conns, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CLIENT_TOO_SLOW );
      continue;
    }

    conn->send_frames[ (conn->send_frame_idx+conn->send_frame_cnt) % http->max_ws_send_frame_cnt ] = frame;
    conn->send_frame_cnt++;

    if( FD_LIKELY( conn->send_frame_cnt==1UL ) ) {
      ws_conn_treap_ele_insert( http->ws_conn_treap, conn, http->ws_conns );
    }
  }

  http->stage_off += http->stage_len;
  http->stage_len = 0;

  return 0;
}

static void
write_conn( fd_http_server_t * http,
            ulong              conn_idx ) {
  if( FD_LIKELY( conn_idx<http->max_conns ) ) write_conn_http( http, conn_idx );
  else                                        write_conn_ws(   http, conn_idx );
}

int
fd_http_server_poll( fd_http_server_t * http ) {
  int nfds = poll( http->pollfds, http->max_conns+http->max_ws_conns+1UL, 0 );
  if( FD_UNLIKELY( 0==nfds ) ) return 0;
  else if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) return 0;
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

  return 1;
}

void
fd_http_server_evict_until( fd_http_server_t * http,
                            ulong              off ) {
  conn_treap_fwd_iter_t next;
  for( conn_treap_fwd_iter_t it=conn_treap_fwd_iter_init( http->conn_treap, http->conns ); !conn_treap_fwd_iter_idx( it ); it=next ) {
    next = conn_treap_fwd_iter_next( it, http->conns );
    struct fd_http_server_connection * conn = conn_treap_fwd_iter_ele( it, http->conns );

    if( FD_UNLIKELY( conn->response._body_off<off ) ) {
      close_conn( http, conn_treap_fwd_iter_idx( it ), FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED );
    } else {
      break;
    }
  }

  ws_conn_treap_fwd_iter_t ws_next;
  for( ws_conn_treap_fwd_iter_t it=ws_conn_treap_fwd_iter_init( http->ws_conn_treap, http->ws_conns ); !ws_conn_treap_fwd_iter_idx( it ); it=ws_next ) {
    ws_next = ws_conn_treap_fwd_iter_next( it, http->ws_conns );
    struct fd_http_server_ws_connection * conn = ws_conn_treap_fwd_iter_ele( it, http->ws_conns );

    if( FD_UNLIKELY( conn->send_frames[ conn->send_frame_idx ].off<off ) ) {
      close_conn( http, ws_conn_treap_fwd_iter_idx( it )+http->max_conns, FD_HTTP_SERVER_CONNECTION_CLOSE_WS_CLIENT_TOO_SLOW );
    } else {
      break;
    }
  }
}

static void
fd_http_server_reserve( fd_http_server_t * http,
                        ulong              len ) {
  ulong remaining = http->oring_sz-((http->stage_off%http->oring_sz)+http->stage_len);
  if( FD_UNLIKELY( len>remaining ) ) {
    /* Appending the format string into the hcache would go past the end
        of the buffer... two cases, */
    if( FD_UNLIKELY( http->stage_len+len>http->oring_sz ) ) {
      /* Case 1: The snap is going to be larger than the entire buffer,
                  there's no way to fit it even if we evict everything
                  else.  Mark the hcache as errored and exit. */

      FD_LOG_WARNING(( "tried to reserve %lu bytes for an outgoing message which exceeds the entire data size", http->stage_len+len ));
      http->stage_err = 1;
      return;
    } else {
      /* Case 2: The snap can fit if we relocate it to the start of the
                 buffer and evict whatever was there.  We also evict the
                 rest of the buffer behind where the snap was to
                 preserve the invariant that snaps are always evicted in
                 circular order. */

      ulong stage_end = http->stage_off+remaining+http->stage_len+len;
      ulong clamp = fd_ulong_if( stage_end>=http->oring_sz, stage_end-http->oring_sz, 0UL );
      fd_http_server_evict_until( http, clamp );
      memmove( http->oring, http->oring+(http->stage_off%http->oring_sz), http->stage_len );
      http->stage_off += http->stage_len+remaining;
    }
  } else {
    /* The snap can fit in the buffer, we just need to evict whatever
        was there before. */
    ulong stage_end = http->stage_off+http->stage_len+len;
    ulong clamp = fd_ulong_if( stage_end>=http->oring_sz, stage_end-http->oring_sz, 0UL );
    fd_http_server_evict_until( http, clamp );
  }
}

void
fd_http_server_stage_trunc( fd_http_server_t * http,
                             ulong len ) {
  http->stage_len = len;
}

ulong
fd_http_server_stage_len( fd_http_server_t * http ) {
  return http->stage_len;
}

void
fd_http_server_printf( fd_http_server_t * http,
                       char const *       fmt,
                       ... ) {
  if( FD_UNLIKELY( http->stage_err ) ) return;

  va_list ap;
  va_start( ap, fmt );
  ulong printed_len = (ulong)vsnprintf( NULL, 0UL, fmt, ap );
  va_end( ap );

  fd_http_server_reserve( http, printed_len );
  if( FD_UNLIKELY( http->stage_err ) ) return;

  va_start( ap, fmt );
  vsnprintf( (char *)http->oring+(http->stage_off%http->oring_sz)+http->stage_len,
             INT_MAX, /* We already proved it's going to fit above */
             fmt,
             ap );
  va_end( ap );

  http->stage_len += printed_len;
}

void
fd_http_server_memcpy( fd_http_server_t * http,
                       uchar const *      data,
                       ulong              data_len ) {
  fd_http_server_reserve( http, data_len );
  if( FD_UNLIKELY( http->stage_err ) ) return;

  fd_memcpy( (char *)http->oring+(http->stage_off%http->oring_sz)+http->stage_len,
             data,
             data_len );
  http->stage_len += data_len;
}

void
fd_http_server_unstage( fd_http_server_t * http ) {
  http->stage_err = 0;
  http->stage_len = 0UL;
}

int
fd_http_server_stage_body( fd_http_server_t *          http,
                           fd_http_server_response_t * response ) {
  if( FD_UNLIKELY( http->stage_err ) ) {
    http->stage_err = 0;
    http->stage_len = 0;
    return -1;
  }

  response->_body_off = http->stage_off;
  response->_body_len = http->stage_len;
  http->stage_off += http->stage_len;
  http->stage_len = 0;
  return 0;
}
