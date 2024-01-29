#include "fd_rpc_client.h"
#include "fd_rpc_client_private.h"

#include "../../../ballet/http/picohttpparser.h"
#include "../../../ballet/json/cJSON.h"
#include "../../../ballet/base58/fd_base58.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>

#define MAX_REQUEST_LEN (1024UL)

void *
fd_rpc_client_new( void * mem,
                   uint   rpc_addr,
                   ushort rpc_port ) {
  fd_rpc_client_t * rpc = (fd_rpc_client_t *)mem;
  rpc->request_id = 0UL;
  rpc->rpc_addr = rpc_addr;
  rpc->rpc_port = rpc_port;
  for( ulong i=0; i<FD_RPC_CLIENT_REQUEST_CNT; i++ ) {
    rpc->requests[ i ].state = FD_RPC_CLIENT_STATE_NONE;
    rpc->fds[ i ].fd = -1;
    rpc->fds[ i ].events = POLLIN | POLLOUT;
  }
  return (void *)rpc;
}

long
fd_rpc_client_wait_ready( fd_rpc_client_t * rpc,
                          long              timeout_ns ) {


  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port   = fd_ushort_bswap( rpc->rpc_port ),
    .sin_addr   = { .s_addr = rpc->rpc_addr }
  };

  struct pollfd pfd = {
    .fd = 0,
    .events = POLLOUT,
    .revents = 0
  };

  long start = fd_log_wallclock();
  for(;;) {
    pfd.fd = socket( AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0 );
    if( FD_UNLIKELY( pfd.fd<0 ) ) return FD_RPC_CLIENT_ERR_NETWORK;

    if( FD_UNLIKELY( -1==connect( pfd.fd, fd_type_pun( &addr ), sizeof(addr) ) && errno!=EINPROGRESS ) ) {
      if( FD_UNLIKELY( close( pfd.fd )<0 ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      return FD_RPC_CLIENT_ERR_NETWORK;
    }

    for(;;) {
      long now = fd_log_wallclock();
      if( FD_UNLIKELY( now-start>=timeout_ns ) ) {
        if( FD_UNLIKELY( close( pfd.fd )<0 ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        return FD_RPC_CLIENT_ERR_NETWORK;
      }

      int nfds = poll( &pfd, 1, (int)((now-start) / 1000000) );
      if( FD_UNLIKELY( 0==nfds ) ) continue;
      else if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) continue;
      else if( FD_UNLIKELY( -1==nfds ) ) {
        if( FD_UNLIKELY( close( pfd.fd )<0 ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        return FD_RPC_CLIENT_ERR_NETWORK;
      } else if( FD_LIKELY( pfd.revents & (POLLERR | POLLHUP) ) ) {
        if( FD_UNLIKELY( close( pfd.fd )<0 ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        break;
      } else if( FD_LIKELY( pfd.revents & POLLOUT ) ) {
        if( FD_UNLIKELY( close( pfd.fd )<0 ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        return FD_RPC_CLIENT_SUCCESS;
      }
    }
  }
}

static ulong
fd_rpc_available_slot( fd_rpc_client_t * rpc ) {
  for( ulong i=0UL; i<FD_RPC_CLIENT_REQUEST_CNT; i++ ) {
    if( FD_LIKELY( rpc->requests[i].state==FD_RPC_CLIENT_STATE_NONE ) ) return i;
  }
  return ULONG_MAX;
}

static ulong
fd_rpc_find_request( fd_rpc_client_t * rpc,
                     long              request_id ) {
  for( ulong i=0UL; i<FD_RPC_CLIENT_REQUEST_CNT; i++ ) {
    if( FD_LIKELY( rpc->requests[i].state==FD_RPC_CLIENT_STATE_NONE ) ) continue;
    if( FD_LIKELY( rpc->requests[i].response.request_id!=request_id ) ) continue;
    return i;
  }
  return ULONG_MAX;
}

static long
fd_rpc_client_request( fd_rpc_client_t * rpc,
                       ulong             method,
                       long              request_id,
                       char *            contents,
                       int               contents_len ) {
  ulong idx = fd_rpc_available_slot( rpc );
  if( FD_UNLIKELY( idx==ULONG_MAX) ) return FD_RPC_CLIENT_ERR_TOO_MANY;

  struct fd_rpc_client_request * request = &rpc->requests[ idx ];

  if( FD_UNLIKELY( contents_len<0 ) ) return FD_RPC_CLIENT_ERR_TOO_LARGE;
  if( FD_UNLIKELY( (ulong)contents_len>=MAX_REQUEST_LEN ) ) return FD_RPC_CLIENT_ERR_TOO_LARGE;

  int printed = snprintf( request->connected.request_bytes, sizeof(request->connected.request_bytes),
                          "POST / HTTP/1.1\r\n"
                          "Host: localhost:12001\r\n"
                          "Content-Length: %d\r\n"
                          "Content-Type: application/json\r\n\r\n"
                          "%s", contents_len, contents );
  if( FD_UNLIKELY( printed<0 ) ) return FD_RPC_CLIENT_ERR_TOO_LARGE;
  if( FD_UNLIKELY( (ulong)printed>=sizeof(request->connected.request_bytes) ) ) return FD_RPC_CLIENT_ERR_TOO_LARGE;
  request->connected.request_bytes_cnt = (ulong)printed;

  int fd = socket( AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( fd<0 ) ) return FD_RPC_CLIENT_ERR_NETWORK;

  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port   = fd_ushort_bswap( rpc->rpc_port ),
    .sin_addr   = { .s_addr = rpc->rpc_addr }
  };

  if( FD_UNLIKELY( -1==connect( fd, fd_type_pun( &addr ), sizeof(addr) ) && errno!=EINPROGRESS ) ) {
    if( FD_UNLIKELY( close( fd )<0 ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return FD_RPC_CLIENT_ERR_NETWORK;
  }

  rpc->request_id = request_id;
  rpc->fds[ idx ].fd = fd;
  request->response.method = method;
  request->response.status = FD_RPC_CLIENT_PENDING;
  request->response.request_id = rpc->request_id;
  request->connected.request_bytes_sent = 0UL;
  request->state = FD_RPC_CLIENT_STATE_CONNECTED;
  return request->response.request_id;
}

long
fd_rpc_client_request_latest_block_hash( fd_rpc_client_t * rpc ) {
  char contents[ MAX_REQUEST_LEN ];
  long request_id = fd_long_if( rpc->request_id==LONG_MAX, 0L, rpc->request_id+1L );

  int contents_len = snprintf( contents, sizeof(contents),
                               "{\"jsonrpc\":\"2.0\",\"id\":\"%ld\",\"method\":\"getLatestBlockhash\",\"params\":[]}",
                               request_id );

  return fd_rpc_client_request( rpc, FD_RPC_CLIENT_METHOD_LATEST_BLOCK_HASH, request_id, contents, contents_len );
}

long
fd_rpc_client_request_transaction_count( fd_rpc_client_t * rpc ) {
  char contents[ MAX_REQUEST_LEN ];
  long request_id = fd_long_if( rpc->request_id==LONG_MAX, 0L, rpc->request_id+1L );

  int contents_len = snprintf( contents, sizeof(contents),
                               "{\"jsonrpc\":\"2.0\",\"id\":\"%ld\",\"method\":\"getTransactionCount\",\"params\":[]}",
                               request_id );

  return fd_rpc_client_request( rpc, FD_RPC_CLIENT_METHOD_TRANSACTION_COUNT, request_id, contents, contents_len );
}

static void
fd_rpc_mark_error( fd_rpc_client_t * rpc,
                   ulong             idx,
                   long              error ) {
  if( FD_LIKELY( rpc->fds[ idx ].fd>=0 ) ) {
    if( FD_UNLIKELY( close( rpc->fds[ idx ].fd )<0 ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    rpc->fds[ idx ].fd = -1;
  }
  rpc->requests[ idx ].state = FD_RPC_CLIENT_STATE_FINISHED;
  rpc->requests[ idx ].response.status = error;
}

static ulong
fd_rpc_phr_content_length( struct phr_header * headers,
                           ulong               num_headers ) {
  for( ulong i=0UL; i<num_headers; i++ ) {
    if( FD_LIKELY( headers[i].name_len!=14UL ) ) continue;
    if( FD_LIKELY( strncasecmp( headers[i].name, "Content-Length", 14UL ) ) ) continue;
    char * end;
    ulong content_length = strtoul( headers[i].value, &end, 10 );
    if( FD_UNLIKELY( end==headers[i].value ) ) return ULONG_MAX;
    return content_length;
  }
  return ULONG_MAX;
}

static long
parse_response( char *                     response,
                ulong                      response_len,
                ulong                      last_response_len,
                fd_rpc_client_response_t * result ) {
  int minor_version;
  int status;
  const char * message;
  ulong message_len;
  struct phr_header headers[ 32 ];
  ulong num_headers = 32UL;
  int http_len = phr_parse_response( response, response_len,
                                    &minor_version, &status, &message, &message_len,
                                    headers, &num_headers, last_response_len );
  if( FD_UNLIKELY( -2==http_len ) ) return FD_RPC_CLIENT_PENDING;
  else if( FD_UNLIKELY( -1==http_len ) ) return FD_RPC_CLIENT_ERR_MALFORMED;

  ulong content_length = fd_rpc_phr_content_length( headers, num_headers );
  if( FD_UNLIKELY( content_length==ULONG_MAX ) ) return FD_RPC_CLIENT_ERR_MALFORMED;
  if( FD_UNLIKELY( content_length+(ulong)http_len > MAX_REQUEST_LEN ) ) return FD_RPC_CLIENT_ERR_TOO_LARGE;
  if( FD_LIKELY( content_length+(ulong)http_len>response_len ) ) return FD_RPC_CLIENT_PENDING;

  if( FD_UNLIKELY( status!=200 ) ) return FD_RPC_CLIENT_ERR_MALFORMED;

  const char * parse_end;
  cJSON * json = cJSON_ParseWithLengthOpts( response + http_len, content_length, &parse_end, 0 );
  if( FD_UNLIKELY( !json ) ) return FD_RPC_CLIENT_ERR_MALFORMED;

  switch( result->method ) {
    case FD_RPC_CLIENT_METHOD_TRANSACTION_COUNT: {
      const cJSON * node = cJSON_GetObjectItemCaseSensitive( json, "result" );
      if( FD_UNLIKELY( !cJSON_IsNumber( node ) || node->valueulong==ULONG_MAX ) ) {
        cJSON_Delete( json );
        return FD_RPC_CLIENT_ERR_MALFORMED;
      }

      result->result.transaction_count.transaction_count = node->valueulong;
      cJSON_Delete( json );
      return FD_RPC_CLIENT_SUCCESS;
    }
    case FD_RPC_CLIENT_METHOD_LATEST_BLOCK_HASH: {
      const cJSON * node = cJSON_GetObjectItemCaseSensitive( json, "result" );
      if( FD_UNLIKELY( !cJSON_IsObject( node ) ) ) {
        cJSON_Delete( json );
        return FD_RPC_CLIENT_ERR_MALFORMED;
      }

      node = cJSON_GetObjectItemCaseSensitive( node, "value" );
      if( FD_UNLIKELY( !cJSON_IsObject( node ) ) ) {
        cJSON_Delete( json );
        return FD_RPC_CLIENT_ERR_MALFORMED;
      }

      node = cJSON_GetObjectItemCaseSensitive( node, "blockhash" );
      if( FD_UNLIKELY( !cJSON_IsString( node ) ) ) {
        cJSON_Delete( json );
        return FD_RPC_CLIENT_ERR_MALFORMED;
      }

      if( FD_UNLIKELY( strnlen( node->valuestring, 45UL )>44UL ) ) {
        cJSON_Delete( json );
        return FD_RPC_CLIENT_ERR_MALFORMED;
      }

      if( FD_UNLIKELY( !fd_base58_decode_32( node->valuestring, result->result.latest_block_hash.block_hash ) ) ) {
        cJSON_Delete( json );
        return FD_RPC_CLIENT_ERR_MALFORMED;
      }

      cJSON_Delete( json );
      return FD_RPC_CLIENT_SUCCESS;
    }
    default:
      FD_TEST( 0 );
  }
}

void
fd_rpc_client_service( fd_rpc_client_t * rpc,
                       int               wait ) {
  int timeout = wait ? -1 : 0;
  int nfds = poll( rpc->fds, FD_RPC_CLIENT_REQUEST_CNT, timeout );
  if( FD_UNLIKELY( 0==nfds ) ) return;
  else if( FD_UNLIKELY( -1==nfds && errno==EINTR ) ) return;
  else if( FD_UNLIKELY( -1==nfds ) ) FD_LOG_ERR(( "poll failed (%i-%s)", errno, strerror( errno ) ));

  for( ulong i=0UL; i<FD_RPC_CLIENT_REQUEST_CNT; i++ ) {
    struct fd_rpc_client_request * request = &rpc->requests[i];

    if( FD_LIKELY( request->state==FD_RPC_CLIENT_STATE_CONNECTED && ( rpc->fds[ i ].revents & POLLOUT ) ) ) {
      long sent = send( rpc->fds[ i ].fd, request->connected.request_bytes+request->connected.request_bytes_sent,
                        request->connected.request_bytes_cnt-request->connected.request_bytes_sent, 0 );
      if( FD_UNLIKELY( -1==sent && errno==EAGAIN ) ) continue;
      if( FD_UNLIKELY( -1==sent ) ) {
        fd_rpc_mark_error( rpc, i, FD_RPC_CLIENT_ERR_NETWORK );
        continue;
      }

      request->connected.request_bytes_sent += (ulong)sent;
      if( FD_UNLIKELY( request->connected.request_bytes_sent==request->connected.request_bytes_cnt ) ) {
        request->sent.response_bytes_read = 0UL;
        request->state = FD_RPC_CLIENT_STATE_SENT;
      }
    }

    if( FD_LIKELY( request->state==FD_RPC_CLIENT_STATE_SENT && ( rpc->fds[ i ].revents & POLLIN ) ) ) {
      long read = recv( rpc->fds[ i ].fd, request->response_bytes+request->sent.response_bytes_read,
                        sizeof(request->response_bytes)-request->sent.response_bytes_read, 0 );
      if( FD_UNLIKELY( -1==read && errno==EAGAIN ) ) continue;
      else if( FD_UNLIKELY( -1==read ) ) {
        fd_rpc_mark_error( rpc, i, FD_RPC_CLIENT_ERR_NETWORK );
        continue;
      }

      request->sent.response_bytes_read += (ulong)read;
      if( FD_UNLIKELY( request->sent.response_bytes_read==sizeof(request->response_bytes) ) ) {
        fd_rpc_mark_error( rpc, i, FD_RPC_CLIENT_ERR_TOO_LARGE );
        continue;
      }

      fd_rpc_client_response_t * response = &request->response;
      long status = parse_response( request->response_bytes,
                                    request->sent.response_bytes_read,
                                    request->sent.response_bytes_read-(ulong)read,
                                    response );
      if( FD_LIKELY( status==FD_RPC_CLIENT_PENDING ) ) continue;
      else if( FD_UNLIKELY( status==FD_RPC_CLIENT_SUCCESS ) ) {
        if( FD_UNLIKELY( close( rpc->fds[ i ].fd )<0 ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        rpc->fds[ i ].fd = -1;
        response->status = FD_RPC_CLIENT_SUCCESS;
        request->state = FD_RPC_CLIENT_STATE_FINISHED;
        continue;
      } else {
        fd_rpc_mark_error( rpc, i, status );
        continue;
      }
    }
  }
}

fd_rpc_client_response_t *
fd_rpc_client_status( fd_rpc_client_t * rpc,
                      long              request_id,
                      int               wait ) {
  ulong idx = fd_rpc_find_request( rpc, request_id );
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return NULL;

  if( FD_LIKELY( !wait ) ) return &rpc->requests[ idx ].response;

  for(;;) {
    if( FD_LIKELY( rpc->requests[ idx ].state==FD_RPC_CLIENT_STATE_FINISHED ) ) return &rpc->requests[ idx ].response;
    fd_rpc_client_service( rpc, 1 );
  }
}

void
fd_rpc_client_close( fd_rpc_client_t * rpc,
                     long              request_id ) {
  ulong idx = fd_rpc_find_request( rpc, request_id );
  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return;

  if( FD_LIKELY( rpc->fds[ idx ].fd>=0 ) ) {
    if( FD_UNLIKELY( close( rpc->fds[ idx ].fd )<0 ) ) FD_LOG_WARNING(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    rpc->fds[ idx ].fd = -1;
  }
  rpc->requests[ idx ].state = FD_RPC_CLIENT_STATE_NONE;
}
