#include "fd_rpc_client.h"
#include "fd_rpc_client_private.h"

#include "../../../util/fd_util.h"
#include "../../../util/net/fd_ip4.h"
#include "../../../ballet/http/picohttpparser.h"
#include "../../../ballet/json/cJSON.h"
#include "../../../ballet/base58/fd_base58.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/ip.h>


FD_STATIC_ASSERT( FD_RPC_CLIENT_ALIGN    ==alignof(fd_rpc_client_t), unit_test );
FD_STATIC_ASSERT( FD_RPC_CLIENT_FOOTPRINT==sizeof (fd_rpc_client_t), unit_test );

volatile int listening;

void *
fd_rpc_serve_one( void * args ) {
  (void)args;

  int sock = socket( AF_INET, SOCK_STREAM, 0 );
  FD_TEST( sock>=0 );

  FD_TEST( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int) )>=0 );

  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port   = fd_ushort_bswap( 12001 ),
    .sin_addr   = { .s_addr = FD_IP4_ADDR(127, 0, 0, 1) }
  };

  FD_TEST( bind( sock, fd_type_pun( &addr ), sizeof(addr) )>=0 );
  FD_TEST( listen( sock, 1 )>=0 );

  listening = 1;

  int content_offset;
  ulong content_length;

  int fd = accept( sock, NULL, NULL );
  FD_TEST( fd>=0 );

  char buf[ 1024 ];
  ulong bytes_read = 0UL;
  while( 1 ) {
    long len = recv( fd, buf+bytes_read, sizeof(buf)-bytes_read, 0 );
    FD_TEST( len>=0 );
    FD_TEST( bytes_read<sizeof(buf) );
    bytes_read += (ulong)len;

    char const * method;
    ulong method_len;
    char const * path;
    ulong path_len;
    int minor_version;
    struct phr_header headers[ 32 ];
    ulong num_headers = 32UL;
    content_offset = phr_parse_request( buf,
                                        bytes_read,
                                        &method, &method_len,
                                        &path, &path_len,
                                        &minor_version,
                                        headers, &num_headers,
                                        bytes_read - (ulong)len );
    FD_TEST( -1!=content_offset );
    if( -2==content_offset ) continue;

    FD_TEST( method_len==4UL );
    FD_TEST( !strncmp( method, "POST", 4UL ) );

    int found = 0;
    ulong i;
    for( i=0UL; i<num_headers; i++ ) {
      if( headers[i].name_len!=12UL ) continue;
      if( !strncmp( headers[i].name, "Content-Type", 12UL ) ) {
        found = 1;
        break;
      }
    }
    FD_TEST( found );
    FD_TEST( headers[i].value_len==16UL );
    FD_TEST( !strncmp( headers[i].value, "application/json", 16UL ) );

    found = 0;
    for( i=0UL; i<num_headers; i++ ) {
      if( headers[i].name_len!=14UL ) continue;
      if( !strncmp( headers[i].name, "Content-Length", 14UL ) ) {
        found = 1;
        break;
      }
    }

    FD_TEST( found );
    content_length = strtoul( headers[i].value, NULL, 10 );

    FD_TEST( (ulong)content_offset + content_length < sizeof( buf ) );
    if( bytes_read < (ulong)content_offset + content_length ) continue;
    break;
  }

  const char * parse_end;
  cJSON * json = cJSON_ParseWithLengthOpts( buf + content_offset, content_length, &parse_end, 0 );
  FD_TEST( json );

  char response_content[ 1024 ];
  int printed;
  char * method = cJSON_GetObjectItem( json, "method" )->valuestring;
  if( !strcmp( method, "getLatestBlockhash" ) ) {
    printed = snprintf( response_content, sizeof(response_content), "{\"jsonrpc\":\"2.0\",\"id\":%lu,\"result\": { \"value\": { \"blockhash\": \"EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N\" } } }",
                        cJSON_GetObjectItem( json, "id" )->valuestring );
  } else if( !strcmp( method, "getTransactionCount" ) ) {
    printed = snprintf( response_content, sizeof(response_content), "{\"jsonrpc\":\"2.0\",\"id\":%lu,\"result\": 268 }",
                        cJSON_GetObjectItem( json, "id" )->valuestring );
  } else {
    FD_LOG_WARNING(( "%s", method ));
    FD_TEST( 0 );
  }
  cJSON_Delete( json );
  FD_TEST( printed>=0 && (ulong)printed<sizeof(response_content) );

  char response[ 1024 ];
  printed = snprintf( response, sizeof(response), "HTTP/1.1 200 OK\r\n"
                                                  "Content-Type: application/json\r\n"
                                                  "Content-Length: %lu\r\n"
                                                  "\r\n"
                                                  "%s",
                      (ulong)printed, response_content );
  FD_TEST( printed>=0 && (ulong)printed<sizeof(response_content) );

  ulong bytes_written = 0UL;
  while( 1 ) {
    long len = send( fd, response, (ulong)printed - bytes_written, 0 );
    FD_TEST( len>=0 );
    bytes_written += (ulong)len;
    if( bytes_written >= (ulong)printed ) break;
  }

  FD_TEST( close( fd )>=0 );
  FD_TEST( close( sock )>=0 );
  return NULL;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Testing align / footprint" ));

  FD_TEST( fd_rpc_client_align    ()==FD_RPC_CLIENT_ALIGN     );
  FD_TEST( fd_rpc_client_footprint()==FD_RPC_CLIENT_FOOTPRINT );

  FD_LOG_NOTICE(( "Testing new" ));

  fd_rpc_client_t _rpc[1];
  void * shrpc = fd_rpc_client_new( _rpc, FD_IP4_ADDR(127, 0, 0, 1), 12001 ); FD_TEST( !!shrpc );

  FD_LOG_NOTICE(( "Testing join" ));

  fd_rpc_client_t * rpc  = fd_rpc_client_join( shrpc ); FD_TEST( !!rpc );

  FD_LOG_NOTICE(( "Testing request_transaction_count" ));

  listening = 0;

  pthread_t thread[1];
  pthread_create( thread, NULL, fd_rpc_serve_one, NULL );

  while( !listening ) ;

  long request_id = fd_rpc_client_request_transaction_count( rpc );
  FD_TEST( request_id>=0L );
  fd_rpc_client_response_t * response = fd_rpc_client_status( rpc, request_id, 1 );
  FD_TEST( !!response );

  FD_TEST( response->status==FD_RPC_CLIENT_SUCCESS );
  FD_TEST( response->result.transaction_count.transaction_count==268UL );

  fd_rpc_client_close( rpc, request_id );

  FD_TEST( !pthread_join( thread[0], NULL ) );

  FD_LOG_NOTICE(( "Testing request_latest_block_hash" ));

  listening = 0;
  pthread_create( thread, NULL, fd_rpc_serve_one, NULL );
  while( !listening ) ;

  request_id = fd_rpc_client_request_latest_block_hash( rpc );
  FD_TEST( request_id>=0L );
  response = fd_rpc_client_status( rpc, request_id, 1 );
  FD_TEST( !!response );

  FD_TEST( response->status==FD_RPC_CLIENT_SUCCESS );
  char out[45];
  fd_base58_encode_32( response->result.latest_block_hash.block_hash, NULL, out );
  FD_TEST( !strcmp( out, "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N" ) );

  fd_rpc_client_close( rpc, request_id );

  FD_TEST( !pthread_join( thread[0], NULL ) );

  FD_LOG_NOTICE(( "Testing leave" ));

  FD_TEST( fd_rpc_client_leave( rpc )==shrpc );

  FD_LOG_NOTICE(( "Testing delete" ));

  FD_TEST( fd_rpc_client_delete( shrpc )==_rpc );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
