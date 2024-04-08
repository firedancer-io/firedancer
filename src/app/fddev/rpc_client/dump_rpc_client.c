#include "fd_rpc_client.h"
#include "fd_rpc_client_private.h"

#include "../../../util/fd_util.h"
#include "../../../util/net/fd_ip4.h"

#include <stdio.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rpc_client_t _rpc[1];
  void * shrpc = fd_rpc_client_new( _rpc, FD_IP4_ADDR(127, 0, 0, 1), 8899 ); FD_TEST( !!shrpc );
  fd_rpc_client_t * rpc  = fd_rpc_client_join( shrpc ); FD_TEST( !!rpc );

  long request_id = fd_rpc_client_request_transaction_count( rpc );
  FD_TEST( request_id>=0 );
  fd_rpc_client_response_t * response = fd_rpc_client_status( rpc, request_id, 1 );
  FD_TEST( !!response );

  FD_TEST( response->status==FD_RPC_CLIENT_SUCCESS );

  printf( "%lu\n", response->result.transaction_count.transaction_count );

  fd_halt();
  return 0;
}
