#ifndef HEADER_fd_src_app_fddev_rpc_client_private_h
#define HEADER_fd_src_app_fddev_rpc_client_private_h

#include "fd_rpc_client.h"

#include <poll.h>

struct fd_rpc_client_request {
  ulong state;

  char response_bytes[ 1024 ]; /* shared across multiple states */

  union {
    struct {
      ulong request_bytes_cnt;
      ulong request_bytes_sent;
      char  request_bytes[ 1024 ];
    } connected;

    struct {
      ulong response_bytes_read;
    } sent;
  };

  fd_rpc_client_response_t response;
};

struct __attribute__((aligned(FD_RPC_CLIENT_ALIGN))) fd_rpc_client_private {
  long request_id;

  uint   rpc_addr;
  ushort rpc_port;

  struct pollfd fds[ FD_RPC_CLIENT_REQUEST_CNT ];
  struct fd_rpc_client_request requests[ FD_RPC_CLIENT_REQUEST_CNT ];
};

#endif /* HEADER_fd_src_app_fddev_rpc_client_private_h */
