#ifndef HEADER_fd_src_flamenco_rpc_fd_rpc_service_h
#define HEADER_fd_src_flamenco_rpc_fd_rpc_service_h

#include "../../util/fd_util.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/runtime/fd_blockstore.h"

struct fd_rpcserver_args {
  fd_funk_t *       funk;
  fd_blockstore_t * blockstore;
  ulong             num_threads;
  ushort            port;
};
typedef struct fd_rpcserver_args fd_rpcserver_args_t;

typedef struct fd_rpc_ctx fd_rpc_ctx_t;

void fd_rpc_start_service(fd_rpcserver_args_t * args, fd_rpc_ctx_t ** ctx);

void fd_rpc_stop_service(fd_rpc_ctx_t * ctx);

#endif /* HEADER_fd_src_flamenco_rpc_fd_rpc_service_h */
