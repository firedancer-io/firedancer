#ifndef HEADER_fd_src_flamenco_rpc_fd_rpc_service_h
#define HEADER_fd_src_flamenco_rpc_fd_rpc_service_h

#include "../../util/fd_util.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../fdctl/run/tiles/fd_replay_notif.h"
#include "../../ballet/http/fd_http_server.h"
#include "fd_block_to_json.h"

struct fd_rpcserver_args {
  fd_funk_t *       funk;
  fd_blockstore_t * blockstore;
  fd_wksp_t *       rep_notify_wksp;
  fd_frag_meta_t *  rep_notify;
  ushort            port;
  fd_http_server_params_t params;
  ulong             hcache_size;
};
typedef struct fd_rpcserver_args fd_rpcserver_args_t;

typedef struct fd_rpc_ctx fd_rpc_ctx_t;

void fd_rpc_start_service(fd_rpcserver_args_t * args, fd_rpc_ctx_t ** ctx);

void fd_rpc_stop_service(fd_rpc_ctx_t * ctx);

void fd_rpc_ws_poll(fd_rpc_ctx_t * ctx);

void fd_rpc_replay_notify(fd_rpc_ctx_t * ctx, fd_replay_notif_msg_t * msg);

#endif /* HEADER_fd_src_flamenco_rpc_fd_rpc_service_h */
