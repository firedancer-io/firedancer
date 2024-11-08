#ifndef HEADER_fd_src_flamenco_rpc_fd_rpc_service_h
#define HEADER_fd_src_flamenco_rpc_fd_rpc_service_h

#include "../../util/fd_util.h"
#include "../../funk/fd_funk.h"
#include "../runtime/fd_blockstore.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../ballet/http/fd_http_server.h"
#include "../../util/wksp/fd_wksp_private.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/shred/fd_stake_ci.h"
#include "fd_block_to_json.h"
#include "../../app/fdctl/run/tiles/fd_replay_notif.h"
#include <netinet/in.h>

typedef struct fd_rpc_ctx fd_rpc_ctx_t;

struct fd_rpcserver_args {
  fd_valloc_t          valloc;
  int                  offline;
  fd_funk_t *          funk;
  fd_blockstore_t *    blockstore;
  fd_stake_ci_t *      stake_ci;
  ushort               port;
  fd_http_server_params_t params;
  struct sockaddr_in   tpu_addr;
};
typedef struct fd_rpcserver_args fd_rpcserver_args_t;

void fd_rpc_create_ctx(fd_rpcserver_args_t * args, fd_rpc_ctx_t ** ctx);

void fd_rpc_start_service(fd_rpcserver_args_t * args, fd_rpc_ctx_t * ctx);

void fd_rpc_stop_service(fd_rpc_ctx_t * ctx);

int fd_rpc_ws_poll(fd_rpc_ctx_t * ctx);

int fd_rpc_ws_fd(fd_rpc_ctx_t * ctx);

void replay_sham_link_during_frag(fd_rpc_ctx_t * ctx, fd_replay_notif_msg_t * state, void const * msg, int sz);

void replay_sham_link_after_frag(fd_rpc_ctx_t * ctx, fd_replay_notif_msg_t * msg);

void stake_sham_link_during_frag(fd_rpc_ctx_t * ctx, fd_stake_ci_t * state, void const * msg, int sz);

void stake_sham_link_after_frag(fd_rpc_ctx_t * ctx, fd_stake_ci_t * state);

#endif /* HEADER_fd_src_flamenco_rpc_fd_rpc_service_h */
