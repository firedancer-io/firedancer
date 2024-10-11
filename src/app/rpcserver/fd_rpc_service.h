#ifndef HEADER_fd_src_flamenco_rpc_fd_rpc_service_h
#define HEADER_fd_src_flamenco_rpc_fd_rpc_service_h

#include "../../util/fd_util.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../fdctl/run/tiles/fd_replay_notif.h"
#include "../../ballet/http/fd_http_server.h"
#include "../../util/wksp/fd_wksp_private.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/shred/fd_stake_ci.h"
#include "fd_block_to_json.h"
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct fd_rpc_ctx fd_rpc_ctx_t;

#define SHAM_LINK_CONTEXT fd_rpc_ctx_t
#define SHAM_LINK_STATE   fd_replay_notif_msg_t
#define SHAM_LINK_NAME    replay_sham_link
#include "sham_link.h"

#define SHAM_LINK_CONTEXT fd_rpc_ctx_t
#define SHAM_LINK_STATE   fd_stake_ci_t
#define SHAM_LINK_NAME    stake_sham_link
#include "sham_link.h"

struct fd_rpcserver_args {
  int                  offline;
  fd_funk_t *          funk;
  fd_blockstore_t *    blockstore;
  replay_sham_link_t * rep_notify;
  stake_sham_link_t *  stake_notify;
  fd_stake_ci_t *      stake_ci;
  ushort               port;
  fd_http_server_params_t params;
  struct sockaddr_in tpu_addr;
};
typedef struct fd_rpcserver_args fd_rpcserver_args_t;

void fd_rpc_start_service(fd_rpcserver_args_t * args, fd_rpc_ctx_t ** ctx);

void fd_rpc_stop_service(fd_rpc_ctx_t * ctx);

void fd_rpc_ws_poll(fd_rpc_ctx_t * ctx);

#endif /* HEADER_fd_src_flamenco_rpc_fd_rpc_service_h */
