#ifndef HEADER_fd_src_discof_rpcserver_fd_rpc_service_h
#define HEADER_fd_src_discof_rpcserver_fd_rpc_service_h

#include "../replay/fd_replay_notif.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../waltz/http/fd_http_server.h"
#include "../../disco/store/fd_store.h"
#include "../../discof/reasm/fd_reasm.h"

#include <netinet/in.h>

typedef struct fd_rpc_ctx fd_rpc_ctx_t;

struct fd_rpcserver_args {
  int                        offline;
  fd_funk_t                  funk[1];
  fd_store_t *               store;
  ushort                     port;
  fd_http_server_params_t    params;
  struct sockaddr_in         tpu_addr;
  uint                       block_index_max;
  uint                       txn_index_max;
  uint                       acct_index_max;
  char                       history_file[ PATH_MAX ];
  fd_pubkey_t                identity_key;

  /* Bump allocator */
  fd_spad_t                * spad;
};
typedef struct fd_rpcserver_args fd_rpcserver_args_t;

void fd_rpc_create_ctx(fd_rpcserver_args_t * args, fd_rpc_ctx_t ** ctx);

void fd_rpc_start_service(fd_rpcserver_args_t * args, fd_rpc_ctx_t * ctx);

int fd_rpc_ws_poll(fd_rpc_ctx_t * ctx);

int fd_rpc_ws_fd(fd_rpc_ctx_t * ctx);

void fd_rpc_replay_during_frag(fd_rpc_ctx_t * ctx, void const * msg, int sz);

void fd_rpc_replay_after_frag(fd_rpc_ctx_t * ctx);

void fd_rpc_stake_during_frag(fd_rpc_ctx_t * ctx, void const * msg, int sz);

void fd_rpc_stake_after_frag(fd_rpc_ctx_t * ctx);

void fd_rpc_repair_during_frag(fd_rpc_ctx_t * ctx, void const * msg, int sz);

void fd_rpc_repair_after_frag(fd_rpc_ctx_t * ctx);

void fd_rpc_tower_during_frag(fd_rpc_ctx_t * ctx, ulong sig, ulong ctl, void const * msg, int sz);

void fd_rpc_tower_after_frag(fd_rpc_ctx_t * ctx);

#endif /* HEADER_fd_src_discof_rpcserver_fd_rpc_service_h */
