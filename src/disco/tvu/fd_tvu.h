#ifndef HEADER_fd_src_tvu_fd_tvu_h
#define HEADER_fd_src_tvu_fd_tvu_h

#include "../../util/fd_util.h"
#include "../../flamenco/gossip/fd_gossip.h"
#include "../../flamenco/repair/fd_repair.h"
#include "../../flamenco/rpc/fd_rpc_service.h"
#include "../../flamenco/runtime/context/fd_exec_epoch_ctx.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/runtime/fd_blockstore.h"
#include "fd_replay.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../keyguard/fd_keyguard_client.h"

typedef struct {
  fd_repair_t *        repair;
  fd_blockstore_t *    blockstore;
  fd_replay_t *        replay;
  fd_exec_slot_ctx_t * slot_ctx;
  fd_tpool_t *         tpool;
  ulong                max_workers;
  ulong                peer_iter;
} fd_tvu_repair_ctx_t;

typedef struct {
  fd_gossip_t *      gossip;
  fd_repair_t *      repair;
  fd_replay_t *      replay;
  fd_keyguard_client_t keyguard_client[1];
} fd_tvu_gossip_ctx_t;

void
fd_tvu_main_setup( fd_runtime_ctx_t *    runtime_ctx,
                   fd_tvu_repair_ctx_t * repair_ctx,
                   fd_tvu_gossip_ctx_t * gossip_ctx,
                   int                   live,
                   fd_wksp_t *           _wksp,
                   fd_runtime_args_t *   args );

int
fd_tvu_main( fd_gossip_t *         gossip,
             fd_gossip_config_t *  gossip_config,
             fd_tvu_repair_ctx_t * repair_ctx,
             fd_repair_config_t *  repair_config,
             volatile int *        stopflag,
             char const *          repair_peer_id_,
             char const *          repair_peer_addr,
             char const *          tvu_addr,
             char const *          tvu_fwd_addr );

int
fd_tvu_parse_args( fd_runtime_args_t * args, int argc, char ** argv );

void
fd_tvu_main_teardown( fd_runtime_ctx_t * tvu_args, fd_tvu_repair_ctx_t * repair_ctx );

#endif /* HEADER_fd_src_tvu_fd_tvu_h */
