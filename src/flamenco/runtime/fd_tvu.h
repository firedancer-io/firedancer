#ifndef HEADER_fd_src_tvu_fd_tvu_h
#define HEADER_fd_src_tvu_fd_tvu_h

#include "../../util/fd_util.h"
#include "../gossip/fd_gossip.h"
#include "../repair/fd_repair.h"
#include "../rpc/fd_rpc_service.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "fd_acc_mgr.h"
#include "fd_blockstore.h"
#include "fd_replay.h"
#include "fd_runtime.h"

struct fd_repair_peer {
  fd_pubkey_t id;
  uint        hash;
  ulong       first_slot;
  ulong       last_slot;
  ulong       request_cnt;
  ulong       reply_cnt;
};
typedef struct fd_repair_peer fd_repair_peer_t;

static fd_pubkey_t pubkey_null = { 0 };

#define MAP_NAME                fd_repair_peer
#define MAP_T                   fd_repair_peer_t
#define MAP_LG_SLOT_CNT         12 /* 4kb peers */
#define MAP_KEY                 id
#define MAP_KEY_T               fd_pubkey_t
#define MAP_KEY_NULL            pubkey_null
#define MAP_KEY_INVAL( k )      !( memcmp( &k, &pubkey_null, sizeof( fd_pubkey_t ) ) )
#define MAP_KEY_EQUAL( k0, k1 ) !( memcmp( ( &k0 ), ( &k1 ), sizeof( fd_pubkey_t ) ) )
#define MAP_KEY_EQUAL_IS_SLOW   1
#define MAP_KEY_HASH( key )     ( (uint)( fd_hash( 0UL, &key, sizeof( fd_pubkey_t ) ) ) )
#include "../../util/tmpl/fd_map.c"

typedef struct {
  fd_repair_t *        repair;
  fd_repair_peer_t *   repair_peers;
  fd_blockstore_t *    blockstore;
  fd_replay_t *        replay;
  fd_exec_slot_ctx_t * slot_ctx;
  fd_tpool_t *         tpool;
  ulong                max_workers;
  ulong                peer_iter;
} fd_tvu_repair_ctx_t;

typedef struct {
  fd_gossip_t *      gossip;
  fd_repair_peer_t * repair_peers;
  fd_repair_t *      repair;
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
             char const *          repair_peer_addr_ );

int
fd_tvu_parse_args( fd_runtime_args_t * args, int argc, char ** argv );

void
fd_tvu_main_teardown( fd_runtime_ctx_t * tvu_args );

#endif /* HEADER_fd_src_tvu_fd_tvu_h */
