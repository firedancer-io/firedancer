#include "../../util/fd_util.h"
#include "fd_blockstore.h"
#include "../rpc/fd_rpc_service.h"
#include "../gossip/fd_gossip.h"
#include "../repair/fd_repair.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "fd_acc_mgr.h"

typedef struct {
  char const * blockstore_wksp_name;
  char const * funk_wksp_name;
  char const * gossip_peer_addr;
  char const * incremental_snapshot;
  char const * load;
  char const * my_gossip_addr;
  char const * my_repair_addr;
  char const * repair_peer_addr;
  char const * repair_peer_id;
  char const * snapshot;
  char const * cmd;
  char const * reset;
  char const * capitalization_file;
  char const * allocator;
  char const * validate_db;
  char const * validate_snapshot;
  char const * capture_fpath;
  char const * trace_fpath;
  int  retrace;
  int  abort_on_mismatch;
  ulong  end_slot;
  ulong  index_max;
  ulong  page_cnt;
  ulong  tcnt;
  ulong  txn_max;
  ushort rpc_port;
} fd_runtime_args_t;

struct fd_repair_peer {
  fd_pubkey_t id;
  uint        hash;
  ulong       first_slot;
  ulong       last_slot;
  ulong       request_cnt;
  ulong       reply_cnt;
};
typedef struct fd_repair_peer fd_repair_peer_t;

typedef struct {
  fd_repair_t *        repair;
  fd_repair_peer_t *   repair_peers;
  fd_blockstore_t *    blockstore;
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

typedef struct {
  /* Private variables needed to construct objects */
  uchar                 epoch_ctx_mem[FD_EXEC_EPOCH_CTX_FOOTPRINT] __attribute__( ( aligned( FD_EXEC_EPOCH_CTX_ALIGN ) ) );
  fd_exec_epoch_ctx_t * epoch_ctx;
  uchar                 slot_ctx_mem[FD_EXEC_SLOT_CTX_FOOTPRINT] __attribute__( ( aligned( FD_EXEC_SLOT_CTX_ALIGN ) ) );
  fd_exec_slot_ctx_t *  slot_ctx;
  fd_acc_mgr_t          _acc_mgr[1];
  fd_repair_config_t    repair_config;
  uchar                 tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );
  fd_tpool_t           *tpool;
  fd_alloc_t           *alloc;
  fd_tvu_repair_ctx_t   repair_ctx;
  fd_gossip_config_t    gossip_config;
  fd_tvu_gossip_ctx_t   gossip_ctx;
  fd_gossip_peer_addr_t gossip_peer_addr;
  uchar                 private_key[32];
  fd_pubkey_t           public_key;

  /* Public variables */
  int                   blowup;
  int                   live;
  fd_gossip_t *         gossip;
  fd_repair_t *         repair;
  volatile int          stopflag;
#ifdef FD_HAS_LIBMICROHTTP
  fd_rpc_ctx_t *        rpc_ctx;
#endif

  // random crap
  fd_capture_ctx_t *     capture_ctx;
  fd_wksp_t           * local_wksp;
  ulong                  max_workers;
  uchar                  abort_on_mismatch;
} fd_runtime_ctx_t;

void
fd_tvu_main_setup( fd_runtime_ctx_t * tvu_args,
                   int live,
                   fd_wksp_t  * _wksp,
                   fd_runtime_args_t *args);

int
fd_tvu_main( fd_gossip_t *        gossip,
             fd_gossip_config_t * gossip_config,
             fd_tvu_repair_ctx_t * repair_ctx,
             fd_repair_config_t * repair_config,
             volatile int *       stopflag,
             char const * repair_peer_id_,
             char const * repair_peer_addr_ );

int
fd_tvu_parse_args( fd_runtime_args_t *args,
                   int argc,
                   char ** argv);
