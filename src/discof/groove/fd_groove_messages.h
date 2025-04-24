#include <linux/limits.h>
#include "../../flamenco/types/fd_types.h"
#include "../../funk/fd_funk_txn.h"

/******************************** Groove Tile API **************************************/

/* Signatures */
#define FD_GROOVE_TILE_PREFETCH_SIGNATURE          (0UL)
#define FD_GROOVE_TILE_BLOCKING_PREFETCH_SIGNATURE (1UL)
#define FD_GROOVE_TILE_LOAD_SNAPSHOT_SIGNATURE     (2UL)

/* Fseqs */
#define FD_MSG_GROOVE_REPLAY_FSEQ_INIT               (0UL)
#define FD_MSG_GROOVE_REPLAY_FSEQ_LOAD_SNAPSHOT_DONE (1UL)

/* Tango Messages */
struct fd_msg_groove_replay_load_snapshot_req {
    char snapshot_path[PATH_MAX];
    char snapshot_dir[PATH_MAX];
    int  snapshot_src_type;
};
typedef struct fd_msg_groove_replay_load_snapshot_req fd_msg_groove_replay_load_snapshot_req_t;

struct fd_msg_groove_prefetch_account_req {
    fd_pubkey_t       pubkey;
    fd_funk_txn_xid_t funk_txn_xid;
};
typedef struct fd_msg_groove_prefetch_account_req fd_msg_groove_prefetch_account_req_t;
