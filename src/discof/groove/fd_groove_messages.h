#include <linux/limits.h>
#include "../../flamenco/types/fd_types.h"
#include "../../funk/fd_funk_txn.h"

/******************************** Groove Tile API **************************************/

/* Signatures */
#define FD_GROOVE_TILE_LOAD_SNAPSHOT_SIGNATURE (0UL)
#define FD_GROOVE_TILE_PREFETCH_SIGNATURE      (1UL)
#define FD_GROOVE_TILE_WRITE_ACCOUNT_SIGNATURE (2UL)

/* Tango Messages */
struct fd_msg_groove_replay_load_snapshot_req {
    char  snapshot_path[PATH_MAX];
    char  snapshot_dir[PATH_MAX];
    int   snapshot_src_type;
    char  snapshot_http_header[PATH_MAX];
    ulong req_id;
};
typedef struct fd_msg_groove_replay_load_snapshot_req fd_msg_groove_replay_load_snapshot_req_t;

struct fd_msg_groove_prefetch_account_req {
    fd_pubkey_t       pubkey;
    ulong             req_id;
};
typedef struct fd_msg_groove_prefetch_account_req fd_msg_groove_prefetch_account_req_t;

struct fd_msg_groove_write_account_req {
    fd_pubkey_t       pubkey;
    ulong             req_id;
};
typedef struct fd_msg_groove_write_account_req fd_msg_groove_write_account_req_t;
