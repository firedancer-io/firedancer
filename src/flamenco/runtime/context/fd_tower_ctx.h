
struct fd_tower_entry {
  fd_funk_txn_t *  txn;
  ulong            slot;
};
typedef struct fd_tower_entry fd_tower_entry_t;

struct fd_tower_ctx {
  fd_funk_txn_t *  blockage;
  fd_tower_entry_t funk_txn_tower[32];
  ushort           funk_txn_index;
  uchar            constipate;
};
typedef struct fd_tower_ctx fd_tower_ctx_t;
