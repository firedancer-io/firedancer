#ifndef HEADER_fd_src_appdctl_run_tiles_fd_replay_notif_h
#define HEADER_fd_src_appdctl_run_tiles_fd_replay_notif_h 1

#include "../../../../funk/fd_funk.h"

/* Data structure which is passed through replay_notif link */

#define FD_REPLAY_NOTIF_MTU 2048U
#define FD_REPLAY_NOTIF_ACCT_MAX ((FD_REPLAY_NOTIF_MTU - 128U)/sizeof(struct fd_replay_notif_acct))
#define FD_REPLAY_NOTIF_DEPTH (1U<<15U)

#define FD_REPLAY_ACCTS_TYPE 0x29FE5135U
#define FD_REPLAY_SLOT_TYPE  0xD1239ACAU

struct __attribute__((aligned(1))) fd_replay_notif_acct {
  uchar id [ 32U ]; /* Account id */
  uchar flags;      /* 0=nothing 1=account written */
};
#define FD_REPLAY_NOTIF_ACCT_WRITTEN  ((uchar)1)
#define FD_REPLAY_NOTIF_ACCT_NO_FLAGS ((uchar)0)

struct __attribute__((aligned(64UL))) fd_replay_notif_msg {
  union {
    struct {
      fd_funk_txn_xid_t           funk_xid;
      uchar                       sig[64U];           /* Transaction signature */
      struct fd_replay_notif_acct accts[FD_REPLAY_NOTIF_ACCT_MAX];
      uint                        accts_cnt;
    } accts;
    struct {
      ulong parent;
      ulong root;
      ulong slot;
      ulong height;
      fd_hash_t bank_hash;
      fd_hash_t block_hash;
      fd_pubkey_t identity;
      ulong transaction_count;
    } slot_exec;
  };
  uint type;
};
typedef struct fd_replay_notif_msg fd_replay_notif_msg_t;

/* MTU on replay_notif link is 128 */
FD_STATIC_ASSERT( sizeof(fd_replay_notif_msg_t) <= FD_REPLAY_NOTIF_MTU, notify message too big);

#endif /* HEADER_fd_src_appdctl_run_tiles_fd_replay_notif_h */
