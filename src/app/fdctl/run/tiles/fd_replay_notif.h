/* Data structure which is passed through replay_notif link */

#define FD_REPLAY_NOTIF_MTU 2048U
#define FD_REPLAY_NOTIF_ACCT_MAX ((FD_REPLAY_NOTIF_MTU - 128U)/sizeof(fd_pubkey_t))

#define FD_REPLAY_SAVED_TYPE 0x29FE5131U

struct __attribute__((aligned(64UL))) fd_replay_notif_msg {
  union {
    struct {
      fd_funk_txn_xid_t funk_xid;
      fd_pubkey_t       acct_id[FD_REPLAY_NOTIF_ACCT_MAX];
      uint              acct_id_cnt;
    } acct_saved;
  };
  uint type;
};
typedef struct fd_replay_notif_msg fd_replay_notif_msg_t;

/* MTU on replay_notif link is 128 */
FD_STATIC_ASSERT( sizeof(fd_replay_notif_msg_t) <= FD_REPLAY_NOTIF_MTU, notify message too big);
