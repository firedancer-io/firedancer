#ifndef HEADER_fd_src_discof_replay_fd_exec_h
#define HEADER_fd_src_discof_replay_fd_exec_h

/* FIXME: SIMD-0180 - set the correct epochs */
#define FD_SIMD0180_ACTIVE_EPOCH_TESTNET (829)
#define FD_SIMD0180_ACTIVE_EPOCH_MAINNET (841)


/* Exec tile task types. */
#define FD_EXEC_TT_TXN_EXEC      (1UL) /* Transaction execution. */
#define FD_EXEC_TT_TXN_SIGVERIFY (2UL) /* Transaction sigverify. */
#define FD_EXEC_TT_LTHASH        (3UL) /* Account lthash. */
#define FD_EXEC_TT_POH_VERIFY    (4UL) /* PoH hash verification. */

/* Sent from the replay tile to the exec tiles.  These describe one of
   several types of tasks for an exec tile.  An idx to the bank in the
   bank pool must be sent over because the key of the bank will change
   as FEC sets are processed. */

struct fd_exec_txn_exec_msg {
  ulong      bank_idx;
  ulong      txn_idx;
  fd_txn_p_t txn;
};
typedef struct fd_exec_txn_exec_msg fd_exec_txn_exec_msg_t;

struct fd_exec_txn_sigverify_msg {
  ulong      bank_idx;
  ulong      txn_idx;
  fd_txn_p_t txn;
};
typedef struct fd_exec_txn_sigverify_msg fd_exec_txn_sigverify_msg_t;

union fd_exec_task_msg {
  fd_exec_txn_exec_msg_t      txn_exec;
  fd_exec_txn_sigverify_msg_t txn_sigverify;
};
typedef union fd_exec_task_msg fd_exec_task_msg_t;

/* Sent from exec tiles to the replay tile, notifying the replay tile
   that a task has been completed.  That is, if the task has any
   observable side effects, such as updates to accounts, then those side
   effects are fully visible on any other exec tile. */

struct fd_exec_txn_exec_done_msg {
  ulong txn_idx;
  int   err;
};
typedef struct fd_exec_txn_exec_done_msg fd_exec_txn_exec_done_msg_t;

struct fd_exec_txn_sigverify_done_msg {
  ulong txn_idx;
  int   err;
};
typedef struct fd_exec_txn_sigverify_done_msg fd_exec_txn_sigverify_done_msg_t;

struct fd_exec_task_done_msg {
  ulong bank_idx;
  union {
    fd_exec_txn_exec_done_msg_t      txn_exec[ 1 ];
    fd_exec_txn_sigverify_done_msg_t txn_sigverify[ 1 ];
  };
};
typedef struct fd_exec_task_done_msg fd_exec_task_done_msg_t;

#endif /* HEADER_fd_src_discof_replay_fd_exec_h */
