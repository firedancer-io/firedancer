#ifndef HEADER_fd_src_discof_replay_fd_exec_h
#define HEADER_fd_src_discof_replay_fd_exec_h

#include "../../disco/fd_txn_p.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/alpenglow/fd_block_marker.h"

/* Exec tile task types. */
#define FD_EXECRP_TT_TXN_EXEC      (1UL) /* Transaction execution. */
#define FD_EXECRP_TT_TXN_SIGVERIFY (2UL) /* Transaction sigverify. */
#define FD_EXECRP_TT_POH_HASH      (3UL) /* PoH hashing. */
#define FD_EXECRP_TT_CERT_VERIFY   (6UL) /* Alpenglow footer cert verify. */
#define FD_EXECRP_TT_SIGVERIFY_FLUSH (7UL) /* Verify the signatures pending on the tile. */
#define FD_EXECRP_TT_SIGVERIFY_CLEAR (8UL) /* Drop the signatures pending on the tile. */

/* Sent from the replay tile to the exec tiles.  These describe one of
   several types of tasks for an exec tile.  An idx to the bank in the
   bank pool must be sent over because the key of the bank will change
   as FEC sets are processed. */

struct fd_execrp_txn_exec_msg {
  ulong      bank_idx;
  ulong      txn_idx;
  fd_txn_p_t txn[ 1 ];

  /* Used currently by solcap to maintain ordering of messages
     this will change to using txn sigs eventually */
  ulong      capture_txn_idx;

  /* FEC-set merkle root at dispatch time. */
  uchar      fec_merkle_root[ 32 ];

  /* 0-indexed position of this transaction within its block. */
  ulong      index_in_slot;
};
typedef struct fd_execrp_txn_exec_msg fd_execrp_txn_exec_msg_t;

/* A sigverify task takes consecutive transactions of one block until
   it holds FD_EXECRP_SIGVERIFY_SIG_PARA signatures.  The exec tile
   verifies the signatures of consecutive tasks of one bank in groups
   of its own size, so a task may complete with signatures still
   pending on the tile; a FLUSH task verifies those, and a CLEAR task
   drops them.  Replay sends one or the other before the tile receives
   a sigverify task for another bank. */
#define FD_EXECRP_SIGVERIFY_SIG_PARA 8
struct fd_execrp_txn_sigverify_msg {
  ulong      bank_idx;
  ulong      cnt;
  ulong      txn_idx[ FD_EXECRP_SIGVERIFY_SIG_PARA ];
  fd_txn_p_t txn    [ FD_EXECRP_SIGVERIFY_SIG_PARA ];
};
typedef struct fd_execrp_txn_sigverify_msg fd_execrp_txn_sigverify_msg_t;

#define FD_EXECRP_POH_PARA 16
struct fd_execrp_poh_hash_msg {
  ulong     bank_idx;
  ulong     cnt;     /* In [1,FD_EXECRP_POH_PARA] */
  ulong     hashcnt; /* 0 or 1, same for every element of the batch */
  fd_hash_t hash[ FD_EXECRP_POH_PARA ];
};
typedef struct fd_execrp_poh_hash_msg fd_execrp_poh_hash_msg_t;

struct fd_execrp_cert_verify_msg {
  ulong                  bank_idx;
  ulong                  quorum;        /* quorum numerator, 0 for a reward cert */
  uint                   tag;           /* vote tag */
  ushort                 shred_version;
  int                    has_hm;        /* hm is the payload's H(m), from replay's memo */
  blst_p2_affine         hm;
  fd_block_footer_cert_t cert[ 1 ];
};
typedef struct fd_execrp_cert_verify_msg fd_execrp_cert_verify_msg_t;

/* FLUSH and CLEAR name the bank whose signatures are pending on the
   tile. */
struct fd_execrp_sigverify_flush_msg {
  ulong bank_idx;
};
typedef struct fd_execrp_sigverify_flush_msg fd_execrp_sigverify_flush_msg_t;

struct fd_execrp_sigverify_clear_msg {
  ulong bank_idx;
};
typedef struct fd_execrp_sigverify_clear_msg fd_execrp_sigverify_clear_msg_t;

union fd_execrp_task_msg {
  fd_execrp_txn_exec_msg_t        txn_exec;
  fd_execrp_txn_sigverify_msg_t   txn_sigverify;
  fd_execrp_poh_hash_msg_t        poh_hash;
  fd_execrp_cert_verify_msg_t     cert_verify;
  fd_execrp_sigverify_flush_msg_t sigverify_flush;
  fd_execrp_sigverify_clear_msg_t sigverify_clear;
};

typedef union fd_execrp_task_msg fd_execrp_task_msg_t;

/* Sent from exec tiles to the replay tile, notifying the replay tile
   that a task has been completed.  That is, if the task has any
   observable side effects, such as updates to accounts, then those side
   effects are fully visible on any other exec tile. */

struct fd_execrp_txn_exec_done_msg {
  ulong txn_idx;

  /* These flags form a nested series of if statements.
     if( is_committable ) {
       if( is_fees_only ) {
         instructions will not be executed
         txn_err will be non-zero and will be one of the account loader errors
       } else if( is_noop ) {
         instructions will not be executed and no fees charged
         txn_err will be non-zero and will be a fee payer validation error
       } else {
         instructions will execute
         if( txn_err is non-zero ) {
           there's likely an instruction error
         } else {
           transaction executed successfully
           https://github.com/anza-xyz/agave/blob/v3.1.8/svm/src/transaction_execution_result.rs#L26
         }
       }
     } else {
       either failed before account loading, or failed cost tracker
     }
  */
  int is_committable;
  int is_fees_only;
  int is_noop;
  int txn_err;

  /* LONG_MAX if stage was not reached */
  long tick_load_start;
  long tick_check_start;
  long tick_exec_start;
  long tick_commit_start;
  long tick_commit_end;

  uint  compute_units_consumed; /* possibly zero if is_committable is zero */
  ulong transaction_fee;
  ulong priority_fee;
  ulong tips;

  /* used by monitoring tools */
  ulong  slot;
  ulong  bank_seq;
  ushort start_shred_idx;
  ushort end_shred_idx;
};
typedef struct fd_execrp_txn_exec_done_msg fd_execrp_txn_exec_done_msg_t;

struct fd_execrp_txn_sigverify_done_msg {
  ulong cnt;
  ulong txn_idx[ FD_EXECRP_SIGVERIFY_SIG_PARA ];
  int   err;         /* Non-zero if a signature verified by this task failed;
                        it may belong to a transaction of an earlier task of
                        the bank */
  ulong pending_cnt; /* Signatures of the bank left unverified on the tile */
};
typedef struct fd_execrp_txn_sigverify_done_msg fd_execrp_txn_sigverify_done_msg_t;

struct fd_execrp_sigverify_flush_done_msg {
  int err; /* Non-zero if a pending signature failed */
};
typedef struct fd_execrp_sigverify_flush_done_msg fd_execrp_sigverify_flush_done_msg_t;

struct fd_execrp_poh_hash_done_msg {
  ulong     cnt;
  fd_hash_t hash[ FD_EXECRP_POH_PARA ];
};
typedef struct fd_execrp_poh_hash_done_msg fd_execrp_poh_hash_done_msg_t;

struct fd_execrp_cert_verify_done_msg {
  int            err;
  int            has_hm; /* hm is the H(m) the tile hashed, for replay's memo */
  blst_p2_affine hm;
};
typedef struct fd_execrp_cert_verify_done_msg fd_execrp_cert_verify_done_msg_t;

struct fd_execrp_task_done_msg {
  ulong bank_idx;
  union {
    fd_execrp_txn_exec_done_msg_t        txn_exec[ 1 ];
    fd_execrp_txn_sigverify_done_msg_t   txn_sigverify[ 1 ];
    fd_execrp_poh_hash_done_msg_t        poh_hash[ 1 ];
    fd_execrp_cert_verify_done_msg_t     cert_verify[ 1 ];
    fd_execrp_sigverify_flush_done_msg_t sigverify_flush[ 1 ];
  };
};
typedef struct fd_execrp_task_done_msg fd_execrp_task_done_msg_t;

#endif /* HEADER_fd_src_discof_replay_fd_execrp_h */
