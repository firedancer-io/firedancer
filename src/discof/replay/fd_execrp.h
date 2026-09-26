#ifndef HEADER_fd_src_discof_replay_fd_exec_h
#define HEADER_fd_src_discof_replay_fd_exec_h

#include "../../disco/fd_txn_p.h"
#include "../../tango/fd_tango_base.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/alpenglow/fd_block_marker.h"
#include "../../flamenco/alpenglow/fd_alpenglow.h"
#include "../../ballet/lthash/fd_lthash.h"

/* Exec tile task types. */
#define FD_EXECRP_TT_TXN_EXEC      (1UL) /* Transaction execution. */
#define FD_EXECRP_TT_TXN_SIGVERIFY (2UL) /* Transaction sigverify. */
#define FD_EXECRP_TT_POH_HASH      (3UL) /* PoH hashing. */
#define FD_EXECRP_TT_LTHASH_SUB    (4UL) /* Hash accounts as they are in the parent bank's fork. */
#define FD_EXECRP_TT_LTHASH_ADD    (5UL) /* Hash accounts as they are in this bank's fork. */
#define FD_EXECRP_TT_CERT_VERIFY   (6UL) /* Alpenglow footer cert verify. */
#define FD_EXECRP_TT_REWARDS       (7UL) /* Alpenglow footer vote rewards, one slice of the signers. */

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

  /* Non-zero asks the exec tile to leave the transaction's expanded
     writable address lookup table accounts in its result entry. */
  int        want_alts;
};
typedef struct fd_execrp_txn_exec_msg fd_execrp_txn_exec_msg_t;

/* A sigverify task carries up to FD_EXECRP_SIGVERIFY_PARA transactions
   of one block, packed back to back after the header: each is
   payload_sz[ i ] bytes of payload followed, at the next
   alignof(fd_txn_t), by its fd_txn_t descriptor.  The scheduler
   budgets bytes so a task fits sizeof(fd_execrp_task_msg_t). */

#define FD_EXECRP_SIGVERIFY_PARA (8UL)

struct fd_execrp_txn_sigverify_msg {
  ulong  bank_idx;
  ulong  cnt;                                    /* In [1,FD_EXECRP_SIGVERIFY_PARA] */
  uint   txn_idx   [ FD_EXECRP_SIGVERIFY_PARA ];
  ushort off       [ FD_EXECRP_SIGVERIFY_PARA ]; /* payload offset from the start of the message */
  ushort payload_sz[ FD_EXECRP_SIGVERIFY_PARA ];
  ushort txn_off   [ FD_EXECRP_SIGVERIFY_PARA ]; /* fd_txn_t offset from the start of the message */
};
typedef struct fd_execrp_txn_sigverify_msg fd_execrp_txn_sigverify_msg_t;

static inline uchar const *
fd_execrp_sigverify_payload( fd_execrp_txn_sigverify_msg_t const * msg, ulong i ) {
  return (uchar const *)msg + msg->off[ i ];
}

static inline fd_txn_t const *
fd_execrp_sigverify_txn( fd_execrp_txn_sigverify_msg_t const * msg, ulong i ) {
  return (fd_txn_t const *)( (uchar const *)msg + msg->txn_off[ i ] );
}

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
  fd_bls_hash_t         hm;
  fd_block_footer_cert_t cert[ 1 ];
};
typedef struct fd_execrp_cert_verify_msg fd_execrp_cert_verify_msg_t;

/* This is the largest power of two at which the LtHash task still fits
   the task union below. */

#define FD_EXECRP_LTHASH_BATCH_MAX (128UL)

struct fd_execrp_lthash_msg {
  ulong          bank_idx;
  ulong          cnt; /* In [1, FD_EXECRP_LTHASH_BATCH_MAX] */
  fd_acct_addr_t acct[ FD_EXECRP_LTHASH_BATCH_MAX ];
};
typedef struct fd_execrp_lthash_msg fd_execrp_lthash_msg_t;

struct fd_execrp_rewards_msg {
  ulong                       bank_idx;
  ulong                       slice_idx; /* in [0, slice_cnt) */
  ulong                       slice_cnt;
  fd_alpenglow_rewards_plan_t plan;
};
typedef struct fd_execrp_rewards_msg fd_execrp_rewards_msg_t;

union fd_execrp_task_msg {
  fd_execrp_txn_exec_msg_t      txn_exec;
  fd_execrp_txn_sigverify_msg_t txn_sigverify;
  fd_execrp_poh_hash_msg_t      poh_hash;
  fd_execrp_cert_verify_msg_t   cert_verify;
  fd_execrp_lthash_msg_t        lthash;
  fd_execrp_rewards_msg_t       rewards;
};

typedef union fd_execrp_task_msg fd_execrp_task_msg_t;

FD_STATIC_ASSERT( sizeof(fd_execrp_lthash_msg_t) <=sizeof(fd_execrp_txn_exec_msg_t), execrp_lthash_msg_sz  );
FD_STATIC_ASSERT( sizeof(fd_execrp_rewards_msg_t)<=sizeof(fd_execrp_txn_exec_msg_t), execrp_rewards_msg_sz );

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

  /* Number of the transaction's expanded writable address lookup table
     accounts the exec tile left in its result entry, in transaction
     order.  0 unless the request had want_alts set and the expansion
     succeeded. */
  uchar alt_writable_cnt;

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
  ulong bank_seq;
};
typedef struct fd_execrp_txn_exec_done_msg fd_execrp_txn_exec_done_msg_t;

/* Sent from exec tiles to the gui for each executed transaction, on a
   link of its own so the gui is not woken by the other completions.
   Published with the tsorig and tspub of the matching TXN_EXEC
   completion. */

struct fd_execrp_gui_msg {
  ulong  slot;
  ushort start_shred_idx;
  ushort end_shred_idx;
};
typedef struct fd_execrp_gui_msg fd_execrp_gui_msg_t;

struct fd_execrp_txn_sigverify_done_msg {
  ulong cnt;                                  /* == the task's cnt */
  uint  txn_idx[ FD_EXECRP_SIGVERIFY_PARA ];  /* in task order */
  uchar err    [ FD_EXECRP_SIGVERIFY_PARA ];  /* nonzero if that transaction failed to verify */
};
typedef struct fd_execrp_txn_sigverify_done_msg fd_execrp_txn_sigverify_done_msg_t;

struct fd_execrp_poh_hash_done_msg {
  ulong     cnt;
  fd_hash_t hash[ FD_EXECRP_POH_PARA ];
};
typedef struct fd_execrp_poh_hash_done_msg fd_execrp_poh_hash_done_msg_t;

struct fd_execrp_cert_verify_done_msg {
  int            err;
  int            has_hm; /* hm is the H(m) the tile hashed, for replay's memo */
  fd_bls_hash_t hm;
};
typedef struct fd_execrp_cert_verify_done_msg fd_execrp_cert_verify_done_msg_t;

struct fd_execrp_lthash_done_msg {
  ulong cnt;
};
typedef struct fd_execrp_lthash_done_msg fd_execrp_lthash_done_msg_t;

struct fd_execrp_rewards_done_msg {
  int   err;
  ulong leader_credits; /* The slice's share of the leader's credits.  Its lthash delta is in the tile's result entry. */
};
typedef struct fd_execrp_rewards_done_msg fd_execrp_rewards_done_msg_t;

struct fd_execrp_task_done_msg {
  ulong bank_idx;
  union {
    fd_execrp_txn_exec_done_msg_t      txn_exec[ 1 ];
    fd_execrp_txn_sigverify_done_msg_t txn_sigverify[ 1 ];
    fd_execrp_poh_hash_done_msg_t      poh_hash[ 1 ];
    fd_execrp_cert_verify_done_msg_t   cert_verify[ 1 ];
    fd_execrp_lthash_done_msg_t        lthash[ 1 ];
    fd_execrp_rewards_done_msg_t       rewards[ 1 ];
  };
};
typedef struct fd_execrp_task_done_msg fd_execrp_task_done_msg_t;

/* Task results too large for the done message.  There is one entry per
   exec tile.  The exec tile fills its entry before it publishes the
   done message, and the task type in the sig says which member is
   valid. */

struct fd_execrp_result {
  union {
    fd_lthash_value_t lthash;                                   /* LTHASH_SUB, LTHASH_ADD, REWARDS. */
    fd_pubkey_t       alt_writable[ FD_TXN_ACCT_ADDR_MAX-1UL ]; /* TXN_EXEC.  alt_writable_cnt of these are valid. */
  };
};
typedef struct fd_execrp_result fd_execrp_result_t;

FD_STATIC_ASSERT( sizeof(fd_execrp_result_t)==sizeof(fd_lthash_value_t), execrp_result_sz );

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_execrp_lthash_msg_sz( ulong cnt ) {
  return offsetof(fd_execrp_lthash_msg_t, acct) + cnt*sizeof(fd_acct_addr_t);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_execrp_h */
