#ifndef HEADER_fd_src_discof_replay_fd_exec_h
#define HEADER_fd_src_discof_replay_fd_exec_h

#include "../../disco/fd_txn_p.h"
#include "../../tango/fd_tango_base.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/alpenglow/fd_block_marker.h"
#include "../../ballet/lthash/fd_lthash.h"

/* Exec tile task types. */
#define FD_EXECRP_TT_TXN_EXEC      (1UL) /* Transaction execution. */
#define FD_EXECRP_TT_TXN_SIGVERIFY (2UL) /* Transaction sigverify. */
#define FD_EXECRP_TT_POH_HASH      (3UL) /* PoH hashing. */
#define FD_EXECRP_TT_LTHASH_SUB    (4UL) /* Hash accounts as they are in the parent bank's fork. */
#define FD_EXECRP_TT_LTHASH_ADD    (5UL) /* Hash accounts as they are in this bank's fork. */
#define FD_EXECRP_TT_CERT_VERIFY   (6UL) /* Alpenglow footer cert verify. */

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

/* A sigverify batch takes consecutive transactions of one block until
   it holds FD_EXECRP_SIGVERIFY_SIG_PARA signatures, so at most
   FD_EXECRP_SIGVERIFY_LANE_MAX since the last transaction can bring
   FD_TXN_SIG_MAX. */
#define FD_EXECRP_SIGVERIFY_SIG_PARA 8
#define FD_EXECRP_SIGVERIFY_LANE_MAX (FD_EXECRP_SIGVERIFY_SIG_PARA-1+FD_TXN_SIG_MAX)
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

/* This is the largest power of two at which the LtHash task still fits
   the task union below. */

#define FD_EXECRP_LTHASH_BATCH_MAX (128UL)
/* Speculative additions need individual hashes for independent stale
   rejection and later undo.  Bound both task duration and result space. */
#define FD_EXECRP_LTHASH_SPEC_MAX (8UL)

struct fd_execrp_lthash_msg {
  ulong          bank_idx;
  ulong          cnt; /* In [1, FD_EXECRP_LTHASH_BATCH_MAX] */
  int            individual; /* ADD only, cnt<=FD_EXECRP_LTHASH_SPEC_MAX. */
  fd_acct_addr_t acct[ FD_EXECRP_LTHASH_BATCH_MAX ];
};
typedef struct fd_execrp_lthash_msg fd_execrp_lthash_msg_t;

union fd_execrp_task_msg {
  fd_execrp_txn_exec_msg_t      txn_exec;
  fd_execrp_txn_sigverify_msg_t txn_sigverify;
  fd_execrp_poh_hash_msg_t      poh_hash;
  fd_execrp_cert_verify_msg_t   cert_verify;
  fd_execrp_lthash_msg_t        lthash;
};

typedef union fd_execrp_task_msg fd_execrp_task_msg_t;

FD_STATIC_ASSERT( sizeof(fd_execrp_lthash_msg_t)<=sizeof(fd_execrp_txn_exec_msg_t), execrp_lthash_msg_sz );

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
  uchar committed_writable_cnt; /* Actual committed account keys in tile result. */

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
  int   err    [ FD_EXECRP_SIGVERIFY_SIG_PARA ]; /* Non-zero if any signature failed */
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
  blst_p2_affine hm;
};
typedef struct fd_execrp_cert_verify_done_msg fd_execrp_cert_verify_done_msg_t;

struct fd_execrp_lthash_done_msg {
  ulong cnt;
};
typedef struct fd_execrp_lthash_done_msg fd_execrp_lthash_done_msg_t;

struct fd_execrp_task_done_msg {
  ulong bank_idx;
  union {
    fd_execrp_txn_exec_done_msg_t      txn_exec[ 1 ];
    fd_execrp_txn_sigverify_done_msg_t txn_sigverify[ 1 ];
    fd_execrp_poh_hash_done_msg_t      poh_hash[ 1 ];
    fd_execrp_cert_verify_done_msg_t   cert_verify[ 1 ];
    fd_execrp_lthash_done_msg_t        lthash[ 1 ];
  };
};
typedef struct fd_execrp_task_done_msg fd_execrp_task_done_msg_t;

/* Task results too large for the done message.  There is one entry per
   exec tile.  The exec tile fills its entry before it publishes the
   done message, and the task type in the sig says which member is
   valid. */

struct fd_execrp_result {
  union {
    fd_lthash_value_t lthash;                                   /* LTHASH_SUB, LTHASH_ADD. */
    fd_lthash_value_t lthash_spec[ FD_EXECRP_LTHASH_SPEC_MAX ];  /* Individual speculative ADD hashes. */
    struct {
      fd_pubkey_t alt_writable[ FD_TXN_ACCT_ADDR_MAX-1UL ];
      fd_pubkey_t committed_writable[ MAX_TX_ACCOUNT_LOCKS ];
    }; /* TXN_EXEC. Counts in done message; both arrays valid concurrently. */
  };
};
typedef struct fd_execrp_result fd_execrp_result_t;

FD_STATIC_ASSERT( sizeof(fd_execrp_result_t)==FD_EXECRP_LTHASH_SPEC_MAX*sizeof(fd_lthash_value_t), execrp_result_sz );

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_execrp_lthash_msg_sz( ulong cnt ) {
  return offsetof(fd_execrp_lthash_msg_t, acct) + cnt*sizeof(fd_acct_addr_t);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_execrp_h */
