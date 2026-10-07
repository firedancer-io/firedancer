#ifndef HEADER_fd_src_discof_replay_fd_exec_h
#define HEADER_fd_src_discof_replay_fd_exec_h

#include "../../disco/fd_txn_p.h"
#include "../../tango/fd_tango_base.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../ballet/lthash/fd_lthash.h"

/* Exec tile task types. */
#define FD_EXECRP_TT_TXN_EXEC      (1UL) /* Transaction execution. */
#define FD_EXECRP_TT_TXN_SIGVERIFY (2UL) /* Transaction sigverify. */
#define FD_EXECRP_TT_POH_HASH      (3UL) /* PoH hashing. */
#define FD_EXECRP_TT_LTHASH_SUB    (4UL) /* Hash an account as it is in the parent bank's fork. */
#define FD_EXECRP_TT_LTHASH_ADD    (5UL) /* Hash an account as it is in this bank's fork. */

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

  /* Non-zero asks the exec tile to return the transaction's expanded
     writable address lookup table accounts in the done message. */
  int        want_alts;
};
typedef struct fd_execrp_txn_exec_msg fd_execrp_txn_exec_msg_t;

struct fd_execrp_txn_sigverify_msg {
  ulong      bank_idx;
  ulong      txn_idx;
  fd_txn_p_t txn[ 1 ];
};
typedef struct fd_execrp_txn_sigverify_msg fd_execrp_txn_sigverify_msg_t;

#define FD_EXECRP_POH_PARA 16
struct fd_execrp_poh_hash_msg {
  ulong     bank_idx;
  ulong     cnt;     /* In [1,FD_EXECRP_POH_PARA] */
  ulong     hashcnt; /* Same for every element of the batch */
  fd_hash_t hash[ FD_EXECRP_POH_PARA ];
};
typedef struct fd_execrp_poh_hash_msg fd_execrp_poh_hash_msg_t;

/* An LtHash task hashes acct as fd_hashes_account_lthash_simple does,
   reading it on the parent bank's accdb fork for SUB and on this bank's
   fork for ADD.  A missing or zero-lamport account hashes to zero. */

struct fd_execrp_lthash_msg {
  ulong          bank_idx;
  ulong          ptxn_idx;   /* rdisp pseudo-txn index for ADD, 0 for SUB */
  fd_acct_addr_t acct;
};
typedef struct fd_execrp_lthash_msg fd_execrp_lthash_msg_t;

union fd_execrp_task_msg {
  fd_execrp_txn_exec_msg_t      txn_exec;
  fd_execrp_txn_sigverify_msg_t txn_sigverify;
  fd_execrp_poh_hash_msg_t      poh_hash;
  fd_execrp_lthash_msg_t        lthash;
};

typedef union fd_execrp_task_msg fd_execrp_task_msg_t;

/* Sent from exec tiles to the replay tile, notifying the replay tile
   that a task has been completed.  That is, if the task has any
   observable side effects, such as updates to accounts, then those side
   effects are fully visible on any other exec tile.

   A TXN_EXEC, TXN_SIGVERIFY or POH_HASH frag is a
   fd_execrp_task_done_msg_t, and a TXN_EXEC frag is followed by
   txn_exec->alt_writable_cnt pubkeys (fd_execrp_txn_exec_done_alt_writable).
   An LTHASH_SUB or LTHASH_ADD frag is a fd_execrp_lthash_done_msg_t.
   Both message types start with bank_idx. */

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
  int is_simple_vote;

  /* Number of pubkeys trailing the frag: the transaction's expanded
     writable address lookup table accounts, in transaction order.  0
     unless the request had want_alts set and the expansion succeeded. */
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
  ulong  slot;
  ulong  bank_seq;
  ushort start_shred_idx;
  ushort end_shred_idx;

  /* vote.slot==ULONG_MAX if this was not a vote transaction */
  struct {
    ulong       slot;
    ulong       vote_slots[ 31UL ];
    uchar       vote_slot_cnt;
    fd_pubkey_t identity[ 1 ];
    fd_pubkey_t vote_acct[ 1 ];
  } vote;
};
typedef struct fd_execrp_txn_exec_done_msg fd_execrp_txn_exec_done_msg_t;

struct fd_execrp_txn_sigverify_done_msg {
  ulong txn_idx;
  int   err;
};
typedef struct fd_execrp_txn_sigverify_done_msg fd_execrp_txn_sigverify_done_msg_t;

struct fd_execrp_poh_hash_done_msg {
  ulong     cnt;
  fd_hash_t hash[ FD_EXECRP_POH_PARA ];
};
typedef struct fd_execrp_poh_hash_done_msg fd_execrp_poh_hash_done_msg_t;

struct fd_execrp_task_done_msg {
  ulong bank_idx;
  union {
    fd_execrp_txn_exec_done_msg_t      txn_exec[ 1 ];
    fd_execrp_txn_sigverify_done_msg_t txn_sigverify[ 1 ];
    fd_execrp_poh_hash_done_msg_t      poh_hash[ 1 ];
  };
};
typedef struct fd_execrp_task_done_msg fd_execrp_task_done_msg_t;

/* The in-band execrp_replay MTU is this size; the topology sizes the
   link from it. */
FD_STATIC_ASSERT( sizeof(fd_execrp_task_done_msg_t)==528UL, execrp_task_done_sz );

/* The done message of an LtHash task.  It is its own type rather than
   a member of the done union so that the 2 KiB value does not grow
   every done frag, and with it every execrp_replay dcache, when the
   feature is off.  bank_idx comes first, at the same offset as in
   fd_execrp_task_done_msg_t, so a consumer can read it before switching
   on the task type.  ptxn_idx and acct are copied from the request. */

struct __attribute__((aligned(64))) fd_execrp_lthash_done_msg {
  ulong             bank_idx;
  ulong             ptxn_idx;
  fd_acct_addr_t    acct;
  fd_lthash_value_t value;   /* 2 KiB */
};
typedef struct fd_execrp_lthash_done_msg fd_execrp_lthash_done_msg_t;

/* dcache chunks are FD_CHUNK_ALIGN aligned. */
FD_STATIC_ASSERT( alignof(fd_execrp_lthash_done_msg_t)<=FD_CHUNK_ALIGN, execrp_lthash_done_align );
FD_STATIC_ASSERT( offsetof(fd_execrp_lthash_done_msg_t, bank_idx)==offsetof(fd_execrp_task_done_msg_t, bank_idx), execrp_lthash_done_bank_idx );

/* execrp_replay link MTUs.  FD_EXECRP_TASK_DONE_MTU_INBAND fits every
   done frag when LtHash is computed in band, where TXN_EXEC frags carry
   no lookup table accounts and there are no LtHash tasks.
   FD_EXECRP_TASK_DONE_MTU_OOB also fits an LtHash done message and a
   TXN_EXEC frag carrying the most writable lookup table accounts a v0
   transaction can have, FD_TXN_ACCT_ADDR_MAX-1 (fd_txn.h).  It equals
   max( sizeof(fd_execrp_lthash_done_msg_t),
        fd_execrp_txn_exec_done_sz( FD_TXN_ACCT_ADDR_MAX-1UL ) ),
   spelled out so it stays a compile-time constant. */

#define FD_EXECRP_TASK_DONE_MTU_INBAND (sizeof(fd_execrp_task_done_msg_t))
#define FD_EXECRP_TXN_EXEC_DONE_MAX_SZ (FD_EXECRP_TASK_DONE_MTU_INBAND+(FD_TXN_ACCT_ADDR_MAX-1UL)*sizeof(fd_pubkey_t))
#define FD_EXECRP_TASK_DONE_MTU_OOB    (sizeof(fd_execrp_lthash_done_msg_t)>FD_EXECRP_TXN_EXEC_DONE_MAX_SZ ? \
                                        sizeof(fd_execrp_lthash_done_msg_t) : FD_EXECRP_TXN_EXEC_DONE_MAX_SZ)

FD_PROTOTYPES_BEGIN

/* fd_execrp_txn_exec_done_alt_writable returns the
   msg->txn_exec->alt_writable_cnt writable lookup table accounts that
   trail a TXN_EXEC done frag.  fd_execrp_txn_exec_done_sz returns the
   size of a TXN_EXEC done frag carrying alt_writable_cnt of them. */

FD_FN_CONST static inline fd_pubkey_t const *
fd_execrp_txn_exec_done_alt_writable( fd_execrp_task_done_msg_t const * msg ) {
  return (fd_pubkey_t const *)(msg+1);
}

FD_FN_CONST static inline ulong
fd_execrp_txn_exec_done_sz( ulong alt_writable_cnt ) {
  return sizeof(fd_execrp_task_done_msg_t) + alt_writable_cnt*sizeof(fd_pubkey_t);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_execrp_h */
