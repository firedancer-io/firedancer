#ifndef HEADER_fd_src_discof_replay_fd_sched_h
#define HEADER_fd_src_discof_replay_fd_sched_h

#include "fd_rdisp.h"
#include "../../disco/store/fd_store.h" /* for fd_store_fec_t */
#include "../../disco/pack/fd_microblock.h" /* for fd_txn_p_t */

#include "../../funk/fd_funk_base.h" /* for ALUTs */
#include "../../util/spad/fd_spad.h" /* for ALUTs */

/* fd_sched wraps all the smarts and mechanical chores around scheduling
   transactions for replay execution.  It is built on top of the
   dispatcher fd_rdisp.  The dispatcher is responsible for high
   performance lane-based scheduling of transactions.  On top of that,
   we add fork-aware management of lanes, and policies regarding which
   lanes to prioritize for execution.

   Conceptually, transactions in a block form a DAG.  We would like to
   make our way through a block with a sufficient degree of parallelism,
   such that the execution time of the critical path of the DAG is the
   limiting factor.  The dispatcher does a good job of emerging the
   critical path of the DAG on the fly.  Blocks are tracked by the
   dispatcher either as a block staged on a lane, or as an unstaged
   block.  When a block is staged, it will enjoy the most intelligent
   online scheduling that the dispatcher has to offer.  Lanes have to
   consist of linear chains of blocks down a fork.  So to map a fork
   tree to lanes, we will need multiple lanes.  Ideally, every branch in
   the fork tree sits on some lane.  However, memory footprint limits us
   to a few number of lanes.

   This module implements a state machine for ensuring that blocks enter
   into and exit ouf of lanes in an orderly fashion.  The public APIs of
   this module are invoked to drive state transitions on a small number
   of events, such as new transactions arriving, or transactions
   completing, or a block being aborted/abandoned.  We also implement
   policies for deciding which blocks get staged onto lanes, or evicted
   from lanes, as well as which lanes to prioritize for execution.


   The general order in which calls happen under the normal case is:

   fd_sched_fec_ingest()* ... fd_sched_txn_next_ready()* ... fd_sched_txn_done()* ...
   more ingest, more ready, more done ...
   ...
   fd_sched_txn_next_ready() indicates that the last transaction in the block is being scheduled
   fd_sched_txn_done()*
   fd_sched_block_is_done()
   end-of-block processing in caller
   fd_sched_txn_next_ready() starts returning transactions from the next block
   more ingest, more ready, more done ...
   ... */

struct fd_sched;
typedef struct fd_sched fd_sched_t;


struct fd_sched_alut_ctx {
  fd_funk_t *       funk;
  fd_funk_txn_xid_t xid[1];
  ulong             els; /* Effective lookup slot. */
  fd_spad_t *       runtime_spad;
};
typedef struct fd_sched_alut_ctx fd_sched_alut_ctx_t;

struct fd_sched_fec {
  ulong            bank_idx;            /* Index of the block.  Assumed to be in [0, block_cnt_max).  Caller
                                           is responsible for ensuring that bank idx is in bounds and unique
                                           across equivocated blocks. */
  ulong            parent_bank_idx;     /* Index of the parent block.  Assumed to be in [0, block_cnt_max).
                                           Caller is responsible for ensuring that parent bank idx is in
                                           bounds and unique across equivocated blocks. */
  ulong            slot;                /* Slot number of the block. */
  ulong            parent_slot;         /* Slot number of the parent block. */
  fd_store_fec_t * fec;                 /* FEC set data. */
  uint             shred_cnt;           /* Number of shreds in the FEC set. */
  uint             is_last_in_batch:1;  /* Set if this is the last FEC set in the batch; relevant because the
                                           parser should ignore trailing bytes at the end of a batch. */
  uint             is_last_in_block:1;  /* Set if this is the last FEC set in the block. */
  uint             is_first_in_block:1; /* Set if this is the first FEC set in the block. */

  fd_sched_alut_ctx_t alut_ctx[ 1 ];
};
typedef struct fd_sched_fec fd_sched_fec_t;

/* The scheduler may return one of the following types of tasks for the
   replay tile.

   e - passed down to exec tiles.
   i - replay completes the task immediately.
   q - replay may either do it immediately or queue the task up. */
#define FD_SCHED_TT_NULL          (0UL)
#define FD_SCHED_TT_BLOCK_START   (1UL) /* (i) Start-of-block processing. */
#define FD_SCHED_TT_BLOCK_END     (2UL) /* (q) End-of-block processing. */
#define FD_SCHED_TT_TXN_EXEC      (3UL) /* (e) Transaction execution. */
#define FD_SCHED_TT_TXN_SIGVERIFY (4UL) /* (e) Transaction sigverify. */
#define FD_SCHED_TT_LTHASH        (5UL) /* (e) Account lthash. */
#define FD_SCHED_TT_POH_VERIFY    (6UL) /* (e) PoH hash verification. */

struct fd_sched_block_start {
  ulong bank_idx;        /* Same as in fd_sched_fec_t. */
  ulong parent_bank_idx; /* Same as in fd_sched_fec_t. */
  ulong slot;            /* Slot number of the block. */
};
typedef struct fd_sched_block_start fd_sched_block_start_t;

struct fd_sched_block_end {
  ulong bank_idx;
};
typedef struct fd_sched_block_end fd_sched_block_end_t;

struct fd_sched_txn_exec {
  ulong bank_idx;
  ulong slot;
  ulong txn_idx;
};
typedef struct fd_sched_txn_exec fd_sched_txn_exec_t;

struct fd_sched_txn_sigverify {
  ulong bank_idx;
  ulong txn_idx;
};
typedef struct fd_sched_txn_sigverify fd_sched_txn_sigverify_t;

struct fd_sched_task {
  ulong task_type; /* Set to one of the task types defined above. */
  union {
    fd_sched_block_start_t   block_start[ 1 ];
    fd_sched_block_end_t     block_end[ 1 ];
    fd_sched_txn_exec_t      txn_exec[ 1 ];
    fd_sched_txn_sigverify_t txn_sigverify[ 1 ];
  };
};
typedef struct fd_sched_task fd_sched_task_t;

FD_PROTOTYPES_BEGIN

/* fd_sched_{align,footprint} return the required alignment and
   footprint in bytes for a region of memory to be used as a scheduler.
   block_cnt_max is the maximum number of blocks that will be tracked by
   the scheduler. */
ulong fd_sched_align    ( void );
ulong fd_sched_footprint( ulong block_cnt_max );

void *
fd_sched_new( void * mem, ulong block_cnt_max );

fd_sched_t *
fd_sched_join( void * mem, ulong block_cnt_max );

/* Add the data in the FEC set to the scheduler.  If is_last_fec is 1,
   then this is the last FEC set in the block.  Transactions may span
   FEC set boundaries.  The scheduler is responsible for incrementally
   parsing transactions from concatenated FEC set data.  Assumes that
   FEC sets are delivered in replay order.  That is, forks form a
   partial ordering over FEC sets: in-order per fork, but arbitrary
   ordering across forks.  The fork tree is implied by the stream of
   parent-child relationships delivered in FEC sets.  Also assumes that
   there is enough space in the scheduler to ingest the FEC set.  The
   caller should generally call fd_sched_fec_can_ingest() first.

   Returns 1 on success, 0 if the block is bad and should be marked
   dead. */
FD_WARN_UNUSED int
fd_sched_fec_ingest( fd_sched_t * sched, fd_sched_fec_t * fec );

/* Check if there is enough space in the scheduler to ingest the data in
   the FEC set.  Returns 1 if there is, 0 otherwise.  This is a cheap
   and conservative check. */
int
fd_sched_fec_can_ingest( fd_sched_t * sched, fd_sched_fec_t * fec );

/* Check if there is enough space in the scheduler to ingest a worst
   case FEC set.  Returns 1 if there is, 0 otherwise.  This is a cheap
   and conservative check, and has less precision than
   fd_sched_fec_can_ingest(). */
int
fd_sched_can_ingest( fd_sched_t * sched );

/* Obtain a transaction eligible for execution.  This implies that all
   prior transactions with w-r or w-w conflicts have completed.
   Information regarding the scheduled transaction is written to the out
   pointer.  Returns 1 on success, 0 on failure.  Failures are generally
   transient and non-fatal, and are simply an indication that no
   transaction is ready for execution yet.  When in-flight transactions
   retire or when more FEC sets are ingested, more transactions may
   become ready for execution.

   Transactions on the same fork will be returned in a way that
   maintains the serial fiction.  That is, reordering can happen, but
   only within the constraint that transactions appear to be ready in
   the order in which they occur in the block.  Transactions from
   different forks may interleave, and the caller should be prepared to
   switch execution context in response to interleavings.  The scheduler
   will barrier on block boundaries, in the sense that transactions from
   a subsequent block will not be returned for execution until all
   transactions from the previous block have completed.  This gives the
   caller a chance to perform end-of-block processing before
   transactions from a subsequent block start executing.  In general,
   the caller should check if the last transaction in the current block
   is done, and if so, do end-of-block processing before calling this
   function to start the next block.

   In addition to returning transactions for execution, this function
   may also return a sigverify task.  Sigverify can be completed
   aynschronously outside the critical path of transaction execution, as
   long as every transaction in a block passes sigverify before we
   commit the block.  The scheduler prioritizes actual execution of
   transactions over sigverify, and in general sigverify tasks are only
   returned when no real transaction can be dispatched.  In other words,
   the scheduler tries to exploit idle cycles in the exec tiles during
   times of low parallelism critical path progression. */
ulong
fd_sched_task_next_ready( fd_sched_t * sched, fd_sched_task_t * out, ulong exec_tile_cnt );

/* Mark a task as complete.  For transaction execution, this means that
   the effects of the execution are now visible on any core that could
   execute a subsequent transaction. */
void
fd_sched_task_done( fd_sched_t * sched, ulong task_type, ulong txn_idx );

/* Abandon a block.  This means that we are no longer interested in
   executing the block.  This also implies that any block which chains
   off of the provided block shall be abandoned.  This is mainly used
   when a block is aborted because we decided that it would be a
   dead/invalid block, and so there's no point in spending resources
   executing it.  The scheduler will no longer return transactions from
   abandoned blocks for execution.  This should only be invoked on an
   actively replayed block, and should only be invoked once on it. */
void
fd_sched_block_abandon( fd_sched_t * sched, ulong bank_idx );

/* Add a block as immediately done to the scheduler.  This is useful for
   installing the snapshot slot, or for informing the scheduler of a
   packed leader block.  Parent block should be ULONG_MAX for the
   snapshot slot, and otherwise a block that hasn't been pruned. */
void
fd_sched_block_add_done( fd_sched_t * sched, ulong bank_idx, ulong parent_bank_idx );

/* Advance the root, pruning all blocks across forks that do not descend
   from the new root.  Assumes the new root is in the fork tree and
   connected to the current root.  Also assumes that there are no more
   in-flight transactions from the soon-to-be-pruned blocks.  This
   should be called after root_notify() and the caller is responsible
   for figuring out the new root to safely prune to. */
void
fd_sched_advance_root( fd_sched_t * sched, ulong root_idx );

/* Notify the scheduler of a new root.  This has the effect of calling
   abandon() on all minority forks that do not descend from the new
   root.  Shortly after a call to this function, in-flight transactions
   from these abandoned blocks should retire from the execution
   pipeline, and the new root will be safe for pruning. */
void
fd_sched_root_notify( fd_sched_t * sched, ulong root_idx );

fd_txn_p_t *
fd_sched_get_txn( fd_sched_t * sched, ulong txn_idx );

fd_hash_t *
fd_sched_get_poh( fd_sched_t * sched, ulong bank_idx );

uint
fd_sched_get_shred_cnt( fd_sched_t * sched, ulong bank_idx );

void *
fd_sched_leave( fd_sched_t * sched );

void *
fd_sched_delete( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_sched_h */
