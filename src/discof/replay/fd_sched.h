#ifndef HEADER_fd_src_discof_replay_fd_sched_h
#define HEADER_fd_src_discof_replay_fd_sched_h

#include "fd_rdisp.h"
#include "../../disco/fd_txn_p.h"
#include "../../disco/store/fd_store.h" /* for fd_store_fec_t */
#include "../../flamenco/accdb/fd_accdb.h"

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
   into and exit out of lanes in an orderly fashion.  The public APIs of
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

#define FD_SCHED_MIN_DEPTH 478
#define FD_SCHED_MAX_DEPTH FD_RDISP_MAX_DEPTH

struct fd_sched;
typedef struct fd_sched fd_sched_t;

struct fd_sched_alut_ctx {
  fd_accdb_t *       accdb;
  fd_accdb_fork_id_t fork_id;
  ulong              els; /* Effective lookup slot. */
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
  fd_store_fec_t * fec;                 /* FEC set metadata. */
  uchar          * data;                /* Resolved laddr of the FEC set data buffer. */
  uint             shred_cnt;           /* Number of shreds in the FEC set. */
  uint             is_last_in_batch:1;  /* Set if this is the last FEC set in the batch; relevant because the
                                           parser should ignore trailing bytes at the end of a batch. */
  uint             is_last_in_block:1;  /* Set if this is the last FEC set in the block. */
  uint             is_first_in_block:1; /* Set if this is the first FEC set in the block.  Bank should increment refcnt for sched if such a FEC set has been ingested by sched. */
  long             completed_ns;        /* Network arrival (wallclock ns) of the shred that completed this FEC set; 0 if unavailable. */

  fd_sched_alut_ctx_t alut_ctx[ 1 ];
};
typedef struct fd_sched_fec fd_sched_fec_t;

/* The state of a transaction.  Non mutually exclusive. */
#define FD_SCHED_TXN_EXEC_DONE      (0x0001UL)
#define FD_SCHED_TXN_SIGVERIFY_DONE (0x0002UL)
#define FD_SCHED_TXN_IS_COMMITTABLE (0x0004UL)
#define FD_SCHED_TXN_IS_FEES_ONLY   (0x0008UL)
#define FD_SCHED_TXN_REPLAY_DONE    (FD_SCHED_TXN_EXEC_DONE|FD_SCHED_TXN_SIGVERIFY_DONE)

struct fd_sched_txn_info {
   ulong flags;
   int   txn_err;
   long  received_ns;
   long  tick_parsed;
   long  tick_sigverify_disp;
   long  tick_sigverify_done;
   long  tick_exec_disp;
   long  tick_exec_done;
   ulong index_in_slot; /* 0-indexed position of this transaction within its block. */
};
typedef struct fd_sched_txn_info fd_sched_txn_info_t;

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
#define FD_SCHED_TT_POH_HASH      (6UL) /* (e) PoH hashing. */
#define FD_SCHED_TT_MARK_DEAD     (7UL) /* (i) Mark the block dead. */

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
  ulong exec_idx;
};
typedef struct fd_sched_txn_exec fd_sched_txn_exec_t;

struct fd_sched_txn_sigverify {
  ulong bank_idx;
  ulong txn_idx;
  ulong exec_idx;
};
typedef struct fd_sched_txn_sigverify fd_sched_txn_sigverify_t;

struct fd_sched_poh_hash {
  ulong     bank_idx;
  ulong     mblk_idx;
  ulong     exec_idx;
  ulong     hashcnt;
  fd_hash_t hash[ 1 ];
};
typedef struct fd_sched_poh_hash fd_sched_poh_hash_t;

struct fd_sched_mark_dead {
  ulong     bank_idx;
};
typedef struct fd_sched_mark_dead fd_sched_mark_dead_t;

struct fd_sched_task {
  ulong task_type; /* Set to one of the task types defined above. */
  union {
    fd_sched_block_start_t   block_start[ 1 ];
    fd_sched_block_end_t     block_end[ 1 ];
    fd_sched_txn_exec_t      txn_exec[ 1 ];
    fd_sched_txn_sigverify_t txn_sigverify[ 1 ];
    fd_sched_poh_hash_t      poh_hash[ 1 ];
    fd_sched_mark_dead_t     mark_dead[ 1 ];
  };
};
typedef struct fd_sched_task fd_sched_task_t;


#define FD_SCHED_DEAD_REASON_NONE                        (0)  /* Block was not ruled invalid by the scheduler.  The replay tile may still rule it invalid, unbeknownst to the scheduler. */
#define FD_SCHED_DEAD_REASON_UNPARSEABLE_CONTENT         (1)  /* Bytes at the head of the stream failed to parse out as any structure (transaction, microblock header, or count) within the largest size a valid block allows: malformed content. */
#define FD_SCHED_DEAD_REASON_SHORT_BLOCK                 (2)  /* Block bytes ended short of the microblocks and transactions declared. */
#define FD_SCHED_DEAD_REASON_TOO_MANY_TXNS               (3)  /* More transactions than a valid block can hold. */
#define FD_SCHED_DEAD_REASON_TOO_MANY_MICROBLOCKS        (4)  /* More microblocks than a valid block can hold. */
#define FD_SCHED_DEAD_REASON_DUPLICATE_ACCOUNT           (5)  /* Transaction referenced the same account more than once. */
#define FD_SCHED_DEAD_REASON_TRAILING_ENTRY              (6)  /* Block did not end on a tick. */
#define FD_SCHED_DEAD_REASON_TOO_MANY_TICKS              (7)  /* More ticks than required. */
#define FD_SCHED_DEAD_REASON_TOO_FEW_TICKS               (8)  /* Fewer ticks than required. */
#define FD_SCHED_DEAD_REASON_ZERO_MICROBLOCKS            (9)  /* A batch header declared zero microblocks. */
#define FD_SCHED_DEAD_REASON_WRONG_HASHES_PER_TICK       (10) /* Tick hash count did not advance the expected hashes per tick. */
#define FD_SCHED_DEAD_REASON_INCONSISTENT_TICK_HASHES    (11) /* Tick hash count differs from the block's preceding ticks, detected at FEC ingest. */
#define FD_SCHED_DEAD_REASON_TICK_HASHES_OVERFLOW        (12) /* More hashes since the last tick than hashes per tick allows. */
#define FD_SCHED_DEAD_REASON_TICK_HASHES_OVERFLOW_INGEST (13) /* Tick header declared more hashes than can fit before the next tick, detected at FEC ingest. */
#define FD_SCHED_DEAD_REASON_ZERO_HASH_TICK              (14) /* Tick advanced zero hashes; PoH params were unknown when the tick parsed. */
#define FD_SCHED_DEAD_REASON_ZERO_HASH_TICK_INGEST       (15) /* Tick advanced zero hashes, detected at FEC ingest. */
#define FD_SCHED_DEAD_REASON_TICK_HASH_MISMATCH          (16) /* PoH hash of a tick did not verify. */
#define FD_SCHED_DEAD_REASON_ENTRY_HASH_MISMATCH         (17) /* PoH hash of a transaction entry did not verify, detected when the entry's PoH hashing task completed. */
#define FD_SCHED_DEAD_REASON_ENTRY_HASH_MISMATCH_INGEST  (18) /* PoH hash of a transaction entry did not verify, detected at FEC ingest when a later FEC set completed the entry's transactions. */
#define FD_SCHED_DEAD_REASON_DEAD_ANCESTOR               (19) /* The block went down with its lineage.  Whether the lineage was discarded or ruled invalid is distinguished by fd_sched_block_is_discarded. */

/* Cause to pass to fd_sched_block_abandon().  A block is considered
   invalid when it violates the protocol, so validity is a function of
   the block's content.  A block may be discarded (temporarily) because
   the validator is under resource pressure.  A block may be discarded
   (permanently) if consensus converged on an alternative fork, which is
   done implicitly in fd_sched_root_notify() for the minority forks it
   abandons. */
#define FD_SCHED_ABANDON_DISCARDED (0)
#define FD_SCHED_ABANDON_INVALID   (1)

struct __attribute__((packed)) fd_microblock_hdr {
  /* Number of PoH hashes between this and last microblock */
  /* 0x00 */ ulong hash_cnt;

  /* PoH state after evaluating this microblock (including all
     appends and mixin). The input to the poh calculation of the first
     microblock is the last hash of the parent block, otherwise it is the
     hash of the previous microblock. */
  /* 0x08 */ uchar hash[32];

  /* Number of transactions in this microblock */
  /* 0x28 */ ulong txn_cnt;
};
typedef struct fd_microblock_hdr fd_microblock_hdr_t;

FD_PROTOTYPES_BEGIN

/* fd_sched_{align,footprint} return the required alignment and
   footprint in bytes for a region of memory to be used as a scheduler.
   footprint silently returns 0 if params are invalid (thus convenient
   to validate params).

   depth controls the reorder buffer transaction count (~1 million
   recommended for live replay, ~10k recommended for async replay).
   block_cnt_max is the maximum number of blocks that will be tracked by
   the scheduler. */

ulong
fd_sched_align( void );

ulong
fd_sched_footprint( ulong depth,           /* in [FD_SCHED_MIN_DEPTH,FD_SCHED_MAX_DEPTH] */
                    ulong block_cnt_max ); /* >= 1 */

/* fd_sched_new creates a sched object backed by the given memory region
   (conforming to align() and footprint()).  Returns NULL if any
   parameter is invalid. */

void *
fd_sched_new( void *     mem,
              fd_rng_t * rng,
              ulong      depth,
              ulong      block_cnt_max,
              ulong      exec_cnt,
              int        is_alpenglow );

fd_sched_t *
fd_sched_join( void * mem );

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

/* Returns the number of worst-case FEC sets sched can ingest. This is a
   cheap and conservative check. */
ulong
fd_sched_can_ingest_cnt( fd_sched_t * sched );

/* Returns 1 if sched is drained, 0 otherwise.  A drained scheduler will
   not return more work.  Otherwise, next_ready will return more work,
   so long as there are exec tiles available. */
int
fd_sched_is_drained( fd_sched_t * sched );

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
   asynchronously outside the critical path of transaction execution, as
   long as every transaction in a block passes sigverify before we
   commit the block.  The scheduler prioritizes actual execution of
   transactions over sigverify, and in general sigverify tasks are only
   returned when no real transaction can be dispatched.  In other words,
   the scheduler tries to exploit idle cycles in the exec tiles during
   times of low parallelism critical path progression.

   This function may also return a PoH hashing task.  These tasks are
   lower priority than transaction execution, but higher priority than
   sigverify.  This is because sigverify tasks are generally bite-sized,
   whereas PoH hashing can be longer, so we would like to get started on
   hashing sooner rather than later. */
ulong
fd_sched_task_next_ready( fd_sched_t * sched, fd_sched_task_t * out );

/* Mark a task as complete.  For transaction execution, this means that
   the effects of the execution are now visible on any core that could
   execute a subsequent transaction.  Returns FD_SCHED_DEAD_REASON_NONE
   (0) on success.  If, given the result of the task, the block turns
   out to be bad, returns the nonzero FD_SCHED_DEAD_REASON_* it was
   ruled bad for.  Only PoH tasks can rule a block bad, and not only
   for a PoH hash mismatch: eager tick verification also runs on this
   path.

   If a block has been abandoned or marked dead for any reason, it'll be
   pruned the moment in-flight task count hits 0 due to the last task
   completing.  Then, in the immediate ensuing stem run loop,
   sched_pruned_next() will return the index for the corresponding bank
   so the refcnt can be decremented for sched.

   The transaction at the given index may be freed upon return from this
   function.  Nonetheless, as long as there is no intervening FEC
   ingestion, it would still be safe to query the transaction using
   get_txn(). */
int
fd_sched_task_done( fd_sched_t * sched, ulong task_type, ulong txn_idx, ulong exec_idx, void * data );

/* Abandon a block.  This means that we are no longer interested in
   executing the block.  This also implies that any block which chains
   off of the provided block shall be abandoned.  This is mainly used
   when a block is aborted because we decided that it would be a
   dead/invalid block, and so there's no point in spending resources
   executing it.  The scheduler will no longer return transactions from
   abandoned blocks for execution.  This should only be invoked on an
   actively replayed block, and should only be invoked once on it.

   For the purposes of bank lifetime management, sched is a subsidiary
   of banks.  So while sched sets things in motion for a bad block to be
   eagerly pruned, banks/replay is the sole initiator of actual pruning.
   The way this works is that an abandoned block will have its refcnt
   queued for release by sched as soon as, and only if, the block has no
   more in-flight tasks associated with it.  No sooner, no later.  In
   the immediate ensuing stem run loop, sched_pruned_next() will return
   the index for the corresponding bank so the refcnt can be decremented
   for sched.  After that point, banks will eventually instruct sched to
   prune the block, when all other components release their refcnts on
   said bank.  Then the bank_idx may be recycled for another block.

   Pass FD_SCHED_ABANDON_INVALID if the block is ruled invalid for any
   reason, or FD_SCHED_ABANDON_DISCARDED if we are merely giving up on
   it without fault, e.g. eviction under resource pressure.  Descendants
   inherit the flavor: they record DEAD_ANCESTOR, and are marked
   discarded iff the lineage was discarded, provided they have no dead
   reason of their own.  A block that is already going down keeps the
   flavor it went down with, so a later abandon cannot re-label it. */
void
fd_sched_block_abandon( fd_sched_t * sched, ulong bank_idx, int cause );

/* fd_sched_get_dead_reason returns the scheduler's reason (one of
   FD_SCHED_DEAD_REASON_*) for why the block at bank_idx went down.
   Returns FD_SCHED_DEAD_REASON_NONE if the block itself was merely
   discarded (root advance, eviction) or if no block is currently
   tracked at bank_idx.  Descendants of a discarded lineage carry
   DEAD_ANCESTOR like any other lineage death;
   fd_sched_block_is_discarded disambiguates discarded from
   ruled-invalid.  The recorded reason is the first one; later failures
   on an already-dead block (e.g. an in-flight PoH task draining after
   the block was abandoned) do not overwrite it. */
int
fd_sched_get_dead_reason( fd_sched_t * sched, ulong bank_idx );

/* fd_sched_block_is_discarded returns 1 if the block went down with a
   discarded (not invalid) lineage, 0 otherwise (including when no
   block is tracked at bank_idx).  Never set on a block that has a dead
   reason of its own, so it does not mask the scheduler's own verdict. */
int
fd_sched_block_is_discarded( fd_sched_t * sched, ulong bank_idx );

/* Prune the given block including descendants of it. */
void
fd_sched_cancel( fd_sched_t * sched, ulong bank_idx );

/* Add a block as immediately done to the scheduler.  This is useful for
   installing the snapshot slot, or for informing the scheduler of a
   packed leader block.  Parent block should be ULONG_MAX for the
   snapshot slot, and otherwise a block that hasn't been pruned. */
void
fd_sched_block_add_done( fd_sched_t * sched, ulong bank_idx, ulong parent_bank_idx, ulong slot );

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

/* Returns the index of a bank whose refcnt should be decremented for
   sched.  This function should be called in a loop to drain all
   outstanding refcnt decrements before any other sched API is called in
   a stem run loop.  Returns ULONG_MAX when there are no more
   outstanding references from sched and the loop should break. */
ulong
fd_sched_pruned_block_next( fd_sched_t * sched );

void
fd_sched_set_poh_params( fd_sched_t * sched, ulong bank_idx, ulong tick_height, ulong max_tick_height, ulong hashes_per_tick, fd_hash_t const * start_poh );

/* fd_sched_block_verify_ticks sets the tick window and verifies
   ticks on bank_idx (shred fuzz harness, no exec).  Returns
   FD_SCHED_DEAD_REASON_NONE (0) if valid, else the
   FD_SCHED_DEAD_REASON_* the ticks are invalid for.  Does not rule the
   block invalid; the caller decides what to do with the verdict. */
int
fd_sched_block_verify_ticks( fd_sched_t * sched,
                             ulong        bank_idx,
                             ulong        tick_height,
                             ulong        max_tick_height,
                             ulong        hashes_per_tick );

/* fd_sched_set_bypass_poh_verify configures whether the per-microblock
   PoH end_hash comparison in maybe_mixin is bypassed.  This is intended
   for test and fuzz harnesses: the expected end_hash is carried in the
   shred payload, so comparing it would reject any mutated input before
   the deeper parse/tick logic is exercised.  Production call sites
   should leave this disabled. */
void
fd_sched_set_bypass_poh_verify( fd_sched_t * sched, int bypass_poh_verify );

/* fd_sched_set_bypass_alut_resolution bypasses ALUT resolution during
   parsing (test/fuzz: no accounts DB).  ALUT txns become serializing.
   Production call sites should leave this disabled. */
void
fd_sched_set_bypass_alut_resolution( fd_sched_t * sched, int bypass_alut_resolution );

fd_txn_p_t *
fd_sched_get_txn( fd_sched_t * sched, ulong txn_idx );

fd_sched_txn_info_t *
fd_sched_get_txn_info( fd_sched_t * sched, ulong txn_idx );

fd_hash_t *
fd_sched_get_poh( fd_sched_t * sched, ulong bank_idx );

uint
fd_sched_get_shred_cnt( fd_sched_t * sched, ulong bank_idx );

/* fd_sched_get_footer_bank_hash returns the bank hash announced by
   bank_idx's Alpenglow block footer, or NULL if no footer marker has
   been parsed for the block (including when the footer simply hasn't
   arrived yet; only meaningful once the block is done).  The hash stays
   valid until the block is pruned. */
fd_hash_t const *
fd_sched_get_footer_bank_hash( fd_sched_t * sched, ulong bank_idx );

/* fd_sched_get_final_cert returns the raw finalization cert bytes
   parsed out of bank_idx's Alpenglow block footer, writing the byte
   count to sz.  Returns NULL (*sz==0) if the block footer carried none
   (or has not been parsed yet; only meaningful once the block is done).
   The bytes are decodable with ag_cert_block_final_de and stay valid
   until the block is pruned. */
uchar const *
fd_sched_get_final_cert( fd_sched_t * sched, ulong bank_idx, ulong * sz );

void
fd_sched_metrics_write( fd_sched_t * sched );

/* Serialize the current state as a cstr to the returned buffer.  Caller
   may read from the buffer until the next invocation of any fd_sched
   function. */
char *
fd_sched_get_state_cstr( fd_sched_t * sched );

void *
fd_sched_leave( fd_sched_t * sched );

void *
fd_sched_delete( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_sched_h */
