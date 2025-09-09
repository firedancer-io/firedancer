#ifndef HEADER_fd_src_discof_replay_fd_sched_h
#define HEADER_fd_src_discof_replay_fd_sched_h

#include "fd_rdisp.h"
#include "../../disco/store/fd_store.h" /* for fd_store_fec_t */
#include "../../disco/pack/fd_microblock.h" /* for fd_txn_p_t */

#include "../../funk/fd_funk_base.h" /* for ALUTs */
#include "../../util/spad/fd_spad.h" /* for ALUTs */

/* fd_sched implements all the smarts and mechanical chore around
   scheduling transactions for replay execution.  The general order in
   which calls happen under the normal case is:

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

typedef fd_eslot_t fd_sched_block_id_t;

struct fd_sched_alut_ctx {
  fd_funk_t *     funk;
  fd_funk_txn_t * funk_txn;
  fd_spad_t *     runtime_spad;
};
typedef struct fd_sched_alut_ctx fd_sched_alut_ctx_t;

struct fd_sched_fec {
  fd_sched_block_id_t block_id;
  fd_sched_block_id_t parent_block_id;
  fd_store_fec_t *    fec;
  uint                is_last_in_batch:1; /* set if this is the last FEC set in the batch; relevant because the
                                             parser should ignore trailing bytes at the end of a batch */
  uint                is_last_in_block:1; /* set if this is the last FEC set in the block */

  fd_sched_alut_ctx_t alut_ctx[ 1 ];
};
typedef struct fd_sched_fec fd_sched_fec_t;

struct fd_sched_txn_ready {
  fd_sched_block_id_t block_id;
  fd_sched_block_id_t parent_block_id;
  ulong               txn_id;
  uint                is_last_in_block:1; /* set if this is the last transaction in the block; relevant because
                                             the caller might need to do end-of-block processing */
};
typedef struct fd_sched_txn_ready fd_sched_txn_ready_t;

FD_PROTOTYPES_BEGIN

/* fd_sched_{align,footprint} return the required alignment and
   footprint in bytes for a region of memory to be used as a scheduler.
   */
ulong fd_sched_align    ( void );
ulong fd_sched_footprint( void );

void *
fd_sched_new( void * mem );

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
   caller should generally call fd_sched_fec_can_ingest() first. */
void
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
   function to start the next block. */
ulong
fd_sched_txn_next_ready( fd_sched_t * sched, fd_sched_txn_ready_t * out_txn );

/* Mark a transaction as complete.  This means that the effects of this
   transaction's execution are now visible on any core that could
   execute a subsequent transaction. */
void
fd_sched_txn_done( fd_sched_t * sched, ulong txn_id );

/* Abandon a block.  This means that we are no longer interested in
   executing the block.  This also implies that any block which chains
   off of the provided block shall be abandoned.  This is mainly used
   when a block is aborted because we decided that it would be a
   dead/invalid block, and so there's no point in spending resources
   executing it.  The scheduler will no longer return transactions from
   abandoned blocks for execution.  This should only be invoked on an
   actively replayed block, and should only be invoked once on it. */
void
fd_sched_block_abandon( fd_sched_t * sched, fd_sched_block_id_t * block_id );

/* Returns 1 if the block is done, 0 otherwise.  A block is done if all
   transactions in the block have completed.  Caller may begin
   end-of-block processing when the block is done.  Assumes that the
   block has not been published away. */
int
fd_sched_block_is_done( fd_sched_t * sched, fd_sched_block_id_t * block_id );

/* Add a block as immediately done to the scheduler.  This is useful for
   installing the snapshot slot, or for informing the scheduler of a
   packed leader block.  Parent block should be NULL for the snapshot
   slot, and otherwise a block that hasn't been published away. */
void
fd_sched_block_add_done( fd_sched_t * sched, fd_sched_block_id_t * block_id, fd_sched_block_id_t * parent_block_id );

/* Publish new root, pruning all blocks across forks that do not descend
   from the new root.  Assumes the new root is in the fork tree and
   connected to the current root.  Also assumes that there are no more
   in-flight transactions from the soon-to-be-pruned blocks.  This
   should be called after root_notify() and the caller is responsible
   for figuring out the new root to safely publish to. */
void
fd_sched_root_publish( fd_sched_t * sched, fd_sched_block_id_t * root );

/* Notify the scheduler of a new root.  This has the effect of calling
   abandon() on all minority forks that do not descend from the new
   root.  Shortly after a call to this function, in-flight transactions
   from these abandoned blocks should retire from the execution
   pipeline, and the new root will be safe for publishing. */
void
fd_sched_root_notify( fd_sched_t * sched, fd_sched_block_id_t * root );

fd_txn_p_t *
fd_sched_get_txn( fd_sched_t * sched, ulong txn_id );

fd_hash_t *
fd_sched_get_poh( fd_sched_t * sched, fd_sched_block_id_t * block_id );

void *
fd_sched_leave( fd_sched_t * sched );

void *
fd_sched_delete( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_rsched_h */
