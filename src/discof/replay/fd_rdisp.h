#ifndef HEADER_fd_src_discof_replay_fd_rdisp_h
#define HEADER_fd_src_discof_replay_fd_rdisp_h

#include "../../disco/fd_disco_base.h"

/* fd_rdisp defines methods for building a DAG (directed acyclic graph)
   of transactions, and executing them in the appropriate order with the
   maximum amount of parallelism.

   Transactions must appear to execute in the order in which they occur
   in the block (the "serial fiction").  However, when two transactions
   are independent, they can actually be scheduled in either order, or
   in parallel.  Two transactions are independent unless one writes to
   an account that the other reads or writes.  If two transactions are
   not independent, the one that comes earlier in the block is a
   predecessor transaction of the one that comes later in the block.  In
   order to ensure correct execution, a transaction cannot be executed
   until all its predecessor transactions have completed.  In this file,
   a transaction completing means that the results of its account writes
   will be visible to a subsequent transaction executing on any core.

   Shockingly, this dispatcher does not need to keep a copy of
   transactions (more on this later), which means it operates almost
   entirely on transaction indices.  An index is a positive integer
   (uint) up to some maximum.  The 0 index is a sentinel, and doesn't
   correspond to a real transaction.  It's up to the caller to maintain
   the mapping between each transaction index and the transaction itself.

   A transaction index is in one of the following states:
     * FREE, which means it doesn't correspond to a transaction.
     * PENDING, which means it corresponds to a transaction that can't
       be scheduled yet because it must come after transactions that
       have not completed execution yet.
     * READY, which means all predecessor transactions have completed
       execution, but this transaction index has not been returned by
       get_next_ready yet.
     * ZOMBIE, which means the transaction completed execution, and
       successor transactions may be transitioned to the READY state,
       but the transaction index should not be recycled yet, because
       there are outstanding non-execution tasks associated with this
       transaction.
     * DISPATCHED, which means this transaction index was returned by
       get_next_ready but has not been completed yet.


                        --------------> PENDING
                add_txn |                  |
         FREE  ---------|                  |
          ^             |                  V    get_next_ready
          |             -------------->  READY ----------------
          |                                                   |
          |                                                   |
          |               complete_txn(reclaim)               V
          |<-------------------------------------------- DISPATCHED
          |                                                   |
          |                                                   | complete_txn(noreclaim)
          |               complete_txn(reclaim)               V
          |<---------------------------------------------- ZOMBIE


   Additionally, fd_rdisp is block-aware, and even somewhat fork-aware.
   Prior to inserting a transaction, a block must be added.  Then, when
   a transaction is inserted, the caller must specify the block it is
   part of.

   At all times, each block is either STAGED or UNSTAGED.  Blocks that
   are STAGED benefit from the full parallelization-maximizing dispatch,
   but at most four linear chains of blocks can be STAGED at any time.
   Assuming the limit of four is still satisfied, when a block is added,
   it may be added as STAGED.  Otherwise, if it's added as UNSTAGED, it
   may be promoted to STAGED later, though this is worse for performance
   than adding it as STAGED initially.  Blocks may be demoted from
   STAGED to UNSTAGED only if the linear chain doesn't contain any
   PENDING, READY, or DISPATCHED transactions.

   Prior to properly introducing staging lanes, we need to introduce two
   more concepts.  A block can be insert-ready, schedule-ready, neither,
   or both.  A block must be insert-ready to call add_txn on
   it; a block must be schedule-ready to call get_next_ready on it.
   Various functions either require or modify these properties of a
   block.  These properties are necessary but not sufficient for the
   respective functions to succeed; for example, a block may be
   schedule-ready but empty, in which case, scheduling will still not
   succeed.  An UNSTAGED block is always both insert-ready and
   schedule-ready.

   A staging lane can contain a single block or a sequence of blocks.
   When a staging lane contains more than one block, some restrictions
   apply, namely, only the first block in the sequence is
   schedule-ready, and only the last block in the sequence is
   insert-ready, where first and last are determined by the order in
   which the block is staged.  Although this restriction makes the
   interface a bit more complicated, it's driven by performance
   requirements and common use cases.  Basically, there's no use for
   being able to replay a block before we've replayed its parent block.

   Basically, rdisp is designed to handle three situations well:
    * The normal case, where replay is pretty much caught up, and there
      are only one or two forks, containing only one or two un-replayed
      blocks each.
    * The startup case, where repair is far ahead of replay, but there's
      only a single fork, or very few forks
    * The DoS case, where there are many forks, perhaps duplicate
      blocks, and we don't know which to prioritize yet, but we will
      execute some, and prune the rest later.  This includes the case
      where we stop receiving transactions from some of the forks but
      don't know that the block has ended.

   In the normal case, there are few enough unreplayed blocks that it
   doesn't really matter how the staging lanes are used.  For the
   startup case, the long linear chains of blocks can all be STAGED using
   the same lane with no performance degradation.  In the DoS case, most
   of the forks will be UNSTAGED, and using some combination of
   replaying, cancelling, and demoting blocks, staging lanes can be freed
   up so that the canonical chain can emerge.

   Consider the following example of storing a fork tree in staging
   lanes:
    - Slot 10's parent is not specified
    - Slot 11's parent is slot 10
    - Slot 13's parent is slot 11
    - Slot 14's parent is also slot 11

   Since the caller chooses the staging lane, the caller may choose
   between
             Lane 0: 10 --> 11 --> 13
             Lane 1: 14
   and
             Lane 0: 10 --> 11 --> 14
             Lane 1: 13.
   or any of the various combinations that consume more staging lanes.
   Note that the concept of staging lanes is a performance optimization,
   not a safety feature.  With the first arrangment, the caller cannot
   call get_next_ready on slot 13 in between slots 10 and 11, but
   there's no issue with calling it on slot 14 then, which would
   obiously result in an incorrect replay.  It's ultimately the callers
   responsibility to ensure correct replay. */

#define FD_RDISP_MAX_DEPTH       0x7FFFFFUL /* 23 bit numbers, approx 8M */
#define FD_RDISP_MAX_BLOCK_DEPTH 0xFFFFUL   /* 16 bits */
#define FD_RDISP_UNSTAGED        ULONG_MAX

struct fd_rdisp;
typedef struct fd_rdisp fd_rdisp_t;

/* fd_rdisp is set up so that the tag of a block can be adjusted to
   account for differences in handling duplicate blocks/equivocation. */
#define FD_RDISP_BLOCK_TAG_T ulong

FD_PROTOTYPES_BEGIN

/* fd_rdisp_{align,footprint} return the required alignment and
   footprint in bytes for a region of memory to be used as a dispatcher.
   depth is the maximum number of transaction indices that can be
   tracked at a time.  Depth must be at least 2 and cannot exceed
   FD_RDISP_MAX_DEPTH.  block_depth is the maximum number of blocks that
   this dispatcher can track.  block_depth must be at least 4 and cannot
   exceed FD_RDISP_MAX_BLOCK_DEPTH. */
ulong fd_rdisp_align    ( void        );
ulong fd_rdisp_footprint( ulong depth, ulong block_depth );


/* fd_rdisp_new formats a region of memory that satisfies the required
   footprint and alignment for use as a dispatcher.  depth and
   block_depth are as explained in fd_rdisp_footprint.  mem is a pointer
   to the first byte of a region of memory with the required alignment
   and footprint.  seed is an arbitrary ulong that is used to determine
   a seed of various internal hash tables.  On return, the caller will
   not be joined.

   fd_rdisp_join joins the caller to the dispatcher, enabling it for
   use. */
void *
fd_rdisp_new( void * mem,
              ulong  depth,
              ulong  block_depth,
              ulong  seed );

fd_rdisp_t *
fd_rdisp_join( void * mem );

/* fd_rdisp_suggest_staging_lane recommends a staging lane to use for a
   potential new block that has a parent block with block tag
   parent_block.  duplicate is non-zero if this is not the first block
   we've seen for its slot.

   This function uses the following logic:
   1. If it's a duplicate, suggest FD_RDISP_UNSTAGED
   2. If parent is the last block in any existing staging lane, suggest
      that lane
   3. If there is at least one free lane, suggest a free lane
   4. Else, suggest FD_RDISP_UNSTAGED
   Note that this function does not add the block (use add_block) for
   that, and does not modify the state of the dispatcher.  The caller
   should feel free to use or not use the suggested staging lane. */
ulong
fd_rdisp_suggest_staging_lane( fd_rdisp_t const *   disp,
                               FD_RDISP_BLOCK_TAG_T parent_block,
                               int                  duplicate );


/* fd_rdisp_add_block allocates a new block with the tag new_block from
   disp's internal pool.  new_block must not be the invalid block tag
   value, and it must be distinct from all other values passed as
   new_block in all prior calls to fd_rdisp_add_block.

   staging_lane must be either [0,4) or FD_RDISP_UNSTAGED.  If
   staging_lane is FD_RDISP_UNSTAGED, the block will be UNSTAGED (see
   the long comment at the beginning of this header), schedule-ready,
   and insert-ready.
   If staging_lane is in [0, 4), the block will be STAGED, and it will
   be insert-ready.  If the specified staging lane contained any blocks
   at the time of the call, the last one will no longer be insert-ready,
   making this the only insert-ready block in the lane.  If the
   specified staging lane did not contain any blocks at the time of the
   call, then the newly added block will also be schedule-ready.

   On successful return, the tag new_block will be usable for other
   functions that take a block tag block.

   Returns 0 on success, and -1 on error, which can only happen if out
   of resources (the number of unremoved blocks is greater than or equal
   to the block_depth) or if new_block was already known. */
int
fd_rdisp_add_block( fd_rdisp_t *          disp,
                    FD_RDISP_BLOCK_TAG_T  new_block,
                    ulong                 staging_lane );

/* fd_rdisp_remove_block deallocates a previously-allocated block with
   the block tag block, freeing all resources associated with it.  block
   must be empty (not contain any transactions in the PENDING, READY,
   DISPATCHED, or ZOMBIE states), and schedule-ready.
   Returns 0 on success, and -1 if block is not known.  After a
   successful return, the block tag block will not be known. */
int
fd_rdisp_remove_block( fd_rdisp_t *          disp,
                       FD_RDISP_BLOCK_TAG_T  block );


/* fd_rdisp_abandon_block is similar to remove_block, but works when the
   block contains transactions.  It immediately transitions all
   transactions part of the block to FREE, and then removes the block as
   in fd_rdisp_remove_block.  Note that if a transaction is DISPATCHED
   at the time of the call complete_txn should NOT be called on that
   transaction index when it completes.  The specified block must be
   schedule-ready.

   In V1 of the dispatcher, this only works if there are no DISPATCHED
   transactions.

   Returns 0 on success, and -1 if block is not known.  After a
   successful return, the block tag block will not be known. */
int
fd_rdisp_abandon_block( fd_rdisp_t          * disp,
                        FD_RDISP_BLOCK_TAG_T  block );


/* fd_rdisp_{promote,demote}_block modify whether a block is STAGED or
   UNSTAGED.  Specifically, promote_block promotes the specified block
   from UNSTAGED to STAGED, using the specified staging_lane.
   demote_block demotes the specified block from STAGED to UNSTAGED.
   disp must be a valid local join.  If the block tag block is not
   known, or is not in the requisite state (UNSTAGED from promote,
   STAGED for demote), returns -1.

   When promote_block promotes the specified block, it is placed at the
   end of the linear chain in the specified staging_lane.  That means
   the operation is as if abandon_block were called on the specified
   block, then add_block with the specified staging_lane, and then all
   transactions in the PENDING and READY states in this block were
   re-added in the same order they were originally added.  It is
   undefined behavior if the specified block contains any transactions
   in the DISPATCHED stage.  As in add_block, upon successful return,
   the specified block will be insert-ready, but will only be
   schedule-ready if the specified staging lane was empty at the time of
   the call.

   demote_block has the additional requirement that the specified block
   must be schedule-ready and empty, that is, not containing any
   transactions in the PENDING, READY, or DISPATCHED states. */

int
fd_rdisp_promote_block( fd_rdisp_t *          disp,
                        FD_RDISP_BLOCK_TAG_T  block,
                        ulong                 staging_lane );
int
fd_rdisp_demote_block( fd_rdisp_t *          disp,
                       FD_RDISP_BLOCK_TAG_T  block );


/* fd_rdisp_rekey_block renames the block with tag old_tag so that it
   has tag new_tag instead.  The block retains all transactions, it's
   STAGED/UNSTAGED state, etc.  On successful return, tag old_tag will
   know longer be a known tag, and new_tag must be used in any future
   calls to refer to the block previously known as old_tag.

   disp must be a valid local join.  new_tag must not be a known tag,
   but old_tag must be a known tag.

   Return 0 on success and -1 on error.  The only error cases are if
   new_tag is already a known tag or old_tag is not a known tag. */
int
fd_rdisp_rekey_block( fd_rdisp_t *           disp,
                      FD_RDISP_BLOCK_TAG_T   new_tag,
                      FD_RDISP_BLOCK_TAG_T   old_tag );

/* fd_rdisp_add_txn adds a transaction to the block with tag
   insert_block in serial order.  That means that this dispatcher will
   ensure this transaction appears to execute after each transaction
   added to this block in a prior call.

   insert_block must be a known block that is insert-ready.  txn,
   payload, and alts describe the transaction to be added.  txn must be
   the result of parsing payload, and alts contains the expansion and
   selection of the address lookup tables mentioned in the transaction
   (i.e. all the writable accounts followed by all the read-only
   accounts).  alts may be NULL, even if the transaction specifies that
   it loads accounts from an address lookup table; in this case,
   addresses from ALTs are ignored.

   Shockingly, this dispatcher does not retain any read interest (much
   less write interest) in the transaction (txn, payload, or alts).  On
   success, it returns a transaction index that was previously in the
   FREE state.  This API is designed to facilitate a model of use where
   the replay tile copies the incoming transaction to a region of
   private memory, adds it to this dispatcher, and then copies it (using
   non-temporal stores) to the output dcache at a location determined by
   the returned index.  Although there are two memcpys in this approach,
   it should result in fewer cache misses.

   If serializing is non-zero, this transaction will be a serialization
   point: all transactions added prior to this one must complete before
   this transaction can be scheduled, and this transaction must complete
   before any subsequently added transactions can be scheduled.  This is
   not good for performance, but is useful for the rare case when
   repair/turbine is several slots ahead of replay, and a transaction
   loads some accounts from an address lookup table, but we haven't
   executed the transaction to populate that part of the address lookup
   table yet.  This is the primary use for alts==NULL.

   Returns 0 and does not add the transaction on failure.  Fails if
   there were no free transaction indices, if the block with tag
   insert_block did not exist, or if it was not schedule-ready.

   At the time this function returns, the returned transaction index
   will be in the PENDING or READY state, depending on whether it
   conflicts with something previously inserted. */
ulong
fd_rdisp_add_txn( fd_rdisp_t          *  disp,
                  FD_RDISP_BLOCK_TAG_T   insert_block,
                  fd_txn_t const       * txn,
                  uchar const          * payload,
                  fd_acct_addr_t const * alts,
                  int                    serializing );

/* fd_rdisp_get_next_ready returns the transaction index of a READY
   transaction that was inserted with block tag schedule_block if one
   exists, and 0 otherwise.  The block with the tag schedule_block must
   be schedule-ready.

   If there are multiple READY transactions, which exact one is returned
   is arbitrary.  That said, this function does make some effort to pick
   one that (upon completion) will unlock more parallelism.  disp must
   be a valid local join.  At the time this function returns, the
   returned transaction index (if nonzero) will transition to the
   DISPATCHED state. */
ulong
fd_rdisp_get_next_ready( fd_rdisp_t           * disp,
                         FD_RDISP_BLOCK_TAG_T   schedule_block );

/* fd_rdisp_complete_txn notifies the dispatcher that the specified
   transaction (which must have been in the DISPATCHED state) has
   completed.  Logs warning and returns on error (invalid txn_idx, not
   in DISPATCHED state).  This function may cause other transactions to
   transition from PENDING to READY.

   At the time this function returns, the specified transaction index
   will be in the FREE state, if reclaim!=0.  Otherwise, if reclaim==0,
   the specified transaction index will be in the ZOMBIE state.  A
   ZOMBIE transaction has the exact same effect as a FREE transaction on
   causing other transactions to transition from PENDING to READY.
   However, the dispatcher will not reclaim the specified transaction
   index, until a future invocation of fd_rdisp_complete_txn where
   reclaim!=0.  This is useful when there is non-execution work to be
   done asynchronously for the transaction, but the caller would like to
   unblock the execution of transactions that depend on this one. */
void
fd_rdisp_complete_txn( fd_rdisp_t * disp,
                       ulong        txn_idx,
                       int          reclaim );


typedef struct {
  FD_RDISP_BLOCK_TAG_T  schedule_ready_block;
  FD_RDISP_BLOCK_TAG_T  insert_ready_block;
} fd_rdisp_staging_lane_info_t;

/* fd_rdisp_staging_lane_info copies the current staging lane info to
   out.  Returns a 4-bit bitset, where bit i being set means that
   staging lane i is occupied.  If staging lane i is occupied, then
   out_sched[i] is populated. */
ulong
fd_rdisp_staging_lane_info( fd_rdisp_t           const * disp,
                            fd_rdisp_staging_lane_info_t out_sched[ static 4 ] );

/* fd_rdisp_verify does some light verification and internal consistency
   checks of some internal data structures.  Aborts with an error
   message if anything fails verification.  disp is a pointer to a valid
   local join, and scratch is a pointer to a region of scratch memory
   with at least depth+1 elements that will be clobbered (its contents
   at the time of the function call are ignored). */
void
fd_rdisp_verify( fd_rdisp_t const * disp,
                 uint             * scratch );

void *
fd_rdisp_leave( fd_rdisp_t * disp );

void *
fd_rdisp_delete( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_rdisp_h */
