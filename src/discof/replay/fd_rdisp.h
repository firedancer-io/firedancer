#ifndef HEADER_fd_src_discof_replay_fd_rdisp_h
#define HEADER_fd_src_discof_replay_fd_rdisp_h

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
     * FREE, which means it doesn't correspond to a transaction
     * PENDING, which means it corresponds to a transaction that can't
       be scheduled yet because it must come after transactions that
       have not completed yet.
     * READY, which means all predecessor transactions have completed,
       but this transaction index has not been returned by
       get_next_ready yet
     * DISPATCHED, which means this transaction index was returned by
       get_next_ready but has not been completed yet.


                        --------------> PENDING
                add_txn |                  |
         FREE  ---------|                  |
          ^             |                  V    get_next_ready
          |             -------------->  READY ----------------
          |                                                   |
          |                                                   |
          |                                                   |
          |                  complete_txn                     V
          ---------------------------------------------- DISPATCHED


   Additionally, fd_rdisp is slot-aware, and even somewhat fork-aware.
   Prior to inserting a transaction, an insert_slot must be added,
   optionally chaining it to a parent. Then, when a transaction is
   inserted, the caller must specify the insert_slot it is part of.

   Using the parent information, fd_rdisp stores these slots in a
   "linear forest" representation, that is, a collection of path graphs.
   In each path in the path graph, transactions can only be added to the
   last slot and scheduled from the first slot.  Each path graph may
   occupy a resource that fd_rdisp calls a concurrency lane.

   Consider the following example:
    - Slot 10's parent is not specified
    - Slot 11's parent is slot 10
    - Slot 13's parent is slot 11
    - Slot 14's parent is also slot 11

   That produces the following linear forest representation.

                     10 --> 11 --> 13
                     14

   Note that the information about slot 14's parent being slot 11 is
   lost in this representation.

   Concurrency lane occupation is lazy, and only happens when actual
   transactions are inserted for the slots.  If all four slots mentioned
   have transactions in them, then this occupies two concurrency lanes.
   In this state, calls to schedule transactions from slot 10 can be
   intermixed with calls to schedule transactions from slot 14
   aribitrarily.  In this state, calls to schedule from slot 11 or 13
   are not allowed.

   Slots stop occupying a concurrency lane as soon as there are no
   transactions for that insert_slot in any of the PENDING, READY, or
   DISPATCHED states.  The caller doesn't need to do anything special to
   free it.  This means the exact concurrency lane a slot occupies can
   change, but this is not exposed at all to the caller.

   If a transaction is added but all the concurrency lanes are full, the
   transaction is added to a deferred queue. */

#define FD_RDISP_MAX_DEPTH      0x7FFFFFUL /* 23 bit numbers, approx 8M */
#define FD_RDISP_MAX_SLOT_DEPTH 0x7FFFFFUL /* Also 23 bits, but for a different reason */

FD_PROTOTYPES_BEGIN

/* fd_rdisp_{align,footprint} return the required alignment and
   footprint in bytes for a region of memory to be used as a dispatcher.
   depth is the maximum number of transaction indices that can be
   tracked at a time.  Depth must be at least 2 and cannot exceed
   FD_RDISP_MAX_DEPTH.  slot_depth is the maximum number of slots that
   this dispatcher can track.  slot_depth must be at least 4 and cannot
   exceed FD_RDISP_MAX_SLOT_DEPTH. */
ulong fd_rdisp_align    ( void        );
ulong fd_rdisp_footprint( ulong depth, ulong slot_depth );


/* TODO: document */
void *
fd_rdisp_new( void * mem,
              ulong  depth,
              ulong  slot_depth );

fd_rdisp_t *
fd_rdisp_join( void * mem );


/* fd_rdisp_add_slot allocates a new slot with the tag new_slot from
   disp's internal pool.  new_slot must not be the invalid slot value,
   and it must be distinct from all other values passed as new_slot in
   all prior calls to fd_rdisp_add_slot.  parent_slot may be the invalid
   slot value (e.g. for the first slot after a snapshot), or it may be
   the tag of a previously added slot that has been marked as DONE.  If
   parent_slot is a recognized slot tag, then transactions inserted with
   a slot tag of new_slot cannot be scheduled until all transactions
   inserted with a slot tag of parent_slot have completed.

   On successful return, the tag new_slot will be useful for other
   functions that take a slot tag.  This slot will not be marked as
   DONE.

   Returns 0 on okay, and a negative value on error:
   -1 means that it's out of resources.
   -2 means that new_slot tag was already a known slot tag. */
int
fd_rdisp_add_slot( fd_rdisp_t          * disp,
                   FD_RDISP_SLOT_TAG_T   new_slot,
                   FD_RDISP_SLOT_TAG_T   parent_slot );

/* fd_rdisp_mark_slot_done marks a slot (identified by tag slot) as
   DONE.  A slot that is marked as DONE is elegible to be the parent of
   a subsequent slot.  A slot that is marked as DONE may NOT have more
   transactions added.  Only slots marked as DONE are elegible for
   automatic cleanup.  Importantly, slots do not need to be marked as
   DONE for transacactions to be scheduled from them.
   disp must be a valid local join of a replay dispatcher.  slot must be
   the tag of a previously added slot.  */
void
fd_rdisp_mark_slot_done( fd_rdisp_t          * disp,
                         FD_RDISP_SLOT_TAG_T   slot );


/* fd_rdisp_cancel_slot marks the slot with tag slot DONE (if not
   already marked as DONE), and then immediately transitions all pending
   transactions with slot tag slot to FREE.  This triggers the automatic
   cleanup of the slot.  If the specified slot is not known, this is a
   no-op. */
void
fd_rdisp_cancel_slot( fd_rdisp_t          * disp,
                      FD_RDISP_SLOT_TAG_T   slot );

/* You may notice there's no fd_rdisp_release_slot or similar.  Slots
   are automatically released when they are marked as DONE and none of
   the transactions added with the associated tag are in the PENDING,
   READY, or DISPATCHED states. */



/* fd_rdisp_add_txn adds a transaction to the slot with tag insert_slot
   in serial order.  That means that this dispatcher will ensure this
   transaction appears to execute after each transaction added to this
   slot in a prior call.

   Shockingly, this dispatcher does not retain any read interest (much
   less write interest) in the transaction.  On success, it returns a
   transaction index that was previously in the FREE state.  This API is
   designed to facilitate a model of use where the replay tile copies
   the incoming transaction to a region of private memory, adds it to
   this dispatcher, and then copies it (using non-temporal stores) to
   the output dcache at a location determined by the returned index.
   Although there are two memcpys in this approach, it tends to result
   in fewer cache misses.

   Returns 0 and does not add the transaction on failure.  Fails if
   there were no free transaction indices, if the slot with tag
   insert_slot did not exist, or if it was marked as DONE.

   If serializing is non-zero, this transaction will be a serialization
   point: all transactions added prior to this one must complete before
   this transaction can be scheduled, and this transaction must complete
   before any subsequently added transactions can be scheduled.  This is
   not good for performance, but is useful for the rare case when
   repair/turbine is several slots ahead of replay, and a transaction
   loads some accounts from an address lookup table, but we haven't
   executed the transaction to populate that part of the address lookup
   table yet.

   At the time this function returns, the returned transaction index
   will be in the PENDING or READY state. */
ulong
fd_rdisp_add_txn( fd_rdisp_t          *  disp,
                  FD_RDISP_SLOT_TAG_T    insert_slot,
                  fd_txn_t const       * txn,
                  uchar const          * payload,
                  fd_acct_addr_t const * alts,
                  int                    serializing );

/* fd_rdisp_get_next_ready returns the transaction index of a READY
   transaction that was inserted with slot tag schedule_slot if one
   exists, and 0 otherwise.  If there are multiple READY transactions,
   which exact one is returned is arbitrary.  That said, this function
   does make some effort to pick one that (upon completion) will unlock
   more parallelism.  disp must be a valid local join.  At the time this
   function returns, the returned transaction index (if nonzero) will
   transition to the DISPATCHED state.  If schedule_slot is not the head
   of a concurrency lane, this returns 0. */
ulong
fd_rdisp_get_next_ready( fd_rdisp_t          * disp,
                         FD_RDISP_SLOT_TAG_T   schedule_slot );

/* fd_rdisp_complete_txn notifies the dispatcher that the
   specified transaction (which must have been in the DISPATCHED state)
   has completed.  Logs warning and returns on error (invalid txn_idx,
   not in DISPATCHED state).  At the time this function returns, the
   specified transaction index will be in the FREE state.  This function
   may cause other transaction to transition from PENDING to READY. */
void
fd_rdisp_complete_txn( fd_rdisp_t * disp,
                       ulong        txn_idx );


/* fd_rdisp_concurrecny_lane_info copies the current insert and schedule
   slots for the first out_cnt concurrency lane.  Returns how many
   concurrency lanes' data was populated. */
ulong
fd_rdisp_concurrency_lane_info( fd_rdisp_t    const * disp,
                                FD_RDISP_SLOT_TAG_T * out_insert,
                                FD_RDISP_SLOT_TAG_T * out_sched,
                                ulong                 out_cnt );


void *
fd_rdisp_leave( fd_rdisp_t * disp );

void *
fd_rdisp_delete( void * mem );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_rdisp_h */
