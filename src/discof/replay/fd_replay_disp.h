#ifndef HEADER_fd_src_discof_replay_fd_replay_disp_h
#define HEADER_fd_src_discof_replay_fd_replay_disp_h

/* fd_replay_disp defines methods for building a DAG (directed acyclic
   graph) of transactions, and executing them in the appropriate order
   with the maximum amount of parallelism.

   Transactions must appear to execute in the order in which they occur
   in the block (the "serial fiction").  However, when two transactions
   are independent, they can actually be scheduled in either order, or
   in parallel.  Two transactions are independent unless one writes to
   an account that the other reads or writes.  If two transactions are
   not independent, the one that comes earlier in the block is a
   predecessor transaction of the one that comes later in the block.  In
   order to ensure correct execution, a transaction cannot be executed
   until all its precessor transactions have completed.  In this file, a
   transaction completing means that the results of its account writes
   will be visible to a subsequent transaction executing on any core.

   Shockingly, this dispatcher does not need to keep a copy of
   transactions (more on this later), which means it operates almost
   entirely on transaction indices.  An index is a positive integer
   (uint) up to some maximum.  The 0 index is a sentinel, and doesn't
   correspond to a real transaction.  It's up to the caller to maintain
   the mapping between transaction indices and the transaction themself.

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
*/

#define FD_REPLAY_DISP_MAX_DEPTH 0x7FFFFFUL /* 23 bit numbers, approx 8M */

/* fd_replay_disp_{align,footprint} return the required alignment and
   footprint in bytes for a region of memory to be used as a dispatcher.
   depth is the maximum number of transaction indices that can be
   tracked at a time.  Depth must be at least 2 and cannot exceed
   FD_REPLAY_DISP_MAX_DEPTH. */
ulong fd_replay_disp_align    ( void        );
ulong fd_replay_disp_footprint( ulong depth );


/* TODO: document */
void *
fd_replay_disp_new( void * mem,
                    ulong  depth );

fd_replay_disp_t *
fd_replay_disp_join( void * mem );

/* fd_replay_disp_add_txn adds a transaction in serial order.  That
   means that this dispatcher will ensure this transaction appears to
   execute after each transaction added in a prior call.

   Shockingly, this dispatcher does not retain any read interest (much
   less write interest) in the transaction.  On success, it returns a
   transaction index that was previously in the FREE state.  This API is
   designed to facilitate a model of use where the replay tile copies
   the incoming transaction to a region of private memory, adds it to
   this dispatcher, and then copies it (using non-temporal stores) to
   the output dcache at a location determined by the returned index.
   Although there are two memcpys in this approach, it tends to result
   in fewer cache misses.

   TODO: describe params
   Returns 0 and does not add the transaction on failure.  Fails if
   there were no free transaction indices. TODO: any other reasons?

   At the time this function returns, the returned transaction index
   will be in the PENDING or READY state. */
ulong
fd_replay_disp_add_txn( fd_replay_disp_t     * disp,
                        fd_txn_t const       * txn,
                        uchar const          * payload,
                        fd_acct_addr_t const * alts );

/* fd_replay_disp_get_next_ready returns a READY transaction if one
   exists, and 0 otherwise.  disp must be a valid local join.  At the
   time this function returns, the returned transaction index will be in
   the DISPATCHED state. */
ulong
fd_replay_disp_get_next_ready( fd_replay_disp_t * disp );

/* fd_replay_disp_complete_txn notifies the dispatcher that the
   specified transaction (which must have been in the DISPATCHED state)
   has completed.  Logs warning and returns on error (invalid txn_idx,
   not in DISPATCHED state).  At the time this function returns, the
   specified transaction index will be in the FREE state.  This function
   may cause other transaction to transition from PENDING to READY. */
void
fd_replay_disp_complete_txn( fd_replay_disp_t * disp,
                             ulong              txn_idx );

void *
fd_replay_disp_leave( fd_replay_disp_t * disp );

void *
fd_replay_disp_delete( void * mem );

#endif /* HEADER_fd_src_discof_replay_fd_replay_disp_h */
