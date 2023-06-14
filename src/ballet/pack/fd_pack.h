#ifndef HEADER_fd_src_ballet_pack_fd_pack_h
#define HEADER_fd_src_ballet_pack_fd_pack_h

/* fd_pack defines methods that prioritizes Solana transactions,
   selecting a subset (potentially all) and ordering them to attempt to
   maximize the overall profitability of the validator. */

#include "../fd_ballet_base.h"
#include "../txn/fd_txn.h"
#include "fd_est_tbl.h"


#define FD_PACK_ALIGN     (32UL)


/* Is this structure useful in other parts of the codebase? Should this
   go somewhere else? */
struct fd_txn_p {
  uchar payload[FD_TPU_MTU];
  ulong payload_sz;
  ulong meta;
  /* union {
    This would be ideal but doesn't work because of the flexible array member
    uchar _[FD_TXN_MAX_SZ];
    fd_txn_t txn;
  }; */
  /* Acces with TXN macro below */
  uchar _[FD_TXN_MAX_SZ] __attribute__((aligned(alignof(fd_txn_t))));
};
typedef struct fd_txn_p fd_txn_p_t;

#define TXN(txn_p) ((fd_txn_t *)( (txn_p)->_ ))


/* fd_pack_scheduled_txn_t is used as the return value for
   fd_pack_schedule_next.  Normally, returning a struct is a bad idea,
   but since it's 128b, it's returned in registers according to the ABI.
   */
struct fd_pack_scheduled_txn {
  /* txn: A pointer into the pack object's txnmem to the transaction
     that was scheduled.  See the note on fd_pack_schedule_next for the
     lifetime of the pointer. */
  fd_txn_p_t * txn;
  /* bank: The bank chosen to execute this transaction.  In [0,
     bank_cnt). */
  uint         bank;
  /* start: The "time" (measured in CUs from the start of the block)
     when this transaction is estimated to start. */
  uint         start;
};
typedef struct fd_pack_scheduled_txn fd_pack_scheduled_txn_t;


/* Forward declare opaque handle */
struct fd_pack_private;
typedef struct fd_pack_private fd_pack_t;

/* fd_pack's memory is split over two regions, the normal one, and
   txnmem.  This is done to facilitate using a dcache as the txnmem,
   which enables sending the results of scheduling operations to
   consumers without a memcpy.

   fd_pack_{,txnmem}_{align,footprint} return the alignment and
   footprint in bytes required for the respective region of memory.

   bank_cnt is the number of banks this tile will schedule transactions
   for.

   The pack structure guarantees that the memory it uses for a
   transaction scheduled to a given bank will remain valid until at
   least `bank_depth` additional transactions have been scheduled to
   that bank.  Typically, this should be the same as the depth of the
   mcache being used to communicate with the banking thread.

   pack_depth sets the maximum number of pending transactions that pack
   stores and may eventually schedule. */

static inline ulong fd_pack_align(        void ) { return FD_PACK_ALIGN; }
static inline ulong fd_pack_txnmem_align( void ) { return 128UL; }

ulong fd_pack_footprint(        ulong bank_cnt, ulong bank_depth, ulong pack_depth );
ulong fd_pack_txnmem_footprint( ulong bank_cnt, ulong bank_depth, ulong pack_depth );


/* fd_pack_new formats a region of memory to be suitable for use as a
   pack object.  mem and txnmem are non-NULL pointers to regions of
   memory in the local address space with the respectively required
   alignment and footprint.  est_tbl is a pointer to a locally joined
   estimation table used to estimate CU usage for transactions.
   bank_cnt, bank_depth, and pack_depth are as above. cu_limit sets the
   maximum number of compute units worth of transactions that will be
   scheduled to each bank in each block.  rng is a local join to a
   random number generator used to perturb estimates.

   Returns `mem` (which will be properly formatted as a pack object) on
   success and NULL on failure.  Logs details on failure.  The caller
   will not be joined to the pack object when this function returns. */
void * fd_pack_new( void * mem, void * txnmem,
    fd_est_tbl_t * est_tbl,
    ulong bank_cnt, ulong bank_depth, ulong pack_depth, ulong cu_limit,
    fd_rng_t * rng );

/* fd_pack_join joins the caller to the pack object.  Every successful
   join should have a matching leave.  Returns mem. */
fd_pack_t * fd_pack_join( void * mem );


/* fd_pack_bank_cnt returns the value used for bank_cnt when the pack
   object was created.  pack must be a valid local join of a pack object
   */
ulong fd_pack_bank_cnt( fd_pack_t * pack );

/* fd_pack_insert_txn_{init,fini,cancel} execute the process of
   inserting a new transaction into the pool of available transactions
   that may be scheduled by the pack object.

   fd_pack_insert_txn_init returns a piece of memory from the txnmem
   region where the transaction should be stored.  The lifetime of this
   memory is managed by fd_pack as explained below.

   Every call to fd_pack_insert_init must be paired with a call to
   exactly one of _fini or _cancel.  Calling fd_pack_insert_txn_fini
   finalizes the transaction insert process and makes the newly-inserted
   transaction available for scheduling.  Calling
   fd_pack_insert_txn_cancel aborts the transaction insertion process.
   The txn pointer passed to _fini or _cancel must come from the most
   recent call to _init.

   The caller of these methods should not retain any read or write
   interest in the transaction after _fini or _cancel have been called.

   pack must be a local join of a pack object.  From the caller's
   perspective, these functions cannot fail.
 */
fd_txn_p_t * fd_pack_insert_txn_init  ( fd_pack_t * pack                   );
void         fd_pack_insert_txn_fini  ( fd_pack_t * pack, fd_txn_p_t * txn );
void         fd_pack_insert_txn_cancel( fd_pack_t * pack, fd_txn_p_t * txn );


/* fd_pack_schedule_next schedules a transaction to a bank.  pack must
   be a local join of a pack object.  On success, returns the scheduled
   transaction, which is in txnmem, along with a little metadata.  The
   pointer  stored in the txn field of the return value is valid until
   at least bank_depth more transactions have been scheduled to the same
   bank.

   On failure, the txn field of the return value is NULL.  This
   typically happens if the pack object has no more transactions, but
   can also happen if banking threads need to stall. */
fd_pack_scheduled_txn_t fd_pack_schedule_next( fd_pack_t * pack );



/* fd_pack_drain_block returns transactions that were scheduled but
   deferred and never returned from schedule_next.  Prior to calling
   pack_clear, this should be called until it returns with a NULL txn
   field.  Otherwise, transactions may be dropped.  Once you call
   pack_drain, you should not call schedule_next until clearing to avoid
   transactions coming out of order.

   Summarizing,
      * insert and schedule transactions
      * drain the block
      * clear
      * repeat for the next block
   */
fd_pack_scheduled_txn_t fd_pack_drain_block( fd_pack_t * pack );

/* fd_pack_clear resets some associated with this pack object.  If
   full_reset is 0, it only resets its knowledge of accounts that may be
   in use on each bank.  If full_reset is non-zero, then it also clears
   all pending transactions from its pool of available transactions.
   pack must be a valid local join. */
void fd_pack_clear( fd_pack_t * pack, int full_reset );


/* fd_pack_leave leaves a local join of a pack object.  Returns pack.
   fd_pack_delete unformats a memory region used to store a pack object
   and returns ownership of the memory to the caller.  Returns mem. */
void * fd_pack_leave(  fd_pack_t * pack );
void * fd_pack_delete( void      * mem  );

FD_PROTOTYPES_END
#endif /*HEADER_fd_src_ballet_pack_fd_pack_h*/
