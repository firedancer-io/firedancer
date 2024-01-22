#ifndef HEADER_fd_src_ballet_pack_fd_pack_h
#define HEADER_fd_src_ballet_pack_fd_pack_h

/* fd_pack defines methods that prioritizes Solana transactions,
   selecting a subset (potentially all) and ordering them to attempt to
   maximize the overall profitability of the validator. */

#include "../fd_ballet_base.h"
#include "../txn/fd_txn.h"
#include "fd_est_tbl.h"


#define FD_PACK_ALIGN     (128UL)

#define FD_PACK_MAX_BANK_TILES 63UL


/* NOTE: THE FOLLOWING CONSTANTS ARE CONSENSUS CRITICAL AND CANNOT BE
   CHANGED WITHOUT COORDINATING WITH SOLANA LABS. */
#define FD_PACK_MAX_COST_PER_BLOCK      (48000000UL)
#define FD_PACK_MAX_VOTE_COST_PER_BLOCK (36000000UL)
#define FD_PACK_MAX_WRITE_COST_PER_ACCT (12000000UL)
#define FD_PACK_FEE_PER_SIGNATURE           (5000UL) /* In lamports */

/* ---- End consensus-critical constants */


/* Is this structure useful in other parts of the codebase? Should this
   go somewhere else? */
struct fd_txn_p {
  uchar payload[FD_TPU_MTU];
  ulong payload_sz;
  ulong meta;
  int   is_simple_vote; /* Populated by pack */
  /* union {
    This would be ideal but doesn't work because of the flexible array member
    uchar _[FD_TXN_MAX_SZ];
    fd_txn_t txn;
  }; */
  /* Access with TXN macro below */
  uchar _[FD_TXN_MAX_SZ] __attribute__((aligned(alignof(fd_txn_t))));
};
typedef struct fd_txn_p fd_txn_p_t;

#define TXN(txn_p) ((fd_txn_t *)( (txn_p)->_ ))


/* Forward declare opaque handle */
struct fd_pack_private;
typedef struct fd_pack_private fd_pack_t;

/* fd_pack_{align,footprint} return the required alignment and
   footprint in bytes for a region of memory to be used as a pack
   object.

   pack_depth sets the maximum number of pending transactions that pack
   stores and may eventually schedule.

   bank_tile_cnt sets the number of bank tiles to which this pack object
   can schedule transactions.  bank_tile_cnt must be in [1,
   FD_PACK_MAX_BANK_TILES].

   max_txn_per_microblock sets the maximum number of transactions that
   pack will schedule in a single microblock. */

FD_FN_CONST static inline ulong fd_pack_align       ( void ) { return FD_PACK_ALIGN; }

FD_FN_CONST ulong
fd_pack_footprint( ulong pack_depth,
                   ulong bank_tile_cnt,
                   ulong max_txn_per_microblock );


/* fd_pack_new formats a region of memory to be suitable for use as a
   pack object.  mem is a non-NULL pointer to a region of memory in the
   local address space with the required alignment and footprint.
   pack_depth, bank_tile_cnt, and max_txn_per_microblock are as above.
   The pack object will produce at most max_microblocks_per_block
   non-empty microblocks in a block.  rng is a local join to a random
   number generator used to perturb estimates.

   Returns `mem` (which will be properly formatted as a pack object) on
   success and NULL on failure.  Logs details on failure.  The caller
   will not be joined to the pack object when this function returns. */
void * fd_pack_new( void * mem,
    ulong pack_depth, ulong bank_tile_cnt, ulong max_txn_per_microblock,
    ulong max_microblocks_per_block, fd_rng_t * rng );

/* fd_pack_join joins the caller to the pack object.  Every successful
   join should have a matching leave.  Returns mem. */
fd_pack_t * fd_pack_join( void * mem );


/* fd_pack_avail_txn_cnt returns the number of transactions that this
   pack object has available to schedule but that have not been
   scheduled yet. pack must be a valid local join.  The return value
   will be in [0, pack_depth). */

FD_FN_PURE ulong fd_pack_avail_txn_cnt( fd_pack_t * pack );

/* fd_pack_bank_tile_cnt: returns the value of bank_tile_cnt provided in
   pack when the pack object was initialized with fd_pack_new.  pack
   must be a valid local join.  The result will be in [1,
   FD_PACK_MAX_BANK_TILES]. */
FD_FN_PURE ulong fd_pack_bank_tile_cnt( fd_pack_t * pack );

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


/* fd_pack_schedule_next_microblock schedules transactions to form a
   microblock, which is a set of non-conflicting transactions.

   pack must be a local join of a pack object.  Transactions part of the
   scheduled microblock are copied to out in no particular order.  The
   cumulative cost of these transactions will not exceed total_cus, and
   the number of transactions will not exceed the value of
   max_txn_per_microblock given in fd_pack_new.

   The block will not contain more than
   vote_fraction*max_txn_per_microblock votes, and votes in total will
   not consume more than vote_fraction*total_cus of the microblock.

   Returns the number of transactions in the scheduled microblock.  The
   return value may be 0 if there are no eligible transactions at the
   moment. */

ulong fd_pack_schedule_next_microblock( fd_pack_t * pack, ulong total_cus, float vote_fraction, ulong bank_tile, fd_txn_p_t * out );


/* fd_pack_microblock_complete signals that the bank_tile with index
   bank_tile has completed its previously scheduled microblock.  This
   permits the scheduling of transactions that conflict with the
   previously scheduled microblock. */
void fd_pack_microblock_complete( fd_pack_t * pack, ulong bank_tile );

/* fd_pack_delete_txn removes a transaction (identified by its first
   signature) from the pool of available transactions.  Returns 1 if the
   transaction was found (and then removed) and 0 if not. */
int fd_pack_delete_transaction( fd_pack_t * pack, fd_ed25519_sig_t const * sig0 );

/* fd_pack_end_block resets some state to prepare for the next block.
   Specifically, the per-block limits are cleared and transactions in
   the microblocks scheduled after the call to this function are allowed
   to conflict with transactions in microblocks scheduled before the
   call to this function, even within gap microblocks. */
void fd_pack_end_block( fd_pack_t * pack );


/* fd_pack_clear_all resets the state associated with this pack object.
   All pending transactions are removed from the pool of available
   transactions and all limits are reset. */
void fd_pack_clear_all( fd_pack_t * pack );


/* fd_pack_leave leaves a local join of a pack object.  Returns pack.
   fd_pack_delete unformats a memory region used to store a pack object
   and returns ownership of the memory to the caller.  Returns mem. */
void * fd_pack_leave(  fd_pack_t * pack );
void * fd_pack_delete( void      * mem  );

FD_PROTOTYPES_END
#endif /*HEADER_fd_src_ballet_pack_fd_pack_h*/
