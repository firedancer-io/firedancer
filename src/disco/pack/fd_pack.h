#ifndef HEADER_fd_src_ballet_pack_fd_pack_h
#define HEADER_fd_src_ballet_pack_fd_pack_h

/* fd_pack defines methods that prioritizes Solana transactions,
   selecting a subset (potentially all) and ordering them to attempt to
   maximize the overall profitability of the validator. */

#include "../../ballet/fd_ballet_base.h"
#include "../../ballet/txn/fd_txn.h"
#include "../shred/fd_shred_batch.h"
#include "fd_est_tbl.h"
#include "fd_microblock.h"
#include "fd_pack_rebate_sum.h"

#define FD_PACK_ALIGN     (128UL)

#define FD_PACK_MAX_BANK_TILES 62UL

/* NOTE: THE FOLLOWING CONSTANTS ARE CONSENSUS CRITICAL AND CANNOT BE
   CHANGED WITHOUT COORDINATING WITH ANZA. */

/* These are bounds on known limits. Upper bound values are used to
   calculate memory footprints while lower bounds are used for
   initializing consensus-dependent logic and invariant checking.  As a
   leader, it is OK to produce blocks using limits smaller than the
   active on-chain limits. Replay should always use the correct
   chain-derived limits.

   The actual limits used by pack may be updated dynamically to some
   in-bounds value. If there is an anticipated feature activation that
   changes these limits, the upper bound should be the largest
   anticipated value while the lower bound should be the current active
   limit. For Frankendancer, the actual value used for consensus will be
   retreived from Agave. */
#define FD_PACK_MAX_COST_PER_BLOCK_LOWER_BOUND      (48000000UL)
#define FD_PACK_MAX_VOTE_COST_PER_BLOCK_LOWER_BOUND (36000000UL)
#define FD_PACK_MAX_WRITE_COST_PER_ACCT_LOWER_BOUND (12000000UL)

#define FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND      (60000000UL) /* simd 0256 */
#define FD_PACK_MAX_VOTE_COST_PER_BLOCK_UPPER_BOUND (36000000UL)
#define FD_PACK_MAX_WRITE_COST_PER_ACCT_UPPER_BOUND (12000000UL)

#define FD_PACK_FEE_PER_SIGNATURE           (5000UL) /* In lamports */

/* Each block is limited to 32k parity shreds.  We don't want pack to
   produce a block with so many transactions we can't shred it, but the
   correspondence between transactions and parity shreds is somewhat
   complicated, so we need to use conservative limits. */
#define FD_PACK_MAX_DATA_PER_BLOCK (FD_SHRED_BATCH_BLOCK_DATA_SZ_MAX)

/* Optionally allow up to 1M shreds per block for benchmarking. */
#define LARGER_MAX_DATA_PER_BLOCK  (32UL*FD_SHRED_BATCH_BLOCK_DATA_SZ_MAX)

/* ---- End consensus-critical constants */

#define FD_TXN_P_FLAGS_IS_SIMPLE_VOTE     ( 1U)
#define FD_TXN_P_FLAGS_BUNDLE             ( 2U)
#define FD_TXN_P_FLAGS_INITIALIZER_BUNDLE ( 4U)
#define FD_TXN_P_FLAGS_SANITIZE_SUCCESS   ( 8U)
#define FD_TXN_P_FLAGS_EXECUTE_SUCCESS    (16U)
#define FD_TXN_P_FLAGS_FEES_ONLY          (32U)
#define FD_TXN_P_FLAGS_DURABLE_NONCE      (64U)

#define FD_TXN_P_FLAGS_RESULT_MASK  (0xFF000000U)

/* A bundle is a sequence of between 1 and FD_PACK_MAX_TXN_PER_BUNDLE
   transactions (both inclusive) that executes and commits atomically.
 */
#define FD_PACK_MAX_TXN_PER_BUNDLE      5UL

/* The percentage of the transaction fees that are burned */
#define FD_PACK_TXN_FEE_BURN_PCT        50UL


/* The Solana network and Firedancer implementation details impose
   several limits on what pack can produce.  These limits are grouped in
   this one struct fd_pack_limits_t, which is just a convenient way to
   pass them around.  The limits listed below are arithmetic limits.
   The limits imposed by practical constraints are almost certainly
   much, much tighter. */
struct fd_pack_limits {
  /* max_{cost, vote_cost}_per_block, max_write_cost_per_acct are
     consensus-critical limits and must be agreed on cluster-wide.  A
     block that consumes more than max_cost_per_block cost units
     (closely related to, but not identical to CUs) in total is invalid.
     Similarly, a block where the sum of the cost of all vote
     transactions exceeds max_vote_cost_per_block cost units is invalid.
     Similarly, a block in where the sum of the cost of all transactions
     that write to a given account exceeds max_write_cost_per_acct is
     invalid. */
  ulong max_cost_per_block;          /* in [0, ULONG_MAX) */
  ulong max_vote_cost_per_block;     /* in [0, max_cost_per_block] */
  ulong max_write_cost_per_acct;     /* in [0, max_cost_per_block] */

  /* max_data_bytes_per_block is derived from consensus-critical limits
     on the number of shreds in a block, but is not directly enforced.
     Separation of concerns means that it's not a good idea for pack to
     know exactly how the block will be shredded, but at the same time,
     we don't want to end up in a situation where we produced a block
     that had too many shreds, because the shred tile's only recourse
     would be to kill the block.  To address this, pack limits the size
     of the data it puts into the block to a limit that we can prove
     will never cause the shred tile to produce too many shreds.

     This limit includes transaction and microblock headers for
     non-empty microblocks that pack produces. */
  ulong max_data_bytes_per_block;    /* in [0, ULONG_MAX - 183] */

  /* max_txn_per_microblock and max_microblocks_per_block are
     Firedancer-imposed implementation limits to bound the amount of
     memory consumption that pack uses.  Pack will produce microblocks
     with no more than max_txn_per_microblock transactions.
     Additionally, once pack produces max_microblocks_per_block
     non-empty microblocks in a block, all subsequent attempts to
     schedule a microblock will return an empty microblock until
     fd_pack_end_block is called. */
  ulong max_txn_per_microblock;      /* in [0, 16777216] */
  ulong max_microblocks_per_block;   /* in [0, 1e12) */

};
typedef struct fd_pack_limits fd_pack_limits_t;


/* Forward declare opaque handle */
struct fd_pack_private;
typedef struct fd_pack_private fd_pack_t;

/* fd_pack_{align,footprint} return the required alignment and
   footprint in bytes for a region of memory to be used as a pack
   object.

   pack_depth sets the maximum number of pending transactions that pack
   stores and may eventually schedule.  pack_depth must be at least 4.

   If bundle_meta_sz is non-zero, then the bundle-related functions on
   this pack object can be used, and it can schedule bundles.
   Additionally, if bundle_meta_sz is non-zero, then a region of size
   bundle_meta_sz bytes (with no additional alignment) will be reserved
   for each bundle.

   Note: if you'd like to use bundles, but don't require metadata for
   the bundles, simply use a small positive value (e.g. 1), always pass
   NULL in insert_bundle_fini, and never call fd_pack_peek_bundle_meta.

   bank_tile_cnt sets the number of bank tiles to which this pack object
   can schedule transactions.  bank_tile_cnt must be in [1,
   FD_PACK_MAX_BANK_TILES].

   limits sets various limits for the blocks and microblocks that pack
   can produce. */

FD_FN_CONST static inline ulong fd_pack_align       ( void ) { return FD_PACK_ALIGN; }

FD_FN_PURE ulong
fd_pack_footprint( ulong                    pack_depth,
                   ulong                    bundle_meta_sz,
                   ulong                    bank_tile_cnt,
                   fd_pack_limits_t const * limits );


/* fd_pack_new formats a region of memory to be suitable for use as a
   pack object.  mem is a non-NULL pointer to a region of memory in the
   local address space with the required alignment and footprint.
   pack_depth, bundle_meta_sz, bank_tile_cnt, and limits are as above.
   rng is a local join to a random number generator used to perturb
   estimates.

   Returns `mem` (which will be properly formatted as a pack object) on
   success and NULL on failure.  Logs details on failure.  The caller
   will not be joined to the pack object when this function returns. */
void * fd_pack_new( void                   * mem,
                    ulong                    pack_depth,
                    ulong                    bundle_meta_sz,
                    ulong                    bank_tile_cnt,
                    fd_pack_limits_t const * limits,
                    fd_rng_t               * rng );

/* fd_pack_join joins the caller to the pack object.  Every successful
   join should have a matching leave.  Returns mem. */
fd_pack_t * fd_pack_join( void * mem );


/* fd_pack_avail_txn_cnt returns the number of transactions that this
   pack object has available to schedule but that have not been
   scheduled yet. pack must be a valid local join.  The return value
   will be in [0, pack_depth). */

/* For performance reasons, implement this here.  The offset is STATIC_ASSERTed
   in fd_pack.c. */
#define FD_PACK_PENDING_TXN_CNT_OFF 72
FD_FN_PURE static inline ulong
fd_pack_avail_txn_cnt( fd_pack_t const * pack ) {
  return *((ulong const *)((uchar const *)pack + FD_PACK_PENDING_TXN_CNT_OFF));
}

/* fd_pack_current_block_cost returns the number of CUs that have been
   scheduled in the current block, net of any rebates.  It should be
   between 0 and the specified value of max_cost_per_block, but it can
   be slightly higher due to temporary cost model nonsense.  Due to
   rebates, this number may decrease as the block progresses.  pack must
   be a valid local join. */
FD_FN_PURE ulong fd_pack_current_block_cost( fd_pack_t const * pack );

/* fd_pack_bank_tile_cnt: returns the value of bank_tile_cnt provided in
   pack when the pack object was initialized with fd_pack_new.  pack
   must be a valid local join.  The result will be in [1,
   FD_PACK_MAX_BANK_TILES]. */
FD_FN_PURE ulong fd_pack_bank_tile_cnt( fd_pack_t const * pack );

/* fd_pack_set_block_limits: Updates the limits provided fd_pack_new to
   these new values.  Any future microblocks produced by this pack
   object will not cause a block to have more than
   limits->max_microblocks_per_block non-empty microblocks or more than
   limits->max_data_bytes_per_block data bytes (counting microblock
   headers as before).  future microblocks will also exclude those that
   cause the total block cost to exceed limits->max_cost_per_block.
   Similarly those that cause the total vote-only cost to exceed
   limits->max_vote_cost_per_block. Also, those that cause the total
   per-account, per block write cost to exceed
   limits->max_write_cost_per_acct.  Note that
   limits->max_txn_per_microblock is ignored. Limits are inclusive, as
   per usual (i.e. a block may have exactly max_microblocks_per_block
   microblocks, but not more).  pack must be a valid local join.

   The typical place to call this is immediately after
   fd_pack_end_block; if this is called after some microblocks have been
   produced for the current block, and the current block already exceeds
   the limits, all the remaining microblocks in the block will be empty,
   but the call is valid. */
void fd_pack_set_block_limits( fd_pack_t * pack, fd_pack_limits_t const * limits );

/* Return values for fd_pack_insert_txn_fini:  Non-negative values
   indicate the transaction was accepted and may be returned in a future
   microblock.  Negative values indicate that the transaction was
   rejected and will never be returned in a future microblock.
   Transactions can be rejected through no fault of their own, so it
   doesn't necessarily imply bad behavior.

   The non-negative (success) codes are essentially a bitflag of three
   bits:
    * (1) whether the transaction met the criteria for a simple vote or
      not,
    * (2) whether this transaction replaced a previously accepted, low
      priority transaction, rather than being accepted in addition to
      all the previously accepted transactions.
    * (4) whether this transaction is a durable nonce transaction

   Since pack maintains a heap with a fixed max size of pack_depth,
   replacing transaction is necessary whenever the heap is full.
   Additionally, only one transaction with a given (nonce account, nonce
   authority, recent blockhash) value is allowed in pack's heap at a
   time, which means if there's already a lower priority transaction
   with the same nonce info, then this transaction will replace it.
   When the heap is full, and a nonce transaction is inserted, these
   return values don't allow you to disambiguate whether the replaced
   transaction had the same nonce info or not.

   Vote and durable nonce transactions are mutually exclusive.

   The negative (failure) codes are a normal enumeration (not a
   bitflag).
    * PRIORITY: pack's heap was full and the transaction's priority was
      lower than the worst currently accepted transaction.
    * NONCE_PRIORITY: pack's heap had a transaction with the same
      durable nonce info that was higher priority.
    * DUPLICATE: the transaction is a duplicate of a currently accepted
      transaction.
    * UNAFFORDABLE: the fee payer could not afford the transaction fee
      (not yet implemented).
    * ADDR_LUT: the transaction tried to load an account from an address
      lookup table, which is not yet supported.
    * EXPIRED: the transaction was already expired upon insertion based
      on the provided value of expires_at compared to the last call to
      fd_pack_expire_before.
    * TOO_LARGE: the transaction requested too many CUs and would never
      be scheduled if it had been accepted.
    * ACCOUNT_CNT: the transaction tried to load more than 64 account
      addresses.
    * DUPLICATE_ACCT: the transaction included an account address twice
      in its list of account addresses to load.
    * ESTIMATION_FAIL: estimation of the transaction's compute cost and
      fee failed, typically because the transaction contained a
      malformed ComputeBudgetProgram instruction.
    * WRITES_SYSVAR: the transaction attempts to write-lock a sysvar.
      Write-locking a sysvar can cause heavy contention.  Agave
      solves this by downgrading these to read locks, but we instead
      solve it by refusing to pack such transactions.
    * INVALID_NONCE: the transaction looks like a durable nonce
      transaction, but the nonce authority did not sign the transaction.
    * BUNDLE_BLACKLIST: bundles are enabled and the transaction uses an
      account in the bundle blacklist.
    * NONCE_CONFLICT: bundle with two transactions that attempt to lock
      the exact same durable nonce (nonce account, authority, and block
      hash).

    NOTE: The corresponding enum in metrics.xml must be kept in sync
    with any changes to these return values. */
#define FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_REPLACE (  6)
#define FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_ADD     (  4)
#define FD_PACK_INSERT_ACCEPT_VOTE_REPLACE          (  3)
#define FD_PACK_INSERT_ACCEPT_NONVOTE_REPLACE       (  2)
#define FD_PACK_INSERT_ACCEPT_VOTE_ADD              (  1)
#define FD_PACK_INSERT_ACCEPT_NONVOTE_ADD           (  0)
#define FD_PACK_INSERT_REJECT_PRIORITY              ( -1)
#define FD_PACK_INSERT_REJECT_NONCE_PRIORITY        ( -2)
#define FD_PACK_INSERT_REJECT_DUPLICATE             ( -3)
#define FD_PACK_INSERT_REJECT_UNAFFORDABLE          ( -4)
#define FD_PACK_INSERT_REJECT_ADDR_LUT              ( -5)
#define FD_PACK_INSERT_REJECT_EXPIRED               ( -6)
#define FD_PACK_INSERT_REJECT_TOO_LARGE             ( -7)
#define FD_PACK_INSERT_REJECT_ACCOUNT_CNT           ( -8)
#define FD_PACK_INSERT_REJECT_DUPLICATE_ACCT        ( -9)
#define FD_PACK_INSERT_REJECT_ESTIMATION_FAIL       (-10)
#define FD_PACK_INSERT_REJECT_WRITES_SYSVAR         (-11)
#define FD_PACK_INSERT_REJECT_INVALID_NONCE         (-12)
#define FD_PACK_INSERT_REJECT_BUNDLE_BLACKLIST      (-13)
#define FD_PACK_INSERT_REJECT_NONCE_CONFLICT        (-14)

/* The FD_PACK_INSERT_{ACCEPT, REJECT}_* values defined above are in the
   range [-FD_PACK_INSERT_RETVAL_OFF,
   -FD_PACK_INSERT_RETVAL_OFF+FD_PACK_INSERT_RETVAL_CNT ) */
#define FD_PACK_INSERT_RETVAL_OFF 14
#define FD_PACK_INSERT_RETVAL_CNT 21

FD_STATIC_ASSERT( FD_PACK_INSERT_REJECT_NONCE_CONFLICT>=-FD_PACK_INSERT_RETVAL_OFF, pack_retval );
FD_STATIC_ASSERT( FD_PACK_INSERT_ACCEPT_NONCE_NONVOTE_REPLACE<FD_PACK_INSERT_RETVAL_CNT-FD_PACK_INSERT_RETVAL_OFF, pack_retval );

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

   expires_at (for _fini only) bounds the lifetime of the inserted
   transaction.  No particular unit is prescribed, and it need not be
   higher than the previous call to txn_fini.  If fd_pack_expire_before
   has been previously called with a value larger (strictly) than the
   provided expires_at, the transaction will be rejected with EXPIRED.
   See fd_pack_expire_before for more details.

   pack must be a local join of a pack object.  From the caller's
   perspective, these functions cannot fail, though pack may reject a
   transaction for a variety of reasons.  fd_pack_insert_txn_fini
   returns one of the FD_PACK_INSERT_ACCEPT_* or FD_PACK_INSERT_REJECT_*
   codes explained above.
 */
fd_txn_e_t * fd_pack_insert_txn_init  ( fd_pack_t * pack                                                         );
int          fd_pack_insert_txn_fini  ( fd_pack_t * pack, fd_txn_e_t * txn, ulong expires_at, ulong * delete_cnt );
void         fd_pack_insert_txn_cancel( fd_pack_t * pack, fd_txn_e_t * txn                                       );

/* fd_pack_insert_bundle_{init,fini,cancel} are parallel to the
   similarly named fd_pack_insert_txn functions but can be used to
   insert a bundle instead of a transaction.

   fd_pack_insert_bundle_init populates and returns bundle.
   Specifically, it populates bundle[0], ...  bundle[txn_cnt-1] with
   pointers to fd_txn_p_t structs that should receive a new transaction.
   The pointers themselves should not be changed which is what the const
   indicates, but the contents of the fd_txn_p_t structs must be changed
   in order for this to be useful.  bundle must be a pointer to the
   first element of an array of at least txn_cnt pointers.

   The bundle consists of the transactions in the order they are
   provided.  I.e. bundle[0] will execute first in the bundle.

   Like with insert_txn, every call to fd_pack_insert_bundle_init must
   be paired with a call to exactly one of _fini or _cancel.  Calling
   fd_pack_insert_bundle_fini finalizes the bundle insertion process and
   makes the newly-inserted bundle available for scheduling.  Calling
   fd_pack_insert_bundle_cancel aborts the transaction insertion
   process.  There can be at most two outstanding bundles, of which one
   should be an initializer bundle.  The bundle argument passed to _fini
   or _cancel must be the return value of a call to _init with the same
   value of txn_cnt.  Additionally, it is okay to interleave calls to
   the insert_txn family of functions with calls to the insert_bundle
   family of functions.

   The caller of these methods should not retain any read or write
   interest in the fd_txn_p_t structs that the entries of bundle
   point to after _fini or _cancel have been called.

   expires_at has the same meaning as above.  Although transactions in
   the bundle may have different recent blockhashes, all transactions in
   the bundle have the same expires_at value, since if one expires, the
   whole bundle becomes invalid.

   If initializer_bundle is non-zero, this bundle will be inserted at
   the front of the bundle queue so that it is the next bundle
   scheduled.  Otherwise, the bundle will be inserted at the back of the
   bundle queue, and will be scheduled in FIFO order with the rest of
   the bundles.  If an initializer bundle is already present in pack's
   pending transactions, that bundle will be deleted.  Additionally, if
   initializer_bundle is non-zero, the transactions in the bundle will
   not be checked against the bundle blacklist; otherwise, the check
   will be performed as normal.  See the section below on initializer
   bundles for more details.

   Other than the blacklist check, transactions in a bundle are subject
   to the same checks as other transactions.  If any transaction in the
   bundle fails validation, the whole bundle will be rejected.

   _fini also accepts bundle_meta, an optional opaque pointer to a
   region of memory of size bundle_meta_sz (as provided in pack_new).
   If bundle_meta is non-NULL, the contents of the memory will be copied
   to a metadata region associated with this bundle and can be retrieved
   later with fd_pack_peek_bundle_meta.  The contents of bundle_meta is
   not retrievable if initializer_bundle is non-zero, so you may wish to
   just pass NULL in that case.  This function does not retain any
   interest in the contents of bundle_meta after it returns.

   txn_cnt must be in [1, MAX_TXN_PER_BUNDLE].  A txn_cnt of 1 inserts a
   single-transaction bundle which is transaction with extremely high
   priority.  That said, inserting transactions as bundles instead of
   transactions can hurt performance and throughput by introducing
   unnecessary stalls.

   fd_pack_insert_bundle_fini returns one of the FD_PACK_INSERT_ACCEPT_*
   or FD_PACK_INSERT_REJECT_* codes explained above.  If there are
   multiple reasons for rejecting a bundle, the which of the reasons it
   returns is unspecified.  delete_cnt is the number of existing
   transactions that were deleted as a side effect of insertion.

   These functions must not be called if the pack object was initialized
   with bundle_meta_sz==0. */

fd_txn_e_t * const * fd_pack_insert_bundle_init  ( fd_pack_t * pack, fd_txn_e_t *       * bundle, ulong txn_cnt                                        );
int                  fd_pack_insert_bundle_fini  ( fd_pack_t * pack, fd_txn_e_t * const * bundle, ulong txn_cnt,
                                                   ulong expires_at, int initializer_bundle, void const * bundle_meta, ulong * delete_cnt );
void                 fd_pack_insert_bundle_cancel( fd_pack_t * pack, fd_txn_e_t * const * bundle, ulong txn_cnt                                        );


/* =========== More details about initializer bundles ===============
   Initializer bundles are a special type of bundle with special support
   from the pack object to facilitate preparing on-chain state for the
   execution of bundles by this validator.  This design is a bit
   complicated, but it eliminates excessive coupling between pack and
   block engine details.

   The pack object maintains a small state machine (initializer bundle
   abbreviated IB):

      [Not Initialized]  ------------------------->|
          ^                                        | Schedule an
          |     End            Rebate shows        | IB
          |     block          IB failed           |
          |<----------[Failed]--------------|      v
          |                               --===[Pending]
          |<------------------------------/     ^  |
          |     End block                   /---|  |
          |                                 |      | Rebate shows
          |                        Schedule |      | IB succeeded
          |                      another IB |      |
          |     End block                   |      V
          -----------------------------------===[Ready]


   When attempting to schedule a bundle the pack object checks the
   state, and employs the following rules:
   * [Not Initialized]: If the top bundle is an IB, schedule it,
     removing it like normal, then transition to [Pending].  Otherwise,
     do not schedule a bundle.
   * [Pending]: Do not schedule a bundle.
   * [Failed]: Do not schedule a bundle
   * [Ready]: Attempt to schedule the next bundle.  If scheduling an IB,
     transition to [Pending].

   As described in the state machine, ending the block (via
   fd_pack_end_block) transitions to [Not Initialized], and calls to
   fd_pack_rebate_cus control the transition out of [Pending].

   This design supports a typical block engine system where some state
   may need to be initialized at the start of the slot and some state
   may need to change between runs of transactions (e.g. 5 transactions
   from block builder A followed by 5 transactions from block builder
   B).  This can be done by inserting an initializer bundle whenever the
   top non-initializer bundle's metadata state (retrievable with
   fd_pack_peek_bundle_meta) doesn't match the current on-chain state.
   Since the initializer bundle will execute before the bundle that was
   previously the top one, by the time the non-initializer bundle
   executes, the on-chain state will be correctly configured.  In this
   scheme, in the rare case that an initializer bundle was inserted but
   never executed, it should be deleted at the end of the slot.

   If at the start of the slot, it is determined that the on-chain state
   is in good shape, the state machine can transition directly to
   [Ready] by calling fd_pack_set_initializer_bundles_ready.

   Initializer bundles are not exempt from expiration, but it should not
   be a problem if they are always inserted with the most recent
   blockhash and deleted at the end of the slot.

   Additionally, a bundle marked as an IB is exempted from the bundle
   account blacklist checks.  For this reason, it's important that IB be
   generated by trusted code with minimal or sanitized
   attacker-controlled input. */


/* fd_pack_peek_bundle_meta returns a constant pointer to the bundle
   metadata associated with the bundle currently in line to be scheduled
   next, or NULL in any of the following cases:
     * There are no bundles
     * The bundle currently in line to be scheduled next is an IB
     * The bundle state is currently [Pending] or [Failed].

   The lifetime of the returned pointer is until the next pack insert,
   schedule, delete, or expire call.  The size of the region pointed to
   by the returned pointer is bundle_meta_sz.  If this bundle was
   inserted with bundle_meta==NULL, then the contents of the region
   pointed to by the returned pointer are arbitrary, but it will be safe
   to read.

   Pack doesn't do anything special to ensure the returned pointer
   points to memory with any particular alignment.  It will naturally
   have an alignment of at least GCD( 64, bundle_meta_sz ). */
void const * fd_pack_peek_bundle_meta( fd_pack_t const * pack );

/* fd_pack_set_initializer_bundles_ready sets the IB state machine state
   (see long initializer bundle comment above) to the [Ready] state.
   This function makes it easy to use bundles without initializer
   bundles.  pack must be a valid local join. */
void fd_pack_set_initializer_bundles_ready( fd_pack_t * pack );


/* FD_PACK_SCHEDULE_{VOTE,BUNDLE,TXN} form a set of bitflags used in
   fd_pack_schedule_next_microblock below.  They control what types of
   scheduling are allowed.  The names should be self-explanatory. */
#define FD_PACK_SCHEDULE_VOTE   1
#define FD_PACK_SCHEDULE_BUNDLE 2
#define FD_PACK_SCHEDULE_TXN    4

/* fd_pack_schedule_next_microblock schedules pending transactions.
   These transaction either form a microblock, which is a set of
   non-conflicting transactions, or a bundle.  The semantics of this
   function are a bit different depending on which one it picks, but
   there are some reasons why they both use this function.

   For both codepaths, pack must be a local join of a pack object.
   schedule_flags must be a bitwise combination of the
   FD_PACK_SCHEDULE_* values defined above.  When the bit is set
   corresponding to a transaction type, this function will consider
   scheduling transactions of that type.  Passing 0 for schedule_flags
   is a no-op.  The full policy is as follows:
    1. If the VOTE bit is set, attempt to schedule votes.  This is the
       microblock case.
    2. If the BUNDLE bit is set, and step 1 did not schedule any votes,
       attempt to schedule bundles.  This is the bundle case.
    3. If the TXN bit is set, and step 2 did not schedule any bundles
       for a reason other than account conflicts, attempt to schedule
       normal transactions.  This is the microblock case.
   Note that it is possible to schedule a microblock containing both
   votes and normal transactions, but bundles cannot be combined with
   either other type.  Additionally, if the BUNDLE bit is not set, step
   2 will not schedule any bundles for that reason, which is a reason
   other than account conflicts, so that clause will always be
   satisfied.

   Microblock case:
   Transactions part of the scheduled microblock are copied to out in no
   particular order.  The cumulative cost of these transactions will not
   exceed total_cus, and the number of transactions will not exceed the
   value of max_txn_per_microblock given in fd_pack_new.

   The block will not contain more than
   vote_fraction*max_txn_per_microblock votes, and votes in total will
   not consume more than vote_fraction*total_cus of the microblock.

   Bundle case:
   Transactions part of the scheduled bundled are copied in execution
   order (i.e. out[0] must be executed first).  The number of
   transactions will not exceed FD_PACK_MAX_TXN_PER_BUNDLE.
   max_txn_per_microblock, total_cus, and vote_fraction are ignored,
   though the block-level limits are respected.

   Both cases:
   The non_execution_cus and requested_exec_plus_acct_data_cus fields of
   each transaction will be populated with the non execution CUs and
   requested execution CUs (including cus derived from the requested
   loaded accounts data size), respectively.  The sum of these two
   values is the total cost of the transaction, i.e. what is used for
   all limits, including the total_cus value.  The lower 3 bits of the
   flags field will be populated (simple vote, bundle, initializer
   bundle). Inspecting these flags is the proper way to tell which
   codepath executed.

   Returns the number of transactions in the scheduled microblock or
   bundle.  The return value may be 0 if there are no eligible
   transactions at the moment. */

ulong
fd_pack_schedule_next_microblock( fd_pack_t  * pack,
                                  ulong        total_cus,
                                  float        vote_fraction,
                                  ulong        bank_tile,
                                  int          schedule_flags,
                                  fd_txn_p_t * out );


/* fd_pack_rebate_cus adjusts the compute unit accounting for the
   specified transactions to take into account the actual consumed CUs
   after execution.  When a transaction is scheduled by
   schedule_next_microblock, pack assumes that it uses all the CUs it
   requests for the purposes of several CU limits.  If it doesn't use
   all the requested CUs, this function "rebates" them to pack so that
   they can be consumed by a different transaction in the block.

   pack must be a valid local join of a pack object.  rebate must point
   to a valid rebate report produced by fd_pack_rebate_sum_t.

   IMPORTANT: CU limits are reset at the end of each block, so this
   should not be called for transactions from a prior block.
   Specifically, there must not be a call to fd_pack_end_block between
   the call to schedule_next_microblock this is paired with and the call
   to rebate_cus.

   This function operates independently of microblock_complete.  In
   general, you probably need to call both.  microblock_complete must be
   called before scheduling another microblock to that bank tile, while
   rebate_cus is optional and has much more relaxed ordering
   constraints.  The restriction about intervening calls to end_block
   and that this must come after schedule_next_microblock are the only
   ordering constraints. */
void fd_pack_rebate_cus( fd_pack_t * pack, fd_pack_rebate_t const * rebate );

/* fd_pack_microblock_complete signals that the bank_tile with index
   bank_tile has completed its previously scheduled microblock.  This
   permits the scheduling of transactions that conflict with the
   previously scheduled microblock.  It is safe to call this multiple
   times after a microblock or even if bank_tile does not have a
   previously scheduled; in this case, the function will return 0 and
   act as a no-op.  Returns 1 if the bank_tile had an outstanding,
   previously scheduled microblock to mark as completed. */
int fd_pack_microblock_complete( fd_pack_t * pack, ulong bank_tile );

/* fd_pack_expire_before deletes all available transactions with
   expires_at values strictly less than expire_before.  pack must be a
   local join of a pack object.  Returns the number of transactions
   deleted.  Subsequent calls to fd_pack_expire_before with the same or
   a smaller value are no-ops. */
ulong fd_pack_expire_before( fd_pack_t * pack, ulong expire_before );

/* fd_pack_delete_txn removes a transaction (identified by its first
   signature) from the pool of available transactions.  Returns a
   nonzero count of the number of transactions deleted, if the
   transaction was found (and then removed) and 0 if not.  The count
   might be >1 if a bundle was caused to be deleted. */
ulong fd_pack_delete_transaction( fd_pack_t * pack, fd_ed25519_sig_t const * sig0 );

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


/* fd_pack_metrics_write writes period metric values to the metrics
   system.  pack must be a valid local join. */
void
fd_pack_metrics_write( fd_pack_t const * pack );


/* fd_pack_leave leaves a local join of a pack object.  Returns pack. */
void * fd_pack_leave(  fd_pack_t * pack );
/* fd_pack_delete unformats a memory region used to store a pack object
   and returns ownership of the memory to the caller.  Returns mem. */
void * fd_pack_delete( void      * mem  );

/* fd_pack_verify (for debugging use primarily) checks to ensure several
   invariants are satisfied.  scratch must point to the first byte of a
   piece of memory meeting the same alignment and footprint constraints
   as pack.  Returns 0 on success and a negative value on failure
   (logging a warning with details). */
int fd_pack_verify( fd_pack_t * pack, void * scratch );

FD_PROTOTYPES_END
#endif /* HEADER_fd_src_ballet_pack_fd_pack_h */
