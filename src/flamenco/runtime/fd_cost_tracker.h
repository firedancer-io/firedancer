#ifndef HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h
#define HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h

/* Combined logic from Agave's `cost_model.rs` and `cost_tracker.rs` for validating
   block limits, specifically during replay. */

#include "../vm/fd_vm_base.h"
#include "fd_system_ids.h"
#include "fd_executor.h"
#include "fd_runtime_const.h"
#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"

// https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L20
#define FD_WRITE_LOCK_UNITS ( 300UL )

// https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L42
#define FD_MAX_BLOCK_ACCOUNTS_DATA_SIZE_DELTA ( 100000000UL )

// https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L34
#define FD_MAX_WRITABLE_ACCOUNT_UNITS ( 12000000UL )

// https://github.com/anza-xyz/agave/blob/v2.3.0/cost-model/src/block_cost_limits.rs#L50-L56
#define FD_MAX_BLOCK_UNITS_SIMD_0256 ( 60000000UL )

// https://github.com/anza-xyz/agave/blob/v3.0.0/cost-model/src/block_cost_limits.rs#L30
#define FD_MAX_BLOCK_UNITS_SIMD_0286 ( 100000000UL )

// https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L38
#define FD_MAX_VOTE_UNITS ( 36000000UL )

// https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L15
#define FD_WRITABLE_ACCOUNTS_PER_BLOCK ( 4096UL )

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L18-L33 */
#define FD_COST_TRACKER_SUCCESS                                     ( 0 )
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_BLOCK_MAX_LIMIT          ( 1 )
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_VOTE_MAX_LIMIT           ( 2 )
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT        ( 3 )
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT ( 4 )
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT ( 5 )

/* A reasonably tight bound can be derived based on CUs.  The most
   optimal use of CUs is to pack as many writable accounts as possible
   for as cheaply as possible.  This means we should try to pack as many
   writable accounts as possible into each transaction.  Each
   transaction requires at least one signature.  We will assume that all
   of these accounts have no account data.

   64 - Max number of accounts per transaction.  In this case we will
   assume that all of these accounts are writable and have no data.
   100000000 - CUs per slot
   720 - Cost of a signature
   300 - Cost of a writable account write lock

   We can have (100000000 / (720 + 64 * 300)) = 5020 transactions per
   slot with maximum writable account utilization.

   So, 5020 transactions per slot * 64 accounts per transaction =
   321280 writable accounts per slot.

   NOTE: A slightly tighter bound can probably be derived.
*/

#define FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT ( \
  FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_TRANSACTION * (FD_MAX_BLOCK_UNITS_SIMD_0286 / ( FD_WRITE_LOCK_UNITS * FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_TRANSACTION + FD_PACK_COST_PER_SIGNATURE)) )
FD_STATIC_ASSERT( FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT==321280UL, "Incorrect FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT" );

FD_PROTOTYPES_BEGIN

/* Initializes the cost tracker and allocates enough memory for the map */
void
fd_cost_tracker_init( fd_cost_tracker_t * self,
                      fd_spad_t *         spad );

/* Modeled after `CostModel::calculate_cost_for_executed_transaction()`.
   Used to compute transaction cost information for executed transactions.

   https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L69-L95 */
fd_transaction_cost_t
fd_calculate_cost_for_executed_transaction( fd_exec_txn_ctx_t const * txn_ctx,
                                            fd_spad_t *               spad );

/* Modeled after `CostTracker::try_add()`. Checks to see if the transaction cost
   would fit in this block. Returns an error on failure.

    https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L163-L173 */
int
fd_cost_tracker_try_add( fd_cost_tracker_t *           self,
                         fd_exec_txn_ctx_t const *     txn_ctx,
                         fd_transaction_cost_t const * tx_cost );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h */
