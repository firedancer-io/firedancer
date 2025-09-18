#ifndef HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h
#define HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../vm/fd_vm_base.h"
#include "fd_system_ids.h"
#include "fd_executor.h"
#include "fd_runtime_const.h"
#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"

/* fd_cost_tracker_t is a block-level tracker for various limits
   including CU consumption, writable account usage, and account data
   size.  A cost is calculated per-transaction and is accumulated to the
   block.  If a block's limits are exceeded, then the block is marked as
   dead. */

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L62-L79 */

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L20 */
#define FD_WRITE_LOCK_UNITS ( 300UL )

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L42 */
#define FD_MAX_BLOCK_ACCOUNTS_DATA_SIZE_DELTA ( 100000000UL )

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L34 */
#define FD_MAX_WRITABLE_ACCOUNT_UNITS ( 12000000UL )

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L50-L56 */
#define FD_MAX_BLOCK_UNITS_SIMD_0207 ( 50000000UL )

/* https://github.com/anza-xyz/agave/blob/v2.3.0/cost-model/src/block_cost_limits.rs#L50-L56 */
#define FD_MAX_BLOCK_UNITS_SIMD_0256 ( 60000000UL )

/* https://github.com/anza-xyz/agave/blob/v3.0.0/cost-model/src/block_cost_limits.rs#L30 */
#define FD_MAX_BLOCK_UNITS_SIMD_0286 ( 100000000UL )

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L38 */
#define FD_MAX_VOTE_UNITS ( 36000000UL )

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

struct fd_cost_tracker {
  ulong magic;

  /* Current accumulated values */
  ulong block_cost;
  ulong vote_cost;
  ulong allocated_accounts_data_size;

  /* Limits */
  ulong block_cost_limit;
  ulong vote_cost_limit;
  ulong account_cost_limit;

  ulong pool_offset_;
  ulong map_offset_;
};
typedef struct fd_cost_tracker fd_cost_tracker_t;

#define FD_COST_TRACKER_ALIGN (128UL)

struct fd_account_cost {
  fd_pubkey_t account;
  ulong       cost;
  ulong       next_;
};
typedef struct fd_account_cost fd_account_cost_t;

#define FD_COST_TRACKER_CHAIN_CNT_EST (262144UL)
#define FD_COST_TRACKER_FOOTPRINT                                                                 \
  /* First, layout the struct with alignment */                                                   \
  sizeof(fd_cost_tracker_t) + FD_COST_TRACKER_ALIGN +                                             \
  /* Now layout the pool's data footprint */                                                      \
  FD_COST_TRACKER_ALIGN + sizeof(fd_account_cost_t) * FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_SLOT + \
  /* Now layout the pool's meta footprint */                                                      \
  FD_COST_TRACKER_ALIGN + 128UL /* POOL_ALIGN */ +                                                \
  /* Now layout the map.  We must make assumptions about the chain */                             \
  /* count to be equivalent to chain_cnt_est. */                                                  \
  FD_COST_TRACKER_ALIGN + 128UL /* MAP_ALIGN */ + (FD_COST_TRACKER_CHAIN_CNT_EST * sizeof(ulong))
#define FD_COST_TRACKER_MAGIC (0xF17EDA2CE7C05170UL) /* FIREDANCER COST V0 */

ulong
fd_cost_tracker_footprint( void );

ulong
fd_cost_tracker_align( void );

void *
fd_cost_tracker_new( void *                mem,
                     fd_features_t const * features,
                     ulong                 slot,
                     ulong                 seed );

fd_cost_tracker_t *
fd_cost_tracker_join( void * mem );

/* fd_cost_tracker_calculate_cost_and_add takes a transaction,
   calculates the cost of the transaction in terms of various block
   level limits and adds it to the cost tracker.  If the incremental
   transaction fits in the block, then the cost tracking is updated and
   FD_COST_TRACKER_SUCCESS is returned.  If the transaction does not
   fit then FD_COST_TRACKER_ERROR_{*} is returned depending on what
   limit is violated.

   This function assumes that the caller is responsible for managing
   concurrent callers.

   This function represents the combination of Agave client functions:
   `CostModel::calculate_cost_for_executed_transaction()` and
   `CostTracker::try_add()`.

    https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L69-L95
    https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L163-L173 */
int
fd_cost_tracker_calculate_cost_and_add( fd_cost_tracker_t *       cost_tracker,
                                        fd_exec_txn_ctx_t const * txn_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h */
