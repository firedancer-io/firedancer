#ifndef HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h
#define HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h

/* fd_cost_tracker_t is a block-level tracker for various limits
   including CU consumption, writable account usage, and account data
   size.  A cost is calculated per-transaction and is accumulated to the
   block.  If a block's limits are exceeded, then the block is marked as
   dead. */

#include "fd_runtime_err.h"
#include "fd_runtime_const.h"
#include "../../disco/pack/fd_pack_cost.h"

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L62-L79 */

#define FD_WRITE_LOCK_UNITS (300U) /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L20 */

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L18-L33 */
#define FD_COST_TRACKER_SUCCESS                                     (0)
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_BLOCK_MAX_LIMIT          (1)
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT        (3)
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT (4)
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT (5)

FD_STATIC_ASSERT( FD_WRITE_LOCK_UNITS*FD_RUNTIME_MAX_TXN_ACC_WRITES_PER_SLOT +
                  FD_PACK_COST_PER_SIGNATURE*((FD_RUNTIME_MAX_TXN_ACC_WRITES_PER_SLOT+63UL)/64UL)<=87500000UL,
                  max_writable_accounts_per_slot_fits );
FD_STATIC_ASSERT( FD_WRITE_LOCK_UNITS*(FD_RUNTIME_MAX_TXN_ACC_WRITES_PER_SLOT+1UL) +
                  FD_PACK_COST_PER_SIGNATURE*((FD_RUNTIME_MAX_TXN_ACC_WRITES_PER_SLOT+64UL)/64UL)>87500000UL,
                  max_writable_accounts_per_slot_is_tight );

/* TODO: Extremely gross.  Used because these are in a pool which needs
   to be compile time sized T. */

/* The average mainnet block uses around 4200 distinct writable
   accounts. We size the cost tracker's account map at 8192 chains
   to give ~2x headroom over the observed average load. */
#define FD_COST_TRACKER_CHAIN_CNT_EST (8192UL)
#define FD_COST_TRACKER_FOOTPRINT                                                                   \
  ( FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND(         \
    FD_LAYOUT_INIT,                                                                                 \
      128UL /* alignof(fd_cost_tracker_t) */,  128UL /* sizeof(fd_cost_tracker_t) */          ),    \
      128UL /* alignof(cost_tracker_out_t )*/, 128UL /* sizeof(cost_tracker_out_t ) */        ),    \
      8UL   /* alignof(account_cost_map_t) */, FD_COST_TRACKER_CHAIN_CNT_EST*4UL /*sizeof(uint)*/ +24UL /* sizeof(account_cost_map_t) */ ), \
      4UL   /* alignof(account_cost_t) */,     FD_RUNTIME_MAX_TXN_ACC_WRITES_PER_SLOT*40UL /*sizeof(account_cost_t)*/ ), \
      128UL ) )                                               \

#define FD_COST_TRACKER_MAGIC (0xF17EDA2CE7C05170UL) /* FIREDANCER COST V0 */

#define FD_COST_TRACKER_ALIGN (128UL)

struct __attribute__((aligned(FD_COST_TRACKER_ALIGN))) fd_cost_tracker {
  ulong block_cost;
  ulong allocated_accounts_data_size;

  ulong block_cost_limit;
  ulong account_cost_limit;
  ulong data_size_limit;

  int larger_max_cost_per_block;
};

typedef struct fd_cost_tracker fd_cost_tracker_t;

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/transaction_cost.rs#L153-L161 */

struct fd_usage_cost_details {
  uint  signature_cost;
  uint  write_lock_cost;
  uint  data_bytes_cost;
  uint  programs_execution_cost;
  uint  loaded_accounts_data_size_cost;
  ulong allocated_accounts_data_size;
};
typedef struct fd_usage_cost_details fd_usage_cost_details_t;

struct fd_transaction_cost {
  fd_usage_cost_details_t transaction;
};

typedef struct fd_transaction_cost fd_transaction_cost_t;

FD_PROTOTYPES_BEGIN

static inline int
fd_cost_tracker_err_to_runtime_err( int err ) {
  switch( err ) {
    case FD_COST_TRACKER_SUCCESS:
      return FD_RUNTIME_EXECUTE_SUCCESS;
    case FD_COST_TRACKER_ERROR_WOULD_EXCEED_BLOCK_MAX_LIMIT:
      return FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_BLOCK_COST_LIMIT;
    case FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT:
      return FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT;
    case FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT:
      return FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT;
    case FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT:
      return FD_RUNTIME_TXN_ERR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT;
    default:
      FD_LOG_CRIT(( "unexpected cost tracker error %d", err ));
  }
}

FD_FN_CONST ulong
fd_cost_tracker_align( void );

FD_FN_CONST ulong
fd_cost_tracker_footprint( void );

void *
fd_cost_tracker_new( void * shmem,
                     int    larger_max_cost_per_block,
                     ulong  seed );

fd_cost_tracker_t *
fd_cost_tracker_join( void * shct );

void
fd_cost_tracker_init( fd_cost_tracker_t *      cost_tracker,
                      fd_features_t const *    features,
                      fd_slot_params_t const * slot_params,
                      ulong                    slot );

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L323-L328 */
FD_FN_PURE uint
fd_cost_tracker_calculate_loaded_accounts_data_size_cost( fd_txn_out_t const * txn_out );

/* fd_cost_tracker_calculate_cost_and_add takes a transaction,
   calculates the cost of the transaction in terms of various block
   level limits and adds it to the cost tracker.  If the incremental
   transaction fits in the block, then the cost tracking is updated and
   FD_COST_TRACKER_SUCCESS is returned.  If the transaction does not
   fit then FD_COST_TRACKER_ERROR_{*} is returned depending on what
   limit is violated.

   This function assumes that the caller is responsible for managing
   concurrent callers.

   This function represents the Agave client function:
   `CostModel::calculate_cost_for_executed_transaction()`

    https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L69-L95
*/

void
fd_cost_tracker_calculate_cost( fd_bank_t *         bank,
                                fd_txn_in_t const * txn_in,
                                fd_txn_out_t *      txn_out );

/* fd_cost_tracker_try_add_cost takes the cost as calculated by
   fd_cost_tracker_calculate_cost and tries to accumulate it into the
   cost tracker.  If the cost fits, the cost is added and
   FD_COST_TRACKER_SUCCESS is returned.  If the cost does not fit, the
   cost will not be updated and FD_COST_TRACKER_ERROR_* is returned
   depending on what limit is violated.

   This function is the Agave client function: 'CostTracker::try_add()'
   https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L163-L173 */

int
fd_cost_tracker_try_add_cost( fd_cost_tracker_t * cost_tracker,
                              fd_txn_out_t *      txn_out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h */
