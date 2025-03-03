#ifndef HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h
#define HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h

/* Combined logic from Agave's `cost_model.rs` and `cost_tracker.rs` for validating
   block limits, specifically during replay. */

#include "../../disco/pack/fd_pack_cost.h"
#include "../vm/fd_vm_base.h"
#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "fd_system_ids.h"
#include "fd_executor.h"

struct __attribute__((aligned(8UL))) fd_cost_tracker {
	ulong magic; /* ==FD_COST_TRACKER_MAGIC */

	/* Limits set at initialization and at the epoch boundary (if new feature activations change this) */
	ulong account_cost_limit;
	ulong block_cost_limit;
	ulong vote_cost_limit;

	/* `cost_by_writable_accounts` is represented as a map in Agave with capacity of 4096 and maps
	   account keys to usage costs. This map gets aggregated throughout a block and is used to validate
		 block limits. */
  fd_account_costs_t cost_by_writable_accounts;

	/* Stats aggregated intra-block */
	ulong block_cost;
	ulong vote_cost;
	ulong transaction_count;
	ulong allocated_accounts_data_size;
	ulong transaction_signature_count;
	ulong secp256k1_instruction_signature_count;
	ulong ed25519_instruction_signature_count;
	ulong secp256r1_instruction_signature_count;
};
typedef struct fd_cost_tracker fd_cost_tracker_t;

#define FD_COST_TRACKER_MAGIC ( 0x1ae35a7b6e06f9cc ) // random value

// https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L20
#define WRITE_LOCK_UNITS ( 300UL )

// https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L42
#define MAX_BLOCK_ACCOUNTS_DATA_SIZE_DELTA ( 100000000UL )

// https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L34
#define MAX_WRITABLE_ACCOUNT_UNITS ( 12000000UL )

// https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L28
#define MAX_BLOCK_UNITS ( 48000000UL )

// https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L29C11-L29C36
#define MAX_BLOCK_UNITS_SIMD_0207 ( 50000000UL )

// https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/block_cost_limits.rs#L38
#define MAX_VOTE_UNITS ( 36000000UL )

// https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L15
#define WRITABLE_ACCOUNTS_PER_BLOCK ( 4096UL )

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L18-L33 */
#define FD_COST_TRACKER_SUCCESS																		  ( 0 )
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_BLOCK_MAX_LIMIT          ( 1 )
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_VOTE_MAX_LIMIT           ( 2 )
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT        ( 3 )
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT ( 4 )
#define FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT ( 5 )

FD_PROTOTYPES_BEGIN

fd_cost_tracker_t *
fd_cost_tracker_new( void *      mem,
                     fd_spad_t * runtime_spad );

void
fd_cost_tracker_reset( fd_cost_tracker_t *  		  self,
											 fd_exec_slot_ctx_t const * slot_ctx,
											 fd_spad_t * 				  		  spad );

/* Modeled after `CostModel::calculate_cost_for_executed_transaction()`.
   Used to compute transaction cost information for executed transactions.

   https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L69-L95 */
fd_transaction_cost_t
fd_calculate_cost_for_executed_transaction( fd_exec_txn_ctx_t const * txn_ctx,
																					  fd_spad_t * 							spad );

/* Modeled after `CostTracker::try_add()`. Checks to see if the transaction cost
   would fit in this block. Returns an error on failure.

	 https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_tracker.rs#L163-L173 */
int
fd_cost_tracker_try_add( fd_cost_tracker_t *  				 self,
		   								 	 fd_exec_txn_ctx_t const *     txn_ctx,
												 fd_transaction_cost_t const * tx_cost );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h */
