#ifndef HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h
#define HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h

#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "../../disco/pack/fd_pack_cost.h"
#include "fd_system_ids.h"

struct __attribute__((aligned(8UL))) fd_cost_tracker {
	/* Limits set at initialization and at the epoch boundary (if new feature activations change this) */
	ulong account_cost_limit;
	ulong block_cost_limit;
	ulong vote_cost_limit;

	/* Stats aggregated between blocks */
	ulong total_executed_units;
	ulong total_loaded_data_sz;
};
typedef struct fd_cost_tracker fd_cost_tracker_t;

FD_PROTOTYPES_BEGIN

/* Modelled after `CostModel::calculate_cost_for_executed_transaction()` and `TransactionCost::sum()` in Agave.
   Used to compute the transaction cost (in CUs) for a given transaction.

   https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L69-L95 */
FD_FN_PURE ulong
fd_calculate_cost_for_executed_transaction( fd_exec_txn_ctx_t const * txn_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h */
