#ifndef HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h
#define HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h

#include "../../disco/pack/fd_pack_cost.h"
#include "../vm/fd_vm_base.h"
#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "fd_system_ids.h"
#include "fd_executor.h"

struct __attribute__((aligned(8UL))) fd_cost_tracker {
	/* Limits set at initialization and at the epoch boundary (if new feature activations change this) */
	ulong account_cost_limit;
	ulong block_cost_limit;
	ulong vote_cost_limit;

	/* Stats aggregated inter-block */
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

#define WRITE_LOCK_UNITS ( 300UL )

FD_PROTOTYPES_BEGIN

/* Modeled after `CostModel::calculate_cost_for_executed_transaction()`.
   Used to compute transaction cost information for executed transactions.

   https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L69-L95 */
fd_transaction_cost_t
fd_calculate_cost_for_executed_transaction( fd_exec_txn_ctx_t const * txn_ctx,
																					  fd_spad_t * 							spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_cost_tracker_h */
