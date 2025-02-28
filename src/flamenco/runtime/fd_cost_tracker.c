#include "fd_cost_tracker.h"

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L152-L187 */
FD_FN_PURE static inline ulong
get_signature_cost( fd_exec_txn_ctx_t const * txn_ctx ) {
	fd_txn_t const *      txn     = txn_ctx->txn_descriptor;
	fd_rawtxn_b_t const * txn_raw = txn_ctx->_txn_raw;

	/* Compute signature counts (both normal + precompile) */
	ulong signature_cost                       = fd_ulong_sat_mul( txn->signature_cnt, FD_PACK_COST_PER_SIGNATURE );
	ulong num_secp256k1_instruction_signatures = 0UL;
	ulong num_ed25519_instruction_signatures   = 0UL;
	ulong num_secp256r1_instruction_signatures = 0UL;

	for( ushort i=0; i<txn->instr_cnt; i++ ) {
		fd_txn_instr_t const * instr = &txn->instr[ i ];
		if( instr->data_sz==0UL ) continue;

    fd_acct_addr_t const * accounts   = fd_txn_get_acct_addrs( txn, txn_raw );
		fd_acct_addr_t const * prog_id    = accounts + instr->program_id;
		uchar const *          instr_data = fd_txn_get_instr_data( instr, txn_raw );

		if( fd_memeq( prog_id, fd_solana_ed25519_sig_verify_program_id.key, sizeof(fd_pubkey_t) ) ) {
			num_secp256k1_instruction_signatures += (ulong)instr_data[ 0 ];
		} else if( fd_memeq( prog_id, fd_solana_keccak_secp_256k_program_id.key, sizeof(fd_pubkey_t) ) ) {
			num_secp256k1_instruction_signatures += (ulong)instr_data[ 0 ];
		} else if( fd_memeq( prog_id, fd_solana_secp256r1_program_id.key, sizeof(fd_pubkey_t) ) ) {
			num_secp256r1_instruction_signatures += (ulong)instr_data[ 0 ];;
		}
	}

	/* No direct permalink, just factored out for readability */
	ulong secp256k1_verify_cost = fd_ulong_sat_mul( FD_PACK_COST_PER_SECP256K1_SIGNATURE, num_secp256k1_instruction_signatures );

	/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L155-L160 */
	ulong ed25519_verify_cost;
	if( FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, ed25519_precompile_verify_strict ) ) {
		ed25519_verify_cost = fd_ulong_sat_mul( FD_PACK_COST_PER_ED25519_SIGNATURE, num_ed25519_instruction_signatures );
	} else {
		ed25519_verify_cost = fd_ulong_sat_mul( FD_PACK_COST_PER_NON_STRICT_ED25519_SIGNATURE, num_ed25519_instruction_signatures );
	}

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L162-L167 */
	ulong secp256r1_verify_cost = 0UL;
	if( FD_FEATURE_ACTIVE( txn_ctx->slot_ctx, enable_secp256r1_precompile ) ) {
		secp256r1_verify_cost = fd_ulong_sat_mul( FD_PACK_COST_PER_SECP256R1_SIGNATURE, num_secp256r1_instruction_signatures );
	}

	/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L169-L186 */
	return fd_ulong_sat_add( signature_cost,
											     fd_ulong_sat_add( secp256k1_verify_cost, fd_ulong_sat_add( ed25519_verify_cost,
																																							        secp256r1_verify_cost ) ) );
}

FD_FN_PURE ulong
fd_calculate_cost_for_executed_transaction( fd_exec_txn_ctx_t const * txn_ctx ) {
	/* Simple vote transactions have a fixed cost of 3428 CUs.
	https://github.com/anza-xyz/agave/blob/v2.1.0/cost-model/src/cost_model.rs#L83-L85 */
	if( fd_txn_is_simple_vote_transaction( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw ) ) {
		return FD_PACK_SIMPLE_VOTE_COST;
	}

	ulong total_cost = 0UL;

	/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L78-L81 */

	/* https://github.com/anza-xyz/agave/blob/v2.1.0/cost-model/src/cost_model.rs#L86-L87 */


	return total_cost;
}
