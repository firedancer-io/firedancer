#include "fd_cost_tracker.h"

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L323-L328 */
FD_FN_PURE static inline ulong
calculate_loaded_accounts_data_size_cost( fd_exec_txn_ctx_t const * txn_ctx ) {
	ulong cost = fd_ulong_sat_sub( fd_ulong_sat_add( txn_ctx->loaded_accounts_data_size,
												  			    							 ACCOUNT_DATA_COST_PAGE_SIZE ),
																 1UL );
  cost /= ACCOUNT_DATA_COST_PAGE_SIZE;
	return fd_ulong_sat_mul( cost, FD_VM_HEAP_COST );
}

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L313-L321 */
FD_FN_PURE static inline ulong
get_instructions_data_cost( fd_exec_txn_ctx_t const * txn_ctx ) {
	ulong total_instr_data_sz = 0UL;
	for( ushort i=0; i<txn_ctx->txn_descriptor->instr_cnt; i++ ) {
		total_instr_data_sz += txn_ctx->txn_descriptor->instr[ i ].data_sz;
	}
	return total_instr_data_sz / FD_PACK_INV_COST_PER_INSTR_DATA_BYTE;
}

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
			num_secp256r1_instruction_signatures += (ulong)instr_data[ 0 ];
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
					         				 fd_ulong_sat_add( secp256k1_verify_cost,
											   										 fd_ulong_sat_add( ed25519_verify_cost,
																															 secp256r1_verify_cost ) ) );
}

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L190-L192 */
FD_FN_PURE static inline ulong
get_write_lock_cost( ulong num_write_locks ) {
	return fd_ulong_sat_mul( num_write_locks, WRITE_LOCK_UNITS );
}

/* Loop through all instructions here and deserialize the instruction data to try to determine any
   system program allocations done.

	 https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L367-L386 */
static inline ulong
calculate_allocated_accounts_data_size( fd_exec_txn_ctx_t const * txn_ctx,
																				fd_spad_t * 							spad ) {
  FD_SPAD_FRAME_BEGIN( spad ) {
		fd_txn_t const *      txn     = txn_ctx->txn_descriptor;
		fd_rawtxn_b_t const * txn_raw = txn_ctx->_txn_raw;

		ulong allocated_accounts_data_size = 0UL;
		for( ushort i=0UL; i<txn->instr_cnt; i++ ) {
			fd_txn_instr_t const * instr      = &txn->instr[ i ];
			fd_acct_addr_t const * accounts   = fd_txn_get_acct_addrs( txn, txn_raw );
			fd_acct_addr_t const * prog_id    = accounts + instr->program_id;
			uchar const *          instr_data = fd_txn_get_instr_data( instr, txn_raw );

			if( instr->data_sz==0UL || !fd_memeq( prog_id, &fd_solana_system_program_id, sizeof(fd_pubkey_t) ) ) continue;

			fd_bincode_decode_ctx_t decode = {
				.data    = instr_data,
				.dataend = instr_data + instr->data_sz
			};

			ulong total_sz   = 0UL;
			int   decode_err = fd_system_program_instruction_decode_footprint( &decode, &total_sz );
			if( FD_UNLIKELY( decode_err ) ) continue;

			uchar * mem = fd_spad_alloc( spad, fd_system_program_instruction_align(), total_sz );
			if( FD_UNLIKELY( !mem ) ) {
				FD_LOG_ERR(( "Unable to allocate memory for system program instruction" ));
			}

			/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L330-L346 */
			fd_system_program_instruction_t * instruction = fd_system_program_instruction_decode( mem, &decode );
			ulong 														space				= 0UL;

			switch( instruction->discriminant ) {
				case fd_system_program_instruction_enum_create_account: {
					space = instruction->inner.create_account.space;
					break;
				}
				case fd_system_program_instruction_enum_create_account_with_seed: {
					space = instruction->inner.create_account_with_seed.space;
					break;
				}
				case fd_system_program_instruction_enum_allocate: {
					space = instruction->inner.allocate;
					break;
				}
				case fd_system_program_instruction_enum_allocate_with_seed: {
					space = instruction->inner.allocate_with_seed.space;
					break;
				}
			}

			/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L373-L380 */
			if( FD_UNLIKELY( space>FD_ACC_SZ_MAX ) ) return 0UL;

			allocated_accounts_data_size = fd_ulong_sat_add( allocated_accounts_data_size, space );
		}

		/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L396-L397 */
		return fd_ulong_min( 2UL*FD_ACC_SZ_MAX, allocated_accounts_data_size );
	} FD_SPAD_FRAME_END;
}

/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L123-L149 */
static inline ulong
calculate_non_vote_transaction_cost( fd_exec_txn_ctx_t const * txn_ctx,
																		 ulong 										 loaded_accounts_data_size_cost,
																		 ulong 										 allocated_accounts_data_size,
																		 fd_spad_t * 							 spad ) {
  /* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L132 */
  ulong signature_cost = get_signature_cost( txn_ctx );

	/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L133 */
	ulong write_lock_cost = get_write_lock_cost( fd_txn_account_cnt( txn_ctx->txn_descriptor, FD_TXN_ACCT_CAT_WRITABLE ) );

	/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L135-L136 */
	ulong allocated_accounts_data_size = calculate_allocated_accounts_data_size( txn_ctx, spad );
}

ulong
fd_calculate_cost_for_executed_transaction( fd_exec_txn_ctx_t const * txn_ctx,
																						fd_spad_t * 							spad ) {
	/* Simple vote transactions have a fixed cost of 3428 CUs.
	https://github.com/anza-xyz/agave/blob/v2.1.0/cost-model/src/cost_model.rs#L83-L85 */
	if( fd_txn_is_simple_vote_transaction( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw ) ) {
		return FD_PACK_SIMPLE_VOTE_COST;
	}

	/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L78-L81 */
	ulong loaded_accounts_data_size_cost = calculate_loaded_accounts_data_size_cost( txn_ctx );

	/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L82-L83 */
	ulong allocated_accounts_data_size = get_instructions_data_cost( txn_ctx );

	/* https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/cost_model.rs#L85-L93 */
	return calculate_non_vote_transaction_cost( txn_ctx, loaded_accounts_data_size_cost, allocated_accounts_data_size, spad );
}
