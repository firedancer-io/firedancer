ifdef FD_HAS_INT128
$(call add-objs,fd_zksdk_zero_ciphertext,fd_flamenco)
$(call add-objs,fd_zksdk_ciphertext_ciphertext_equality,fd_flamenco)
$(call add-objs,fd_zksdk_ciphertext_commitment_equality,fd_flamenco)
$(call add-objs,fd_zksdk_pubkey_validity,fd_flamenco)
$(call add-objs,fd_zksdk_percentage_with_cap,fd_flamenco)
$(call add-objs,fd_zksdk_batched_range_proof_u64,fd_flamenco)
$(call add-objs,fd_zksdk_batched_range_proof_u128,fd_flamenco)
$(call add-objs,fd_zksdk_batched_range_proof_u256,fd_flamenco)
$(call add-objs,fd_zksdk_grouped_ciphertext_2_handles_validity,fd_flamenco)
$(call add-objs,fd_zksdk_batched_grouped_ciphertext_2_handles_validity,fd_flamenco)
$(call add-objs,fd_zksdk_grouped_ciphertext_3_handles_validity,fd_flamenco)
$(call add-objs,fd_zksdk_batched_grouped_ciphertext_3_handles_validity,fd_flamenco)
endif
