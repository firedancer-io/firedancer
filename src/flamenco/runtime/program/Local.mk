ifdef FD_HAS_SECP256K1
$(call add-hdrs, \
	fd_system_program.h \
	fd_vote_program.h \
	fd_stake_program.h \
	fd_builtin_programs.h \
	fd_compute_budget_program.h \
	fd_config_program.h \
	fd_bpf_loader_program.h \
	fd_bpf_upgradeable_loader_program.h \
	fd_bpf_deprecated_loader_program.h \
	fd_bpf_loader_v4_program.h \
	fd_ed25519_program.h \
	fd_secp256k1_program.h \
	fd_address_lookup_table_program.h \
	fd_zk_token_proof_program.h \
	fd_bpf_loader_serialization.h \
	fd_program_util.h \
)

$(call add-objs,fd_system_program,fd_flamenco)
$(call add-objs,fd_nonce_program,fd_flamenco)
$(call add-objs,fd_vote_program,fd_flamenco)
$(call add-objs,fd_stake_program,fd_flamenco)
$(call add-objs,fd_builtin_programs,fd_flamenco)
$(call add-objs,fd_compute_budget_program,fd_flamenco)
$(call add-objs,fd_config_program,fd_flamenco)
$(call add-objs,fd_bpf_loader_program,fd_flamenco)
$(call add-objs,fd_bpf_upgradeable_loader_program,fd_flamenco)
$(call add-objs,fd_bpf_deprecated_loader_program,fd_flamenco)
$(call add-objs,fd_bpf_loader_v4_program,fd_flamenco)
$(call add-objs,fd_ed25519_program,fd_flamenco)
$(call add-objs,fd_secp256k1_program,fd_flamenco)
$(call add-objs,fd_address_lookup_table_program,fd_flamenco)
$(call add-objs,fd_zk_token_proof_program,fd_flamenco)
$(call add-objs,fd_bpf_loader_serialization,fd_flamenco)
endif
