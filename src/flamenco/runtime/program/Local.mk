### Reusable

$(call add-hdrs,fd_builtin_programs.h)
$(call add-objs,fd_builtin_programs,fd_flamenco)

$(call add-hdrs,fd_bpf_loader_serialization.h)
$(call add-objs,fd_bpf_loader_serialization,fd_flamenco)

### Precompiles

$(call add-hdrs,fd_precompiles.h)
$(call add-objs,fd_precompiles,fd_flamenco)

### Native programs

$(call add-hdrs,fd_address_lookup_table_program.h)
$(call add-objs,fd_address_lookup_table_program,fd_flamenco)

ifdef FD_HAS_SECP256K1
$(call add-hdrs,fd_bpf_loader_program.h)
$(call add-objs,fd_bpf_loader_program,fd_flamenco)
endif

$(call add-hdrs,fd_loader_v4_program.h)
$(call add-objs,fd_loader_v4_program,fd_flamenco)

$(call add-hdrs,fd_config_program.h)
$(call add-objs,fd_config_program,fd_flamenco)

$(call add-hdrs,fd_compute_budget_program.h)
$(call add-objs,fd_compute_budget_program,fd_flamenco)

$(call add-hdrs,fd_stake_program.h)
$(call add-objs,fd_stake_program,fd_flamenco)

$(call add-hdrs,fd_system_program.h)
$(call add-objs,fd_system_program fd_system_program_nonce,fd_flamenco)

$(call add-hdrs,fd_vote_program.h)
$(call add-objs,fd_vote_program,fd_flamenco)

$(call add-hdrs,fd_zk_elgamal_proof_program.h)
$(call add-objs,fd_zk_elgamal_proof_program,fd_flamenco)

$(call add-hdrs,fd_native_cpi.h)
$(call add-objs,fd_native_cpi,fd_flamenco)
