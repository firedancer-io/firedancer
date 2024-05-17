ifdef FD_HAS_INT128

### Reusable

$(call add-hdrs,fd_builtin_programs.h)
$(call add-objs,fd_builtin_programs,fd_flamenco)

$(call add-hdrs,fd_bpf_loader_serialization.h)
$(call add-objs,fd_bpf_loader_serialization,fd_flamenco)

$(call add-hdrs,fd_bpf_program_util.h)
$(call add-objs,fd_bpf_program_util,fd_flamenco)

### Precompiles

$(call add-hdrs,fd_precompiles.h)
$(call add-objs,fd_precompiles,fd_flamenco)

### Native programs

$(call add-hdrs,fd_address_lookup_table_program.h)
$(call add-objs,fd_address_lookup_table_program,fd_flamenco)

$(call add-hdrs,fd_bpf_loader_v1_program.h)
$(call add-objs,fd_bpf_loader_v1_program,fd_flamenco)

$(call add-hdrs,fd_bpf_loader_v2_program.h)
$(call add-objs,fd_bpf_loader_v2_program,fd_flamenco)

$(call add-hdrs,fd_bpf_loader_v3_program.h)
$(call add-objs,fd_bpf_loader_v3_program,fd_flamenco)

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

$(call add-hdrs,fd_native_cpi.h)
$(call add-objs,fd_native_cpi,fd_flamenco)
endif
