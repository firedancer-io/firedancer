ifdef FD_HAS_INT128
$(call add-hdrs,fd_address_lookup_table_program.h)
$(call add-objs,fd_address_lookup_table_program,fd_flamenco)

$(call add-hdrs,fd_bpf_loader_v1_program.h)
$(call add-objs,fd_bpf_loader_v1_program,fd_flamenco)

$(call add-hdrs,fd_bpf_loader_v4_program.h)
$(call add-objs,fd_bpf_loader_v4_program,fd_flamenco)

$(call add-hdrs,fd_config_program.h)
$(call add-objs,fd_config_program,fd_flamenco)

$(call add-hdrs,fd_ed25519_program.h)
$(call add-objs,fd_ed25519_program,fd_flamenco)

$(call add-hdrs,fd_system_program.h)
$(call add-objs,fd_system_program fd_system_program_nonce,fd_flamenco)
endif
