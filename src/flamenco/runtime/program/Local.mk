ifdef FD_HAS_INT128
$(call add-hdrs,fd_bpf_loader_v1_program.h)
$(call add-objs,fd_bpf_loader_v1_program,fd_flamenco)

$(call add-hdrs,fd_bpf_loader_v4_program.h)
$(call add-objs,fd_bpf_loader_v4_program,fd_flamenco)

$(call add-hdrs,fd_config_program.h)
$(call add-objs,fd_config_program,fd_flamenco)

$(call add-hdrs,fd_ed25519_program.h)
$(call add-objs,fd_ed25519_program,fd_flamenco)
endif
