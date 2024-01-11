ifdef FD_HAS_INT128
$(call add-hdrs,fd_bpf_loader_v4_program.h)
$(call add-objs,fd_bpf_loader_v4_program,fd_flamenco)
endif
