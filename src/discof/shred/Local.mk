ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call add-objs,fd_shred_cap,fd_discof,fd_flamenco)
endif
endif
