ifdef FD_HAS_INT128
$(call add-objs,fd_fec_repair,fd_discof)
ifdef FD_HAS_SSE
$(call add-objs,fd_repair_tile,fd_discof)
endif
endif
