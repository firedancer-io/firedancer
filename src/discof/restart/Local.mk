ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call add-hdrs,fd_restart.h)
$(call add-objs,fd_restart,fd_discof)
$(call add-objs,fd_restart_tile,fd_discof)
endif
endif
