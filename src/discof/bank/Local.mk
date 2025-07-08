ifdef FD_HAS_ATOMIC
ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call add-objs,fd_bank_tile,fd_discof)
endif
endif
endif
