ifdef FD_HAS_ATOMIC
ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call add-hdrs,fd_bank_abi.h)
$(call add-objs,fd_bank_abi,fd_discof)
endif
endif
endif
