ifdef FD_HAS_ATOMIC
$(call add-hdrs,fd_bank_abi.h)
$(call add-objs,fd_bank_abi fd_bank_tile,fd_discoh)
endif
