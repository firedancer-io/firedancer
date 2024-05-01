ifdef FD_HAS_INT128
$(call add-hdrs,fd_txn_generate.h)
$(call add-objs,fd_txn_generate,fd_flamenco)
endif
