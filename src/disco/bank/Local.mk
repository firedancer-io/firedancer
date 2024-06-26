ifdef FD_HAS_ATOMIC
$(call add-hdrs,fd_bank_abi.h fd_txncache.h fd_rwlock.h)
$(call add-objs,fd_bank_abi fd_txncache,fd_disco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_txncache,test_txncache,fd_disco fd_util)
$(call run-unit-test,test_txncache,)
endif
endif
