ifdef FD_HAS_ALLOCA
$(call add-hdrs,fd_store.h fd_ledger.h)
$(call add-objs,fd_store,fd_disco)
$(call add-objs,fd_ledger,fd_disco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_store,test_store,fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_store)
$(call make-unit-test,test_ledger,test_ledger,fd_disco fd_ballet fd_util)
$(call run-unit-test,test_ledger)
endif
endif
