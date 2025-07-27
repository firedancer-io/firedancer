ifdef FD_HAS_INT128
$(call add-hdrs,fd_store.h)
$(call add-objs,fd_store,fd_disco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_store,test_store,fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_store)
endif
endif
