ifdef FD_HAS_ALLOCA
$(call add-hdrs,fd_store.h fd_shredb.h)
$(call add-objs,fd_store,fd_disco)
$(call add-objs,fd_shredb,fd_disco)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_store,test_store,fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_store)
$(call make-unit-test,test_shredb,test_shredb,fd_disco fd_ballet fd_util)
$(call run-unit-test,test_shredb)
endif
endif
