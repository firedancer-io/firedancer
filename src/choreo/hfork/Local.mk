$(call add-hdrs,fd_hfork.h)
$(call add-objs,fd_hfork,fd_choreo)
ifdef FD_HAS_HOSTED
ifdef FD_HAS_SECP256K1
$(call make-unit-test,test_hfork,test_hfork,fd_choreo fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_hfork)
endif
endif
