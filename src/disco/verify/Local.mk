ifdef FD_HAS_ALLOCA
$(call add-objs,fd_verify_tile,fd_disco)
$(call make-unit-test,test_verify,test_verify,fd_ballet fd_tango fd_util)
$(call make-unit-test,test_verify_tile,test_verify_tile,fd_disco fd_ballet fd_tango fd_util)
$(call run-unit-test,test_verify)
$(call run-unit-test,test_verify_tile)
endif
