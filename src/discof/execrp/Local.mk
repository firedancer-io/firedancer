ifdef FD_HAS_HOSTED
ifdef FD_HAS_ALLOCA
$(call add-objs,fd_execrp_tile,fd_discof)
ifdef FD_HAS_INT128
$(call make-unit-test,test_execrp_tile,test_execrp_tile,fd_discof fd_disco fd_choreo fd_flamenco_test fd_flamenco fd_funk fd_tango fd_ballet fd_util)
$(call run-unit-test,test_execrp_tile)
endif
endif
endif
