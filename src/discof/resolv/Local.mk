ifdef FD_HAS_HOSTED
$(call add-objs,fd_resolv_tile,fd_discof)
$(call make-unit-test,test_resolv_tile,test_resolv_tile,fd_discof fd_disco fd_flamenco_test fd_flamenco fd_funk fd_tango fd_ballet fd_util)
$(call run-unit-test,test_resolv_tile)
endif
