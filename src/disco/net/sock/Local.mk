ifdef FD_HAS_HOSTED
$(call add-objs,fd_sock_tile,fd_disco)
ifdef FD_HAS_LINUX
$(call make-unit-test,test_sock_tile,test_sock_tile,fd_disco fd_tango fd_util)
$(call run-unit-test,test_sock_tile)
endif
endif
