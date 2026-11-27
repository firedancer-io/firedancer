ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-objs,fd_vhost,fd_disco)
$(call add-objs,fd_vhost_tile,fd_disco)
$(call make-unit-test,test_vhost,test_vhost,fd_disco fd_waltz fd_tango fd_util)
$(call run-unit-test,test_vhost)
endif
endif
