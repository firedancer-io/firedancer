ifdef FD_HAS_HOSTED
$(call add-objs,fd_adminctl fd_admin_tile,fd_discof)
$(call make-unit-test,test_admin_tile,test_admin_tile,fd_discof fd_disco fd_flamenco fd_tango fd_ballet fd_util)
$(call run-unit-test,test_admin_tile)
endif
