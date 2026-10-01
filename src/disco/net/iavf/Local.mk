ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-objs,fd_iavf,fd_disco)
$(call make-unit-test,test_iavf_tile,test_iavf_tile,fd_disco fd_util)
$(call run-unit-test,test_iavf_tile)
endif
endif
