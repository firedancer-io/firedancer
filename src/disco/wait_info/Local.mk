ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_wait_info.h)
$(call make-unit-test,test_wait_info,test_wait_info,fd_disco fd_util)
$(call run-unit-test,test_wait_info)
endif
endif
