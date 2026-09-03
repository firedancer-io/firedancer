ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call add-hdrs,fd_sleep.h)
$(call add-objs,fd_sleep fd_mwaitx_tile,fd_disco)
$(call make-unit-test,test_sleep,test_sleep,fd_disco fd_tango fd_util)
$(call run-unit-test,test_sleep)
endif
endif
