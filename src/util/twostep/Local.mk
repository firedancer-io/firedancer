ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call make-lib,fd_twostep)
$(call add-objs,fd_twostep,fd_twostep)
$(call make-unit-test,test_twostep,test_twostep,fd_twostep fd_fibre fd_util)
# $(call run-unit-test,test_twostep)
endif
endif
