ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX
$(call make-lib,fd_fibre)
$(call add-objs,fd_fibre,fd_fibre)
$(call make-unit-test,test_fibre,test_fibre,fd_fibre fd_util)
$(call run-unit-test,test_fibre)
endif
endif
