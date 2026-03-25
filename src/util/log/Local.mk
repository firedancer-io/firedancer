$(call add-hdrs,fd_log.h)
$(call add-objs,fd_log,fd_util)
ifdef FD_HAS_HOSTED
$(call add-objs,fd_backtrace,fd_util)
endif
$(call make-unit-test,test_log,test_log,fd_util)
