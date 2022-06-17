$(call add-hdrs,fd_log.h)
$(call add-objs,fd_log,fd_util)
$(call make-unit-test,test_log,test_log,fd_util)

