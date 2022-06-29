$(call make-lib,fd_util)
$(call add-hdrs,fd_util_base.h)
$(call add-objs,fd_hash fd_util,fd_util)
$(call make-unit-test,test_base,test_base,fd_util)
$(call make-unit-test,test_util,test_util,fd_util)

