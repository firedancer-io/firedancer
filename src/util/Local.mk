$(call make-lib,fd_util)
$(call add-hdrs,fd_util_base.h fd_util.h)
$(call add-objs,fd_hash fd_util,fd_util)
$(call make-unit-test,test_util_base,test_util_base,fd_util)
$(call make-unit-test,test_util,test_util,fd_util)

