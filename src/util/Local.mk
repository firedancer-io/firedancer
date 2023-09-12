$(call make-lib,fd_util)
$(call add-hdrs,fd_util_base.h fd_util.h)
$(call add-objs,fd_hash fd_util,fd_util)
$(call make-unit-test,test_util,test_util,fd_util)
$(call run-unit-test,test_util,)

ifndef FD_HAS_UBSAN
# The point of test_util_base is to diagnose compatibility of the build
# target with the FD machine model.  It does this in part by extensively
# probing the linguistic UB/IB behaviors of the target.  As such, we
# expect this test to fail by design if running under ubsan and thus
# don't bother building it if FD_HAS_UBSAN is defined.
$(call make-unit-test,test_util_base,test_util_base,fd_util)
$(call run-unit-test,test_util_base,)
endif
