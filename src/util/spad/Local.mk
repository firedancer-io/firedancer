$(call add-hdrs,fd_spad.h)
# checked impls: production under handholding/deepasan/msan, else test-only
ifneq ($(FD_HAS_HANDHOLDING)$(FD_HAS_DEEPASAN)$(FD_HAS_MSAN),)
$(call add-objs,fd_spad,fd_util)
else
$(call add-objs,fd_spad,fd_util_extra)
endif
$(call make-unit-test,test_spad,test_spad,fd_util_extra fd_util)
$(call run-unit-test,test_spad)
