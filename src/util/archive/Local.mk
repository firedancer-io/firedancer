$(call add-hdrs,fd_ar.h)
$(call add-objs,fd_ar,fd_util)
$(call make-unit-test,test_ar,test_ar,fd_util)
