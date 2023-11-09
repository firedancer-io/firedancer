$(call add-hdrs,fd_hist.h)
$(call make-unit-test,test_hist,test_hist,fd_util)
$(call run-unit-test,test_hist,)
