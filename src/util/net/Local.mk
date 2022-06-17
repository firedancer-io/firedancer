$(call add-hdrs,fd_eth.h)
$(call add-objs,fd_eth,fd_util)
$(call make-unit-test,test_eth,test_eth,fd_util)
