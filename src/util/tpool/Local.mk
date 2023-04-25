$(call add-hdrs,fd_tpool.h)
$(call add-objs,fd_tpool,fd_util)
$(call make-unit-test,test_tpool,test_tpool,fd_util)

