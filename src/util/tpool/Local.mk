$(call add-hdrs,fd_tpool.h fd_map_reduce.h)
$(call add-objs,fd_tpool,fd_util_test)
$(call make-unit-test,test_tpool,test_tpool,fd_util_test fd_util)

