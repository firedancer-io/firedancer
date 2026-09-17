$(call add-hdrs,fd_tpool.h fd_map_reduce.h)
$(call add-objs,fd_tpool,fd_util_extra)
$(call make-unit-test,test_tpool,test_tpool,fd_util_extra fd_util)

