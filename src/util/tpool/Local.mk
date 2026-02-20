$(call add-hdrs,fd_tpool.h fd_map_reduce.h)
ifdef FD_HAS_CXX
$(call add-objs,fd_tpool_cxx,fd_util)
else
$(call add-objs,fd_tpool,fd_util)
endif
$(call make-unit-test,test_tpool,test_tpool,fd_util)

