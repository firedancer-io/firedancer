$(call add-hdrs,fd_list.h)
$(call add-objs,fd_list,fd_util)
$(call make-unit-test,test_list,test_list,fd_util)
$(call run-unit-test,test_list,)
