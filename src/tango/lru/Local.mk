$(call add-hdrs,fd_lru.h fd_list.h)
$(call add-objs,fd_lru fd_list,fd_tango)
$(call make-unit-test,test_lru,test_lru,fd_tango fd_util)
$(call make-unit-test,test_list,test_list,fd_tango fd_util)
