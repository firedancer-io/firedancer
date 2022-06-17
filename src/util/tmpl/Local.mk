$(call add-hdrs,fd_smallset.c fd_set.c fd_sort.c)
$(call make-unit-test,test_smallset,test_smallset,fd_util)
$(call make-unit-test,test_set,test_set,fd_util)
$(call make-unit-test,test_sort,test_sort,fd_util)
