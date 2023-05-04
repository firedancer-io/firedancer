$(call add-hdrs,fd_tilegroup.h)
$(call add-objs,fd_tilegroup,fd_util)

$(call make-unit-test,test_tilegroup,test_tilegroup,fd_util)
$(call run-unit-test,test_tilegroup,)

