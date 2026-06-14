$(call add-hdrs,fd_falcon.h)
$(call add-objs,fd_falcon,fd_ballet)
$(call make-unit-test,test_falcon,test_falcon,fd_ballet fd_util)
$(call run-unit-test,test_falcon)
