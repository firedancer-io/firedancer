$(call make-lib,fd_funk)
$(call add-hdrs,fd_funk_base.h)
$(call add-objs,fd_funk_base,fd_funk)
$(call make-unit-test,test_funk_base,test_funk_base,fd_funk fd_util)
$(call run-unit-test,test_funk_base,)

