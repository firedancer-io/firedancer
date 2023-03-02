$(call add-hdrs,fd_sqrt.h fd_fxp.h fd_stat.h)
$(call add-objs,fd_stat,fd_util)
$(call make-unit-test,test_sqrt,test_sqrt,fd_util)
$(call make-unit-test,test_fxp,test_fxp,fd_util)
$(call make-unit-test,test_stat,test_stat,fd_util)
$(call run-unit-test,test_sqrt,)
$(call run-unit-test,test_fxp,)
$(call run-unit-test,test_stat,)

