$(call add-hdrs,fd_sqrt.h fd_fxp.h)
$(call make-unit-test,test_sqrt,test_sqrt,fd_util)
$(call make-unit-test,test_fxp,test_fxp,fd_util)

