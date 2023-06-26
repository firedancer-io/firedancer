$(call add-hdrs,fd_env.h)
$(call add-objs,fd_env,fd_util)
$(call make-unit-test,test_env,test_env,fd_util)
$(call run-unit-test,test_env,)

