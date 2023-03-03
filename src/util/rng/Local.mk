$(call add-hdrs,fd_rng.h)
$(call add-objs,fd_rng,fd_util)
$(call make-unit-test,test_rng,test_rng,fd_util)
$(call run-unit-test,test_rng,)

