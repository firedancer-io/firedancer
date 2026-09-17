$(call add-hdrs,fd_rng.h)
$(call add-objs,fd_rng_secure,fd_util)
$(call add-objs,fd_rng,fd_util_extra)
$(call make-unit-test,test_rng,test_rng,fd_util_extra fd_util)
$(call run-unit-test,test_rng)

