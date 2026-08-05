$(call add-hdrs,fd_uint256.h fd_uint256_mul.h)
$(call make-unit-test,test_uint256,test_uint256,fd_util)
$(call run-unit-test,test_uint256)

ifdef FD_HAS_S2NBIGNUM
$(call add-hdrs,fd_big_mod_exp.h)
$(call add-objs,fd_big_mod_exp,fd_ballet)
$(call make-unit-test,test_big_mod_exp,test_big_mod_exp,fd_ballet fd_util)
$(call run-unit-test,test_big_mod_exp)
endif
