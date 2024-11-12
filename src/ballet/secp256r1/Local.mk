$(call add-hdrs,fd_secp256r1.h)
$(call add-objs,fd_secp256r1,fd_ballet)
$(call make-unit-test,test_secp256r1,test_secp256r1,fd_ballet fd_util,$(S2NBIGNUM_LIBS))
$(call run-unit-test,test_secp256r1)
