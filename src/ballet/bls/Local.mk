$(call add-hdrs,fd_bls12_381.h fd_bls.h)
$(call add-objs,fd_bls12_381 fd_bls,fd_ballet)
$(call make-unit-test,test_bls12_381,test_bls12_381,fd_ballet fd_util,$(BLST_LIBS))
$(call run-unit-test,test_bls12_381)
