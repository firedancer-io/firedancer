ifdef FD_HAS_INT128
$(call add-hdrs,fd_bn254.h fd_bn254_scalar.h fd_poseidon.h)
$(call add-objs,fd_bn254 fd_poseidon,fd_ballet)
$(call make-unit-test,test_bn254,test_bn254,fd_ballet fd_util)
$(call make-unit-test,test_poseidon,test_poseidon,fd_ballet fd_util)
$(call run-unit-test,test_bn254)
$(call run-unit-test,test_poseidon)
ifdef FD_HAS_AVX512
$(call make-unit-test,test_bn254_avx512,avx512/test_bn254_avx512,fd_util)
$(call run-unit-test,test_bn254_avx512)
endif
endif
