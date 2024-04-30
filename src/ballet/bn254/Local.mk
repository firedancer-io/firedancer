$(call add-hdrs,fd_bn254.h fd_bn254_scalar.h fd_poseidon.h)
$(call add-objs,fd_bn254 fd_poseidon,fd_ballet)
$(call make-unit-test,test_bn254,test_bn254,fd_ballet fd_util)
$(call make-unit-test,test_poseidon,test_poseidon,fd_ballet fd_util)
