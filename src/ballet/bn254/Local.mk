ifneq ($(FD_HAS_LIBFF),)
ifndef FD_HAS_FFI

$(call add-hdrs,fd_bn254.h fd_poseidon.h)
$(call add-objs,fd_bn254 fd_poseidon_params fd_poseidon,fd_ballet)
$(call make-unit-test,test_bn254,test_bn254,fd_ballet fd_util)
$(call make-unit-test,test_poseidon,test_poseidon,fd_ballet fd_util)

endif
else

$(info bn254 disabled due to lack of libff)

endif
